// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: hugetlbro [SECONDS] (needs root)
 *
 * SECONDS is how long to keep trying (300 by default).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define KPF_BUDDY	10
#define KPF_HUGE	17
#define KPF_HWPOISON	19
#define BLOCK		512		/* pages per 2 MB huge page */
#define MAXBLK		4096

static const char *ok = "[+]", *err = "[-]";

/* shared between the controller and the two workers on CPU 0 */
struct shared {
	volatile uint32_t go;		/* round number, futex */
	volatile uint32_t mf_done;
	volatile uint32_t grow_done;
	volatile unsigned long pfn;
	volatile int64_t start_ns;	/* when the memory error is written */
	volatile int64_t fire_ns;	/* when the pool grows */
	char grow[32];
};
static struct shared *sh;

static int put(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;
	int r = write(fd, val, strlen(val)) < 0 ? -errno : 0;
	close(fd);
	return r;
}

static int get(const char *path, char *buf, size_t len)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;
	ssize_t n = read(fd, buf, len - 1);
	close(fd);
	buf[n > 0 ? n : 0] = 0;
	while (n > 0 && buf[n - 1] == '\n')
		buf[--n] = 0;
	return 0;
}

static int64_t ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static double now(void)
{
	return ns() / 1e9;
}

static void pin(int cpu, int prio)
{
	cpu_set_t set;
	struct sched_param sp = { .sched_priority = prio };

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
	if (prio)
		sched_setscheduler(0, SCHED_FIFO, &sp);
}

static void fwait(volatile uint32_t *addr, uint32_t val)
{
	while (*addr == val)
		syscall(SYS_futex, addr, FUTEX_WAIT, val, NULL, NULL, 0);
}

static void fwake(volatile uint32_t *addr)
{
	syscall(SYS_futex, addr, FUTEX_WAKE, 2, NULL, NULL, 0);
}

static uint64_t kflags(int kpf, unsigned long pfn)
{
	uint64_t fl = 0;
	if (pread(kpf, &fl, 8, pfn * 8) != 8)
		fl = 0;
	return fl;
}

static long pool(void)
{
	char buf[32];
	if (get("/proc/sys/vm/nr_hugepages", buf, sizeof(buf)))
		return -1;
	return atol(buf);
}

static void set_pool(long n)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "%ld", n);
	put("/proc/sys/vm/nr_hugepages", buf);
}

/* memory error worker: writes the page to hard_offline_page at start_ns */
static void mf_worker(void)
{
	int fd = open("/sys/devices/system/memory/hard_offline_page", O_WRONLY);
	char buf[32];
	uint32_t seen = 0;

	pin(0, 10);
	for (;;) {
		fwait(&sh->go, seen);
		seen = sh->go;
		snprintf(buf, sizeof(buf), "0x%lx", sh->pfn << 12);
		while (ns() < sh->start_ns)
			;
		ssize_t r = pwrite(fd, buf, strlen(buf), 0);	/* errors are normal here */
		(void)r;
		sh->mf_done = seen;
	}
}

/* pool worker: preempts the memory error at fire_ns and grows the pool by one */
static void grow_worker(void)
{
	int fd = open("/proc/sys/vm/nr_hugepages", O_WRONLY);
	uint32_t seen = 0;

	pin(0, 20);
	for (;;) {
		fwait(&sh->go, seen);
		seen = sh->go;
		struct timespec ts = { sh->fire_ns / 1000000000LL, sh->fire_ns % 1000000000LL };
		clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
		ssize_t r = pwrite(fd, sh->grow, strlen(sh->grow), 0);
		(void)r;
		sh->grow_done = seen;
	}
}

/* copy the kernel's reports (hidden by the low console level) to stdout */
static void kmsg_reports(int kmsg)
{
	static const char *pat[] = { "WARNING:", "BUG:", "Oops", "KASAN", "kernel BUG",
				     "circular locking", "inconsistent lock", NULL };
	char rec[1024];
	ssize_t n;

	while ((n = read(kmsg, rec, sizeof(rec) - 1)) > 0 || (n < 0 && errno == EPIPE)) {
		if (n <= 0)
			continue;
		rec[n] = 0;
		char *msg = strchr(rec, ';');
		unsigned long long us = 0;
		sscanf(rec, "%*u,%*u,%llu", &us);
		if (!msg)
			continue;
		msg++;
		for (int i = 0; pat[i]; i++)
			if (strstr(msg, pat[i])) {
				printf("[%5llu.%06llu] %s", us / 1000000, us % 1000000, msg);
				break;
			}
	}
}

/* the movable zone: first pfn and number of pages */
static int movable_zone(unsigned long *start, unsigned long *pages)
{
	FILE *f = fopen("/proc/zoneinfo", "r");
	char line[256];
	int in = 0;

	*start = *pages = 0;
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "zone "))
			in = !!strstr(line, "Movable");
		else if (in)
			sscanf(line, " spanned %lu", pages), sscanf(line, " start_pfn: %lu", start);
	}
	fclose(f);
	return *start && *pages ? 0 : -1;
}

/* free 2 MB blocks in the movable zone */
static long movable_free_blocks(void)
{
	FILE *f = fopen("/proc/buddyinfo", "r");
	char line[512];
	long n = 0;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (!strstr(line, "Movable"))
			continue;
		char *p = strstr(line, "Movable") + 7;
		for (int o = 0; o < 11; o++) {
			long c = strtol(p, &p, 10);
			if (o >= 9)
				n += c << (o - 9);
		}
	}
	fclose(f);
	return n;
}

/* node 0's memory_failure() counters: "ignored" counts the late rounds */
static void mf_stats(void)
{
	static const char *name[] = { "total", "recovered", "ignored", "failed", "delayed" };
	char path[96], buf[32];

	printf("hugetlbro: memory_failure() results:");
	for (int i = 0; i < 5; i++) {
		snprintf(path, sizeof(path), "/sys/devices/system/node/node0/memory_failure/%s", name[i]);
		if (!get(path, buf, sizeof(buf)))
			printf(" %s %s", name[i], buf);
	}
	printf("\n");
}

static unsigned long mstart, mpages;
static unsigned char washuge[MAXBLK];

/* a whole free 2 MB block: every page free in the buddy allocator */
static int block_free(int kpf, unsigned long head)
{
	uint64_t fl[BLOCK];

	if (pread(kpf, fl, sizeof(fl), head * 8) != sizeof(fl))
		return 0;
	for (int i = 0; i < BLOCK; i++)
		if (fl[i] != 1ULL << KPF_BUDDY)
			return 0;
	return 1;
}

/* the block the last shrink freed (was a huge page), or any free block */
static long find_free_block(int kpf, int any)
{
	long nblk = mpages / BLOCK;

	for (long b = 0; b < nblk && b < MAXBLK; b++) {
		unsigned long head = (mstart + BLOCK - 1) / BLOCK * BLOCK + b * BLOCK;
		if ((washuge[b] || any) && block_free(kpf, head))
			return head;
	}
	return -1;
}

static unsigned char stuck[MAXBLK * BLOCK / 8];	/* injected pages we could not unpoison */
static int nfalse;

/*
 * movable pages other than @hit that read as hwpoisoned, in the blocks that
 * are not huge pages now (or in all blocks); prints up to 8 marker lines
 */
static long false_marks(int kpf, unsigned long hit, int all, long *blocks)
{
	static uint64_t fl[BLOCK];
	long nblk = mpages / BLOCK, n = 0;
	unsigned long first = (mstart + BLOCK - 1) / BLOCK * BLOCK;

	*blocks = 0;
	for (long b = 0; b < nblk && b < MAXBLK; b++) {
		unsigned long head = first + b * BLOCK;
		long here = 0;

		if (!all && kflags(kpf, head) >> KPF_HUGE & 1)
			continue;
		if (pread(kpf, fl, sizeof(fl), head * 8) != sizeof(fl))
			continue;
		for (int i = 0; i < BLOCK; i++) {
			unsigned long pfn = head + i, off = pfn - first;

			if (!(fl[i] >> KPF_HWPOISON & 1) || pfn == hit ||
			    stuck[off / 8] >> (off % 8) & 1)
				continue;
			here++;
			if (nfalse++ < 8)
				printf("LB-FALSE-HWPOISON pfn=0x%lx block=0x%lx injected=0x%lx\n",
				       pfn, head, hit);
		}
		n += here;
		*blocks += !!here;
	}
	return n;
}

static void mark_huge(int kpf)
{
	long nblk = mpages / BLOCK;

	for (long b = 0; b < nblk && b < MAXBLK; b++) {
		unsigned long head = (mstart + BLOCK - 1) / BLOCK * BLOCK + b * BLOCK;
		washuge[b] = kflags(kpf, head) >> KPF_HUGE & 1;
	}
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	double t0 = now(), last = t0;
	long early = 0, late = 0, round;
	double d = 10000;	/* ns from the write to the grow; adapted every round */
	char buf[64];

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (isatty(STDOUT_FILENO)) {
		ok = "\033[32m[+]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	int kpf = open("/proc/kpageflags", O_RDONLY);
	int kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (kpf < 0 || kmsg < 0 || access("/sys/devices/system/memory/hard_offline_page", W_OK) ||
	    access("/sys/kernel/debug/hwpoison/unpoison-pfn", W_OK)) {
		printf("%s hugetlbro: needs /proc/kpageflags, /dev/kmsg, hard_offline_page and "
		       "hwpoison/unpoison-pfn in debugfs\n", err);
		return 2;
	}
	lseek(kmsg, 0, SEEK_END);
	if (movable_zone(&mstart, &mpages)) {
		printf("%s hugetlbro: no movable zone (boot with movablecore=)\n", err);
		return 2;
	}

	/* the workers first, so that their pages are not taken from block B */
	sh = mmap(NULL, sizeof(*sh), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	memset(sh, 0, sizeof(*sh));
	pid_t mf = fork();
	if (!mf)
		mf_worker();
	pid_t gw = fork();
	if (!gw)
		grow_worker();
	pin(1, 0);
	srand(getpid());

	/* fill the movable zone with huge pages, then free one of them: block B */
	set_pool(0);
	set_pool(movable_free_blocks());
	for (int i = 0; i < 64 && movable_free_blocks() > 0; i++)
		set_pool(pool() + 1);
	mark_huge(kpf);
	for (int i = 0; i < 64 && movable_free_blocks() < 1; i++)
		set_pool(pool() - 1);
	long m = pool() + 1;
	long blk = find_free_block(kpf, 0);
	if (m < 2 || blk < 0 || movable_free_blocks() != 1) {
		printf("%s hugetlbro: could not set up the pool (%ld huge pages, %ld free blocks)\n",
		       err, m - 1, movable_free_blocks());
		kill(mf, SIGKILL);
		kill(gw, SIGKILL);
		return 2;
	}
	printf("hugetlbro: %ld huge pages fill the movable zone; the next one is allocated "
	       "from block 0x%lx\n", m, blk);

	snprintf(sh->grow, sizeof(sh->grow), "%ld", m);

	for (round = 1; now() - t0 < limit; round++) {
		unsigned long pfn = blk + 64 + rand() % (BLOCK - 64);
		double jit = (rand() % 4001 - 2000);	/* +-2 us */
		int64_t t = ns();

		sh->pfn = pfn;
		sh->start_ns = t + 100000;
		sh->fire_ns = sh->start_ns + (int64_t)(d + jit);
		sh->go = round;
		fwake(&sh->go);

		/* the memory error worker dies in the kernel when the bug hits */
		double tw = now();
		int st, dead = 0;
		while ((sh->mf_done != round || sh->grow_done != round) && now() - tw < 5) {
			if (waitpid(mf, &st, WNOHANG) == mf) {
				dead = 1;
				break;
			}
			usleep(50);
		}
		kmsg_reports(kmsg);
		if (dead || sh->mf_done != round) {
			double secs = now() - t0;
			sleep(1);
			kmsg_reports(kmsg);
			printf("LB-RESULT bug rounds=%ld seconds=%.1f\n", round, secs);
			printf("%s hugetlbro: bug: the memory error on pfn 0x%lx %s (round %ld, %.1f s)\n",
			       ok, pfn, dead ? "killed its task in the kernel" : "never returned",
			       round, secs);
			kill(gw, SIGKILL);
			return 0;
		}

		/* grow before the hugetlb check: the new huge page was dissolved again */
		long n = pool();
		if (n == m - 1) {
			early++;
			d += 50;
		} else {
			late++;
			d -= 50;
			set_pool(m - 1);
		}
		if (d < 0)
			d = 0;

		/* the free block (freed huge page) may hold pages that were never hit */
		long nb, nf = false_marks(kpf, pfn, 0, &nb);
		if (nf) {
			double secs = now() - t0;
			long all, ab;

			kill(mf, SIGKILL);
			kill(gw, SIGKILL);
			/* free every huge page: their tail pages show the mark too */
			set_pool(0);
			all = false_marks(kpf, pfn, 1, &ab);
			kmsg_reports(kmsg);
			mf_stats();
			printf("LB-RESULT bug rounds=%ld seconds=%.1f\n", round, secs);
			printf("%s hugetlbro: bug: after the memory error on pfn 0x%lx, %ld other pages "
			       "of the freed block read as hwpoisoned (round %ld, %.1f s)\n",
			       ok, pfn, nf, round, secs);
			printf("%s hugetlbro: after freeing the whole pool, %ld pages in %ld blocks "
			       "read as hwpoisoned; only pfn 0x%lx had an error\n", ok, all, ab, pfn);
			return 0;
		}
		if (kflags(kpf, pfn) >> KPF_HWPOISON & 1) {
			snprintf(buf, sizeof(buf), "%lu", pfn);
			put("/sys/kernel/debug/hwpoison/unpoison-pfn", buf);
			if (kflags(kpf, pfn) >> KPF_HWPOISON & 1) {
				unsigned long off = pfn - (mstart + BLOCK - 1) / BLOCK * BLOCK;
				stuck[off / 8] |= 1 << (off % 8);
			}
		}
		if (!block_free(kpf, blk)) {
			long b = -1;

			/* a small allocation took part of it: free one more huge page */
			for (int i = 0; i < 8 && b < 0 && m > 2; i++) {
				if (movable_free_blocks() == 1)
					b = find_free_block(kpf, 1);
				if (b < 0)
					set_pool(--m - 1);
			}
			if (b < 0) {
				printf("%s hugetlbro: lost the free block (round %ld)\n", err, round);
				kill(mf, SIGKILL);
				kill(gw, SIGKILL);
				return 2;
			}
			blk = b;
			snprintf(sh->grow, sizeof(sh->grow), "%ld", m);
		}
		if (now() - last >= 10) {
			last = now();
			printf("hugetlbro: %ld rounds, %.0f s: pool grew %ld times before the hugetlb "
			       "check, %ld after; aim %.1f us after the write\n", round,
			       last - t0, early, late, d / 1000);
		}
	}
	double secs = now() - t0;
	kill(mf, SIGKILL);
	kill(gw, SIGKILL);
	printf("hugetlbro: pool grew %ld times before the hugetlb check, %ld after\n", early, late);
	mf_stats();
	printf("LB-RESULT none rounds=%ld seconds=%.1f\n", round - 1, secs);
	printf("%s hugetlbro: no report in %ld rounds, %.1f s\n", ok, round - 1, secs);
	return 1;
}

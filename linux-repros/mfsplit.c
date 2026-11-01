// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: mfsplit DIR [SECONDS] (needs root)
 *
 * DIR is on a tmpfs mounted with huge=always.  SECONDS is how long to keep
 * trying (300 by default).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define SZ		(2UL << 20)
#define KPF_THP		22
#define KPF_HWPOISON	19
#define HOLD_NS		40000000LL	/* killer keeps CPU 0 this long: an RCU grace period */
#define NCHAIN		16

static const char *ok = "[+]", *err = "[-]";

enum { BEFORE, IN, AFTER, LATE, UNKNOWN, NCLASS };

static volatile uint32_t go, off_done, kill_done;
static volatile int64_t start_ns, fire_ns, t_in, t_wake;
static volatile int file_fd = -1, off_tid, cls, in_off;
static volatile long off_ret;
static char path[256], addr[32];
static int sofd;

/* the call chain to min_order_for_split, from the outermost frame inward */
static struct { char fn[64]; long ret; } chain[NCHAIN];
static int nchain;

static int64_t ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000LL + ts.tv_nsec;
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

static void fwait(volatile uint32_t *a, uint32_t val)
{
	while (*a == val)
		syscall(SYS_futex, a, FUTEX_WAIT_PRIVATE, val, NULL, NULL, 0);
}

static void fwake(volatile uint32_t *a)
{
	syscall(SYS_futex, a, FUTEX_WAKE_PRIVATE, 8, NULL, NULL, 0);
}

static int put(const char *p, const char *val)
{
	int fd = open(p, O_WRONLY);
	if (fd < 0)
		return -errno;
	int r = write(fd, val, strlen(val)) < 0 ? -errno : 0;
	close(fd);
	return r;
}

static uint64_t kflags(int kpf, unsigned long pfn)
{
	uint64_t fl = 0;
	if (pread(kpf, &fl, 8, pfn * 8) != 8)
		fl = 0;
	return fl;
}

/* soft offline worker: writes the page's address at start_ns */
static void *offline_worker(void *arg)
{
	uint32_t seen = 0;

	(void)arg;
	off_tid = syscall(SYS_gettid);
	pin(0, 10);
	for (;;) {
		fwait(&go, seen);
		seen = go;
		while (ns() < start_ns)
			;
		t_in = ns();
		ssize_t r = pwrite(sofd, addr, strlen(addr), 0);
		off_ret = r < 0 ? -errno : 0;
		off_done = seen;
		fwake(&off_done);
	}
	return NULL;
}

struct frame { char fn[64]; long off; };

static int frames(struct frame *f, int max)
{
	char p[64], buf[4096];
	int n = 0;

	snprintf(p, sizeof(p), "/proc/self/task/%d/stack", off_tid);
	int fd = open(p, O_RDONLY);
	if (fd < 0)
		return 0;
	ssize_t len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	buf[len > 0 ? len : 0] = 0;
	for (char *l = strtok(buf, "\n"); l && n < max; l = strtok(NULL, "\n")) {
		char *s = strchr(l, ' ');
		if (!s || sscanf(s + 1, "%63[^+]+0x%lx", f[n].fn, &f[n].off) != 2)
			continue;
		n++;
	}
	return n;
}

static int irq_frame(const char *fn)
{
	return strstr(fn, "schedule") || strstr(fn, "irqentry") || strstr(fn, "sysvec") ||
	       strstr(fn, "apic_timer") || strstr(fn, "irq_exit") || strstr(fn, "user_mode");
}

/* where the preempted soft offline is relative to min_order_for_split() */
static int classify(struct frame *f, int n)
{
	int i, c, top = 0;

	while (top < n && irq_frame(f[top].fn))
		top++;
	for (i = top; i < n; i++)
		if (!strcmp(f[i].fn, "min_order_for_split")) {
			in_off = f[i].off;
			if (!nchain) {
				/* learn the chain: return offsets of the callers */
				for (int j = n - 1; j > i && nchain < NCHAIN; j--, nchain++) {
					strcpy(chain[nchain].fn, f[j].fn);
					chain[nchain].ret = f[j].off;
				}
			}
			return IN;
		}
	if (top == n)
		return BEFORE;		/* user space: not in the write yet */
	if (!nchain) {
		for (i = top; i < n; i++)
			if (strstr(f[i].fn, "split") || strstr(f[i].fn, "folio_lock") ||
			    strstr(f[i].fn, "migrat") || strstr(f[i].fn, "isolate") ||
			    strstr(f[i].fn, "evict") || strstr(f[i].fn, "handle_poison") ||
			    strstr(f[i].fn, "free"))
				return AFTER;
		return BEFORE;
	}
	/* walk the chain from the outside in: before or after each call */
	i = n - 1;
	for (c = 0; c < nchain; c++) {
		while (i >= top && strcmp(f[i].fn, chain[c].fn))
			i--;
		if (i < top)
			return UNKNOWN;
		if (f[i].off < chain[c].ret)
			return BEFORE;
		if (f[i].off > chain[c].ret || i == top)
			return AFTER;
		i--;
	}
	return UNKNOWN;
}

/* killer: preempts the soft offline at fire_ns, unlinks and closes the file */
static void *killer(void *arg)
{
	struct frame f[48];
	uint32_t seen = 0;

	(void)arg;
	pin(0, 20);
	for (;;) {
		fwait(&go, seen);
		seen = go;
		struct timespec ts = { fire_ns / 1000000000LL, fire_ns % 1000000000LL };
		clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
		t_wake = ns();
		if (off_done == seen)
			cls = LATE;
		else
			cls = classify(f, frames(f, 48));
		unlink(path);
		close(file_fd);
		if (cls == IN)
			while (ns() - t_wake < HOLD_NS)
				;
		kill_done = seen;
		fwake(&kill_done);
	}
	return NULL;
}

/* a new file with one 2 MB folio; returns the pfn of one of its pages */
static long new_file(int kpf, char *buf)
{
	unsigned long pfn = 0;
	uint64_t pm;
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);

	if (fd < 0)
		return -1;
	if (pwrite(fd, buf, SZ, 0) != (ssize_t)SZ) {
		close(fd);
		unlink(path);
		return -1;
	}
	char *m = mmap(NULL, SZ, PROT_READ, MAP_SHARED, fd, 0);
	if (m == MAP_FAILED) {
		close(fd);
		unlink(path);
		return -1;
	}
	unsigned long i = rand() % (SZ / 4096);
	int pmfd = open("/proc/self/pagemap", O_RDONLY);
	(void)*(volatile char *)(m + i * 4096);
	if (pread(pmfd, &pm, 8, ((unsigned long)m / 4096 + i) * 8) == 8 && (pm >> 63))
		pfn = pm & ((1ULL << 55) - 1);
	close(pmfd);
	munmap(m, SZ);
	if (!pfn || !(kflags(kpf, pfn) >> KPF_THP & 1)) {
		close(fd);
		unlink(path);
		return 0;
	}
	file_fd = fd;
	return pfn;
}

/* a KASAN report in the kernel log since the start */
static int kasan_report(int kmsg)
{
	char rec[1024];
	ssize_t n;
	int hit = 0;

	while ((n = read(kmsg, rec, sizeof(rec) - 1)) > 0 || (n < 0 && errno == EPIPE)) {
		if (n <= 0)
			continue;
		rec[n] = 0;
		if (strstr(rec, "KASAN:"))
			hit = 1;
	}
	return hit;
}

int main(int argc, char **argv)
{
	int limit = argc > 2 ? atoi(argv[2]) : 300;
	long cnt[NCLASS] = { 0 }, nothp = 0, round, last = 0;
	int64_t t0 = ns(), d = 2000;	/* ns from the write to the timer; adapted */
	long inoff[256] = { 0 }, step = 4000;
	int lastdir = 0, streak = 0;
	pthread_t th;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (isatty(STDOUT_FILENO)) {
		ok = "\033[32m[+]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	if (argc < 2) {
		printf("usage: mfsplit DIR [SECONDS]\n");
		return 2;
	}
	snprintf(path, sizeof(path), "%s/mfsplit.f", argv[1]);
	int kpf = open("/proc/kpageflags", O_RDONLY);
	int kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	sofd = open("/sys/devices/system/memory/soft_offline_page", O_WRONLY);
	if (kpf < 0 || kmsg < 0 || sofd < 0 ||
	    access("/sys/kernel/debug/hwpoison/unpoison-pfn", W_OK)) {
		printf("%s mfsplit: needs /proc/kpageflags, /dev/kmsg, soft_offline_page and "
		       "hwpoison/unpoison-pfn in debugfs\n", err);
		return 2;
	}
	lseek(kmsg, 0, SEEK_END);
	char *buf = aligned_alloc(SZ, SZ);
	memset(buf, 'a', SZ);
	pin(1, 0);
	srand(getpid());
	pthread_create(&th, NULL, offline_worker, NULL);
	pthread_create(&th, NULL, killer, NULL);
	while (!off_tid)
		usleep(1000);

	for (round = 1; ns() - t0 < limit * 1000000000LL; round++) {
		long pfn = new_file(kpf, buf);
		if (pfn < 0) {
			printf("%s mfsplit: could not write a 2 MB file in %s\n", err, argv[1]);
			return 2;
		}
		if (!pfn) {
			/* no 2 MB folio: compact and try again */
			if (++nothp > 1000) {
				printf("%s mfsplit: no 2 MB folios in %s (mounted with "
				       "huge=always?)\n", err, argv[1]);
				return 2;
			}
			put("/proc/sys/vm/compact_memory", "1");
			round--;
			continue;
		}
		nothp = 0;
		snprintf(addr, sizeof(addr), "0x%lx", pfn << 12);
		int64_t jit = rand() % 801 - 400;	/* +-400 ns */
		start_ns = ns() + 50000;
		fire_ns = start_ns + (d + jit > 0 ? d + jit : 0);
		go = round;
		fwake(&go);
		fwait(&off_done, round - 1);
		fwait(&kill_done, round - 1);

		cnt[cls]++;
		if (cls == IN)
			inoff[in_off & 255]++;
		if (kasan_report(kmsg)) {
			double secs = (ns() - t0) / 1e9;
			printf("mfsplit: preempted in min_order_for_split at offsets:");
			for (int i = 0; i < 256; i++)
				if (inoff[i])
					printf(" 0x%x:%ld", i, inoff[i]);
			printf("\n");
			printf("LB-RESULT bug rounds=%ld seconds=%.1f\n", round, secs);
			printf("%s mfsplit: bug: soft offline read the mapping of a freed inode "
			       "(KASAN report above; round %ld, %.1f s, %ld rounds preempted in "
			       "min_order_for_split)\n", ok, round, secs, cnt[IN]);
			return 0;
		}
		/* aim: one step toward min_order_for_split(), halved on each turn */
		int dir = cls == BEFORE ? 1 : cls == AFTER || cls == LATE ? -1 : 0;
		if (dir && dir == -lastdir && step > 20)
			step /= 2, streak = 0;
		else if (dir && ++streak > 32 && step < 4000)
			step *= 2, streak = 0;	/* drifted: speed up again */
		if (dir)
			lastdir = dir;
		d += dir * step;
		if (d < 0)
			d = 0;
		if (kflags(kpf, pfn) >> KPF_HWPOISON & 1) {
			char s[32];
			snprintf(s, sizeof(s), "%ld", pfn);
			put("/sys/kernel/debug/hwpoison/unpoison-pfn", s);
		}
		if ((ns() - t0) / 1000000000LL >= last + 10) {
			last = (ns() - t0) / 1000000000LL;
			printf("mfsplit: %ld rounds, %ld s: preempted before min_order_for_split %ld, "
			       "in it %ld, after %ld, after the write %ld, unknown %ld; aim %.2f us\n",
			       round, last, cnt[BEFORE], cnt[IN], cnt[AFTER], cnt[LATE],
			       cnt[UNKNOWN], d / 1000.0);
		}
	}
	double secs = (ns() - t0) / 1e9;
	printf("mfsplit: preempted in min_order_for_split at offsets:");
	for (int i = 0; i < 256; i++)
		if (inoff[i])
			printf(" 0x%x:%ld", i, inoff[i]);
	printf("\n");
	printf("LB-RESULT none rounds=%ld seconds=%.1f\n", round - 1, secs);
	printf("%s mfsplit: no report in %ld rounds, %.1f s\n", ok, round - 1, secs);
	return 1;
}

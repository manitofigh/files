// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: mfoffline DIR... [SECONDS] (needs root)
 *
 * DIR is a directory on the file system to use (ext4, tmpfs, ...); with
 * several, the rounds take turns.  SECONDS is how long to keep trying (300
 * by default).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAXBLK	64
#define PAGE	4096
#define KPF_HWPOISON	19

static const char *ok = "[+]", *err = "[-]";

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

static double now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void msleep(int ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
	nanosleep(&ts, NULL);
}

static int offlinable[MAXBLK], movable[MAXBLK];
static unsigned long block_pages;

static void state_path(char *path, size_t len, int blk)
{
	snprintf(path, len, "/sys/devices/system/memory/memory%d/state", blk);
}

static unsigned long page_pfn(int pm, void *addr)
{
	uint64_t ent = 0;
	if (pread(pm, &ent, 8, ((uintptr_t)addr / PAGE) * 8) != 8 || !(ent >> 63))
		return 0;
	return ent & ((1ULL << 55) - 1);
}

static int hwpoisoned(unsigned long pfn)
{
	uint64_t fl = 0;
	int fd = open("/proc/kpageflags", O_RDONLY);
	if (fd < 0)
		return 0;
	if (pread(fd, &fl, 8, pfn * 8) != 8)
		fl = 0;
	close(fd);
	return (fl >> KPF_HWPOISON) & 1;
}

/*
 * fill the free memory of the movable blocks that cannot be offlined with
 * anonymous pages, so that file pages land in blocks that can
 */
static void fill_pinned_blocks(void)
{
	const long n = 16384;
	int pm = open("/proc/self/pagemap", O_RDONLY);

	for (int iter = 0; iter < 64; iter++) {
		char *m = mmap(NULL, n * PAGE, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		long kept = 0;
		if (m == MAP_FAILED)
			break;
		madvise(m, n * PAGE, MADV_NOHUGEPAGE);
		for (long i = 0; i < n; i++)
			m[i * PAGE] = 1;
		for (long i = 0; i < n; i++) {
			unsigned long b = page_pfn(pm, m + i * PAGE) / block_pages;
			if (b < MAXBLK && movable[b] && !offlinable[b])
				kept++;
			else
				munmap(m + i * PAGE, PAGE);
		}
		if (kept < n / 256)
			break;
	}
	close(pm);
}

/*
 * write the file page by page until two of its pages lie in the same
 * offlinable block; returns their offsets and pfns
 */
static int find_pages(int fd, long off[2], unsigned long pfn[2], int *blk)
{
	static long first[MAXBLK];
	static unsigned long firstpfn[MAXBLK];
	char buf[PAGE];
	int pm = open("/proc/self/pagemap", O_RDONLY);
	int found = 0;

	memset(first, -1, sizeof(first));
	memset(buf, 'x', sizeof(buf));
	for (long i = 0; i < 262144 && !found; i++) {
		if (pwrite(fd, buf, PAGE, i * PAGE) != PAGE)
			break;
		char *m = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, fd, i * PAGE);
		if (m == MAP_FAILED)
			break;
		volatile char c = m[0];
		(void)c;
		unsigned long f = page_pfn(pm, m);
		munmap(m, PAGE);
		int b = f / block_pages;
		if (!f || b >= MAXBLK || !offlinable[b])
			continue;
		if (first[b] < 0) {
			first[b] = i;
			firstpfn[b] = f;
			continue;
		}
		pfn[0] = firstpfn[b];
		off[0] = first[b] * PAGE;
		off[1] = i * PAGE;
		pfn[1] = f;
		*blk = b;
		found = 1;
	}
	close(pm);
	fsync(fd);
	return found;
}

/* take a reference on the file page at off: vmsplice it into a pipe */
static int pin(int fd, long off, int p[2])
{
	if (pipe(p))
		return -1;
	char *m = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, fd, off);
	if (m == MAP_FAILED)
		return -1;
	volatile char c = m[0];
	(void)c;
	struct iovec iov = { m, PAGE };
	ssize_t n = vmsplice(p[1], &iov, 1, 0);
	munmap(m, PAGE);
	return n == PAGE ? 0 : -1;
}

/* drop the reference: empty and close the pipe */
static void unpin(int p[2])
{
	char buf[PAGE];
	if (p[0] < 0)
		return;
	fcntl(p[0], F_SETFL, O_NONBLOCK);
	while (read(p[0], buf, sizeof(buf)) > 0)
		;
	close(p[0]);
	close(p[1]);
	p[0] = p[1] = -1;
}

/* write val to path in a child; returns its pid (exit code: errno) */
static pid_t put_child(const char *path, const char *val)
{
	pid_t c = fork();
	if (c == 0) {
		alarm(20);
		int r = put(path, val);
		_exit(r ? -r : 0);
	}
	return c;
}

static int wait_child(pid_t c)
{
	int st = 0;
	waitpid(c, &st, 0);
	return WIFEXITED(st) ? WEXITSTATUS(st) : 255;
}

int main(int argc, char **argv)
{
	int ndirs = argc - 1, limit = 300;
	char buf[256], path[128], file[256];
	double t0 = now();
	int round;

	if (ndirs > 1 && strspn(argv[argc - 1], "0123456789") == strlen(argv[argc - 1])) {
		limit = atoi(argv[argc - 1]);
		ndirs--;
	}
	if (ndirs < 1) {
		fprintf(stderr, "usage: %s DIR... [SECONDS]\n", argv[0]);
		return 2;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (isatty(STDOUT_FILENO)) {
		ok = "\033[32m[+]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	if (get("/sys/devices/system/memory/block_size_bytes", buf, sizeof(buf)) < 0) {
		printf("%s mfoffline: no memory hotplug in sysfs\n", err);
		return 2;
	}
	block_pages = strtoul(buf, NULL, 16) / PAGE;
	int nblk = 0;
	for (int b = 0; b < MAXBLK; b++) {
		char zones[128] = "";
		snprintf(path, sizeof(path), "/sys/devices/system/memory/memory%d/valid_zones", b);
		if (get(path, zones, sizeof(zones)) < 0 || !strstr(zones, "Movable"))
			continue;
		movable[b] = 1;
		state_path(path, sizeof(path), b);
		if (!put(path, "offline")) {
			offlinable[b] = 1;
			nblk++;
			put(path, "online_movable");
		}
	}
	if (!nblk) {
		printf("%s mfoffline: no memory block can be offlined (boot with movablecore=)\n", err);
		return 2;
	}
	fill_pinned_blocks();

	for (round = 1; now() - t0 < limit; round++) {
		const char *dir = argv[1 + (round - 1) % ndirs];
		long off[2];
		unsigned long pfn[2];
		int blk, pq[2] = { -1, -1 }, pp[2] = { -1, -1 };

		snprintf(file, sizeof(file), "%s/f%d", dir, round);
		int fd = open(file, O_RDWR | O_CREAT | O_TRUNC, 0600);
		if (fd < 0 || !find_pages(fd, off, pfn, &blk)) {
			printf("%s mfoffline: no two file pages in one offlinable block (%s)\n",
			       err, dir);
			return 2;
		}
		/* page q keeps the offline retrying, page p fails to migrate until poisoned */
		if (pin(fd, off[0], pq) || pin(fd, off[1], pp)) {
			printf("%s mfoffline: vmsplice: %s\n", err, strerror(errno));
			return 2;
		}
		close(fd);

		state_path(path, sizeof(path), blk);
		pid_t offl = put_child(path, "offline");
		double t = now();
		while (now() - t < 2 && (get(path, buf, sizeof(buf)) || strcmp(buf, "going-offline")))
			msleep(1);
		msleep(100 + rand() % 200);

		/* memory error on page p while the offline runs */
		snprintf(buf, sizeof(buf), "0x%lx", pfn[1] << 12);
		pid_t mf = put_child("/sys/devices/system/memory/hard_offline_page", buf);
		t = now();
		while (now() - t < 2 && !hwpoisoned(pfn[1]))
			msleep(1);
		int poisoned = hwpoisoned(pfn[1]);
		msleep(100);
		unpin(pp);
		msleep(100);
		unpin(pq);
		int off_err = wait_child(offl);
		int mf_err = wait_child(mf);
		printf("mfoffline: round %d (%s): memory error on file page 0x%lx (%s), offline of "
		       "memory%d: %s\n", round, dir, pfn[1], poisoned ? "flag set" : "no flag",
		       blk, off_err ? strerror(off_err) : "done");
		(void)mf_err;

		/* walk the page cache of the file (drop_caches) in a child */
		pid_t c = fork();
		if (c == 0)
			_exit(put("/proc/sys/vm/drop_caches", "3") ? 1 : 0);
		int st = 0;
		waitpid(c, &st, 0);
		if (!WIFEXITED(st)) {
			double secs = now() - t0;
			printf("LB-RESULT bug rounds=%d seconds=%.1f\n", round, secs);
			printf("%s mfoffline: bug: drop_caches died (signal %d) on the page of "
			       "offlined memory%d (%s, round %d, %.1f s)\n", ok, WTERMSIG(st), blk,
			       dir, round, secs);
			return 0;
		}
		unlink(file);
		if (!off_err && put(path, "online_movable"))
			offlinable[blk] = 0;
	}
	double secs = now() - t0;
	printf("LB-RESULT none rounds=%d seconds=%.1f\n", round - 1, secs);
	printf("%s mfoffline: no report in %d rounds, %.1f s\n", ok, round - 1, secs);
	return 1;
}

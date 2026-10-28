// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: hugeoffline [SECONDS] (needs root)
 *
 * SECONDS is how long to keep trying (300 by default).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAXBLK	64
#define STUCK	10	/* s before an offline counts as stuck */

static const char *ok = "[+]", *warn = "[~]", *err = "[-]";

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

static void pin(int cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
}

static long meminfo(const char *key)
{
	char buf[8192];
	if (get("/proc/meminfo", buf, sizeof(buf)) < 0)
		return -1;
	char *p = strstr(buf, key);
	return p ? strtol(p + strlen(key), NULL, 10) : -1;
}

static char task_state(pid_t pid)
{
	char path[64], buf[1024];
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	if (get(path, buf, sizeof(buf)) < 0)
		return 0;
	char *p = strrchr(buf, ')');
	return p ? p[2] : '?';
}

static int gone(pid_t pid)
{
	int st;
	return waitpid(pid, &st, WNOHANG) == pid;
}

static int offlinable[MAXBLK];
static unsigned long block_pages;
static unsigned long used[1024];
static int nused;

static int was_used(unsigned long pfn)
{
	for (int i = 0; i < nused; i++)
		if (used[i] == pfn)
			return 1;
	return 0;
}

static void state_path(char *path, size_t len, int blk)
{
	snprintf(path, len, "/sys/devices/system/memory/memory%d/state", blk);
}

/* a free 2 MB hugetlb page in an offlinable block: grow the pool until one is there */
static unsigned long find_huge_page(int *blk)
{
	int kpf = open("/proc/kpageflags", O_RDONLY);
	char buf[32];
	if (kpf < 0)
		return 0;
	for (long pool = meminfo("HugePages_Total:") + 8; pool <= 400; pool += 8) {
		snprintf(buf, sizeof(buf), "%ld", pool);
		if (put("/proc/sys/vm/nr_hugepages", buf))
			break;
		for (int b = 0; b < MAXBLK; b++) {
			if (!offlinable[b])
				continue;
			for (unsigned long pfn = b * block_pages; pfn < (b + 1) * block_pages; pfn += 512) {
				uint64_t fl = 0;
				if (pread(kpf, &fl, 8, pfn * 8) != 8)
					break;
				/* KPF_HUGE, KPF_COMPOUND_HEAD, not KPF_HWPOISON */
				if ((fl & (1ULL << 17)) && (fl & (1ULL << 15)) &&
				    !(fl & (1ULL << 19)) && !was_used(pfn) && nused < 1024) {
					close(kpf);
					used[nused++] = pfn;
					*blk = b;
					return pfn;
				}
			}
		}
	}
	close(kpf);
	return 0;
}

/* memory error on a page of the huge page, with one slab allocation of this task failing */
static int poison(unsigned long pfn)
{
	const char *fs = "/sys/kernel/debug/failslab";
	char path[128], addr[64];
	snprintf(path, sizeof(path), "%s/task-filter", fs);
	put(path, "Y");
	snprintf(path, sizeof(path), "%s/probability", fs);
	put(path, "100");
	snprintf(path, sizeof(path), "%s/interval", fs);
	put(path, "1");
	snprintf(path, sizeof(path), "%s/times", fs);
	put(path, "1");
	int hfd = open("/sys/devices/system/memory/hard_offline_page", O_WRONLY);
	int mfd = open("/proc/self/make-it-fail", O_WRONLY);
	if (hfd < 0 || mfd < 0)
		return -1;
	snprintf(addr, sizeof(addr), "0x%lx", pfn << 12);
	if (write(mfd, "1", 1) != 1)
		return -1;
	int r = write(hfd, addr, strlen(addr)) < 0 ? -errno : 0;
	lseek(mfd, 0, SEEK_SET);
	if (write(mfd, "0", 1) != 1)
		return -1;
	close(mfd);
	close(hfd);
	return r == -EINVAL ? -1 : 0;
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	char buf[256], path[128];
	double t0 = now();
	int round;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (isatty(STDOUT_FILENO)) {
		ok = "\033[32m[+]\033[0m";
		warn = "\033[33m[~]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	pin(0);
	if (get("/sys/devices/system/memory/block_size_bytes", buf, sizeof(buf)) < 0) {
		printf("%s hugeoffline: no memory hotplug in sysfs\n", err);
		return 2;
	}
	block_pages = strtoul(buf, NULL, 16) / 4096;
	int nblk = 0;
	for (int b = 0; b < MAXBLK; b++) {
		char zones[128] = "";
		snprintf(path, sizeof(path), "/sys/devices/system/memory/memory%d/valid_zones", b);
		if (get(path, zones, sizeof(zones)) < 0 || !strstr(zones, "Movable"))
			continue;
		state_path(path, sizeof(path), b);
		if (!put(path, "offline")) {
			offlinable[b] = 1;
			nblk++;
			put(path, "online_movable");
		}
	}
	if (!nblk) {
		printf("%s hugeoffline: no memory block can be offlined (boot with movablecore=)\n", err);
		return 2;
	}

	for (round = 1; now() - t0 < limit; round++) {
		int blk;
		unsigned long head = find_huge_page(&blk);
		if (!head) {
			printf("%s hugeoffline: no free huge page left in an offlinable block\n", warn);
			break;
		}
		long total = meminfo("HugePages_Total:");
		if (poison(head + 7) < 0) {
			printf("%s hugeoffline: cannot use failslab or hard_offline_page\n", err);
			return 2;
		}
		printf("hugeoffline: round %d: memory error on huge page 0x%lx (memory%d), "
		       "HugePages_Total %ld -> %ld\n", round, head, blk, total,
		       meminfo("HugePages_Total:"));

		state_path(path, sizeof(path), blk);
		pid_t a = fork();
		if (a == 0) {
			pin(1);
			_exit(put(path, "offline") ? 1 : 0);
		}
		double ta = now();
		while (!gone(a) && now() - ta < STUCK)
			usleep(10000);
		if (task_state(a)) {
			double secs = now() - t0;
			printf("hugeoffline: offline of memory%d has not returned after %d s; "
			       "sending SIGKILL\n", blk, STUCK);
			/* another hotplug user, blocked behind it: the hung task report */
			pid_t b = fork();
			if (b == 0) {
				pin(2);
				snprintf(buf, sizeof(buf), "0x%lx", (head + 512 * 4) << 12);
				put("/sys/devices/system/memory/soft_offline_page", buf);
				_exit(0);
			}
			kill(a, SIGKILL);
			sleep(10);
			if (task_state(a) && !gone(a)) {
				printf("LB-UNKILLABLE pid=%d: offline still running 10 s after SIGKILL "
				       "(state %c)\n", a, task_state(a));
				printf("LB-RESULT bug rounds=%d seconds=%.1f\n", round, secs);
				printf("%s hugeoffline: bug: the offline of memory%d never returned and "
				       "survived SIGKILL (round %d, %.1f s)\n", ok, blk, round, secs);
				return 0;
			}
			/* offline_pages() retries until signalled: the block holds a poisoned page */
			printf("hugeoffline: the offline of memory%d ended after SIGKILL; not using that "
			       "block again\n", blk);
			offlinable[blk] = 0;
			waitpid(b, NULL, 0);
			continue;
		}
		put(path, "online_movable");
	}
	double secs = now() - t0;
	printf("LB-RESULT none rounds=%d seconds=%.1f\n", round - 1, secs);
	printf("%s hugeoffline: no unkillable offline in %d rounds, %.1f s\n", ok, round - 1, secs);
	return 1;
}

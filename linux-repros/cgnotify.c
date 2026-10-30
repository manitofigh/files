// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: cgnotify [SECONDS] (needs root)
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
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CG	"/sys/fs/cgroup"
#define P	CG "/cgnotify"
#define C	P "/c"
#define PAGE	4096
#define FOLIO	(512 * 1024)	/* the anon mTHP size run.sh turns on */
#define MARGIN	(96 * PAGE)	/* above usage: 4K charges fit, 512K ones do not */
#define MAXCHG	8

static const char *ok = "[+]", *warn = "[~]", *err = "[-]";
static int kmsg = -1;

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

static int put(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY);
	ssize_t n = -1;

	if (fd >= 0) {
		n = write(fd, s, strlen(s));
		close(fd);
	}
	return n == (ssize_t)strlen(s) ? 0 : -1;
}

static long get(const char *path, const char *key)
{
	char buf[4096], *p;
	ssize_t n;
	int fd = open(path, O_RDONLY);

	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	if (!key)
		return atol(buf);
	p = strstr(buf, key);
	return p ? atol(p + strlen(key)) : -1;
}

/* the kernel reported this bug: a line from /dev/kmsg, in our own words */
static const char *kernel_report(void)
{
	static const char *const keys[][2] = {
		{ "ODEBUG: init active", "set-up of a pending timer (debug objects)" },
		{ "ODEBUG: free active", "free of a pending timer (debug objects)" },
		{ "general protection fault", "general protection fault" },
		{ "detach_timer", "crash in the timer wheel" },
		{ "KASAN:", "KASAN report" },
	};
	char buf[1024];
	ssize_t n;

	while ((n = read(kmsg, buf, sizeof(buf) - 1)) > 0 || (n < 0 && errno == EPIPE)) {
		if (n <= 0)
			continue;
		buf[n] = 0;
		for (unsigned int i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
			if (strstr(buf, keys[i][0]))
				return keys[i][1];
	}
	return NULL;
}

/* in C: a 512K fault whose charge fails (memory.events "max"), then 4K */
static void charger(int cpu)
{
	char pid[32], *raw, *mem;

	prctl(PR_SET_PDEATHSIG, SIGKILL);
	pin(cpu);
	snprintf(pid, sizeof(pid), "%d", getpid());
	if (put(C "/cgroup.procs", pid))
		_exit(2);
	raw = mmap(NULL, 2 * FOLIO, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (raw == MAP_FAILED)
		_exit(2);
	mem = (char *)(((uintptr_t)raw + FOLIO - 1) & ~(uintptr_t)(FOLIO - 1));
	for (;;) {
		*(volatile char *)mem = 1;
		madvise(mem, FOLIO, MADV_DONTNEED);
	}
}

static int limit_c(void)
{
	char buf[32];
	long cur = get(C "/memory.current", NULL);

	if (cur < 0)
		return -1;
	snprintf(buf, sizeof(buf), "%ld", cur + MARGIN);
	return put(C "/memory.max", buf);
}

static void cleanup(pid_t *kids, int n)
{
	for (int i = 0; i < n; i++)
		if (kids[i] > 0)
			kill(kids[i], SIGKILL);
	for (int i = 0; i < n; i++)
		if (kids[i] > 0)
			waitpid(kids[i], NULL, 0);
	rmdir(C);
	rmdir(P);
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN), nkids;
	pid_t kids[MAXCHG] = { 0 };
	const char *report = NULL;
	double t0, last;
	long round, max0;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (isatty(STDOUT_FILENO)) {
		ok = "\033[32m[+]\033[0m";
		warn = "\033[33m[~]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	nkids = ncpu > 1 ? ncpu - 1 : 1;
	if (nkids > MAXCHG)
		nkids = MAXCHG;

	/* P has memory and io for its children; io keeps C's memory css alive */
	rmdir(C);
	rmdir(P);
	if (put(CG "/cgroup.subtree_control", "+memory +io") ||
	    (mkdir(P, 0755) && errno != EEXIST) ||
	    put(P "/cgroup.subtree_control", "+memory +io") ||
	    (mkdir(C, 0755) && errno != EEXIST) || limit_c()) {
		printf("%s cgnotify: cgroup setup failed: %s\n", err, strerror(errno));
		return 2;
	}
	kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (kmsg < 0) {
		printf("%s cgnotify: /dev/kmsg: %s\n", err, strerror(errno));
		return 2;
	}
	lseek(kmsg, 0, SEEK_END);

	for (int i = 0; i < nkids; i++) {
		kids[i] = fork();
		if (kids[i] == 0)
			charger(i % ncpu);
	}
	pin(ncpu - 1);
	usleep(200000);
	max0 = get(C "/memory.events", "max ");

	/* hide and show C's memory css, then limit it again */
	t0 = last = now();
	for (round = 1; now() - t0 < limit; round++) {
		if (put(P "/cgroup.subtree_control", "-memory") ||
		    put(P "/cgroup.subtree_control", "+memory") || limit_c()) {
			printf("%s cgnotify: toggling memory failed in round %ld: %s\n",
			       err, round, strerror(errno));
			cleanup(kids, nkids);
			return 2;
		}
		if ((report = kernel_report()))
			break;
		if (now() - last >= 10) {
			long max = get(C "/memory.events", "max ");

			last = now();
			printf("cgnotify: round %ld, %.0f s, %ld charge failures in C\n",
			       round, last - t0, max - max0);
			if (max <= max0) {
				printf("%s cgnotify: no charge failures in C (512K mTHP off?)\n", err);
				cleanup(kids, nkids);
				return 2;
			}
		}
	}
	double secs = now() - t0;

	if (report) {
		usleep(100000);
		cleanup(kids, nkids);
		printf("LB-RESULT bug rounds=%ld seconds=%.1f\n", round, secs);
		printf("%s cgnotify: bug: the kernel reported a %s (round %ld, %.1f s)\n",
		       ok, report, round, secs);
		return 0;
	}
	cleanup(kids, nkids);
	usleep(100000);
	if ((report = kernel_report())) {
		printf("LB-RESULT bug rounds=%ld seconds=%.1f\n", round - 1, secs);
		printf("%s cgnotify: bug: the kernel reported a %s after the last round\n",
		       ok, report);
		return 0;
	}
	printf("LB-RESULT none rounds=%ld seconds=%.1f\n", round - 1, secs);
	printf("%s cgnotify: no report in %ld rounds, %.1f s\n", ok, round - 1, secs);
	return 1;
}

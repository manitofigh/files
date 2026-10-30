// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: swapmthp SWAPDEV [SECONDS] (needs root)
 *
 * SWAPDEV is an mkswap'ed synchronous block device (brd), not in use.
 * SECONDS is how long to keep trying (300 by default).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/swap.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE	4096
#define FOLIO	(64 * 1024)
#define NR	(FOLIO / PAGE)
#define CHUNKS	256		/* 64K folios per round: 16 MiB */
#define WAIT	20		/* s before a step counts as stuck */

static const char *ok = "[+]", *warn = "[~]", *err = "[-]";
static const char *swapdev;
static int kmsg = -1;

/* shared with the child */
struct shared {
	_Atomic int ready;	/* child: data swapped out, race done */
	_Atomic int stop;	/* parent: swapoff and swapon done */
	_Atomic long bad;	/* child: pages with wrong data */
	_Atomic int setup;	/* child: setup failed */
};
static struct shared *sh;

/* the racing threads in the child */
static char *mem;
static _Atomic int go = -1, arrived;
static unsigned int seed = 1;

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

static void spin(unsigned int n)
{
	for (volatile unsigned int i = 0; i < n; i++)
		;
}

static uint64_t pattern(long page)
{
	return 0x5157000000000000ULL | page;
}

/* the kernel reported this bug: a line from /dev/kmsg, in our own words */
static const char *kernel_report(void)
{
	static const char *const keys[][2] = {
		{ "kernel BUG at mm/memory.c", "BUG_ON in do_swap_page()" },
		{ "mm/swapfile.c", "warning in swapoff (unuse_pte())" },
		{ "mm/rmap.c", "warning in the anon rmap code" },
		{ "Bad page", "bad page state" },
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

static void *toucher(void *arg)
{
	pin(0);
	for (int i = 0; i < CHUNKS; i++) {
		while (go != i)
			;
		arrived++;
		while (arrived < 2)
			;
		(void)*(volatile char *)(mem + i * FOLIO + PAGE);
		arrived++;
	}
	return NULL;
}

static void *zapper(void *arg)
{
	pin(1);
	for (int i = 0; i < CHUNKS; i++) {
		while (go != i)
			;
		arrived++;
		while (arrived < 2)
			;
		spin(rand_r(&seed) % 6000);
		madvise(mem + i * FOLIO + PAGE, PAGE, MADV_DONTNEED);
		arrived++;
	}
	return NULL;
}

static void child(void)
{
	size_t len = (size_t)CHUNKS * FOLIO;
	pthread_t t1, t2;
	char *raw;
	long bad = 0;

	raw = mmap(NULL, len + FOLIO, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (raw == MAP_FAILED)
		goto fail;
	mem = (char *)(((uintptr_t)raw + FOLIO - 1) & ~(uintptr_t)(FOLIO - 1));
	for (long p = 0; p < (long)(len / PAGE); p++)
		*(uint64_t *)(mem + p * PAGE) = pattern(p);
	if (madvise(mem, len, MADV_PAGEOUT))
		goto fail;

	/* fault on page 1 of each 64K range while another thread zaps it */
	seed = getpid();
	if (pthread_create(&t1, NULL, toucher, NULL) ||
	    pthread_create(&t2, NULL, zapper, NULL))
		goto fail;
	for (int i = 0; i < CHUNKS; i++) {
		arrived = 0;
		go = i;
		while (arrived < 4)
			;
	}
	pthread_join(t1, NULL);
	pthread_join(t2, NULL);
	sh->ready = 1;

	/* read everything back while swapoff runs */
	pin(0);
	do {
		for (long p = 0; p < (long)(len / PAGE); p++) {
			uint64_t v = *(volatile uint64_t *)(mem + p * PAGE);

			if (v != pattern(p) && !(p % NR == 1 && v == 0))
				bad++;
		}
	} while (!sh->stop);
	sh->bad = bad;
	_exit(0);
fail:
	sh->setup = 1;
	_exit(2);
}

/* wait for pid, watching the kernel log; 1: exited, 0: still running */
static int reap(pid_t pid, double secs, const char **report)
{
	double t = now();
	int st;

	while (now() - t < secs) {
		if ((*report = kernel_report()))
			return 0;
		if (waitpid(pid, &st, WNOHANG) == pid)
			return 1;
		usleep(1000);
	}
	return 0;
}

int main(int argc, char **argv)
{
	int limit = argc > 2 ? atoi(argv[2]) : 300;
	const char *report = NULL;
	double t0 = now();
	int round;
	long bad = 0;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (isatty(STDOUT_FILENO)) {
		ok = "\033[32m[+]\033[0m";
		warn = "\033[33m[~]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	if (argc < 2) {
		fprintf(stderr, "usage: swapmthp SWAPDEV [SECONDS]\n");
		return 2;
	}
	swapdev = argv[1];
	kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	sh = mmap(NULL, sizeof(*sh), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (kmsg < 0 || sh == MAP_FAILED) {
		printf("%s swapmthp: setup failed: %s\n", err, strerror(errno));
		return 2;
	}
	lseek(kmsg, 0, SEEK_END);
	swapoff(swapdev);
	if (swapon(swapdev, 0)) {
		printf("%s swapmthp: swapon %s: %s\n", err, swapdev, strerror(errno));
		return 2;
	}

	for (round = 1; now() - t0 < limit; round++) {
		pid_t c, s;

		memset(sh, 0, sizeof(*sh));
		c = fork();
		if (c == 0)
			child();
		while (!sh->ready && !sh->setup && !(report = kernel_report()))
			usleep(1000);
		if (report)
			break;
		if (sh->setup) {
			printf("%s swapmthp: the child's setup failed\n", err);
			return 2;
		}

		/* swapoff in its own process: it can get stuck after the bug */
		s = fork();
		if (s == 0) {
			pin(1);
			if (swapoff(swapdev))
				_exit(3);
			_exit(swapon(swapdev, 0) ? 4 : 0);
		}
		if (!reap(s, WAIT, &report)) {
			if (!report)
				printf("%s swapmthp: swapoff has not returned after %d s\n", warn, WAIT);
			break;
		}
		sh->stop = 1;
		if (!reap(c, WAIT, &report))
			break;
		usleep(20000);	/* bad page reports come at exit */
		if ((report = kernel_report()))
			break;
		bad += sh->bad;
		if (round % 20 == 0)
			printf("swapmthp: round %d, %.1f s\n", round, now() - t0);
	}
	double secs = now() - t0;

	if (report) {
		printf("LB-RESULT bug rounds=%d seconds=%.1f\n", round, secs);
		printf("%s swapmthp: bug: the kernel reported a %s (round %d, %.1f s)\n",
		       ok, report, round, secs);
		return 0;
	}
	if (now() - t0 < limit) {
		printf("%s swapmthp: stopped in round %d without a kernel report\n", err, round);
		return 2;
	}
	printf("LB-RESULT none rounds=%d seconds=%.1f\n", round - 1, secs);
	if (bad)
		printf("%s swapmthp: %ld pages read back with wrong data\n", err, bad);
	printf("%s swapmthp: no report in %d rounds, %.1f s\n", ok, round - 1, secs);
	return bad ? 2 : 1;
}

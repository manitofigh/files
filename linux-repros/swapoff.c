// SPDX-License-Identifier: GPL-2.0
/*
 * swapoff() racing an order-0 swap allocation: side a swaps out a 64k mthp
 * and one page in one madvise(MADV_PAGEOUT) call, side b runs swapoff() on
 * the same device at a varying offset from it. on affected kernels the
 * page's slot search never ends and swapoff() waits forever for the mthp's
 * write. needs an asynchronous, non-rotational swap device and 64k mthp.
 *
 * usage: swapoff-repro DEVICE [SECONDS]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/swap.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MTHP	(64 * 1024)
#define PAGE	4096
#define AREA_PRIME	((char *)0x300000000UL)	/* primes cpu 0's mthp cluster */
#define AREA_RACE	((char *)0x200000000UL)	/* the raced mthp + one page */

static const char *dev;
static _Atomic int round_no, a_done, b_done;
static _Atomic long long t_go, b_delay;	/* ns */
static long long a_time;		/* side a's madvise() duration */
static _Atomic int *rounds;		/* rounds done, shared with the parent */
static const char *ok = "[+]", *warn = "[~]", *err = "[-]";
static volatile sig_atomic_t timed_out;

static void __attribute__((noreturn)) die(const char *msg)
{
	fprintf(stderr, "%s swapoff: %s: %s\n", err, msg, strerror(errno));
	exit(2);
}

static long long now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void spin_until(long long t)
{
	while (now_ns() < t)
		;
}

static void pin(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set))
		die("sched_setaffinity");
}

static void map_fixed(char *addr, size_t len, int fill)
{
	if (mmap(addr, len, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != addr)
		die("mmap");
	memset(addr, fill, len);	/* non-zero: zero pages are not written */
}

static void *side_a(void *arg)
{
	int seen = 0;

	pin(0);
	prctl(PR_SET_NAME, "madvise-a");
	for (;;) {
		while (round_no == seen)
			;
		seen = round_no;
		/* a first mthp, so the raced one takes the per-cpu fast path */
		map_fixed(AREA_PRIME, MTHP, 0x3c);
		if (madvise(AREA_PRIME, MTHP, MADV_PAGEOUT))
			die("madvise");
		map_fixed(AREA_RACE, MTHP + PAGE, 0x5a);
		spin_until(t_go);
		madvise(AREA_RACE, MTHP + PAGE, MADV_PAGEOUT);
		a_time = now_ns() - t_go;
		a_done = seen;
	}
	return arg;
}

static void *side_b(void *arg)
{
	int seen = 0;

	pin(1);
	prctl(PR_SET_NAME, "swapoff-b");
	for (;;) {
		while (round_no == seen)
			;
		seen = round_no;
		spin_until(t_go + b_delay);
		if (swapoff(dev))
			die("swapoff");
		b_done = seen;
	}
	return arg;
}

/* the racing process: one swapon/race/swapoff round per iteration */
static void racer(void)
{
	long long window = 400000, start, deadline;
	pthread_t a, b;
	int n;

	srand(getpid());
	pthread_create(&a, NULL, side_a, NULL);
	pthread_create(&b, NULL, side_b, NULL);
	pin(2);
	for (n = 1;; n++) {
		if (swapon(dev, 0))
			die("swapon");
		/* sweep swapoff's start over side a's madvise() and a bit before */
		b_delay = rand() % (window + 50000) - 50000;
		t_go = now_ns() + 2000000;
		round_no = n;
		start = now_ns();
		deadline = start + 3000000000LL;
		while ((a_done != n || b_done != n) && now_ns() < deadline)
			;
		if (a_done != n || b_done != n) {
			printf("STUCK %d %d %d\n", n, a_done == n, b_done == n);
			fflush(stdout);
			pause();
		}
		/* track side a's madvise() duration, so the sweep covers it */
		window = (window * 7 + a_time + a_time / 4) / 8;
		*rounds = n;
		if (n % 2000 == 0) {
			printf("ROUND %d\n", n);
			fflush(stdout);
		}
	}
}

static void on_alarm(int sig)
{
	(void)sig;
	timed_out = 1;
}

int main(int argc, char **argv)
{
	int limit = argc > 2 ? atoi(argv[2]) : 600;
	struct sigaction sa = { .sa_handler = on_alarm };
	int pfd[2], n, a_ret, b_ret;
	char line[128];
	long long start;
	double secs;
	pid_t child;
	FILE *in;

	if (argc < 2) {
		fprintf(stderr, "usage: %s DEVICE [SECONDS]\n", argv[0]);
		return 2;
	}
	dev = argv[1];
	if (isatty(STDOUT_FILENO)) {
		ok = "\033[32m[+]\033[0m";
		warn = "\033[33m[~]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	rounds = mmap(NULL, sizeof(*rounds), PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (rounds == MAP_FAILED)
		die("mmap");
	if (pipe(pfd))
		die("pipe");
	start = now_ns();
	child = fork();
	if (child < 0)
		die("fork");
	if (child == 0) {
		dup2(pfd[1], STDOUT_FILENO);
		close(pfd[0]);
		racer();
	}
	close(pfd[1]);
	/* no SA_RESTART: the alarm ends the blocking fgets() below */
	sigaction(SIGALRM, &sa, NULL);
	alarm(limit);
	in = fdopen(pfd[0], "r");
	while (!timed_out && fgets(line, sizeof(line), in)) {
		secs = (now_ns() - start) / 1e9;
		if (sscanf(line, "ROUND %d", &n) == 1) {
			printf("swapoff: %d rounds, %.0f s\n", n, secs);
			continue;
		}
		if (sscanf(line, "STUCK %d %d %d", &n, &a_ret, &b_ret) != 3)
			continue;
		printf("swapoff: round %d, after 3 s: madvise() %s, swapoff() %s\n", n,
		       a_ret ? "returned" : "has not returned",
		       b_ret ? "returned" : "has not returned");
		/* the slot search loops in side a's madvise(): no bug without it */
		if (a_ret) {
			printf("%s swapoff: only swapoff() has not returned: not this bug\n", warn);
			return 3;
		}
		printf("%s swapoff: bug: madvise() has not returned (round %d, %.1f s)\n", ok, n, secs);
		printf("LB-RESULT bug rounds=%d seconds=%.1f\n", n, secs);
		return 0;
	}
	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	if (!timed_out) {
		fprintf(stderr, "%s swapoff: the racing process exited\n", err);
		return 2;
	}
	secs = (now_ns() - start) / 1e9;
	printf("%s swapoff: no bug in %d rounds, %.1f s\n", ok, *rounds, secs);
	printf("LB-RESULT none rounds=%d seconds=%.1f\n", *rounds, secs);
	return 1;
}

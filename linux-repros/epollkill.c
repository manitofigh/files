// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: epollkill [SECONDS]
 *
 * SECONDS is how long to keep trying (300 by default).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define WAIT_MS 2000	/* how long B gets to wake up */

static int tty;

static void say(const char *c, const char *fmt, const char *arg)
{
	if (!tty)
		return;
	printf("%s ", c);
	printf(fmt, arg);
	putchar('\n');
	fflush(stdout);
}

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec / 1e9;
}

static void pin(int cpu)
{
	cpu_set_t s;

	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	if (sched_setaffinity(0, sizeof(s), &s)) {
		perror("sched_setaffinity");
		exit(2);
	}
}

/* process state letter from /proc/PID/stat */
static char state(pid_t pid)
{
	char path[64], buf[512], *p;
	FILE *f;
	size_t n;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	f = fopen(path, "r");
	if (!f)
		return '?';
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = 0;
	p = strrchr(buf, ')');
	return p && p[1] ? p[2] : '?';
}

static void wchan(pid_t pid, char *out, size_t len)
{
	char path[64];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/wchan", pid);
	out[0] = 0;
	f = fopen(path, "r");
	if (f) {
		if (!fgets(out, len, f))
			out[0] = 0;
		fclose(f);
	}
}

/* fork a waiter on @cpu; returns once it sleeps in epoll_wait() */
static pid_t waiter(int ep, int cpu, int idle, int done)
{
	int go[2];
	pid_t pid;
	char c;

	if (pipe(go))
		return -1;
	pid = fork();
	if (pid < 0)
		return -1;
	if (!pid) {
		struct sched_param sp = { 0 };
		struct epoll_event ev;

		pin(cpu);
		if (idle)
			sched_setscheduler(0, SCHED_IDLE, &sp);
		close(go[0]);
		if (write(go[1], "w", 1) != 1)
			_exit(2);
		if (epoll_wait(ep, &ev, 1, -1) == 1 && done >= 0 &&
		    write(done, "B", 1) != 1)
			_exit(2);
		_exit(0);
	}
	close(go[1]);
	if (read(go[0], &c, 1) != 1)
		return -1;
	close(go[0]);
	/* after the handshake, the next sleep is the one in epoll_wait() */
	while (state(pid) != 'S')
		usleep(1000);
	usleep(1000);
	return pid;
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	double t0 = now();
	unsigned long rounds = 0;
	int hit = 0;
	cpu_set_t all;

	tty = isatty(1);
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (ncpu < 2) {
		printf("epollkill: needs 2 CPUs\n");
		return 2;
	}
	sched_getaffinity(0, sizeof(all), &all);
	srand(getpid());

	while (now() - t0 < limit) {
		struct epoll_event ev = { .events = EPOLLIN };
		struct pollfd pfd;
		uint64_t one = 1;
		int efd, ep, done[2], n, ready;
		pid_t a, b;
		char w[64];

		rounds++;
		efd = eventfd(0, 0);
		ep = epoll_create1(0);
		if (efd < 0 || ep < 0 || pipe(done)) {
			perror("epollkill: setup");
			return 2;
		}
		ev.data.fd = efd;
		if (epoll_ctl(ep, EPOLL_CTL_ADD, efd, &ev)) {
			perror("epoll_ctl");
			return 2;
		}

		/* B waits first, A last: A is first in line for the wakeup */
		b = waiter(ep, 1, 0, done[1]);
		a = waiter(ep, 0, 1, -1);
		if (a < 0 || b < 0) {
			perror("epollkill: fork");
			return 2;
		}

		/* same CPU as A, which is SCHED_IDLE: A cannot run before the kill */
		pin(0);
		usleep(rand() % 1000);
		if (write(efd, &one, sizeof(one)) != sizeof(one)) {
			perror("epollkill: eventfd write");
			return 2;
		}
		kill(a, SIGKILL);
		waitpid(a, NULL, 0);
		sched_setaffinity(0, sizeof(all), &all);

		/* the eventfd stays readable; B must wake up and report it */
		pfd = (struct pollfd){ .fd = done[0], .events = POLLIN };
		n = poll(&pfd, 1, WAIT_MS);
		pfd = (struct pollfd){ .fd = efd, .events = POLLIN };
		ready = poll(&pfd, 1, 0) == 1;
		if (!n && ready && state(b) == 'S') {
			struct epoll_event e;
			char msg[256];

			wchan(b, w, sizeof(w));
			snprintf(msg, sizeof(msg),
				 "LB-LOST-WAKEUP B (pid %d, %s) asleep in epoll_wait() for %d ms, epoll_wait(ep, 0) finds %d ready event(s)",
				 b, w[0] ? w : "?", WAIT_MS, epoll_wait(ep, &e, 1, 0));
			printf("%s\n", msg);
			say("\033[32m[+]\033[0m", "%s", "the wakeup was lost");
			hit = 1;
		}
		kill(b, SIGKILL);
		waitpid(b, NULL, 0);
		close(efd);
		close(ep);
		close(done[0]);
		close(done[1]);
		if (hit)
			break;
		if (rounds % 200 == 0) {
			snprintf(w, sizeof(w), "%lu rounds, no lost wakeup", rounds);
			say("\033[33m[~]\033[0m", "%s", w);
		}
	}
	printf("LB-RESULT %s rounds=%lu seconds=%.1f\n", hit ? "bug" : "none",
	       rounds, now() - t0);
	return hit ? 0 : 1;
}

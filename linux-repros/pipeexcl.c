// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: pipeexcl [SECONDS]
 *
 * SECONDS is how long to keep trying (300 by default).
 */
#define _GNU_SOURCE
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define WAIT_MS 2000	/* how long A gets to wake up */

#ifndef EPOLL_FLAGS
#define EPOLL_FLAGS (EPOLLIN | EPOLLEXCLUSIVE)
#endif

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

/* wait until @pid sleeps */
static void asleep(pid_t pid)
{
	while (state(pid) != 'S')
		usleep(1000);
	usleep(1000);
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	double t0 = now();
	unsigned long rounds = 0;
	int hit = 0;

	tty = isatty(1);
	setvbuf(stdout, NULL, _IOLBF, 0);
	srand(getpid());

	while (now() - t0 < limit) {
		struct epoll_event ev = { .events = EPOLL_FLAGS };
		int p[2], woke[2], go[2], done[2], ep, n, ready;
		struct pollfd pfd;
		pid_t e, a;
		char c, w[64];

		rounds++;
		ep = epoll_create1(0);
		if (ep < 0 || pipe(p) || pipe(woke) || pipe(go) || pipe(done) ||
		    epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev)) {
			perror("pipeexcl: setup");
			return 2;
		}

		/* E: an epoll watcher that takes one byte and leaves */
		e = fork();
		if (!e) {
			if (epoll_wait(ep, &ev, 1, -1) != 1 ||
			    write(woke[1], "e", 1) != 1 ||
			    read(go[0], &c, 1) != 1 ||
			    read(p[0], &c, 1) != 1)
				_exit(2);
			_exit(0);
		}
		if (e > 0)
			asleep(e);

		/* A: a plain blocking reader, queued after E's epoll entry */
		a = fork();
		if (!a) {
			if (read(p[0], &c, 1) != 1 || write(done[1], "a", 1) != 1)
				_exit(2);
			_exit(0);
		}
		if (a < 0 || e < 0) {
			perror("pipeexcl: fork");
			return 2;
		}
		asleep(a);

		/* the pipe is empty: one wakeup, which E's epoll_wait() takes */
		if (write(p[1], "1", 1) != 1) {
			perror("pipeexcl: write");
			return 2;
		}
		pfd = (struct pollfd){ .fd = woke[0], .events = POLLIN };
		poll(&pfd, 1, 100);
		/* a second byte before E reads, then E takes one and exits */
		usleep(rand() % 1000);
		if (write(p[1], "2", 1) != 1 || write(go[1], "g", 1) != 1) {
			perror("pipeexcl: write");
			return 2;
		}
		waitpid(e, NULL, 0);

		/* one byte is left; A must wake up and read it */
		pfd = (struct pollfd){ .fd = done[0], .events = POLLIN };
		n = poll(&pfd, 1, WAIT_MS);
		pfd = (struct pollfd){ .fd = p[0], .events = POLLIN };
		ready = poll(&pfd, 1, 0) == 1;
		if (!n && ready && state(a) == 'S') {
			wchan(a, w, sizeof(w));
			printf("LB-LOST-WAKEUP A (pid %d, %s) asleep in read() for %d ms, the pipe holds %d byte(s)\n",
			       a, w[0] ? w : "?", WAIT_MS, ready);
			say("\033[32m[+]\033[0m", "%s", "the wakeup was lost");
			hit = 1;
		}
		kill(a, SIGKILL);
		waitpid(a, NULL, 0);
		close(ep);
		close(p[0]);
		close(p[1]);
		close(woke[0]);
		close(woke[1]);
		close(go[0]);
		close(go[1]);
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

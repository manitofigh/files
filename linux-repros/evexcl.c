// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: evexcl [SECONDS]
 *
 * SECONDS is how long to keep trying (300 by default).
 */
#define _GNU_SOURCE
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
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
		struct itimerspec its = { .it_value.tv_nsec = 1000000 };
		int timer = rand() & 1, fd, ep, woke[2], done[2], n, ready;
		const char *name = timer ? "timerfd" : "eventfd";
		struct pollfd pfd;
		uint64_t v = 1;
		pid_t e, a;
		char w[64];

		rounds++;
		fd = timer ? timerfd_create(CLOCK_MONOTONIC, 0) : eventfd(0, 0);
		ep = epoll_create1(0);
		if (fd < 0 || ep < 0 || pipe(woke) || pipe(done) ||
		    epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev)) {
			perror("evexcl: setup");
			return 2;
		}

		/* E: an epoll watcher, killed after its wakeup before it reads */
		e = fork();
		if (!e) {
			if (epoll_wait(ep, &ev, 1, -1) == 1 &&
			    write(woke[1], "e", 1) == 1)
				pause();
			_exit(2);
		}
		if (e > 0)
			asleep(e);

		/* A: a plain blocking reader, queued after E's epoll entry */
		a = fork();
		if (!a) {
			if (read(fd, &v, sizeof(v)) != sizeof(v) ||
			    write(done[1], "a", 1) != 1)
				_exit(2);
			_exit(0);
		}
		if (a < 0 || e < 0) {
			perror("evexcl: fork");
			return 2;
		}
		asleep(a);

		usleep(rand() % 1000);
		if (timer ? timerfd_settime(fd, 0, &its, NULL) :
			    write(fd, &v, sizeof(v)) != sizeof(v)) {
			perror("evexcl: signal");
			return 2;
		}
		pfd = (struct pollfd){ .fd = woke[0], .events = POLLIN };
		poll(&pfd, 1, 100);
		kill(e, SIGKILL);
		waitpid(e, NULL, 0);

		/* the file stays readable; A must wake up and read it */
		pfd = (struct pollfd){ .fd = done[0], .events = POLLIN };
		n = poll(&pfd, 1, WAIT_MS);
		pfd = (struct pollfd){ .fd = fd, .events = POLLIN };
		ready = poll(&pfd, 1, 0) == 1;
		if (!n && ready && state(a) == 'S') {
			char msg[256];

			wchan(a, w, sizeof(w));
			snprintf(msg, sizeof(msg),
				 "LB-LOST-WAKEUP A (pid %d, %s) asleep in read() of a readable %s for %d ms",
				 a, w[0] ? w : "?", name, WAIT_MS);
			printf("%s\n", msg);
			say("\033[32m[+]\033[0m", "%s", "the wakeup was lost");
			hit = 1;
		}
		kill(a, SIGKILL);
		waitpid(a, NULL, 0);
		close(fd);
		close(ep);
		close(woke[0]);
		close(woke[1]);
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

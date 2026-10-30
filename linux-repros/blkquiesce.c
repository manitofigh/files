// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: blkquiesce [SECONDS] (needs root)
 *
 * It needs a connected nvme-loop subsystem named "blkquiesce" with
 * namespaces 1 to 8.
 * SECONDS is how long to keep trying (300 by default).
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NQN	"blkquiesce"
#define NS_DIR	"/sys/kernel/config/nvmet/subsystems/" NQN "/namespaces"
#define NR_NS	8
#define HOG_CPU	1	/* run.sh puts nvme-reset-wq here, nvme-wq on CPU 0 */

static const char *ok = "[+]", *warn = "[~]", *err = "[-]";
static char ctrl[64];		/* /sys/class/nvme/nvmeX */
static int kmsg = -1;
static volatile int stop, resetting, busy;
static volatile long resets;

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

static int get(const char *path, char *buf, size_t len)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, len - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = 0;
	return 0;
}

static void spin_us(long us)
{
	double end = now() + us / 1e6;

	while (now() < end)
		;
}

static void sleep_us(long us)
{
	struct timespec ts = { us / 1000000, us % 1000000 * 1000 };

	nanosleep(&ts, NULL);
}

/* the host controller connected to our subsystem */
static int find_ctrl(void)
{
	char path[300], buf[256];
	struct dirent *d;
	DIR *dir = opendir("/sys/class/nvme");

	if (!dir)
		return -1;
	while ((d = readdir(dir))) {
		if (strncmp(d->d_name, "nvme", 4))
			continue;
		snprintf(path, sizeof(path), "/sys/class/nvme/%s/subsysnqn", d->d_name);
		if (!get(path, buf, sizeof(buf)) && !strncmp(buf, NQN, strlen(NQN))) {
			snprintf(ctrl, sizeof(ctrl), "/sys/class/nvme/%.32s", d->d_name);
			closedir(dir);
			return 0;
		}
	}
	closedir(dir);
	return -1;
}

/* namespaces (block devices) the host has for this controller */
static int host_ns(void)
{
	struct dirent *d;
	DIR *dir = opendir(ctrl);
	const char *name = strrchr(ctrl, '/') + 1;
	size_t len = strlen(name);
	int n = 0;

	if (!dir)
		return -1;
	while ((d = readdir(dir)))
		if (!strncmp(d->d_name, name, len) && d->d_name[len] == 'n')
			n++;
	closedir(dir);
	return n;
}

static int ns_enable(int nsid, int on)
{
	char path[128];

	snprintf(path, sizeof(path), NS_DIR "/%d/enable", nsid);
	return put(path, on ? "1" : "0");
}

/* the kernel reported something: a line from /dev/kmsg, in our own words */
static const char *kernel_report(void)
{
	static const char *const keys[][2] = {
		{ "KASAN:", "KASAN report" },
		{ "general protection fault", "general protection fault" },
		{ "BUG:", "kernel bug report" },
		{ "WARNING:", "kernel warning" },
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

/* reset the controller again and again while the namespaces go away */
static void *resetter(void *arg)
{
	char path[128];

	(void)arg;
	pin(0);
	snprintf(path, sizeof(path), "%.64s/reset_controller", ctrl);
	while (!stop) {
		if (!resetting) {
			sleep_us(1000);
			continue;
		}
		busy = 1;
		if (!resetting) {
			busy = 0;
			continue;
		}
		put(path, "1");
		busy = 0;
		resets++;
	}
	return NULL;
}

/* SCHED_FIFO on the CPU of the reset worker: preempts it at random points */
static void *hog(void *arg)
{
	struct sched_param sp = { .sched_priority = 50 };
	unsigned int seed = 1;

	(void)arg;
	pin(HOG_CPU);
	if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp))
		printf("%s blkquiesce: no SCHED_FIFO (%s), the race is narrower\n",
		       warn, strerror(errno));
	while (!stop) {
		if (!resetting) {
			sleep_us(1000);
			continue;
		}
		/* a short run for the worker, then 15-40 ms off its CPU */
		sleep_us(rand_r(&seed) % 200);
		spin_us(15000 + rand_r(&seed) % 25000);
	}
	return NULL;
}

/* all namespaces on the target and on the host, no reset running */
static int fill(void)
{
	char path[128];
	double t0 = now();

	for (int i = 1; i <= NR_NS; i++)
		ns_enable(i, 1);
	snprintf(path, sizeof(path), "%.64s/rescan_controller", ctrl);
	put(path, "1");
	while (host_ns() < NR_NS) {
		if (now() - t0 > 20)
			return -1;
		sleep_us(2000);
	}
	sleep_us(20000);	/* let the scan finish */
	return 0;
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	unsigned int seed = getpid();
	const char *report = NULL;
	pthread_t rt, ht;
	double t0, last;
	long round;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (isatty(STDOUT_FILENO)) {
		ok = "\033[32m[+]\033[0m";
		warn = "\033[33m[~]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	if (find_ctrl()) {
		printf("%s blkquiesce: no nvme controller for %s (run.sh sets it up)\n", err, NQN);
		return 2;
	}
	kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (kmsg < 0) {
		printf("%s blkquiesce: /dev/kmsg: %s\n", err, strerror(errno));
		return 2;
	}
	lseek(kmsg, 0, SEEK_END);
	pin(0);
	pthread_create(&rt, NULL, resetter, NULL);
	pthread_create(&ht, NULL, hog, NULL);

	t0 = last = now();
	for (round = 1; now() - t0 < limit; round++) {
		if (fill()) {
			printf("%s blkquiesce: the host did not get all %d namespaces back in round %ld\n",
			       err, NR_NS, round);
			stop = 1;
			pthread_join(rt, NULL);
			pthread_join(ht, NULL);
			return 2;
		}
		/* resets, while the namespaces but the first are taken away */
		resetting = 1;
		for (int i = 2; i <= NR_NS; i++) {
			sleep_us(rand_r(&seed) % 4000);
			ns_enable(i, 0);
		}
		for (double t = now(); host_ns() > 1 && now() - t < 10; )
			sleep_us(2000);
		resetting = 0;
		while (busy)
			sleep_us(1000);
		if ((report = kernel_report()))
			break;
		if (now() - last >= 10) {
			last = now();
			printf("blkquiesce: round %ld, %.0f s, %ld resets\n", round, last - t0, resets);
		}
	}
	double secs = now() - t0;

	stop = 1;
	pthread_join(rt, NULL);
	pthread_join(ht, NULL);
	if (!report) {
		usleep(200000);
		report = kernel_report();
	}
	if (report) {
		printf("LB-RESULT bug rounds=%ld seconds=%.1f\n", round, secs);
		printf("%s blkquiesce: bug: the kernel reported a %s (round %ld, %.1f s, %ld resets)\n",
		       ok, report, round, secs, resets);
		return 0;
	}
	printf("LB-RESULT none rounds=%ld seconds=%.1f\n", round - 1, secs);
	printf("%s blkquiesce: no report in %ld rounds, %.1f s, %ld resets\n",
	       ok, round - 1, secs, resets);
	return 1;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: wdboot [SECONDS] (needs root)
 *
 * SECONDS is how long to keep trying (300 by default).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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

int main(int argc, char **argv)
{
	double limit = argc > 1 ? atof(argv[1]) : 300, t0, last;
	char buf[64], path[96];
	unsigned long rounds = 0;
	int cpu, r;

	if (isatty(1)) {
		ok = "\033[32m[+]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	setvbuf(stdout, NULL, _IOLBF, 0);

	if (get("/sys/devices/system/clocksource/clocksource0/current_clocksource",
		buf, sizeof(buf)) || strcmp(buf, "jiffies")) {
		printf("%s wdboot: the clocksource is '%s', not jiffies (boot with clocksource=jiffies)\n",
		       err, buf);
		return 2;
	}
	/* the last online CPU goes offline and online again */
	if (get("/sys/devices/system/cpu/online", buf, sizeof(buf)) ||
	    (cpu = atoi(strrchr(buf, '-') ? strrchr(buf, '-') + 1 : buf)) < 1) {
		printf("%s wdboot: needs 2 or more CPUs (online: %s)\n", err, buf);
		return 2;
	}
	snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/online", cpu);

	t0 = last = now();
	while (now() - t0 < limit) {
		if ((r = put(path, "0")) || (r = put(path, "1"))) {
			printf("%s wdboot: cpu%d offline/online: %s\n", err, cpu, strerror(-r));
			return 2;
		}
		rounds++;
		if (now() - last >= 10) {
			last = now();
			printf("wdboot: %lu rounds, %.0f s\n", rounds, last - t0);
		}
	}
	printf("%s wdboot: no hang in %lu rounds\n", ok, rounds);
	printf("LB-RESULT none rounds=%lu seconds=%.1f\n", rounds, now() - t0);
	return 1;
}

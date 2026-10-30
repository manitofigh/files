// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: ksoftpark [SECONDS] [CPU] (needs root)
 *
 * SECONDS is how long to keep trying (300 by default).
 * CPU is the CPU to offline (the last one by default).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PORT	9	/* discard: a bound socket nobody reads */
#define WARMUP	2	/* s of load before each offline */
#define STUCK	10	/* s before an offline counts as stuck */
#define HUNG	90	/* s to wait for the hung task report */
#define DRAIN	60	/* s for the offline to finish once the load stops */
#define MAXSEND	64

static const char *ok = "[+]", *warn = "[~]", *err = "[-]";
static pid_t senders[MAXSEND];
static int nsend;

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

static int gone(pid_t pid)
{
	int st;
	return waitpid(pid, &st, WNOHANG) == pid;
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

/* softnet_stat of one CPU: packets processed, dropped, time squeezes */
static int softnet(int cpu, unsigned long *v)
{
	char line[512];
	FILE *f = fopen("/proc/net/softnet_stat", "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		unsigned long x[13];
		if (sscanf(line, "%lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx",
			   &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &x[6], &x[7], &x[8],
			   &x[9], &x[10], &x[11], &x[12]) == 13 && (int)x[12] == cpu) {
			v[0] = x[0], v[1] = x[1], v[2] = x[2];
			fclose(f);
			return 0;
		}
	}
	fclose(f);
	return -1;
}

static int lo_up(void)
{
	struct ifreq ifr = { .ifr_name = "lo" };
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0 || ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
		return -1;
	ifr.ifr_flags |= IFF_UP;
	int r = ioctl(s, SIOCSIFFLAGS, &ifr);
	close(s);
	return r;
}

static void start_senders(int ncpu, int target)
{
	nsend = 0;
	for (int c = 0; c < ncpu; c++) {
		/* CPU 0 runs the offline */
		if (c == target || (c == 0 && ncpu > 3))
			continue;
		for (int i = 0; i < 2 && nsend < MAXSEND; i++) {
			pid_t p = fork();
			if (p == 0) {
				struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(PORT),
							 .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
				char msg[32] = "ksoftpark";
				int s = socket(AF_INET, SOCK_DGRAM, 0);
				pin(c);
				for (;;)
					sendto(s, msg, sizeof(msg), MSG_DONTWAIT, (void *)&a, sizeof(a));
			}
			senders[nsend++] = p;
		}
	}
}

static void stop_senders(void)
{
	for (int i = 0; i < nsend; i++)
		kill(senders[i], SIGKILL);
	for (int i = 0; i < nsend; i++)
		waitpid(senders[i], NULL, 0);
	nsend = 0;
}

/* new kernel log lines that match pat, from /dev/kmsg (opened at the end) */
static int kmsg_has(int fd, const char *pat)
{
	char rec[2048];
	int found = 0;
	ssize_t n;
	while ((n = read(fd, rec, sizeof(rec) - 1)) > 0 || (n < 0 && errno == EPIPE)) {
		if (n < 0)
			continue;
		rec[n] = 0;
		if (strstr(rec, pat))
			found = 1;
	}
	return found;
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	int target = argc > 2 ? atoi(argv[2]) : ncpu - 1;
	char buf[128], online[128];
	double t0 = now(), slowest = 0;
	int round;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (isatty(STDOUT_FILENO)) {
		ok = "\033[32m[+]\033[0m";
		warn = "\033[33m[~]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	if (ncpu < 3 || target < 1 || target >= ncpu) {
		printf("%s ksoftpark: needs 3 or more online CPUs and a CPU other than 0 to offline\n",
		       err);
		return 2;
	}
	snprintf(online, sizeof(online), "/sys/devices/system/cpu/cpu%d/online", target);
	snprintf(buf, sizeof(buf), "%x", 1 << target);
	if (lo_up() < 0 || put("/sys/class/net/lo/queues/rx-0/rps_cpus", buf) < 0) {
		printf("%s ksoftpark: cannot bring up lo or set its rps_cpus\n", err);
		return 2;
	}
	if (put(online, "1") < 0) {
		printf("%s ksoftpark: cannot online cpu%d\n", err, target);
		return 2;
	}

	/* the receiving socket; nobody reads it, so a full queue drops at once */
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(PORT),
				 .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	int rx = socket(AF_INET, SOCK_DGRAM, 0);
	if (rx < 0 || bind(rx, (void *)&a, sizeof(a)) < 0) {
		printf("%s ksoftpark: cannot bind 127.0.0.1:%d\n", err, PORT);
		return 2;
	}
	int kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (kmsg >= 0)
		lseek(kmsg, 0, SEEK_END);

	pin(0);
	for (round = 1; now() - t0 < limit; round++) {
		unsigned long s0[3] = { 0 }, s1[3] = { 0 };

		start_senders(ncpu, target);
		softnet(target, s0);
		sleep(WARMUP);
		softnet(target, s1);
		pid_t off = fork();
		if (off == 0) {
			pin(0);
			_exit(put(online, "0") ? 1 : 0);
		}
		double ta = now();
		while (!gone(off) && now() - ta < STUCK)
			usleep(10000);
		if (!task_state(off)) {
			double took = now() - ta;
			stop_senders();
			if (took > slowest)
				slowest = took;
			if (round == 1 || round % 20 == 0)
				printf("ksoftpark: round %d: cpu%d receiving %lu packets/s (%lu dropped/s, "
				       "%lu time squeezes/s); offline took %.3f s\n", round, target,
				       (s1[0] - s0[0]) / WARMUP, (s1[1] - s0[1]) / WARMUP,
				       (s1[2] - s0[2]) / WARMUP, took);
			if (put(online, "1") < 0) {
				printf("%s ksoftpark: cannot online cpu%d again\n", err, target);
				return 2;
			}
			continue;
		}

		double secs = now() - t0;
		printf("ksoftpark: round %d: cpu%d receiving %lu packets/s (%lu dropped/s, "
		       "%lu time squeezes/s)\n", round, target, (s1[0] - s0[0]) / WARMUP,
		       (s1[1] - s0[1]) / WARMUP, (s1[2] - s0[2]) / WARMUP);
		printf("ksoftpark: the offline of cpu%d has not returned after %d s (state %c); "
		       "keeping the load on\n", target, STUCK, task_state(off));
		/* a cpus_read_lock() user, blocked behind the offline */
		pid_t rd = fork();
		if (rd == 0) {
			pin(1);
			_exit(put("/proc/sys/vm/stat_refresh", "1") ? 1 : 0);
		}
		double th = now();
		int hung = 0;
		while (!gone(off) && now() - th < HUNG) {
			if (kmsg >= 0 && kmsg_has(kmsg, "blocked for more than")) {
				hung = 1;
				break;
			}
			sleep(1);
		}
		if (!task_state(off)) {
			printf("%s ksoftpark: the offline of cpu%d finished after %.1f s with the load "
			       "still on\n", warn, target, now() - ta);
			if (now() - ta > slowest)
				slowest = now() - ta;
			stop_senders();
			waitpid(rd, NULL, 0);
			put(online, "1");
			continue;
		}
		printf("ksoftpark: %s after %.0f s with the offline still waiting; stopping "
		       "the senders\n", hung ? "hung task report" : "no hung task report",
		       now() - ta);
		/* let the hung task reports finish before the load goes */
		sleep(5);
		double ts = now();
		stop_senders();
		while (!gone(off) && now() - ts < DRAIN)
			usleep(10000);
		int done = !task_state(off);
		printf("LB-OFFLINE-STUCK cpu=%d waited=%.1f s, %s\n", target, ts - ta,
		       done ? "finished" : "still waiting");
		if (done)
			printf("ksoftpark: the offline of cpu%d finished %.2f s after the senders "
			       "stopped (it had waited %.1f s with the load on)\n", target,
			       now() - ts, ts - ta);
		else
			printf("%s ksoftpark: the offline of cpu%d is still waiting %d s after the "
			       "senders stopped\n", warn, target, DRAIN);
		waitpid(rd, NULL, WNOHANG);
		printf("LB-RESULT bug rounds=%d seconds=%.1f\n", round, secs);
		printf("%s ksoftpark: bug: offlining cpu%d waited as long as it received "
		       "packets (round %d, %.1f s)\n", ok, target, round, secs);
		return 0;
	}
	double secs = now() - t0;
	printf("LB-RESULT none rounds=%d seconds=%.1f\n", round - 1, secs);
	printf("%s ksoftpark: every offline of cpu%d finished under load in %d rounds, %.1f s "
	       "(the slowest took %.3f s)\n", ok, target, round - 1, secs, slowest);
	return 1;
}

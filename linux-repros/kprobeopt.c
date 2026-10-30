// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: kprobeopt [SECONDS [CASE]] (needs root, tracefs and debugfs mounted)
 *
 * SECONDS is how long to keep trying (300 by default).
 * CASE is 1 (int3 left in the text, the default), 2 or 3 (a probe that never fires).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define T	"/sys/kernel/tracing"
#define LIST	"/sys/kernel/debug/kprobes/list"
#define OPTSYS	"/proc/sys/debug/kprobes-optimization"
#define MAXOFF	96
#define CALLS	1000
#define SETTLE	1000	/* ms for a dispatch, its grace period and finalize */

/* F is called by sysinfo(2); G is only a second optimized probe */
static const char *const fnames[] = { "__do_sys_sysinfo", "__x64_sys_sysinfo" };
static const char *const gnames[] = { "__do_sys_newuname", "__x64_sys_newuname",
				      "__x64_sys_getppid" };

static const char *ok = "[+]", *warn = "[~]", *err = "[-]";
static int kmsg = -1;
static const char *F, *G;
static int o1, o2, o3;	/* k1 at F+o1, k2 at F+o2 inside k1's jump, k3 at G+o3 */

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void msleep(int ms)
{
	usleep(ms * 1000);
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

static int slurp(const char *path, char *buf, size_t size)
{
	int fd = open(path, O_RDONLY);
	size_t len = 0;
	ssize_t n;

	if (fd < 0)
		return -1;
	while (len < size - 1 && (n = read(fd, buf + len, size - 1 - len)) > 0)
		len += n;
	close(fd);
	buf[len] = 0;
	return 0;
}

/* add "p:NAME FN+OFF" to kprobe_events */
static int add(const char *name, const char *fn, int off)
{
	char cmd[128];

	snprintf(cmd, sizeof(cmd), "p:%s %s+%d", name, fn, off);
	return put(T "/kprobe_events", cmd);
}

static int del(const char *name)
{
	char cmd[64];

	snprintf(cmd, sizeof(cmd), "-:%s", name);
	return put(T "/kprobe_events", cmd);
}

static int enable(const char *name, int on)
{
	char path[128];

	snprintf(path, sizeof(path), T "/events/kprobes/%s/enable", name);
	return put(path, on ? "1" : "0");
}

static int optsys(int on)
{
	return put(OPTSYS, on ? "1" : "0");
}

/* the probe at FN+OFF: -1 not listed, 0 listed, 1 optimized */
static int state(const char *fn, int off)
{
	static char buf[65536];
	char key[96], *p, *eol;

	if (slurp(LIST, buf, sizeof(buf)))
		return -1;
	snprintf(key, sizeof(key), " %s+0x%x ", fn, off);
	p = strstr(buf, key);
	if (!p)
		return -1;
	eol = strchr(p, '\n');
	if (eol)
		*eol = 0;
	return strstr(p, "[OPTIMIZED]") ? 1 : 0;
}

/* the OPTIMIZED flag is set when the probe is queued: give the optimizer time */
static int wait_optimized(const char *fn, int off, int ms)
{
	for (int t = 0; t < ms; t += 10) {
		if (state(fn, off) == 1) {
			msleep(SETTLE);
			return 0;
		}
		msleep(10);
	}
	return -1;
}

static long hits(const char *name)
{
	char buf[8192], key[64], *p;

	if (slurp(T "/kprobe_profile", buf, sizeof(buf)))
		return -1;
	snprintf(key, sizeof(key), " %s ", name);
	p = strstr(buf, key);
	return p ? atol(p + strlen(key)) : -1;
}

/* remove every probe and let the optimizer finish with them */
static void reset(void)
{
	enable("k1", 0);
	enable("k2", 0);
	enable("k3", 0);
	enable("ks", 0);
	put(T "/events/kprobes/enable", "0");
	del("k1");
	del("k2");
	del("k3");
	del("ks");
	/* turning optimization off waits until the optimizer has no work left */
	optsys(0);
	optsys(1);
}

/* the kernel reported this bug: a line from /dev/kmsg, in our own words */
static const char *kernel_report(void)
{
	static const char *const keys[][2] = {
		{ "Oops: int3", "int3 oops (no kprobe behind the int3)" },
		{ "KASAN:", "KASAN report" },
		{ "kernel BUG", "kernel BUG" },
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

/* run F CALLS times in a child: 0 fine, 1 the child died (oops), -1 error */
static int call_f(void)
{
	int status;
	pid_t pid = fork();

	if (pid < 0)
		return -1;
	if (pid == 0) {
		struct sysinfo si;

		for (int i = 0; i < CALLS; i++)
			sysinfo(&si);
		_exit(0);
	}
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}

/* offsets in FN where a probe can be registered (instruction boundaries) */
static int boundaries(const char *fn, int *offs)
{
	int n = 0;

	for (int off = 1; off < MAXOFF; off++) {
		if (add("ks", fn, off))
			continue;
		del("ks");
		offs[n++] = off;
	}
	return n;
}

static int optimizable(const char *fn, int off)
{
	int r;

	if (add("ks", fn, off) || enable("ks", 1)) {
		del("ks");
		return 0;
	}
	r = !wait_optimized(fn, off, 2000);
	/* F must run on sysinfo(2) */
	if (r && fn == F)
		r = !call_f() && hits("ks") > 0;
	reset();
	return r;
}

/* find k1/k2 in F (two boundaries less than 5 bytes apart, k1 optimizable) and k3 in G */
static int setup(void)
{
	int offs[MAXOFF], n;

	for (unsigned int i = 0; i < sizeof(fnames) / sizeof(fnames[0]) && !o2; i++) {
		F = fnames[i];
		n = boundaries(F, offs);
		for (int j = 0; j + 1 < n && !o2; j++)
			if (offs[j + 1] - offs[j] < 5 && optimizable(F, offs[j])) {
				o1 = offs[j];
				o2 = offs[j + 1];
			}
	}
	if (!o2)
		return -1;
	for (unsigned int i = 0; i < sizeof(gnames) / sizeof(gnames[0]) && !o3; i++) {
		G = gnames[i];
		n = boundaries(G, offs);
		for (int j = 0; j < n && !o3; j++)
			if (optimizable(G, offs[j]))
				o3 = offs[j];
	}
	return o3 ? 0 : -1;
}

/* k1 and k3 optimized, k2 registered (disabled) inside k1's jump */
static int prepare(void)
{
	if (add("k1", F, o1) || add("k3", G, o3) || enable("k1", 1) || enable("k3", 1))
		return -1;
	if (wait_optimized(F, o1, 3000) || wait_optimized(G, o3, 3000))
		return -1;
	return add("k2", F, o2);
}

/*
 * case 1: disable k1 and enable k2 while another generation waits for its
 * grace period, then remove k1 and call F. Returns 1 if F oopsed.
 */
static int case1(void)
{
	int r;

	if (prepare())
		return -1;
	enable("k3", 0);
	msleep(50);
	if (enable("k1", 0) || enable("k2", 1) || enable("k3", 1))
		return -1;
	msleep(SETTLE);
	if (del("k1"))
		return -1;
	r = call_f();
	return r;
}

/*
 * case 2: disable and remove k1, enable k2, add k1 again (it cannot be
 * optimized next to k2, so it stays an int3); returns 1 if k1 never fires.
 */
static int case2(void)
{
	if (prepare())
		return -1;
	enable("k3", 0);
	msleep(50);
	if (enable("k1", 0) || del("k1") || enable("k2", 1) || enable("k3", 1) ||
	    add("k1", F, o1) || enable("k1", 1))
		return -1;
	msleep(SETTLE);
	if (call_f())
		return -1;
	return hits("k1") == 0;
}

/*
 * case 3: disable k1, remove and add it again while it waits for its grace
 * period, then turn optimization off; returns 1 if k1 never fires.
 */
static int case3(void)
{
	if (add("k1", F, o1) || enable("k1", 1) || wait_optimized(F, o1, 3000))
		return -1;
	if (enable("k1", 0))
		return -1;
	msleep(30);
	if (del("k1") || add("k1", F, o1) || enable("k1", 1) || optsys(0))
		return -1;
	msleep(SETTLE);
	if (call_f())
		return -1;
	return hits("k1") == 0;
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	int which = argc > 2 ? atoi(argv[2]) : 1;
	const char *report = NULL;
	int r = 0;
	double t0;
	long round;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (isatty(STDOUT_FILENO)) {
		ok = "\033[32m[+]\033[0m";
		warn = "\033[33m[~]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	if (which < 1 || which > 3) {
		printf("%s kprobeopt: CASE is 1, 2 or 3\n", err);
		return 2;
	}
	if (access(T "/kprobe_events", W_OK) || access(LIST, R_OK)) {
		printf("%s kprobeopt: no kprobe events in tracefs or no kprobes list in debugfs\n",
		       err);
		return 2;
	}
	kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (kmsg < 0) {
		printf("%s kprobeopt: /dev/kmsg: %s\n", err, strerror(errno));
		return 2;
	}
	lseek(kmsg, 0, SEEK_END);

	reset();
	if (setup()) {
		printf("%s kprobeopt: no optimizable probe pair found\n", err);
		reset();
		return 2;
	}
	printf("kprobeopt: k1 at %s+%d, k2 at %s+%d, k3 at %s+%d\n", F, o1, F, o2, G, o3);

	t0 = now();
	for (round = 1; now() - t0 < limit; round++) {
		r = which == 1 ? case1() : which == 2 ? case2() : case3();
		if (r < 0) {
			printf("%s kprobeopt: probe setup failed in round %ld: %s\n",
			       warn, round, strerror(errno));
			r = 0;
		}
		if ((report = kernel_report()) || r)
			break;
		reset();
	}
	double secs = now() - t0;

	if (!report && r) {
		msleep(500);
		report = kernel_report();
	}
	if (r || report) {
		printf("LB-RESULT bug rounds=%ld seconds=%.1f\n", round, secs);
		if (which == 1)
			printf("%s kprobeopt: bug: %s (round %ld, %.1f s)\n", ok,
			       report ? report : "the caller of the probed function died",
			       round, secs);
		else
			printf("%s kprobeopt: bug: k1 at %s+%d never fired in %d calls (round %ld, %.1f s)\n",
			       ok, F, o1, CALLS, round, secs);
		return 0;
	}
	reset();
	printf("LB-RESULT none rounds=%ld seconds=%.1f\n", round - 1, secs);
	printf("%s kprobeopt: no bug in %ld rounds, %.1f s\n", ok, round - 1, secs);
	return 1;
}

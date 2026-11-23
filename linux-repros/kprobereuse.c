// SPDX-License-Identifier: GPL-2.0
/*
 * kprobereuse: a disabled kprobe added at the address of a removed
 * optimized kprobe that still waits to be unoptimized.
 *
 * Usage: kprobereuse [SECONDS [CASE]] (needs root, tracefs and debugfs mounted)
 *
 * Case 1 (default), each round:
 *   add k1 at F+o and k3 at G+o3, enable both, wait until both are optimized
 *   disable k3 (its unoptimization now waits for a grace period, so k1's
 *   cannot start before it ends)
 *   disable k1, remove k1      (k1's aggregate probe: unused, to be unoptimized)
 *   add k2 at F+o (disabled)   (reuses k1's aggregate probe)
 *   remove k2
 *   wait, then add k1 at F+o again
 * The vulnerable kernel leaves the aggregate probe hashed and optimized with
 * no probes on it; adding k1 again warns in reuse_unused_kprobe().
 *
 * Case 2: as case 1 but k2 is enabled when it is added; checks that k2
 * fires, then that k1 added again fires (the enabled path still works).
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
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
static int o1, o3;	/* k1 and k2 at F+o1, k3 at G+o3 */
static unsigned long faddr;	/* address of F+o1 */
static unsigned char orig[5];	/* the text there with no probe */

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

static void reset(void)
{
	enable("k1", 0);
	enable("k2", 0);
	enable("k3", 0);
	enable("ks", 0);
	del("k1");
	del("k2");
	del("k3");
	del("ks");
	/* turning optimization off waits until the optimizer has no work left */
	optsys(0);
	optsys(1);
}

/* a kernel warning or oops from /dev/kmsg */
static const char *kernel_report(void)
{
	static char line[1024];
	char buf[1024];
	ssize_t n;

	while ((n = read(kmsg, buf, sizeof(buf) - 1)) > 0 || (n < 0 && errno == EPIPE)) {
		if (n <= 0)
			continue;
		buf[n] = 0;
		if (strstr(buf, "WARNING:") || strstr(buf, "Oops") ||
		    strstr(buf, "KASAN:") || strstr(buf, "kernel BUG")) {
			char *p = strchr(buf, ';');

			snprintf(line, sizeof(line), "%s", p ? p + 1 : buf);
			line[strcspn(line, "\n")] = 0;
			return line;
		}
	}
	return NULL;
}

/* run F CALLS times in a child: 0 fine, 1 the child died, -1 error */
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

static unsigned long ksym(const char *name)
{
	char line[256], sym[200], t;
	unsigned long a;
	FILE *f = fopen("/proc/kallsyms", "r");

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "%lx %c %199s", &a, &t, sym) == 3 && !strcmp(sym, name)) {
			fclose(f);
			return a;
		}
	fclose(f);
	return 0;
}

/* read N bytes of kernel text at ADDR through /proc/kcore */
static int ktext(unsigned long addr, unsigned char *buf, int n)
{
	Elf64_Ehdr eh;
	Elf64_Phdr ph;
	int fd = open("/proc/kcore", O_RDONLY), r = -1;

	if (fd < 0)
		return -1;
	if (pread(fd, &eh, sizeof(eh), 0) != sizeof(eh))
		goto out;
	for (int i = 0; i < eh.e_phnum; i++) {
		if (pread(fd, &ph, sizeof(ph), eh.e_phoff + i * sizeof(ph)) != sizeof(ph))
			goto out;
		if (ph.p_type == PT_LOAD && addr >= ph.p_vaddr &&
		    addr + n <= ph.p_vaddr + ph.p_memsz) {
			r = pread(fd, buf, n, ph.p_offset + addr - ph.p_vaddr) == n ? 0 : -1;
			break;
		}
	}
out:
	close(fd);
	return r;
}

static int optimizable(const char *fn, int off)
{
	int r;

	if (add("ks", fn, off) || enable("ks", 1)) {
		del("ks");
		return 0;
	}
	r = !wait_optimized(fn, off, 2000);
	if (r && fn == F)
		r = !call_f() && hits("ks") > 0;
	reset();
	return r;
}

static int find(const char *const *names, int nr, const char **fn)
{
	for (int i = 0; i < nr; i++) {
		*fn = names[i];
		for (int off = 1; off < MAXOFF; off++) {
			if (add("ks", *fn, off))
				continue;
			del("ks");
			if (optimizable(*fn, off))
				return off;
		}
	}
	return 0;
}

/* k1 optimized, k3's unoptimization waiting for its grace period */
static int prepare(void)
{
	if (add("k1", F, o1) || add("k3", G, o3) || enable("k1", 1) || enable("k3", 1))
		return -1;
	if (wait_optimized(F, o1, 3000) || wait_optimized(G, o3, 3000))
		return -1;
	enable("k3", 0);
	msleep(50);
	return 0;
}

/* returns 1 if the bug showed (a probe that does not fire, or a dead caller) */
static int round_once(int which)
{
	long h;

	if (prepare())
		return -1;
	double t = now();

	if (enable("k1", 0))
		return -1;
	double t1 = now();
	if (del("k1"))
		return -1;
	double t2 = now();
	if (add("k2", F, o1) || (which == 2 && enable("k2", 1)))
		return -1;
	if (getenv("KR_DEBUG"))
		printf("dbg: disable %.1f ms, del %.1f ms, add %.1f ms, k2 state %d\n",
		       (t1 - t) * 1e3, (t2 - t1) * 1e3, (now() - t2) * 1e3, state(F, o1));
	if (which == 2) {
		if (call_f())
			return 1;
		h = hits("k2");
		if (h <= 0) {
			printf("%s kprobereuse: k2 enabled but %ld hits in %d calls\n",
			       warn, h, CALLS);
			return 1;
		}
		enable("k2", 0);
	}
	if (del("k2"))
		return -1;
	/* let the optimizer finish everything, then give it time to re-optimize */
	msleep(SETTLE);
	optsys(0);
	optsys(1);
	msleep(2 * SETTLE);
	{
		unsigned char now_text[5];

		if (ktext(faddr, now_text, 5))
			return -1;
		if (memcmp(now_text, orig, 5)) {
			printf("%s kprobereuse: no probe at %s+%d but its text is "
			       "%02x %02x %02x %02x %02x (was %02x %02x %02x %02x %02x), "
			       "kprobes list entry: %d\n", warn, F, o1,
			       now_text[0], now_text[1], now_text[2], now_text[3], now_text[4],
			       orig[0], orig[1], orig[2], orig[3], orig[4], state(F, o1));
			return 1;
		}
	}
	if (add("k1", F, o1) || enable("k1", 1))
		return -1;
	if (call_f())
		return 1;
	h = hits("k1");
	if (h <= 0) {
		printf("%s kprobereuse: k1 added again but %ld hits in %d calls\n",
		       warn, h, CALLS);
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	int which = argc > 2 ? atoi(argv[2]) : 1;
	const char *report = NULL;
	int r = 0;
	double t0, secs;
	long round;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (isatty(STDOUT_FILENO)) {
		ok = "\033[32m[+]\033[0m";
		warn = "\033[33m[~]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	if (which < 1 || which > 2) {
		printf("%s kprobereuse: CASE is 1 or 2\n", err);
		return 2;
	}
	if (access(T "/kprobe_events", W_OK) || access(LIST, R_OK)) {
		printf("%s kprobereuse: no kprobe events in tracefs or no kprobes list\n", err);
		return 2;
	}
	kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (kmsg < 0) {
		printf("%s kprobereuse: /dev/kmsg: %s\n", err, strerror(errno));
		return 2;
	}
	lseek(kmsg, 0, SEEK_END);

	reset();
	o1 = find(fnames, 2, &F);
	o3 = find(gnames, 3, &G);
	if (!o1 || !o3) {
		printf("%s kprobereuse: no optimizable probe sites found\n", err);
		return 2;
	}
	faddr = ksym(F) + o1;
	if (faddr == (unsigned long)o1 || ktext(faddr, orig, 5)) {
		printf("%s kprobereuse: cannot read %s from /proc/kcore\n", err, F);
		return 2;
	}
	printf("kprobereuse: k1/k2 at %s+%d, k3 at %s+%d, case %d\n", F, o1, G, o3, which);

	t0 = now();
	for (round = 1; now() - t0 < limit; round++) {
		r = round_once(which);
		if (r < 0) {
			printf("%s kprobereuse: probe setup failed in round %ld: %s\n",
			       warn, round, strerror(errno));
			r = 0;
		}
		if ((report = kernel_report()) || r)
			break;
		reset();
	}
	secs = now() - t0;
	if (!report && r) {
		msleep(500);
		report = kernel_report();
	}
	if (r || report) {
		printf("LB-RESULT bug rounds=%ld seconds=%.1f\n", round, secs);
		printf("%s kprobereuse: bug: %s (round %ld, %.1f s)\n", ok,
		       report ? report : "jump left in the text with no probe, or a probe did not fire", round, secs);
		return 0;
	}
	reset();
	printf("LB-RESULT none rounds=%ld seconds=%.1f\n", round - 1, secs);
	printf("%s kprobereuse: no bug in %ld rounds, %.1f s\n", ok, round - 1, secs);
	return 1;
}

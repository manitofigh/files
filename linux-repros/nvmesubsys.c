// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: nvmesubsys [SECONDS] (needs root)
 *
 * SECONDS is how long to keep trying (300 by default).
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NQN	"nvmesubsys"
#define NVMET	"/sys/kernel/config/nvmet"
#define FI	"/sys/kernel/debug/failslab"
#define MAX_NTH	256	/* nvme_init_identify() allocations tried */
#define STUCK	30	/* s before a connect counts as stuck */

static const char *ok = "[+]", *warn = "[~]", *err = "[-]";
static int kmsg = -1;

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

static int fi(const char *knob, const char *val)
{
	char path[128];
	snprintf(path, sizeof(path), "%s/%s", FI, knob);
	return put(path, val);
}

static double now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
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

/* start and end of a kernel function, from /proc/kallsyms */
static int func_range(const char *name, unsigned long *start, unsigned long *end)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char line[256], sym[128], type;
	unsigned long addr;
	*start = *end = 0;
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx %c %127s", &addr, &type, sym) != 3)
			continue;
		if (*start && addr > *start && (!*end || addr < *end))
			*end = addr;
		if (!*start && !strcmp(sym, name)) {
			*start = addr;
			rewind(f);
		}
	}
	fclose(f);
	return *start && *end ? 0 : -1;
}

/*
 * kernel messages since the last call: did the subsystem link fail, and the
 * first lockdep or hung task line, if any
 */
static void kmsg_scan(int *linkfail, char *report, size_t len)
{
	char buf[1024];
	ssize_t n;
	*linkfail = 0;
	report[0] = 0;
	while ((n = read(kmsg, buf, sizeof(buf) - 1)) > 0 || (n < 0 && errno == EPIPE)) {
		if (n <= 0)
			continue;
		buf[n] = 0;
		char *msg = strchr(buf, ';');
		msg = msg ? msg + 1 : buf;
		msg[strcspn(msg, "\n")] = 0;
		if (strstr(msg, "failed to create sysfs link from subsystem"))
			*linkfail = 1;
		if (!report[0] && (strstr(msg, "possible recursive locking detected") ||
				   strstr(msg, "blocked for more than")))
			snprintf(report, len, "%.200s", msg);
	}
}

/* an nvme-loop target with one subsystem (no namespaces needed) */
static int setup_target(void)
{
	if (access(NVMET, F_OK))
		mount("none", "/sys/kernel/config", "configfs", 0, NULL);
	if (access(NVMET, F_OK))
		return -1;
	if (access(NVMET "/subsystems/" NQN, F_OK)) {
		if (mkdir(NVMET "/subsystems/" NQN, 0755) ||
		    put(NVMET "/subsystems/" NQN "/attr_allow_any_host", "1"))
			return -1;
	}
	if (access(NVMET "/ports/1", F_OK)) {
		if (mkdir(NVMET "/ports/1", 0755) ||
		    put(NVMET "/ports/1/addr_trtype", "loop"))
			return -1;
	}
	if (access(NVMET "/ports/1/subsystems/" NQN, F_OK) &&
	    symlink(NVMET "/subsystems/" NQN, NVMET "/ports/1/subsystems/" NQN))
		return -1;
	return 0;
}

/* delete every host controller of our subsystem */
static int disconnect(void)
{
	char path[300], buf[256];
	struct dirent *d;
	DIR *dir = opendir("/sys/class/nvme");
	int n = 0;
	if (!dir)
		return 0;
	while ((d = readdir(dir))) {
		if (strncmp(d->d_name, "nvme", 4))
			continue;
		snprintf(path, sizeof(path), "/sys/class/nvme/%s/subsysnqn", d->d_name);
		if (get(path, buf, sizeof(buf)) || strcmp(buf, NQN))
			continue;
		snprintf(path, sizeof(path), "/sys/class/nvme/%s/delete_controller", d->d_name);
		n += !put(path, "1");
	}
	closedir(dir);
	return n;
}

/*
 * connect a loop controller in a child, with its NTH slab allocation under
 * nvme_init_identify() made to fail (0: none); 0 = connected, 1 = failed,
 * 2 = still in write() after STUCK s
 */
static int connect_ctrl(int nth, pid_t *child, int *fired)
{
	int pfd[2];
	char c = 0;
	if (pipe(pfd))
		return -1;
	pid_t pid = fork();
	if (pid == 0) {
		const char *opts = "transport=loop,nqn=" NQN;
		char val[16], left[16];
		close(pfd[0]);
		int fd = open("/dev/nvme-fabrics", O_RDWR);
		if (fd < 0)
			_exit(3);
		snprintf(val, sizeof(val), "%d", nth);
		if (nth && put("/proc/thread-self/fail-nth", val))
			_exit(3);
		int r = write(fd, opts, strlen(opts)) < 0;
		get("/proc/thread-self/fail-nth", left, sizeof(left));
		put("/proc/thread-self/fail-nth", "0");
		c = nth && !strcmp(left, "0");
		if (write(pfd[1], &c, 1) != 1)
			_exit(3);
		_exit(r);
	}
	close(pfd[1]);
	*child = pid;
	*fired = 0;
	for (double t0 = now(); now() - t0 < STUCK; usleep(20000)) {
		int st;
		if (waitpid(pid, &st, WNOHANG) == pid) {
			if (read(pfd[0], &c, 1) == 1)
				*fired = c;
			close(pfd[0]);
			if (!WIFEXITED(st) || WEXITSTATUS(st) > 1)
				return -1;
			return WEXITSTATUS(st);
		}
	}
	close(pfd[0]);
	return 2;
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	unsigned long start, end;
	char val[32], line[256];
	int round, nth = 1, hits = 0;
	double t0 = now();

	if (!isatty(1))
		ok = warn = err = "";
	setvbuf(stdout, NULL, _IOLBF, 0);

	if (access(FI, F_OK))
		mount("debugfs", "/sys/kernel/debug", "debugfs", 0, NULL);
	if (setup_target()) {
		printf("%s cannot set up the nvme-loop target (CONFIG_NVME_TARGET_LOOP?)\n", err);
		return 2;
	}
	if (func_range("nvme_init_identify", &start, &end)) {
		printf("%s no nvme_init_identify in /proc/kallsyms\n", err);
		return 2;
	}
	/* fail-nth counts only slab allocations made under nvme_init_identify() */
	snprintf(val, sizeof(val), "%lu", start);
	if (fi("require-start", val) < 0) {
		printf("%s no failslab stack filter (CONFIG_FAULT_INJECTION_STACKTRACE_FILTER)\n", err);
		return 2;
	}
	snprintf(val, sizeof(val), "%lu", end);
	fi("require-end", val);
	fi("stacktrace-depth", "32");
	fi("ignore-gfp-wait", "N");
	fi("cache-filter", "N");
	fi("probability", "0");
	fi("verbose", "1");
	kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (kmsg < 0) {
		printf("%s cannot read /dev/kmsg\n", err);
		return 2;
	}
	lseek(kmsg, 0, SEEK_END);
	disconnect();

	for (round = 1; now() - t0 < limit; round++) {
		pid_t child;
		int fired, linkfail, r;

		r = connect_ctrl(nth, &child, &fired);
		kmsg_scan(&linkfail, line, sizeof(line));
		if (r == 2) {
			printf("LB-CONNECT-HUNG pid %d state %c after %d s (sysfs link %s)\n",
			       child, task_state(child), STUCK,
			       linkfail ? "failed" : "not failed");
			if (line[0])
				printf("%s kernel: %s\n", ok, line);
			printf("%s the connect never returns: the bug\n", ok);
			printf("LB-RESULT bug rounds=%d seconds=%.1f\n", round, now() - t0);
			return 0;
		}
		if (r < 0) {
			printf("%s round %d: the connect child failed\n", err, round);
			return 2;
		}
		if (linkfail) {
			/* the link failed and the connect returned: a new connect must work */
			hits++;
			disconnect();
			if (connect_ctrl(0, &child, &fired)) {
				printf("%s round %d: connect after the failed link does not work\n",
				       err, round);
				printf("LB-RESULT bug rounds=%d seconds=%.1f\n", round, now() - t0);
				return 0;
			}
			printf("round %d: allocation %d under nvme_init_identify() failed the link, "
			       "connect returned an error, the next connect works\n", round, nth);
		}
		disconnect();
		/* the whole connect passed without a failure: start over */
		nth = r == 0 && !fired ? 1 : nth % MAX_NTH + 1;
		if (round == 1 && nth == 1) {
			printf("%s no allocation under nvme_init_identify() failed\n", err);
			return 2;
		}
	}
	printf("%s no stuck connect in %d rounds (%d with the subsystem link failing)\n",
	       ok, round - 1, hits);
	printf("LB-RESULT none rounds=%d seconds=%.1f\n", round - 1, now() - t0);
	return 1;
}

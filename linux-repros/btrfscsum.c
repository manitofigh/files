// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: btrfscsum [SECONDS [IMAGE]] (needs root)
 *
 * SECONDS is how long to keep trying (300 by default).
 * IMAGE is the sha256 btrfs image put on /dev/ram0 each round
 * (/tmp/btrfscsum.img by default).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/btrfs.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SRC	"/dev/ram0"
#define TGT	"/dev/ram1"
#define MNT	"/mnt/btrfscsum"
#define FI	"/sys/kernel/debug/failslab"
#define STUCK	30	/* s before a replace counts as stuck */

static const char *ok = "[+]", *warn = "[~]", *err = "[-]";

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

static int copy_image(const char *image)
{
	static char buf[1 << 20];
	int in = open(image, O_RDONLY), out = open(SRC, O_WRONLY);
	ssize_t n = -1;
	if (in >= 0 && out >= 0)
		while ((n = read(in, buf, sizeof(buf))) > 0)
			if (write(out, buf, n) != n) {
				n = -1;
				break;
			}
	if (out >= 0)
		fsync(out);
	close(in);
	close(out);
	return n == 0 ? 0 : -1;
}

/* fresh filesystem on ram0, with no device of an earlier round still registered */
static int fresh_fs(const char *image)
{
	struct btrfs_ioctl_vol_args va = { 0 };
	int ctl = open("/dev/btrfs-control", O_RDWR);
	if (ctl >= 0) {
		ioctl(ctl, BTRFS_IOC_FORGET_DEV, &va);
		close(ctl);
	}
	if (copy_image(image))
		return -1;
	return mount(SRC, MNT, "btrfs", 0, NULL) ? -1 : 0;
}

/*
 * dirty a random range of a file and start its writeback without waiting
 * (not REQ_SYNC), while the checksum array allocation is made to fail once
 */
static int write_with_failure(int round, int *fired, int *failed)
{
	static char buf[256 << 10];
	char path[64], times[16];
	size_t len = (1 + rand() % 64) * 4096;
	off_t off = (rand() % 64) * 4096;
	int r;

	snprintf(path, sizeof(path), "%s/f%d", MNT, round);
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return -1;
	memset(buf, round, len);
	r = pwrite(fd, buf, len, off) == (ssize_t)len ? 0 : -1;
	fi("times", "1");
	/* the write error shows up here or in fsync() */
	*failed = !r && (sync_file_range(fd, off, len, SYNC_FILE_RANGE_WRITE) ||
			 sync_file_range(fd, off, len, SYNC_FILE_RANGE_WAIT_AFTER));
	get(FI "/times", times, sizeof(times));
	fi("times", "0");
	*fired = !strcmp(times, "0");
	*failed |= fsync(fd) < 0;
	close(fd);
	return r;
}

/* replace ram0 by ram1 in a child: 0 = done, 1 = still running after STUCK s */
static int replace(pid_t *child)
{
	struct btrfs_ioctl_dev_replace_args args = { 0 };
	pid_t pid = fork();
	if (pid == 0) {
		int fd = open(MNT, O_RDONLY | O_DIRECTORY);
		args.cmd = BTRFS_IOCTL_DEV_REPLACE_CMD_START;
		args.start.srcdevid = 1;
		args.start.cont_reading_from_srcdev_mode =
			BTRFS_IOCTL_DEV_REPLACE_CONT_READING_FROM_SRCDEV_MODE_ALWAYS;
		strcpy((char *)args.start.tgtdev_name, TGT);
		_exit(ioctl(fd, BTRFS_IOC_DEV_REPLACE, &args) || args.result ? 3 : 0);
	}
	*child = pid;
	for (double t0 = now(); now() - t0 < STUCK; usleep(100000)) {
		int st;
		if (waitpid(pid, &st, WNOHANG) == pid)
			return WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 0 : -1;
	}
	return 1;
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	const char *image = argc > 2 ? argv[2] : "/tmp/btrfscsum.img";
	unsigned long start, end;
	char val[32];
	int round, injected = 0;
	double t0 = now();

	if (!isatty(1))
		ok = warn = err = "";
	srand(time(NULL) ^ getpid());
	setvbuf(stdout, NULL, _IOLBF, 0);

	if (func_range("btrfs_csum_one_bio", &start, &end)) {
		printf("%s no btrfs_csum_one_bio in /proc/kallsyms\n", err);
		return 2;
	}
	/* fail only allocations made under btrfs_csum_one_bio(), in any task */
	snprintf(val, sizeof(val), "%lu", start);
	if (fi("require-start", val) < 0) {
		printf("%s no failslab stack filter (CONFIG_FAULT_INJECTION_STACKTRACE_FILTER)\n", err);
		return 2;
	}
	snprintf(val, sizeof(val), "%lu", end);
	fi("require-end", val);
	fi("stacktrace-depth", "32");
	fi("task-filter", "N");
	fi("ignore-gfp-wait", "N");
	fi("cache-filter", "N");
	fi("probability", "100");
	fi("interval", "1");
	fi("verbose", "2");
	fi("times", "0");
	mkdir(MNT, 0755);

	for (round = 1; now() - t0 < limit; round++) {
		pid_t child;
		int fired, failed, r;

		if (fresh_fs(image)) {
			printf("%s round %d: cannot put the image on %s and mount it: %s\n",
			       err, round, SRC, strerror(errno));
			return 2;
		}
		if (write_with_failure(round, &fired, &failed) < 0) {
			printf("%s round %d: write failed: %s\n", err, round, strerror(errno));
			return 2;
		}
		injected += fired;
		printf("round %d: checksum allocation %s, write %s; replacing %s by %s\n",
		       round, fired ? "failed" : "not failed", failed ? "error" : "ok",
		       SRC, TGT);
		r = replace(&child);
		if (r == 1) {
			printf("LB-REPLACE-HUNG pid %d state %c after %d s\n", child,
			       task_state(child), STUCK);
			printf("%s the replace never finishes: the bug\n", ok);
			printf("LB-RESULT bug rounds=%d seconds=%.1f\n", round, now() - t0);
			return 0;
		}
		if (r < 0)
			printf("%s round %d: the replace failed\n", warn, round);
		if (umount(MNT)) {
			printf("%s round %d: umount: %s\n", err, round, strerror(errno));
			return 2;
		}
	}
	printf("%s no stuck replace in %d rounds (%d with a failed checksum allocation)\n",
	       ok, round - 1, injected);
	printf("LB-RESULT none rounds=%d seconds=%.1f\n", round - 1, now() - t0);
	return 1;
}

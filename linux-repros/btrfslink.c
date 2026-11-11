// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: btrfslink [SECONDS] (needs root)
 *
 * SECONDS is how long to keep trying (300 by default).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/btrfs.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

#define DEV	"/dev/ram0"
#define DMNAME	"btrfslink"
#define DMNODE	"/tmp/btrfslink-dm"
#define MNT	"/mnt/btrfslink"
#define REF	"/tmp/btrfslink-ref"	/* the same steps on tmpfs */
#define IMG	"/tmp/btrfslink.img"

static const char *ok = "[+]", *warn = "[~]", *err = "[-]";
static uint64_t img_sectors;

static void die(const char *what)
{
	printf("%s btrfslink: %s: %s\n", err, what, strerror(errno));
	exit(2);
}

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec / 1e9;
}

/*
 * a fresh btrfs on DEV (a RAM disk: modprobe brd rd_size=262144), copied
 * from IMG if it is there (a VM without btrfs-progs), else made by mkfs
 */
static void fresh_fs(void)
{
	static char buf[1 << 20];
	int in = open(IMG, O_RDONLY), out;
	uint64_t sz;
	ssize_t n;

	if (in < 0) {
		if (system("mkfs.btrfs -q -f " DEV " >/dev/null"))
			die("mkfs.btrfs " DEV);
		out = open(DEV, O_RDONLY);
		if (out < 0 || ioctl(out, BLKGETSIZE64, &sz))
			die("size of " DEV);
		close(out);
		img_sectors = sz / 512;
		return;
	}
	out = open(DEV, O_WRONLY);
	if (out < 0)
		die("open " DEV);
	img_sectors = 0;
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		if (write(out, buf, n) != n)
			die("write " DEV);
		img_sectors += n / 512;
	}
	if (n < 0 || fsync(out))
		die("copy " IMG);
	ioctl(out, BLKFLSBUF, 0);
	close(in);
	close(out);
}

/* device-mapper ioctls, as dmsetup does them */
static int dm_cmd(unsigned long cmd, struct dm_ioctl *io)
{
	int fd = open("/dev/mapper/control", O_RDWR), r;

	if (fd < 0)
		die("open /dev/mapper/control");
	io->version[0] = DM_VERSION_MAJOR;
	io->version[1] = 0;
	io->version[2] = 0;
	strcpy(io->name, DMNAME);
	r = ioctl(fd, cmd, io);
	close(fd);
	return r;
}

static void dm_suspend(int suspend)
{
	struct dm_ioctl io = { .data_size = sizeof(io) };

	/* like dmsetup suspend --nolockfs: don't freeze (commit) the fs */
	io.flags = suspend ? DM_SUSPEND_FLAG | DM_SKIP_LOCKFS_FLAG : 0;
	if (dm_cmd(DM_DEV_SUSPEND, &io))
		die(suspend ? "DM_DEV_SUSPEND" : "DM_DEV_SUSPEND (resume)");
}

/* load one target over the whole image and make it live */
static void dm_table(const char *type, const char *params)
{
	char buf[4096] __attribute__((aligned(8)));
	struct dm_ioctl *io = (void *)buf;
	struct dm_target_spec *sp = (void *)(io + 1);
	size_t plen = strlen(params) + 1;

	memset(buf, 0, sizeof(buf));
	sp->sector_start = 0;
	sp->length = img_sectors;
	strcpy(sp->target_type, type);
	strcpy((char *)(sp + 1), params);
	io->data_start = sizeof(*io);
	io->data_size = sizeof(*io) + ((sizeof(*sp) + plen + 7) & ~7UL);
	io->target_count = 1;
	if (dm_cmd(DM_TABLE_LOAD, io))
		die("DM_TABLE_LOAD");
	dm_suspend(1);
	dm_suspend(0);
}

static void dm_remove(void)
{
	struct dm_ioctl io = { .data_size = sizeof(io) };

	unlink(DMNODE);
	dm_cmd(DM_DEV_REMOVE, &io);
}

static void dm_create(void)
{
	struct dm_ioctl io = { .data_size = sizeof(io) };

	if (dm_cmd(DM_DEV_CREATE, &io))
		die("DM_DEV_CREATE");
	if (mknod(DMNODE, S_IFBLK | 0600, makedev(major(io.dev), minor(io.dev))))
		die("mknod " DMNODE);
	dm_table("linear", DEV " 0");
}

/* the "power cut": drop every write from now on */
static void power_cut(void)
{
	dm_table("flakey", DEV " 0 0 180 1 drop_writes");
}

/* forget the unmounted btrfs devices of the last case */
static void forget_devs(void)
{
	struct btrfs_ioctl_vol_args args = { 0 };
	int fd = open("/dev/btrfs-control", O_RDWR);

	if (fd >= 0) {
		ioctl(fd, BTRFS_IOC_FORGET_DEV, &args);
		close(fd);
	}
}

static const char *base;	/* MNT or REF while the steps run */

static char *at(const char *name)
{
	static char p[4][128];
	static int i;

	i = (i + 1) % 4;
	snprintf(p[i], sizeof(p[i]), "%s/%s", base, name);
	return p[i];
}

static void must(int r, const char *what)
{
	if (r)
		die(what);
}

static unsigned int extra;	/* random per case, same for both runs */

static void fill(int fd, off_t off, size_t len, int seed)
{
	char *p;

	len += extra % 4096;
	p = malloc(len);
	for (size_t i = 0; i < len; i++)
		p[i] = (char)(seed + extra + i * 7);
	if (pwrite(fd, p, len, off) != (ssize_t)len)
		die("pwrite");
	free(p);
}

static int sync_fd(int fd, int data_only)
{
	return data_only ? fdatasync(fd) : fsync(fd);
}

/*
 * Each case returns the fd it fsyncs last; the file is then expected
 * under the name it returns in *name.
 */

/* the basic case: fsync (data_only = 0) or fdatasync (1) */
static int case_basic(int data_only, const char **name)
{
	int fd;

	must(mkdir(at("c"), 0755), "mkdir c");
	fd = open(at("c/f0"), O_CREAT | O_RDWR, 0644);
	must(fd < 0, "open c/f0");
	must(mkdir(at("c/d1"), 0755), "mkdir c/d1");
	fill(fd, 0, 4096, 1);
	must(link(at("c/f0"), at("c/d1/f1")), "link c/f0 c/d1/f1");
	must(unlink(at("c/f0")), "unlink c/f0");
	fill(fd, 26670, 16384, 2);
	must(sync_fd(fd, data_only), "fsync");
	*name = "c/d1/f1";
	return fd;
}

/* two links, the fsynced fd is on the first removed one */
static int case_twolinks(int data_only, const char **name)
{
	int fd;

	must(mkdir(at("c"), 0755), "mkdir c");
	fd = open(at("c/f0"), O_CREAT | O_RDWR, 0644);
	must(fd < 0, "open c/f0");
	must(link(at("c/f0"), at("c/f3")), "link c/f0 c/f3");
	must(unlink(at("c/f0")), "unlink c/f0");
	must(mkdir(at("c/d1"), 0755), "mkdir c/d1");
	must(link(at("c/f3"), at("c/d1/f4")), "link c/f3 c/d1/f4");
	must(mkdir(at("c/d2"), 0755), "mkdir c/d2");
	must(fallocate(fd, 0, 7248, 20000), "fallocate");
	fill(fd, 8913, 512, 45);
	must(unlink(at("c/f3")), "unlink c/f3");
	must(sync_fd(fd, data_only), "fsync");
	*name = "c/d1/f4";
	return fd;
}

/* link + unlink, then a rename of the remaining link into a new dir */
static int case_rename(int data_only, const char **name)
{
	int fd;

	must(mkdir(at("c"), 0755), "mkdir c");
	fd = open(at("c/f0"), O_CREAT | O_RDWR, 0644);
	must(fd < 0, "open c/f0");
	fill(fd, 0, 8192, 3);
	must(link(at("c/f0"), at("c/f5")), "link c/f0 c/f5");
	must(unlink(at("c/f0")), "unlink c/f0");
	must(mkdir(at("c/d1"), 0755), "mkdir c/d1");
	must(rename(at("c/f5"), at("c/f0")), "rename c/f5 c/f0");
	must(mkdir(at("c/d2"), 0755), "mkdir c/d2");
	must(rename(at("c/f0"), at("c/d1/f1")), "rename c/f0 c/d1/f1");
	must(sync_fd(fd, data_only), "fsync");
	*name = "c/d1/f1";
	return fd;
}

static const struct {
	const char *name;
	int (*run)(int, const char **);
	int data_only;
} cases[] = {
	{ "link+unlink, fsync", case_basic, 0 },
	{ "link+unlink, fdatasync", case_basic, 1 },
	{ "two links, fdatasync", case_twolinks, 1 },
	{ "link+unlink+rename, fdatasync", case_rename, 1 },
};
#define NCASES (sizeof(cases) / sizeof(cases[0]))

/* read up to 1 MiB of PATH; -1 if it is missing */
static ssize_t slurp(const char *path, char *buf)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, 1 << 20);
	close(fd);
	return n;
}

/* 1: the fsynced file is lost or wrong after the power cut */
static int run_case(int c, char *what, size_t wlen)
{
	static char want[1 << 20], got[1 << 20];
	const char *name;
	ssize_t nw, ng;
	int fd;

	/* the expected result: the same steps on tmpfs */
	extra = rand();
	if (system("rm -rf " REF))
		die("rm " REF);
	must(mkdir(REF, 0755), "mkdir " REF);
	base = REF;
	close(cases[c].run(cases[c].data_only, &name));
	nw = slurp(at(name), want);

	forget_devs();
	fresh_fs();
	dm_create();
	if (mount(DMNODE, MNT, "btrfs", 0, "commit=300"))
		die("mount");
	base = MNT;
	fd = cases[c].run(cases[c].data_only, &name);
	power_cut();
	close(fd);
	if (umount(MNT))
		die("umount (power cut)");
	dm_table("linear", DEV " 0");
	if (mount(DMNODE, MNT, "btrfs", 0, NULL))
		die("mount after the power cut");
	ng = slurp(at(name), got);
	umount(MNT);
	dm_remove();

	if (ng == nw && !memcmp(want, got, nw))
		return 0;
	if (ng < 0)
		snprintf(what, wlen, "%s: %s is gone after the power cut and log replay",
			 cases[c].name, name);
	else
		snprintf(what, wlen, "%s: %s has %zd bytes after the power cut, not %zd",
			 cases[c].name, name, ng, nw);
	return 1;
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	unsigned long rounds = 0, lost = 0;
	double t0 = now(), hit_at = 0;
	char what[256];

	setvbuf(stdout, NULL, _IOLBF, 0);
	srand(getpid() ^ time(NULL));
	mkdir(MNT, 0755);
	umount(MNT);
	dm_remove();	/* left over from an earlier run */

	/* every case of a round runs; stop after the first round with a loss */
	while (!lost && now() - t0 < limit) {
		rounds++;
		for (unsigned int c = 0; c < NCASES; c++) {
			if (!run_case(c, what, sizeof(what)))
				continue;
			printf("LB-FILE-LOST %s\n", what);
			if (!lost++)
				hit_at = now() - t0;
		}
		if (!lost && rounds % 50 == 0)
			printf("%s %lu rounds, no file lost\n", warn, rounds);
	}
	if (lost)
		printf("%s %lu of %zu fsynced files lost in round %lu (%.1f s): the bug\n",
		       ok, lost, NCASES, rounds, hit_at);
	else
		printf("%s no fsynced file lost in %lu rounds (%zu cases each)\n",
		       ok, rounds, NCASES);
	printf("LB-RESULT %s rounds=%lu seconds=%.1f\n", lost ? "bug" : "none",
	       rounds, lost ? hit_at : now() - t0);
	return lost ? 0 : 1;
}

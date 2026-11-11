// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: ext4fcmkdir [SECONDS] (needs root)
 *
 * SECONDS is how long to keep trying (300 by default).
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <linux/loop.h>
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

#define IMG	"/tmp/ext4fcmkdir.img"
#define IMGMB	64
#define MNT	"/tmp/ext4fcmkdir.mnt"
#define NODE	"/tmp/ext4fcmkdir.dm"
#define DMNAME	"ext4fcmkdir"

static char loopdev[32];
static char problem[256];

static void die(const char *what)
{
	printf("ext4fcmkdir: %s: %s\n", what, strerror(errno));
	exit(2);
}

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec / 1e9;
}

/* one device-mapper ioctl; with @type, a table of one target over the disk */
static int dm(unsigned long cmd, uint32_t flags, const char *type,
	      const char *params, struct dm_ioctl *out)
{
	char buf[16384] __attribute__((aligned(8)));
	struct dm_ioctl *io = (void *)buf;
	int fd, r;

	memset(buf, 0, sizeof(buf));
	io->version[0] = DM_VERSION_MAJOR;
	io->data_size = sizeof(buf);
	io->data_start = sizeof(*io);
	io->flags = flags;
	strcpy(io->name, DMNAME);
	if (type) {
		struct dm_target_spec *t = (void *)(buf + sizeof(*io));

		io->target_count = 1;
		t->length = IMGMB << 11;
		strcpy(t->target_type, type);
		snprintf((char *)(t + 1), 256, "%s %s", loopdev, params);
	}
	fd = open("/dev/mapper/control", O_RDWR);
	if (fd < 0)
		die("/dev/mapper/control (CONFIG_BLK_DEV_DM)");
	r = ioctl(fd, cmd, io);
	close(fd);
	if (!r && out)
		*out = *io;
	return r;
}

/* switch the dm device to a new table */
static void table(const char *type, const char *params)
{
	if (dm(DM_TABLE_LOAD, 0, type, params, NULL))
		die(type);
	/* no lockfs: freezing the file system would force a full commit */
	if (dm(DM_DEV_SUSPEND, DM_SUSPEND_FLAG | DM_SKIP_LOCKFS_FLAG,
	       NULL, NULL, NULL) ||
	    dm(DM_DEV_SUSPEND, 0, NULL, NULL, NULL))
		die("DM_DEV_SUSPEND");
}

/* a fresh fast_commit ext4 on a loop device, with a linear dm device on top */
static void setup(void)
{
	struct loop_info64 li = { .lo_flags = LO_FLAGS_AUTOCLEAR };
	struct dm_ioctl io;
	unsigned char sb[1024];
	char cmd[256];
	int ctl, fd, lfd, n;

	fd = open(IMG, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || ftruncate(fd, IMGMB << 20))
		die(IMG);
	snprintf(cmd, sizeof(cmd),
		 "mkfs.ext4 -q -F -t ext4 -O fast_commit -b 4096 %s >/dev/null 2>&1", IMG);
	/* s_feature_compat: COMPAT_FAST_COMMIT */
	if (system(cmd) || pread(fd, sb, 1024, 1024) != 1024 ||
	    !(sb[0x5c + 1] & 0x04)) {
		printf("ext4fcmkdir: \"mkfs.ext4 -O fast_commit\" failed (needs e2fsprogs 1.46+)\n");
		exit(2);
	}
	ctl = open("/dev/loop-control", O_RDWR);
	if (ctl < 0)
		die("/dev/loop-control (CONFIG_BLK_DEV_LOOP)");
	n = ioctl(ctl, LOOP_CTL_GET_FREE);
	close(ctl);
	if (n < 0)
		die("LOOP_CTL_GET_FREE");
	snprintf(loopdev, sizeof(loopdev), "/dev/loop%d", n);
	lfd = open(loopdev, O_RDWR);
	if (lfd < 0 || ioctl(lfd, LOOP_SET_FD, fd) || ioctl(lfd, LOOP_SET_STATUS64, &li))
		die(loopdev);
	close(fd);
	dm(DM_DEV_REMOVE, 0, NULL, NULL, NULL);
	if (dm(DM_DEV_CREATE, 0, NULL, NULL, &io))
		die("DM_DEV_CREATE");
	unlink(NODE);
	if (mknod(NODE, S_IFBLK | 0600, io.dev))
		die("mknod");
	table("linear", "0");
	close(lfd);	/* the dm device holds it now; it goes away with it */
}

static void do_mount(void)
{
	if (mount(NODE, MNT, "ext4", 0, NULL))
		die("mount");
}

static void do_umount(void)
{
	if (umount(MNT))
		die("umount");
}

/* new directories, a file in the deepest one, fsync (a fast commit) */
static void work(int depth, int files)
{
	char path[256] = MNT;
	int fd;

	/* fast commits start only after the first full commit of a mount */
	fd = open(MNT "/w", O_CREAT | O_RDWR, 0644);
	if (fd < 0 || syncfs(fd))
		die("syncfs");
	close(fd);

	for (int i = 0; i < depth; i++) {
		size_t l = strlen(path);

		snprintf(path + l, sizeof(path) - l, "/d%d", rand() % 1000);
		if (mkdir(path, 0755) && errno != EEXIST)
			die("mkdir");
	}
	for (int i = 0; i < files; i++) {
		size_t l = strlen(path);

		snprintf(path + l, sizeof(path) - l, "/f%d", i);
		fd = open(path, O_CREAT | O_RDWR, 0644);
		if (fd < 0)
			die("creat");
		if (i == files - 1 && fsync(fd))
			die("fsync");
		close(fd);
		path[l] = 0;
	}
}

/* every directory's link count and block count; returns the number of dirs */
static int walk(const char *path)
{
	struct stat st, s;
	struct dirent *de;
	int dirs = 1, sub = 0;
	char p[1024];
	DIR *d;

	if (lstat(path, &st) || !(d = opendir(path)))
		die(path);
	while ((de = readdir(d))) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		snprintf(p, sizeof(p), "%s/%s", path, de->d_name);
		if (lstat(p, &s))
			die(p);
		if (S_ISDIR(s.st_mode)) {
			sub++;
			dirs += walk(p);
		}
	}
	closedir(d);
	if (!problem[0] && st.st_nlink != 2 + (nlink_t)sub)
		snprintf(problem, sizeof(problem),
			 "directory %s/ has %lu links, should have %d",
			 path + strlen(MNT), (unsigned long)st.st_nlink, 2 + sub);
	if (!problem[0] && st.st_blocks * 512 < st.st_size)
		snprintf(problem, sizeof(problem),
			 "directory %s/ is %lld bytes but has %lld blocks",
			 path + strlen(MNT), (long long)st.st_size,
			 (long long)st.st_blocks);
	return dirs;
}

static uint32_t le(const unsigned char *p, int n)
{
	uint32_t v = 0;

	while (n--)
		v = v << 8 | p[n];
	return v;
}

/* bg_used_dirs_count of all groups added up, read from the disk */
static long used_dirs(void)
{
	unsigned char sb[1024], d[64];
	uint32_t bs, first, groups, dsize = 32;
	long sum = 0;
	int fd;

	fd = open(IMG, O_RDONLY);
	if (fd < 0 || pread(fd, sb, 1024, 1024) != 1024)
		die("superblock");
	bs = 1024 << le(sb + 0x18, 4);
	first = le(sb + 0x14, 4);
	groups = (le(sb + 0x04, 4) - first + le(sb + 0x20, 4) - 1) / le(sb + 0x20, 4);
	if (le(sb + 0x60, 4) & 0x80)
		dsize = le(sb + 0xfe, 2);
	for (uint32_t g = 0; g < groups; g++) {
		if (pread(fd, d, dsize, (off_t)(first + 1) * bs + g * dsize) != dsize)
			die("group descriptor");
		sum += le(d + 0x10, 2) + (dsize >= 64 ? le(d + 0x30, 2) << 16 : 0);
	}
	close(fd);
	return sum;
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	double t0 = now();
	int round = 0, dirs;
	long gd;

	setvbuf(stdout, NULL, _IONBF, 0);
	srand(getpid() ^ time(NULL));
	mkdir(MNT, 0755);
	printf("ext4fcmkdir: mkdir, create a file in it, fsync, power cut (dm-flakey),\n"
	       "    mount to replay the fast commit and check the counts (up to %d s)\n", limit);
	while (now() - t0 < limit) {
		round++;
		setup();
		do_mount();
		work(1 + rand() % 3, 1 + rand() % 3);
		/* the power cut: nothing written after the fsync reaches the disk */
		table("flakey", "0 0 180 1 drop_writes");
		do_umount();
		table("linear", "0");
		do_mount();	/* replays the fast commit */
		do_umount();
		do_mount();
		problem[0] = 0;
		dirs = walk(MNT);
		do_umount();
		dm(DM_DEV_REMOVE, 0, NULL, NULL, NULL);
		gd = used_dirs();
		if (!problem[0] && gd != dirs)
			snprintf(problem, sizeof(problem),
				 "group descriptors count %ld directories, there are %d",
				 gd, dirs);
		if (problem[0]) {
			printf("round %d: after the fast commit replay %s\n", round, problem);
			/* what e2fsck says, if it is there */
			gd = system("e2fsck -fn " IMG " 2>&1 | grep -E 'should be|count wrong'");
			printf("ext4fcmkdir: wrong counts after a fast commit replay: the bug\n");
			printf("LB-RESULT bug rounds=%d seconds=%.1f\n", round, now() - t0);
			return 0;
		}
	}
	printf("ext4fcmkdir: %d rounds, the counts were right every time\n", round);
	printf("LB-RESULT none rounds=%d seconds=%.1f\n", round, now() - t0);
	return 1;
}

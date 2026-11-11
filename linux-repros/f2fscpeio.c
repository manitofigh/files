// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: f2fscpeio [SECONDS] (needs root)
 *
 * SECONDS is how long to keep trying (300 by default).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <linux/f2fs.h>
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
#define DMNAME	"f2fscpeio"
#define DMNODE	"/tmp/f2fscpeio-dm"
#define MNT	"/mnt/f2fscpeio"
#define BLK	4096
#define NOBAD	((uint64_t)-1)

static const char *ok = "[+]", *warn = "[~]", *err = "[-]";

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void die(const char *what)
{
	printf("%s %s: %s\n", err, what, strerror(errno));
	exit(2);
}

/* read or write one block of DEV, bypassing the page cache */
static void dev_io(int wr, uint64_t blk, void *buf)
{
	int fd = open(DEV, (wr ? O_RDWR : O_RDONLY) | O_DIRECT);

	if (fd < 0)
		die("open " DEV);
	if ((wr ? pwrite(fd, buf, BLK, blk * BLK) : pread(fd, buf, BLK, blk * BLK)) != BLK)
		die(wr ? "write " DEV : "read " DEV);
	close(fd);
}

static void fill(char *p, size_t len, unsigned int seed)
{
	for (size_t i = 0; i < len; i++)
		p[i] = (char)(seed * 31 + i * 7 + (i >> 9));
}

static void put_file(const char *name, size_t len, unsigned int seed)
{
	char path[64], *p = malloc(len);
	int fd;

	snprintf(path, sizeof(path), MNT "/%s", name);
	fill(p, len, seed);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0 || write(fd, p, len) != (ssize_t)len)
		die("write file");
	close(fd);
	free(p);
}

/* 1: NAME is there with the right contents */
static int check_file(const char *name, size_t len, unsigned int seed)
{
	char path[64], *want = malloc(len), *got = malloc(len + 1);
	int fd, r = 0;

	snprintf(path, sizeof(path), MNT "/%s", name);
	fill(want, len, seed);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		r = read(fd, got, len + 1) == (ssize_t)len && !memcmp(want, got, len);
		close(fd);
	}
	free(want);
	free(got);
	return r;
}

/* sync, then cut the power: no checkpoint after the one sync wrote */
static void sync_and_cut(void)
{
	__u32 how = F2FS_GOING_DOWN_NOSYNC;
	int fd;

	sync();
	fd = open(MNT, O_RDONLY | O_DIRECTORY);
	if (fd < 0 || ioctl(fd, F2FS_IOC_SHUTDOWN, &how))
		die("F2FS_IOC_SHUTDOWN");
	close(fd);
	if (umount(MNT))
		die("umount");
}

/* the two checkpoint packs: first block, version, block count */
struct cps {
	uint64_t start[2], ver[2];
	uint32_t total[2];
	int newest;
};

static void read_cps(struct cps *c)
{
	unsigned char *b;
	uint32_t cp_blkaddr, log_bps;

	if (posix_memalign((void **)&b, BLK, BLK))
		die("posix_memalign");
	dev_io(0, 0, b);
	cp_blkaddr = *(uint32_t *)(b + 1024 + 76);
	log_bps = *(uint32_t *)(b + 1024 + 20);
	for (int i = 0; i < 2; i++) {
		c->start[i] = cp_blkaddr + ((uint64_t)i << log_bps);
		dev_io(0, c->start[i], b);
		c->ver[i] = *(uint64_t *)b;
		c->total[i] = *(uint32_t *)(b + 136);
	}
	c->newest = (int64_t)(c->ver[1] - c->ver[0]) > 0;
	free(b);
}

static int is_f2fs(void)
{
	unsigned char *b;
	int r;

	if (posix_memalign((void **)&b, BLK, BLK))
		die("posix_memalign");
	dev_io(0, 0, b);
	r = *(uint32_t *)(b + 1024) == 0xF2F52010;
	free(b);
	return r;
}

static int dm(unsigned long cmd, struct dm_ioctl *io)
{
	int fd = open("/dev/mapper/control", O_RDWR), r;

	if (fd < 0)
		die("open /dev/mapper/control");
	io->version[0] = DM_VERSION_MAJOR;
	strcpy(io->name, DMNAME);
	r = ioctl(fd, cmd, io);
	close(fd);
	return r;
}

static void dm_remove(void)
{
	struct dm_ioctl io = { .data_size = sizeof(io) };

	unlink(DMNODE);
	dm(DM_DEV_REMOVE, &io);
}

/* load DEV, with an error target over block BAD unless BAD is NOBAD, into DMNAME */
static void dm_table(uint64_t bad)
{
	char buf[4096] __attribute__((aligned(8))) = { 0 };
	struct dm_ioctl *io = (void *)buf;
	uint64_t sz, s = bad * (BLK / 512), e = s + BLK / 512;
	struct { uint64_t start, len; const char *type; char params[64]; } t[3] = {
		{ 0, s, "linear", DEV " 0" },
		{ s, BLK / 512, "error", "" },
		{ e, 0, "linear", "" },
	};
	size_t off = sizeof(*io);
	int fd = open(DEV, O_RDONLY), n = 3;

	if (fd < 0 || ioctl(fd, BLKGETSIZE64, &sz))
		die("size of " DEV);
	close(fd);
	t[2].len = sz / 512 - e;
	snprintf(t[2].params, sizeof(t[2].params), DEV " %llu", (unsigned long long)e);
	if (bad == NOBAD) {
		t[0].len = sz / 512;
		n = 1;
	}

	for (int i = 0; i < n; i++) {
		struct dm_target_spec *sp = (void *)(buf + off);
		size_t len = (sizeof(*sp) + strlen(t[i].params) + 1 + 7) & ~7UL;

		sp->sector_start = t[i].start;
		sp->length = t[i].len;
		sp->next = i < n - 1 ? len : 0;
		strcpy(sp->target_type, t[i].type);
		strcpy((char *)(sp + 1), t[i].params);
		off += len;
	}
	io->data_size = off;
	io->data_start = sizeof(*io);
	io->target_count = n;
	if (dm(DM_TABLE_LOAD, io))
		die("DM_TABLE_LOAD");
	memset(buf, 0, sizeof(*io));
	io->data_size = sizeof(*io);
	io->flags = DM_SKIP_LOCKFS_FLAG;	/* no freeze of a mounted f2fs */
	if (dm(DM_DEV_SUSPEND, io))	/* without DM_SUSPEND_FLAG: swap in and resume */
		die("DM_DEV_SUSPEND");
}

/* DMNODE: DEV with an error target over block BAD */
static void dm_create(uint64_t bad)
{
	struct dm_ioctl io = { .data_size = sizeof(io) };

	if (dm(DM_DEV_CREATE, &io))
		die("DM_DEV_CREATE");
	mknod(DMNODE, S_IFBLK | 0600, makedev(major(io.dev), minor(io.dev)));
	dm_table(bad);
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	double t0 = now();
	int round = 0, eio = 0, hit = 0;

	setvbuf(stdout, NULL, _IOLBF, 0);
	srand(getpid() ^ time(NULL));
	if (access(DEV, F_OK) && system("modprobe brd rd_nr=1 rd_size=131072")) {
		printf("%s no %s (brd)\n", err, DEV);
		return 2;
	}
	if (access("/dev/mapper/control", F_OK) && system("modprobe dm-mod")) {
		printf("%s no device-mapper\n", err);
		return 2;
	}
	mkdir(MNT, 0755);
	umount(MNT);
	dm_remove();
	if (system("mkfs.f2fs -f -q " DEV " >/dev/null 2>&1") && !is_f2fs()) {
		printf("%s mkfs.f2fs %s failed\n", err, DEV);
		return 2;
	}

	while (!hit && now() - t0 < limit) {
		char old[32], new[32];
		size_t olen = 4096 + rand() % 65536, nlen = 4096 + rand() % 262144;
		int last = rand() % 2, kept, merr = 0, seen = -1;
		struct cps c;
		uint64_t bad;

		round++;
		if (mount(DEV, MNT, "f2fs", 0, NULL))
			die("mount " DEV);
		/* keep the filesystem from filling up */
		snprintf(old, sizeof(old), MNT "/old%d", round - 1);
		snprintf(new, sizeof(new), MNT "/new%d", round - 1);
		unlink(old);
		unlink(new);
		snprintf(old, sizeof(old), "old%d", round);
		snprintf(new, sizeof(new), "new%d", round);
		put_file(old, olen, round);
		sync();
		/* NEW is only in the checkpoint of the second sync */
		put_file(new, nlen, round + 1);
		sync_and_cut();

		/* fail the first or the last block of the newest pack */
		read_cps(&c);
		bad = c.start[c.newest] + (last ? c.total[c.newest] - 1 : 0);
		dm_create(bad);
		if (mount(DMNODE, MNT, "f2fs", 0, NULL)) {
			merr = errno;
		} else {
			/* the device works again: the error was only at mount */
			dm_table(NOBAD);
			seen = check_file(new, nlen, round + 1);
			umount(MNT);
		}
		dm_remove();

		if (mount(DEV, MNT, "f2fs", 0, NULL))
			die("mount " DEV);
		kept = check_file(new, nlen, round + 1);
		umount(MNT);

		if (merr == EIO && kept) {
			eio++;
		} else if (!merr && !seen && !kept) {
			printf("LB-ROLLBACK round %d: a read error on block %llu (%s block of the newest checkpoint pack, version %llx) "
			       "mounted the older pack (version %llx); %s (%zu bytes, synced) is gone after a clean mount\n",
			       round, (unsigned long long)bad, last ? "last" : "first",
			       (unsigned long long)c.ver[c.newest],
			       (unsigned long long)c.ver[!c.newest], new, nlen);
			printf("%s the filesystem was rolled back to the older checkpoint: the bug\n", ok);
			hit = 1;
		} else if (merr || seen != 1 || !kept) {
			printf("%s round %d: mount with the read error: %s, %s %s then, %s after a clean mount\n",
			       warn, round, merr ? strerror(merr) : "ok", new,
			       seen < 0 ? "-" : seen ? "there" : "missing",
			       kept ? "there" : "missing");
		}
	}
	if (!hit)
		printf("%s no rollback in %d rounds (%d mounts failed with EIO and kept the data)\n",
		       ok, round, eio);
	printf("LB-RESULT %s rounds=%d seconds=%.1f\n", hit ? "bug" : "none",
	       round, now() - t0);
	return hit ? 0 : 1;
}

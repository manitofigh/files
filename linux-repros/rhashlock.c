// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: rhashlock [SECONDS] (needs root)
 *
 * SECONDS is how long to keep trying (300 by default).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAP_TYPE_RHASH	35		/* BPF_MAP_TYPE_RHASH (v7.2) */
#define KEY		7
#define STUCK		5		/* s without a finished map operation: stuck */
#define NKEYS		64		/* keys per round: the table grows and shrinks */
#define FUNC		"rhashtable_jhash2"	/* hashes keys when the table is resized */
#define REGS_DI		112		/* offsetof(struct pt_regs, di) on x86_64 */

static const char *ok = "[+]", *warn = "[~]", *err = "[-]";

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

static int sys_bpf(int cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static void __attribute__((noreturn)) die(const char *msg)
{
	printf("%s rhashlock: %s: %s\n", err, msg, strerror(errno));
	exit(2);
}

static int map_create(int type, int value_size, int entries, int flags)
{
	union bpf_attr attr = {
		.map_type = type, .key_size = 4, .value_size = value_size,
		.max_entries = entries, .map_flags = flags,
	};
	int fd = sys_bpf(BPF_MAP_CREATE, &attr);

	if (fd < 0)
		die(type == MAP_TYPE_RHASH ? "creating the resizable hash map" : "BPF_MAP_CREATE");
	return fd;
}

static int map_op(int cmd, int fd, uint32_t key, void *value)
{
	union bpf_attr attr = { .map_fd = fd, .key = (uintptr_t)&key,
				.value = (uintptr_t)value };

	return sys_bpf(cmd, &attr);
}

#define I(c, d, s, o, i) ((struct bpf_insn){ c, d, s, o, i })
#define OUT		0x7fff		/* jump target: the program's end */
#define MOV_R(d, s)	I(BPF_ALU64 | BPF_MOV | BPF_X, d, s, 0, 0)
#define MOV_I(d, i)	I(BPF_ALU64 | BPF_MOV | BPF_K, d, 0, 0, i)
#define ADD_I(d, i)	I(BPF_ALU64 | BPF_ADD | BPF_K, d, 0, 0, i)
#define ST_W(d, o, i)	I(BPF_ST | BPF_MEM | BPF_W, d, 0, o, i)
#define LDX(sz, d, s, o) I(BPF_LDX | BPF_MEM | (sz), d, s, o, 0)
#define LD_MAP(d, fd)	I(BPF_LD | BPF_DW | BPF_IMM, d, BPF_PSEUDO_MAP_FD, 0, fd), I(0, 0, 0, 0, 0)
#define CALL(f)		I(BPF_JMP | BPF_CALL, 0, 0, 0, f)
#define JNE_I(d, i)	I(BPF_JMP | BPF_JNE | BPF_K, d, 0, OUT, i)
#define JEQ_I(d, i)	I(BPF_JMP | BPF_JEQ | BPF_K, d, 0, OUT, i)
#define XADD(d, s)	I(BPF_STX | BPF_ATOMIC | BPF_DW, d, s, 0, BPF_ADD)
#define EXIT		I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

/* stats[i] += 1; ends the program if the lookup fails */
#define COUNT(stats, i)							\
	ST_W(BPF_REG_10, -36, i),					\
	MOV_R(BPF_REG_2, BPF_REG_10), ADD_I(BPF_REG_2, -36),		\
	LD_MAP(BPF_REG_1, stats),					\
	CALL(BPF_FUNC_map_lookup_elem),					\
	JEQ_I(BPF_REG_0, 0),						\
	MOV_I(BPF_REG_1, 1),						\
	XADD(BPF_REG_0, BPF_REG_1)

/*
 * kprobe on rhashtable_jhash2(key, ...): when key is KEY, count it in
 * stats[0] and delete KEY from map; count -EBUSY in stats[1]
 */
static int prog_load(int map, int stats)
{
	struct bpf_insn insn[] = {
		/* fp-8 = *(u32 *)regs->di */
		LDX(BPF_DW, BPF_REG_3, BPF_REG_1, REGS_DI),
		MOV_R(BPF_REG_1, BPF_REG_10), ADD_I(BPF_REG_1, -8),
		MOV_I(BPF_REG_2, 4),
		CALL(BPF_FUNC_probe_read_kernel),
		JNE_I(BPF_REG_0, 0),
		LDX(BPF_W, BPF_REG_1, BPF_REG_10, -8),
		JNE_I(BPF_REG_1, KEY),
		COUNT(stats, 0),
		/* delete KEY */
		ST_W(BPF_REG_10, -40, KEY),
		MOV_R(BPF_REG_2, BPF_REG_10), ADD_I(BPF_REG_2, -40),
		LD_MAP(BPF_REG_1, map),
		CALL(BPF_FUNC_map_delete_elem),
		JNE_I(BPF_REG_0, -EBUSY),
		COUNT(stats, 1),
		MOV_I(BPF_REG_0, 0),
		EXIT,
	};
	int len = sizeof(insn) / sizeof(insn[0]);
	static char log[1 << 16];
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_KPROBE,
		.insns = (uintptr_t)insn, .insn_cnt = len,
		.license = (uintptr_t)"GPL",
		.log_buf = (uintptr_t)log, .log_size = sizeof(log), .log_level = 1,
	};
	int fd;

	for (int i = 0; i < len; i++)
		if (BPF_CLASS(insn[i].code) == BPF_JMP && insn[i].off == OUT)
			insn[i].off = len - 2 - i - 1;
	fd = sys_bpf(BPF_PROG_LOAD, &attr);
	if (fd < 0) {
		printf("%s", log);
		die("BPF_PROG_LOAD");
	}
	return fd;
}

/* a kprobe perf event on FUNC running prog */
static int kprobe_attach(int prog)
{
	struct perf_event_attr attr = { .size = sizeof(attr) };
	FILE *f = fopen("/sys/bus/event_source/devices/kprobe/type", "r");
	int fd;

	if (!f || fscanf(f, "%u", &attr.type) != 1)
		die("no kprobe PMU (CONFIG_KPROBE_EVENTS?)");
	fclose(f);
	attr.config1 = (uintptr_t)FUNC;
	fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
	if (fd < 0)
		die("kprobe on " FUNC);
	if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, prog) || ioctl(fd, PERF_EVENT_IOC_ENABLE, 0))
		die("attaching the program to the kprobe");
	return fd;
}

/* insert keys 0..NKEYS-1, then delete them, forever; counts operations in *done */
static void __attribute__((noreturn)) churn(int map, int cpu, volatile long *done)
{
	uint64_t val = 1;

	prctl(PR_SET_PDEATHSIG, SIGKILL);
	pin(cpu);
	for (;;) {
		for (uint32_t k = 0; k < NKEYS; k++, (*done)++)
			if (map_op(BPF_MAP_UPDATE_ELEM, map, k, &val) && errno != EEXIST)
				_exit(2);
		for (uint32_t k = 0; k < NKEYS; k++, (*done)++)
			if (map_op(BPF_MAP_DELETE_ELEM, map, k, NULL) && errno != ENOENT)
				_exit(2);
		done[1]++;
	}
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	int map, stats, prog, kp, status;
	uint64_t seen = 0, busy = 0;
	volatile long *done;
	long last = 0, rounds;
	double t0, moved;
	pid_t kid;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (isatty(STDOUT_FILENO)) {
		ok = "\033[32m[+]\033[0m";
		warn = "\033[33m[~]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	if (ncpu < 2) {
		printf("%s rhashlock: needs 2 CPUs\n", err);
		return 2;
	}
	done = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (done == MAP_FAILED)
		die("mmap");

	map = map_create(MAP_TYPE_RHASH, 8, 2 * NKEYS, BPF_F_NO_PREALLOC);
	stats = map_create(BPF_MAP_TYPE_ARRAY, 8, 2, 0);
	prog = prog_load(map, stats);
	kp = kprobe_attach(prog);

	/* the resize work runs on the cpu that queued it: the child's */
	kid = fork();
	if (kid == 0)
		churn(map, 0, done);
	pin(ncpu - 1);

	t0 = moved = now();
	while (now() - t0 < limit) {
		usleep(100000);
		if (waitpid(kid, &status, WNOHANG) == kid) {
			printf("%s rhashlock: a map update or delete failed\n", err);
			return 2;
		}
		if (done[0] != last) {
			last = done[0];
			moved = now();
		} else if (now() - moved >= STUCK) {
			rounds = done[1] + 1;
			printf("LB-RESULT bug rounds=%ld seconds=%.1f\n", rounds, moved - t0);
			printf("%s rhashlock: bug: the map operations on cpu 0 stopped %d s ago (round %ld, %.1f s);\n"
			       "    cpu 0 spins on a bucket lock that it holds itself, with interrupts off\n",
			       ok, STUCK, rounds, moved - t0);
			return 0;
		}
	}
	kill(kid, SIGKILL);
	waitpid(kid, NULL, 0);
	close(kp);
	rounds = done[1];
	map_op(BPF_MAP_LOOKUP_ELEM, stats, 0, &seen);
	map_op(BPF_MAP_LOOKUP_ELEM, stats, 1, &busy);
	printf("LB-RESULT none rounds=%ld seconds=%.1f\n", rounds, now() - t0);
	if (!seen) {
		printf("%s rhashlock: the program never saw key %d being rehashed\n", warn, KEY);
		return 1;
	}
	printf("%s rhashlock: no stuck cpu in %ld rounds, %.1f s; key %d was rehashed %llu times,\n"
	       "    the program's delete then failed with -EBUSY %llu times\n",
	       ok, rounds, now() - t0, KEY, (unsigned long long)seen, (unsigned long long)busy);
	return 1;
}

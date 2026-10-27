// SPDX-License-Identifier: GPL-2.0
/*
 * bpftimer: a bpf timer fires on its freed inner map (kernel/bpf/helpers.c)
 *
 * the timer lives in an inner array map m that the programs reach only
 * through an outer array-of-maps o. updating m[0] or closing m's last fd
 * detaches the timer from m and cancels it (bpf_async_cancel_and_free()). a
 * racing bpf_timer_set_callback() that read the timer just before puts its
 * callback back, and a racing bpf_timer_start() that took its reference just
 * before arms it again. deleting o[0] frees m after an rcu grace period, the
 * detached timer only after an rcu tasks trace grace period: a timer
 * expiring in between runs bpf_timer_cb() on the freed map.
 *
 * needs root and CONFIG_BPF_JIT; raw bpf(2) with hand-built btf, no libbpf.
 * usage: bpftimer [SECONDS]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define REPEAT		256		/* program runs per BPF_PROG_TEST_RUN */
#define ATTEMPTS	32		/* timers detached per inner map */
#define DELAY_MIN	1000000		/* timer delay: 1 to 31 ms */
#define DELAY_SPAN	30000000
#define TAINT_BAD_PAGE	32		/* set by a kasan report */

static int btf_fd, outer_fd, conf_fd;
static int prog_init, prog_setcb, prog_start;
static _Atomic int rounds;
static const char *ok = "[+]", *err = "[-]";

static void __attribute__((noreturn)) die(const char *msg)
{
	fprintf(stderr, "%s bpftimer: %s: %s\n", err, msg, strerror(errno));
	exit(2);
}

static int sys_bpf(int cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static long long now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void pin(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set))
		die("sched_setaffinity");
}

static int tainted(void)
{
	FILE *f = fopen("/proc/sys/kernel/tainted", "r");
	int t = 0;

	if (f) {
		if (fscanf(f, "%d", &t) != 1)
			t = 0;
		fclose(f);
	}
	return t;
}

/*
 * btf: [1] int, [2] long long, [3] struct bpf_timer, [4] struct val { struct
 * bpf_timer t; }, [5]/[6] int main(void), [7]/[8] int cb(long long a, b, t)
 */
static int load_btf(void)
{
	static const char str[] = "\0int\0long long\0bpf_timer\0a\0b\0val\0t\0main\0cb";
	enum { S_INT = 1, S_LL = 5, S_TIMER = 15, S_A = 25, S_B = 27, S_VAL = 29,
	       S_T = 33, S_MAIN = 35, S_CB = 40 };
	static const uint32_t types[] = {
		S_INT, BTF_KIND_INT << 24, 4, (BTF_INT_SIGNED << 24) | 32,
		S_LL, BTF_KIND_INT << 24, 8, (BTF_INT_SIGNED << 24) | 64,
		S_TIMER, (BTF_KIND_STRUCT << 24) | 2, 16, S_A, 2, 0, S_B, 2, 64,
		S_VAL, (BTF_KIND_STRUCT << 24) | 1, 16, S_T, 3, 0,
		0, BTF_KIND_FUNC_PROTO << 24, 1,
		S_MAIN, BTF_KIND_FUNC << 24, 5,
		0, (BTF_KIND_FUNC_PROTO << 24) | 3, 1, S_A, 2, S_B, 2, S_T, 2,
		S_CB, BTF_KIND_FUNC << 24, 7,
	};
	static struct {
		struct btf_header hdr;
		uint32_t types[sizeof(types) / 4];
		char str[sizeof(str)];
	} blob = {
		.hdr = { .magic = BTF_MAGIC, .version = BTF_VERSION,
			 .hdr_len = sizeof(struct btf_header),
			 .type_len = sizeof(types), .str_off = sizeof(types),
			 .str_len = sizeof(str) },
	};
	union bpf_attr attr = { 0 };
	int fd;

	memcpy(blob.types, types, sizeof(types));
	memcpy(blob.str, str, sizeof(str));
	attr.btf = (uintptr_t)&blob;
	attr.btf_size = sizeof(blob.hdr) + sizeof(types) + sizeof(str);
	fd = sys_bpf(BPF_BTF_LOAD, &attr);
	if (fd < 0)
		die("BPF_BTF_LOAD");
	return fd;
}

static int map_create(int type, int value_size, int entries, int inner, int btf_value)
{
	union bpf_attr attr = {
		.map_type = type, .key_size = 4, .value_size = value_size,
		.max_entries = entries, .inner_map_fd = inner,
	};
	int fd;

	if (btf_value) {
		attr.btf_fd = btf_fd;
		attr.btf_key_type_id = 1;
		attr.btf_value_type_id = btf_value;
	}
	fd = sys_bpf(BPF_MAP_CREATE, &attr);
	if (fd < 0)
		die("BPF_MAP_CREATE");
	return fd;
}

static void map_update(int fd, uint32_t key, const void *value)
{
	union bpf_attr attr = { .map_fd = fd, .key = (uintptr_t)&key,
				.value = (uintptr_t)value };

	if (sys_bpf(BPF_MAP_UPDATE_ELEM, &attr))
		die("BPF_MAP_UPDATE_ELEM");
}

#define I(c, d, s, o, i) ((struct bpf_insn){ c, d, s, o, i })
#define MOV_R(d, s)	I(BPF_ALU64 | BPF_MOV | BPF_X, d, s, 0, 0)
#define MOV_I(d, i)	I(BPF_ALU64 | BPF_MOV | BPF_K, d, 0, 0, i)
#define ADD_I(d, i)	I(BPF_ALU64 | BPF_ADD | BPF_K, d, 0, 0, i)
#define ST_W(d, o, i)	I(BPF_ST | BPF_MEM | BPF_W, d, 0, o, i)
#define LDX_DW(d, s, o)	I(BPF_LDX | BPF_MEM | BPF_DW, d, s, o, 0)
#define LD_MAP(d, fd)	I(BPF_LD | BPF_DW | BPF_IMM, d, BPF_PSEUDO_MAP_FD, 0, fd), I(0, 0, 0, 0, 0)
#define LD_FUNC(d, off)	I(BPF_LD | BPF_DW | BPF_IMM, d, BPF_PSEUDO_FUNC, 0, off), I(0, 0, 0, 0, 0)
#define CALL(f)		I(BPF_JMP | BPF_CALL, 0, 0, 0, f)
#define JEQ_I(d, i, o)	I(BPF_JMP | BPF_JEQ | BPF_K, d, 0, o, i)
#define EXIT		I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

/* r6 = &m[0], r7 = m, with m = o[0]; jumps "out" insns past the end if missing */
#define REACH_TIMER(out)						\
	ST_W(BPF_REG_10, -4, 0),					\
	MOV_R(BPF_REG_2, BPF_REG_10), ADD_I(BPF_REG_2, -4),		\
	LD_MAP(BPF_REG_1, outer_fd),					\
	CALL(BPF_FUNC_map_lookup_elem),					\
	JEQ_I(BPF_REG_0, 0, (out) + 6),					\
	MOV_R(BPF_REG_7, BPF_REG_0),					\
	MOV_R(BPF_REG_2, BPF_REG_10), ADD_I(BPF_REG_2, -4),		\
	MOV_R(BPF_REG_1, BPF_REG_7),					\
	CALL(BPF_FUNC_map_lookup_elem),					\
	JEQ_I(BPF_REG_0, 0, (out)),					\
	MOV_R(BPF_REG_6, BPF_REG_0)

/* the timer callback: return 0 */
#define CALLBACK	MOV_I(BPF_REG_0, 0), EXIT
#define CALLBACK_LEN	2

/* with_cb: the program ends with CALLBACK, which needs btf func_info */
static int prog_load(const struct bpf_insn *insn, int len, const char *name, int with_cb)
{
	struct bpf_func_info info[2] = {
		{ .insn_off = 0, .type_id = 6 },
		{ .insn_off = len - CALLBACK_LEN, .type_id = 8 },
	};
	static char log[1 << 16];
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
		.insns = (uintptr_t)insn, .insn_cnt = len,
		.license = (uintptr_t)"GPL",
		.log_buf = (uintptr_t)log, .log_size = sizeof(log), .log_level = 1,
	};
	int fd;

	if (with_cb) {
		attr.prog_btf_fd = btf_fd;
		attr.func_info_rec_size = sizeof(info[0]);
		attr.func_info = (uintptr_t)info;
		attr.func_info_cnt = 2;
	}
	strncpy(attr.prog_name, name, sizeof(attr.prog_name) - 1);
	fd = sys_bpf(BPF_PROG_LOAD, &attr);
	if (fd < 0) {
		fprintf(stderr, "%s", log);
		die("BPF_PROG_LOAD");
	}
	return fd;
}

#define LEN(a)	((int)(sizeof(a) / sizeof((a)[0])))

static void load_progs(void)
{
	/* bpf_timer_init(&v->t, m, CLOCK_MONOTONIC); bpf_timer_set_callback(&v->t, cb) */
	struct bpf_insn init[] = {
		REACH_TIMER(10),
		MOV_R(BPF_REG_1, BPF_REG_6), MOV_R(BPF_REG_2, BPF_REG_7),
		MOV_I(BPF_REG_3, CLOCK_MONOTONIC),
		CALL(BPF_FUNC_timer_init),
		MOV_R(BPF_REG_1, BPF_REG_6),
		LD_FUNC(BPF_REG_2, 5),
		CALL(BPF_FUNC_timer_set_callback),
		EXIT,
		MOV_I(BPF_REG_0, 1), EXIT,		/* out */
		CALLBACK,
	};
	/* bpf_timer_set_callback(&v->t, cb) */
	struct bpf_insn setcb[] = {
		REACH_TIMER(6),
		MOV_R(BPF_REG_1, BPF_REG_6),
		LD_FUNC(BPF_REG_2, 5),
		CALL(BPF_FUNC_timer_set_callback),
		EXIT,
		MOV_I(BPF_REG_0, 1), EXIT,		/* out */
		CALLBACK,
	};
	/* bpf_timer_start(&v->t, c[0], 0) */
	struct bpf_insn start[] = {
		ST_W(BPF_REG_10, -4, 0),
		MOV_R(BPF_REG_2, BPF_REG_10), ADD_I(BPF_REG_2, -4),
		LD_MAP(BPF_REG_1, conf_fd),
		CALL(BPF_FUNC_map_lookup_elem),
		JEQ_I(BPF_REG_0, 0, 20),
		LDX_DW(BPF_REG_8, BPF_REG_0, 0),
		REACH_TIMER(6),
		MOV_R(BPF_REG_1, BPF_REG_6), MOV_R(BPF_REG_2, BPF_REG_8),
		MOV_I(BPF_REG_3, 0),
		CALL(BPF_FUNC_timer_start),
		EXIT,
		MOV_I(BPF_REG_0, 1), EXIT,		/* out */
	};

	prog_init = prog_load(init, LEN(init), "timer_init", 1);
	prog_setcb = prog_load(setcb, LEN(setcb), "timer_setcb", 1);
	prog_start = prog_load(start, LEN(start), "timer_start", 0);
}

static int test_run(int prog, int repeat)
{
	unsigned char packet[64] = { 0 };
	union bpf_attr attr = { 0 };

	attr.test.prog_fd = prog;
	attr.test.data_in = (uintptr_t)packet;
	attr.test.data_size_in = sizeof(packet);
	attr.test.repeat = repeat;
	if (sys_bpf(BPF_PROG_TEST_RUN, &attr))
		die("BPF_PROG_TEST_RUN");
	return attr.test.retval;
}

/* threads "start" (cpu 0) and "setcb" (cpu 1): run their program on o[0], nonstop */
static void *racer(void *arg)
{
	int setcb = arg != NULL;

	pin(setcb);
	for (;;)
		test_run(setcb ? prog_setcb : prog_start, REPEAT);
	return NULL;
}

/* thread "close" (cpu 2): one round per inner map m */
static void *closer(void *arg)
{
	uint32_t key = 0, zero[4] = { 0 };
	union bpf_attr attr = { .map_fd = outer_fd, .key = (uintptr_t)&key };
	uint64_t delay;
	int fd, k;
	long i;

	pin(2);
	for (;;) {
		fd = map_create(BPF_MAP_TYPE_ARRAY, 16, 1, 0, 4);
		map_update(outer_fd, 0, &fd);
		delay = DELAY_MIN + rand() % DELAY_SPAN;
		map_update(conf_fd, 0, &delay);

		/* new timers on m[0]: an update detaches each one, the close the last */
		for (k = 1; k <= ATTEMPTS; k++) {
			if (test_run(prog_init, 1)) {
				errno = EINVAL;
				die("timer init");
			}
			for (i = rand() % 20000; i > 0; i--)
				__asm__ volatile("" ::: "memory");
			if (k < ATTEMPTS)
				map_update(fd, 0, zero);
		}
		close(fd);

		/* m's last reference: m is freed after an rcu grace period */
		if (sys_bpf(BPF_MAP_DELETE_ELEM, &attr))
			die("BPF_MAP_DELETE_ELEM");
		rounds++;
	}
	return arg;
}

/* a kernel report (kasan, lockdep, warning) taints the kernel */
static int bug_seen(int taint0, double secs)
{
	int taint = tainted(), n = rounds;

	if (taint == taint0)
		return 0;
	sleep(2);	/* let the report reach the console first */
	printf("%s bpftimer: bug: the kernel reported an error after %d rounds, %.1f s (taint %d -> %d)\n",
	       ok, n, secs, taint0, taint);
	printf("LB-RESULT bug rounds=%d seconds=%.1f\n", n, secs);
	return 1;
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 600;
	void *(*fn[3])(void *) = { racer, racer, closer };
	double secs = 0, shown = 0;
	long long start;
	pthread_t thread;
	int taint0, fd;
	long i;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (isatty(STDOUT_FILENO)) {
		ok = "\033[32m[+]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	srand(getpid());
	/* kasan reports once per boot and taints the kernel: a fresh boot only */
	taint0 = tainted();
	if (taint0 & TAINT_BAD_PAGE) {
		fprintf(stderr, "%s bpftimer: kernel already tainted: reboot the VM first\n", err);
		return 2;
	}

	/* setup: c[0] = timer delay; o holds m */
	btf_fd = load_btf();
	conf_fd = map_create(BPF_MAP_TYPE_ARRAY, 8, 1, 0, 0);
	fd = map_create(BPF_MAP_TYPE_ARRAY, 16, 1, 0, 4);
	outer_fd = map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, 4, 1, fd, 0);
	close(fd);
	load_progs();
	for (i = 0; i < 3; i++) {
		errno = pthread_create(&thread, NULL, fn[i], (void *)i);
		if (errno)
			die("pthread_create");
	}
	printf("bpftimer: maps and programs loaded, racing for up to %d s\n", limit);

	/* watch, mostly asleep: cpu 3 stays free for the rcu and kworker threads */
	start = now_ns();
	while (secs < limit) {
		usleep(10000);
		secs = (now_ns() - start) / 1e9;
		if (bug_seen(taint0, secs))
			return 0;
		if (secs >= shown + 30) {
			shown = secs;
			printf("bpftimer: %d rounds, %.0f s\n", rounds, secs);
		}
	}

	printf("%s bpftimer: no bug in %d rounds, %.1f s\n", ok, rounds, secs);
	printf("LB-RESULT none rounds=%d seconds=%.1f\n", rounds, secs);
	return 1;
}

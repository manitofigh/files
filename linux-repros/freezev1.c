// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: freezev1 [SECONDS [FILTERS]] (needs root)
 *
 * SECONDS is how long to keep trying (300 by default).
 * FILTERS caps the number of seccomp filters of the second thread (10000).
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FZ	"/mnt/freezer"	/* v1 freezer hierarchy (run.sh) */
#define G	FZ "/freezev1"
#define PF_EXITING	0x4

static const char *ok = "[+]", *warn = "[~]", *err = "[-]";

/* shared by the reproducer, the round's child and the pid namespace init */
static struct shm {
	int go_b;	/* B: exit now */
	int go_a;	/* A: exit now */
	int ready;	/* B has its filters */
	int hog;	/* the busy loop on B's CPU runs while set */
	int setup_err;
	int filters;	/* seccomp filters B got */
	pid_t stuck;	/* the init that stays frozen */
	long frozen;	/* rounds in which the freeze caught the init */
	long window;	/* ... while B had not dropped the live count yet */
} *sh;

static int nfilters = 10000;

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

static int get(const char *path, char *buf, size_t len)
{
	int fd = open(path, O_RDONLY);
	ssize_t n = -1;

	if (fd >= 0) {
		n = read(fd, buf, len - 1);
		close(fd);
	}
	if (n < 0)
		return -1;
	buf[n] = 0;
	return 0;
}

static void fwait(int *addr)
{
	while (!__atomic_load_n(addr, __ATOMIC_ACQUIRE))
		syscall(SYS_futex, addr, FUTEX_WAIT, 0, NULL, NULL, 0);
}

static void fwake(int *addr)
{
	__atomic_store_n(addr, 1, __ATOMIC_RELEASE);
	syscall(SYS_futex, addr, FUTEX_WAKE, 1, NULL, NULL, 0);
}

/* state letter and flags of a task from /proc/PID/task/TID/stat */
static int task_stat(pid_t pid, pid_t tid, char *state, unsigned long *flags)
{
	char path[64], buf[512], *p;

	snprintf(path, sizeof(path), "/proc/%d/task/%d/stat", pid, tid);
	if (get(path, buf, sizeof(buf)))
		return -1;
	p = strrchr(buf, ')');
	if (!p || sscanf(p + 2, "%c %*d %*d %*d %*d %*d %lu", state, flags) != 2)
		return -1;
	return 0;
}

/* the other thread of PID */
static pid_t other_thread(pid_t pid)
{
	char path[64];
	struct dirent *d;
	pid_t tid = 0;
	DIR *dir;

	snprintf(path, sizeof(path), "/proc/%d/task", pid);
	dir = opendir(path);
	if (!dir)
		return 0;
	while ((d = readdir(dir)))
		if (atoi(d->d_name) > 0 && atoi(d->d_name) != pid)
			tid = atoi(d->d_name);
	closedir(dir);
	return tid;
}

/* B: many filters of its own, so its exit spends long in seccomp_filter_release() */
static void *thread_b(void *arg)
{
	struct sock_filter insn = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	struct sock_fprog prog = { .len = 1, .filter = &insn };
	struct sched_param sp = { 0 };

	pin(1);
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	/* up to the kernel's limit on the instructions of a filter chain (ENOMEM) */
	for (sh->filters = 0; sh->filters < nfilters; sh->filters++)
		if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) {
			if (errno != ENOMEM || sh->filters < 100)
				sh->setup_err = errno;
			break;
		}
	prctl(PR_SET_NAME, "fz-thread");
	sched_setscheduler(0, SCHED_IDLE, &sp);
	fwake(&sh->ready);
	fwait(&sh->go_b);
	syscall(SYS_exit, 0);
	return NULL;
}

/* P, pid 1 of the new pid namespace: thread A (the leader) and thread B */
static void init_main(void)
{
	pthread_t t;

	prctl(PR_SET_NAME, "fz-init");
	pin(0);
	if (pthread_create(&t, NULL, thread_b, NULL)) {
		sh->setup_err = errno;
		fwake(&sh->ready);
		_exit(2);
	}
	fwait(&sh->go_a);
	syscall(SYS_exit, 0);
}

static void hog_main(void)
{
	pin(1);
	while (__atomic_load_n(&sh->hog, __ATOMIC_RELAXED))
		;
	_exit(0);
}

/* wait until test() is true, up to SECS */
#define WAIT_FOR(test, secs) ({				\
	double __end = now() + (secs);			\
	int __ok;					\
	while (!(__ok = (test)) && now() < __end)	\
		usleep(200);				\
	__ok;						\
})

static int state_is(pid_t pid, pid_t tid, char want)
{
	unsigned long flags;
	char st;

	return !task_stat(pid, tid, &st, &flags) && st == want;
}

static int exiting(pid_t pid, pid_t tid)
{
	unsigned long flags;
	char st;

	return !task_stat(pid, tid, &st, &flags) && (flags & PF_EXITING);
}

static int gone(pid_t pid, pid_t tid)
{
	char path[64];

	snprintf(path, sizeof(path), "/proc/%d/task/%d", pid, tid);
	return access(path, F_OK) != 0;
}

/* pid listed in the cgroup: hidden once its process has no live threads */
static int listed(pid_t pid)
{
	char buf[4096], *p;
	int n = 0;

	if (get(G "/tasks", buf, sizeof(buf)))
		return 0;
	for (p = strtok(buf, "\n"); p && !n; p = strtok(NULL, "\n"))
		n = atoi(p) == pid;
	return n;
}

static int reaped(pid_t pid)
{
	return waitpid(pid, NULL, WNOHANG) == pid;
}

/*
 * One round, in a child (it owns the new pid namespace): returns 0 when the
 * init stays frozen after the thaw, 1 when not, 2 on a setup error.
 */
static int round_main(void)
{
	pid_t p = -1, d = -1, h, b;
	char buf[64], st;
	unsigned long flags;
	const char *why;

	sh->go_a = sh->go_b = sh->ready = sh->hog = sh->setup_err = 0;
	why = "new pid namespace";
	if (unshare(CLONE_NEWPID))
		goto setup;
	p = fork();
	if (p == 0)
		init_main();
	if (p < 0)
		goto setup;
	/* D: pid 2 of the namespace, our child; its pid keeps the init waiting */
	d = fork();
	if (d == 0) {
		for (;;)
			pause();
	}
	snprintf(buf, sizeof(buf), "%d", p);
	why = "moving the init into the freezer cgroup";
	if (d < 0 || put(G "/cgroup.procs", buf))
		goto setup;
	fwait(&sh->ready);
	why = "second thread or its seccomp filters";
	if (sh->setup_err) {
		errno = sh->setup_err;
		goto setup;
	}
	b = other_thread(p);
	if (!b)
		goto setup;

	/* B exits on CPU 1 under a busy loop; once it has PF_EXITING, A exits */
	sh->hog = 1;
	h = fork();
	if (h == 0)
		hog_main();
	usleep(2000);
	fwake(&sh->go_b);
	why = "second thread did not start its exit";
	if (!WAIT_FOR(exiting(p, b) || gone(p, b), 5))
		goto setup;
	fwake(&sh->go_a);
	/* A in zap_pid_ns_processes(), waiting for D's pid (TASK_IDLE) */
	why = "init did not reach its wait for the namespace's other pids";
	if (!WAIT_FOR(state_is(p, p, 'I'), 5))
		goto setup;
	put(G "/freezer.state", "FROZEN");
	if (state_is(p, p, 'D')) {
		sh->frozen++;
		/* still listed after the freeze: B is still between PF_EXITING and live-- */
		if (listed(p) && !gone(p, b) && exiting(p, b))
			sh->window++;
	}
	/* let B finish its exit: the last live thread is gone */
	__atomic_store_n(&sh->hog, 0, __ATOMIC_RELAXED);
	waitpid(h, NULL, 0);
	WAIT_FOR(gone(p, b), 10);
	put(G "/freezer.state", "THAWED");
	/* reaping D frees the last pid: a thawed init finishes its exit */
	kill(d, SIGKILL);
	waitpid(d, NULL, 0);
	if (WAIT_FOR(reaped(p), 2))
		return 1;
	if (task_stat(p, p, &st, &flags))
		return 1;
	get(G "/freezer.state", buf, sizeof(buf));
	if (st != 'D' || strncmp(buf, "THAWED", 6))
		return 1;
	kill(p, SIGKILL);
	if (WAIT_FOR(reaped(p), 3))
		return 1;
	if (!state_is(p, p, 'D'))
		return 1;
	sh->stuck = p;
	return 0;
setup:
	printf("%s freezev1: setup failed: %s (%s)\n", err, why, strerror(errno));
	sh->hog = 0;
	fwake(&sh->go_b);
	fwake(&sh->go_a);
	if (p > 0)
		kill(p, SIGKILL);
	if (d > 0)
		kill(d, SIGKILL);
	put(G "/freezer.state", "THAWED");
	return 2;
}

static void show_stack(pid_t pid)
{
	char path[64], buf[4096];

	snprintf(path, sizeof(path), "/proc/%d/stack", pid);
	if (!get(path, buf, sizeof(buf)))
		printf("freezev1: kernel stack of pid %d:\n%s", pid, buf);
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN), rc = 1, status;
	long round;
	double t0, last;
	pid_t r;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (isatty(STDOUT_FILENO)) {
		ok = "\033[32m[+]\033[0m";
		warn = "\033[33m[~]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	if (argc > 2)
		nfilters = atoi(argv[2]);
	if (ncpu < 2) {
		printf("%s freezev1: needs 2 CPUs\n", err);
		return 2;
	}
	sh = mmap(NULL, sizeof(*sh), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	rmdir(G);
	if (sh == MAP_FAILED || (mkdir(G, 0755) && errno != EEXIST)) {
		printf("%s freezev1: setup failed: %s\n", err, strerror(errno));
		return 2;
	}
	pin(0);

	t0 = last = now();
	for (round = 1; now() - t0 < limit; round++) {
		r = fork();
		if (r == 0)
			_exit(round_main());
		waitpid(r, &status, 0);
		rc = WIFEXITED(status) ? WEXITSTATUS(status) : 2;
		if (rc == 2) {
			printf("%s freezev1: round %ld failed to set up\n", err, round);
			return 2;
		}
		if (round == 1)
			printf("freezev1: the init's second thread has %d seccomp filters\n",
			       sh->filters);
		if (rc == 0)
			break;
		if (now() - last >= 10) {
			last = now();
			printf("freezev1: round %ld, %.0f s, the freeze caught the exiting init in %ld,"
			       " %ld of them inside B's window\n", round, last - t0, sh->frozen,
			       sh->window);
		}
	}
	double secs = now() - t0;

	if (rc == 0) {
		char buf[64];

		get(G "/freezer.state", buf, sizeof(buf));
		printf("LB-FROZEN-AFTER-THAW: pid %d (the pid namespace init) is in state D, "
		       "SIGKILL does not end it, its freezer cgroup is %s", sh->stuck, buf);
		show_stack(sh->stuck);
		/* the kernel's view: the task dump shows it (task:fz-init state:D) */
		put("/proc/sysrq-trigger", "t");
		sleep(5);
		printf("freezev1: frozen while the other thread had not dropped the live count yet"
		       " (the bug's window): %ld of %ld rounds\n", sh->window, round);
		printf("LB-RESULT bug rounds=%ld seconds=%.1f\n", round, secs);
		printf("%s freezev1: bug: the pid namespace init stays frozen after its freezer "
		       "cgroup was thawed (round %ld, %.1f s)\n", ok, round, secs);
		return 0;
	}
	printf("LB-RESULT none rounds=%ld seconds=%.1f\n", round - 1, secs);
	printf("%s freezev1: every init finished its exit after the thaw (%ld rounds, %.1f s;"
	       " frozen during its exit in %ld)\n", ok, round - 1, secs, sh->frozen);
	printf("freezev1: frozen while the other thread had not dropped the live count yet"
	       " (the bug's window): %ld of %ld rounds\n", sh->window, round - 1);
	if (!sh->frozen)
		printf("%s freezev1: the freeze never caught the exiting init (window missed)\n",
		       warn);
	return 1;
}

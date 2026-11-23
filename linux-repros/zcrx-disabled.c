// zcrx: an io_uring zcrx event sent to a ring that is still disabled
// (IORING_SETUP_R_DISABLED). A disabled ring has no submitter task yet, so
// the task work wake-up for the event calls wake_up_state(NULL).
//
// Each round runs in a fresh child process:
//   thread T2: creates ring A (R_DISABLED | SINGLE_ISSUER | DEFER_TASKRUN |
//              CQE32), registers a zcrx instance on it (no device, memory
//              from the user, events: COPY), exports it as an fd, submits a
//              private FUTEX_WAIT on another ring D and exits. Its exit-time
//              cancel pass visits ring A and sets A->cq_wait_nr = 1.
//   thread T:  creates ring B, imports the zcrx fd, sends 1000 bytes over a
//              loopback TCP pair and submits a RECV_ZC on B. The data sits
//              in page frags, so zcrx copies it and sends the COPY event to
//              ring A: io_req_local_work_add(A) wakes A->submitter_task (NULL).
// Needs CAP_NET_ADMIN (zcrx registration).
//
// zcrx [SECONDS]: rounds until the kernel reports an oops (exit 0, LB-RESULT
// bug) or SECONDS pass (exit 1, LB-RESULT none). Exit 2: setup failed.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef FUTEX2_SIZE_U32
#define FUTEX2_SIZE_U32 0x02
#endif
#ifndef FUTEX2_PRIVATE
#define FUTEX2_PRIVATE 128
#endif

static void die(const char *what)
{
	fprintf(stderr, "zcrx: %s: %s\n", what, strerror(errno));
	_exit(2);
}

static int uring_setup(unsigned entries, struct io_uring_params *p)
{
	return syscall(__NR_io_uring_setup, entries, p);
}

static int uring_enter(int fd, unsigned to_submit, unsigned min_complete, unsigned flags)
{
	return syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, NULL, 0);
}

static int uring_register(int fd, unsigned op, void *arg, unsigned nr)
{
	return syscall(__NR_io_uring_register, fd, op, arg, nr);
}

struct ring {
	int fd;
	struct io_uring_params p;
	unsigned *sq_tail, *sq_mask, *sq_array;
	struct io_uring_sqe *sqes;
};

static void ring_create(struct ring *r, unsigned flags)
{
	memset(r, 0, sizeof(*r));
	r->p.flags = flags;
	r->fd = uring_setup(8, &r->p);
	if (r->fd < 0)
		die("io_uring_setup");
}

static void ring_map(struct ring *r)
{
	size_t sq_len = r->p.sq_off.array + r->p.sq_entries * sizeof(unsigned);
	size_t cq_len = r->p.cq_off.cqes + r->p.cq_entries * 32;
	void *sq;

	if (cq_len > sq_len)
		sq_len = cq_len;
	sq = mmap(NULL, sq_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, r->fd,
		  IORING_OFF_SQ_RING);
	if (sq == MAP_FAILED)
		die("mmap sq ring");
	r->sq_tail = sq + r->p.sq_off.tail;
	r->sq_mask = sq + r->p.sq_off.ring_mask;
	r->sq_array = sq + r->p.sq_off.array;
	r->sqes = mmap(NULL, r->p.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQES);
	if (r->sqes == MAP_FAILED)
		die("mmap sqes");
}

static struct io_uring_sqe *ring_sqe(struct ring *r)
{
	unsigned tail = *r->sq_tail;
	unsigned idx = tail & *r->sq_mask;
	struct io_uring_sqe *sqe = &r->sqes[idx];

	memset(sqe, 0, sizeof(*sqe));
	r->sq_array[idx] = idx;
	__atomic_store_n(r->sq_tail, tail + 1, __ATOMIC_RELEASE);
	return sqe;
}

static uint32_t futex_word;
static int zcrx_fd = -1;

static void *t2_main(void *arg)
{
	static struct io_uring_zcrx_area_reg area;
	static struct io_uring_region_desc rd;
	static struct zcrx_event_desc ev;
	static struct io_uring_zcrx_ifq_reg reg;
	static struct zcrx_ctrl ctrl;
	struct io_uring_sqe *sqe;
	struct ring a, d;
	size_t area_len = 16 * 4096;
	void *mem;

	(void)arg;
	ring_create(&a, IORING_SETUP_R_DISABLED | IORING_SETUP_SINGLE_ISSUER |
				IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32);
	mem = mmap(NULL, area_len, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (mem == MAP_FAILED)
		die("mmap area");
	area = (struct io_uring_zcrx_area_reg){ .addr = (uintptr_t)mem, .len = area_len };
	rd = (struct io_uring_region_desc){ .size = 4096 };
	ev = (struct zcrx_event_desc){ .user_data = 0xe0e0, .type_mask = 1U << ZCRX_EVENT_COPY };
	reg = (struct io_uring_zcrx_ifq_reg){
		.rq_entries = 8,
		.flags = ZCRX_REG_NODEV,
		.area_ptr = (uintptr_t)&area,
		.region_ptr = (uintptr_t)&rd,
		.event_desc = (uintptr_t)&ev,
	};
	if (uring_register(a.fd, IORING_REGISTER_ZCRX_IFQ, &reg, 1) < 0)
		die("register zcrx on ring A");
	ctrl = (struct zcrx_ctrl){ .zcrx_id = reg.zcrx_id, .op = ZCRX_CTRL_EXPORT };
	if (uring_register(a.fd, IORING_REGISTER_ZCRX_CTRL, &ctrl, 0) < 0)
		die("export zcrx");
	zcrx_fd = ctrl.zc_export.zcrx_fd;

	/* a tracked request, so this thread's exit runs the cancel pass */
	ring_create(&d, 0);
	ring_map(&d);
	sqe = ring_sqe(&d);
	sqe->opcode = IORING_OP_FUTEX_WAIT;
	sqe->fd = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;
	sqe->addr = (uintptr_t)&futex_word;
	sqe->addr3 = 0xffffffff;
	if (uring_enter(d.fd, 1, 0, 0) != 1)
		die("submit FUTEX_WAIT");
	return NULL;
}

static void tcp_pair(int *client, int *server)
{
	struct sockaddr_in addr = { .sin_family = AF_INET,
				    .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t alen = sizeof(addr);
	int l = socket(AF_INET, SOCK_STREAM, 0);

	if (l < 0 || bind(l, (void *)&addr, sizeof(addr)) || listen(l, 1) ||
	    getsockname(l, (void *)&addr, &alen))
		die("listen");
	*client = socket(AF_INET, SOCK_STREAM, 0);
	if (*client < 0 || connect(*client, (void *)&addr, sizeof(addr)))
		die("connect");
	*server = accept(l, NULL, NULL);
	if (*server < 0)
		die("accept");
	close(l);
}

static void round_child(void)
{
	struct io_uring_zcrx_ifq_reg imp = { .flags = ZCRX_REG_IMPORT };
	static char payload[1000];
	struct io_uring_sqe *sqe;
	struct pollfd pfd;
	int client, server;
	struct ring b;
	pthread_t t2;

	if (pthread_create(&t2, NULL, t2_main, NULL) || pthread_join(t2, NULL))
		die("thread T2");

	ring_create(&b, IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN |
				IORING_SETUP_CQE32);
	ring_map(&b);
	imp.if_idx = zcrx_fd;
	if (uring_register(b.fd, IORING_REGISTER_ZCRX_IFQ, &imp, 1) < 0)
		die("import zcrx into ring B");

	tcp_pair(&client, &server);
	memset(payload, 'z', sizeof(payload));
	if (write(client, payload, sizeof(payload)) != sizeof(payload))
		die("write");
	pfd = (struct pollfd){ .fd = server, .events = POLLIN };
	if (poll(&pfd, 1, 5000) != 1)
		die("poll");

	sqe = ring_sqe(&b);
	sqe->opcode = IORING_OP_RECV_ZC;
	sqe->fd = server;
	sqe->ioprio = IORING_RECV_MULTISHOT;
	sqe->zcrx_ifq_idx = imp.zcrx_id;
	if (uring_enter(b.fd, 1, 0, 0) != 1)
		die("submit RECV_ZC");
	uring_enter(b.fd, 0, 0, IORING_ENTER_GETEVENTS);
	_exit(0);
}

static int kmsg = -1;

static int kernel_report(void)
{
	char buf[1024];
	ssize_t n;

	while ((n = read(kmsg, buf, sizeof(buf) - 1)) > 0 || (n < 0 && errno == EPIPE)) {
		if (n <= 0)
			continue;
		buf[n] = 0;
		if (strstr(buf, "BUG: kernel NULL pointer dereference") ||
		    strstr(buf, "general protection fault") || strstr(buf, "KASAN:"))
			return 1;
	}
	return 0;
}

static void lo_up(void)
{
	struct ifreq ifr = { .ifr_name = "lo" };
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	if (s < 0 || ioctl(s, SIOCGIFFLAGS, &ifr))
		die("lo flags");
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(s, SIOCSIFFLAGS, &ifr))
		die("lo up");
	close(s);
}

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	double t0 = now(), secs = 0;
	long rounds = 0;

	kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (kmsg < 0)
		die("/dev/kmsg");
	lseek(kmsg, 0, SEEK_END);
	lo_up();

	while ((secs = now() - t0) < limit) {
		int status, stuck = 0;
		pid_t pid = fork();

		if (pid < 0)
			die("fork");
		if (pid == 0)
			round_child();
		rounds++;
		/* an oopsed child may never be reaped; look at the log meanwhile */
		while (waitpid(pid, &status, WNOHANG) == 0) {
			if (kernel_report())
				goto hit;
			usleep(10000);
			if (++stuck == 1000) {
				printf("zcrx: round %ld: child stuck for 10 s\n", rounds);
				goto hit;
			}
		}
		if (kernel_report())
			goto hit;
		if (WIFEXITED(status) && WEXITSTATUS(status) == 2) {
			printf("zcrx: round %ld failed\n", rounds);
			return 2;
		}
	}
	printf("LB-RESULT none rounds=%ld seconds=%.2f\n", rounds, secs);
	return 1;
hit:
	printf("LB-RESULT bug rounds=%ld seconds=%.2f\n", rounds, now() - t0);
	return 0;
}

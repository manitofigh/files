// SPDX-License-Identifier: GPL-2.0
/*
 * Usage: napitimer [SECONDS] (needs root)
 *
 * SECONDS is how long to keep trying (300 by default).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <linux/genetlink.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>

#define NSIM_ID		7
#define NSIM		"/sys/bus/netdevsim"
#define NSIM_DEV	NSIM "/devices/netdevsim7"
#define QRESET		"/sys/kernel/debug/netdevsim/netdevsim7/ports/0/queue_reset"
#define RX_ADDR		"10.77.0.2"
#define TX_ADDR		"10.77.0.1"
#define PORT		4242
#define SUSPEND_NS	1000000000ULL	/* irq-suspend-timeout: 1 s */

/* uapi values, in case the libc headers are older than the kernel */
#define NETDEV_CMD_NAPI_SET			14
#define NETDEV_A_NAPI_ID			2
#define NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT	7
#ifndef SO_INCOMING_NAPI_ID
#define SO_INCOMING_NAPI_ID	56
#endif

static const char *ok = "[+]", *warn = "[~]", *err = "[-]";
static int kmsg = -1;
static volatile int stop;
static volatile long resets, reset_errors;

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

/* the kernel reported this bug: a line from /dev/kmsg, in our own words */
static const char *kernel_report(void)
{
	static const char *const keys[][2] = {
		{ "ODEBUG: free active", "free of a pending hrtimer (debug objects)" },
		{ "ODEBUG: init active", "set-up of a pending hrtimer (debug objects)" },
		{ "general protection fault", "general protection fault" },
		{ "KASAN:", "KASAN report" },
	};
	char buf[1024];
	ssize_t n;

	while ((n = read(kmsg, buf, sizeof(buf) - 1)) > 0 || (n < 0 && errno == EPIPE)) {
		if (n <= 0)
			continue;
		buf[n] = 0;
		for (unsigned int i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
			if (strstr(buf, keys[i][0]))
				return keys[i][1];
	}
	return NULL;
}

/* the netdevsim port names: port 0 (registered first) receives, port 1 sends */
static int find_ports(char *rx, char *tx)
{
	unsigned int idx[2] = { 0 }, n = 0, k;
	struct dirent *de;
	DIR *d;

	rx[0] = tx[0] = 0;
	d = opendir(NSIM_DEV "/net");
	if (!d)
		return -1;
	while ((de = readdir(d)) && n < 2) {
		if (de->d_name[0] == '.' || strlen(de->d_name) >= IFNAMSIZ)
			continue;
		k = if_nametoindex(de->d_name);
		if (k)
			idx[n++] = k;
	}
	closedir(d);
	if (n < 2)
		return -1;
	if_indextoname(idx[0] < idx[1] ? idx[0] : idx[1], rx);
	if_indextoname(idx[0] < idx[1] ? idx[1] : idx[0], tx);
	return 0;
}

static int if_up(int s, const char *name, const char *addr)
{
	struct ifreq ifr = { 0 };
	struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;

	strcpy(ifr.ifr_name, name);
	if (addr) {
		sin->sin_family = AF_INET;
		inet_pton(AF_INET, addr, &sin->sin_addr);
		if (ioctl(s, SIOCSIFADDR, &ifr))
			return -1;
		inet_pton(AF_INET, "255.255.255.0", &sin->sin_addr);
		if (ioctl(s, SIOCSIFNETMASK, &ifr))
			return -1;
	}
	if (ioctl(s, SIOCGIFFLAGS, &ifr))
		return -1;
	ifr.ifr_flags |= IFF_UP;
	return ioctl(s, SIOCSIFFLAGS, &ifr);
}

static uint16_t csum(const void *p, int len)
{
	const uint16_t *w = p;
	uint32_t sum = 0;

	for (; len > 1; len -= 2)
		sum += *w++;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

/* one UDP datagram from the tx port to RX_ADDR:PORT, as a raw frame */
static int send_frame(const char *tx, const char *rx)
{
	unsigned char f[64] = { 0 };
	struct sockaddr_ll sll = { 0 };
	struct ifreq ifr = { 0 };
	int s, n;

	s = socket(AF_PACKET, SOCK_RAW, 0);
	if (s < 0)
		return -1;
	strcpy(ifr.ifr_name, rx);
	if (ioctl(s, SIOCGIFHWADDR, &ifr))
		goto fail;
	memcpy(f, ifr.ifr_hwaddr.sa_data, 6);		/* dst: the rx port */
	f[6] = 0x02;					/* src: any local MAC */
	f[11] = 0x01;
	f[12] = 0x08;					/* IPv4 */
	f[14] = 0x45;					/* IP header, 20 bytes */
	f[16] = 0;
	f[17] = 20 + 8 + 4;
	f[22] = 64;					/* ttl */
	f[23] = IPPROTO_UDP;
	inet_pton(AF_INET, TX_ADDR, f + 26);
	inet_pton(AF_INET, RX_ADDR, f + 30);
	*(uint16_t *)(f + 24) = csum(f + 14, 20);
	*(uint16_t *)(f + 34) = htons(PORT);
	*(uint16_t *)(f + 36) = htons(PORT);
	*(uint16_t *)(f + 38) = htons(8 + 4);		/* udp csum 0: none */
	memcpy(f + 42, "napi", 4);

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(tx);
	sll.sll_halen = 6;
	memcpy(sll.sll_addr, f, 6);
	n = sendto(s, f, 60, 0, (struct sockaddr *)&sll, sizeof(sll));
	close(s);
	return n == 60 ? 0 : -1;
fail:
	close(s);
	return -1;
}

/* netlink attribute helpers */
static void *nla_put(struct nlmsghdr *nh, int type, const void *data, int len)
{
	struct nlattr *a = (void *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));

	a->nla_type = type;
	a->nla_len = NLA_HDRLEN + len;
	memcpy((char *)a + NLA_HDRLEN, data, len);
	nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + NLA_ALIGN(a->nla_len);
	return a;
}

static int genl_call(int s, struct nlmsghdr *nh, char *reply, int len)
{
	int n;

	nh->nlmsg_flags |= NLM_F_REQUEST | NLM_F_ACK;
	if (send(s, nh, nh->nlmsg_len, 0) < 0)
		return -1;
	n = recv(s, reply, len, 0);
	return n;
}

/* netdev genl: napi-set {id, irq-suspend-timeout} */
static int napi_set_suspend(unsigned int napi_id, uint64_t timeout)
{
	char req[256] = { 0 }, rep[4096];
	struct nlmsghdr *nh = (void *)req, *r;
	struct genlmsghdr *g = NLMSG_DATA(nh);
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	int s, n, family = -1;

	s = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (s < 0 || bind(s, (struct sockaddr *)&sa, sizeof(sa)))
		return -1;

	nh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nh->nlmsg_type = GENL_ID_CTRL;
	g->cmd = CTRL_CMD_GETFAMILY;
	g->version = 1;
	nla_put(nh, CTRL_ATTR_FAMILY_NAME, "netdev", 7);
	n = genl_call(s, nh, rep, sizeof(rep));
	for (r = (void *)rep; n > 0 && NLMSG_OK(r, n); r = NLMSG_NEXT(r, n)) {
		struct nlattr *a = (void *)((char *)NLMSG_DATA(r) + GENL_HDRLEN);
		int alen = r->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

		if (r->nlmsg_type != GENL_ID_CTRL)
			continue;
		for (; alen >= NLA_HDRLEN && a->nla_len >= NLA_HDRLEN;
		     alen -= NLA_ALIGN(a->nla_len),
		     a = (void *)((char *)a + NLA_ALIGN(a->nla_len)))
			if (a->nla_type == CTRL_ATTR_FAMILY_ID)
				family = *(uint16_t *)((char *)a + NLA_HDRLEN);
	}
	if (family < 0)
		goto fail;
	recv(s, rep, sizeof(rep), MSG_DONTWAIT);	/* the ack */

	memset(req, 0, sizeof(req));
	nh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nh->nlmsg_type = family;
	g->cmd = NETDEV_CMD_NAPI_SET;
	g->version = 1;
	nla_put(nh, NETDEV_A_NAPI_ID, &napi_id, 4);
	nla_put(nh, NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT, &timeout, 8);
	n = genl_call(s, nh, rep, sizeof(rep));
	r = (void *)rep;
	if (n < (int)NLMSG_LENGTH(sizeof(struct nlmsgerr)) || r->nlmsg_type != NLMSG_ERROR)
		goto fail;
	errno = -((struct nlmsgerr *)NLMSG_DATA(r))->error;
	close(s);
	return errno ? -1 : 0;
fail:
	close(s);
	return -1;
}

static int epfd;

/* epoll_wait() that always returns the readable socket: napi_suspend_irqs() */
static void *poller(void *arg)
{
	struct epoll_event ev;

	pin(0);
	while (!stop)
		epoll_wait(epfd, &ev, 1, 0);
	return NULL;
}

/* queue resets on the poller's CPU, at a higher priority: each one stops
 * the poller wherever it is when the reset wakes up
 */
static void *resetter(void *arg)
{
	struct sched_param sp = { .sched_priority = 10 };
	int fd = open(QRESET, O_WRONLY);

	pin(0);
	pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
	while (!stop && fd >= 0) {
		if (pwrite(fd, "0 0", 3, 0) == 3)
			resets++;
		else
			reset_errors++;
	}
	if (fd >= 0)
		close(fd);
	return NULL;
}

static void cleanup(void)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%d", NSIM_ID);
	put(NSIM "/del_device", buf);
}

int main(int argc, char **argv)
{
	int limit = argc > 1 ? atoi(argv[1]) : 300;
	struct epoll_params bp = { .busy_poll_budget = 8, .prefer_busy_poll = 1 };
	struct sockaddr_in sin = { .sin_family = AF_INET, .sin_port = htons(PORT) };
	struct epoll_event ev = { .events = EPOLLIN };
	char rx[IFNAMSIZ], tx[IFNAMSIZ], buf[64];
	unsigned int napi_id = 0;
	socklen_t sl = sizeof(napi_id);
	const char *report = NULL;
	pthread_t pt, rt;
	double t0, last, secs;
	int s, u, nsfd, i;
	long r0;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (isatty(STDOUT_FILENO)) {
		ok = "\033[32m[+]\033[0m";
		warn = "\033[33m[~]\033[0m";
		err = "\033[31m[-]\033[0m";
	}
	if (sysconf(_SC_NPROCESSORS_ONLN) < 2) {
		printf("%s napitimer: needs 2 CPUs\n", err);
		return 2;
	}

	/* two netdevsim ports with one queue each, linked to each other */
	cleanup();
	snprintf(buf, sizeof(buf), "%d 2 1", NSIM_ID);
	if (put(NSIM "/new_device", buf)) {
		printf("%s napitimer: cannot create a netdevsim device: %s\n",
		       err, strerror(errno));
		return 2;
	}
	for (i = 0; i < 50 && find_ports(rx, tx); i++)
		usleep(100000);
	s = socket(AF_INET, SOCK_DGRAM, 0);
	nsfd = open("/proc/self/ns/net", O_RDONLY);
	snprintf(buf, sizeof(buf), "%d:%u %d:%u", nsfd, if_nametoindex(rx),
		 nsfd, if_nametoindex(tx));
	if (!rx[0] || !tx[0]) {
		printf("%s napitimer: the netdevsim ports did not show up\n", err);
		cleanup();
		return 2;
	}
	if (put(NSIM "/link_device", buf) || if_up(s, rx, RX_ADDR) || if_up(s, tx, NULL)) {
		printf("%s napitimer: linking %s and %s failed: %s\n",
		       err, rx, tx, strerror(errno));
		cleanup();
		return 2;
	}

	/* one datagram that stays queued: the socket is always readable */
	u = socket(AF_INET, SOCK_DGRAM, 0);
	inet_pton(AF_INET, RX_ADDR, &sin.sin_addr);
	if (bind(u, (struct sockaddr *)&sin, sizeof(sin))) {
		printf("%s napitimer: bind: %s\n", err, strerror(errno));
		cleanup();
		return 2;
	}
	for (i = 0; i < 50; i++) {
		if (send_frame(tx, rx) == 0)
			usleep(100000);
		if (recv(u, buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT) > 0)
			break;
	}
	getsockopt(u, SOL_SOCKET, SO_INCOMING_NAPI_ID, &napi_id, &sl);
	if (i == 50 || napi_id == 0) {
		printf("%s napitimer: no datagram through the netdevsim pair (napi id %u)\n",
		       err, napi_id);
		cleanup();
		return 2;
	}
	if (napi_set_suspend(napi_id, SUSPEND_NS)) {
		printf("%s napitimer: napi-set irq-suspend-timeout failed: %s\n",
		       err, strerror(errno));
		cleanup();
		return 2;
	}
	printf("napitimer: %s <-> %s linked, napi %u: irq-suspend-timeout 1 s\n",
	       rx, tx, napi_id);

	/* epoll with prefer_busy_poll; the napi id comes from the socket */
	epfd = epoll_create1(0);
	if (epfd < 0 || ioctl(epfd, EPIOCSPARAMS, &bp) ||
	    epoll_ctl(epfd, EPOLL_CTL_ADD, u, &ev)) {
		printf("%s napitimer: epoll busy poll setup failed: %s\n",
		       err, strerror(errno));
		cleanup();
		return 2;
	}

	kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (kmsg < 0) {
		printf("%s napitimer: /dev/kmsg: %s\n", err, strerror(errno));
		cleanup();
		return 2;
	}
	lseek(kmsg, 0, SEEK_END);

	pin(1);
	pthread_create(&pt, NULL, poller, NULL);
	pthread_create(&rt, NULL, resetter, NULL);
	t0 = last = now();
	r0 = 0;
	while ((secs = now() - t0) < limit) {
		usleep(50000);
		if ((report = kernel_report()))
			break;
		if (now() - last >= 10) {
			last = now();
			printf("napitimer: %.0f s, %ld queue resets\n", last - t0, resets);
			if (resets == r0) {
				printf("%s napitimer: queue reset does not work (%ld errors)\n",
				       err, reset_errors);
				stop = 1;
				pthread_join(pt, NULL);
				pthread_join(rt, NULL);
				cleanup();
				return 2;
			}
			r0 = resets;
		}
	}
	stop = 1;
	pthread_join(pt, NULL);
	pthread_join(rt, NULL);
	if (!report) {
		usleep(1500000);	/* a stray timer fires after 1 s */
		report = kernel_report();
	}
	if (report) {
		printf("LB-RESULT bug rounds=%ld seconds=%.2f\n", resets, secs);
		printf("%s napitimer: bug: the kernel reported a %s (%ld queue resets, %.1f s)\n",
		       ok, report, resets, secs);
		return 0;
	}
	close(u);
	close(epfd);
	cleanup();
	usleep(100000);
	if ((report = kernel_report())) {
		printf("LB-RESULT bug rounds=%ld seconds=%.2f\n", resets, secs);
		printf("%s napitimer: bug: the kernel reported a %s after the last reset\n",
		       ok, report);
		return 0;
	}
	printf("LB-RESULT none rounds=%ld seconds=%.2f\n", resets, secs);
	printf("%s napitimer: no report in %ld queue resets, %.1f s\n", ok, resets, secs);
	return 1;
}

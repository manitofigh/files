// SPDX-License-Identifier: GPL-2.0
/*
 * netdevsim: queue reset in mode 2 (or 3) frees the old struct nsim_rq while
 * the peer port's nsim_start_xmit() can still use it (rq->skb_queue,
 * rq->napi_timer).
 *
 * Two linked netdevsim ports. Sender threads (CPU 1 and up) send large raw
 * frames from port 1 to port 0; one thread on CPU 0 resets port 0's queue
 * in a loop. Stops when the kernel logs a KASAN or debug objects report.
 * In a VM it hits fastest when the vCPUs share host CPUs (a sender
 * preempted right after nsim_start_xmit() looked up the rq).
 *
 * Needs root, CONFIG_NETDEVSIM, CONFIG_DEBUG_FS, CONFIG_PACKET, 2+ CPUs.
 * Build: gcc -O2 -Wall -static -pthread -o nsimtimer nsimtimer.c
 * Usage: nsimtimer [SECONDS [MODE]]   (300 s, mode 2 by default)
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>

#define NSIM_ID		7
#define NSIM		"/sys/bus/netdevsim"
#define NSIM_DEV	NSIM "/devices/netdevsim7"
#define QRESET		"/sys/kernel/debug/netdevsim/netdevsim7/ports/0/queue_reset"
#define MAX_SENDERS	16
#define FRAME		65000	/* paged skb: nsim_start_xmit() linearizes it */

static volatile int stop;
static volatile long resets, reset_errors, sent[MAX_SENDERS];
static volatile int send_errno;
static char rx[IFNAMSIZ], tx[IFNAMSIZ], mode_str[8];
static unsigned char rx_mac[6];

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

/* port 0 (registered first, lower ifindex) receives, port 1 sends */
static int find_ports(void)
{
	unsigned int idx[2] = { 0 }, n = 0, k;
	struct dirent *de;
	DIR *d;

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

static int if_up(int s, const char *name)
{
	struct ifreq ifr = { 0 };

	strcpy(ifr.ifr_name, name);
	ifr.ifr_mtu = 65535;
	if (ioctl(s, SIOCSIFMTU, &ifr))
		return -1;
	if (ioctl(s, SIOCGIFFLAGS, &ifr))
		return -1;
	ifr.ifr_flags |= IFF_UP;
	return ioctl(s, SIOCSIFFLAGS, &ifr);
}

/*
 * Both ports are created with two queues and run with one: when the peer's
 * queue count differs from num_rx_queues, netdevsim never stops the sender's
 * TX queue when a ring fills (a ring freed by a reset would never wake it).
 */
static int set_channels(int s, const char *name, unsigned int n)
{
	struct ethtool_channels ch = { .cmd = ETHTOOL_SCHANNELS, .combined_count = n };
	struct ifreq ifr = { 0 };

	strcpy(ifr.ifr_name, name);
	ifr.ifr_data = (void *)&ch;
	return ioctl(s, SIOCETHTOOL, &ifr);
}

static void *sender(void *arg)
{
	long id = (long)arg;
	static unsigned char frames[MAX_SENDERS][FRAME];
	unsigned char *f = frames[id];
	struct sockaddr_ll sll = { 0 };
	int s, one = 1, sndbuf = 64 << 20;

	pin(id + 1);
	s = socket(AF_PACKET, SOCK_RAW, 0);
	if (s < 0)
		return NULL;
	setsockopt(s, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one));
	/* frames queued on a ring that is being reset must not block us */
	setsockopt(s, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf));
	memcpy(f, rx_mac, 6);
	f[6] = 0x02;
	f[11] = 0x01;
	f[12] = 0x08;			/* IPv4 + UDP: the TX queue comes from */
	f[14] = 0x45;			/* the flow hash, i.e. the ports */
	f[22] = 64;
	f[23] = 17;
	f[26] = 10;
	f[30] = 10;
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(tx);
	sll.sll_halen = 6;
	memcpy(sll.sll_addr, rx_mac, 6);
	while (!stop) {
		f[34]++;		/* UDP source port */
		if (sendto(s, f, FRAME, 0, (struct sockaddr *)&sll, sizeof(sll)) > 0)
			sent[id]++;
		else
			send_errno = errno;
	}
	close(s);
	return NULL;
}

static void *resetter(void *arg)
{
	int fd = open(QRESET, O_WRONLY);
	int len = strlen(mode_str);

	pin(0);
	while (!stop && fd >= 0) {
		if (pwrite(fd, mode_str, len, 0) == len)
			resets++;
		else
			reset_errors++;
	}
	if (fd >= 0)
		close(fd);
	return NULL;
}

static int kernel_report(int kmsg)
{
	static const char *const keys[] = {
		"KASAN:", "ODEBUG:", "general protection fault", "BUG:", "WARNING:",
	};
	char buf[1024];
	ssize_t n;

	while ((n = read(kmsg, buf, sizeof(buf) - 1)) > 0 || (n < 0 && errno == EPIPE)) {
		if (n <= 0)
			continue;
		buf[n] = 0;
		for (unsigned int i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
			if (strstr(buf, keys[i]))
				return 1;
	}
	return 0;
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
	int mode = argc > 2 ? atoi(argv[2]) : 2;
	pthread_t st[MAX_SENDERS], rt;
	int s, nsfd, kmsg, i, ncpu, nsend, hit = 0;
	struct ifreq ifr = { 0 };
	double t0, secs, last;
	long total;
	char buf[64];

	setvbuf(stdout, NULL, _IOLBF, 0);
	ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 2) {
		printf("nsimtimer: needs 2 CPUs\n");
		return 2;
	}
	nsend = ncpu - 1 > MAX_SENDERS ? MAX_SENDERS : ncpu - 1;
	snprintf(mode_str, sizeof(mode_str), "0 %d", mode);
	mount("debugfs", "/sys/kernel/debug", "debugfs", 0, NULL);

	cleanup();
	snprintf(buf, sizeof(buf), "%d 2 2", NSIM_ID);
	if (put(NSIM "/new_device", buf)) {
		printf("nsimtimer: cannot create a netdevsim device: %s\n", strerror(errno));
		return 2;
	}
	for (i = 0; i < 50 && find_ports(); i++)
		usleep(100000);
	if (!rx[0] || !tx[0]) {
		printf("nsimtimer: the netdevsim ports did not show up\n");
		cleanup();
		return 2;
	}
	s = socket(AF_INET, SOCK_DGRAM, 0);
	nsfd = open("/proc/self/ns/net", O_RDONLY);
	snprintf(buf, sizeof(buf), "%d:%u %d:%u", nsfd, if_nametoindex(rx),
		 nsfd, if_nametoindex(tx));
	if (set_channels(s, rx, 1) || set_channels(s, tx, 1) || put(NSIM "/link_device", buf) ||
	    if_up(s, rx) || if_up(s, tx)) {
		printf("nsimtimer: linking %s and %s failed: %s\n", rx, tx, strerror(errno));
		cleanup();
		return 2;
	}
	strcpy(ifr.ifr_name, rx);
	ioctl(s, SIOCGIFHWADDR, &ifr);
	memcpy(rx_mac, ifr.ifr_hwaddr.sa_data, 6);
	printf("nsimtimer: %s -> %s, %d senders, queue reset mode %d, up to %d s\n",
	       tx, rx, nsend, mode, limit);

	kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	lseek(kmsg, 0, SEEK_END);

	for (i = 0; i < nsend; i++)
		pthread_create(&st[i], NULL, sender, (void *)(long)i);
	pthread_create(&rt, NULL, resetter, NULL);
	t0 = last = now();
	while ((secs = now() - t0) < limit) {
		usleep(50000);
		if (kmsg >= 0 && (hit = kernel_report(kmsg)))
			break;
		if (now() - last >= 10) {
			last = now();
			for (total = 0, i = 0; i < nsend; i++)
				total += sent[i];
			printf("nsimtimer: %.0f s, %ld resets (%ld errors), %ld frames (%s)\n",
			       last - t0, resets, reset_errors, total, strerror(send_errno));
		}
	}
	stop = 1;
	for (i = 0; i < nsend; i++)
		pthread_join(st[i], NULL);
	pthread_join(rt, NULL);
	if (!hit) {
		cleanup();
		usleep(500000);
		hit = kmsg >= 0 && kernel_report(kmsg);
	}
	printf("LB-RESULT %s rounds=%ld seconds=%.2f\n", hit ? "bug" : "none", resets, secs);
	return hit ? 0 : 1;
}

#include <error.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/epoll.h>

#include "netgpu_lib.h"

struct node {
	int family;
	int socktype;
	int protocol;
	socklen_t addrlen;
	struct sockaddr_storage addr;
};

struct {
	const char *ifname;
	size_t sz;
	int nentries;
	int fill_entries;
	int queue_id;
	int memtype;
} opt = {
	.ifname		= "eth0",
	.sz		= 1024 * 1024 * 2,
	.nentries	= 1024,
	.fill_entries	= 10240,
	.queue_id	= -1,
	.memtype	= MEMTYPE_HOST,
};

static void
usage(const char *prog)
{
	error(1, 0, "Usage: %s [options] hostname port", prog);
}

#define OPTSTR "i:s:q:m"

static void
parse_cmdline(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, OPTSTR)) != -1) {
		switch (c) {
		case 'i':
			opt.ifname = optarg;
			break;
		case 's':
			opt.sz = atoi(optarg);
			break;
		case 'q':
			opt.queue_id = atoi(optarg);
			break;
		case 'm':
			opt.memtype = MEMTYPE_CUDA;
			break;
		default:
			usage(basename(argv[0]));
		}
	}
}

static struct netgpu_ctx *
setup_ctx(int count, void *ptr[])
{
	struct netgpu_ctx *ctx = NULL;
	int i;

	CHK_ERR(netgpu_open_ctx(&ctx, opt.ifname));

	for (i = 0; i < count; i++) {
		ptr[i] = netgpu_alloc_memory(opt.sz, opt.memtype);
		CHECK(ptr[i]);

		CHK_ERR(netgpu_register_memory(ctx, ptr[i], opt.sz,
					       opt.memtype));
	}

	return ctx;
}

static void
close_ctx(struct netgpu_ctx *ctx, int count, void *ptr[])
{
	int i;

	netgpu_close_ctx(&ctx);

	for (i = 0; i < count; i++)
		netgpu_free_memory(ptr[i], opt.sz, opt.memtype);
}

void
set_blocking_mode(int fd, bool on)
{
	int flag;

	CHECK((flag = fcntl(fd, F_GETFL)) != -1);

	if (on)
		flag &= ~O_NONBLOCK;
	else
		flag |= O_NONBLOCK;

	CHK_ERR(fcntl(fd, F_SETFL, flag));

	flag = fcntl(fd, F_GETFL);
	CHECK(!(flag & O_NONBLOCK) == on);
}

const char *
show_node_addr(struct node *node)
{
	static char host[NI_MAXHOST];
	int rc;

	rc = getnameinfo((struct sockaddr *)&node->addr,
	    (node->family == AF_INET) ? sizeof(struct sockaddr_in) :
					sizeof(struct sockaddr_in6),
	    host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
	CHECK_MSG(rc == 0, "getnameinfo: %s", gai_strerror(rc));
	return host;
}

static bool
name2addr(const char *name, struct node *node, bool local)
{
	struct addrinfo hints, *result, *ai;
	int s, rc;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = node->family;
	hints.ai_socktype = node->socktype;
	node->addrlen = 0;

	rc = getaddrinfo(name, NULL, &hints, &result);
	CHECK_MSG(rc == 0, "getaddrinfo: %s", gai_strerror(rc));

	for (ai = result; ai != NULL; ai = ai->ai_next) {
		if (!local)
			break;

		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s == -1)
			continue;

		rc = bind(s, ai->ai_addr, ai->ai_addrlen);
		close(s);

		if (rc == 0)
			break;
	}

	if (ai != NULL) {
		node->addrlen = ai->ai_addrlen;
		node->protocol = ai->ai_protocol;
		memcpy(&node->addr, ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(result);

	return node->addrlen != 0;
}

void
set_port(struct node *node, int port)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	if (node->family == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)&node->addr;
		sin6->sin6_port = htons(port);
	} else {
		sin = (struct sockaddr_in *)&node->addr;
		sin->sin_port = htons(port);
	}
}

static void
tcp_connect(int fd, const char *hostname, short port)
{
	struct node node;
	int one = 1;

	node.family = AF_INET6;
	node.socktype = SOCK_STREAM;
	if (!name2addr(hostname, &node, false))
		CHECK_MSG(1, "could not get IP of %s", hostname);

	set_port(&node, port);

	CHK_ERR(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
	CHK_ERR(setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one)));

	CHK_ERR(connect(fd, (struct sockaddr *)&node.addr, node.addrlen));

	set_blocking_mode(fd, true);
}

#define SO_NOTIFY 69

#define N_SLICES	4

static void
send_loop(int fd, struct netgpu_skq *skq, uint64_t addr)
{
        uint8_t cbuf[CMSG_SPACE(sizeof(uint64_t))];
	bool busy[N_SLICES];
        struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = &cbuf,
	};
	uint64_t *data, base, *notify;
	int i, n, count, loopc, slice;
	struct epoll_event ev;
	size_t sz;
	int ep;

	cmsg = (struct cmsghdr *)cbuf;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SO_NOTIFY;
	cmsg->cmsg_len = CMSG_LEN(sizeof(uint64_t));
	data = (uint64_t *)CMSG_DATA(cmsg);

	sz = 10000;
	iov.iov_len = sz;
	count = (opt.sz / sz) / N_SLICES;
	loopc = 0;
	slice = 0;

	ev.events = EPOLLRDBAND;
	CHK_ERR(ep = epoll_create(1));
	CHK_ERR(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev));

	printf("send loop\n");
	for (;;) {
		bool waited;

		waited = false;
		while (busy[slice]) {
			if (netgpu_get_cq_batch(skq, &notify, 1)) {
				n = *notify % N_SLICES;
				CHECK_MSG(busy[n], "Slice %d !busy\n", n);
				busy[n] = false;
			} else {
				CHECK(!waited);
				CHK_ERR(n = epoll_wait(ep, &ev, 1, -1));
				CHECK(n != 0);
				waited = true;
			}
		}
		base = addr + (slice * count * sz);
		for (i = 0; i < count - 1; i++) {
			iov.iov_base = (void *)(base + i * sz);
			CHK_ERR(n = sendmsg(fd, &msg, MSG_NETDMA));
			CHECK(n == sz);
		}

		iov.iov_base = (void *)(base + i * sz);
		msg.msg_controllen = cmsg->cmsg_len;
		*data = loopc++;
		CHK_ERR(n = sendmsg(fd, &msg, MSG_NETDMA));
		CHECK(n == sz);
		msg.msg_controllen = 0;

		busy[slice] = true;
		slice = (slice + 1) == N_SLICES ? 0 : slice + 1;

		if (netgpu_get_cq_batch(skq, &notify, 1)) {
			n = *notify % N_SLICES;
			CHECK_MSG(busy[n], "Slice %d !busy\n", n);
			busy[n] = false;
		}
	}
}

static void
test_send(const char *hostname, short port)
{
	struct netgpu_ctx *ctx;
	struct netgpu_ifq *ifq;
	struct netgpu_skq *skq;
	void *ptr[1], *pktbuf;
	size_t sz;
	int fd;

	ctx = setup_ctx(array_size(ptr), ptr);

	sz = opt.fill_entries * 4096;
	pktbuf = netgpu_alloc_memory(sz, opt.memtype);
	CHECK(pktbuf);
	CHK_ERR(netgpu_register_memory(ctx, pktbuf, sz, opt.memtype));
	CHK_ERR(netgpu_open_ifq(&ifq, ctx, opt.queue_id, opt.fill_entries));
	netgpu_populate_ring(ifq, (uint64_t)pktbuf, opt.fill_entries);

	CHK_SYS(fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP));
	CHK_ERR(netgpu_attach_socket(&skq, ctx, fd, opt.nentries));

	tcp_connect(fd, hostname, port);

	send_loop(fd, skq, (uint64_t)ptr[0]);

	netgpu_close_ifq(&ifq);
	close_ctx(ctx, array_size(ptr), ptr);
}

int
main(int argc, char **argv)
{
	char *hostname;
	short port;

	parse_cmdline(argc, argv);
	if (argc - optind < 2)
		usage(basename(argv[0]));
	hostname = argv[optind];
	port = atoi(argv[optind + 1]);

	test_send(hostname, port);

	return 0;
}

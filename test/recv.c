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
#include <signal.h>

#include "netgpu_lib.h"

struct {
	bool stop;
} run;

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
	printf("using queue %d\n", opt.queue_id);
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

	CHK_SYS(fcntl(fd, F_SETFL, flag));

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
udp_connect(int fd, const char *hostname, short port)
{
	struct node node;
	int one = 1;

	node.family = AF_INET6;
	node.socktype = SOCK_DGRAM;
	if (!name2addr(hostname, &node, true))
		CHECK_MSG(1, "could not get IP of %s", hostname);

	set_port(&node, port);

	CHK_SYS(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
	CHK_SYS(setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one)));

//	CHK_SYS(connect(fd, (struct sockaddr *)&node.addr, node.addrlen));
	CHK_SYS(bind(fd, (struct sockaddr *)&node.addr, node.addrlen));

	set_blocking_mode(fd, true);
}

#define SO_NOTIFY 69

#define BATCH_SIZE	32

struct udp_meta {
	uint16_t	data_len;
	uint8_t		iov_count;
	uint8_t		cmsg_len;
	uint32_t	flags;
	struct iovec 	iov[];
};

static void
hex_dump(void *pkt, size_t length, uint64_t addr)
{
        const unsigned char *address = (unsigned char *)pkt;
        const unsigned char *line = address;
        size_t line_size = 16;
        unsigned char c;
        char buf[32];
        int i = 0;

        sprintf(buf, "addr=0x%lx", addr);
        printf("length = %zu\n", length);
        printf("%s | ", buf);
        while (length-- > 0) {
                printf("%02X ", *address++);
                if (!(++i % line_size) || (length == 0 && i % line_size)) {
                        if (length == 0) {
                                while (i++ % line_size)
                                        printf("__ ");
                        }
                        printf(" | ");  /* right close */
                        while (line < address) {
                                c = *line++;
                                printf("%c", (c < 33 || c == 255) ? 0x2E : c);
                        }
                        printf("\n");
                        if (length > 0)
                                printf("%s | ", buf);
                }
        }
        printf("\n");
}

static void
pkt_dump(struct iovec *iov)
{
	return;
	hex_dump(iov->iov_base, iov->iov_len, (uint64_t)iov->iov_base);
}

static uint64_t rx_bytes;
static uint64_t rx_pkts;
static uint64_t rx_frags;

static bool
handle_read(struct netgpu_skq *skq, struct netgpu_ifq *ifq)
{
	struct iovec *iov[BATCH_SIZE];
	struct udp_meta *meta;
	int i, f, count;

	iov[0] = NULL;
	count = netgpu_get_rx_batch(skq, iov, array_size(iov));
	if (!count)
		return true;
	rx_pkts += count;

	for (i = 0; i < count; i++) {
		meta = iov[i]->iov_base;
		rx_frags += meta->iov_count;
		for (f = 0; f < meta->iov_count; f++) {
			pkt_dump(&meta->iov[f]);
			rx_bytes += meta->iov[f].iov_len;
			netgpu_recycle_buffer(ifq, meta->iov[f].iov_base);
		}
		netgpu_recycle_meta(skq, meta);
	}
	netgpu_recycle_complete(ifq);
	netgpu_submit_meta(skq);

	return count != array_size(iov);
}

static void
recv_loop(int fd, struct netgpu_skq *skq, struct netgpu_ifq *ifq)
{
	struct epoll_event ev[1];
	int i, n, ep;
	bool done;

	ev[0].events = EPOLLIN;
	CHK_SYS(ep = epoll_create(1));
	CHK_SYS(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev[0]));

	printf("recv loop\n");
	while (!run.stop) {
		n = epoll_wait(ep, ev, array_size(ev), -1);
		if (n == 0)
			continue;
		if (n == -1) {
			if (errno == EINTR)
				continue;
			ERROR_HERE(1, errno, "epoll_wait");
		}
		done = true;
		for (i = 0; i < n; i++) {
			if (ev[i].events & EPOLLIN)
				done = handle_read(skq, ifq);
			if (done && ev[i].events & EPOLLRDHUP) {
				/* handle data before exiting */
				printf("SAW EPOLLRDHUP, break..\n");
				goto out;
			}
			if (done && ev[i].events & EPOLLHUP) {
				printf("SAW EPOLLHUP, break..\n");
				goto out;
			}
		}
	}
out:
	printf("Exiting loop.\n");
}

static void
test_recv(const char *hostname, short port)
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
	printf("pktdata:  [%p:%p]\n", pktbuf, pktbuf + sz);

	CHK_SYS(fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP));
	CHK_ERR(netgpu_attach_socket(&skq, ctx, fd, opt.nentries));

	/* add memory area for metadata */
	sz = opt.nentries * 256;
	pktbuf = netgpu_alloc_memory(sz, MEMTYPE_HOST);
	CHECK(pktbuf);
	CHK_ERR(netgpu_add_meta(skq, fd, pktbuf, sz, opt.nentries, 256));
	netgpu_populate_meta(skq, (uint64_t)pktbuf, opt.nentries, 256);
	printf("metadata: [%p:%p]\n", pktbuf, pktbuf + sz);

	udp_connect(fd, hostname, port);

	recv_loop(fd, skq, ifq);

	netgpu_close_ifq(&ifq);
	close_ctx(ctx, array_size(ptr), ptr);
}

static void
handle_signal(int sig)
{
	run.stop = true;
}

static void
setup(void)
{
        struct sigaction sa = {
                .sa_handler = handle_signal,
        };
        sigaction(SIGINT, &sa, NULL);
}

static void
statistics(void)
{
	if (!rx_pkts)
		return;

	printf("packets: %ld\n", rx_pkts);
	printf("  frags: %ld  %ld frags/pkt\n", rx_frags, rx_frags/rx_pkts);
	printf("  bytes: %ld  %ld bytes/frag,  %ld bytes/pkt\n", rx_bytes,
		rx_bytes/rx_frags, rx_bytes/rx_pkts);
}

int
main(int argc, char **argv)
{
	char *hostname;
	short port;

	parse_cmdline(argc, argv);
	if (argc - optind < 1)
		usage(basename(argv[0]));
	hostname = argv[optind];
	port = atoi(argv[optind + 1]);

	setup();

	test_recv(hostname, port);

	statistics();

	return 0;
}

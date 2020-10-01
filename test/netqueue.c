#include <error.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "netgpu_lib.h"

struct {
	const char *ifname;
	size_t sz;
	int nentries;
	int fill_entries;
	int queue_id;
	int memtype;
} opt = {
	.ifname		= "eth0",
	.sz		= 1024 * 64,
	.nentries	= 1024,
	.fill_entries	= 1024,
	.queue_id	= -1,
	.memtype	= MEMTYPE_HOST,
};

static void
usage(const char *prog)
{
	error(1, 0, "Usage: %s [options]", prog);
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

static void
test_one(int queue_id)
{
	struct netgpu_ctx *ctx = NULL;
	struct netgpu_ifq *ifq = NULL;
	void *ptr[2];

	ctx = setup_ctx(array_size(ptr), ptr);

	CHK_ERR(netgpu_open_ifq(&ifq, ctx, queue_id, opt.fill_entries));
	printf("returned queue %d\n", netgpu_ifq_id(ifq));

	netgpu_close_ifq(&ifq);
	close_ctx(ctx, array_size(ptr), ptr);
}

static void
test_ordering(void)
{
	struct netgpu_ctx *ctx = NULL;
	struct netgpu_ifq *ifq = NULL;
	struct netgpu_skq *skq = NULL;
	void *ptr[2];
	int fd;

	ctx = setup_ctx(array_size(ptr), ptr);

	CHK_ERR(netgpu_open_ifq(&ifq, ctx, opt.queue_id, opt.fill_entries));
	printf("returned queue %d\n", netgpu_ifq_id(ifq));

	CHK_SYS(fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP));
	CHK_ERR(netgpu_attach_socket(&skq, ctx, fd, opt.nentries));

	close_ctx(ctx, array_size(ptr), ptr);
	netgpu_close_ifq(&ifq);

	close(fd);
	netgpu_detach_socket(&skq);
}

int
main(int argc, char **argv)
{
	parse_cmdline(argc, argv);

	printf("using queue id %d\n", opt.queue_id);
	test_one(opt.queue_id);
	test_ordering();

	return 0;
}

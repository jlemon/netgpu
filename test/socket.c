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
} opt = {
	.ifname 	= "eth0",
	.sz 		= 1024 * 64,
	.nentries 	= 1024,
};

static void
usage(const char *prog)
{
	error(1, 0, "Usage: %s [options]", prog);
}

#define OPTSTR "i:s:"

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
		ptr[i] = netgpu_alloc_memory(opt.sz, MEMTYPE_HOST);
		CHECK(ptr[i]);

		CHK_ERR(netgpu_register_memory(ctx, ptr[i], opt.sz,
					       MEMTYPE_HOST));
	}

	return ctx;
}

static void
close_ctx(struct netgpu_ctx *ctx, int count, void *ptr[])
{
	int i;

	netgpu_close_ctx(&ctx);

	for (i = 0; i < count; i++)
		netgpu_free_memory(ptr[i], opt.sz, MEMTYPE_HOST);
}

static void
test_one(void)
{
	struct netgpu_ctx *ctx = NULL;
	struct netgpu_skq *skq = NULL;
	void *ptr[2];
	int fd;

	CHK_SYSCALL(fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP));

	ctx = setup_ctx(array_size(ptr), ptr);
	CHK_ERR(netgpu_attach_socket(&skq, ctx, fd, opt.nentries));
	
	netgpu_detach_socket(&skq);
	close_ctx(ctx, array_size(ptr), ptr);
	close(fd);
}

static void
test_ordering(void)
{
	struct netgpu_ctx *ctx = NULL;
	struct netgpu_skq *skq = NULL;
	void *ptr[2];
	int fd;

	CHK_SYSCALL(fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP));

	ctx = setup_ctx(array_size(ptr), ptr);
	CHK_ERR(netgpu_attach_socket(&skq, ctx, fd, opt.nentries));
	
	close_ctx(ctx, array_size(ptr), ptr);

	close(fd);
	netgpu_detach_socket(&skq);
}

int
main(int argc, char **argv)
{
	parse_cmdline(argc, argv);

	test_one();
	test_ordering();

	return 0;
}

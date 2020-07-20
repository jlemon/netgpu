#include <error.h>
#include <errno.h>
#include <stdio.h>
#include <libgen.h>
#include <getopt.h>

#include "netgpu_lib.h"

struct {
	const char *ifname;
	int memtype;
} opt = {
	.ifname		= "eth0",
	.memtype	= MEMTYPE_HOST,
};

static void
usage(const char *prog)
{
	error(1, 0, "Usage: %s [options]", prog);
}

#define OPTSTR "i:m"

static void
parse_cmdline(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, OPTSTR)) != -1) {
		switch (c) {
		case 'i':
			opt.ifname = optarg;
			break;
		case 'm':
			opt.memtype = MEMTYPE_CUDA;
			break;
		default:
			usage(basename(argv[0]));
		}
	}
}

static void
close_memarea(struct netgpu_mem **mem, void *ptr, size_t sz)
{
	netgpu_close_memarea(mem);
	netgpu_free_memory(ptr, sz, opt.memtype);
}

static int
open_memarea(struct netgpu_mem **mem, void **ptr, size_t sz)
{
	int idx;

	*ptr = netgpu_alloc_memory(sz, opt.memtype);
	CHECK(*ptr);

	CHK_ERR(netgpu_open_memarea(mem));

	idx = netgpu_add_memarea(*mem, *ptr, sz, opt.memtype);
	CHECK(idx > 0);

	return idx;
}

static void
test_memarea(size_t sz)
{
	struct netgpu_mem *mem = NULL;
	void *ptr;
	int idx;

	idx = open_memarea(&mem, &ptr, sz);
	close_memarea(&mem, ptr, sz);
}

static void
test_ctx_nop(const char *ifname, size_t sz)
{
	struct netgpu_mem *mem = NULL;
	struct netgpu_ctx *ctx = NULL;
	void *ptr;
	int idx;

	idx = open_memarea(&mem, &ptr, sz);

	CHK_ERR(netgpu_open_ctx(&ctx, ifname));
	netgpu_close_ctx(&ctx);

	close_memarea(&mem, ptr, sz);
}

static void
test_dmamap1(const char *ifname, size_t sz)
{
	struct netgpu_mem *mem = NULL;
	struct netgpu_ctx *ctx = NULL;
	void *ptr;
	int idx;

	idx = open_memarea(&mem, &ptr, sz);
	CHK_ERR(netgpu_open_ctx(&ctx, ifname));

	CHK_ERR(netgpu_attach_region(ctx, mem, idx));

	netgpu_close_ctx(&ctx);
	close_memarea(&mem, ptr, sz);
}

static void
test_dmamap2(const char *ifname, size_t sz)
{
	struct netgpu_mem *mem = NULL;
	struct netgpu_ctx *ctx = NULL;
	void *ptr;
	int idx;

	idx = open_memarea(&mem, &ptr, sz);
	CHK_ERR(netgpu_open_ctx(&ctx, ifname));

	CHK_ERR(netgpu_attach_region(ctx, mem, idx));

	netgpu_close_memarea(&mem);
	netgpu_close_ctx(&ctx);
	netgpu_free_memory(ptr, sz, opt.memtype);
}

static void
test_dmamap3(const char *ifname, size_t sz)
{
	struct netgpu_mem *mem = NULL;
	struct netgpu_ctx *ctx = NULL;
	void *ptr;
	int idx;

	CHK_ERR(netgpu_open_ctx(&ctx, ifname));
	idx = open_memarea(&mem, &ptr, sz);

	CHK_ERR(netgpu_attach_region(ctx, mem, idx));

	netgpu_close_memarea(&mem);
	netgpu_close_ctx(&ctx);
	netgpu_free_memory(ptr, sz, opt.memtype);
}

static void
test_dmamap4(const char *ifname, size_t sz)
{
	struct netgpu_mem *mem = NULL;
	struct netgpu_ctx *ctx = NULL;
	void *ptr;

	ptr = netgpu_alloc_memory(sz, opt.memtype);
	CHECK(ptr);

	CHK_ERR(netgpu_open_ctx(&ctx, ifname));
	CHK_ERR(netgpu_register_memory(ctx, ptr, sz, opt.memtype));

	netgpu_close_ctx(&ctx);
	netgpu_free_memory(ptr, sz, opt.memtype);
}

int
main(int argc, char **argv)
{
	parse_cmdline(argc, argv);

	test_memarea(1024 * 64);
	test_ctx_nop(opt.ifname, 1024 * 64);
	test_dmamap1(opt.ifname, 1024 * 64);
	test_dmamap2(opt.ifname, 1024 * 64);
	test_dmamap3(opt.ifname, 1024 * 64);
	test_dmamap4(opt.ifname, 1024 * 64);

	return 0;
}

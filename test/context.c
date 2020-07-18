#include <error.h>
#include <errno.h>
#include <stdio.h>
#include <libgen.h>
#include <getopt.h>

#include "netgpu_lib.h"

static void
test_one(const char *ifname)
{
	struct netgpu_ctx *ctx = NULL;

	CHK_ERR(netgpu_open_ctx(&ctx, ifname));
	netgpu_close_ctx(&ctx);
}

static void
test_two(const char *ifname)
{
	struct netgpu_ctx *ctx1 = NULL, *ctx2 = NULL;

	CHK_ERR(netgpu_open_ctx(&ctx1, ifname));
	CHK_ERR(netgpu_open_ctx(&ctx2, ifname));
	netgpu_close_ctx(&ctx1);
	netgpu_close_ctx(&ctx2);
}

static void
test_mem(const char *ifname, size_t sz)
{
	struct netgpu_ctx *ctx = NULL;
        void *ptr;

	ptr = netgpu_alloc_memory(sz, MEMTYPE_HOST);
	CHECK(ptr);

	CHK_ERR(netgpu_open_ctx(&ctx, ifname));
	CHK_ERR(netgpu_register_memory(ctx, ptr, sz, MEMTYPE_HOST));

	netgpu_close_ctx(&ctx);
	netgpu_free_memory(ptr, sz, MEMTYPE_HOST);
}

static void
test_mem2(const char *ifname, size_t sz)
{
	struct netgpu_ctx *ctx = NULL;
        void *ptr, *ptr2;

	ptr = netgpu_alloc_memory(sz, MEMTYPE_HOST);
	CHECK(ptr);
	ptr2 = netgpu_alloc_memory(sz, MEMTYPE_HOST);
	CHECK(ptr2);

	CHK_ERR(netgpu_open_ctx(&ctx, ifname));
	CHK_ERR(netgpu_register_memory(ctx, ptr, sz, MEMTYPE_HOST));
	CHK_ERR(netgpu_register_memory(ctx, ptr2, sz, MEMTYPE_HOST));

	netgpu_close_ctx(&ctx);
	netgpu_free_memory(ptr, sz, MEMTYPE_HOST);
	netgpu_free_memory(ptr2, sz, MEMTYPE_HOST);
}


static void
test_sharing(const char *ifname, size_t sz)
{
	struct netgpu_ctx *ctx1 = NULL, *ctx2 = NULL;
        struct netgpu_mem *mem = NULL;
        void *ptr;
        int idx;

        CHK_ERR(netgpu_open_memarea(&mem));
	ptr = netgpu_alloc_memory(sz, MEMTYPE_HOST);
	CHECK(ptr);
	idx = netgpu_add_memarea(mem, ptr, sz, MEMTYPE_HOST);
	CHECK(idx > 0);

	CHK_ERR(netgpu_open_ctx(&ctx1, ifname));
	CHK_ERR(netgpu_attach_region(ctx1, mem, idx));

	CHK_ERR(netgpu_open_ctx(&ctx2, ifname));
	CHK_ERR(netgpu_attach_region(ctx2, mem, idx));

	netgpu_close_ctx(&ctx1);

	CHK_ERR(netgpu_open_ctx(&ctx1, ifname));
	CHK_ERR(netgpu_attach_region(ctx1, mem, idx));

	netgpu_close_ctx(&ctx2);
	netgpu_close_ctx(&ctx1);
        netgpu_close_memarea(&mem);
	netgpu_free_memory(ptr, sz, MEMTYPE_HOST);
}

static void
test_ordering(const char *ifname, size_t sz)
{
	struct netgpu_ctx *ctx = NULL;
        struct netgpu_mem *mem = NULL;
        void *ptr, *ptr2;
	int idx, err;

        CHK_ERR(netgpu_open_memarea(&mem));
	ptr = netgpu_alloc_memory(sz, MEMTYPE_HOST);
	CHECK(ptr);
	idx = netgpu_add_memarea(mem, ptr, sz, MEMTYPE_HOST);
	CHECK(idx > 0);

	CHK_ERR(netgpu_open_ctx(&ctx, ifname));
	CHK_ERR(netgpu_attach_region(ctx, mem, idx));

	/* can't add memory region more than once */
	err = netgpu_attach_region(ctx, mem, idx);
	CHECK(err == -EEXIST);

	/* adding same memory region to internal memarea is not allowed */
	err = netgpu_register_memory(ctx, ptr, sz, MEMTYPE_HOST);
	CHECK(err == -EEXIST);

	/* close memarea while in use */
        netgpu_close_memarea(&mem);

	ptr2 = netgpu_alloc_memory(sz, MEMTYPE_HOST);
	CHECK(ptr2);
	CHK_ERR(netgpu_register_memory(ctx, ptr2, sz, MEMTYPE_HOST));

	/* free memory while in use */
	netgpu_free_memory(ptr2, sz, MEMTYPE_HOST);

	netgpu_close_ctx(&ctx);
	netgpu_free_memory(ptr, sz, MEMTYPE_HOST);
}

int
main(int argc, char **argv)
{
	char *ifname = "eth0";			/* default */

	if (argc > 1)
		ifname = argv[1];

	test_one(ifname);
	test_two(ifname);
	test_mem(ifname, 1024 * 64);
	test_mem2(ifname, 1024 * 64);
	test_sharing(ifname, 1024 * 64);
	test_ordering(ifname, 1024 * 64);

	return 0;
}

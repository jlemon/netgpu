#include <error.h>
#include <errno.h>
#include <stdio.h>
#include <libgen.h>
#include <getopt.h>

#include "netgpu_lib.h"

static void
test_normal(size_t sz, int count)
{
	struct netgpu_mem *mem = NULL;
	void *ptr[count];
	int idx[count];
	int i;

	CHK_ERR(netgpu_open_memarea(&mem));

	for (i = 0; i < count; i++) {
		ptr[i] = netgpu_alloc_memory(sz, MEMTYPE_HOST);
		CHECK(ptr[i]);

		idx[i] = netgpu_add_memarea(mem, ptr[i], sz, MEMTYPE_HOST);
		CHECK(idx[i] > 0);
	}

	netgpu_close_memarea(&mem);

	for (i = 0; i < count; i++)
		netgpu_free_memory(ptr[i], sz, MEMTYPE_HOST);

	for (i = 0; i < count; i++)
		CHECK_MSG(idx[i] == i+1, "idx[%d] == %d", i, idx[i]);
}

static void
test_one(size_t sz)
{
	test_normal(sz, 1);
}

static void
test_overlap(size_t sz)
{
	struct netgpu_mem *mem = NULL;
	void *ptr;
	int idx;

	ptr = netgpu_alloc_memory(sz, MEMTYPE_HOST);
	CHECK(ptr);

	CHK_ERR(netgpu_open_memarea(&mem));

	idx = netgpu_add_memarea(mem, ptr, sz, MEMTYPE_HOST);
	CHECK(idx > 0);

	idx = netgpu_add_memarea(mem, ptr, sz, MEMTYPE_HOST);
	CHECK(idx == -EEXIST);

	netgpu_close_memarea(&mem);

	netgpu_free_memory(ptr, sz, MEMTYPE_HOST);
}

static void
test_duplicate(size_t sz)
{
	struct netgpu_mem *mem1 = NULL, *mem2 = NULL;
	void *ptr;
	int idx;

	ptr = netgpu_alloc_memory(sz, MEMTYPE_HOST);
	CHECK(ptr);

	CHK_ERR(netgpu_open_memarea(&mem1));
	CHK_ERR(netgpu_open_memarea(&mem2));

	idx = netgpu_add_memarea(mem1, ptr, sz, MEMTYPE_HOST);
	CHECK(idx > 0);

	idx = netgpu_add_memarea(mem2, ptr, sz, MEMTYPE_HOST);
	CHECK(idx == -EEXIST);

	netgpu_close_memarea(&mem1);
	netgpu_close_memarea(&mem2);

	netgpu_free_memory(ptr, sz, MEMTYPE_HOST);
}

int
main(int argc, char **argv)
{

	/* test single regions of different sizes */
	test_one(1024);
	test_one(1024 * 1024);
	test_one(1024 * 1024 * 1024);

	/* multiple regions in same memarea */
	test_normal(1024 * 16, 8);

	/* overlapping regions in same area are disallowed */
	test_overlap(1024 * 16);

	/* duplicate areas in different memareas are disallowed */
	test_duplicate(1024 * 16);

	return 0;
}

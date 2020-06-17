#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
//#include <netdb.h>
//#include <time.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <net/if.h>

#include "util.h"

#include "bpf/libbpf_util.h"
#include "uapi/misc/netgpu.h"
#include "uapi/misc/shqueue.h"

#ifdef USE_CUDA
#include "cuda.h"
#include "cuda_runtime.h"
#endif

#define MSG_NETDMA      0x8000000       
#define SO_REGISTER_DMA         69

#define PAGE_SIZE	4096

struct netgpu {
	int fd;
	unsigned ifindex;
	struct shared_queue fill;
	struct shared_queue rx;
};

static int
netgpu_mmap_queue(int fd, struct shared_queue *q, struct netgpu_user_queue *u)
{

	q->map_ptr = mmap(NULL, u->map_sz, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_POPULATE, fd, u->map_off);
	if (q->map_ptr == MAP_FAILED)
		return -errno;

	q->mask = u->mask;
	q->map_sz = u->map_sz;
	q->elt_sz = u->elt_sz;
	q->entries = u->entries;

	q->prod = q->map_ptr + u->off.prod;
	q->cons = q->map_ptr + u->off.cons;
	q->data = q->map_ptr + u->off.desc;	/* XXX rename */

	q->cached_cons = 0;
	q->cached_prod = 0;

	return 0;
}

static int
netgpu_mmap(struct netgpu *ctx, struct netgpu_params *p)
{
	int rc;

	rc = netgpu_mmap_queue(ctx->fd, &ctx->fill, &p->fill);
	if (rc)
		return rc;

	rc = netgpu_mmap_queue(ctx->fd, &ctx->rx, &p->rx);
	if (rc)
		return rc;

	return 0;
}

void
netgpu_populate_ring(struct netgpu *ctx, uint64_t addr, int count)
{
	uint64_t *addrp;
	int i;

	/* ring entries will be power of 2. */
	if (sq_prod_space(&ctx->fill) < count)
		err_exit("sq_prod_space");

	for (i = 0; i < count; i++) {
		addrp = sq_prod_reserve(&ctx->fill);
		*addrp = (uint64_t)addr + i * PAGE_SIZE;
	}
	sq_prod_submit(&ctx->fill);
}

int
netgpu_start(struct netgpu **ctxp, const char *ifname, int queue_id,
	     int nentries)
{
	struct netgpu_params p;
	struct netgpu *ctx;
	int err;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;
	memset(ctx, 0, sizeof(*ctx));

	memset(&p, 0, sizeof(p));

	p.ifindex = if_nametoindex(ifname);
	if (!p.ifindex) {
		warn("Interface %s does not exist\n", ifname);
		err = -EEXIST;
		goto out;
	}
	p.queue_id = queue_id;

	p.fill.elt_sz = sizeof(uint64_t);
	p.fill.entries = nentries;

	p.rx.elt_sz = sizeof(struct iovec);
	p.rx.entries = nentries;

	ctx->fd = open("/dev/netgpu", O_RDWR);
	if (ctx->fd == -1)
		err_exit("open(/dev/netgpu)");

	if (ioctl(ctx->fd, NETGPU_IOCTL_ATTACH_DEV, &p.ifindex))
		err_exit("ioctl(ATTACH_DEV)");

	if (ioctl(ctx->fd, NETGPU_IOCTL_BIND_QUEUE, &p))
		err_exit("ioctl(BIND_QUEUE)");
	ctx->ifindex = p.ifindex;

	err = netgpu_mmap(ctx, &p);
	if (err)
		err_with(-err, "netgpu_mmap");

	*ctxp = ctx;
	return 0;

out:
	free(ctx);
	return err;
}

void
netgpu_stop(struct netgpu **ctxp)
{
	struct netgpu *ctx = *ctxp;

	if (ctx->fill.map_ptr)
		munmap(ctx->fill.map_ptr, ctx->fill.map_sz);

	if (ctx->rx.map_ptr)
		munmap(ctx->rx.map_ptr, ctx->rx.map_sz);

	close(ctx->fd);

	free(ctx);
	*ctxp = NULL;
}

int
netgpu_get_rx_batch(struct netgpu *ctx, struct iovec **iov, int count)
{
	return sq_cons_batch(&ctx->rx, (void **)iov, count);
}

void
netgpu_recycle_buffer(struct netgpu *ctx, void *ptr)
{
	uint64_t *addrp;

	addrp = sq_prod_reserve(&ctx->fill);
	*addrp = (uint64_t)ptr & ~(PAGE_SIZE - 1);
}

bool
netgpu_recycle_batch(struct netgpu *ctx, struct iovec **iov, int count)
{
	uint64_t *addrp;
	int i;

	if (!sq_prod_avail(&ctx->fill, count))
		return false;

	for (i = 0; i < count; i++) {
		addrp = sq_prod_get_ptr(&ctx->fill);
		*addrp = (uint64_t)iov[i]->iov_base & ~(PAGE_SIZE - 1);
	}
}

void
netgpu_recycle_complete(struct netgpu *ctx)
{
	sq_prod_submit(&ctx->fill);
}

int
netgpu_register_region(struct netgpu *ctx, void *va, size_t size, bool gpumem)
{
        struct dma_region dmar;

        dmar.iov.iov_base = va;
        dmar.iov.iov_len = size;
        dmar.host_memory  = !gpumem;

        if (ioctl(ctx->fd, NETGPU_IOCTL_ADD_REGION, &dmar))
                err_exit("ioctl(ADD_REGION)");

        return 0;
}

int
netgpu_attach_socket(struct netgpu *ctx, int fd)
{
	int one = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one)))
		err_exit("setsockopt(SO_ZEROCOPY)");

        if (setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX, &ctx->ifindex,
                       sizeof(ctx->ifindex)))
                err_exit("setsockopt(bind)");

        /* attaches sk to ctx and sets up custom data_ready hook */
	if (setsockopt(fd, SOL_SOCKET, SO_REGISTER_DMA,
                       &ctx->fd, sizeof(ctx->fd)))
		err_exit("setsockopt(REGISTER_DMA)");

	return 0;
}

static void *
netgpu_alloc_host_memory(size_t size)
{
	void *addr;

	/* XXX page align size... */

	addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (addr == MAP_FAILED)
		err_exit("mmap");

	if (mlock(addr, size))
		err_exit("mlock");

	return addr;
}

static void
netgpu_free_host_memory(void *area, size_t size)
{
	munmap(area, size);
}

#ifdef USE_CUDA
#define err_with(e, ...) do {                                           \
        fprintf(stderr, "%s:%d:%s %s(%d) ",                             \
                __FILE__, __LINE__, __func__, strerror(e), e);          \
        fprintf(stderr, __VA_ARGS__);                                   \
        fprintf(stderr, "\n");                                          \
        exit(1);                                                        \
} while (0)

#define err_exit(...) err_with(errno, __VA_ARGS__)

#define CHECK(fcn) do {                                                 \
        CUresult err = fcn;                                             \
        const char *str;                                                \
        if (err) {                                                      \
                cuGetErrorString(err, &str);                            \
                err_exit(str);                                          \
        }                                                               \
} while (0)

static uint64_t
pin_buffer(void *ptr, size_t size)
{
        uint64_t id;
        unsigned int one = 1;

        /*
         * Disables all data transfer optimizations
         */
        CHECK(cuPointerSetAttribute(&one,
            CU_POINTER_ATTRIBUTE_SYNC_MEMOPS, (CUdeviceptr)ptr));

        CHECK(cuPointerGetAttribute(&id,
            CU_POINTER_ATTRIBUTE_BUFFER_ID, (CUdeviceptr)ptr));

        return id;
}

static void *
netgpu_alloc_gpu_memory(size_t size)
{
        void *gpu;
        uint64_t id;

printf("allocating %ld from gpu...\n", size);
        CHECK(cudaMalloc(&gpu, size));

        id = pin_buffer(gpu, size);

        return gpu;
}

static void *
netgpu_free_gpu_memory(void *area, size_t size)
{
	CHECK(cudaFree(area));
}
#endif

void *
netgpu_alloc_memory(size_t size, bool gpumem)
{
        void *area = NULL;

        if (!gpumem)
                area = netgpu_alloc_host_memory(size);
#ifdef USE_CUDA
        else
                area = netgpu_alloc_gpu_memory(size);
#endif
        return area;
}

void
netgpu_free_memory(void *area, size_t size, bool gpumem)
{
        if (!gpumem)
                netgpu_free_host_memory(area, size);
#ifdef USE_CUDA
        else
                netgpu_free_gpu_memory(area, size);
#endif
}

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <net/if.h>
#include <linux/sockios.h>

#include "netgpu_lib.h"

#ifdef USE_CUDA
#include "cuda.h"
#include "cuda_runtime.h"
#endif

#define PAGE_SIZE	4096

struct netgpu_skq {
	struct shared_queue rx;
	struct shared_queue cq;
};

struct netgpu_ifq {
	int fd;
	unsigned queue_id;
	struct shared_queue fill;
};

struct netgpu_mem {
	int fd;
};

struct netgpu_ctx {
	int fd;
	unsigned ifindex;
	struct netgpu_mem *mem;
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
	q->data = q->map_ptr + u->off.data;

	q->cached_cons = 0;
	q->cached_prod = 0;

	return 0;
}

static int
netgpu_mmap_socket(int fd, struct netgpu_skq *skq,
		   struct netgpu_socket_param *p)
{
	int rc;

	rc = netgpu_mmap_queue(fd, &skq->rx, &p->rx);
	if (rc)
		return rc;

	rc = netgpu_mmap_queue(fd, &skq->cq, &p->cq);
	if (rc)
		return rc;

	return 0;
}

static int
netgpu_mmap_ifq(struct netgpu_ifq *ifq, struct netgpu_ifq_param *p)
{
	return netgpu_mmap_queue(ifq->fd, &ifq->fill, &p->fill);
}

void
netgpu_populate_ring(struct netgpu_ifq *ifq, uint64_t addr, int count)
{
	uint64_t *addrp;
	int i;

	/* ring entries will be power of 2. */
	if (sq_prod_space(&ifq->fill) < count)
		err_exit("sq_prod_space");

	for (i = 0; i < count; i++) {
		addrp = sq_prod_reserve(&ifq->fill);
		*addrp = (uint64_t)addr + i * PAGE_SIZE;
	}
	sq_prod_submit(&ifq->fill);
}

int
netgpu_get_rx_batch(struct netgpu_skq *skq, struct iovec **iov, int count)
{
	return sq_cons_batch(&skq->rx, (void **)iov, count);
}

void
netgpu_recycle_buffer(struct netgpu_ifq *ifq, void *ptr)
{
	uint64_t *addrp;

	addrp = sq_prod_reserve(&ifq->fill);
	*addrp = (uint64_t)ptr & ~(PAGE_SIZE - 1);
}

bool
netgpu_recycle_batch(struct netgpu_ifq *ifq, struct iovec **iov, int count)
{
	uint64_t *addrp;
	int i;

	if (!sq_prod_avail(&ifq->fill, count))
		return false;

	for (i = 0; i < count; i++) {
		addrp = sq_prod_get_ptr(&ifq->fill);
		*addrp = (uint64_t)iov[i]->iov_base & ~(PAGE_SIZE - 1);
	}
}

void
netgpu_recycle_complete(struct netgpu_ifq *ifq)
{
	sq_prod_submit(&ifq->fill);
}

void
netgpu_detach_socket(struct netgpu_skq **skqp)
{
	struct netgpu_skq *skq = *skqp;

	if (skq->rx.map_ptr)
		munmap(skq->rx.map_ptr, skq->rx.map_sz);

	if (skq->cq.map_ptr)
		munmap(skq->cq.map_ptr, skq->cq.map_sz);

	free(skq);
	*skqp = NULL;
}

int
netgpu_attach_socket(struct netgpu_skq **skqp, struct netgpu_ctx *ctx, int fd,
		     int nentries)
{
	struct netgpu_socket_param p;
	struct netgpu_skq *skq;
	int one = 1;
	int err;

	skq = malloc(sizeof(*skq));
	if (!skq)
		return -ENOMEM;
	memset(skq, 0, sizeof(*skq));

	memset(&p, 0, sizeof(p));
	p.ctx_fd = ctx->fd;

	p.rx.elt_sz = sizeof(struct iovec);
	p.rx.entries = nentries;

	p.cq.elt_sz = sizeof(uint64_t);
	p.cq.entries = nentries;

	if (setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one)))
		err_exit("setsockopt(SO_ZEROCOPY)");

	/* for TX - specify outgoing device */
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX, &ctx->ifindex,
		       sizeof(ctx->ifindex)))
		err_exit("setsockopt(SO_BINDTOIFINDEX)");

	/* attaches sk to ctx and sets up custom data_ready hook */
	if (ioctl(fd, NETGPU_SOCK_IOCTL_ATTACH_QUEUES, &p))
		err_exit("ioctl(ATTACH_QUEUES)");

	err = netgpu_mmap_socket(fd, skq, &p);
	if (err)
		err_with(-err, "netgpu_mmap_socket");

	*skqp = skq;

	return 0;
}

void
netgpu_close_ifq(struct netgpu_ifq **ifqp)
{
	struct netgpu_ifq *ifq = *ifqp;

	close(ifq->fd);
	if (ifq->fill.map_ptr)
		munmap(ifq->fill.map_ptr, ifq->fill.map_sz);

	free(ifq);
	*ifqp = NULL;
}

int
netgpu_ifq_id(struct netgpu_ifq *ifq)
{
	return ifq->queue_id;
}

int
netgpu_open_ifq(struct netgpu_ifq **ifqp, struct netgpu_ctx *ctx,
		int queue_id, int fill_entries)
{
	struct netgpu_ifq_param p;
	struct netgpu_ifq *ifq;
	int err;

	ifq = malloc(sizeof(*ifq));
	if (!ifq)
		return -ENOMEM;
	memset(ifq, 0, sizeof(*ifq));

	memset(&p, 0, sizeof(p));
	p.queue_id = queue_id;
	p.fill.elt_sz = sizeof(uint64_t);
	p.fill.entries = fill_entries;

	if (ioctl(ctx->fd, NETGPU_CTX_IOCTL_BIND_QUEUE, &p)) {
		err = -errno;
		free(ifq);
		return err;
	}

	ifq->fd = p.ifq_fd;
	ifq->queue_id = p.queue_id;

	err = netgpu_mmap_ifq(ifq, &p);
	if (err) {
		close(ifq->fd);
		free(ifq);
		return err;
	}

	*ifqp = ifq;
	return 0;
}

int
netgpu_attach_region(struct netgpu_ctx *ctx, struct netgpu_mem *mem, int idx)
{
	struct netgpu_attach_param p;

	p.mem_fd = mem->fd;
	p.mem_idx = idx;

	if (ioctl(ctx->fd, NETGPU_CTX_IOCTL_ATTACH_REGION, &p))
		return -errno;

	return 0;
}

int
netgpu_register_memory(struct netgpu_ctx *ctx, void *va, size_t size,
		       enum netgpu_memtype memtype)
{
	int idx, err;

	if (!ctx->mem) {
		err = netgpu_open_memarea(&ctx->mem);
		if (err)
			return err;
	}
	idx = netgpu_add_memarea(ctx->mem, va, size, memtype);
	if (idx < 0)
		return idx;

	return netgpu_attach_region(ctx, ctx->mem, idx);
}

void
netgpu_close_ctx(struct netgpu_ctx **ctxp)
{
	struct netgpu_ctx *ctx = *ctxp;

	if (ctx->mem)
		netgpu_close_memarea(&ctx->mem);

	close(ctx->fd);
	free(ctx);
	*ctxp = NULL;
}

int
netgpu_open_ctx(struct netgpu_ctx **ctxp, const char *ifname)
{
	struct netgpu_ctx *ctx;
	int err;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;
	memset(ctx, 0, sizeof(*ctx));

	ctx->ifindex = if_nametoindex(ifname);
	if (!ctx->ifindex) {
		warn("Interface %s does not exist\n", ifname);
		err = -EEXIST;
		goto out;
	}

	ctx->fd = open("/dev/netgpu", O_RDWR);
	if (ctx->fd == -1)
		err_exit("open(/dev/netgpu)");

	if (ioctl(ctx->fd, NETGPU_CTX_IOCTL_ATTACH_DEV, &ctx->ifindex))
		err_exit("ioctl(ATTACH_DEV)");

	*ctxp = ctx;
	return 0;

out:
	free(ctx);
	return err;
}

int
netgpu_add_memarea(struct netgpu_mem *mem, void *va, size_t size,
		   enum netgpu_memtype memtype)
{
	struct netgpu_region_param p;
	int idx;

	p.iov.iov_base = va;
	p.iov.iov_len = size;
	p.memtype = memtype;

	idx = ioctl(mem->fd, NETGPU_MEM_IOCTL_ADD_REGION, &p);
	if (idx < 0)
		idx = -errno;

	return idx;
}

void
netgpu_close_memarea(struct netgpu_mem **memp)
{
	struct netgpu_mem *mem = *memp;

	close(mem->fd);
	free(mem);
	*memp = NULL;
}

/* XXX change so memory areas are always of one type? */
int
netgpu_open_memarea(struct netgpu_mem **memp)
{
	struct netgpu_mem *mem;

	mem = malloc(sizeof(*mem));
	if (!mem)
		return -ENOMEM;
	memset(mem, 0, sizeof(*mem));

	mem->fd = open("/dev/netgpu_mem", O_RDWR);
	if (mem->fd == -1)
		err_exit("open(/dev/netgpu_mem)");

	*memp = mem;

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
#define CHK_CUDA(fcn) do {						\
	CUresult err = fcn;						\
	const char *str;						\
	if (err) {							\
		cuGetErrorString(err, &str);				\
		err_exit(str);						\
	}								\
} while (0)

static uint64_t
pin_buffer(void *ptr, size_t size)
{
	uint64_t id;
	unsigned int one = 1;

	/*
	 * Disables all data transfer optimizations
	 */
	CHK_CUDA(cuPointerSetAttribute(&one,
	    CU_POINTER_ATTRIBUTE_SYNC_MEMOPS, (CUdeviceptr)ptr));

	CHK_CUDA(cuPointerGetAttribute(&id,
	    CU_POINTER_ATTRIBUTE_BUFFER_ID, (CUdeviceptr)ptr));

	return id;
}

static void *
netgpu_alloc_cuda_memory(size_t size)
{
	void *gpu;
	uint64_t id;

	printf("allocating %ld from gpu...\n", size);
	CHK_CUDA(cudaMalloc(&gpu, size));

	id = pin_buffer(gpu, size);

	return gpu;
}

static void *
netgpu_free_cuda_memory(void *area, size_t size)
{
	printf("freeing %ld from gpu...\n", size);
	CHK_CUDA(cudaFree(area));
}
#endif

void *
netgpu_alloc_memory(size_t size, enum netgpu_memtype memtype)
{
	void *area = NULL;

	if (memtype == MEMTYPE_HOST)
		area = netgpu_alloc_host_memory(size);
#ifdef USE_CUDA
	else if (memtype == MEMTYPE_CUDA)
		area = netgpu_alloc_cuda_memory(size);
#endif
	return area;
}

void
netgpu_free_memory(void *area, size_t size, enum netgpu_memtype memtype)
{
	if (memtype == MEMTYPE_HOST)
		netgpu_free_host_memory(area, size);
#ifdef USE_CUDA
	else if (memtype == MEMTYPE_CUDA)
		netgpu_free_cuda_memory(area, size);
#endif
	else
		stop_here("Unhandled memtype: %d", memtype);
}

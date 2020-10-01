#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <sys/uio.h>

#include "netgpu_util.h"

#include "bpf/libbpf_util.h"
#include "uapi/misc/netgpu.h"
#include "uapi/misc/shqueue.h"

#include "netgpu_lib.h"


#ifndef MSG_ZEROCOPY
#define MSG_ZEROCOPY	0x4000000
#endif
#define MSG_NETDMA	0x8000000


struct netgpu_skq;
struct netgpu_ifq;
struct netgpu_ctx;
struct netgpu_mem;

void netgpu_populate_ring(struct netgpu_ifq *ifq, uint64_t addr, int count);
int netgpu_get_rx_batch(struct netgpu_skq *skq, struct iovec *iov[], int count);
int netgpu_get_cq_batch(struct netgpu_skq *skq, uint64_t *notify[], int count);
void netgpu_recycle_buffer(struct netgpu_ifq *ifq, void *ptr);
bool netgpu_recycle_batch(struct netgpu_ifq *ifq, struct iovec **iov,
			  int count);
void netgpu_recycle_complete(struct netgpu_ifq *ifq);

void netgpu_populate_meta(struct netgpu_skq *skq, uint64_t addr, int count,
			  int size);
void netgpu_recycle_meta(struct netgpu_skq *skq, void *ptr);
void netgpu_submit_meta(struct netgpu_skq *skq);
int netgpu_add_meta(struct netgpu_skq *skq, int fd, void *addr, size_t len,
		    int nentries, int meta_len);

int netgpu_attach_socket(struct netgpu_skq **skqp, struct netgpu_ctx *ctx,
			 int fd, int nentries);
void netgpu_detach_socket(struct netgpu_skq **skqp);

int netgpu_ifq_id(struct netgpu_ifq *ifq);
int netgpu_open_ifq(struct netgpu_ifq **ifqp, struct netgpu_ctx *ctx,
		    int queue_id, int fill_entries);
void netgpu_close_ifq(struct netgpu_ifq **ifqp);

int netgpu_attach_region(struct netgpu_ctx *ctx, struct netgpu_mem *mem,
			 int idx);
int netgpu_open_ctx(struct netgpu_ctx **ctxp, const char *ifname);
void netgpu_close_ctx(struct netgpu_ctx **ctxp);

int netgpu_open_memarea(struct netgpu_mem **memp);
void netgpu_close_memarea(struct netgpu_mem **memp);
int netgpu_add_memarea(struct netgpu_mem *mem, void *va, size_t size,
		       enum netgpu_memtype memtype);

void *netgpu_alloc_memory(size_t size, enum netgpu_memtype memtype);
void netgpu_free_memory(void *area, size_t size, enum netgpu_memtype memtype);


/* convenience functions */
int netgpu_register_memory(struct netgpu_ctx *ctx, void *va, size_t size,
			   enum netgpu_memtype memtype);

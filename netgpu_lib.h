#pragma once

#include <stdbool.h>

#ifndef MSG_ZEROCOPY
#define MSG_ZEROCOPY     0x4000000
#endif
#define MSG_NETDMA      0x8000000

struct netgpu;

int netgpu_start(struct netgpu **ctxp, const char *ifname, int queue_id,
		 int nentries);
void netgpu_stop(struct netgpu **ctxp);
int netgpu_register_region(struct netgpu *ctx, void *va, size_t size,
			   bool gpumem);
int netgpu_attach_socket(struct netgpu *ctx, int s);

void netgpu_populate_ring(struct netgpu *ctx, uint64_t addr, int count);
int netgpu_get_rx_batch(struct netgpu *ctx, struct iovec **iov, int count);
bool netgpu_recycle_batch(struct netgpu *ctx, struct iovec **iov, int count);
void netgpu_recycle_buffer(struct netgpu *ctx, void *ptr);
void netgpu_recycle_complete(struct netgpu *ctx);

void *netgpu_alloc_memory(size_t size, bool gpumem);
void netgpu_free_memory(void *area, size_t size, bool gpumem);

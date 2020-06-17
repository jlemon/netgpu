#pragma once

#include <linux/ioctl.h>

/* VA memory provided by a specific PCI device. */
struct dma_region {
	struct iovec iov;
	unsigned host_memory : 1;
};

#define NETGPU_OFF_FILL_ID	(0ULL << 12)
#define NETGPU_OFF_RX_ID	(1ULL << 12)

struct netgpu_queue_offsets {
	unsigned prod;
	unsigned cons;
	unsigned desc;
	unsigned resv;
};

struct netgpu_user_queue {
	unsigned elt_sz;
	unsigned entries;
	unsigned mask;
	unsigned map_sz;
	unsigned map_off;
	struct netgpu_queue_offsets off;
};

struct netgpu_params {
	unsigned flags;
	unsigned ifindex;
	unsigned queue_id;
	unsigned resv;
	struct netgpu_user_queue fill;
	struct netgpu_user_queue rx;
};

#define NETGPU_IOCTL_ATTACH_DEV		_IOR(0, 1, int)
#define NETGPU_IOCTL_BIND_QUEUE		_IOWR(0, 2, struct netgpu_params)
#define NETGPU_IOCTL_SETUP_RING		_IOWR(0, 2, struct netgpu_params)
#define NETGPU_IOCTL_ADD_REGION		_IOW(0, 3, struct dma_region)


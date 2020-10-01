#ifndef _UAPI_MISC_NETGPU_H
#define _UAPI_MISC_NETGPU_H

#include <linux/ioctl.h>

#define NETGPU_OFF_FILL_ID	(0ULL << 12)
#define NETGPU_OFF_RX_ID	(1ULL << 12)
#define NETGPU_OFF_CQ_ID	(2ULL << 12)
#define NETGPU_OFF_META_ID	(3ULL << 12)

struct netgpu_queue_offsets {
	unsigned prod;
	unsigned cons;
	unsigned data;
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

enum netgpu_memtype {
	MEMTYPE_HOST,
	MEMTYPE_CUDA,

	MEMTYPE_MAX,
};

/* VA memory provided by a specific PCI device. */
struct netgpu_region_param {
	struct iovec iov;
	enum netgpu_memtype memtype;
};

struct netgpu_attach_param {
	int mem_fd;
	int mem_idx;
};

struct netgpu_socket_param {
	unsigned resv;			/* now, op selection */
	union {
		struct {
			int ctx_fd;
			struct netgpu_user_queue rx;
			struct netgpu_user_queue cq;
		};
		struct {
			struct iovec iov;
			struct netgpu_user_queue meta;
			unsigned meta_len;
		};
	};
};

struct netgpu_ifq_param {
	unsigned resv;
	unsigned ifq_fd;		/* OUT parameter */
	unsigned queue_id;		/* IN/OUT, IN: -1 if don't care */
	struct netgpu_user_queue fill;
};

struct netgpu_ctx_param {
	unsigned resv;
	unsigned ifindex;
};

#define NETGPU_CTX_IOCTL_ATTACH_DEV	_IOR( 0, 1, int)
#define NETGPU_CTX_IOCTL_BIND_QUEUE	_IOWR(0, 2, struct netgpu_ifq_param)
#define NETGPU_CTX_IOCTL_ATTACH_REGION	_IOW( 0, 3, struct netgpu_attach_param)
#define NETGPU_MEM_IOCTL_ADD_REGION	_IOR( 0, 4, struct netgpu_region_param)
#define NETGPU_SOCK_IOCTL_ATTACH_QUEUES	(SIOCPROTOPRIVATE + 0)

#endif /* _UAPI_MISC_NETGPU_H */

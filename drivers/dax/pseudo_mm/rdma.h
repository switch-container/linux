#ifndef __PSEUDO_MM_RDMA_H__
#define __PSEUDO_MM_RDMA_H__

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <linux/inet.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/mm_types.h>
#include <linux/gfp.h>
#include <linux/pagemap.h>
#include <linux/spinlock.h>

struct pseudo_mm_rdma_dev {
	struct ib_device *dev;
	struct ib_pd *pd;
};

struct rdma_req {
	struct completion done;
	struct list_head list;
	struct ib_cqe cqe;
	u64 dma;
	struct page *page;
};

struct pseudo_mm_rdma_ctrl;

struct rdma_queue {
	struct ib_qp *qp;
	struct ib_cq *cq;
	spinlock_t cq_lock;

	struct pseudo_mm_rdma_ctrl *ctrl;

	struct rdma_cm_id *cm_id;
	int cm_error;
	struct completion cm_done;

	atomic_t pending;
};

struct pseudo_mm_rdma_memregion {
	u64 baseaddr;
	u32 key;
};

struct pseudo_mm_rdma_ctrl {
	struct pseudo_mm_rdma_dev *rdev; // TODO: move this to queue
	struct rdma_queue *queues;
	struct pseudo_mm_rdma_memregion servermr;

	union {
		struct sockaddr addr;
		struct sockaddr_in addr_in;
	};

	union {
		struct sockaddr srcaddr;
		struct sockaddr_in srcaddr_in;
	};
};

struct rdma_queue *pseudo_mm_rdma_get_queue(unsigned int cpuid);
/*
 * pseudo_mm_rdma_read_sync() - read a page from remote roffset into local page
 * @page: local page that will be copied the content to
 * @roffset: remote offset in bytes (instead of in page offset)
 *
 * NOTE: that this function will be returned without finishing to handle the rdma read.
 * However, the lock of page will be unlocked when read finish.
 * And the user need to poll the queue explicitly with pseudo_mm_rdma_poll_load()
 * since this queue is IB_POLL_DIRECT.
 */
int pseudo_mm_rdma_read_sync(struct page *page, u64 roffset);
/*
 * pseudo_mm_rdma_poll_load() - poll the rdma queue explicitly used by pseudo_mm
 * @cpu: cpu id of the caller
 *
 * Since pseudo_mm adopts fastswap, it allocates one rdma queue for each online cpu.
 * This usually should be called after pseudo_mm_rdma_read_sync to process the rdma read request.
 */
int pseudo_mm_rdma_poll_load(int cpu);



#endif

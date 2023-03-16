/*
 * Copyright (c) 2023 Amazon.com, Inc. or its affiliates. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef _SM2_FIFO_H_
#define _SM2_FIFO_H_

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include "sm2_common.h"
#include "sm2.h"

/*
 * Multi Writer, Single Reader Queue (Not Thread Safe)
 * This data structure must live in the SMR
 * This implementation of this is a one directional linked list with head/tail pointers
 * Every pointer is a relative offset into the Shared Memory Region
 */

#define SM2_FIFO_FREE -3

/* TODO: Switch to ofi_atom */
#define atomic_swap_ptr(addr, value) \
	atomic_exchange_explicit((_Atomic unsigned long *) addr, value, memory_order_relaxed)

#define atomic_compare_exchange(x, y, z) \
	__atomic_compare_exchange_n((int64_t *) (x), (int64_t *) (y), (int64_t)(z), \
								 false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)


// TODO MOVE TO its own FILE
#if defined(PLATFORM_ARCH_X86_64) && defined(PLATFORM_COMPILER_GNU) && __GNUC__ < 8
    /* work around a bug in older gcc versions where ACQUIRE seems to get
     * treated as a no-op instead */
#define BUSTED_ATOMIC_MB 1
#else
#define BUSTED_ATOMIC_MB 0
#endif

static inline void atomic_mb(void)
{
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

static inline void atomic_rmb(void)
{
#if BUSTED_ATOMIC_MB
    __asm__ __volatile__("" : : : "memory");
#else
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
#endif
}

static inline void atomic_wmb(void)
{
    __atomic_thread_fence(__ATOMIC_RELEASE);
}

// TODO MOVE TO OWN FILE ^^^^^^^^^^^^^^^

struct sm2_fifo {
	long int head;
	long int tail;
};

/* Initialize FIFO queue to empty state */
static inline void sm2_fifo_init(struct sm2_fifo *fifo)
{
	fifo->head = SM2_FIFO_FREE;
	fifo->tail = SM2_FIFO_FREE;
}

/* Write, Enqueue */
static inline void sm2_fifo_write(struct sm2_ep *ep, int peer_id,
        struct sm2_free_queue_entry *fqe)
{
	struct sm2_mmap *map = ep->mmap_regions;
	struct sm2_region *peer_region = sm2_smr_region(ep, peer_id);
	struct sm2_fifo *peer_fifo = sm2_recv_queue(peer_region);
	struct sm2_free_queue_entry *prev_fqe;
	long int offset = sm2_absptr_to_relptr(fqe, map);
	long int prev;

	assert(peer_fifo->head != 0);
	assert(peer_fifo->tail != 0);
	assert(offset != 0);

	fqe->protocol_hdr.next = SM2_FIFO_FREE;

	atomic_wmb();
	prev = atomic_swap_ptr(&peer_fifo->tail, offset);
	atomic_rmb();

	assert(prev != offset);

	if (OFI_LIKELY(SM2_FIFO_FREE != prev)) {
		if (OFI_UNLIKELY(prev + sizeof(fqe) > map->size)) {
			/* Need to re-map */
			sm2_mmap_remap(map, prev + sizeof(fqe));
			atomic_mb();
		}

		prev_fqe = sm2_relptr_to_absptr(prev, map);
		prev_fqe->protocol_hdr.next = offset;
	} else {
		peer_fifo->head = offset;
	}

	atomic_wmb();
}

/* Read, Dequeue */
static inline struct sm2_free_queue_entry* sm2_fifo_read(struct sm2_ep *ep)
{
	struct sm2_mmap *map = ep->mmap_regions;
	struct sm2_region *self_region = sm2_smr_region(ep, ep->self_fiaddr);
	struct sm2_fifo *self_fifo = sm2_recv_queue(self_region);
	struct sm2_free_queue_entry* fqe;
	long int prev_head;

	assert(self_fifo->head != 0);
	assert(self_fifo->tail != 0);

	// TODO Do I need this: atomic_mb();

	if (SM2_FIFO_FREE == self_fifo->head) {
		return NULL;
	}

	atomic_rmb();

	prev_head = self_fifo->head;

	if (OFI_UNLIKELY(prev_head + sizeof(fqe) > map->size)) {
		/* Need to re-map, and re-generate pointers */
		sm2_mmap_remap(map, prev_head + sizeof(fqe));
		self_region = sm2_smr_region(ep, ep->self_fiaddr);
		self_fifo = sm2_recv_queue(self_region);
		atomic_mb();
	}

	fqe = (struct sm2_free_queue_entry*)sm2_relptr_to_absptr(prev_head, map);
	self_fifo->head = SM2_FIFO_FREE;

	assert(fqe->protocol_hdr.next != prev_head);
	assert(fqe != 0);
	assert(fqe->protocol_hdr.next != 0);

	if (OFI_UNLIKELY(SM2_FIFO_FREE == fqe->protocol_hdr.next)) {
		atomic_rmb();
		if (!atomic_compare_exchange(&self_fifo->tail, &prev_head, SM2_FIFO_FREE)) {
			while (SM2_FIFO_FREE == fqe->protocol_hdr.next) {
				atomic_rmb();
			}
			self_fifo->head = fqe->protocol_hdr.next;
		}
	} else {
		self_fifo->head = fqe->protocol_hdr.next;
	}

	atomic_wmb();
	return fqe;
}

static inline void sm2_fifo_write_back(struct sm2_ep *ep,
		struct sm2_free_queue_entry *fqe)
{
	fqe->protocol_hdr.op_src = sm2_buffer_return;
	assert(fqe->protocol_hdr.id != ep->self_fiaddr);
	sm2_fifo_write(ep, fqe->protocol_hdr.id, fqe);
}

#endif /* _SM2_FIFO_H_ */

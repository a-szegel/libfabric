// Developed by Seth Zegelstein @ AWS
// 02/16/2023

#ifndef _SM2_FIFO_H_
#define _SM2_FIFO_H_

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include "sm2_common.h"

#define sm2_fifo_FREE -3

#define atomic_swap_ptr(addr, value) \
        atomic_exchange_explicit((_Atomic unsigned long *) addr, value, memory_order_relaxed)

// Multi Writer, Single Reader Queue (Not Thread Safe)
// This data structure must live in the SMR
// This implementation of this is a one directional linked list with head/tail pointers
// Every pointer is a relative offset into the Shared Memory Region

// TODO need to have FIFO Queue work with offsets instead of pointers

struct sm2_fifo {
    long int fifo_head;
    long int fifo_tail;
};


// TODO Remove PT2PT Hack to make Nemesis work for N writers to 1 receiver
// TODO Remove Owning Region, it is the hack
static inline long int virtual_addr_to_offset(struct sm2_region *owning_region, struct sm2_free_queue_entry *fqe) {
    return (long int) ((char *) fqe - (char *) owning_region);
}

// TODO Remove Owning Region, it is the hack
static inline struct sm2_free_queue_entry* offset_to_virtual_addr(struct sm2_region *owning_region, long int fqe_offset) {
    return (struct sm2_free_queue_entry *) ((char *) owning_region + fqe_offset);
}

// Initialize FIFO queue to empty state
static inline void sm2_fifo_init(struct sm2_fifo *fifo)
{
    fifo->fifo_head = sm2_fifo_FREE;
    fifo->fifo_tail = sm2_fifo_FREE;
}

static inline bool sm2_fifo_empty(struct sm2_fifo* fifo) {
    if (fifo->fifo_head == sm2_fifo_FREE)
        return true;
    return false;
}

/* Write, Enqueue */
// TODO Remove Owning Region, it is the pt2pt only hack
static inline void sm2_fifo_write(struct sm2_fifo *fifo, struct sm2_region *owning_region, struct sm2_free_queue_entry *fqe)
{
    struct sm2_free_queue_entry *prev_fqe;
    long int offset = virtual_addr_to_offset(owning_region, fqe);
    long int prev;

    // Set next pointer to NULL
    fqe->nemesis_hdr.next = sm2_fifo_FREE;

    prev = atomic_swap_ptr(&fifo->fifo_tail, offset);

    assert(prev != offset);

    if (OFI_LIKELY(sm2_fifo_FREE != prev)) {
        prev_fqe = offset_to_virtual_addr(owning_region, prev);
        prev_fqe->nemesis_hdr.next = offset;
    } else {
        fifo->fifo_head = offset;
    }
}

/* Read, Dequeue */
// TODO Put a real implementation in here
// TODO Remove Owning Region, it is the pt2pt only hack
static inline struct sm2_free_queue_entry* sm2_fifo_read(struct sm2_fifo *fifo, struct sm2_region *owning_region)
{
    return offset_to_virtual_addr(owning_region, fifo->fifo_head);
}

// TODO Need a writeback method (A way for receiver to return FQE to sender's FIFO)
static inline void sm2_fifo_write_back(struct sm2_free_queue_entry *sm_fqe) {
    // Do Something here
}

#endif /* _SM2_FIFO_H_ */
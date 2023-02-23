// Developed by Seth Zegelstein @ AWS
// 02/16/2023

#ifndef _SM2_FIFO_H_
#define _SM2_FIFO_H_

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include "sm2_common.h"

#define SM_FIFO_FREE -3

#define atomic_swap_ptr(addr, value) \
        atomic_exchange_explicit((_Atomic unsigned long *) addr, value, memory_order_relaxed)

// Multi Writer, Single Reader Queue (Not Thread Safe)
// This data structure must live in the SMR
// This implementation of this is a one directional linked list with head/tail pointers
// Every pointer is a relative offset into the Shared Memory Region

// TODO need to have FIFO Queue work with offsets instead of pointers

struct sm_fifo {
    long int fifo_head;
    long int fifo_tail;
};
typedef struct sm_fifo sm_fifo;


// Pass in actual addresses as mapped, and have this function convert it to a relative offset
// fifo pointer never needs to go to offset, but sm_fqe pointer does

// smr is from process that allocated the SMR
// is relative from the base of the FL a good idea?
// Offset From Free Stack Region = Free Queue Entry - Start of Free Stack
// Attempt 1:
// static inline long int virtual_addr_to_offset(struct sm2_region *owning_region, struct sm2_free_queue_entry *fqe) {
//     return (long int) ((char *) fqe - sm2_free_stack(owning_region));
// }

// static inline struct sm2_free_queue_entry *sm_fqe offset_to_virtual_addr(struct sm2_region *owning_region, long int fqe_offset) {
//     return (struct sm2_free_queue_entry *) ((char *) sm2_free_stack(owning_region) + fqe_offset);
// }

// Mapped address to offset
static inline virtual2relative() {

}

// offset to mapped address
static inline relative2virtual() {

}



// Initialize FIFO queue to empty state
static inline void sm_fifo_init(sm_fifo *fifo)
{
    fifo->fifo_head = SM_FIFO_FREE;
    fifo->fifo_tail = SM_FIFO_FREE;
}

static inline bool sm_fifo_empty(sm_fifo* fifo) {
    if (fifo->fifo_head == SM_FIFO_FREE)
        return true;
    return false;
}

/* Write, Enqueue */
// TODO Put a real implementation for write
// TODO Use a real virtual to

static inline bool sm_fifo_write_ep(mca_btl_sm_hdr_t *hdr, struct mca_btl_base_endpoint_t *ep)
{
    fifo_value_t rhdr = virtual2relative((char *) hdr);
    if (ep->fbox_out.buffer) {
        /* if there is a fast box for this peer then use the fast box to send the fragment header.
         * this is done to ensure fragment ordering */
        opal_atomic_wmb();
        return mca_btl_sm_fbox_sendi(ep, 0xfe, &rhdr, sizeof(rhdr), NULL, 0);
    }
    mca_btl_sm_try_fbox_setup(ep, hdr);
    hdr->next = SM_FIFO_FREE;
    sm_fifo_write(ep->fifo, rhdr);

    return true;
}


static inline void sm_fifo_write(sm_fifo *fifo, struct sm2_region *owning_region, struct sm2_free_queue_entry *fqe)
{
    long int offset = virtual_addr_to_offset(owning_region, sm_fqe);
    long int prev;

    prev = atomic_swap_ptr(&fifo->fifo_tail, offset);

    assert(prev != offset);

    if (OFI_LIKELY(SM_FIFO_FREE != prev)) {
        struct sm2_free_queue_entry *prev_fqe = relative2virtual(prev);
        mca_btl_sm_hdr_t *hdr = (mca_btl_sm_hdr_t *) relative2virtual(prev);
        prev_fqe->nemesis_hdr->next = offset;
    } else {
        fifo->fifo_head = offset;
    }
}

/* Read, Dequeue */
// TODO Put a real implementation for read
static inline long int sm_fifo_read(sm_fifo *fifo)
{
    return fifo->fifo_head;
}

// TODO Need a writeback method (A way for receiver to return FQE to sender's FIFO)
static inline void sm_fifo_write_back(struct sm2_free_queue_entry *sm_fqe) {
    // Do Something here
}

#endif /* _SM2_FIFO_H_ */

#define MCA_BTL_SM_LOCAL_RANK opal_process_info.my_local_rank

#if SIZEOF_VOID_P == 8
#    define MCA_BTL_SM_OFFSET_MASK 0xffffffffll
#    define MCA_BTL_SM_OFFSET_BITS 32
#    define MCA_BTL_SM_BITNESS     64
#else
#    define MCA_BTL_SM_OFFSET_MASK 0x00ffffffl
#    define MCA_BTL_SM_OFFSET_BITS 24
#    define MCA_BTL_SM_BITNESS     32
#endif

/***
 * One or more FIFO components may be a pointer that must be
 * accessed by multiple processes.  Since the shared region may
 * be mmapped differently into each process's address space,
 * these pointers will be relative to some base address.  Here,
 * we define inline functions to translate between relative
 * addresses and virtual addresses.
 */

/* This only works for finding the relative address for a pointer within my_segment */

// addr - start of segment (that addr is from)
// and then we change the higher order bits to reflect which segment it is from
static inline fifo_value_t virtual2relative(char *addr)
{
    return (fifo_value_t)((intptr_t)(addr - mca_btl_sm_component.my_segment))
           | ((fifo_value_t) MCA_BTL_SM_LOCAL_RANK << MCA_BTL_SM_OFFSET_BITS);
}

static inline fifo_value_t virtual2relativepeer(struct mca_btl_base_endpoint_t *endpoint,
                                                char *addr)
{
    return (fifo_value_t)((intptr_t)(addr - endpoint->segment_base))
           | ((fifo_value_t) endpoint->peer_smp_rank << MCA_BTL_SM_OFFSET_BITS);
}

static inline void *relative2virtual(fifo_value_t offset)
{
    return (void *) (intptr_t)(
        (offset & MCA_BTL_SM_OFFSET_MASK)
        + mca_btl_sm_component.endpoints[offset >> MCA_BTL_SM_OFFSET_BITS].segment_base);
}

#endif /* MCA_BTL_SM_VIRTUAL_H */



P1
id 1 = P2
id 2 = P3

P2
id 1 = P3
id 2 = P2

P3
id 1 = P2
id 2 = P3



P1 owns SMR1 which has Empty FI_FIFO

P2 calculates offset, can add their offset into that by changing head and tail pointers SMR2, + some offset

P3 needs to get to SHM2


in order to stay atomic, we need to be in 64 bits

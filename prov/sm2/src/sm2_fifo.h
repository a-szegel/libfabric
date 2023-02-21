// Developed by Seth Zegelstein @ AWS
// 02/16/2023

#ifndef _SM2_FIFO_H_
#define _SM2_FIFO_H_

#include <stdbool.h>
#include "sm2_common.h"

#define SM_FIFO_FREE -3

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
static inline void sm_fifo_write(sm_fifo *fifo, struct sm2_free_queue_entry *sm_fqe)
{
    fifo->fifo_head = (long int) sm_fqe;
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
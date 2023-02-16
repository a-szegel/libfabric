// Developed by Seth Zegelstein @ AWS
// 02/16/2023


// TODO Figure out a way to initialize this in SHM region ****

#include "sm2_fqe.h"

#define SM_FIFO_FREE -3

#ifndef _SM2_FIFO_H_
#define _SM2_FIFO_H_

// Multi Writer, Single Reader
// This data structure must live in the SMR
// This implementation of this is a one directional linked list with head/tail pointers
// Every pointer is a relative offset into the Shared Memory Region

struct sm_fifo {
    long int fifo_head;
    long int fifo_tail;
};
typedef struct sm_fifo sm_fifo;

// Initialize FIFO queue to empty state
 void sm_fifo_init(sm_fifo *fifo)
{
    fifo->fifo_head = SM_FIFO_FREE;
    fifo->fifo_tail = SM_FIFO_FREE;
}

/* Write, Enqueue */
// TODO Put a real implementation for write
void sm_fifo_write(sm_fifo *fifo, sm_fqe *sm_fqe)
{
    fifo->fifo_head = (long int) sm_fqe;
}

/* Read, Dequeue */
// TODO Put a real implementation for read
long int sm_fifo_read(sm_fifo *fifo)
{
    return fifo->fifo_head;
}

// TODO Need a writeback method (A way for receiver to return FQE to sender's FIFO)
void sm_fifo_write_back(sm_fqe *sm_fqe) {
    // Do Something here
}

#endif /* _SM2_FIFO_H_ */
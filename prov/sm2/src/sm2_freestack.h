// Developed by Seth Zegelstein @ AWS
// 02/16/2023

#include "sm2_fqe.h"

#define SM_LIFO_FREE -3

// TODO Figure out a way to initialize this in SHM region ****

#ifndef _SM2_FREESTACK_H_
#define _SM2_FREESTACK_H_

struct sm_free_stack {
    sm_fqe *lifo_head;
};
typedef struct sm_free_stack sm_free_stack;

void sm_freestack_init(sm_free_stack *free_stack) {
    free_stack->lifo_head = (sm_fqe *) SM_LIFO_FREE;
}

// TODO Fixup
void push(sm_free_stack *free_stack, sm_fqe* fqe) {
    if ((long) free_stack->lifo_head == SM_LIFO_FREE) {
        free_stack->lifo_head = fqe;
    } else {
        free_stack->lifo_head->next = (long) fqe;
    }
}

// TODO Fixup
sm_fqe* pop(sm_free_stack *free_stack) {
   sm_fqe *fqe;
   fqe =  free_stack->lifo_head;
   free_stack->lifo_head = (sm_fqe *) fqe->next;
}

#endif /* _SM2_FREESTACK_H_ */
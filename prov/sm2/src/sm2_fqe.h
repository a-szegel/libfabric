// Developed by Seth Zegelstein @ AWS
// 02/16/2023

#ifndef _SM2_FQE_H_
#define _SM2_FQE_H_

struct sm_fqe {
    /* For FIFO and LIFO queues */
    long int next;

    /* For Returns*/
    long int fifo_home;        /* fifo list to return fragment too once we are done with it */
    long int home_free_list;   /* free list this fragment was allocated within, for returning frag to free list */

    /* For our Data*/
    long int data_pointer;
    int data_size;
    int segment_size;
};
typedef struct sm_fqe sm_fqe;

#endif /* _SM2_FQE_H_ */
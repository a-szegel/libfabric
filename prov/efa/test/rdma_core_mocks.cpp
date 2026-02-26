/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "rdma_core_mocks.h"

RdmaCoreMock* g_rdma_core_mock = nullptr;

extern "C" {

// ibv_* mock implementations
struct ibv_ah* ibv_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	return g_rdma_core_mock->ibv_create_ah(pd, attr);
}

int ibv_destroy_ah(struct ibv_ah *ah)
{
	return g_rdma_core_mock->ibv_destroy_ah(ah);
}

int ibv_is_fork_initialized()
{
	return g_rdma_core_mock->ibv_is_fork_initialized();
}

int ibv_query_device(struct ibv_context *context, struct ibv_device_attr *device_attr)
{
	return g_rdma_core_mock->ibv_query_device(context, device_attr);
}

struct ibv_context* ibv_open_device(struct ibv_device *device)
{
	return g_rdma_core_mock->ibv_open_device(device);
}

int ibv_close_device(struct ibv_context *context)
{
	return g_rdma_core_mock->ibv_close_device(context);
}

struct ibv_pd* ibv_alloc_pd(struct ibv_context *context)
{
	return g_rdma_core_mock->ibv_alloc_pd(context);
}

int ibv_dealloc_pd(struct ibv_pd *pd)
{
	return g_rdma_core_mock->ibv_dealloc_pd(pd);
}

struct ibv_mr* ibv_reg_mr(struct ibv_pd *pd, void *addr, size_t length, int access)
{
	return g_rdma_core_mock->ibv_reg_mr(pd, addr, length, access);
}

int ibv_dereg_mr(struct ibv_mr *mr)
{
	return g_rdma_core_mock->ibv_dereg_mr(mr);
}

struct ibv_cq* ibv_create_cq(struct ibv_context *context, int cqe, void *cq_context,
	struct ibv_comp_channel *channel, int comp_vector)
{
	return g_rdma_core_mock->ibv_create_cq(context, cqe, cq_context, channel, comp_vector);
}

int ibv_destroy_cq(struct ibv_cq *cq)
{
	return g_rdma_core_mock->ibv_destroy_cq(cq);
}

int ibv_poll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *wc)
{
	return g_rdma_core_mock->ibv_poll_cq(cq, num_entries, wc);
}

struct ibv_qp* ibv_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *qp_init_attr)
{
	return g_rdma_core_mock->ibv_create_qp(pd, qp_init_attr);
}

int ibv_destroy_qp(struct ibv_qp *qp)
{
	return g_rdma_core_mock->ibv_destroy_qp(qp);
}

int ibv_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
	struct ibv_qp_init_attr *init_attr)
{
	return g_rdma_core_mock->ibv_query_qp(qp, attr, attr_mask, init_attr);
}

int ibv_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask)
{
	return g_rdma_core_mock->ibv_modify_qp(qp, attr, attr_mask);
}

int ibv_post_send(struct ibv_qp *qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr)
{
	return g_rdma_core_mock->ibv_post_send(qp, wr, bad_wr);
}

int ibv_post_recv(struct ibv_qp *qp, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad_wr)
{
	return g_rdma_core_mock->ibv_post_recv(qp, wr, bad_wr);
}

struct ibv_device** ibv_get_device_list(int *num_devices)
{
	return g_rdma_core_mock->ibv_get_device_list(num_devices);
}

void ibv_free_device_list(struct ibv_device **list)
{
	g_rdma_core_mock->ibv_free_device_list(list);
}

const char* ibv_get_device_name(struct ibv_device *device)
{
	return g_rdma_core_mock->ibv_get_device_name(device);
}

int ibv_req_notify_cq(struct ibv_cq *cq, int solicited_only)
{
	return g_rdma_core_mock->ibv_req_notify_cq(cq, solicited_only);
}

int ibv_get_cq_event(struct ibv_comp_channel *channel, struct ibv_cq **cq, void **cq_context)
{
	return g_rdma_core_mock->ibv_get_cq_event(channel, cq, cq_context);
}

void ibv_ack_cq_events(struct ibv_cq *cq, unsigned int nevents)
{
	g_rdma_core_mock->ibv_ack_cq_events(cq, nevents);
}

struct ibv_comp_channel* ibv_create_comp_channel(struct ibv_context *context)
{
	return g_rdma_core_mock->ibv_create_comp_channel(context);
}

int ibv_destroy_comp_channel(struct ibv_comp_channel *channel)
{
	return g_rdma_core_mock->ibv_destroy_comp_channel(channel);
}

#ifdef HAVE_EFA_DATA_IN_ORDER_ALIGNED_128_BYTES
int ibv_query_qp_data_in_order(struct ibv_qp *qp, enum ibv_wr_opcode op, uint32_t flags)
{
	return g_rdma_core_mock->ibv_query_qp_data_in_order(qp, op, flags);
}
#endif

// efadv_* mock implementations
int efadv_query_device(struct ibv_context *ibvctx, struct efadv_device_attr *attr, uint32_t inlen)
{
	return g_rdma_core_mock->efadv_query_device(ibvctx, attr, inlen);
}

struct ibv_cq_ex* efadv_create_cq(struct ibv_context *ibvctx, struct ibv_cq_init_attr_ex *attr_ex,
	struct efadv_cq_init_attr *efa_attr, uint32_t inlen)
{
	return g_rdma_core_mock->efadv_create_cq(ibvctx, attr_ex, efa_attr, inlen);
}

struct ibv_qp* efadv_create_qp_ex(struct ibv_context *ibvctx, struct ibv_qp_init_attr_ex *attr_ex,
	struct efadv_qp_init_attr *efa_attr, uint32_t inlen)
{
	return g_rdma_core_mock->efadv_create_qp_ex(ibvctx, attr_ex, efa_attr, inlen);
}

struct ibv_ah* efadv_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr,
	struct efadv_ah_attr *efa_attr, uint32_t inlen)
{
	return g_rdma_core_mock->efadv_create_ah(pd, attr, efa_attr, inlen);
}

#ifdef HAVE_EFADV_QUERY_MR
int efadv_query_mr(struct ibv_mr *ibvmr, struct efadv_mr_attr *attr, uint32_t inlen)
{
	return g_rdma_core_mock->efadv_query_mr(ibvmr, attr, inlen);
}
#endif

#ifdef HAVE_EFADV_QUERY_QP_WQS
int efadv_query_qp_wqs(struct ibv_qp *ibvqp, struct efadv_qp_wqs_attr *attr, uint32_t inlen)
{
	return g_rdma_core_mock->efadv_query_qp_wqs(ibvqp, attr, inlen);
}
#endif

#ifdef HAVE_EFADV_QUERY_CQ
int efadv_query_cq(struct ibv_cq *ibvcq, struct efadv_cq_attr *attr, uint32_t inlen)
{
	return g_rdma_core_mock->efadv_query_cq(ibvcq, attr, inlen);
}
#endif

} // extern "C"

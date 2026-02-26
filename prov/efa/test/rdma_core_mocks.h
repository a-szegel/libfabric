/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef RDMA_CORE_MOCKS_H
#define RDMA_CORE_MOCKS_H

#include <gmock/gmock.h>
#include <infiniband/verbs.h>
#include <infiniband/efadv.h>

// Undefine macros that conflict with mocking
#ifdef ibv_reg_mr
#undef ibv_reg_mr
#endif

class RdmaCoreMock {
public:
	virtual ~RdmaCoreMock() = default;

	// ibv_* functions
	MOCK_METHOD(struct ibv_ah*, ibv_create_ah, (struct ibv_pd *pd, struct ibv_ah_attr *attr));
	MOCK_METHOD(int, ibv_destroy_ah, (struct ibv_ah *ah));
	MOCK_METHOD(int, ibv_is_fork_initialized, ());
	MOCK_METHOD(int, ibv_query_device, (struct ibv_context *context, struct ibv_device_attr *device_attr));
	MOCK_METHOD(struct ibv_context*, ibv_open_device, (struct ibv_device *device));
	MOCK_METHOD(int, ibv_close_device, (struct ibv_context *context));
	MOCK_METHOD(struct ibv_pd*, ibv_alloc_pd, (struct ibv_context *context));
	MOCK_METHOD(int, ibv_dealloc_pd, (struct ibv_pd *pd));
	MOCK_METHOD(struct ibv_mr*, ibv_reg_mr, (struct ibv_pd *pd, void *addr, size_t length, int access));
	MOCK_METHOD(int, ibv_dereg_mr, (struct ibv_mr *mr));
	MOCK_METHOD(struct ibv_cq*, ibv_create_cq, (struct ibv_context *context, int cqe, void *cq_context,
		struct ibv_comp_channel *channel, int comp_vector));
	MOCK_METHOD(int, ibv_destroy_cq, (struct ibv_cq *cq));
	MOCK_METHOD(int, ibv_poll_cq, (struct ibv_cq *cq, int num_entries, struct ibv_wc *wc));
	MOCK_METHOD(struct ibv_qp*, ibv_create_qp, (struct ibv_pd *pd, struct ibv_qp_init_attr *qp_init_attr));
	MOCK_METHOD(int, ibv_destroy_qp, (struct ibv_qp *qp));
	MOCK_METHOD(int, ibv_query_qp, (struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		struct ibv_qp_init_attr *init_attr));
	MOCK_METHOD(int, ibv_modify_qp, (struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask));
	MOCK_METHOD(int, ibv_post_send, (struct ibv_qp *qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr));
	MOCK_METHOD(int, ibv_post_recv, (struct ibv_qp *qp, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad_wr));
	MOCK_METHOD(struct ibv_device**, ibv_get_device_list, (int *num_devices));
	MOCK_METHOD(void, ibv_free_device_list, (struct ibv_device **list));
	MOCK_METHOD(const char*, ibv_get_device_name, (struct ibv_device *device));
	MOCK_METHOD(int, ibv_req_notify_cq, (struct ibv_cq *cq, int solicited_only));
	MOCK_METHOD(int, ibv_get_cq_event, (struct ibv_comp_channel *channel, struct ibv_cq **cq, void **cq_context));
	MOCK_METHOD(void, ibv_ack_cq_events, (struct ibv_cq *cq, unsigned int nevents));
	MOCK_METHOD(struct ibv_comp_channel*, ibv_create_comp_channel, (struct ibv_context *context));
	MOCK_METHOD(int, ibv_destroy_comp_channel, (struct ibv_comp_channel *channel));

#ifdef HAVE_EFA_DATA_IN_ORDER_ALIGNED_128_BYTES
	MOCK_METHOD(int, ibv_query_qp_data_in_order, (struct ibv_qp *qp, enum ibv_wr_opcode op, uint32_t flags));
#endif

	// efadv_* functions
	MOCK_METHOD(int, efadv_query_device, (struct ibv_context *ibvctx, struct efadv_device_attr *attr, uint32_t inlen));
	MOCK_METHOD(struct ibv_cq_ex*, efadv_create_cq, (struct ibv_context *ibvctx, struct ibv_cq_init_attr_ex *attr_ex,
		struct efadv_cq_init_attr *efa_attr, uint32_t inlen));
	MOCK_METHOD(struct ibv_qp*, efadv_create_qp_ex, (struct ibv_context *ibvctx, struct ibv_qp_init_attr_ex *attr_ex,
		struct efadv_qp_init_attr *efa_attr, uint32_t inlen));
	MOCK_METHOD(struct ibv_ah*, efadv_create_ah, (struct ibv_pd *pd, struct ibv_ah_attr *attr,
		struct efadv_ah_attr *efa_attr, uint32_t inlen));

#ifdef HAVE_EFADV_QUERY_MR
	MOCK_METHOD(int, efadv_query_mr, (struct ibv_mr *ibvmr, struct efadv_mr_attr *attr, uint32_t inlen));
#endif

#ifdef HAVE_EFADV_QUERY_QP_WQS
	MOCK_METHOD(int, efadv_query_qp_wqs, (struct ibv_qp *ibvqp, struct efadv_qp_wqs_attr *attr, uint32_t inlen));
#endif

#ifdef HAVE_EFADV_QUERY_CQ
	MOCK_METHOD(int, efadv_query_cq, (struct ibv_cq *ibvcq, struct efadv_cq_attr *attr, uint32_t inlen));
#endif
};

extern RdmaCoreMock* g_rdma_core_mock;

#endif // RDMA_CORE_MOCKS_H

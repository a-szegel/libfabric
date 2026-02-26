/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef EFA_MOCKS_H
#define EFA_MOCKS_H

#include <gmock/gmock.h>
#include "efa.h"
#include "efa_cq.h"
#include "efa_rdm_cq.h"
#include "efa_base_ep.h"
#include "efa_rdm_pke.h"
#include "efa_rdm_ope.h"

class EfaMock {
public:
	virtual ~EfaMock() = default;

	// EFA internal functions
	MOCK_METHOD(struct efa_ah*, efa_ah_alloc, (struct efa_domain *domain, const uint8_t *gid, bool insert_implicit_av));
	MOCK_METHOD(void, efa_ah_release, (struct efa_domain *domain, struct efa_ah *ah, bool release_from_implicit_av));
	
	// OFI HMEM functions
	MOCK_METHOD(ssize_t, ofi_copy_from_hmem_iov, (void *dest, size_t size, enum fi_hmem_iface hmem_iface,
		uint64_t device, const struct iovec *hmem_iov, size_t hmem_iov_count, uint64_t hmem_iov_offset));
	
	// EFA RDM packet entry functions
	MOCK_METHOD(ssize_t, efa_rdm_pke_copy_payload_to_ope, (struct efa_rdm_pke *pke, struct efa_rdm_ope *ope));
	MOCK_METHOD(int, efa_rdm_pke_read, (struct efa_rdm_ope *ope));
	MOCK_METHOD(ssize_t, efa_rdm_pke_proc_matched_rtm, (struct efa_rdm_pke *pkt_entry));
	
	// EFA RDM operation functions
	MOCK_METHOD(ssize_t, efa_rdm_ope_post_send, (struct efa_rdm_ope *ope, int pkt_type));
	
	// EFA device functions
	MOCK_METHOD(bool, efa_device_support_unsolicited_write_recv, ());
	
	// EFA data path operations
	MOCK_METHOD(int, efa_qp_post_recv, (struct efa_qp *qp, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad_wr));
	MOCK_METHOD(int, efa_qp_post_send, (struct efa_qp *qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr));
	MOCK_METHOD(int, efa_qp_post_read, (struct efa_qp *qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr));
	MOCK_METHOD(int, efa_qp_post_write, (struct efa_qp *qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr));
	
	// EFA CQ operations
	MOCK_METHOD(int, efa_ibv_cq_start_poll, (struct efa_ibv_cq *ibv_cq, struct ibv_poll_cq_attr *attr));
	MOCK_METHOD(int, efa_ibv_cq_next_poll, (struct efa_ibv_cq *ibv_cq));
	MOCK_METHOD(void, efa_ibv_cq_end_poll, (struct efa_ibv_cq *ibv_cq));
	MOCK_METHOD(uint32_t, efa_ibv_cq_wc_read_opcode, (struct efa_ibv_cq *ibv_cq));
	MOCK_METHOD(uint32_t, efa_ibv_cq_wc_read_qp_num, (struct efa_ibv_cq *ibv_cq));
	MOCK_METHOD(uint32_t, efa_ibv_cq_wc_read_vendor_err, (struct efa_ibv_cq *ibv_cq));
	MOCK_METHOD(uint32_t, efa_ibv_cq_wc_read_src_qp, (struct efa_ibv_cq *ibv_cq));
	MOCK_METHOD(uint16_t, efa_ibv_cq_wc_read_slid, (struct efa_ibv_cq *ibv_cq));
	MOCK_METHOD(uint32_t, efa_ibv_cq_wc_read_byte_len, (struct efa_ibv_cq *ibv_cq));
	MOCK_METHOD(uint32_t, efa_ibv_cq_wc_read_wc_flags, (struct efa_ibv_cq *ibv_cq));
	MOCK_METHOD(uint32_t, efa_ibv_cq_wc_read_imm_data, (struct efa_ibv_cq *ibv_cq));
	MOCK_METHOD(bool, efa_ibv_cq_wc_is_unsolicited, (struct efa_ibv_cq *ibv_cq));
	MOCK_METHOD(int, efa_ibv_cq_wc_read_sgid, (struct efa_ibv_cq *ibv_cq, uint8_t *sgid));
	MOCK_METHOD(int, efa_ibv_get_cq_event, (struct efa_ibv_cq *ibv_cq));
	MOCK_METHOD(int, efa_ibv_req_notify_cq, (struct efa_ibv_cq *ibv_cq, int solicited_only));

#ifdef HAVE_CUDA
	MOCK_METHOD(int, ofi_cudaMalloc, (void **ptr, size_t size));
#endif

#ifdef HAVE_NEURON
	MOCK_METHOD(int, neuron_alloc, (void **handle, size_t size));
#endif
};

extern EfaMock* g_efa_mock;

#endif // EFA_MOCKS_H

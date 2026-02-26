/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_mocks.h"

EfaMock* g_efa_mock = nullptr;

extern "C" {

// Forward declarations for wrapped functions
struct efa_ah* __wrap_efa_ah_alloc(struct efa_domain*, const uint8_t*, bool);
void __wrap_efa_ah_release(struct efa_domain*, struct efa_ah*, bool);
ssize_t __wrap_ofi_copy_from_hmem_iov(void*, size_t, enum fi_hmem_iface, uint64_t,
	const struct iovec*, size_t, uint64_t);
ssize_t __wrap_efa_rdm_pke_copy_payload_to_ope(struct efa_rdm_pke*, struct efa_rdm_ope*);
int __wrap_efa_rdm_pke_read(struct efa_rdm_ope*);
ssize_t __wrap_efa_rdm_pke_proc_matched_rtm(struct efa_rdm_pke*);
ssize_t __wrap_efa_rdm_ope_post_send(struct efa_rdm_ope*, int);
bool __wrap_efa_device_support_unsolicited_write_recv();
int __wrap_efa_qp_post_recv(struct efa_qp*, struct ibv_recv_wr*, struct ibv_recv_wr**);
int __wrap_efa_qp_post_send(struct efa_qp*, struct ibv_send_wr*, struct ibv_send_wr**);
int __wrap_efa_qp_post_read(struct efa_qp*, struct ibv_send_wr*, struct ibv_send_wr**);
int __wrap_efa_qp_post_write(struct efa_qp*, struct ibv_send_wr*, struct ibv_send_wr**);
int __wrap_efa_ibv_cq_start_poll(struct efa_ibv_cq*, struct ibv_poll_cq_attr*);
int __wrap_efa_ibv_cq_next_poll(struct efa_ibv_cq*);
void __wrap_efa_ibv_cq_end_poll(struct efa_ibv_cq*);
uint32_t __wrap_efa_ibv_cq_wc_read_opcode(struct efa_ibv_cq*);
uint32_t __wrap_efa_ibv_cq_wc_read_qp_num(struct efa_ibv_cq*);
uint32_t __wrap_efa_ibv_cq_wc_read_vendor_err(struct efa_ibv_cq*);
uint32_t __wrap_efa_ibv_cq_wc_read_src_qp(struct efa_ibv_cq*);
uint16_t __wrap_efa_ibv_cq_wc_read_slid(struct efa_ibv_cq*);
uint32_t __wrap_efa_ibv_cq_wc_read_byte_len(struct efa_ibv_cq*);
uint32_t __wrap_efa_ibv_cq_wc_read_wc_flags(struct efa_ibv_cq*);
uint32_t __wrap_efa_ibv_cq_wc_read_imm_data(struct efa_ibv_cq*);
bool __wrap_efa_ibv_cq_wc_is_unsolicited(struct efa_ibv_cq*);
int __wrap_efa_ibv_cq_wc_read_sgid(struct efa_ibv_cq*, uint8_t*);
int __wrap_efa_ibv_get_cq_event(struct efa_ibv_cq*);
int __wrap_efa_ibv_req_notify_cq(struct efa_ibv_cq*, int);

// Wrapped implementations
struct efa_ah* __wrap_efa_ah_alloc(struct efa_domain *domain, const uint8_t *gid, bool insert_implicit_av)
{
	return g_efa_mock->efa_ah_alloc(domain, gid, insert_implicit_av);
}

void __wrap_efa_ah_release(struct efa_domain *domain, struct efa_ah *ah, bool release_from_implicit_av)
{
	g_efa_mock->efa_ah_release(domain, ah, release_from_implicit_av);
}

ssize_t __wrap_ofi_copy_from_hmem_iov(void *dest, size_t size, enum fi_hmem_iface hmem_iface,
	uint64_t device, const struct iovec *hmem_iov, size_t hmem_iov_count, uint64_t hmem_iov_offset)
{
	return g_efa_mock->ofi_copy_from_hmem_iov(dest, size, hmem_iface, device, hmem_iov, hmem_iov_count, hmem_iov_offset);
}

ssize_t __wrap_efa_rdm_pke_copy_payload_to_ope(struct efa_rdm_pke *pke, struct efa_rdm_ope *ope)
{
	return g_efa_mock->efa_rdm_pke_copy_payload_to_ope(pke, ope);
}

int __wrap_efa_rdm_pke_read(struct efa_rdm_ope *ope)
{
	return g_efa_mock->efa_rdm_pke_read(ope);
}

ssize_t __wrap_efa_rdm_pke_proc_matched_rtm(struct efa_rdm_pke *pkt_entry)
{
	return g_efa_mock->efa_rdm_pke_proc_matched_rtm(pkt_entry);
}

ssize_t __wrap_efa_rdm_ope_post_send(struct efa_rdm_ope *ope, int pkt_type)
{
	return g_efa_mock->efa_rdm_ope_post_send(ope, pkt_type);
}

bool __wrap_efa_device_support_unsolicited_write_recv()
{
	return g_efa_mock->efa_device_support_unsolicited_write_recv();
}

int __wrap_efa_qp_post_recv(struct efa_qp *qp, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad_wr)
{
	return g_efa_mock->efa_qp_post_recv(qp, wr, bad_wr);
}

int __wrap_efa_qp_post_send(struct efa_qp *qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr)
{
	return g_efa_mock->efa_qp_post_send(qp, wr, bad_wr);
}

int __wrap_efa_qp_post_read(struct efa_qp *qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr)
{
	return g_efa_mock->efa_qp_post_read(qp, wr, bad_wr);
}

int __wrap_efa_qp_post_write(struct efa_qp *qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr)
{
	return g_efa_mock->efa_qp_post_write(qp, wr, bad_wr);
}

int __wrap_efa_ibv_cq_start_poll(struct efa_ibv_cq *ibv_cq, struct ibv_poll_cq_attr *attr)
{
	return g_efa_mock->efa_ibv_cq_start_poll(ibv_cq, attr);
}

int __wrap_efa_ibv_cq_next_poll(struct efa_ibv_cq *ibv_cq)
{
	return g_efa_mock->efa_ibv_cq_next_poll(ibv_cq);
}

void __wrap_efa_ibv_cq_end_poll(struct efa_ibv_cq *ibv_cq)
{
	g_efa_mock->efa_ibv_cq_end_poll(ibv_cq);
}

uint32_t __wrap_efa_ibv_cq_wc_read_opcode(struct efa_ibv_cq *ibv_cq)
{
	return g_efa_mock->efa_ibv_cq_wc_read_opcode(ibv_cq);
}

uint32_t __wrap_efa_ibv_cq_wc_read_qp_num(struct efa_ibv_cq *ibv_cq)
{
	return g_efa_mock->efa_ibv_cq_wc_read_qp_num(ibv_cq);
}

uint32_t __wrap_efa_ibv_cq_wc_read_vendor_err(struct efa_ibv_cq *ibv_cq)
{
	return g_efa_mock->efa_ibv_cq_wc_read_vendor_err(ibv_cq);
}

uint32_t __wrap_efa_ibv_cq_wc_read_src_qp(struct efa_ibv_cq *ibv_cq)
{
	return g_efa_mock->efa_ibv_cq_wc_read_src_qp(ibv_cq);
}

uint16_t __wrap_efa_ibv_cq_wc_read_slid(struct efa_ibv_cq *ibv_cq)
{
	return g_efa_mock->efa_ibv_cq_wc_read_slid(ibv_cq);
}

uint32_t __wrap_efa_ibv_cq_wc_read_byte_len(struct efa_ibv_cq *ibv_cq)
{
	return g_efa_mock->efa_ibv_cq_wc_read_byte_len(ibv_cq);
}

uint32_t __wrap_efa_ibv_cq_wc_read_wc_flags(struct efa_ibv_cq *ibv_cq)
{
	return g_efa_mock->efa_ibv_cq_wc_read_wc_flags(ibv_cq);
}

uint32_t __wrap_efa_ibv_cq_wc_read_imm_data(struct efa_ibv_cq *ibv_cq)
{
	return g_efa_mock->efa_ibv_cq_wc_read_imm_data(ibv_cq);
}

bool __wrap_efa_ibv_cq_wc_is_unsolicited(struct efa_ibv_cq *ibv_cq)
{
	return g_efa_mock->efa_ibv_cq_wc_is_unsolicited(ibv_cq);
}

int __wrap_efa_ibv_cq_wc_read_sgid(struct efa_ibv_cq *ibv_cq, uint8_t *sgid)
{
	return g_efa_mock->efa_ibv_cq_wc_read_sgid(ibv_cq, sgid);
}

int __wrap_efa_ibv_get_cq_event(struct efa_ibv_cq *ibv_cq)
{
	return g_efa_mock->efa_ibv_get_cq_event(ibv_cq);
}

int __wrap_efa_ibv_req_notify_cq(struct efa_ibv_cq *ibv_cq, int solicited_only)
{
	return g_efa_mock->efa_ibv_req_notify_cq(ibv_cq, solicited_only);
}

#ifdef HAVE_CUDA
int __wrap_ofi_cudaMalloc(void **ptr, size_t size)
{
	return g_efa_mock->ofi_cudaMalloc(ptr, size);
}
#endif

#ifdef HAVE_NEURON
int __wrap_neuron_alloc(void **handle, size_t size)
{
	return g_efa_mock->neuron_alloc(handle, size);
}
#endif

} // extern "C"

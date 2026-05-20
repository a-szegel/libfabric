/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef _efa_rdm_pke_CMD_H
#define _efa_rdm_pke_CMD_H

#include <rdma/fi_endpoint.h>
#include <stdbool.h>
#include <stdint.h>
#include "efa_errno.h"
#include "efa_rdm_pke.h"
#include "efa_rdm_pke_nonreq.h"
#include "efa_rdm_pkt_type.h"

int efa_rdm_pke_fill_data(struct efa_rdm_pke *pke,
			  int pkt_type,
			  struct efa_rdm_ope *ope,
			  int64_t data_offset,
			  int data_size);

void efa_rdm_pke_handle_sent(struct efa_rdm_pke *pke, int pkt_type, struct efa_rdm_peer *peer);

void efa_rdm_pke_handle_data_copied(struct efa_rdm_pke *pkt_entry);

void efa_rdm_pke_handle_tx_error(struct efa_rdm_pke *pkt_entry, int prov_errno);

void efa_rdm_pke_handle_send_completion(struct efa_rdm_pke *pkt_entry);

void efa_rdm_pke_handle_rx_error(struct efa_rdm_pke *pkt_entry, int prov_errno);

void efa_rdm_pke_proc_received(struct efa_rdm_pke *pkt_entry);

void efa_rdm_pke_proc_received_no_hdr(struct efa_rdm_pke *pkt_entry, bool has_imm_data, uint32_t imm_data);

/**
 * @brief return whether a provider errno indicates that the peer cleanly
 *        aborted an in-flight protocol step
 *
 * "Peer cleanly aborted" means the peer made a normal, voluntary action
 * (e.g. closed an MR mid-protocol or tore down its endpoint) that caused
 * the receiver-side device op posted by this side to fail. It is
 * distinct from genuine local faults (LOCAL_ERROR_*) and network faults
 * (BAD_LENGTH, UNRESP_REMOTE, etc.) that the user must continue to see.
 *
 * Currently the recognized peer-abort statuses are:
 *
 * - EFA_IO_COMP_STATUS_REMOTE_ERROR_BAD_ADDRESS (7) — sender's MR was
 *   invalid or deregistered while a receiver-initiated RDMA READ
 *   referenced it.
 * - EFA_IO_COMP_STATUS_REMOTE_ERROR_ABORT (8) — peer EP was reset /
 *   torn down by the remote side while a control SEND was in flight.
 *
 * @param[in] prov_errno provider-specific error code
 * @return true if the prov_errno matches a peer-abort status
 */
static inline bool efa_rdm_prov_errno_is_peer_abort(int prov_errno)
{
	return prov_errno == EFA_IO_COMP_STATUS_REMOTE_ERROR_BAD_ADDRESS ||
	       prov_errno == EFA_IO_COMP_STATUS_REMOTE_ERROR_ABORT;
}

/**
 * @brief return whether the failing packet is a receiver-side
 *        protocol op tied to an rxe
 *
 * In `efa_rdm_pke_handle_tx_error`, the `case EFA_RDM_RXE:` branch is
 * entered for any send completion whose pkt_entry->ope is an rxe. Such
 * packets fall into two categories:
 *
 * 1. Receiver-initiated RDMA READ context packets posted as part of
 *    LONGREAD / RUNTREAD RTM. These have base header type
 *    `EFA_RDM_RMA_CONTEXT_PKT` and `context_type ==
 *    EFA_RDM_RDMA_READ_CONTEXT`. The READ WR references the
 *    sender's user MR, so a peer cleanly canceling that MR while
 *    the READ is in flight produces `REMOTE_ERROR_BAD_ADDRESS`. A
 *    peer-EP teardown produces `REMOTE_ERROR_ABORT`.
 *
 * 2. Receiver-side control SENDs that ride on the matched rxe:
 *    `EFA_RDM_CTS_PKT`, `EFA_RDM_EOR_PKT`, and `EFA_RDM_RECEIPT_PKT`.
 *    These SENDs are posted from the local EFA TX bounce-buffer
 *    pool, which has its own pre-registered MR — they never
 *    reference any user MR. Consequently a peer canceling its
 *    user MR cannot cause `REMOTE_ERROR_BAD_ADDRESS` on these
 *    packets; the only peer-abort prov_errno applicable to them
 *    is `REMOTE_ERROR_ABORT`, raised when the peer EP is torn
 *    down mid-protocol.
 *
 * Together, these are the packets whose failure can be re-routed
 * through the new peer-abort handler when the prov_errno indicates
 * the peer cleanly went away. Other packet types in the RXE branch
 * (none today — but future-proof) fall through to the existing
 * `efa_rdm_rxe_handle_error` path.
 *
 * @param[in] pkt_entry packet entry that hit a TX error
 * @return true if the packet is a receiver-side protocol op tied to an rxe
 */
static inline bool efa_rdm_pkt_is_rxe_protocol_op(struct efa_rdm_pke *pkt_entry)
{
	int pkt_type = efa_rdm_pkt_type_of(pkt_entry);

	switch (pkt_type) {
	case EFA_RDM_RMA_CONTEXT_PKT: {
		struct efa_rdm_rma_context_pkt *ctx_pkt =
			(struct efa_rdm_rma_context_pkt *)pkt_entry->wiredata;
		return ctx_pkt->context_type == EFA_RDM_RDMA_READ_CONTEXT;
	}
	case EFA_RDM_CTS_PKT:
	case EFA_RDM_EOR_PKT:
	case EFA_RDM_RECEIPT_PKT:
		return true;
	default:
		return false;
	}
}

#endif

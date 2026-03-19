/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

/**
 * @file efa_proto_ope.c
 * @brief Init/release functions for the per-protocol operation entry structs.
 *
 * These functions are wired in during Task 11 (the atomic switchover from
 * struct efa_proto_ope to the new hierarchy).  Until then they coexist with
 * the old efa_proto_tx_construct / efa_proto_rx_release functions.
 */

#include <assert.h>
#include <ofi_mem.h>
#include <ofi_iov.h>
#include "efa.h"
#include "efa_cntr.h"
#include "efa_proto_ope.h"
#include "efa_proto_ope_legacy.h"
#include "efa_rdm_ep.h"
#include "efa_rdm_peer.h"
#include "efa_rdm_pke.h"
#include "efa_rdm_rxe_map.h"
#include "efa_rdm_util.h"

/* ────────────────────────────────────────────────────────────────────────────
 * Base initialisation — shared by every leaf constructor
 * ──────────────────────────────────────────────────────────────────────────── */

static void
efa_proto_ope_base_init(struct efa_proto_ope_base *base,
		       struct efa_rdm_ep *ep,
		       struct efa_rdm_peer *peer,
		       const struct fi_msg *msg,
		       enum efa_proto_ope_type type,
		       uint32_t op, uint64_t flags)
{
	base->type = type;
	base->op = op;
	base->ep = ep;
	base->peer = peer;

	base->internal_flags = 0;
	base->tx_id = ofi_buf_index(base);
	base->rx_id = base->tx_id;
	base->msg_id = 0;
	base->total_len = 0;
	base->tag = 0;

	base->state = (type <= EFA_PROTO_TX_ATOMIC)
		? EFA_PROTO_TXE_REQ : EFA_PROTO_RXE_INIT;
	base->queued_ctrl_type = 0;
	base->efa_outstanding_tx_ops = 0;

	base->iov_count = msg->iov_count;
	if (msg->msg_iov)
		memcpy(base->iov, msg->msg_iov,
		       sizeof(struct iovec) * msg->iov_count);
	if (msg->desc)
		memcpy(base->desc, msg->desc,
		       sizeof(*msg->desc) * msg->iov_count);
	else
		memset(base->desc, 0, sizeof(*base->desc) * msg->iov_count);
	memset(base->mr, 0, sizeof(*base->mr) * msg->iov_count);

	base->rma_iov_count = 0;

	/* cq_entry */
	base->cq_entry.op_context = msg->context;
	base->cq_entry.data = msg->data;
	base->cq_entry.len = ofi_total_iov_len(base->iov, base->iov_count);
	base->cq_entry.buf = OFI_LIKELY(base->cq_entry.len > 0)
		? base->iov[0].iov_base : NULL;
	base->total_len = base->cq_entry.len;

	/* flags — TX op flags only apply to TX entries */
	if (type <= EFA_PROTO_TX_ATOMIC) {
		uint64_t tx_op_flags;

		assert(ep->base_ep.util_ep.tx_msg_flags == 0 ||
		       ep->base_ep.util_ep.tx_msg_flags == FI_COMPLETION);
		tx_op_flags = ep->base_ep.util_ep.tx_op_flags;
		if (ep->base_ep.util_ep.tx_msg_flags == 0)
			tx_op_flags &= ~FI_COMPLETION;
		base->fi_flags = flags | tx_op_flags;
	} else {
		base->fi_flags = flags;
	}

	dlist_init(&base->entry);
	dlist_init(&base->queued_pkts);
	if (peer) {
		if (type <= EFA_PROTO_TX_ATOMIC)
			dlist_insert_tail(&base->peer_entry, &peer->txe_list);
		else
			dlist_insert_tail(&base->peer_entry, &peer->rxe_list);
	}

	/* Insert into endpoint's tx/rx entry list */
	if (type <= EFA_PROTO_TX_ATOMIC)
		dlist_insert_tail(&base->ep_entry, &ep->txe_list);
	else
		dlist_insert_tail(&base->ep_entry, &ep->rxe_list);
}

/* ────────────────────────────────────────────────────────────────────────────
 * TX leaf constructors
 * ──────────────────────────────────────────────────────────────────────────── */

static inline void efa_proto_tx_base_init(struct efa_proto_tx_base *tx)
{
	tx->bytes_acked = 0;
	tx->bytes_sent = 0;
	tx->local_read_pkt_entry = NULL;
}

void efa_proto_tx_msg_init(struct efa_proto_tx_msg *entry,
			   struct efa_rdm_ep *ep,
			   struct efa_rdm_peer *peer,
			   const struct fi_msg *msg,
			   uint32_t op, uint64_t flags)
{
	efa_proto_ope_base_init(&entry->tx.base, ep, peer, msg,
			       EFA_PROTO_TX_MSG, op, flags);
	efa_proto_tx_base_init(&entry->tx);

	entry->window = 0;
	entry->bytes_runt = 0;
	entry->bytes_read_completed = 0;
	entry->bytes_read_submitted = 0;
	entry->bytes_read_total_len = 0;
	entry->bytes_read_offset = 0;

	switch (op) {
	case ofi_op_tagged:
		entry->tx.base.cq_entry.flags = FI_TRANSMIT | FI_MSG | FI_TAGGED;
		break;
	case ofi_op_msg:
		entry->tx.base.cq_entry.flags = FI_TRANSMIT | FI_MSG;
		break;
	default:
		assert(0 && "efa_proto_tx_msg_init: invalid op");
	}
}

void efa_proto_tx_rma_read_init(struct efa_proto_tx_rma_read *entry,
				struct efa_rdm_ep *ep,
				struct efa_rdm_peer *peer,
				const struct fi_msg *msg,
				uint64_t flags)
{
	efa_proto_ope_base_init(&entry->tx.base, ep, peer, msg,
			       EFA_PROTO_TX_RMA_READ, ofi_op_read_req, flags);
	efa_proto_tx_base_init(&entry->tx);

	entry->tx.base.cq_entry.flags = FI_RMA | FI_READ;
	entry->bytes_read_completed = 0;
	entry->bytes_read_submitted = 0;
	entry->bytes_read_total_len = 0;
	entry->bytes_read_offset = 0;
}

void efa_proto_tx_rma_write_init(struct efa_proto_tx_rma_write *entry,
				 struct efa_rdm_ep *ep,
				 struct efa_rdm_peer *peer,
				 const struct fi_msg *msg,
				 uint64_t flags)
{
	efa_proto_ope_base_init(&entry->tx.base, ep, peer, msg,
			       EFA_PROTO_TX_RMA_WRITE, ofi_op_write, flags);
	efa_proto_tx_base_init(&entry->tx);

	entry->tx.base.cq_entry.flags = FI_RMA | FI_WRITE;
	entry->bytes_write_completed = 0;
	entry->bytes_write_submitted = 0;
	entry->bytes_write_total_len = 0;
}

void efa_proto_tx_atomic_init(struct efa_proto_tx_atomic *entry,
			      struct efa_rdm_ep *ep,
			      struct efa_rdm_peer *peer,
			      const struct fi_msg *msg,
			      uint32_t op, uint64_t flags,
			      const struct efa_proto_atomic_hdr *hdr,
			      const struct efa_proto_atomic_ex *ex)
{
	efa_proto_ope_base_init(&entry->tx.base, ep, peer, msg,
			       EFA_PROTO_TX_ATOMIC, op, flags);
	efa_proto_tx_base_init(&entry->tx);

	entry->atomic_hdr = *hdr;
	if (ex)
		entry->atomic_ex = *ex;

	switch (op) {
	case ofi_op_atomic:
		entry->tx.base.cq_entry.flags = FI_WRITE | FI_ATOMIC;
		break;
	case ofi_op_atomic_fetch:
	case ofi_op_atomic_compare:
		entry->tx.base.cq_entry.flags = FI_READ | FI_ATOMIC;
		break;
	default:
		assert(0 && "efa_proto_tx_atomic_init: invalid op");
	}
}

/* ────────────────────────────────────────────────────────────────────────────
 * RX leaf constructors
 * ──────────────────────────────────────────────────────────────────────────── */

static inline void efa_proto_rx_base_init(struct efa_proto_rx_base *rx)
{
	rx->bytes_received = 0;
	rx->bytes_received_via_mulreq = 0;
	rx->bytes_copied = 0;
	rx->bytes_queued_blocking_copy = 0;
	rx->ignore = 0;
	rx->unexp_pkt = NULL;
	rx->rxe_map = NULL;
	rx->peer_rxe = NULL;
	rx->cuda_copy_method = EFA_PROTO_CUDA_COPY_UNSPEC;
}

void efa_proto_rx_msg_init(struct efa_proto_rx_msg *entry,
			   struct efa_rdm_ep *ep,
			   struct efa_rdm_peer *peer,
			   uint32_t op)
{
	struct fi_msg empty_msg = { 0 };

	efa_proto_ope_base_init(&entry->rx.base, ep, peer, &empty_msg,
			       EFA_PROTO_RX_MSG, op, 0);
	efa_proto_rx_base_init(&entry->rx);

	entry->window = 0;
	entry->bytes_runt = 0;
	entry->bytes_read_completed = 0;
	entry->bytes_read_submitted = 0;
	entry->bytes_read_total_len = 0;
	entry->bytes_read_offset = 0;

	switch (op) {
	case ofi_op_tagged:
		entry->rx.base.cq_entry.flags = FI_RECV | FI_MSG | FI_TAGGED;
		break;
	case ofi_op_msg:
		entry->rx.base.cq_entry.flags = FI_RECV | FI_MSG;
		break;
	default:
		assert(0 && "efa_proto_rx_msg_init: invalid op");
	}
}

void efa_proto_rx_rma_write_init(struct efa_proto_rx_rma_write *entry,
				 struct efa_rdm_ep *ep,
				 struct efa_rdm_peer *peer)
{
	struct fi_msg empty_msg = { 0 };

	efa_proto_ope_base_init(&entry->rx.base, ep, peer, &empty_msg,
			       EFA_PROTO_RX_RMA_WRITE, ofi_op_write, 0);
	efa_proto_rx_base_init(&entry->rx);

	entry->rx.base.cq_entry.flags = FI_REMOTE_WRITE | FI_RMA;
}

void efa_proto_rx_rma_read_init(struct efa_proto_rx_rma_read *entry,
				struct efa_rdm_ep *ep,
				struct efa_rdm_peer *peer)
{
	struct fi_msg empty_msg = { 0 };

	efa_proto_ope_base_init(&entry->rx.base, ep, peer, &empty_msg,
			       EFA_PROTO_RX_RMA_READ, ofi_op_read_rsp, 0);
	efa_proto_rx_base_init(&entry->rx);

	entry->rx.base.cq_entry.flags = FI_REMOTE_READ | FI_RMA;
	entry->window = 0;
	entry->bytes_sent = 0;
}

void efa_proto_rx_atomic_init(struct efa_proto_rx_atomic *entry,
			      struct efa_rdm_ep *ep,
			      struct efa_rdm_peer *peer,
			      uint32_t op)
{
	struct fi_msg empty_msg = { 0 };

	efa_proto_ope_base_init(&entry->rx.base, ep, peer, &empty_msg,
			       EFA_PROTO_RX_ATOMIC, op, 0);
	efa_proto_rx_base_init(&entry->rx);

	entry->atomic_hdr.atomic_op = 0;
	entry->atomic_hdr.datatype = 0;
	entry->atomrsp_data = NULL;

	switch (op) {
	case ofi_op_atomic:
		entry->rx.base.cq_entry.flags = FI_REMOTE_WRITE | FI_ATOMIC;
		break;
	case ofi_op_atomic_fetch:
	case ofi_op_atomic_compare:
		entry->rx.base.cq_entry.flags = FI_REMOTE_READ | FI_ATOMIC;
		break;
	default:
		assert(0 && "efa_proto_rx_atomic_init: invalid op");
	}
}

/* ────────────────────────────────────────────────────────────────────────────
 * Release helpers — common cleanup for base, tx_base, rx_base
 * ──────────────────────────────────────────────────────────────────────────── */

void efa_proto_ope_base_release(struct efa_proto_ope_base *base)
{
	int i, err;
	struct dlist_entry *tmp;
	struct efa_rdm_pke *pkt_entry;

	if (base->peer)
		dlist_remove(&base->peer_entry);

	for (i = 0; i < base->iov_count; i++) {
		if (base->mr[i]) {
			err = fi_close((struct fid *)base->mr[i]);
			if (OFI_UNLIKELY(err))
				efa_base_ep_write_eq_error(&base->ep->base_ep,
							   err, FI_EFA_ERR_MR_DEREG);
			base->mr[i] = NULL;
		}
	}

	dlist_remove(&base->ep_entry);

	if (base->state == EFA_PROTO_OPE_SEND)
		dlist_remove(&base->entry);

	dlist_foreach_container_safe(&base->queued_pkts,
				     struct efa_rdm_pke,
				     pkt_entry, entry, tmp)
		efa_rdm_pke_release_tx(pkt_entry);

	if (base->internal_flags & EFA_PROTO_OPE_QUEUED_FLAGS) {
		dlist_remove(&base->queued_entry);
		base->internal_flags &= ~EFA_PROTO_OPE_QUEUED_FLAGS;
	}

#ifdef ENABLE_EFA_POISONING
	efa_rdm_poison_mem_region(base, sizeof(union efa_proto_ope_entry));
#endif
	ofi_buf_free(base);
}

void efa_proto_rx_base_release(struct efa_proto_rx_base *rx)
{
	if (rx->rxe_map)
		efa_rdm_rxe_map_remove(rx->rxe_map, rx->base.msg_id,
				       EFA_PROTO_OPE_FROM_BASE(&rx->base));

	if (rx->peer_rxe) {
		efa_rdm_ep_get_peer_srx(rx->base.ep)->owner_ops->free_entry(rx->peer_rxe);
		rx->peer_rxe = NULL;
	}

	efa_proto_ope_base_release(&rx->base);
}

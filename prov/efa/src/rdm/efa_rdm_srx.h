/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef _EFA_RDM_SRX_H
#define _EFA_RDM_SRX_H

#include "efa.h"

int efa_rdm_peer_srx_construct(struct efa_rdm_ep *efa_rdm_ep);

void efa_rdm_srx_update_rxe(struct fi_peer_rx_entry *peer_rxe,
			    struct efa_rdm_ope *rxe);

/**
 * @brief Re-queue a matched fi_peer_rx_entry back into its SRX queue.
 *
 * Used by receiver-side peer-abort handling: after the receiver
 * decides to abandon an in-flight protocol step that it cannot
 * complete (because the peer cleanly went away), it returns the
 * matched peer_rxe to the head of the appropriate SRX posted-recv
 * queue (msg/tag, with FI_ADDR_UNSPEC vs per-source) so the user's
 * original fi_recv survives and can match a subsequent message.
 *
 * The caller must hold the SRX genlock (the same lock the matcher
 * runs under). The function is a no-op for invalid inputs (NULL or
 * already-posted entry) and falls back to ofi_buf_free for multi-recv
 * children — see comment in the implementation.
 *
 * @param[in] peer_rxe the entry to re-queue
 * @return 0 on success, negative libfabric error code on failure
 */
int efa_rdm_srx_repost_peer_rxe(struct fi_peer_rx_entry *peer_rxe);

static inline struct util_srx_ctx *efa_rdm_srx_get_srx_ctx(struct fi_peer_rx_entry *peer_rxe)
{
	return (struct util_srx_ctx *) peer_rxe->srx->ep_fid.fid.context;
}

#endif /* _EFA_RDM_SRX_H */

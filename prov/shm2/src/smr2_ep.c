/*
 * Copyright (c) 2013-2021 Intel Corporation. All rights reserved
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/un.h>

#include "ofi_iov.h"
#include "ofi_hmem.h"
#include "ofi_mr.h"
#include "smr2_signal.h"
#include "smr2.h"

extern struct fi_ops_msg smr2_msg_ops, smr2_no_recv_msg_ops, smr2_srx_msg_ops;
extern struct fi_ops_tagged smr2_tag_ops, smr2_no_recv_tag_ops, smr2_srx_tag_ops;
DEFINE_LIST(smr2_sock_name_list);
pthread_mutex_t smr2_sock_list_lock = PTHREAD_MUTEX_INITIALIZER;
int smr2_global_ep_idx = 0;

int smr2_setname(fid_t fid, void *addr, size_t addrlen)
{
	struct smr2_ep *ep;
	char *name;

	if (addrlen > SMR2_NAME_MAX) {
		FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
			"Addrlen exceeds max addrlen (%d)\n", SMR2_NAME_MAX);
		return -FI_EINVAL;
	}

	ep = container_of(fid, struct smr2_ep, util_ep.ep_fid.fid);
	if (ep->region) {
		FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
			"Cannot set name after EP has been enabled\n");
		return -FI_EBUSY;
	}

	name = strdup(addr);
	if (!name)
		return -FI_ENOMEM;

	if (ep->name)
		free((void *) ep->name);
	ep->name = name;
	return 0;
}

int smr2_getname(fid_t fid, void *addr, size_t *addrlen)
{
	struct smr2_ep *ep;
	int ret = 0;

	ep = container_of(fid, struct smr2_ep, util_ep.ep_fid.fid);
	if (!ep->name)
		return -FI_EADDRNOTAVAIL;

	if (!addr || *addrlen == 0 ||
	    snprintf(addr, *addrlen, "%s", ep->name) >= *addrlen)
		ret = -FI_ETOOSMALL;

	*addrlen = strlen(ep->name) + 1;

	if (!ret)
		((char *) addr)[*addrlen - 1] = '\0';

	return ret;
}

static struct fi_ops_cm smr2_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.setname = smr2_setname,
	.getname = smr2_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = fi_no_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
	.shutdown = fi_no_shutdown,
};

int smr2_getopt(fid_t fid, int level, int optname,
	       void *optval, size_t *optlen)
{
	struct smr2_ep *smr2_ep =
		container_of(fid, struct smr2_ep, util_ep.ep_fid);

	if ((level != FI_OPT_ENDPOINT) || (optname != FI_OPT_MIN_MULTI_RECV))
		return -FI_ENOPROTOOPT;

	*(size_t *)optval = smr2_get_smr2_srx(smr2_ep)->min_multi_recv_size;
	*optlen = sizeof(size_t);

	return FI_SUCCESS;
}

int smr2_setopt(fid_t fid, int level, int optname,
	       const void *optval, size_t optlen)
{
	struct smr2_ep *smr2_ep =
		container_of(fid, struct smr2_ep, util_ep.ep_fid);

	if ((level != FI_OPT_ENDPOINT) || (optname != FI_OPT_MIN_MULTI_RECV))
		return -FI_ENOPROTOOPT;

	smr2_get_smr2_srx(smr2_ep)->min_multi_recv_size = *(size_t *)optval;

	return FI_SUCCESS;
}

static int smr2_match_recv_ctx(struct dlist_entry *item, const void *args)
{
	struct smr2_rx_entry *pending_recv;

	pending_recv = container_of(item, struct smr2_rx_entry, peer_entry);
	return pending_recv->peer_entry.context == args;
}

static int smr2_ep_cancel_recv(struct smr2_ep *ep, struct smr2_queue *queue,
			      void *context, uint32_t op)
{
	struct smr2_srx_ctx *srx = smr2_get_smr2_srx(ep);
	struct smr2_rx_entry *recv_entry;
	struct dlist_entry *entry;
	int ret = 0;

	ofi_spin_lock(&srx->lock);
	entry = dlist_remove_first_match(&queue->list, smr2_match_recv_ctx,
					 context);
	if (entry) {
		recv_entry = container_of(entry, struct smr2_rx_entry, peer_entry);
		ret = smr2_write_err_comp(ep->util_ep.rx_cq,
			recv_entry->peer_entry.context,
			smr2_rx_cq_flags(op, recv_entry->peer_entry.flags, 0),
			recv_entry->peer_entry.tag, FI_ECANCELED);
		ofi_freestack_push(srx->recv_fs, recv_entry);
		ret = ret ? ret : 1;
	}

	ofi_spin_unlock(&srx->lock);
	return ret;
}

static ssize_t smr2_ep_cancel(fid_t ep_fid, void *context)
{
	struct smr2_ep *ep;
	int ret;

	ep = container_of(ep_fid, struct smr2_ep, util_ep.ep_fid);

	ret = smr2_ep_cancel_recv(ep, &smr2_get_smr2_srx(ep)->trecv_queue, context,
				 ofi_op_tagged);
	if (ret)
		return (ret < 0) ? ret : 0;

	ret = smr2_ep_cancel_recv(ep, &smr2_get_smr2_srx(ep)->recv_queue, context,
				 ofi_op_msg);
	return (ret < 0) ? ret : 0;
}

static struct fi_ops_ep smr2_ep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = smr2_ep_cancel,
	.getopt = smr2_getopt,
	.setopt = smr2_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

static void smr2_send_name(struct smr2_ep *ep, int64_t id)
{
	struct smr2_region *peer_smr;
	struct smr2_cmd *cmd;
	struct smr2_inject_buf *tx_buf;

	peer_smr = smr2_peer_region(ep->region, id);

	pthread_spin_lock(&peer_smr->lock);

	if (smr2_peer_data(ep->region)[id].name_sent || !peer_smr->cmd_cnt)
		goto out;

	cmd = ofi_cirque_next(smr2_cmd_queue(peer_smr));

	cmd->msg.hdr.op = SMR2_OP_MAX + ofi_ctrl_connreq;
	cmd->msg.hdr.id = id;
	cmd->msg.hdr.data = ep->region->pid;

	tx_buf = smr_freestack_pop(smr2_inject_pool(peer_smr));
	cmd->msg.hdr.src_data = smr2_get_offset(peer_smr, tx_buf);

	cmd->msg.hdr.size = strlen(ep->name) + 1;
	memcpy(tx_buf->data, ep->name, cmd->msg.hdr.size);

	smr2_peer_data(ep->region)[id].name_sent = 1;
	ofi_cirque_commit(smr2_cmd_queue(peer_smr));
	peer_smr->cmd_cnt--;
	smr2_signal(peer_smr);

out:
	pthread_spin_unlock(&peer_smr->lock);
}

int64_t smr2_verify_peer(struct smr2_ep *ep, fi_addr_t fi_addr)
{
	int64_t id;
	int ret;

	id = smr2_addr_lookup(ep->util_ep.av, fi_addr);
	assert(id < SMR2_MAX_PEERS);

	if (smr2_peer_data(ep->region)[id].addr.id >= 0)
		return id;

	if (ep->region->map->peers[id].peer.id < 0) {
		ret = smr2_map_to_region(&smr2_prov, ep->region->map, id);
		if (ret == -ENOENT)
			return -1;

	}

	smr2_send_name(ep, id);

	return -1;
}

static int smr2_match_msg(struct dlist_entry *item, const void *args)
{
	struct smr2_match_attr *attr = (struct smr2_match_attr *)args;
	struct smr2_rx_entry *recv_entry;

	recv_entry = container_of(item, struct smr2_rx_entry, peer_entry);
	return smr2_match_id(recv_entry->peer_entry.addr, attr->id);
}

static int smr2_match_tagged(struct dlist_entry *item, const void *args)
{
	struct smr2_match_attr *attr = (struct smr2_match_attr *)args;
	struct smr2_rx_entry *recv_entry;

	recv_entry = container_of(item, struct smr2_rx_entry, peer_entry);
	return smr2_match_id(recv_entry->peer_entry.addr, attr->id) &&
	       smr2_match_tag(recv_entry->peer_entry.tag, recv_entry->ignore,
			     attr->tag);
}

static void smr2_init_queue(struct smr2_queue *queue,
			   dlist_func_t *match_func)
{
	dlist_init(&queue->list);
	queue->match_func = match_func;
}

void smr2_format_pend_resp(struct smr2_tx_entry *pend, struct smr2_cmd *cmd,
			  void *context, enum fi_hmem_iface iface, uint64_t device,
			  const struct iovec *iov, uint32_t iov_count,
			  uint64_t op_flags, int64_t id, struct smr2_resp *resp)
{
	pend->cmd = *cmd;
	pend->context = context;
	memcpy(pend->iov, iov, sizeof(*iov) * iov_count);
	pend->iov_count = iov_count;
	pend->peer_id = id;
	pend->op_flags = op_flags;
	pend->bytes_done = 0;
	resp->status = FI_EBUSY;

	pend->iface = iface;
	pend->device = device;

	resp->msg_id = (uint64_t) (uintptr_t) pend;
}

void smr2_generic_format(struct smr2_cmd *cmd, int64_t peer_id, uint32_t op,
			uint64_t tag, uint64_t data, uint64_t op_flags)
{
	cmd->msg.hdr.op = op;
	cmd->msg.hdr.op_flags = op == ofi_op_read_req ? SMR2_RMA_REQ : 0;
	cmd->msg.hdr.tag = tag;
	cmd->msg.hdr.id = peer_id;
	cmd->msg.hdr.data = data;

	if (op_flags & FI_REMOTE_CQ_DATA)
		cmd->msg.hdr.op_flags |= SMR2_REMOTE_CQ_DATA;
	if (op_flags & FI_COMPLETION)
		cmd->msg.hdr.op_flags |= SMR2_TX_COMPLETION;
}

static void smr2_format_inject(struct smr2_cmd *cmd, enum fi_hmem_iface iface,
		uint64_t device, const struct iovec *iov, size_t count,
		struct smr2_region *smr, struct smr2_inject_buf *tx_buf)
{
	cmd->msg.hdr.op_src = smr2_src_inject;
	cmd->msg.hdr.src_data = smr2_get_offset(smr, tx_buf); // this might need to be adjusted when FQE  definition changes
	cmd->msg.hdr.size = ofi_copy_from_hmem_iov(tx_buf->data, SMR2_INJECT_SIZE,
						   iface, device, iov, count, 0);
}

int smr2_select_proto(bool use_ipc, bool cma_avail, enum fi_hmem_iface iface,
		     uint32_t op, uint64_t total_len, uint64_t op_flags)
{
	return smr2_src_inject;
}

static ssize_t smr2_do_inject(struct smr2_ep *ep, struct smr2_region *peer_smr, int64_t id,
			     int64_t peer_id, uint32_t op, uint64_t tag, uint64_t data,
			     uint64_t op_flags, enum fi_hmem_iface iface, uint64_t device,
			     const struct iovec *iov, size_t iov_count, size_t total_len,
			     void *context)
{
	struct smr2_cmd *cmd;
	struct smr2_inject_buf *tx_buf;

	cmd = ofi_cirque_next(smr2_cmd_queue(peer_smr)); // This should go away
	tx_buf = smr_freestack_pop(smr2_inject_pool(peer_smr));  // this can stay... might need different FQE definition

	smr2_generic_format(cmd, peer_id, op, tag, data, op_flags); // This can stay
	smr2_format_inject(cmd, iface, device, iov, iov_count, peer_smr, tx_buf);

	// This should change to enqueue the free queue entry on the peers fifo buffer
	ofi_cirque_commit(smr2_cmd_queue(peer_smr));
	peer_smr->cmd_cnt--;  // TODO Delete CMD_COUNT... gets us nothing

	return FI_SUCCESS;
}

smr2_proto_func smr2_proto_ops[smr2_src_max] = {
	[smr2_src_inject] = &smr2_do_inject,
};

static void smr2_cleanup_epoll(struct smr2_sock_info *sock_info)
{
	fd_signal_free(&sock_info->signal);
	ofi_epoll_close(sock_info->epollfd);
}

int smr2_srx_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct smr2_srx_ctx *srx;

	if (flags != FI_RECV || bfid->fclass != FI_CLASS_CQ)
		return -FI_EINVAL;

	srx = container_of(fid, struct smr2_srx_ctx, peer_srx.ep_fid.fid);
	srx->cq = container_of(bfid, struct smr2_cq, util_cq.cq_fid.fid);
	ofi_atomic_inc32(&srx->cq->util_cq.ref);
	return FI_SUCCESS;
}

static void smr2_close_recv_queue(struct smr2_srx_ctx *srx,
				 struct smr2_queue *recv_queue)
{
	struct fi_cq_err_entry err_entry;
	struct smr2_rx_entry *rx_entry;
	int ret;

	while (!dlist_empty(&recv_queue->list)) {
		dlist_pop_front(&recv_queue->list, struct smr2_rx_entry,
				rx_entry, peer_entry);

		memset(&err_entry, 0, sizeof err_entry);
		err_entry.op_context = rx_entry->peer_entry.context;
		err_entry.flags = rx_entry->peer_entry.flags;
		err_entry.tag = rx_entry->peer_entry.tag;
		err_entry.err = FI_ECANCELED;
		err_entry.prov_errno = -FI_ECANCELED;
		ret = srx->cq->peer_cq->owner_ops->writeerr(srx->cq->peer_cq, &err_entry);
		if (ret)
			FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
				"Error writing recv entry error to rx cq\n");

		ofi_freestack_push(srx->recv_fs, rx_entry);
	}
}

static void smr2_close_unexp_queue(struct smr2_srx_ctx *srx,
				 struct smr2_queue *unexp_queue)
{
	struct smr2_rx_entry *rx_entry;

	while (!dlist_empty(&unexp_queue->list)) {
		dlist_pop_front(&unexp_queue->list, struct smr2_rx_entry,
				rx_entry, peer_entry);
		rx_entry->peer_entry.srx->peer_ops->discard_msg(
							&rx_entry->peer_entry);
	}
}

static int smr2_srx_close(struct fid *fid)
{
	struct smr2_srx_ctx *srx;

	srx = container_of(fid, struct smr2_srx_ctx, peer_srx.ep_fid.fid);
	if (!srx)
		return -FI_EINVAL;

	smr2_close_recv_queue(srx, &srx->recv_queue);
	smr2_close_recv_queue(srx, &srx->trecv_queue);

	smr2_close_unexp_queue(srx, &srx->unexp_msg_queue);
	smr2_close_unexp_queue(srx, &srx->unexp_tagged_queue);

	ofi_atomic_dec32(&srx->cq->util_cq.ref);
	smr2_recv_fs_free(srx->recv_fs);
	ofi_spin_destroy(&srx->lock);
	free(srx);

	return FI_SUCCESS;
}

static int smr2_ep_close(struct fid *fid)
{
	struct smr2_ep *ep;

	ep = container_of(fid, struct smr2_ep, util_ep.ep_fid.fid);

	if (ep->sock_info) {
		fd_signal_set(&ep->sock_info->signal);
		pthread_join(ep->sock_info->listener_thread, NULL);
		close(ep->sock_info->listen_sock);
		unlink(ep->sock_info->name);
		smr2_cleanup_epoll(ep->sock_info);
		free(ep->sock_info);
	}

	ofi_endpoint_close(&ep->util_ep);

	if (ep->region)
		smr2_free(ep->region);

	if (ep->util_ep.ep_fid.msg != &smr2_no_recv_msg_ops)
		smr2_srx_close(&ep->srx->fid);

	smr2_cmd_ctx_fs_free(ep->cmd_ctx_fs);
	smr2_pend_fs_free(ep->pend_fs);
	smr2_sar_fs_free(ep->sar_fs);
	ofi_spin_destroy(&ep->tx_lock);

	free((void *)ep->name);
	free(ep);
	return 0;
}

static int smr2_ep_trywait(void *arg)
{
	struct smr2_ep *ep;

	ep = container_of(arg, struct smr2_ep, util_ep.ep_fid.fid);

	smr2_ep_progress(&ep->util_ep);

	return FI_SUCCESS;
}

static int smr2_ep_bind_cq(struct smr2_ep *ep, struct util_cq *cq, uint64_t flags)
{
	int ret;

	ret = ofi_ep_bind_cq(&ep->util_ep, cq, flags);
	if (ret)
		return ret;

	if (flags & FI_RECV)
		ep->rx_comp = cq->domain->info_domain_caps & FI_SOURCE ?
				smr2_rx_src_comp: smr2_rx_comp;

	if (cq->wait) {
		ret = ofi_wait_add_fid(cq->wait, &ep->util_ep.ep_fid.fid, 0,
				       smr2_ep_trywait);
		if (ret)
			return ret;
	}

	ret = fid_list_insert(&cq->ep_list,
			      &cq->ep_list_lock,
			      &ep->util_ep.ep_fid.fid);

	return ret;
}

static int smr2_ep_bind_cntr(struct smr2_ep *ep, struct util_cntr *cntr, uint64_t flags)
{
	int ret;

	ret = ofi_ep_bind_cntr(&ep->util_ep, cntr, flags);
	if (ret)
		return ret;

	if (cntr->wait) {
		ret = ofi_wait_add_fid(cntr->wait, &ep->util_ep.ep_fid.fid, 0,
				       smr2_ep_trywait);
		if (ret)
			return ret;
	}

	return FI_SUCCESS;
}

static int smr2_ep_bind(struct fid *ep_fid, struct fid *bfid, uint64_t flags)
{
	struct smr2_ep *ep;
	struct util_av *av;
	int ret = 0;

	ep = container_of(ep_fid, struct smr2_ep, util_ep.ep_fid.fid);
	switch (bfid->fclass) {
	case FI_CLASS_AV:
		av = container_of(bfid, struct util_av, av_fid.fid);
		ret = ofi_ep_bind_av(&ep->util_ep, av);
		if (ret) {
			FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
				"duplicate AV binding\n");
			return -FI_EINVAL;
		}
		break;
	case FI_CLASS_CQ:
		ret = smr2_ep_bind_cq(ep, container_of(bfid, struct util_cq,
						      cq_fid.fid), flags);
		break;
	case FI_CLASS_EQ:
		break;
	case FI_CLASS_CNTR:
		ret = smr2_ep_bind_cntr(ep, container_of(bfid,
				struct util_cntr, cntr_fid.fid), flags);
		break;
	case FI_CLASS_SRX_CTX:
		ep->srx = container_of(bfid, struct fid_ep, fid);
		break;
	default:
		FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
			"invalid fid class\n");
		ret = -FI_EINVAL;
		break;
	}
	return ret;
}

bool smr2_adjust_multi_recv(struct smr2_srx_ctx *srx,
			   struct fi_peer_rx_entry *rx_entry, size_t len)
{
	size_t left;
	void *new_base;

	left = rx_entry->iov[0].iov_len - len;

	new_base = (void *) ((uintptr_t) rx_entry->iov[0].iov_base + len);
	rx_entry->iov[0].iov_len = left;
	rx_entry->iov[0].iov_base = new_base;
	rx_entry->size = left;

	return left < srx->min_multi_recv_size;
}

static int smr2_get_msg(struct fid_peer_srx *srx, fi_addr_t addr,
		       size_t size, struct fi_peer_rx_entry **rx_entry)
{
	struct smr2_rx_entry *smr2_entry;
	struct smr2_srx_ctx *srx_ctx;
	struct smr2_match_attr match_attr;
	struct dlist_entry *dlist_entry;
	struct smr2_rx_entry *owner_entry;
	int ret;

	srx_ctx = srx->ep_fid.fid.context;
	ofi_spin_lock(&srx_ctx->lock);

	match_attr.id = addr;

	dlist_entry = dlist_find_first_match(&srx_ctx->recv_queue.list,
					     srx_ctx->recv_queue.match_func,
					     &match_attr);
	if (!dlist_entry) {
		smr2_entry = smr2_alloc_rx_entry(srx_ctx);
		if (!smr2_entry) {
			ret = -FI_ENOMEM;
		} else {
			smr2_entry->peer_entry.owner_context = NULL;
			smr2_entry->peer_entry.addr = addr;
			smr2_entry->peer_entry.size = size;
			smr2_entry->peer_entry.srx = srx;
			*rx_entry = &smr2_entry->peer_entry;
			ret = -FI_ENOENT;
		}
		goto out;
	}

	*rx_entry = (struct fi_peer_rx_entry *) dlist_entry;

	if ((*rx_entry)->flags & FI_MULTI_RECV) {
		owner_entry = container_of(*rx_entry, struct smr2_rx_entry, peer_entry);
		smr2_entry = smr2_get_recv_entry(srx_ctx, owner_entry->iov, owner_entry->desc,
					     owner_entry->peer_entry.count, addr,
					     owner_entry->peer_entry.context,
					     owner_entry->peer_entry.tag,
					     owner_entry->ignore,
					     owner_entry->peer_entry.flags & (~FI_MULTI_RECV));
		if (!smr2_entry) {
			ret = -FI_ENOMEM;
			goto out;
		}

		if (smr2_adjust_multi_recv(srx_ctx, &owner_entry->peer_entry, size))
			dlist_remove(dlist_entry);

		smr2_entry->peer_entry.owner_context = owner_entry;
		*rx_entry = &smr2_entry->peer_entry;
		owner_entry->multi_recv_ref++;
	} else {
		dlist_remove(dlist_entry);
	}

	(*rx_entry)->srx = srx;
	ret = FI_SUCCESS;
out:
	ofi_spin_unlock(&srx_ctx->lock);
	return ret;
}

static int smr2_get_tag(struct fid_peer_srx *srx, fi_addr_t addr,
			uint64_t tag, struct fi_peer_rx_entry **rx_entry)
{
	struct smr2_rx_entry *smr2_entry;
	struct smr2_srx_ctx *srx_ctx;
	struct smr2_match_attr match_attr;
	struct dlist_entry *dlist_entry;
	int ret;

	srx_ctx = srx->ep_fid.fid.context;
	ofi_spin_lock(&srx_ctx->lock);

	match_attr.id = addr;
	match_attr.tag = tag;

	dlist_entry = dlist_find_first_match(&srx_ctx->trecv_queue.list,
					     srx_ctx->trecv_queue.match_func,
					     &match_attr);
	if (!dlist_entry) {
		smr2_entry = smr2_alloc_rx_entry(srx_ctx);
		if (!smr2_entry) {
			ret = -FI_ENOMEM;
		} else {
			smr2_entry->peer_entry.owner_context = NULL;
			smr2_entry->peer_entry.addr = addr;
			smr2_entry->peer_entry.tag = tag;
			smr2_entry->peer_entry.srx = srx;
			*rx_entry = &smr2_entry->peer_entry;
			ret = -FI_ENOENT;
		}
		goto out;
	}
	dlist_remove(dlist_entry);

	*rx_entry = (struct fi_peer_rx_entry *) dlist_entry;
	(*rx_entry)->srx = srx;
	ret = FI_SUCCESS;
out:
	ofi_spin_unlock(&srx_ctx->lock);
	return ret;
}

static int smr2_queue_msg(struct fi_peer_rx_entry *rx_entry)
{
	struct smr2_srx_ctx *srx_ctx = rx_entry->srx->ep_fid.fid.context;

	ofi_spin_lock(&srx_ctx->lock);
	dlist_insert_tail((struct dlist_entry *) rx_entry,
			  &srx_ctx->unexp_msg_queue.list);
	ofi_spin_unlock(&srx_ctx->lock);
	return 0;
}

static int smr2_queue_tag(struct fi_peer_rx_entry *rx_entry)
{
	struct smr2_srx_ctx *srx_ctx = rx_entry->srx->ep_fid.fid.context;

	ofi_spin_lock(&srx_ctx->lock);
	dlist_insert_tail((struct dlist_entry *) rx_entry,
			  &srx_ctx->unexp_tagged_queue.list);
	ofi_spin_unlock(&srx_ctx->lock);
	return 0;
}

static void smr2_free_entry(struct fi_peer_rx_entry *entry)
{
	struct smr2_srx_ctx *srx = (struct smr2_srx_ctx *) entry->srx->ep_fid.fid.context;
	struct smr2_rx_entry *smr2_entry, *owner_entry;

	ofi_spin_lock(&srx->lock);
	smr2_entry = container_of(entry, struct smr2_rx_entry, peer_entry);
	if (entry->owner_context) {
		owner_entry = container_of(entry->owner_context,
					   struct smr2_rx_entry, peer_entry);
		if (!--owner_entry->multi_recv_ref &&
		    owner_entry->peer_entry.size < srx->min_multi_recv_size) {
			if (smr2_rx_comp(srx->cq, owner_entry->peer_entry.context,
					FI_MULTI_RECV, 0, NULL,
					0, 0, FI_ADDR_NOTAVAIL)) {
				FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
					"unable to write rx MULTI_RECV completion\n");
			}
			ofi_freestack_push(srx->recv_fs, owner_entry);
		}
	}

	ofi_freestack_push(srx->recv_fs, smr2_entry);
	ofi_spin_unlock(&srx->lock);
}

static struct fi_ops_srx_owner smr2_srx_owner_ops = {
	.size = sizeof(struct fi_ops_srx_owner),
	.get_msg = smr2_get_msg,
	.get_tag = smr2_get_tag,
	.queue_msg = smr2_queue_msg,
	.queue_tag = smr2_queue_tag,
	.free_entry = smr2_free_entry,
};

static int smr2_discard(struct fi_peer_rx_entry *rx_entry)
{
	struct smr2_cmd_ctx *cmd_ctx = rx_entry->peer_context;

	ofi_freestack_push(cmd_ctx->ep->cmd_ctx_fs, cmd_ctx);
	return FI_SUCCESS;
}

struct fi_ops_srx_peer smr2_srx_peer_ops = {
	.size = sizeof(struct fi_ops_srx_peer),
	.start_msg = smr2_unexp_start,
	.start_tag = smr2_unexp_start,
	.discard_msg = smr2_discard,
	.discard_tag = smr2_discard,
};

static struct fi_ops smr2_srx_fid_ops = {
	.size = sizeof(struct fi_ops),
	.close = smr2_srx_close,
	.bind = smr2_srx_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_ep smr2_srx_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = smr2_ep_cancel,
	.getopt = fi_no_getopt,
	.setopt = fi_no_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

static int smr2_ep_srx_context(struct smr2_domain *domain, size_t rx_size,
			      struct fid_ep **rx_ep)
{
	struct smr2_srx_ctx *srx;
	int ret = FI_SUCCESS;

	srx = calloc(1, sizeof(*srx));
	if (!srx)
		return -FI_ENOMEM;

	ret = ofi_spin_init(&srx->lock);
	if (ret)
		goto err;

	smr2_init_queue(&srx->recv_queue, smr2_match_msg);
	smr2_init_queue(&srx->trecv_queue, smr2_match_tagged);
	smr2_init_queue(&srx->unexp_msg_queue, smr2_match_msg);
	smr2_init_queue(&srx->unexp_tagged_queue, smr2_match_tagged);

	srx->recv_fs = smr2_recv_fs_create(rx_size, NULL, NULL);

	srx->min_multi_recv_size = SMR2_INJECT_SIZE;
	srx->dir_recv = domain->util_domain.info_domain_caps & FI_DIRECTED_RECV;

	srx->peer_srx.owner_ops = &smr2_srx_owner_ops;
	srx->peer_srx.peer_ops = &smr2_srx_peer_ops;

	srx->peer_srx.ep_fid.fid.fclass = FI_CLASS_SRX_CTX;
	srx->peer_srx.ep_fid.fid.context = srx;
	srx->peer_srx.ep_fid.fid.ops = &smr2_srx_fid_ops;
	srx->peer_srx.ep_fid.ops = &smr2_srx_ops;

	srx->peer_srx.ep_fid.msg = &smr2_srx_msg_ops;
	srx->peer_srx.ep_fid.tagged = &smr2_srx_tag_ops;
	*rx_ep = &srx->peer_srx.ep_fid;

	return FI_SUCCESS;

err:
	free(srx);
	return ret;
}

int smr2_srx_context(struct fid_domain *domain, struct fi_rx_attr *attr,
		    struct fid_ep **rx_ep, void *context)
{
	struct smr2_domain *smr2_domain;

	smr2_domain = container_of(domain, struct smr2_domain, util_domain.domain_fid);

	if (attr->op_flags & FI_PEER) {
		smr2_domain->srx = ((struct fi_peer_srx_context *) (context))->srx;
		smr2_domain->srx->peer_ops = &smr2_srx_peer_ops;
		return FI_SUCCESS;
	}
	return smr2_ep_srx_context(smr2_domain, attr->size, rx_ep);
}

static int smr2_ep_ctrl(struct fid *fid, int command, void *arg)
{
	struct smr2_attr attr;
	struct smr2_domain *domain;
	struct smr2_ep *ep;
	struct smr2_av *av;
	int ret;

	ep = container_of(fid, struct smr2_ep, util_ep.ep_fid.fid);
	av = container_of(ep->util_ep.av, struct smr2_av, util_av);

	switch (command) {
	case FI_ENABLE:
		if ((ofi_needs_rx(ep->util_ep.caps) && !ep->util_ep.rx_cq) ||
		    (ofi_needs_tx(ep->util_ep.caps) && !ep->util_ep.tx_cq))
			return -FI_ENOCQ;
		if (!ep->util_ep.av)
			return -FI_ENOAV;

		attr.name = smr2_no_prefix(ep->name);
		attr.rx_count = ep->rx_size;
		attr.tx_count = ep->tx_size;
		attr.flags = ep->util_ep.caps & FI_HMEM ?
				SMR2_FLAG_HMEM_ENABLED : 0;

		ret = smr2_create(&smr2_prov, av->smr2_map, &attr, &ep->region);
		if (ret)
			return ret;

		if (!ep->srx) {
			domain = container_of(ep->util_ep.domain,
					      struct smr2_domain,
					      util_domain.domain_fid);
			ret = smr2_ep_srx_context(domain, ep->rx_size,
						 &ep->srx);
			if (ret)
				return ret;
			ret = smr2_srx_bind(&ep->srx->fid,
					   &ep->util_ep.rx_cq->cq_fid.fid,
					   FI_RECV);
			if (ret)
				return ret;
		} else {
			ep->util_ep.ep_fid.msg = &smr2_no_recv_msg_ops;
			ep->util_ep.ep_fid.tagged = &smr2_no_recv_tag_ops;
		}
		smr2_exchange_all_peers(ep->region);

		break;
	default:
		return -FI_ENOSYS;
	}
	return ret;
}

static struct fi_ops smr2_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = smr2_ep_close,
	.bind = smr2_ep_bind,
	.control = smr2_ep_ctrl,
	.ops_open = fi_no_ops_open,
};

static int smr2_endpoint_name(struct smr2_ep *ep, char *name, char *addr,
			     size_t addrlen)
{
	memset(name, 0, SMR2_NAME_MAX);
	if (!addr || addrlen > SMR2_NAME_MAX)
		return -FI_EINVAL;

	pthread_mutex_lock(&smr2_ep_list_lock);
	ep->ep_idx = smr2_global_ep_idx++;
	pthread_mutex_unlock(&smr2_ep_list_lock);

	if (strstr(addr, SMR2_PREFIX))
		snprintf(name, SMR2_NAME_MAX - 1, "%s:%d:%d", addr, getuid(),
			 ep->ep_idx);
	else
		snprintf(name, SMR2_NAME_MAX - 1, "%s", addr);

	return 0;
}

static void smr2_init_sig_handlers(void)
{
	static bool sig_init = false;

	pthread_mutex_lock(&smr2_ep_list_lock);
	if (sig_init)
		goto out;

	/* Signal handlers to cleanup tmpfs files on an unclean shutdown */
	assert(SIGBUS < SIGRTMIN && SIGSEGV < SIGRTMIN
	       && SIGTERM < SIGRTMIN && SIGINT < SIGRTMIN);
	smr2_reg_sig_handler(SIGBUS);
	smr2_reg_sig_handler(SIGSEGV);
	smr2_reg_sig_handler(SIGTERM);
	smr2_reg_sig_handler(SIGINT);

	sig_init = true;
out:
	pthread_mutex_unlock(&smr2_ep_list_lock);
}

int smr2_endpoint(struct fid_domain *domain, struct fi_info *info,
		  struct fid_ep **ep_fid, void *context)
{
	struct smr2_ep *ep;
	int ret;
	char name[SMR2_NAME_MAX];

	smr2_init_sig_handlers();

	ep = calloc(1, sizeof(*ep));
	if (!ep)
		return -FI_ENOMEM;

	ret = smr2_endpoint_name(ep, name, info->src_addr, info->src_addrlen);
	if (ret)
		goto ep;
	ret = smr2_setname(&ep->util_ep.ep_fid.fid, name, SMR2_NAME_MAX);
	if (ret)
		goto ep;

	ret = ofi_spin_init(&ep->tx_lock);
	if (ret)
		goto name;

	ep->rx_size = info->rx_attr->size;
	ep->tx_size = info->tx_attr->size;
	ret = ofi_endpoint_init(domain, &smr2_util_prov, info, &ep->util_ep, context,
				smr2_ep_progress);
	if (ret)
		goto lock;

	ep->util_ep.ep_fid.msg = &smr2_msg_ops;
	ep->util_ep.ep_fid.tagged = &smr2_tag_ops;

	ep->cmd_ctx_fs = smr2_cmd_ctx_fs_create(info->rx_attr->size, NULL, NULL);
	ep->pend_fs = smr2_pend_fs_create(info->tx_attr->size, NULL, NULL);
	ep->sar_fs = smr2_sar_fs_create(info->rx_attr->size, NULL, NULL);

	dlist_init(&ep->sar_list);

	ep->util_ep.ep_fid.fid.ops = &smr2_ep_fi_ops;
	ep->util_ep.ep_fid.ops = &smr2_ep_ops;
	ep->util_ep.ep_fid.cm = &smr2_cm_ops;
	ep->util_ep.ep_fid.rma = NULL;

	*ep_fid = &ep->util_ep.ep_fid;
	return 0;

lock:
	ofi_spin_destroy(&ep->tx_lock);
name:
	free((void *)ep->name);
ep:
	free(ep);
	return ret;
}

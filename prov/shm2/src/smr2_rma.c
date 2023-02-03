/*
 * Copyright (c) 2013-2021 Intel Corporation. All rights reserved
 * (C) Copyright 2021 Amazon.com, Inc. or its affiliates.
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

#include "ofi_iov.h"
#include "smr2.h"


static void smr2_add_rma_cmd(struct smr2_region *peer_smr,
		const struct fi_rma_iov *rma_iov, size_t iov_count)
{
	struct smr2_cmd *cmd;

	cmd = ofi_cirque_next(smr2_cmd_queue(peer_smr));

	cmd->rma.rma_count = iov_count;
	memcpy(cmd->rma.rma_iov, rma_iov, sizeof(*rma_iov) * iov_count);

	ofi_cirque_commit(smr2_cmd_queue(peer_smr));
	peer_smr->cmd_cnt--;
}

static void smr2_format_rma_resp(struct smr2_cmd *cmd, fi_addr_t peer_id,
				const struct fi_rma_iov *rma_iov, size_t count,
				size_t total_len, uint32_t op, uint64_t op_flags)
{
	smr2_generic_format(cmd, peer_id, op, 0, 0, op_flags);
	cmd->msg.hdr.size = total_len;
}

static ssize_t smr2_rma_fast(struct smr2_region *peer_smr, const struct iovec *iov,
			size_t iov_count, const struct fi_rma_iov *rma_iov,
			size_t rma_count, void **desc, int peer_id, void *context,
			uint32_t op, uint64_t op_flags)
{
	struct iovec cma_iovec[SMR2_IOV_LIMIT], rma_iovec[SMR2_IOV_LIMIT];
	struct smr2_cmd *cmd;
	size_t total_len;
	int ret, i;

	memcpy(cma_iovec, iov, sizeof(*iov) * iov_count);
	for (i = 0; i < rma_count; i++) {
		rma_iovec[i].iov_base = (void *) rma_iov[i].addr;
		rma_iovec[i].iov_len = rma_iov[i].len;
	}

	total_len = ofi_total_iov_len(iov, iov_count);

	ret = smr2_cma_loop(peer_smr->pid, cma_iovec, iov_count, rma_iovec,
			   rma_count, 0, total_len, op == ofi_op_write);

	if (ret)
		return ret;

	cmd = ofi_cirque_next(smr2_cmd_queue(peer_smr));
	smr2_format_rma_resp(cmd, peer_id, rma_iov, rma_count, total_len,
			    (op == ofi_op_write) ? ofi_op_write_async :
			    ofi_op_read_async, op_flags);
	ofi_cirque_commit(smr2_cmd_queue(peer_smr));
	peer_smr->cmd_cnt--;

	return 0;
}

static ssize_t smr2_generic_rma(struct smr2_ep *ep, const struct iovec *iov,
	size_t iov_count, const struct fi_rma_iov *rma_iov, size_t rma_count,
	void **desc, fi_addr_t addr, void *context, uint32_t op, uint64_t data,
	uint64_t op_flags)
{
	struct smr2_domain *domain;
	struct smr2_region *peer_smr;
	enum fi_hmem_iface iface;
	uint64_t device;
	int64_t id, peer_id;
	int cmds, err = 0, proto = smr2_src_inject;
	ssize_t ret = 0;
	size_t total_len;
	bool use_ipc;

	assert(iov_count <= SMR2_IOV_LIMIT);
	assert(rma_count <= SMR2_IOV_LIMIT);
	assert(ofi_total_iov_len(iov, iov_count) ==
	       ofi_total_rma_iov_len(rma_iov, rma_count));

	domain = container_of(ep->util_ep.domain, struct smr2_domain, util_domain);

	id = smr2_verify_peer(ep, addr);
	if (id < 0)
		return -FI_EAGAIN;

	peer_id = smr2_peer_data(ep->region)[id].addr.id;
	peer_smr = smr2_peer_region(ep->region, id);

	cmds = 1 + !(domain->fast_rma && !(op_flags &
		    (FI_REMOTE_CQ_DATA | FI_DELIVERY_COMPLETE)) &&
		     rma_count == 1 && smr2_cma_enabled(ep, peer_smr));

	pthread_spin_lock(&peer_smr->lock);
	if (peer_smr->cmd_cnt < cmds ||
	    smr2_peer_data(ep->region)[id].sar_status) {
		ret = -FI_EAGAIN;
		goto unlock_region;
	}

	ofi_spin_lock(&ep->tx_lock);

	if (cmds == 1) {
		err = smr2_rma_fast(peer_smr, iov, iov_count, rma_iov,
				   rma_count, desc, peer_id,  context, op,
				   op_flags);
		if (err) {
			FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
				"error doing fast RMA\n");
			ret = smr2_write_err_comp(ep->util_ep.rx_cq, NULL,
						op_flags, 0, err);
		} else {
			ret = smr2_complete_tx(ep, context, op, op_flags);
		}

		if (ret) {
			FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
				"unable to process tx completion\n");
		}
		goto signal;
	}

	iface = smr2_get_mr_hmem_iface(ep->util_ep.domain, desc, &device);

	total_len = ofi_total_iov_len(iov, iov_count);
	assert(!(op_flags & FI_INJECT) || total_len <= SMR2_INJECT_SIZE);

	/* Do not inject if IPC is available so device to device
	 * transfer may occur if possible. */
	use_ipc = ofi_hmem_is_ipc_enabled(iface) && (iov_count == 1) &&
		  desc && (smr2_get_mr_flags(desc) & FI_HMEM_DEVICE_ONLY) &&
		  !(op_flags & FI_INJECT);

	proto = smr2_select_proto(use_ipc, smr2_cma_enabled(ep, peer_smr), iface,
				 op, total_len, op_flags);

	ret = smr2_proto_ops[proto](ep, peer_smr, id, peer_id, op, 0, data, op_flags,
				   iface, device, iov, iov_count, total_len, context);
	if (ret)
		goto unlock_cq;

	smr2_add_rma_cmd(peer_smr, rma_iov, rma_count);

	if (proto != smr2_src_inject)
		goto signal;

	ret = smr2_complete_tx(ep, context, op, op_flags);
	if (ret) {
		FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
			"unable to process tx completion\n");
	}

signal:
	smr2_signal(peer_smr);
unlock_cq:
	ofi_spin_unlock(&ep->tx_lock);
unlock_region:
	pthread_spin_unlock(&peer_smr->lock);
	return ret;
}

static ssize_t smr2_read(struct fid_ep *ep_fid, void *buf, size_t len,
			void *desc, fi_addr_t src_addr, uint64_t addr,
			uint64_t key, void *context)
{
	struct smr2_ep *ep;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	ep = container_of(ep_fid, struct smr2_ep, util_ep.ep_fid.fid);

	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;
	rma_iov.addr = addr;
	rma_iov.len = len;
	rma_iov.key = key;

	return smr2_generic_rma(ep, &msg_iov, 1, &rma_iov, 1, &desc,
			       src_addr, context, ofi_op_read_req, 0,
			       smr2_ep_tx_flags(ep));
}

static ssize_t smr2_readv(struct fid_ep *ep_fid, const struct iovec *iov,
			 void **desc, size_t count, fi_addr_t src_addr,
			 uint64_t addr, uint64_t key, void *context)
{
	struct smr2_ep *ep;
	struct fi_rma_iov rma_iov;

	ep = container_of(ep_fid, struct smr2_ep, util_ep.ep_fid.fid);

	rma_iov.addr = addr;
	rma_iov.len  = ofi_total_iov_len(iov, count);
	rma_iov.key = key;

	return smr2_generic_rma(ep, iov, count, &rma_iov, 1, desc,
			       src_addr, context, ofi_op_read_req, 0,
			       smr2_ep_tx_flags(ep));
}

static ssize_t smr2_readmsg(struct fid_ep *ep_fid, const struct fi_msg_rma *msg,
			   uint64_t flags)
{
	struct smr2_ep *ep;

	ep = container_of(ep_fid, struct smr2_ep, util_ep.ep_fid.fid);

	return smr2_generic_rma(ep, msg->msg_iov, msg->iov_count,
			       msg->rma_iov, msg->rma_iov_count,
			       msg->desc, msg->addr, msg->context,
			       ofi_op_read_req, 0,
			       flags | ep->util_ep.tx_msg_flags);
}

static ssize_t smr2_write(struct fid_ep *ep_fid, const void *buf, size_t len,
			 void *desc, fi_addr_t dest_addr, uint64_t addr,
			 uint64_t key, void *context)
{
	struct smr2_ep *ep;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	ep = container_of(ep_fid, struct smr2_ep, util_ep.ep_fid.fid);

	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;
	rma_iov.addr = addr;
	rma_iov.len = len;
	rma_iov.key = key;

	return smr2_generic_rma(ep, &msg_iov, 1, &rma_iov, 1, &desc,
			       dest_addr, context, ofi_op_write, 0,
			       smr2_ep_tx_flags(ep));
}

static ssize_t smr2_writev(struct fid_ep *ep_fid, const struct iovec *iov,
			  void **desc, size_t count, fi_addr_t dest_addr,
			  uint64_t addr, uint64_t key, void *context)
{
	struct smr2_ep *ep;
	struct fi_rma_iov rma_iov;

	ep = container_of(ep_fid, struct smr2_ep, util_ep.ep_fid.fid);

	rma_iov.addr = addr;
	rma_iov.len  = ofi_total_iov_len(iov, count);
	rma_iov.key = key;

	return smr2_generic_rma(ep, iov, count, &rma_iov, 1, desc,
			       dest_addr, context, ofi_op_write, 0,
			       smr2_ep_tx_flags(ep));
}


static ssize_t smr2_writemsg(struct fid_ep *ep_fid, const struct fi_msg_rma *msg,
			    uint64_t flags)
{
	struct smr2_ep *ep;

	ep = container_of(ep_fid, struct smr2_ep, util_ep.ep_fid.fid);

	return smr2_generic_rma(ep, msg->msg_iov, msg->iov_count,
			       msg->rma_iov, msg->rma_iov_count,
			       msg->desc, msg->addr, msg->context,
			       ofi_op_write, msg->data,
			       flags | ep->util_ep.tx_msg_flags);
}

static ssize_t smr2_generic_rma_inject(struct fid_ep *ep_fid, const void *buf,
		size_t len, fi_addr_t dest_addr, uint64_t addr, uint64_t key,
		uint64_t data, uint64_t flags)
{
	struct smr2_ep *ep;
	struct smr2_domain *domain;
	struct smr2_region *peer_smr;
	struct iovec iov;
	struct fi_rma_iov rma_iov;
	int64_t id, peer_id;
	int cmds;
	ssize_t ret = 0;

	assert(len <= SMR2_INJECT_SIZE);
	ep = container_of(ep_fid, struct smr2_ep, util_ep.ep_fid.fid);
	domain = container_of(ep->util_ep.domain, struct smr2_domain, util_domain);

	id = smr2_verify_peer(ep, dest_addr);
	if (id < 0)
		return -FI_EAGAIN;

	peer_id = smr2_peer_data(ep->region)[id].addr.id;
	peer_smr = smr2_peer_region(ep->region, id);

	cmds = 1 + !(domain->fast_rma && !(flags & FI_REMOTE_CQ_DATA) &&
		     smr2_cma_enabled(ep, peer_smr));

	pthread_spin_lock(&peer_smr->lock);
	if (peer_smr->cmd_cnt < cmds ||
	    smr2_peer_data(ep->region)[id].sar_status) {
		ret = -FI_EAGAIN;
		goto unlock_region;
	}

	iov.iov_base = (void *) buf;
	iov.iov_len = len;
	rma_iov.addr = addr;
	rma_iov.len = len;
	rma_iov.key = key;

	if (cmds == 1) {
		ret = smr2_rma_fast(peer_smr, &iov, 1, &rma_iov, 1, NULL,
				   peer_id, NULL, ofi_op_write, flags);
		if (ret)
			goto unlock_region;
		goto signal;
	}

	ret = smr2_proto_ops[smr2_src_inject](ep, peer_smr, id, peer_id, ofi_op_write, 0,
			data, flags, FI_HMEM_SYSTEM, 0, &iov, 1, len, NULL);

	assert(!ret);
	smr2_add_rma_cmd(peer_smr, &rma_iov, 1);
signal:
	smr2_signal(peer_smr);
	ofi_ep_tx_cntr_inc_func(&ep->util_ep, ofi_op_write);
unlock_region:
	pthread_spin_unlock(&peer_smr->lock);
	return ret;
}

static ssize_t smr2_writedata(struct fid_ep *ep_fid, const void *buf, size_t len,
			     void *desc, uint64_t data, fi_addr_t dest_addr,
			     uint64_t addr, uint64_t key, void *context)
{
	struct smr2_ep *ep;
	struct iovec iov;
	struct fi_rma_iov rma_iov;

	ep = container_of(ep_fid, struct smr2_ep, util_ep.ep_fid.fid);

	iov.iov_base = (void *) buf;
	iov.iov_len = len;
	rma_iov.addr = addr;
	rma_iov.len = len;
	rma_iov.key = key;

	return smr2_generic_rma(ep, &iov, 1, &rma_iov, 1, &desc, dest_addr, context,
			       ofi_op_write, data,
			       FI_REMOTE_CQ_DATA | smr2_ep_tx_flags(ep));
}

static ssize_t smr2_rma_inject(struct fid_ep *ep_fid, const void *buf,
			      size_t len, fi_addr_t dest_addr, uint64_t addr,
			      uint64_t key)
{
	return smr2_generic_rma_inject(ep_fid, buf, len, dest_addr, addr, key,
				      0, 0);
}

static ssize_t smr2_inject_writedata(struct fid_ep *ep_fid, const void *buf,
			size_t len, uint64_t data, fi_addr_t dest_addr,
			uint64_t addr, uint64_t key)
{
	return smr2_generic_rma_inject(ep_fid, buf, len, dest_addr, addr, key,
				      data, FI_REMOTE_CQ_DATA);
}

struct fi_ops_rma smr2_rma_ops = {
	.size = sizeof(struct fi_ops_rma),
	.read = smr2_read,
	.readv = smr2_readv,
	.readmsg = smr2_readmsg,
	.write = smr2_write,
	.writev = smr2_writev,
	.writemsg = smr2_writemsg,
	.inject = smr2_rma_inject,
	.writedata = smr2_writedata,
	.injectdata = smr2_inject_writedata,
};

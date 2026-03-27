/*
 * Copyright (c) 2026 Amazon.com, Inc. or its affiliates. All rights reserved.
 *
 * This software is available to you under the BSD license
 * below:
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
 *
 * Test aborting in-flight RMA operations by closing MRs.
 *
 * Test modes:
 *   - Initiator close: client posts RMA ops, client closes its local MRs
 *   - Target close: client posts RMA ops, server closes its remote MRs
 *   - Multi-op per MR: N ops share 1 MR, close aborts all remaining
 *   - Partial close: 2 MRs on same buffer, close only 1, other completes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

#include <rdma/fi_errno.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_cm.h>

#include "shared.h"

enum cancel_mode {
	CANCEL_REVERSE,
	CANCEL_RANDOM,
};

enum close_side {
	CLOSE_INITIATOR,
	CLOSE_TARGET,
};

enum test_mode {
	TEST_ABORT,
	TEST_PARTIAL,
	TEST_SEND,
	TEST_TAGGED,
};

/*
 * Each MR slot can have ops_per_mr operations posted against it.
 * op_ctx tracks per-operation state; mr_slot tracks per-MR state.
 */
struct op_ctx {
	struct fi_context2 context;
	int mr_idx;	/* which mr_slot this op belongs to */
	int completed;
	int status;	/* 0 = success, negative = error code */
};

struct mr_slot {
	char *buf;
	struct fid_mr *mr;
	void *desc;
	uint64_t key;
	int posted;	/* number of ops posted using this MR */
	int mr_closed;
};

static struct mr_slot *slots;
static struct op_ctx *op_arr;
static int *cancel_order;
static int wq_depth = 8192;
static int ops_per_mr = 1;
static enum cancel_mode cancel_mode = CANCEL_REVERSE;
static enum close_side close_side = CLOSE_INITIATOR;
static enum test_mode test_mode = TEST_ABORT;

/* Remote side MR info */
static struct fi_rma_iov *remote_arr;

#define MR_ABORT_KEY_BASE 0x1000
#define CQ_TIMEOUT_MS 30000

static uint64_t local_access_for_op(void)
{
	uint64_t access = 0;

	switch (opts.rma_op) {
	case FT_RMA_WRITE:
	case FT_RMA_WRITEDATA:
		access = FI_WRITE;
		break;
	case FT_RMA_READ:
		access = FI_READ;
		break;
	default:
		access = FI_WRITE | FI_READ;
		break;
	}
	if (fi->domain_attr->mr_mode & FI_MR_LOCAL)
		access |= FI_READ | FI_WRITE;
	return access;
}

static uint64_t remote_access_for_op(void)
{
	switch (opts.rma_op) {
	case FT_RMA_WRITE:
	case FT_RMA_WRITEDATA:
		return FI_REMOTE_WRITE;
	case FT_RMA_READ:
		return FI_REMOTE_READ;
	default:
		return FI_REMOTE_WRITE | FI_REMOTE_READ;
	}
}

static int max_ops(void)
{
	return wq_depth * ops_per_mr;
}

static int alloc_test_res(void)
{
	int i;

	slots = calloc(wq_depth, sizeof(*slots));
	if (!slots)
		return -FI_ENOMEM;

	op_arr = calloc(max_ops(), sizeof(*op_arr));
	if (!op_arr)
		return -FI_ENOMEM;

	cancel_order = calloc(wq_depth, sizeof(*cancel_order));
	if (!cancel_order)
		return -FI_ENOMEM;

	remote_arr = calloc(wq_depth, sizeof(*remote_arr));
	if (!remote_arr)
		return -FI_ENOMEM;

	for (i = 0; i < wq_depth; i++) {
		slots[i].buf = calloc(1, opts.transfer_size);
		if (!slots[i].buf)
			return -FI_ENOMEM;
		slots[i].key = MR_ABORT_KEY_BASE + i;
	}

	return 0;
}

static void free_test_res(void)
{
	int i;

	if (slots) {
		for (i = 0; i < wq_depth; i++) {
			FT_CLOSE_FID(slots[i].mr);
			free(slots[i].buf);
		}
		free(slots);
		slots = NULL;
	}
	free(op_arr);
	op_arr = NULL;
	free(cancel_order);
	cancel_order = NULL;
	free(remote_arr);
	remote_arr = NULL;
}

static int register_mrs(uint64_t access)
{
	int i, ret;

	for (i = 0; i < wq_depth; i++) {
		if (slots[i].mr)
			continue;

		ret = ft_reg_mr(fi, slots[i].buf, opts.transfer_size,
				access, slots[i].key, opts.iface,
				opts.device, &slots[i].mr, &slots[i].desc);
		if (ret) {
			FT_PRINTERR("ft_reg_mr", ret);
			return ret;
		}
	}
	return 0;
}

static int exchange_mr_keys(void)
{
	struct fi_rma_iov *local_info;
	int i, ret;

	local_info = calloc(wq_depth, sizeof(*local_info));
	if (!local_info)
		return -FI_ENOMEM;

	for (i = 0; i < wq_depth; i++) {
		local_info[i].key = fi_mr_key(slots[i].mr);
		local_info[i].addr =
			(fi->domain_attr->mr_mode & FI_MR_VIRT_ADDR) ?
			(uintptr_t) slots[i].buf : 0;
		local_info[i].len = opts.transfer_size;
	}

	if (opts.dst_addr) {
		ret = ft_sock_send(oob_sock, local_info,
				   wq_depth * sizeof(*local_info));
		if (ret)
			goto out;
		ret = ft_sock_recv(oob_sock, remote_arr,
				   wq_depth * sizeof(*remote_arr));
	} else {
		ret = ft_sock_recv(oob_sock, remote_arr,
				   wq_depth * sizeof(*remote_arr));
		if (ret)
			goto out;
		ret = ft_sock_send(oob_sock, local_info,
				   wq_depth * sizeof(*local_info));
	}

out:
	free(local_info);
	return ret;
}

static void reset_test_state(void)
{
	int i;

	for (i = 0; i < wq_depth; i++) {
		slots[i].posted = 0;
		slots[i].mr_closed = 0;
	}
	for (i = 0; i < max_ops(); i++) {
		op_arr[i].completed = 0;
		op_arr[i].status = 0;
		op_arr[i].mr_idx = -1;
	}
}

static ssize_t post_rma_op(int op_idx, int mr_idx)
{
	struct mr_slot *s = &slots[mr_idx];
	struct op_ctx *o = &op_arr[op_idx];

	o->mr_idx = mr_idx;

	switch (opts.rma_op) {
	case FT_RMA_WRITE:
		return fi_write(ep, s->buf, opts.transfer_size, s->desc,
				remote_fi_addr, remote_arr[mr_idx].addr,
				remote_arr[mr_idx].key, &o->context);
	case FT_RMA_WRITEDATA:
		return fi_writedata(ep, s->buf, opts.transfer_size, s->desc,
				    remote_cq_data, remote_fi_addr,
				    remote_arr[mr_idx].addr,
				    remote_arr[mr_idx].key, &o->context);
	case FT_RMA_READ:
		return fi_read(ep, s->buf, opts.transfer_size, s->desc,
			       remote_fi_addr, remote_arr[mr_idx].addr,
			       remote_arr[mr_idx].key, &o->context);
	default:
		return -FI_EINVAL;
	}
}

static ssize_t post_send_op(int op_idx, int mr_idx)
{
	struct mr_slot *s = &slots[mr_idx];
	struct op_ctx *o = &op_arr[op_idx];

	o->mr_idx = mr_idx;

	if (test_mode == TEST_TAGGED)
		return fi_tsend(ep, s->buf, opts.transfer_size, s->desc,
				remote_fi_addr, 0xCAFE, &o->context);
	else
		return fi_send(ep, s->buf, opts.transfer_size, s->desc,
			       remote_fi_addr, &o->context);
}

static ssize_t post_recv_op(int op_idx, int mr_idx)
{
	struct mr_slot *s = &slots[mr_idx];
	struct op_ctx *o = &op_arr[op_idx];

	o->mr_idx = mr_idx;

	if (test_mode == TEST_TAGGED)
		return fi_trecv(ep, s->buf, opts.transfer_size, s->desc,
				remote_fi_addr, 0xCAFE, 0, &o->context);
	else
		return fi_recv(ep, s->buf, opts.transfer_size, s->desc,
			       remote_fi_addr, &o->context);
}

static void shuffle(int *arr, int n)
{
	int i, j, tmp;

	for (i = n - 1; i > 0; i--) {
		j = rand() % (i + 1);
		tmp = arr[i];
		arr[i] = arr[j];
		arr[j] = tmp;
	}
}

static void build_cancel_order(int num_mrs)
{
	int i, tmp;

	for (i = 0; i < num_mrs; i++)
		cancel_order[i] = i;

	switch (cancel_mode) {
	case CANCEL_REVERSE:
		for (i = 0; i < num_mrs / 2; i++) {
			tmp = cancel_order[i];
			cancel_order[i] = cancel_order[num_mrs - 1 - i];
			cancel_order[num_mrs - 1 - i] = tmp;
		}
		break;
	case CANCEL_RANDOM:
		shuffle(cancel_order, num_mrs);
		break;
	}
}

static struct op_ctx *find_op_by_context(void *op_context)
{
	int i;

	for (i = 0; i < max_ops(); i++) {
		if (&op_arr[i].context == op_context)
			return &op_arr[i];
	}
	return NULL;
}

static int drain_cq(struct fid_cq *cq, int expected)
{
	struct fi_cq_tagged_entry comp;
	struct fi_cq_err_entry err;
	struct op_ctx *o;
	uint64_t deadline;
	int remaining, ret;

	remaining = expected;
	deadline = ft_gettime_ms() + CQ_TIMEOUT_MS;

	while (remaining > 0 && ft_gettime_ms() < deadline) {
		ret = fi_cq_read(cq, &comp, 1);
		if (ret > 0) {
			o = find_op_by_context(comp.op_context);
			if (o) {
				o->completed = 1;
				o->status = 0;
			}
			remaining--;
		} else if (ret == -FI_EAVAIL) {
			memset(&err, 0, sizeof(err));
			ret = fi_cq_readerr(cq, &err, 0);
			if (ret < 0 && ret != -FI_EAGAIN) {
				FT_PRINTERR("fi_cq_readerr", ret);
				return ret;
			}
			if (ret == 1) {
				o = find_op_by_context(err.op_context);
				if (o) {
					o->completed = 1;
					o->status = -err.err;
				}
				remaining--;
			}
		} else if (ret < 0 && ret != -FI_EAGAIN) {
			FT_PRINTERR("fi_cq_read", ret);
			return ret;
		}
	}

	return remaining;
}

static const char *op_str(void)
{
	switch (opts.rma_op) {
	case FT_RMA_WRITE: return "write";
	case FT_RMA_WRITEDATA: return "writedata";
	case FT_RMA_READ: return "read";
	default: return "unknown";
	}
}

static const char *cancel_str(void)
{
	return cancel_mode == CANCEL_REVERSE ? "reverse" : "random";
}

static const char *side_str(void)
{
	return close_side == CLOSE_INITIATOR ? "initiator" : "target";
}

/*
 * Test 1: Fill-and-abort
 *
 * Initiator mode: post ops until EAGAIN, then close local MRs.
 * Target mode: for each MR, client sends a 0-byte write-with-imm
 *   followed by the large write/read. Server watches for the
 *   write-with-imm completions and closes the corresponding MR
 *   immediately, racing the large transfer.
 */
static int run_fill_abort_client(int iter)
{
	int i, mr_idx, op_idx, ret;
	int total_posted, mrs_used;
	int completed_ok, completed_err, missing;
	struct fi_context2 signal_ctx;

	reset_test_state();

	total_posted = 0;
	mrs_used = 0;
	op_idx = 0;

	if (close_side == CLOSE_TARGET) {
		/*
		 * Target-close: for each MR slot, post a 0-byte
		 * write-with-imm (signal) then the large op.
		 * The imm data carries the MR index so the server
		 * knows which MR to close.
		 */
		for (mr_idx = 0; mr_idx < wq_depth; mr_idx++) {
			int posted_this_mr = 0;
			int eagain = 0;

			for (i = 0; i < ops_per_mr; i++) {
				/* Signal: 0-byte writedata with mr_idx as imm */
				ret = fi_writedata(ep, NULL, 0, NULL,
						   (uint64_t) mr_idx,
						   remote_fi_addr,
						   remote_arr[mr_idx].addr,
						   remote_arr[mr_idx].key,
						   &signal_ctx);
				if (ret == -FI_EAGAIN) {
					eagain = 1;
					break;
				}
				if (ret) {
					FT_PRINTERR("fi_writedata (signal)", ret);
					return ret;
				}
				/* Don't track signal completions — fire and forget.
				 * Drain them later along with everything else. */
				total_posted++;

				/* Large op */
				ret = post_rma_op(op_idx, mr_idx);
				if (ret == -FI_EAGAIN) {
					eagain = 1;
					break;
				}
				if (ret) {
					FT_PRINTERR("post_rma_op", ret);
					return ret;
				}
				posted_this_mr++;
				op_idx++;
				total_posted++;
			}
			if (posted_this_mr > 0) {
				slots[mr_idx].posted = posted_this_mr;
				mrs_used++;
			}
			if (eagain)
				break;
		}
	} else {
		/* Initiator-close: just fill the WQ */
		for (mr_idx = 0; mr_idx < wq_depth; mr_idx++) {
			int posted_this_mr = 0;
			int eagain = 0;

			for (i = 0; i < ops_per_mr; i++) {
				ret = post_rma_op(op_idx, mr_idx);
				if (ret == -FI_EAGAIN) {
					eagain = 1;
					break;
				}
				if (ret) {
					FT_PRINTERR("post_rma_op", ret);
					return ret;
				}
				posted_this_mr++;
				op_idx++;
				total_posted++;
			}
			if (posted_this_mr > 0) {
				slots[mr_idx].posted = posted_this_mr;
				mrs_used++;
			}
			if (eagain)
				break;
		}
	}

	if (total_posted == 0) {
		FT_ERR("could not post any operations");
		return -FI_EINVAL;
	}

	/* Phase 2: Build cancel order from MR slots that have posted ops */
	build_cancel_order(mrs_used);

	/* Phase 3: Close MRs (initiator mode only) */
	if (close_side == CLOSE_INITIATOR) {
		for (i = 0; i < mrs_used; i++) {
			int idx = cancel_order[i];

			/* Close may fail if op already completed — expected */
			fi_close(&slots[idx].mr->fid);
			slots[idx].mr = NULL;
			slots[idx].mr_closed = 1;
		}
	}

	/* Phase 4: Drain CQ */
	missing = drain_cq(txcq, total_posted);

	/* Phase 5: Report */
	completed_ok = 0;
	completed_err = 0;
	for (i = 0; i < total_posted; i++) {
		if (op_arr[i].completed) {
			if (op_arr[i].status == 0)
				completed_ok++;
			else
				completed_err++;
		}
	}

	printf("Iteration %d: op=%s size=%zu posted=%d mrs=%d "
	       "ops_per_mr=%d ok=%d err=%d missing=%d "
	       "cancel=%s side=%s ... %s\n",
	       iter, op_str(), opts.transfer_size, total_posted,
	       mrs_used, ops_per_mr, completed_ok, completed_err,
	       missing, cancel_str(), side_str(),
	       missing == 0 ? "PASS" : "FAIL");

	return missing == 0 ? 0 : -FI_EOTHER;
}

/*
 * Server side for target-close mode.
 *
 * Pre-posts receives, then polls rxcq for write-with-imm completions.
 * The imm data carries the MR index. On each completion, immediately
 * close that MR. Keeps going until all MRs are closed or timeout.
 */
static int run_fill_abort_server(void)
{
	struct fi_cq_data_entry comp;
	struct fi_cq_err_entry err;
	struct fi_context2 rx_ctxs[1];
	uint64_t deadline;
	int closed, mr_idx, ret;

	if (close_side != CLOSE_TARGET)
		return 0;

	/* Pre-post receives for the write-with-imm signals */
	ret = ft_post_rx(ep, 0, &rx_ctxs[0]);
	if (ret)
		return ret;

	closed = 0;
	deadline = ft_gettime_ms() + CQ_TIMEOUT_MS;

	while (closed < wq_depth && ft_gettime_ms() < deadline) {
		ret = fi_cq_read(rxcq, &comp, 1);
		if (ret > 0) {
			if (comp.flags & FI_REMOTE_CQ_DATA) {
				mr_idx = (int) comp.data;
				if (mr_idx >= 0 && mr_idx < wq_depth &&
				    slots[mr_idx].mr) {
					ret = fi_close(&slots[mr_idx].mr->fid);
					if (ret)
						FT_PRINTERR("fi_close(mr)", ret);
					slots[mr_idx].mr = NULL;
					slots[mr_idx].mr_closed = 1;
					closed++;
				}
			}
			/* Re-post receive for next signal */
			ret = ft_post_rx(ep, 0, &rx_ctxs[0]);
			if (ret)
				return ret;
		} else if (ret == -FI_EAVAIL) {
			memset(&err, 0, sizeof(err));
			fi_cq_readerr(rxcq, &err, 0);
			/* Errors on rx side after MR close are expected */
		} else if (ret < 0 && ret != -FI_EAGAIN) {
			FT_PRINTERR("fi_cq_read (server rx)", ret);
			return ret;
		}
	}

	printf("Server: closed %d/%d MRs\n", closed, wq_depth);
	return 0;
}

/*
 * Test 2: Partial close
 *
 * Register 2 MRs on the same buffer. Post 1 write with each MR.
 * Close only the first MR. Verify: one op errors, the other completes.
 * Only runs on the client (initiator) side.
 */
static int run_partial_close_client(void)
{
	struct mr_slot extra_slot = {0};
	struct op_ctx ops[2];
	memset(ops, 0, sizeof(ops));
	struct fi_cq_tagged_entry comp;
	struct fi_cq_err_entry err;
	uint64_t deadline;
	int completed = 0;
	int completed_ok = 0, completed_err = 0;
	int ret;

	/* Use slot 0's buffer for both MRs */
	extra_slot.buf = slots[0].buf;
	extra_slot.key = MR_ABORT_KEY_BASE + wq_depth; /* unique key */

	ret = ft_reg_mr(fi, extra_slot.buf, opts.transfer_size,
			local_access_for_op(), extra_slot.key, opts.iface,
			opts.device, &extra_slot.mr, &extra_slot.desc);
	if (ret) {
		FT_PRINTERR("ft_reg_mr (extra)", ret);
		return ret;
	}

	/* Exchange the extra key with server */
	{
		struct fi_rma_iov local_iov, remote_iov;

		local_iov.key = fi_mr_key(extra_slot.mr);
		local_iov.addr =
			(fi->domain_attr->mr_mode & FI_MR_VIRT_ADDR) ?
			(uintptr_t) extra_slot.buf : 0;
		local_iov.len = opts.transfer_size;

		ret = ft_sock_send(oob_sock, &local_iov, sizeof(local_iov));
		if (ret)
			goto close_extra;
		ret = ft_sock_recv(oob_sock, &remote_iov, sizeof(remote_iov));
		if (ret)
			goto close_extra;

		/* Post write using slot 0's MR (will be closed) */
		ops[0].mr_idx = 0;
		ret = fi_write(ep, slots[0].buf, opts.transfer_size,
			       slots[0].desc, remote_fi_addr,
			       remote_arr[0].addr, remote_arr[0].key,
			       &ops[0].context);
		if (ret) {
			FT_PRINTERR("fi_write (slot 0)", ret);
			goto close_extra;
		}

		/* Post write using extra MR (will survive) */
		ops[1].mr_idx = -1;
		ret = fi_write(ep, extra_slot.buf, opts.transfer_size,
			       extra_slot.desc, remote_fi_addr,
			       remote_iov.addr, remote_iov.key,
			       &ops[1].context);
		if (ret) {
			FT_PRINTERR("fi_write (extra)", ret);
			goto close_extra;
		}

		/* Close only slot 0's MR */
		ret = fi_close(&slots[0].mr->fid);
		if (ret)
			FT_PRINTERR("fi_close(mr)", ret);
		slots[0].mr = NULL;

		/* Drain both completions */
		deadline = ft_gettime_ms() + CQ_TIMEOUT_MS;
		while (completed < 2 && ft_gettime_ms() < deadline) {
			ret = fi_cq_read(txcq, &comp, 1);
			if (ret > 0) {
				completed++;
				completed_ok++;
			} else if (ret == -FI_EAVAIL) {
				memset(&err, 0, sizeof(err));
				ret = fi_cq_readerr(txcq, &err, 0);
				if (ret == 1) {
					completed++;
					completed_err++;
				}
			} else if (ret < 0 && ret != -FI_EAGAIN) {
				FT_PRINTERR("fi_cq_read", ret);
				break;
			}
		}

		printf("Partial close: posted=2 ok=%d err=%d missing=%d ... %s\n",
		       completed_ok, completed_err, 2 - completed,
		       (completed == 2 && completed_ok >= 1 &&
			completed_err >= 1) ? "PASS" : "FAIL");

		ret = (completed == 2 && completed_ok >= 1 &&
		       completed_err >= 1) ? 0 : -FI_EOTHER;
	}

close_extra:
	FT_CLOSE_FID(extra_slot.mr);
	return ret;
}

static int run_partial_close_server(void)
{
	struct mr_slot extra_slot = {0};
	struct fi_rma_iov local_iov, remote_iov;
	int ret;

	/* Register an extra MR for the second write target */
	extra_slot.buf = calloc(1, opts.transfer_size);
	if (!extra_slot.buf)
		return -FI_ENOMEM;
	extra_slot.key = MR_ABORT_KEY_BASE + wq_depth;

	ret = ft_reg_mr(fi, extra_slot.buf, opts.transfer_size,
			remote_access_for_op(), extra_slot.key, opts.iface,
			opts.device, &extra_slot.mr, &extra_slot.desc);
	if (ret) {
		FT_PRINTERR("ft_reg_mr (extra)", ret);
		free(extra_slot.buf);
		return ret;
	}

	/* Exchange the extra key with client */
	local_iov.key = fi_mr_key(extra_slot.mr);
	local_iov.addr = (fi->domain_attr->mr_mode & FI_MR_VIRT_ADDR) ?
		(uintptr_t) extra_slot.buf : 0;
	local_iov.len = opts.transfer_size;

	ret = ft_sock_recv(oob_sock, &remote_iov, sizeof(remote_iov));
	if (!ret)
		ret = ft_sock_send(oob_sock, &local_iov, sizeof(local_iov));

	FT_CLOSE_FID(extra_slot.mr);
	free(extra_slot.buf);
	return ret;
}

/*
 * Test 3: Endpoint reuse after abort
 *
 * Re-register MRs, do a normal write + read round-trip.
 */
static int reuse_check_client(void)
{
	struct fi_context2 reuse_ctx;
	struct fi_cq_tagged_entry comp;
	struct fi_cq_err_entry err;
	int i, ret;

	/* Drain any residual error entries from the abort test */
	do {
		ret = fi_cq_read(txcq, &comp, 1);
		if (ret == -FI_EAVAIL) {
			memset(&err, 0, sizeof(err));
			fi_cq_readerr(txcq, &err, 0);
			printf("Reuse drain: residual error %d (%s)\n",
			       err.err, fi_strerror(err.err));
		}
	} while (ret != -FI_EAGAIN);

	/* Close old MRs and re-register with both write and read access */
	for (i = 0; i < wq_depth; i++)
		FT_CLOSE_FID(slots[i].mr);

	ret = register_mrs(FI_WRITE | FI_READ);
	if (ret)
		return ret;

	ret = exchange_mr_keys();
	if (ret)
		return ret;

	/* Write */
	memset(slots[0].buf, 0xAB, opts.transfer_size);
	ret = fi_write(ep, slots[0].buf, opts.transfer_size,
		       slots[0].desc, remote_fi_addr,
		       remote_arr[0].addr, remote_arr[0].key, &reuse_ctx);
	if (ret) {
		FT_PRINTERR("fi_write (reuse)", ret);
		return ret;
	}

	do {
		ret = fi_cq_read(txcq, &comp, 1);
		if (ret == -FI_EAVAIL) {
			memset(&err, 0, sizeof(err));
			fi_cq_readerr(txcq, &err, 0);
			FT_ERR("Unexpected CQ error during reuse write:");
			FT_CQ_ERR(txcq, err, NULL, 0);
			return -err.err;
		}
	} while (ret == -FI_EAGAIN);
	if (ret < 0) {
		FT_PRINTERR("fi_cq_read (reuse write)", ret);
		return ret;
	}

	ret = ft_sync();
	if (ret)
		return ret;

	/* Read */
	memset(slots[0].buf, 0, opts.transfer_size);
	ret = fi_read(ep, slots[0].buf, opts.transfer_size,
		      slots[0].desc, remote_fi_addr,
		      remote_arr[0].addr, remote_arr[0].key, &reuse_ctx);
	if (ret) {
		FT_PRINTERR("fi_read (reuse)", ret);
		return ret;
	}

	do {
		ret = fi_cq_read(txcq, &comp, 1);
		if (ret == -FI_EAVAIL) {
			memset(&err, 0, sizeof(err));
			fi_cq_readerr(txcq, &err, 0);
			FT_ERR("Unexpected CQ error during reuse read:");
			FT_CQ_ERR(txcq, err, NULL, 0);
			return -err.err;
		}
	} while (ret == -FI_EAGAIN);
	if (ret < 0) {
		FT_PRINTERR("fi_cq_read (reuse read)", ret);
		return ret;
	}

	printf("Reuse: write ok, read ok ... PASS\n");
	return 0;
}

static int reuse_check_server(void)
{
	int i, ret;

	/* Close existing MRs and re-register with both read+write access */
	for (i = 0; i < wq_depth; i++)
		FT_CLOSE_FID(slots[i].mr);

	ret = register_mrs(FI_REMOTE_WRITE | FI_REMOTE_READ);
	if (ret)
		return ret;

	ret = exchange_mr_keys();
	if (ret)
		return ret;

	/* Sync after client's write */
	ret = ft_sync();
	if (ret)
		return ret;

	/* Client does read, no sync needed — server just keeps MRs alive */
	return 0;
}

/*
 * Test 4: Send/Tagged abort
 *
 * Client fills TX queue with fi_send/fi_tsend, then closes sender MRs.
 * Server pre-posts fi_recv/fi_trecv. If target-close, server closes
 * its recv MRs instead.
 */
static int run_send_abort_client(int iter)
{
	int i, mr_idx, op_idx, ret;
	int total_posted, mrs_used;
	int completed_ok, completed_err, missing;
	const char *mode_str = (test_mode == TEST_TAGGED) ? "tagged" : "send";

	reset_test_state();

	total_posted = 0;
	mrs_used = 0;
	op_idx = 0;

	/* Sync so server has recvs posted before we start sending */
	ret = ft_sync();
	if (ret)
		return ret;

	/* Fill TX queue with sends */
	for (mr_idx = 0; mr_idx < wq_depth; mr_idx++) {
		int posted_this_mr = 0;
		int eagain = 0;

		for (i = 0; i < ops_per_mr; i++) {
			ret = post_send_op(op_idx, mr_idx);
			if (ret == -FI_EAGAIN) {
				eagain = 1;
				break;
			}
			if (ret) {
				FT_PRINTERR("post_send_op", ret);
				return ret;
			}
			posted_this_mr++;
			op_idx++;
			total_posted++;
		}
		if (posted_this_mr > 0) {
			slots[mr_idx].posted = posted_this_mr;
			mrs_used++;
		}
		if (eagain)
			break;
	}

	if (total_posted == 0) {
		FT_ERR("could not post any send operations");
		return -FI_EINVAL;
	}

	/* Close sender MRs (initiator mode) */
	if (close_side == CLOSE_INITIATOR) {
		build_cancel_order(mrs_used);
		for (i = 0; i < mrs_used; i++) {
			int idx = cancel_order[i];

			ret = fi_close(&slots[idx].mr->fid);
			if (ret)
				FT_PRINTERR("fi_close(mr)", ret);
			slots[idx].mr = NULL;
			slots[idx].mr_closed = 1;
		}
	}

	/* Drain TX CQ */
	missing = drain_cq(txcq, total_posted);

	completed_ok = 0;
	completed_err = 0;
	for (i = 0; i < total_posted; i++) {
		if (op_arr[i].completed) {
			if (op_arr[i].status == 0)
				completed_ok++;
			else
				completed_err++;
		}
	}

	printf("Iteration %d: mode=%s size=%zu posted=%d mrs=%d "
	       "ok=%d err=%d missing=%d side=%s ... %s\n",
	       iter, mode_str, opts.transfer_size, total_posted,
	       mrs_used, completed_ok, completed_err,
	       missing, side_str(),
	       missing == 0 ? "PASS" : "FAIL");

	return missing == 0 ? 0 : -FI_EOTHER;
}

static int run_send_abort_server(int iter)
{
	int i, mr_idx, op_idx, ret;
	int total_posted, mrs_used;
	int missing;

	reset_test_state();

	total_posted = 0;
	mrs_used = 0;
	op_idx = 0;

	/* Pre-post receives */
	for (mr_idx = 0; mr_idx < wq_depth; mr_idx++) {
		int posted_this_mr = 0;

		for (i = 0; i < ops_per_mr; i++) {
			ret = post_recv_op(op_idx, mr_idx);
			if (ret) {
				FT_PRINTERR("post_recv_op", ret);
				return ret;
			}
			posted_this_mr++;
			op_idx++;
			total_posted++;
		}
		if (posted_this_mr > 0) {
			slots[mr_idx].posted = posted_this_mr;
			mrs_used++;
		}
	}

	/* Sync to let client start sending */
	ret = ft_sync();
	if (ret)
		return ret;

	/* Close recv MRs (target mode) */
	if (close_side == CLOSE_TARGET) {
		build_cancel_order(mrs_used);
		for (i = 0; i < mrs_used; i++) {
			int idx = cancel_order[i];

			ret = fi_close(&slots[idx].mr->fid);
			if (ret)
				FT_PRINTERR("fi_close(mr)", ret);
			slots[idx].mr = NULL;
			slots[idx].mr_closed = 1;
		}
	}

	/* Drain RX CQ — expect mix of success and errors */
	missing = drain_cq(rxcq, total_posted);

	printf("Server iter %d: recvs=%d missing=%d ... %s\n",
	       iter, total_posted, missing,
	       missing == 0 ? "PASS" : "FAIL");

	return missing == 0 ? 0 : -FI_EOTHER;
}

/*
 * Top-level client and server flows.
 */
static int run_client(void)
{
	int i, ret;

	switch (test_mode) {
	case TEST_ABORT:
		ret = register_mrs(local_access_for_op());
		if (ret)
			return ret;

		ret = exchange_mr_keys();
		if (ret)
			return ret;

		for (i = 0; i < opts.iterations; i++) {
			ret = run_fill_abort_client(i + 1);
			if (ret)
				return ret;

			ret = ft_sync();
			if (ret)
				return ret;

			if (i < opts.iterations - 1) {
				ret = register_mrs(local_access_for_op());
				if (ret)
					return ret;

				ret = exchange_mr_keys();
				if (ret)
					return ret;
			}
		}
		break;

	case TEST_PARTIAL:
		ret = register_mrs(local_access_for_op());
		if (ret)
			return ret;

		ret = exchange_mr_keys();
		if (ret)
			return ret;

		for (i = 0; i < opts.iterations; i++) {
			ret = run_partial_close_client();
			if (ret)
				return ret;

			ret = ft_sync();
			if (ret)
				return ret;

			if (i < opts.iterations - 1) {
				ret = register_mrs(local_access_for_op());
				if (ret)
					return ret;

				ret = exchange_mr_keys();
				if (ret)
					return ret;
			}
		}
		break;

	case TEST_SEND:
	case TEST_TAGGED:
		ret = register_mrs(FI_SEND);
		if (ret)
			return ret;

		for (i = 0; i < opts.iterations; i++) {
			ret = run_send_abort_client(i + 1);
			if (ret)
				return ret;

			ret = ft_sync();
			if (ret)
				return ret;

			if (i < opts.iterations - 1) {
				ret = register_mrs(FI_SEND);
				if (ret)
					return ret;
			}
		}
		break;
	}

	/* Endpoint reuse check */
	ret = reuse_check_client();
	if (ret)
		return ret;

	return ft_sync();
}

static int run_server(void)
{
	int i, ret;

	switch (test_mode) {
	case TEST_ABORT:
		ret = register_mrs(remote_access_for_op());
		if (ret)
			return ret;

		ret = exchange_mr_keys();
		if (ret)
			return ret;

		for (i = 0; i < opts.iterations; i++) {
			ret = run_fill_abort_server();
			if (ret)
				return ret;

			ret = ft_sync();
			if (ret)
				return ret;

			if (i < opts.iterations - 1) {
				ret = register_mrs(remote_access_for_op());
				if (ret)
					return ret;

				ret = exchange_mr_keys();
				if (ret)
					return ret;
			}
		}
		break;

	case TEST_PARTIAL:
		ret = register_mrs(remote_access_for_op());
		if (ret)
			return ret;

		ret = exchange_mr_keys();
		if (ret)
			return ret;

		for (i = 0; i < opts.iterations; i++) {
			ret = run_partial_close_server();
			if (ret)
				return ret;

			ret = ft_sync();
			if (ret)
				return ret;

			if (i < opts.iterations - 1) {
				ret = register_mrs(remote_access_for_op());
				if (ret)
					return ret;

				ret = exchange_mr_keys();
				if (ret)
					return ret;
			}
		}
		break;

	case TEST_SEND:
	case TEST_TAGGED:
		ret = register_mrs(FI_RECV);
		if (ret)
			return ret;

		for (i = 0; i < opts.iterations; i++) {
			ret = run_send_abort_server(i + 1);
			if (ret)
				return ret;

			ret = ft_sync();
			if (ret)
				return ret;

			if (i < opts.iterations - 1) {
				ret = register_mrs(FI_RECV);
				if (ret)
					return ret;
			}
		}
		break;
	}

	/* Endpoint reuse check */
	ret = reuse_check_server();
	if (ret)
		return ret;

	return ft_sync();
}

static int run(void)
{
	int ret;

	/* Target-close needs CQ data format for write-with-imm */
	if (close_side == CLOSE_TARGET)
		cq_attr.format = FI_CQ_FORMAT_DATA;

	if (hints->ep_attr->type == FI_EP_MSG)
		ret = ft_init_fabric_cm();
	else
		ret = ft_init_fabric();
	if (ret)
		return ret;

	ret = alloc_test_res();
	if (ret)
		return ret;

	if (opts.dst_addr)
		ret = run_client();
	else
		ret = run_server();

	free_test_res();
	ft_finalize();
	return ret;
}

int main(int argc, char **argv)
{
	int op, ret;

	opts = INIT_OPTS;
	opts.options |= FT_OPT_OOB_SYNC | FT_OPT_SKIP_MSG_ALLOC | FT_OPT_SIZE;
	opts.transfer_size = 4096; /* 4KB default — override with -S */
	opts.iterations = 10;

	hints = fi_allocinfo();
	if (!hints)
		return EXIT_FAILURE;

	srand(time(NULL));

	while ((op = getopt(argc, argv,
			    "W:N:C:R:T:h" CS_OPTS INFO_OPTS API_OPTS)) != -1) {
		switch (op) {
		case 'W':
			wq_depth = atoi(optarg);
			break;
		case 'N':
			ops_per_mr = atoi(optarg);
			break;
		case 'C':
			if (!strcmp(optarg, "reverse"))
				cancel_mode = CANCEL_REVERSE;
			else if (!strcmp(optarg, "random"))
				cancel_mode = CANCEL_RANDOM;
			else {
				FT_ERR("Unknown cancel mode: %s", optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'R':
			if (!strcmp(optarg, "initiator"))
				close_side = CLOSE_INITIATOR;
			else if (!strcmp(optarg, "target"))
				close_side = CLOSE_TARGET;
			else {
				FT_ERR("Unknown close side: %s", optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'T':
			if (!strcmp(optarg, "abort"))
				test_mode = TEST_ABORT;
			else if (!strcmp(optarg, "partial"))
				test_mode = TEST_PARTIAL;
			else if (!strcmp(optarg, "send"))
				test_mode = TEST_SEND;
			else if (!strcmp(optarg, "tagged"))
				test_mode = TEST_TAGGED;
			else {
				FT_ERR("Unknown test mode: %s", optarg);
				return EXIT_FAILURE;
			}
			break;
		default:
			ft_parseinfo(op, optarg, hints, &opts);
			ft_parsecsopts(op, optarg, &opts);
			ret = ft_parse_api_opts(op, optarg, hints, &opts);
			if (ret)
				return ret;
			break;
		case '?':
		case 'h':
			ft_csusage(argv[0],
				"Test aborting in-flight operations by "
				"closing MRs.");
			FT_PRINT_OPTS_USAGE("-T <test>",
				"Test mode: abort|partial|send|tagged "
				"(default: abort)");
			FT_PRINT_OPTS_USAGE("-o <op>",
				"RMA op: write|read|writedata "
				"(default: write)");
			FT_PRINT_OPTS_USAGE("-W <count>",
				"Number of MR/buffer pairs "
				"(default: 128)");
			FT_PRINT_OPTS_USAGE("-N <count>",
				"Operations per MR before close "
				"(default: 1)");
			FT_PRINT_OPTS_USAGE("-C <mode>",
				"MR cancel order: reverse|random "
				"(default: reverse)");
			FT_PRINT_OPTS_USAGE("-R <side>",
				"Which side closes MRs: "
				"initiator|target (default: initiator)");
			return EXIT_FAILURE;
		}
	}

	if (optind < argc)
		opts.dst_addr = argv[optind];

	hints->caps = FI_MSG;
	switch (test_mode) {
	case TEST_ABORT:
	case TEST_PARTIAL:
		hints->caps |= FI_RMA;
		if (opts.rma_op == FT_RMA_WRITEDATA || close_side == CLOSE_TARGET)
			hints->caps |= FI_RMA_EVENT;
		break;
	case TEST_TAGGED:
		hints->caps |= FI_TAGGED;
		break;
	case TEST_SEND:
		break;
	}
	hints->mode = FI_CONTEXT | FI_CONTEXT2;
	hints->domain_attr->mr_mode = opts.mr_mode;
	hints->domain_attr->resource_mgmt = FI_RM_ENABLED;
	hints->addr_format = opts.address_format;

	ret = run();

	ft_free_res();
	return ft_exit_code(ret);
}

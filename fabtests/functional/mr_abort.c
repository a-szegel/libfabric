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
 * Test aborting in-flight RMA operations by closing local MRs.
 *
 * Workflow:
 *   1. Allocate W MR/buffer pairs (1 MR per operation)
 *   2. Post fi_write/fi_read/fi_writedata until TX WQ returns -FI_EAGAIN
 *   3. Build cancel order array from posted operations (reverse or random)
 *   4. Close all posted MRs as fast as possible
 *   5. Drain CQ — every posted op must produce a completion (success or error)
 *   6. Re-register MRs, repeat for I iterations
 *   7. Verify endpoint is still usable with a normal write+read round-trip
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

#include <rdma/fi_errno.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_cm.h>

#include "shared.h"

enum cancel_mode {
	CANCEL_REVERSE,
	CANCEL_RANDOM,
};

struct mr_abort_ctx {
	char *buf;
	struct fid_mr *mr;
	void *desc;
	uint64_t key;
	struct fi_context2 context;
	int posted;
	int mr_closed;
	int completed;
	int status;
};

static struct mr_abort_ctx *ctx_arr;
static int *cancel_order;
static int wq_depth = 128;
static enum cancel_mode cancel_mode = CANCEL_REVERSE;

/* Remote side MR info — exchanged over OOB */
static struct fi_rma_iov *remote_arr;

/* Key base offset to avoid colliding with the shared.c default MR keys */
#define MR_ABORT_KEY_BASE 0x1000

static uint64_t mr_access_for_op(void)
{
	switch (opts.rma_op) {
	case FT_RMA_WRITE:
	case FT_RMA_WRITEDATA:
		return FI_WRITE;
	case FT_RMA_READ:
		return FI_READ;
	default:
		return FI_WRITE | FI_READ;
	}
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

static int alloc_ctx_arr(void)
{
	int i;

	ctx_arr = calloc(wq_depth, sizeof(*ctx_arr));
	if (!ctx_arr)
		return -FI_ENOMEM;

	cancel_order = calloc(wq_depth, sizeof(*cancel_order));
	if (!cancel_order)
		return -FI_ENOMEM;

	remote_arr = calloc(wq_depth, sizeof(*remote_arr));
	if (!remote_arr)
		return -FI_ENOMEM;

	for (i = 0; i < wq_depth; i++) {
		ctx_arr[i].buf = calloc(1, opts.transfer_size);
		if (!ctx_arr[i].buf)
			return -FI_ENOMEM;
		ctx_arr[i].key = MR_ABORT_KEY_BASE + i;
	}

	return 0;
}

static void free_ctx_arr(void)
{
	int i;

	if (ctx_arr) {
		for (i = 0; i < wq_depth; i++) {
			FT_CLOSE_FID(ctx_arr[i].mr);
			free(ctx_arr[i].buf);
		}
		free(ctx_arr);
		ctx_arr = NULL;
	}
	free(cancel_order);
	cancel_order = NULL;
	free(remote_arr);
	remote_arr = NULL;
}

static int register_mrs(uint64_t access)
{
	int i, ret;

	if (fi->domain_attr->mr_mode & FI_MR_LOCAL)
		access |= FI_READ | FI_WRITE;

	for (i = 0; i < wq_depth; i++) {
		if (ctx_arr[i].mr)
			continue;

		ret = ft_reg_mr(fi, ctx_arr[i].buf, opts.transfer_size,
				access, ctx_arr[i].key, opts.iface,
				opts.device, &ctx_arr[i].mr, &ctx_arr[i].desc);
		if (ret) {
			FT_PRINTERR("ft_reg_mr", ret);
			return ret;
		}
	}
	return 0;
}

/*
 * Exchange per-MR keys over OOB socket.
 * Both sides send their key + address info, receive the peer's.
 */
static int exchange_mr_keys(void)
{
	struct fi_rma_iov *local_info;
	int i, ret;

	local_info = calloc(wq_depth, sizeof(*local_info));
	if (!local_info)
		return -FI_ENOMEM;

	for (i = 0; i < wq_depth; i++) {
		local_info[i].key = fi_mr_key(ctx_arr[i].mr);
		local_info[i].addr = (fi->domain_attr->mr_mode & FI_MR_VIRT_ADDR) ?
			(uintptr_t) ctx_arr[i].buf : 0;
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

static void reset_ctx_arr(void)
{
	int i;

	for (i = 0; i < wq_depth; i++) {
		ctx_arr[i].posted = 0;
		ctx_arr[i].mr_closed = 0;
		ctx_arr[i].completed = 0;
		ctx_arr[i].status = 0;
	}
}

static ssize_t post_rma_op(int idx)
{
	struct mr_abort_ctx *c = &ctx_arr[idx];

	switch (opts.rma_op) {
	case FT_RMA_WRITE:
		return fi_write(ep, c->buf, opts.transfer_size, c->desc,
				remote_fi_addr, remote_arr[idx].addr,
				remote_arr[idx].key, &c->context);
	case FT_RMA_WRITEDATA:
		return fi_writedata(ep, c->buf, opts.transfer_size, c->desc,
				    remote_cq_data, remote_fi_addr,
				    remote_arr[idx].addr, remote_arr[idx].key,
				    &c->context);
	case FT_RMA_READ:
		return fi_read(ep, c->buf, opts.transfer_size, c->desc,
			       remote_fi_addr, remote_arr[idx].addr,
			       remote_arr[idx].key, &c->context);
	default:
		return -FI_EINVAL;
	}
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

static void build_cancel_order(int posted)
{
	int i, tmp;

	for (i = 0; i < posted; i++)
		cancel_order[i] = i;

	switch (cancel_mode) {
	case CANCEL_REVERSE:
		for (i = 0; i < posted / 2; i++) {
			tmp = cancel_order[i];
			cancel_order[i] = cancel_order[posted - 1 - i];
			cancel_order[posted - 1 - i] = tmp;
		}
		break;
	case CANCEL_RANDOM:
		shuffle(cancel_order, posted);
		break;
	}
}

static struct mr_abort_ctx *find_ctx_by_context(void *op_context)
{
	int i;

	for (i = 0; i < wq_depth; i++) {
		if (&ctx_arr[i].context == op_context)
			return &ctx_arr[i];
	}
	return NULL;
}

static int drain_cq(int posted)
{
	struct fi_cq_tagged_entry comp;
	struct fi_cq_err_entry err;
	struct mr_abort_ctx *c;
	uint64_t deadline;
	int remaining, ret;

	remaining = posted;
	deadline = ft_gettime_ms() + 30000; /* 30 second timeout */

	while (remaining > 0 && ft_gettime_ms() < deadline) {
		ret = fi_cq_read(txcq, &comp, 1);
		if (ret > 0) {
			c = find_ctx_by_context(comp.op_context);
			if (c) {
				c->completed = 1;
				c->status = 0;
				remaining--;
			}
		} else if (ret == -FI_EAVAIL) {
			memset(&err, 0, sizeof(err));
			ret = fi_cq_readerr(txcq, &err, 0);
			if (ret < 0 && ret != -FI_EAGAIN) {
				FT_PRINTERR("fi_cq_readerr", ret);
				return ret;
			}
			if (ret == 1) {
				c = find_ctx_by_context(err.op_context);
				if (c) {
					c->completed = 1;
					c->status = -err.err;
					remaining--;
				}
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

static int run_abort_iteration(int iter)
{
	int i, idx, posted, ret;
	int completed_ok, completed_err, missing;

	reset_ctx_arr();

	/* Phase 1: Fill TX WQ */
	posted = 0;
	for (i = 0; i < wq_depth; i++) {
		ret = post_rma_op(i);
		if (ret == -FI_EAGAIN)
			break;
		if (ret) {
			FT_PRINTERR("post_rma_op", ret);
			return ret;
		}
		ctx_arr[i].posted = 1;
		posted++;
	}

	if (posted == 0) {
		FT_ERR("could not post any operations");
		return -FI_EINVAL;
	}

	/* Phase 2: Build cancel order from posted operations */
	build_cancel_order(posted);

	/* Phase 3: Close MRs as fast as possible */
	for (i = 0; i < posted; i++) {
		idx = cancel_order[i];
		ret = fi_close(&ctx_arr[idx].mr->fid);
		if (ret)
			FT_PRINTERR("fi_close(mr)", ret);
		ctx_arr[idx].mr = NULL;
		ctx_arr[idx].mr_closed = 1;
	}

	/* Phase 4: Drain CQ */
	missing = drain_cq(posted);

	/* Phase 5: Report */
	completed_ok = 0;
	completed_err = 0;
	for (i = 0; i < posted; i++) {
		if (ctx_arr[i].completed) {
			if (ctx_arr[i].status == 0)
				completed_ok++;
			else
				completed_err++;
		}
	}

	printf("Iteration %d: op=%s size=%zu posted=%d ok=%d err=%d "
	       "missing=%d cancel=%s ... %s\n",
	       iter, op_str(), opts.transfer_size, posted,
	       completed_ok, completed_err, missing, cancel_str(),
	       missing == 0 ? "PASS" : "FAIL");

	return missing == 0 ? 0 : -FI_EOTHER;
}

static int reuse_check(void)
{
	struct fi_context2 reuse_ctx;
	struct fi_cq_tagged_entry comp;
	int ret;

	/* Re-register MRs for the reuse test */
	ret = register_mrs(mr_access_for_op());
	if (ret)
		return ret;

	ret = exchange_mr_keys();
	if (ret)
		return ret;

	/* Write test */
	memset(ctx_arr[0].buf, 0xAB, opts.transfer_size);
	ret = fi_write(ep, ctx_arr[0].buf, opts.transfer_size,
		       ctx_arr[0].desc, remote_fi_addr,
		       remote_arr[0].addr, remote_arr[0].key, &reuse_ctx);
	if (ret) {
		FT_PRINTERR("fi_write (reuse)", ret);
		return ret;
	}

	do {
		ret = fi_cq_sread(txcq, &comp, 1, NULL, 30000);
	} while (ret == -FI_EAGAIN);

	if (ret < 0) {
		FT_PRINTERR("fi_cq_sread (reuse write)", ret);
		return ret;
	}

	ret = ft_sync();
	if (ret)
		return ret;

	/* Read test */
	memset(ctx_arr[0].buf, 0, opts.transfer_size);
	ret = fi_read(ep, ctx_arr[0].buf, opts.transfer_size,
		      ctx_arr[0].desc, remote_fi_addr,
		      remote_arr[0].addr, remote_arr[0].key, &reuse_ctx);
	if (ret) {
		FT_PRINTERR("fi_read (reuse)", ret);
		return ret;
	}

	do {
		ret = fi_cq_sread(txcq, &comp, 1, NULL, 30000);
	} while (ret == -FI_EAGAIN);

	if (ret < 0) {
		FT_PRINTERR("fi_cq_sread (reuse read)", ret);
		return ret;
	}

	printf("Reuse: write ok, read ok ... PASS\n");
	return 0;
}

static int run_client(void)
{
	int i, ret;

	ret = register_mrs(mr_access_for_op());
	if (ret)
		return ret;

	ret = exchange_mr_keys();
	if (ret)
		return ret;

	for (i = 0; i < opts.iterations; i++) {
		ret = run_abort_iteration(i + 1);
		if (ret)
			return ret;

		/* Sync with server between iterations */
		ret = ft_sync();
		if (ret)
			return ret;

		/* Re-register closed MRs for next iteration */
		if (i < opts.iterations - 1) {
			ret = register_mrs(mr_access_for_op());
			if (ret)
				return ret;

			ret = exchange_mr_keys();
			if (ret)
				return ret;
		}
	}

	/* Endpoint reuse check */
	ret = reuse_check();
	if (ret)
		return ret;

	return ft_sync();
}

static int run_server(void)
{
	int i, ret;

	ret = register_mrs(remote_access_for_op());
	if (ret)
		return ret;

	ret = exchange_mr_keys();
	if (ret)
		return ret;

	for (i = 0; i < opts.iterations; i++) {
		/* Wait for client to finish abort iteration */
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

	/* Reuse check: re-register and exchange keys */
	ret = register_mrs(remote_access_for_op());
	if (ret)
		return ret;

	ret = exchange_mr_keys();
	if (ret)
		return ret;

	/* Sync after client's write */
	ret = ft_sync();
	if (ret)
		return ret;

	/* Sync after client's read */
	return ft_sync();
}

static int run(void)
{
	int ret;

	if (hints->ep_attr->type == FI_EP_MSG)
		ret = ft_init_fabric_cm();
	else
		ret = ft_init_fabric();
	if (ret)
		return ret;

	ret = alloc_ctx_arr();
	if (ret)
		return ret;

	if (opts.dst_addr)
		ret = run_client();
	else
		ret = run_server();

	free_ctx_arr();
	ft_finalize();
	return ret;
}

int main(int argc, char **argv)
{
	int op, ret;

	opts = INIT_OPTS;
	opts.options |= FT_OPT_OOB_SYNC | FT_OPT_SKIP_MSG_ALLOC | FT_OPT_SIZE;
	opts.transfer_size = 1024 * 1024; /* 1MB default */
	opts.iterations = 1;

	hints = fi_allocinfo();
	if (!hints)
		return EXIT_FAILURE;

	srand(time(NULL));

	while ((op = getopt(argc, argv, "W:C:h" CS_OPTS INFO_OPTS API_OPTS)) != -1) {
		switch (op) {
		case 'W':
			wq_depth = atoi(optarg);
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
				"Test aborting in-flight RMA operations by "
				"closing local MRs.");
			FT_PRINT_OPTS_USAGE("-o <op>",
				"RMA op: write|read|writedata (default: write)");
			FT_PRINT_OPTS_USAGE("-W <count>",
				"Number of MR/buffer pairs to allocate "
				"(default: 128)");
			FT_PRINT_OPTS_USAGE("-C <mode>",
				"MR cancel order: reverse|random "
				"(default: reverse)");
			return EXIT_FAILURE;
		}
	}

	if (optind < argc)
		opts.dst_addr = argv[optind];

	hints->caps = FI_MSG | FI_RMA;
	if (opts.rma_op == FT_RMA_WRITEDATA)
		hints->caps |= FI_RMA_EVENT;
	hints->mode = FI_CONTEXT | FI_CONTEXT2;
	hints->domain_attr->mr_mode = opts.mr_mode;
	hints->domain_attr->resource_mgmt = FI_RM_ENABLED;
	hints->addr_format = opts.address_format;

	ret = run();

	ft_free_res();
	return ft_exit_code(ret);
}

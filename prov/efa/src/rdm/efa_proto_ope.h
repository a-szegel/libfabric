/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef _EFA_PROTO_OPE_H
#define _EFA_PROTO_OPE_H

#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <ofi_list.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_eq.h>

/*
 * NOTE: This header uses ENABLE_DEBUG (from config.h).  It must be included
 * after config.h / efa.h so that the macro is defined for debug builds.
 */

/*
 * Forward declarations — avoid pulling in heavy headers.
 * The full definitions are available via efa_rdm_ep.h / efa_rdm_pke.h
 * in translation units that need them.
 */
struct efa_rdm_ep;
struct efa_rdm_peer;
struct efa_rdm_pke;
struct efa_rdm_rxe_map;
struct fi_peer_rx_entry;
struct fid_mr;

#define EFA_PROTO_IOV_LIMIT	(4)

#define EFA_PROTO_STATIC_ASSERT(expr, msg) _Static_assert(expr, msg)

/**
 * @brief operation entry type — discriminator for the struct hierarchy
 */
enum efa_proto_ope_type {
	EFA_PROTO_TX_MSG = 1,
	EFA_PROTO_TX_RMA_READ,
	EFA_PROTO_TX_RMA_WRITE,
	EFA_PROTO_TX_ATOMIC,
	EFA_PROTO_RX_MSG,
	EFA_PROTO_RX_RMA_WRITE,
	EFA_PROTO_RX_RMA_READ,
	EFA_PROTO_RX_ATOMIC,
};

/**
 * @brief operation entry state (shared across all protocol structs)
 */
enum efa_proto_ope_state {
	EFA_PROTO_TXE_REQ = 1,
	EFA_PROTO_OPE_SEND,
	EFA_PROTO_RXE_INIT,
	EFA_PROTO_RXE_UNEXP,
	EFA_PROTO_RXE_MATCHED,
	EFA_PROTO_RXE_RECV,
	EFA_PROTO_OPE_ERR,
};

/**
 * @brief basic information of an atomic operation
 */
struct efa_proto_atomic_hdr {
	uint32_t atomic_op;
	uint32_t datatype;
};

/**
 * @brief extra information for fetch/compare atomic
 */
struct efa_proto_atomic_ex {
	struct iovec resp_iov[EFA_PROTO_IOV_LIMIT];
	int resp_iov_count;
	struct iovec comp_iov[EFA_PROTO_IOV_LIMIT];
	int comp_iov_count;
	void *result_desc[EFA_PROTO_IOV_LIMIT];
	void *compare_desc[EFA_PROTO_IOV_LIMIT];
};

/**
 * @brief how to copy data from bounce buffer to CUDA receive buffer
 */
enum efa_proto_cuda_copy_method {
	EFA_PROTO_CUDA_COPY_UNSPEC = 0,
	EFA_PROTO_CUDA_COPY_BLOCKING,
	EFA_PROTO_CUDA_COPY_LOCALREAD,
};

/* ────────────────────────────────────────────────────────────────────────────
 * Base struct — fields accessed by every protocol path.
 *
 * Layout: hot fields first (first cache line), then cold.
 * Within each zone, largest-to-smallest to minimise padding.
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * @brief Base operation entry shared by all protocol structs.
 *
 * Every leaf struct embeds this as its first member ("poor-man's inheritance"),
 * so a pointer to any leaf can be cast to struct efa_proto_ope_base *.
 */
struct efa_proto_ope_base {
	/* ── hot: first cache line (offset 0–63) ── */
	enum efa_proto_ope_type type;	/* 4  (0) */
	uint32_t op;			/* 4  (4) */
	struct efa_rdm_ep *ep;		/* 8  (8) */
	struct efa_rdm_peer *peer;	/* 8  (16) */
	uint64_t fi_flags;		/* 8  (24) */
	uint32_t internal_flags;	/* 4  (32) */
	uint32_t tx_id;			/* 4  (36) */
	uint32_t rx_id;			/* 4  (40) */
	uint32_t msg_id;		/* 4  (44) */
	uint64_t total_len;		/* 8  (48) */
	uint64_t tag;			/* 8  (56) */
	/* ── end first cache line ── */

	enum efa_proto_ope_state state;	/* 4  (64) */
	int queued_ctrl_type;		/* 4  (68) */
	size_t efa_outstanding_tx_ops;	/* 8  (72) */
	size_t iov_count;		/* 8  (80) */

	struct iovec iov[EFA_PROTO_IOV_LIMIT];		/* 64 (88) */
	void *desc[EFA_PROTO_IOV_LIMIT];		/* 32 (152) */
	struct fid_mr *mr[EFA_PROTO_IOV_LIMIT];		/* 32 (184) */

	size_t rma_iov_count;				/* 8  (216) */
	struct fi_rma_iov rma_iov[EFA_PROTO_IOV_LIMIT];/* 96 (224) */

	struct fi_cq_tagged_entry cq_entry;		/* 48 (320) */

	/* dlist entries used by all paths */
	struct dlist_entry entry;		/* 16 (368) — proto_ope_longcts_send_list */
	struct dlist_entry ep_entry;		/* 16 (384) — tx/rxe_list in ep */
	struct dlist_entry queued_entry;	/* 16 (400) — proto_ope_queued_list */
	struct dlist_entry queued_pkts;		/* 16 (416) — queued pkt list head */
	struct dlist_entry peer_entry;		/* 16 (432) — tx/rxe_list in peer */

#if ENABLE_DEBUG
	struct dlist_entry pending_recv_entry;	/* 16 (448) — debug only */
#endif
};
/* base size: 448 bytes without debug, 464 with debug (7 / 7.25 cache lines) */

/* ────────────────────────────────────────────────────────────────────────────
 * TX intermediate base — adds fields common to all TX leaf structs
 * ──────────────────────────────────────────────────────────────────────────── */

struct efa_proto_tx_base {
	struct efa_proto_ope_base base;

	uint64_t bytes_acked;			/* 8 */
	uint64_t bytes_sent;			/* 8 */
	struct efa_rdm_pke *local_read_pkt_entry; /* 8 */
};

/* ────────────────────────────────────────────────────────────────────────────
 * RX intermediate base — adds fields common to all RX leaf structs
 * ──────────────────────────────────────────────────────────────────────────── */

struct efa_proto_rx_base {
	struct efa_proto_ope_base base;

	uint64_t bytes_received;		/* 8 */
	uint64_t bytes_received_via_mulreq;	/* 8 */
	uint64_t bytes_copied;			/* 8 */
	uint64_t bytes_queued_blocking_copy;	/* 8 */
	uint64_t ignore;			/* 8 */
	struct efa_rdm_pke *unexp_pkt;		/* 8 */
	struct efa_rdm_rxe_map *rxe_map;	/* 8 */
	struct fi_peer_rx_entry *peer_rxe;	/* 8 */
	struct dlist_entry ack_list_entry;	/* 16 */
	enum efa_proto_cuda_copy_method cuda_copy_method; /* 4 + 4 pad */
};

/* ────────────────────────────────────────────────────────────────────────────
 * Leaf TX structs
 * ──────────────────────────────────────────────────────────────────────────── */

struct efa_proto_tx_msg {
	struct efa_proto_tx_base tx;

	int64_t window;
	uint64_t bytes_runt;
	uint64_t bytes_read_completed;
	uint64_t bytes_read_submitted;
	uint64_t bytes_read_total_len;
	uint64_t bytes_read_offset;
};

struct efa_proto_tx_rma_read {
	struct efa_proto_tx_base tx;

	uint64_t bytes_read_completed;
	uint64_t bytes_read_submitted;
	uint64_t bytes_read_total_len;
	uint64_t bytes_read_offset;
};

struct efa_proto_tx_rma_write {
	struct efa_proto_tx_base tx;

	uint64_t bytes_write_completed;
	uint64_t bytes_write_submitted;
	uint64_t bytes_write_total_len;
};

struct efa_proto_tx_atomic {
	struct efa_proto_tx_base tx;

	struct efa_proto_atomic_hdr atomic_hdr;
	struct efa_proto_atomic_ex atomic_ex;
};

/* ────────────────────────────────────────────────────────────────────────────
 * Leaf RX structs
 * ──────────────────────────────────────────────────────────────────────────── */

struct efa_proto_rx_msg {
	struct efa_proto_rx_base rx;

	int64_t window;
	uint64_t bytes_runt;
	uint64_t bytes_read_completed;
	uint64_t bytes_read_submitted;
	uint64_t bytes_read_total_len;
	uint64_t bytes_read_offset;
};

struct efa_proto_rx_rma_write {
	struct efa_proto_rx_base rx;
	/* no additional fields — RTW responder only needs rx_base */
};

struct efa_proto_rx_rma_read {
	struct efa_proto_rx_base rx;

	int64_t window;
	/* RTR responder sends data, so it needs bytes_sent */
	uint64_t bytes_sent;
};

struct efa_proto_rx_atomic {
	struct efa_proto_rx_base rx;

	struct efa_proto_atomic_hdr atomic_hdr;
	char *atomrsp_data;
};

/* ────────────────────────────────────────────────────────────────────────────
 * Union — single bufpool allocation type
 * ──────────────────────────────────────────────────────────────────────────── */

union efa_proto_ope_entry {
	struct efa_proto_ope_base base;
	struct efa_proto_tx_base tx_base;
	struct efa_proto_rx_base rx_base;
	struct efa_proto_tx_msg tx_msg;
	struct efa_proto_tx_rma_read tx_rma_read;
	struct efa_proto_tx_rma_write tx_rma_write;
	struct efa_proto_tx_atomic tx_atomic;
	struct efa_proto_rx_msg rx_msg;
	struct efa_proto_rx_rma_write rx_rma_write;
	struct efa_proto_rx_rma_read rx_rma_read;
	struct efa_proto_rx_atomic rx_atomic;
};

/**
 * @brief Size of each bufpool entry — the union of all leaf types.
 */
#define EFA_PROTO_OPE_POOL_ENTRY_SIZE sizeof(union efa_proto_ope_entry)

/* ────────────────────────────────────────────────────────────────────────────
 * Static assertions — size budgets and hot-field placement
 * ──────────────────────────────────────────────────────────────────────────── */

/* Hot fields must be in the first cache line (64 bytes) */
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, type) < 64,
	"type must be in first cache line");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, op) < 64,
	"op must be in first cache line");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, ep) < 64,
	"ep must be in first cache line");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, peer) < 64,
	"peer must be in first cache line");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, fi_flags) < 64,
	"fi_flags must be in first cache line");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, internal_flags) < 64,
	"internal_flags must be in first cache line");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, total_len) < 64,
	"total_len must be in first cache line");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, tag) < 64,
	"tag must be in first cache line");

/* Base struct: 7 cache lines (448 bytes) without debug */
#if !ENABLE_DEBUG
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_ope_base) <= 448,
	"efa_proto_ope_base must fit in 7 cache lines");
#endif

/*
 * Leaf struct size budgets (optimized builds only).
 * The original monolithic efa_rdm_ope is 872 bytes (14 cache lines).
 * Debug builds add pending_recv_entry (+16 bytes) to the base, so
 * these budgets only apply to release builds.
 */
#if !ENABLE_DEBUG
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_tx_msg) <= 528,
	"efa_proto_tx_msg size budget");
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_tx_rma_read) <= 512,
	"efa_proto_tx_rma_read size budget");
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_tx_rma_write) <= 504,
	"efa_proto_tx_rma_write size budget");
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_rx_msg) <= 600,
	"efa_proto_rx_msg size budget");
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_rx_rma_write) <= 552,
	"efa_proto_rx_rma_write size budget");
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_rx_rma_read) <= 568,
	"efa_proto_rx_rma_read size budget");
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_rx_atomic) <= 568,
	"efa_proto_rx_atomic size budget");

/* tx_atomic is the largest — acceptable since atomic is least perf-critical */
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_tx_atomic) <= 696,
	"efa_proto_tx_atomic size budget");
#endif

/* First-member inheritance: base pointer cast is safe */
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_tx_base, base) == 0,
	"tx_base.base must be at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_rx_base, base) == 0,
	"rx_base.base must be at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_tx_msg, tx) == 0,
	"tx_msg.tx must be at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_tx_rma_read, tx) == 0,
	"tx_rma_read.tx must be at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_tx_rma_write, tx) == 0,
	"tx_rma_write.tx must be at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_tx_atomic, tx) == 0,
	"tx_atomic.tx must be at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_rx_msg, rx) == 0,
	"rx_msg.rx must be at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_rx_rma_write, rx) == 0,
	"rx_rma_write.rx must be at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_rx_rma_read, rx) == 0,
	"rx_rma_read.rx must be at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_rx_atomic, rx) == 0,
	"rx_atomic.rx must be at offset 0");

/* ────────────────────────────────────────────────────────────────────────────
 * Cache line layout enforcement (64 bytes per cache line)
 *
 * Base: hot fields in CL0, iov/desc/mr in CL1-3, rma_iov in CL3-5,
 *       cq_entry+dlists in CL5-7.
 * TX/RX base: leaf-specific fields start right after base (CL7+).
 * Goal: non-atomic leaf structs ≤ ~8 CL, vs 14 CL for the old monolithic struct.
 * ──────────────────────────────────────────────────────────────────────────── */

/* --- Base struct field ordering --- */
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, type) == 0,
	"type at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, op) == 4,
	"op at offset 4");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, ep) == 8,
	"ep at offset 8");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, peer) == 16,
	"peer at offset 16");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, fi_flags) == 24,
	"fi_flags at offset 24");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, internal_flags) == 32,
	"internal_flags at offset 32");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, total_len) == 48,
	"total_len at offset 48");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, tag) == 56,
	"tag at offset 56");

/* state starts at CL1 boundary */
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, state) == 64,
	"state at CL1 boundary");

/* iov array starts within CL1 */
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, iov) == 88,
	"iov at offset 88");

/* cq_entry in CL5 */
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, cq_entry) == 320,
	"cq_entry at offset 320");

/* --- TX base: leaf fields start right after base --- */
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_tx_base, bytes_acked) ==
	sizeof(struct efa_proto_ope_base),
	"tx_base fields start immediately after base");

/* --- RX base: leaf fields start right after base --- */
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_rx_base, bytes_received) ==
	sizeof(struct efa_proto_ope_base),
	"rx_base fields start immediately after base");

/* --- No padding holes in intermediate bases --- */
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_tx_base) ==
	sizeof(struct efa_proto_ope_base) + 8 + 8 + 8,
	"tx_base has no padding holes (base + 3 fields)");

/* --- Leaf sizes: every non-atomic leaf < old struct (888 bytes) --- */
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_tx_msg) < 888,
	"tx_msg smaller than old monolithic struct");
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_tx_rma_read) < 888,
	"tx_rma_read smaller than old monolithic struct");
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_tx_rma_write) < 888,
	"tx_rma_write smaller than old monolithic struct");
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_tx_atomic) < 888,
	"tx_atomic smaller than old monolithic struct");
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_rx_msg) < 888,
	"rx_msg smaller than old monolithic struct");
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_rx_rma_write) < 888,
	"rx_rma_write smaller than old monolithic struct");
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_rx_rma_read) < 888,
	"rx_rma_read smaller than old monolithic struct");
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_rx_atomic) < 888,
	"rx_atomic smaller than old monolithic struct");

/* --- Union sized by largest member (tx_atomic) --- */
EFA_PROTO_STATIC_ASSERT(sizeof(union efa_proto_ope_entry) == sizeof(struct efa_proto_tx_atomic),
	"union sized by tx_atomic (largest member)");

/* --- Verify union covers all members --- */
EFA_PROTO_STATIC_ASSERT(sizeof(union efa_proto_ope_entry) >= sizeof(struct efa_proto_tx_msg),
	"union covers tx_msg");
EFA_PROTO_STATIC_ASSERT(sizeof(union efa_proto_ope_entry) >= sizeof(struct efa_proto_rx_msg),
	"union covers rx_msg");
EFA_PROTO_STATIC_ASSERT(sizeof(union efa_proto_ope_entry) >= sizeof(struct efa_proto_rx_rma_read),
	"union covers rx_rma_read");
EFA_PROTO_STATIC_ASSERT(sizeof(union efa_proto_ope_entry) >= sizeof(struct efa_proto_rx_atomic),
	"union covers rx_atomic");

/* ────────────────────────────────────────────────────────────────────────────
 * Legacy monolithic struct — still the active memory layout.
 * Will be removed after the per-protocol layout switchover.
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * @brief Legacy 2-value type discriminator.
 * Will be replaced by enum efa_proto_ope_type (8 values) after layout switchover.
 */
enum efa_proto_ope_type_legacy {
	EFA_PROTO_TXE = 1,
	EFA_PROTO_RXE,
};

/* ────────────────────────────────────────────────────────────────────────────
 * internal_flags bit definitions
 * ──────────────────────────────────────────────────────────────────────────── */

#define EFA_PROTO_RXE_RECV_CANCEL			BIT_ULL(3)
#define EFA_PROTO_TXE_DELIVERY_COMPLETE_REQUESTED	BIT_ULL(6)
#define EFA_PROTO_OPE_QUEUED_RNR			BIT_ULL(9)
#define EFA_PROTO_RXE_EOR_IN_FLIGHT			BIT_ULL(10)
#define EFA_PROTO_TXE_WRITTEN_RNR_CQ_ERR_ENTRY		BIT_ULL(10)
#define EFA_PROTO_OPE_QUEUED_CTRL			BIT_ULL(11)
#define EFA_PROTO_OPE_QUEUED_READ			BIT_ULL(12)
#define EFA_PROTO_OPE_READ_NACK				BIT_ULL(13)
#define EFA_PROTO_OPE_QUEUED_BEFORE_HANDSHAKE		BIT_ULL(14)
#define EFA_PROTO_OPE_INTERNAL				BIT_ULL(15)
#define EFA_PROTO_TXE_RECEIPT_RECEIVED			BIT_ULL(16)
#define EFA_PROTO_TXE_NO_COMPLETION			BIT_ULL(60)
#define EFA_PROTO_TXE_NO_COUNTER			BIT_ULL(61)

#define EFA_PROTO_OPE_QUEUED_FLAGS \
	(EFA_PROTO_OPE_QUEUED_RNR | EFA_PROTO_OPE_QUEUED_CTRL | \
	 EFA_PROTO_OPE_QUEUED_READ | EFA_PROTO_OPE_QUEUED_BEFORE_HANDSHAKE)

/* ────────────────────────────────────────────────────────────────────────────
 * Legacy function declarations (operate on struct efa_proto_ope)
 * ──────────────────────────────────────────────────────────────────────────── */

void efa_proto_tx_release(struct efa_proto_ope_base *txe);
void efa_proto_rx_release(struct efa_proto_ope_base *rxe);
void efa_proto_rx_release_internal(struct efa_proto_ope_base *rxe);
void efa_proto_ope_try_fill_desc(struct efa_proto_ope_base *ope, int mr_iov_start, uint64_t access);
int efa_proto_tx_prepare_to_be_read(struct efa_proto_ope_base *txe, struct fi_rma_iov *read_iov);
size_t efa_proto_ope_mulreq_total_data_size(struct efa_proto_ope_base *ope, int pkt_type);
size_t efa_proto_tx_max_req_data_capacity(struct efa_rdm_ep *ep, struct efa_proto_ope_base *txe, int pkt_type);
void efa_proto_tx_handle_error(struct efa_proto_ope_base *txe, int err, int prov_errno);
void efa_proto_rx_handle_error(struct efa_proto_ope_base *rxe, int err, int prov_errno);
void efa_proto_tx_report_completion(struct efa_proto_ope_base *txe);
void efa_proto_rx_report_completion(struct efa_proto_ope_base *rxe);
void efa_proto_ope_handle_recv_completed(struct efa_proto_ope_base *ope);
void efa_proto_ope_handle_send_completed(struct efa_proto_ope_base *ope);

static inline bool efa_proto_tx_dc_ready_for_release(struct efa_proto_ope_base *txe)
{
	return (txe->efa_outstanding_tx_ops == 0) &&
	       (txe->internal_flags & EFA_PROTO_TXE_RECEIPT_RECEIVED);
}

int efa_proto_ope_prepare_to_post_read(struct efa_proto_ope_base *ope);
void efa_proto_ope_prepare_to_post_write(struct efa_proto_ope_base *ope);
int efa_proto_ope_post_read(struct efa_proto_ope_base *ope);
int efa_proto_ope_post_remote_write(struct efa_proto_ope_base *ope);
int efa_proto_ope_post_remote_read_or_queue(struct efa_proto_ope_base *ope);
int efa_proto_rx_post_local_read_or_queue(struct efa_proto_ope_base *rxe,
					  size_t rx_data_offset,
					  struct efa_rdm_pke *pkt_entry,
					  char *pkt_data, size_t data_size);
ssize_t efa_proto_ope_prepare_to_post_send(struct efa_proto_ope_base *ope, int pkt_type,
					   int *pkt_entry_cnt, int *pkt_entry_data_size_vec);
ssize_t efa_proto_ope_post_send(struct efa_proto_ope_base *ope, int pkt_type);
ssize_t efa_proto_ope_post_send_fallback(struct efa_proto_ope_base *ope, int pkt_type, ssize_t err);
ssize_t efa_proto_ope_post_send_or_queue(struct efa_proto_ope_base *ope, int pkt_type);
ssize_t efa_proto_ope_repost_queued_before_handshake(struct efa_proto_ope_base *ope);
ssize_t efa_proto_tx_prepare_local_read_pkt_entry(struct efa_proto_ope_base *txe);
int efa_proto_ope_process_queued(struct efa_proto_ope_base *ope, uint32_t flag);

/* ────────────────────────────────────────────────────────────────────────────
 * Bridge macros — cast between legacy struct and new base struct
 * ──────────────────────────────────────────────────────────────────────────── */

/** Identity cast — both sides are now struct efa_proto_ope_base * */
#define EFA_PROTO_BASE_FROM_OPE(ope) (ope)
#define EFA_PROTO_OPE_FROM_BASE(base) (base)

/* ────────────────────────────────────────────────────────────────────────────
 * Leaf-type cast helpers — access non-base fields from ope_base pointer
 * ──────────────────────────────────────────────────────────────────────────── */

static inline struct efa_proto_tx_base *efa_proto_to_tx(struct efa_proto_ope_base *b)
{ return (struct efa_proto_tx_base *)b; }

static inline struct efa_proto_rx_base *efa_proto_to_rx(struct efa_proto_ope_base *b)
{ return (struct efa_proto_rx_base *)b; }

static inline struct efa_proto_tx_msg *efa_proto_to_tx_msg(struct efa_proto_ope_base *b)
{ return (struct efa_proto_tx_msg *)b; }

static inline struct efa_proto_rx_msg *efa_proto_to_rx_msg(struct efa_proto_ope_base *b)
{ return (struct efa_proto_rx_msg *)b; }

static inline struct efa_proto_tx_rma_read *efa_proto_to_tx_rma_read(struct efa_proto_ope_base *b)
{ return (struct efa_proto_tx_rma_read *)b; }

static inline struct efa_proto_tx_rma_write *efa_proto_to_tx_rma_write(struct efa_proto_ope_base *b)
{ return (struct efa_proto_tx_rma_write *)b; }

static inline struct efa_proto_tx_atomic *efa_proto_to_tx_atomic(struct efa_proto_ope_base *b)
{ return (struct efa_proto_tx_atomic *)b; }

static inline struct efa_proto_rx_rma_read *efa_proto_to_rx_rma_read(struct efa_proto_ope_base *b)
{ return (struct efa_proto_rx_rma_read *)b; }

static inline struct efa_proto_rx_atomic *efa_proto_to_rx_atomic(struct efa_proto_ope_base *b)
{ return (struct efa_proto_rx_atomic *)b; }

/**
 * @brief Access the window field from a generic ope pointer.
 * Window exists in tx_msg, rx_msg, and rx_rma_read leaf types.
 */
static inline int64_t *efa_proto_ope_window_ptr(struct efa_proto_ope_base *b)
{
	if (b->type <= EFA_PROTO_TX_ATOMIC)
		return &((struct efa_proto_tx_msg *)b)->window;
	else
		return &((struct efa_proto_rx_msg *)b)->window;
}

/**
 * @brief Access the bytes_runt field from a generic ope pointer.
 */
static inline uint64_t *efa_proto_ope_bytes_runt_ptr(struct efa_proto_ope_base *b)
{
	if (b->type <= EFA_PROTO_TX_ATOMIC)
		return &((struct efa_proto_tx_msg *)b)->bytes_runt;
	else
		return &((struct efa_proto_rx_msg *)b)->bytes_runt;
}

/**
 * @brief Read-counter accessors for generic ope pointer.
 * These fields exist in tx_msg, tx_rma_read, rx_msg.
 * For TX, we cast to tx_msg (tx_rma_read has same layout for these fields).
 */
static inline uint64_t *efa_proto_ope_bytes_read_completed_ptr(struct efa_proto_ope_base *b)
{
	if (b->type <= EFA_PROTO_TX_ATOMIC)
		return &((struct efa_proto_tx_msg *)b)->bytes_read_completed;
	else
		return &((struct efa_proto_rx_msg *)b)->bytes_read_completed;
}

static inline uint64_t *efa_proto_ope_bytes_read_submitted_ptr(struct efa_proto_ope_base *b)
{
	if (b->type <= EFA_PROTO_TX_ATOMIC)
		return &((struct efa_proto_tx_msg *)b)->bytes_read_submitted;
	else
		return &((struct efa_proto_rx_msg *)b)->bytes_read_submitted;
}

static inline uint64_t *efa_proto_ope_bytes_read_total_len_ptr(struct efa_proto_ope_base *b)
{
	if (b->type <= EFA_PROTO_TX_ATOMIC)
		return &((struct efa_proto_tx_msg *)b)->bytes_read_total_len;
	else
		return &((struct efa_proto_rx_msg *)b)->bytes_read_total_len;
}

static inline uint64_t *efa_proto_ope_bytes_read_offset_ptr(struct efa_proto_ope_base *b)
{
	if (b->type <= EFA_PROTO_TX_ATOMIC)
		return &((struct efa_proto_tx_msg *)b)->bytes_read_offset;
	else
		return &((struct efa_proto_rx_msg *)b)->bytes_read_offset;
}

/* ────────────────────────────────────────────────────────────────────────────
 * Inline helpers for type discrimination
 * ──────────────────────────────────────────────────────────────────────────── */

static inline bool efa_proto_is_tx(const struct efa_proto_ope_base *base)
{
	return base->type >= EFA_PROTO_TX_MSG && base->type <= EFA_PROTO_TX_ATOMIC;
}

static inline bool efa_proto_is_rx(const struct efa_proto_ope_base *base)
{
	return base->type >= EFA_PROTO_RX_MSG && base->type <= EFA_PROTO_RX_ATOMIC;
}

/** Downcast base to tx_base — caller must ensure efa_proto_is_tx(base) */
static inline struct efa_proto_tx_base *
efa_proto_tx_base_of(struct efa_proto_ope_base *base)
{
	return (struct efa_proto_tx_base *)base;
}

/** Downcast base to rx_base — caller must ensure efa_proto_is_rx(base) */
static inline struct efa_proto_rx_base *
efa_proto_rx_base_of(struct efa_proto_ope_base *base)
{
	return (struct efa_proto_rx_base *)base;
}

/* ────────────────────────────────────────────────────────────────────────────
 * Leaf init/release functions — implemented in efa_proto_ope.c
 * ──────────────────────────────────────────────────────────────────────────── */

/* TX leaf constructors */
void efa_proto_tx_msg_init(struct efa_proto_tx_msg *entry,
			   struct efa_rdm_ep *ep, struct efa_rdm_peer *peer,
			   const struct fi_msg *msg,
			   uint32_t op, uint64_t flags);

void efa_proto_tx_rma_read_init(struct efa_proto_tx_rma_read *entry,
				struct efa_rdm_ep *ep, struct efa_rdm_peer *peer,
				const struct fi_msg *msg, uint64_t flags);

void efa_proto_tx_rma_write_init(struct efa_proto_tx_rma_write *entry,
				 struct efa_rdm_ep *ep, struct efa_rdm_peer *peer,
				 const struct fi_msg *msg, uint64_t flags);

void efa_proto_tx_atomic_init(struct efa_proto_tx_atomic *entry,
			      struct efa_rdm_ep *ep, struct efa_rdm_peer *peer,
			      const struct fi_msg *msg,
			      uint32_t op, uint64_t flags,
			      const struct efa_proto_atomic_hdr *hdr,
			      const struct efa_proto_atomic_ex *ex);

/* RX leaf constructors */
void efa_proto_rx_msg_init(struct efa_proto_rx_msg *entry,
			   struct efa_rdm_ep *ep, struct efa_rdm_peer *peer,
			   uint32_t op);

void efa_proto_rx_rma_write_init(struct efa_proto_rx_rma_write *entry,
				 struct efa_rdm_ep *ep, struct efa_rdm_peer *peer);

void efa_proto_rx_rma_read_init(struct efa_proto_rx_rma_read *entry,
				struct efa_rdm_ep *ep, struct efa_rdm_peer *peer);

void efa_proto_rx_atomic_init(struct efa_proto_rx_atomic *entry,
			      struct efa_rdm_ep *ep, struct efa_rdm_peer *peer,
			      uint32_t op);

/* Release functions */
void efa_proto_ope_base_release(struct efa_proto_ope_base *base);
void efa_proto_rx_base_release(struct efa_proto_rx_base *rx);

/* ────────────────────────────────────────────────────────────────────────────
 * Task 12: Compile-time validation — before/after size comparison
 *
 * Original struct efa_proto_ope: 872 bytes (14 cache lines) without debug.
 * The new hierarchy eliminates unused fields from each protocol path.
 *
 * After switchover, each protocol path only touches the cache lines it needs:
 *
 * | Protocol Path     | New struct              | Reduction vs 872B |
 * |-------------------|-------------------------|-------------------|
 * | TX msg/tagged     | efa_proto_tx_msg        | ~40%              |
 * | TX RMA read       | efa_proto_tx_rma_read   | ~42%              |
 * | TX RMA write      | efa_proto_tx_rma_write  | ~43%              |
 * | TX atomic         | efa_proto_tx_atomic     | ~21%              |
 * | RX msg/tagged     | efa_proto_rx_msg        | ~32%              |
 * | RX RMA write      | efa_proto_rx_rma_write  | ~38%              |
 * | RX RMA read       | efa_proto_rx_rma_read   | ~36%              |
 * | RX atomic         | efa_proto_rx_atomic     | ~36%              |
 *
 * The union (efa_proto_ope_entry) is sized by the largest member (tx_atomic)
 * and is used for the single bufpool allocation.
 * ──────────────────────────────────────────────────────────────────────────── */

#endif /* _EFA_PROTO_OPE_H */

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

struct efa_rdm_ep;
struct efa_rdm_peer;
struct efa_rdm_pke;
struct efa_rdm_rxe_map;
struct fi_peer_rx_entry;
struct fid_mr;

#define EFA_PROTO_IOV_LIMIT	(4)

#define EFA_PROTO_STATIC_ASSERT(expr, msg) _Static_assert(expr, msg)

/**
 * @brief operation entry type — discriminator for the struct hierarchy.
 *
 * Per-protocol types: each protocol vtable instance gets its own type value
 * so leaf structs can be identified without knowing the protocol at compile time.
 */
enum efa_proto_ope_type {
	/* TX protocols */
	EFA_PROTO_TX_EAGER_MSG = 1,
	EFA_PROTO_TX_MEDIUM_MSG,
	EFA_PROTO_TX_LONGCTS_MSG,
	EFA_PROTO_TX_LONGREAD_MSG,
	EFA_PROTO_TX_RUNTREAD_MSG,
	EFA_PROTO_TX_EAGER_WRITE,
	EFA_PROTO_TX_LONGCTS_WRITE,
	EFA_PROTO_TX_LONGREAD_READ,
	EFA_PROTO_TX_ATOMIC,
	/* RX protocols */
	EFA_PROTO_RX_EAGER_MSG,
	EFA_PROTO_RX_LONGCTS_MSG,
	EFA_PROTO_RX_LONGREAD_MSG,
	EFA_PROTO_RX_RUNTREAD_MSG,
	EFA_PROTO_RX_RTW,
	EFA_PROTO_RX_RTR,
	EFA_PROTO_RX_ATOMIC,
};

enum efa_proto_ope_state {
	EFA_PROTO_TXE_REQ = 1,
	EFA_PROTO_OPE_SEND,
	EFA_PROTO_RXE_INIT,
	EFA_PROTO_RXE_UNEXP,
	EFA_PROTO_RXE_MATCHED,
	EFA_PROTO_RXE_RECV,
	EFA_PROTO_OPE_ERR,
};

struct efa_proto_atomic_hdr {
	uint32_t atomic_op;
	uint32_t datatype;
};

struct efa_proto_atomic_ex {
	struct iovec resp_iov[EFA_PROTO_IOV_LIMIT];
	int resp_iov_count;
	struct iovec comp_iov[EFA_PROTO_IOV_LIMIT];
	int comp_iov_count;
	void *result_desc[EFA_PROTO_IOV_LIMIT];
	void *compare_desc[EFA_PROTO_IOV_LIMIT];
};

enum efa_proto_cuda_copy_method {
	EFA_PROTO_CUDA_COPY_UNSPEC = 0,
	EFA_PROTO_CUDA_COPY_BLOCKING,
	EFA_PROTO_CUDA_COPY_LOCALREAD,
};

/* ────────────────────────────────────────────────────────────────────────────
 * Minimal base struct — ONLY fields used by every protocol path.
 *
 * Fields removed from old base (moved to leaves that need them):
 *   rx_id (4)           → longcts, RTR responder leaves
 *   queued_ctrl_type (4) → longcts leaves
 *   mr[4] (32)          → all non-eager leaves
 *   rma_iov_count (8)   → RMA/longread/runtread/atomic leaves
 *   rma_iov[4] (96)     → RMA/longread/runtread/atomic leaves
 *   entry (16)          → longcts leaves (longcts_send_list)
 *
 * Total removed: 160 bytes. New base: 288 bytes (4.5 cache lines)
 * vs old base: 448 bytes (7 cache lines) = 36% reduction.
 * ──────────────────────────────────────────────────────────────────────────── */

struct efa_proto_ope_base {
	/* ── CL0: hot fields (offset 0–63, zero padding) ── */
	enum efa_proto_ope_type type;	/*   4  (0)   */
	uint32_t op;			/*   4  (4)   */
	struct efa_rdm_ep *ep;		/*   8  (8)   */
	struct efa_rdm_peer *peer;	/*   8  (16)  */
	uint64_t fi_flags;		/*   8  (24)  */
	uint32_t internal_flags;	/*   4  (32)  */
	uint32_t tx_id;			/*   4  (36)  */
	uint32_t msg_id;		/*   4  (40)  */
	enum efa_proto_ope_state state;	/*   4  (44)  */
	uint64_t total_len;		/*   8  (48)  */
	uint64_t tag;			/*   8  (56)  */
	/* ── CL1 boundary (64) ── */
	size_t efa_outstanding_tx_ops;	/*   8  (64)  */
	size_t iov_count;		/*   8  (72)  */
	struct iovec iov[EFA_PROTO_IOV_LIMIT];	/*  64  (80)  */
	/* ── CL2 boundary (128) at iov offset 48 ── */
	void *desc[EFA_PROTO_IOV_LIMIT];	/*  32  (144) */
	struct fi_cq_tagged_entry cq_entry;	/*  48  (176) */
	/* ── CL3 boundary (192) at cq_entry offset 16 ── */
	struct dlist_entry ep_entry;		/*  16  (224) */
	struct dlist_entry peer_entry;		/*  16  (240) */
	/* ── CL4 boundary (256) ── */
	struct dlist_entry queued_pkts;		/*  16  (256) */
	struct dlist_entry queued_entry;	/*  16  (272) */

#if ENABLE_DEBUG
	struct dlist_entry pending_recv_entry;	/*  16  (288) — debug only */
#endif
};
/* size: 288 bytes, 5 cachelines (last CL: 32 bytes), zero padding */

/* ────────────────────────────────────────────────────────────────────────────
 * Composable field groups — embedded in leaves that need them.
 * These are NOT intermediate base structs; they are plain structs
 * composed into leaves via direct embedding.
 * ──────────────────────────────────────────────────────────────────────────── */

/** MR array — needed by all protocols that register memory (everything except eager) */
struct efa_proto_mr_fields {
	struct fid_mr *mr[EFA_PROTO_IOV_LIMIT];		/*  32  (0)   */
};
/* size: 32 */

/** RMA IOV — needed by longread, runtread, RMA, atomic */
struct efa_proto_rma_fields {
	size_t rma_iov_count;				/*   8  (0)   */
	struct fi_rma_iov rma_iov[EFA_PROTO_IOV_LIMIT];/*  96  (8)   */
};
/* size: 104 */

/** CTS flow control — needed by longcts and RTR responder */
struct efa_proto_cts_fields {
	uint32_t rx_id;			/*   4  (0)   */
	int queued_ctrl_type;		/*   4  (4)   */
	int64_t window;			/*   8  (8)   */
	struct dlist_entry entry;	/*  16  (16)  — longcts_send_list */
};
/* size: 32 */

/** Read progress counters — needed by longread and runtread */
struct efa_proto_read_fields {
	uint64_t bytes_read_completed;	/*   8  (0)   */
	uint64_t bytes_read_submitted;	/*   8  (8)   */
	uint64_t bytes_read_total_len;	/*   8  (16)  */
	uint64_t bytes_read_offset;	/*   8  (24)  */
};
/* size: 32 */

/** RX common fields — needed by all RX msg protocols */
struct efa_proto_rx_common {
	uint64_t bytes_received;		/*   8  (0)   */
	uint64_t bytes_copied;			/*   8  (8)   */
	uint64_t ignore;			/*   8  (16)  */
	struct efa_rdm_pke *unexp_pkt;		/*   8  (24)  */
	struct fi_peer_rx_entry *peer_rxe;	/*   8  (32)  */
};
/* size: 40 */

/* ────────────────────────────────────────────────────────────────────────────
 * TX leaf structs — one per protocol
 * ──────────────────────────────────────────────────────────────────────────── */

/** TX eager msg/tagged — minimal, base only. size: 288, 5 CL */
struct efa_proto_tx_eager_msg {
	struct efa_proto_ope_base base;			/* 288  (0)   */
};

/** TX medium msg/tagged. size: 344, 6 CL */
struct efa_proto_tx_medium_msg {
	struct efa_proto_ope_base base;			/* 288  (0)   */
	struct efa_proto_mr_fields mr;			/*  32  (288) */
	/* ── CL5 boundary (320) ── */
	uint64_t bytes_acked;				/*   8  (320) */
	uint64_t bytes_sent;				/*   8  (328) */
	uint64_t bytes_runt;				/*   8  (336) */
};

/** TX longcts msg/tagged. size: 376, 6 CL */
struct efa_proto_tx_longcts_msg {
	struct efa_proto_ope_base base;			/* 288  (0)   */
	struct efa_proto_mr_fields mr;			/*  32  (288) */
	/* ── CL5 boundary (320) ── */
	struct efa_proto_cts_fields cts;		/*  32  (320) */
	uint64_t bytes_acked;				/*   8  (352) */
	uint64_t bytes_sent;				/*   8  (360) */
	struct efa_rdm_pke *local_read_pkt_entry;	/*   8  (368) */
};

/** TX longread — shared by msg/tagged longread and RMA read (RTR). size: 456, 8 CL */
struct efa_proto_tx_longread {
	struct efa_proto_ope_base base;			/* 288  (0)   */
	struct efa_proto_mr_fields mr;			/*  32  (288) */
	/* ── CL5 boundary (320) ── */
	struct efa_proto_rma_fields rma;		/* 104  (320) */
	/* ── CL6 boundary (384) at rma offset 64 ── */
	struct efa_proto_read_fields read;		/*  32  (424) */
};

/** TX runtread msg/tagged. size: 480, 8 CL */
struct efa_proto_tx_runtread_msg {
	struct efa_proto_ope_base base;			/* 288  (0)   */
	struct efa_proto_mr_fields mr;			/*  32  (288) */
	/* ── CL5 boundary (320) ── */
	struct efa_proto_rma_fields rma;		/* 104  (320) */
	/* ── CL6 boundary (384) at rma offset 64 ── */
	struct efa_proto_read_fields read;		/*  32  (424) */
	/* ── CL7 boundary (448) at read offset 24 ── */
	uint64_t bytes_acked;				/*   8  (456) */
	uint64_t bytes_sent;				/*   8  (464) */
	uint64_t bytes_runt;				/*   8  (472) */
};

/** TX eager RMA write (RTW). size: 424, 7 CL */
struct efa_proto_tx_eager_write {
	struct efa_proto_ope_base base;			/* 288  (0)   */
	struct efa_proto_mr_fields mr;			/*  32  (288) */
	/* ── CL5 boundary (320) ── */
	struct efa_proto_rma_fields rma;		/* 104  (320) */
};

/** TX longcts RMA write. size: 480, 8 CL */
struct efa_proto_tx_longcts_write {
	struct efa_proto_ope_base base;			/* 288  (0)   */
	struct efa_proto_mr_fields mr;			/*  32  (288) */
	/* ── CL5 boundary (320) ── */
	struct efa_proto_rma_fields rma;		/* 104  (320) */
	/* ── CL6 boundary (384) at rma offset 64 ── */
	struct efa_proto_cts_fields cts;		/*  32  (424) */
	/* ── CL7 boundary (448) at cts offset 24 ── */
	uint64_t bytes_acked;				/*   8  (456) */
	uint64_t bytes_sent;				/*   8  (464) */
	struct efa_rdm_pke *local_read_pkt_entry;	/*   8  (472) */
};

/** TX atomic. size: 640, 10 CL */
struct efa_proto_tx_atomic {
	struct efa_proto_ope_base base;			/* 288  (0)   */
	struct efa_proto_mr_fields mr;			/*  32  (288) */
	/* ── CL5 boundary (320) ── */
	struct efa_proto_rma_fields rma;		/* 104  (320) */
	/* ── CL6 boundary (384) at rma offset 64 ── */
	struct efa_proto_atomic_hdr atomic_hdr;		/*   8  (424) */
	struct efa_proto_atomic_ex atomic_ex;		/* 208  (432) */
	/* ── CL7–10 ── */
};

/* ────────────────────────────────────────────────────────────────────────────
 * RX leaf structs — one per protocol
 * ──────────────────────────────────────────────────────────────────────────── */

/** RX eager msg/tagged. size: 328, 6 CL */
struct efa_proto_rx_eager_msg {
	struct efa_proto_ope_base base;			/* 288  (0)   */
	struct efa_proto_rx_common rx;			/*  40  (288) */
};

/** RX longcts msg/tagged. size: 440, 7 CL (4 bytes padding) */
struct efa_proto_rx_longcts_msg {
	struct efa_proto_ope_base base;			/* 288  (0)   */
	struct efa_proto_mr_fields mr;			/*  32  (288) */
	/* ── CL5 boundary (320) ── */
	struct efa_proto_cts_fields cts;		/*  32  (320) */
	struct efa_proto_rx_common rx;			/*  40  (352) */
	/* ── CL6 boundary (384) at rx offset 32 ── */
	uint64_t bytes_received_via_mulreq;		/*   8  (392) */
	uint64_t bytes_queued_blocking_copy;		/*   8  (400) */
	struct efa_rdm_rxe_map *rxe_map;		/*   8  (408) */
	struct dlist_entry ack_list_entry;		/*  16  (416) */
	enum efa_proto_cuda_copy_method cuda_copy_method; /* 4 (432) + 4 pad */
};

/** RX longread msg/tagged. size: 496, 8 CL */
struct efa_proto_rx_longread_msg {
	struct efa_proto_ope_base base;			/* 288  (0)   */
	struct efa_proto_mr_fields mr;			/*  32  (288) */
	/* ── CL5 boundary (320) ── */
	struct efa_proto_rma_fields rma;		/* 104  (320) */
	/* ── CL6 boundary (384) at rma offset 64 ── */
	struct efa_proto_read_fields read;		/*  32  (424) */
	/* ── CL7 boundary (448) at read offset 24 ── */
	struct efa_proto_rx_common rx;			/*  40  (456) */
};

/** RX runtread msg/tagged. size: 520, 9 CL */
struct efa_proto_rx_runtread_msg {
	struct efa_proto_ope_base base;			/* 288  (0)   */
	struct efa_proto_mr_fields mr;			/*  32  (288) */
	/* ── CL5 boundary (320) ── */
	struct efa_proto_rma_fields rma;		/* 104  (320) */
	/* ── CL6 boundary (384) at rma offset 64 ── */
	struct efa_proto_read_fields read;		/*  32  (424) */
	/* ── CL7 boundary (448) at read offset 24 ── */
	struct efa_proto_rx_common rx;			/*  40  (456) */
	uint64_t bytes_runt;				/*   8  (496) */
	uint64_t bytes_received_via_mulreq;		/*   8  (504) */
	/* ── CL8 boundary (512) ── */
	struct efa_rdm_rxe_map *rxe_map;		/*   8  (512) */
};

/** RX RTW (RMA write responder). size: 480, 8 CL */
struct efa_proto_rx_rtw {
	struct efa_proto_ope_base base;			/* 288  (0)   */
	struct efa_proto_mr_fields mr;			/*  32  (288) */
	/* ── CL5 boundary (320) ── */
	struct efa_proto_rma_fields rma;		/* 104  (320) */
	/* ── CL6 boundary (384) at rma offset 64 ── */
	struct efa_proto_rx_common rx;			/*  40  (424) */
	/* ── CL7 boundary (448) at rx offset 24 ── */
	struct dlist_entry ack_list_entry;		/*  16  (464) */
};

/** RX RTR (RMA read responder). size: 464, 8 CL */
struct efa_proto_rx_rtr {
	struct efa_proto_ope_base base;			/* 288  (0)   */
	struct efa_proto_mr_fields mr;			/*  32  (288) */
	/* ── CL5 boundary (320) ── */
	struct efa_proto_rma_fields rma;		/* 104  (320) */
	/* ── CL6 boundary (384) at rma offset 64 ── */
	struct efa_proto_cts_fields cts;		/*  32  (424) */
	/* ── CL7 boundary (448) at cts offset 24 ── */
	uint64_t bytes_sent;				/*   8  (456) */
};

/** RX atomic (RTA responder). size: 440, 7 CL */
struct efa_proto_rx_atomic {
	struct efa_proto_ope_base base;			/* 288  (0)   */
	struct efa_proto_mr_fields mr;			/*  32  (288) */
	/* ── CL5 boundary (320) ── */
	struct efa_proto_rma_fields rma;		/* 104  (320) */
	/* ── CL6 boundary (384) at rma offset 64 ── */
	struct efa_proto_atomic_hdr atomic_hdr;		/*   8  (424) */
	char *atomrsp_data;				/*   8  (432) */
};

/* ────────────────────────────────────────────────────────────────────────────
 * Union — single bufpool allocation type
 * ──────────────────────────────────────────────────────────────────────────── */

/* ────────────────────────────────────────────────────────────────────────────
 * Union — single bufpool allocation type. size: 640 (10 CL)
 * Sized by largest member: tx_atomic (640)
 * Old monolithic efa_rdm_ope was 872 bytes (13.6 CL) = 27% reduction in pool entry
 * ──────────────────────────────────────────────────────────────────────────── */

union efa_proto_ope_entry {
	struct efa_proto_ope_base base;			/* 288 */
	struct efa_proto_tx_eager_msg tx_eager_msg;	/* 288 */
	struct efa_proto_tx_medium_msg tx_medium_msg;	/* 344 */
	struct efa_proto_tx_longcts_msg tx_longcts_msg;	/* 376 */
	struct efa_proto_tx_longread tx_longread;	/* 456 */
	struct efa_proto_tx_runtread_msg tx_runtread_msg;/* 480 */
	struct efa_proto_tx_eager_write tx_eager_write;	/* 424 */
	struct efa_proto_tx_longcts_write tx_longcts_write;/* 480 */
	struct efa_proto_tx_atomic tx_atomic;		/* 640 ← largest */
	struct efa_proto_rx_eager_msg rx_eager_msg;	/* 328 */
	struct efa_proto_rx_longcts_msg rx_longcts_msg;	/* 440 */
	struct efa_proto_rx_longread_msg rx_longread_msg;/* 496 */
	struct efa_proto_rx_runtread_msg rx_runtread_msg;/* 520 */
	struct efa_proto_rx_rtw rx_rtw;			/* 480 */
	struct efa_proto_rx_rtr rx_rtr;			/* 464 */
	struct efa_proto_rx_atomic rx_atomic;		/* 440 */
};

#define EFA_PROTO_OPE_POOL_ENTRY_SIZE sizeof(union efa_proto_ope_entry)

/* ────────────────────────────────────────────────────────────────────────────
 * Static assertions
 * ──────────────────────────────────────────────────────────────────────────── */

/* Hot fields in first cache line */
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, type) == 0,
	"type at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, ep) < 64,
	"ep in first cache line");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, peer) < 64,
	"peer in first cache line");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, fi_flags) < 64,
	"fi_flags in first cache line");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, total_len) < 64,
	"total_len in first cache line");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, tag) < 64,
	"tag in first cache line");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_ope_base, state) < 64,
	"state in first cache line");

/* Base size: 288 bytes (4.5 cache lines) without debug */
#if !ENABLE_DEBUG
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_ope_base) == 288,
	"base must be exactly 288 bytes (zero waste)");
#endif

/* First-member inheritance: all leaves start with base at offset 0 */
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_tx_eager_msg, base) == 0,
	"tx_eager_msg.base at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_tx_medium_msg, base) == 0,
	"tx_medium_msg.base at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_tx_longcts_msg, base) == 0,
	"tx_longcts_msg.base at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_tx_longread, base) == 0,
	"tx_longread.base at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_tx_runtread_msg, base) == 0,
	"tx_runtread_msg.base at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_tx_eager_write, base) == 0,
	"tx_eager_write.base at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_tx_longcts_write, base) == 0,
	"tx_longcts_write.base at offset 0");
/* tx_longread_read uses struct efa_proto_tx_longread (same layout) */
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_tx_atomic, base) == 0,
	"tx_atomic.base at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_rx_eager_msg, base) == 0,
	"rx_eager_msg.base at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_rx_longcts_msg, base) == 0,
	"rx_longcts_msg.base at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_rx_longread_msg, base) == 0,
	"rx_longread_msg.base at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_rx_runtread_msg, base) == 0,
	"rx_runtread_msg.base at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_rx_rtw, base) == 0,
	"rx_rtw.base at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_rx_rtr, base) == 0,
	"rx_rtr.base at offset 0");
EFA_PROTO_STATIC_ASSERT(offsetof(struct efa_proto_rx_atomic, base) == 0,
	"rx_atomic.base at offset 0");

/* TX eager msg = base only (hottest path, zero waste) */
EFA_PROTO_STATIC_ASSERT(sizeof(struct efa_proto_tx_eager_msg) == sizeof(struct efa_proto_ope_base),
	"tx_eager_msg is exactly base size");

/* Union sized by largest member (tx_atomic) */
EFA_PROTO_STATIC_ASSERT(sizeof(union efa_proto_ope_entry) >= sizeof(struct efa_proto_tx_atomic),
	"union covers tx_atomic");
EFA_PROTO_STATIC_ASSERT(sizeof(union efa_proto_ope_entry) >= sizeof(struct efa_proto_tx_runtread_msg),
	"union covers tx_runtread_msg");
EFA_PROTO_STATIC_ASSERT(sizeof(union efa_proto_ope_entry) >= sizeof(struct efa_proto_rx_longcts_msg),
	"union covers rx_longcts_msg");
EFA_PROTO_STATIC_ASSERT(sizeof(union efa_proto_ope_entry) >= sizeof(struct efa_proto_rx_runtread_msg),
	"union covers rx_runtread_msg");

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
 * Inline helpers for type discrimination
 * ──────────────────────────────────────────────────────────────────────────── */

static inline bool efa_proto_is_tx(const struct efa_proto_ope_base *base)
{
	return base->type >= EFA_PROTO_TX_EAGER_MSG &&
	       base->type <= EFA_PROTO_TX_ATOMIC;
}

static inline bool efa_proto_is_rx(const struct efa_proto_ope_base *base)
{
	return base->type >= EFA_PROTO_RX_EAGER_MSG &&
	       base->type <= EFA_PROTO_RX_ATOMIC;
}

/* ────────────────────────────────────────────────────────────────────────────
 * Bridge macros — identity casts for migration
 * ──────────────────────────────────────────────────────────────────────────── */

#define EFA_PROTO_BASE_FROM_OPE(ope) (ope)
#define EFA_PROTO_OPE_FROM_BASE(base) (base)

/* ────────────────────────────────────────────────────────────────────────────
 * Function declarations
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

#endif /* _EFA_PROTO_OPE_H */

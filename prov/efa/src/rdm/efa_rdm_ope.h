/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef _EFA_RDM_OPE_H
#define _EFA_RDM_OPE_H

#include <assert.h>

#include "efa_rdm_pke.h"

#define EFA_RDM_IOV_LIMIT		(4)

struct efa_rdm_atomic_proto;

/**
 * @brief EFA RDM operation entry (ope) type
 */
enum efa_rdm_ope_type {
	EFA_RDM_TXE = 1, /**< this ope is for an TX operation */
	EFA_RDM_RXE,     /**< this ope is for an RX operation */
};

/*
 * These values are serialized in efa_rdm_peer_error_hdr
 * (emitter_ope_type), so they are wire format and may never change.
 */
static_assert(EFA_RDM_TXE == 1 && EFA_RDM_RXE == 2,
	      "efa_rdm_ope_type values are serialized in efa_rdm_peer_error_hdr");

/**
 * @brief Which set of fields an ope uses, set by the protocol that owns it.
 *
 * Protocols that use the same fields share a kind.
 */
enum efa_rdm_ope_kind {
	EFA_RDM_TXE_KIND_MSG_EAGER = 1,	/**< eager, zero copy */
	EFA_RDM_TXE_KIND_MSG,		/**< medium, long CTS, long read, runt read */
	EFA_RDM_TXE_KIND_RMA,		/**< eager write, long read write, handshake, RMA before the handshake */
	EFA_RDM_TXE_KIND_RMA_SEND,	/**< long CTS write */
	EFA_RDM_TXE_KIND_RMA_RECV,	/**< short RTR, long CTS RTR */
	EFA_RDM_TXE_KIND_DEVICE_WRITE,	/**< RDMA write */
	EFA_RDM_TXE_KIND_DEVICE_READ,	/**< RDMA read, local read */
	EFA_RDM_TXE_KIND_ATOMIC,	/**< write, fetch and compare atomic */
	EFA_RDM_RXE_KIND_MSG,		/**< eager, medium, long CTS */
	EFA_RDM_RXE_KIND_MSG_READ,	/**< long read, runt read */
	EFA_RDM_RXE_KIND_WRITE,		/**< eager write, long CTS write */
	EFA_RDM_RXE_KIND_WRITE_READ,	/**< long read write */
	EFA_RDM_RXE_KIND_READ_RSP,	/**< short RTR, long CTS RTR responder */
	EFA_RDM_RXE_KIND_ATOMIC,	/**< atomic responder */
};

/**
 * @brief EFA RDM operation entry (ope)'s state
 */
enum efa_rdm_ope_state {
	EFA_RDM_TXE_REQ = 1,	/**< txe sending REQ packet */
	EFA_RDM_OPE_SEND,	/**< ope sending data in progress */
	EFA_RDM_RXE_INIT,	/**< rxe ready to recv RTM */
	EFA_RDM_RXE_UNEXP,	/**< rxe unexp msg waiting for post recv */
	EFA_RDM_RXE_MATCHED,	/**< rxe matched with RTM */
	EFA_RDM_RXE_RECV,	/**< rxe large msg recv data pkts */
	EFA_RDM_OPE_ERR, /*< ope is in error state */
};

/**
 * @brief basic information of an atomic operation
 * used by all 3 types of atomic operations: fetch, compare and write
 */
struct efa_rdm_atomic_hdr {
	/* atomic_op is different from tx_op */
	uint32_t atomic_op;
	uint32_t datatype;
};

/**
 * @brief extra information that is not included in fi_msg_atomic
 * used by fetch atomic and compare atomic.
 *     resp stands for response
 *     comp stands for compare
 */
struct efa_rdm_atomic_ex {
	struct iovec resp_iov[EFA_RDM_IOV_LIMIT];
	int resp_iov_count;
	struct iovec comp_iov[EFA_RDM_IOV_LIMIT];
	int comp_iov_count;
	void *result_desc[EFA_RDM_IOV_LIMIT];
	void *compare_desc[EFA_RDM_IOV_LIMIT];
};

/**
 * @brief how to copy data from bounce buffer to CUDA receive buffer
 */
enum efa_rdm_cuda_copy_method {
	EFA_RDM_CUDA_COPY_UNSPEC = 0,
	EFA_RDM_CUDA_COPY_BLOCKING,   /** gdrcopy or cudaMemcpy */
	EFA_RDM_CUDA_COPY_LOCALREAD   /** device driven copy by using local RDMA read */
};

/**
 * @brief EFA RDM operation entry (ope)
 *
 */
struct efa_rdm_ope {
	enum efa_rdm_ope_type type;
	/**
	 * @brief generation of this pool slot
	 *
	 * Bumped on release and preserved across the release-time poisoning,
	 * so it tells this occupant of the slot from any earlier one. A pke
	 * snapshots it to catch a stale ope back-pointer, and a txe id carries
	 * it so a peer's id stops resolving once the slot moves on. That second
	 * use is not debug only, so this must stay correct in release builds.
	 */
	uint8_t gen;

	/** @brief enum efa_rdm_ope_kind */
	uint8_t kind;

	struct efa_rdm_ep *ep;
	struct efa_rdm_peer *peer;
	struct efa_rdm_proto *proto; /**< protocol selected for the operation; NULL when it uses none */

	uint32_t tx_id;
	uint32_t rx_id;
	uint32_t op;

	uint32_t msg_id;

	uint64_t tag;

	uint64_t total_len;

	enum efa_rdm_ope_state state;
	int queued_ctrl_type;

	uint64_t fi_flags;

	/**
	 * @brief used by EFA provider to check status of an operation entry
	 * @details
	 * flags whose name started with EFA_RDM_TXE or EFA_RDM_RXE are
	 * applied (such as #EFA_RDM_TXE_DELIVERY_COMPLETE_REQUESTED)
	 * on internal_flags, and is not visible from user.
	 * This flag is different from #cq_entry.flags, which is
	 * applied to CQ entry's returned to user.
	 */
	uint32_t internal_flags;

	size_t iov_count;
	struct iovec iov[EFA_RDM_IOV_LIMIT];
	void *desc[EFA_RDM_IOV_LIMIT];
	/**
	 * Snapshots of each desc[i] efa_rdm_mr generation counter,
	 * captured at dispatch time (and re-captured whenever desc[] is
	 * rewritten). Used by the data path to detect a closed MR.
	 */
	uint32_t desc_gen[EFA_RDM_IOV_LIMIT];
	struct fid_mr *mr[EFA_RDM_IOV_LIMIT];

	struct fi_cq_tagged_entry cq_entry;

	/* entry is linked with ope_longcts_send_list in efa_rdm_ep */
	struct dlist_entry entry;

	/* ep_entry is linked to base_ep.ope_list */
	struct dlist_entry ep_entry;

	/* ack_list_entry is linked to ope_posted_ack_list in efa_rdm_ep */
	struct dlist_entry ack_list_entry;

	/* queued_entry is linked with ope_queued_list in efa_rdm_ep */
	struct dlist_entry queued_entry;

	/* Queued packets due to TX queue full or RNR backoff */
	struct dlist_entry queued_pkts;


	/* linked with tx/rxe_list in rdm_peer */
	struct dlist_entry peer_entry;

#if ENABLE_DEBUG
	/* linked with ope_recv_list in efa_rdm_ep */
	struct dlist_entry pending_recv_entry;
#endif

	size_t efa_outstanding_tx_ops;

	/**
	 * @brief The REQ packet type selected for this ope.
	 */
	uint32_t req_pkt_type;

	/**
	 * @brief Provider errno to attach when emitting an EFA_RDM_PEER_ERROR_PKT
	 *
	 * Set by efa_rdm_rxe_emit_peer_error (LONGREAD direction), by the LONGCTS
	 * sender-side abort path, and read by efa_rdm_pke_init_peer_error to
	 * populate the wire header's prov_errno field. Has no meaning if no
	 * PEER_ERROR_PKT is being emitted from this ope.
	 */
	int peer_error_prov_errno;
};

/**
 * @brief progress of an ope that sends the data of a transfer
 */
struct efa_rdm_ope_sender {
	/** bytes the receiver allows to be sent */
	int64_t window;
	uint64_t bytes_sent;
	uint64_t bytes_acked;
	/** bytes sent in the REQ packets of a runt read */
	uint64_t bytes_runt;
};

/**
 * @brief progress of an ope that receives the data of a transfer
 */
struct efa_rdm_ope_receiver {
	/** bytes the receiver allowed the sender to send */
	int64_t window;
	uint64_t bytes_received;
	uint64_t bytes_received_via_mulreq;
	uint64_t bytes_copied;
	uint64_t bytes_queued_blocking_copy;
	enum efa_rdm_cuda_copy_method cuda_copy_method;
};

/**
 * @brief the remote memory an ope writes, reads or applies an atomic to
 */
struct efa_rdm_ope_rma {
	size_t rma_iov_count;
	struct fi_rma_iov rma_iov[EFA_RDM_IOV_LIMIT];
};

/**
 * @brief progress of the RDMA reads an ope posts
 */
struct efa_rdm_ope_read {
	uint64_t bytes_read_completed;
	uint64_t bytes_read_submitted;
	uint64_t bytes_read_total_len;
	uint64_t bytes_read_offset;
};

/**
 * @brief progress of the RDMA writes a txe posts
 */
struct efa_rdm_ope_write {
	uint64_t bytes_write_completed;
	uint64_t bytes_write_submitted;
	uint64_t bytes_write_total_len;
};

/**
 * @brief txe of an RMA operation (EFA_RDM_TXE_KIND_RMA to
 * EFA_RDM_TXE_KIND_DEVICE_READ)
 *
 * Every RMA kind starts with the rma group, so a txe can take its kind once
 * the protocol is chosen, after the rma group is filled.
 */
struct efa_rdm_txe_rma {
	struct efa_rdm_ope base;
	struct efa_rdm_ope_rma rma;
	struct efa_rdm_ope_sender sender;
	/** the source packet entry of a local read */
	struct efa_rdm_pke *local_read_pkt_entry;
	union {
		struct efa_rdm_ope_write write;	/**< EFA_RDM_TXE_KIND_DEVICE_WRITE */
		struct efa_rdm_ope_read read;	/**< EFA_RDM_TXE_KIND_DEVICE_READ */
		struct efa_rdm_ope_receiver receiver;	/**< EFA_RDM_TXE_KIND_RMA_RECV */
	} u;
};

/**
 * @brief txe of a message (EFA_RDM_TXE_KIND_MSG_EAGER and
 * EFA_RDM_TXE_KIND_MSG)
 */
struct efa_rdm_txe_msg {
	struct efa_rdm_ope base;
	struct efa_rdm_ope_sender sender;
};

/**
 * @brief txe of an atomic operation (EFA_RDM_TXE_KIND_ATOMIC)
 */
struct efa_rdm_txe_atomic {
	struct efa_rdm_ope base;
	struct efa_rdm_ope_rma rma;
	struct efa_rdm_atomic_hdr atomic_hdr;
	const struct efa_rdm_atomic_proto *atomic_proto;
	/** only fetch and compare atomics use this */
	struct efa_rdm_atomic_ex atomic_ex;
};

/**
 * @brief rxe of a message (EFA_RDM_RXE_KIND_MSG and
 * EFA_RDM_RXE_KIND_MSG_READ)
 *
 * Only EFA_RDM_RXE_KIND_MSG_READ uses the rma and read groups.
 */
struct efa_rdm_rxe_msg {
	struct efa_rdm_ope base;
	struct efa_rdm_ope_receiver receiver;
	/** unexpected packets held until the message is matched */
	struct efa_rdm_pke *unexp_pkt;
	/** used by peer SRX ops */
	struct fi_peer_rx_entry *peer_rxe;
	/** the rxe_map that the rxe is ever inserted */
	struct efa_rdm_rxe_map *rxe_map;
	/** bytes the sender sent in the REQ packets of a runt read */
	uint64_t bytes_runt;
	struct efa_rdm_ope_rma rma;
	struct efa_rdm_ope_read read;
};

/**
 * @brief rxe of an emulated write (EFA_RDM_RXE_KIND_WRITE and
 * EFA_RDM_RXE_KIND_WRITE_READ)
 *
 * Only EFA_RDM_RXE_KIND_WRITE_READ uses the rma and read groups.
 */
struct efa_rdm_rxe_write {
	struct efa_rdm_ope base;
	struct efa_rdm_ope_receiver receiver;
	struct efa_rdm_ope_rma rma;
	struct efa_rdm_ope_read read;
};

/**
 * @brief rxe of an emulated read responder (EFA_RDM_RXE_KIND_READ_RSP)
 */
struct efa_rdm_rxe_read_rsp {
	struct efa_rdm_ope base;
	struct efa_rdm_ope_sender sender;
};

/**
 * @brief rxe of an atomic responder (EFA_RDM_RXE_KIND_ATOMIC)
 */
struct efa_rdm_rxe_atomic {
	struct efa_rdm_ope base;
	struct efa_rdm_atomic_hdr atomic_hdr;
	char *atomrsp_data;
};

/**
 * @brief An entry of the txe pool, which holds a txe of any kind.
 */
union efa_rdm_txe_slot {
	struct efa_rdm_ope base;
	struct efa_rdm_txe_msg msg;
	struct efa_rdm_txe_rma rma;
	struct efa_rdm_txe_atomic atomic;
};

/**
 * @brief An entry of the rxe pool, which holds an rxe of any kind.
 */
union efa_rdm_rxe_slot {
	struct efa_rdm_ope base;
	struct efa_rdm_rxe_msg msg;
	struct efa_rdm_rxe_write write;
	struct efa_rdm_rxe_read_rsp read_rsp;
	struct efa_rdm_rxe_atomic atomic;
};

static inline struct efa_rdm_txe_atomic *efa_rdm_txe_atomic(struct efa_rdm_ope *txe)
{
	assert(txe->kind == EFA_RDM_TXE_KIND_ATOMIC);
	return container_of(txe, struct efa_rdm_txe_atomic, base);
}

static inline struct efa_rdm_rxe_atomic *efa_rdm_rxe_atomic(struct efa_rdm_ope *rxe)
{
	assert(rxe->kind == EFA_RDM_RXE_KIND_ATOMIC);
	return container_of(rxe, struct efa_rdm_rxe_atomic, base);
}

static inline bool efa_rdm_txe_kind_is_rma(uint8_t kind)
{
	return kind >= EFA_RDM_TXE_KIND_RMA &&
	       kind <= EFA_RDM_TXE_KIND_DEVICE_READ;
}

static inline struct efa_rdm_txe_rma *efa_rdm_txe_rma(struct efa_rdm_ope *txe)
{
	assert(efa_rdm_txe_kind_is_rma(txe->kind));
	return container_of(txe, struct efa_rdm_txe_rma, base);
}

static inline struct efa_rdm_rxe_msg *efa_rdm_rxe_msg(struct efa_rdm_ope *rxe)
{
	assert(rxe->kind == EFA_RDM_RXE_KIND_MSG ||
	       rxe->kind == EFA_RDM_RXE_KIND_MSG_READ);
	return container_of(rxe, struct efa_rdm_rxe_msg, base);
}

static inline struct efa_rdm_rxe_write *efa_rdm_rxe_write(struct efa_rdm_ope *rxe)
{
	assert(rxe->kind == EFA_RDM_RXE_KIND_WRITE ||
	       rxe->kind == EFA_RDM_RXE_KIND_WRITE_READ);
	return container_of(rxe, struct efa_rdm_rxe_write, base);
}

/**
 * @brief Whether an ope of this kind has the rma group.
 */
static inline bool efa_rdm_ope_kind_has_rma(uint8_t kind)
{
	return efa_rdm_txe_kind_is_rma(kind) ||
	       kind == EFA_RDM_TXE_KIND_ATOMIC ||
	       kind == EFA_RDM_RXE_KIND_MSG_READ ||
	       kind == EFA_RDM_RXE_KIND_WRITE_READ;
}

/**
 * @brief The remote memory of an RMA or atomic txe, or of an rxe that reads
 * its data from the sender.
 */
static inline struct efa_rdm_ope_rma *efa_rdm_ope_rma(struct efa_rdm_ope *ope)
{
	switch (ope->kind) {
	case EFA_RDM_TXE_KIND_ATOMIC:
		return &efa_rdm_txe_atomic(ope)->rma;
	case EFA_RDM_RXE_KIND_MSG_READ:
		return &efa_rdm_rxe_msg(ope)->rma;
	case EFA_RDM_RXE_KIND_WRITE_READ:
		return &efa_rdm_rxe_write(ope)->rma;
	default:
		return &efa_rdm_txe_rma(ope)->rma;
	}
}

/**
 * @brief The RDMA read progress of a device read txe, or of an rxe that reads
 * its data from the sender.
 */
static inline struct efa_rdm_ope_read *efa_rdm_ope_read(struct efa_rdm_ope *ope)
{
	switch (ope->kind) {
	case EFA_RDM_RXE_KIND_MSG_READ:
		return &efa_rdm_rxe_msg(ope)->read;
	case EFA_RDM_RXE_KIND_WRITE_READ:
		return &efa_rdm_rxe_write(ope)->read;
	default:
		assert(ope->kind == EFA_RDM_TXE_KIND_DEVICE_READ);
		return &efa_rdm_txe_rma(ope)->u.read;
	}
}

static inline struct efa_rdm_txe_msg *efa_rdm_txe_msg(struct efa_rdm_ope *txe)
{
	assert(txe->kind == EFA_RDM_TXE_KIND_MSG_EAGER ||
	       txe->kind == EFA_RDM_TXE_KIND_MSG);
	return container_of(txe, struct efa_rdm_txe_msg, base);
}

static inline struct efa_rdm_rxe_read_rsp *efa_rdm_rxe_read_rsp(struct efa_rdm_ope *rxe)
{
	assert(rxe->kind == EFA_RDM_RXE_KIND_READ_RSP);
	return container_of(rxe, struct efa_rdm_rxe_read_rsp, base);
}

/**
 * @brief Whether an ope of this kind has the sender group.
 */
static inline bool efa_rdm_ope_kind_has_sender(uint8_t kind)
{
	return kind == EFA_RDM_TXE_KIND_MSG_EAGER ||
	       kind == EFA_RDM_TXE_KIND_MSG ||
	       efa_rdm_txe_kind_is_rma(kind) ||
	       kind == EFA_RDM_RXE_KIND_READ_RSP;
}

/**
 * @brief Whether an ope of this kind has the receiver group.
 */
static inline bool efa_rdm_ope_kind_has_receiver(uint8_t kind)
{
	return kind == EFA_RDM_TXE_KIND_RMA_RECV ||
	       kind == EFA_RDM_RXE_KIND_MSG ||
	       kind == EFA_RDM_RXE_KIND_MSG_READ ||
	       kind == EFA_RDM_RXE_KIND_WRITE ||
	       kind == EFA_RDM_RXE_KIND_WRITE_READ;
}

/**
 * @brief Whether an rxe of this kind is a message rxe.
 */
static inline bool efa_rdm_rxe_kind_is_msg(uint8_t kind)
{
	return kind == EFA_RDM_RXE_KIND_MSG ||
	       kind == EFA_RDM_RXE_KIND_MSG_READ;
}

/**
 * @brief The send progress of an ope that sends a transfer's data.
 */
static inline struct efa_rdm_ope_sender *efa_rdm_ope_sender(struct efa_rdm_ope *ope)
{
	switch (ope->kind) {
	case EFA_RDM_TXE_KIND_MSG_EAGER:
	case EFA_RDM_TXE_KIND_MSG:
		return &efa_rdm_txe_msg(ope)->sender;
	case EFA_RDM_RXE_KIND_READ_RSP:
		return &efa_rdm_rxe_read_rsp(ope)->sender;
	default:
		return &efa_rdm_txe_rma(ope)->sender;
	}
}

/**
 * @brief The receive progress of an ope that receives a transfer's data.
 */
static inline struct efa_rdm_ope_receiver *efa_rdm_ope_receiver(struct efa_rdm_ope *ope)
{
	switch (ope->kind) {
	case EFA_RDM_RXE_KIND_MSG:
	case EFA_RDM_RXE_KIND_MSG_READ:
		return &efa_rdm_rxe_msg(ope)->receiver;
	case EFA_RDM_RXE_KIND_WRITE:
	case EFA_RDM_RXE_KIND_WRITE_READ:
		return &efa_rdm_rxe_write(ope)->receiver;
	default:
		assert(ope->kind == EFA_RDM_TXE_KIND_RMA_RECV);
		return &efa_rdm_txe_rma(ope)->u.receiver;
	}
}

/**
 * @brief Start the receive progress of a txe that receives its data.
 */
static inline void efa_rdm_txe_init_receiver(struct efa_rdm_ope *txe)
{
	memset(efa_rdm_ope_receiver(txe), 0, sizeof(struct efa_rdm_ope_receiver));
}

/**
 * @brief The RDMA write progress of a device write txe.
 */
static inline struct efa_rdm_ope_write *efa_rdm_txe_write(struct efa_rdm_ope *txe)
{
	assert(txe->kind == EFA_RDM_TXE_KIND_DEVICE_WRITE);
	return &efa_rdm_txe_rma(txe)->u.write;
}

/* Every bit set is reserved as an ope id that is never legal, so a peer-owned
 * id that has not been learned yet cannot be mistaken for a pool index. */
#define EFA_RDM_OPE_ID_INVALID		UINT32_MAX

/* Bit 31 of an ope id tags the kind, set for a txe id and clear for an rxe id,
 * and the 31 bits below it carry the id. */
#define EFA_RDM_OPE_ID_TAG		((uint32_t) 1 << 31)
#define EFA_RDM_OPE_ID_MASK		(~EFA_RDM_OPE_ID_TAG)

/* An rxe id spends the whole payload on its pool index, and its pool holds at
 * most as many entries as that payload can name. */
#define EFA_RDM_RXE_POOL_MAX_CNT	((size_t) EFA_RDM_OPE_ID_MASK + 1)

/* A txe id splits the payload: bits 21:0 are its pool index and bits 29:22 the
 * slot generation, which tells a live id from one that outlived the slot. That
 * leaves bit 30 unspent, which is what keeps a txe id clear of the sentinel. */
#define EFA_RDM_TXE_ID_INDEX_BITS	(22)
#define EFA_RDM_TXE_ID_INDEX_MASK \
	(((uint32_t) 1 << EFA_RDM_TXE_ID_INDEX_BITS) - 1)
#define EFA_RDM_TXE_ID_GEN_SHIFT	(EFA_RDM_TXE_ID_INDEX_BITS)
/* the generation field is exactly as wide as ope::gen, so a generation always
 * fits the field it is shifted into and never needs masking on the way in */
#define EFA_RDM_TXE_ID_GEN_MASK \
	((uint32_t) UINT8_MAX << EFA_RDM_TXE_ID_GEN_SHIFT)
#define EFA_RDM_TXE_POOL_MAX_CNT \
	((size_t) 1 << EFA_RDM_TXE_ID_INDEX_BITS)

/* Default cap on concurrent tx operations, see FI_EFA_RDM_TXE_POOL_SIZE. */
/* TODO: lower this in the future. */
#define EFA_RDM_TXE_POOL_SIZE_DEFAULT	EFA_RDM_TXE_POOL_MAX_CNT

/* Entries the txe pool starts at and grows by. */
#define EFA_RDM_TXE_POOL_CHUNK_SIZE	(8192)

static_assert((EFA_RDM_OPE_ID_INVALID & EFA_RDM_OPE_ID_TAG) != 0,
	      "the sentinel must be txe tagged so no rxe id can reach it");
static_assert(EFA_RDM_RXE_POOL_MAX_CNT - 1 <= EFA_RDM_OPE_ID_MASK,
	      "an rxe pool index must fit in the ope id payload");
static_assert((EFA_RDM_TXE_ID_GEN_MASK & EFA_RDM_TXE_ID_INDEX_MASK) == 0,
	      "a txe id's generation and index fields must not overlap");
static_assert((EFA_RDM_OPE_ID_TAG | EFA_RDM_TXE_ID_GEN_MASK |
	       EFA_RDM_TXE_ID_INDEX_MASK) < EFA_RDM_OPE_ID_INVALID,
	      "the largest txe id must stop short of the sentinel");
static_assert(EFA_RDM_TXE_POOL_SIZE_DEFAULT <= EFA_RDM_TXE_POOL_MAX_CNT,
	      "the default txe pool cap must fit in a txe id");
static_assert(sizeof(((struct efa_rdm_ope *) NULL)->gen) == sizeof(uint8_t),
	      "the generation field must match the width of ope::gen");

/**
 * @brief whether an ope id names an rxe, which is to say its tag is clear
 */
static inline bool efa_rdm_ope_id_is_rxe(uint32_t ope_id)
{
	return !(ope_id & EFA_RDM_OPE_ID_TAG);
}

/**
 * @brief pool index named by an rxe id
 */
static inline size_t efa_rdm_rxe_id_index(uint32_t rxe_id)
{
	return rxe_id & EFA_RDM_OPE_ID_MASK;
}

/**
 * @brief pool index named by a txe id
 */
static inline size_t efa_rdm_txe_id_index(uint32_t txe_id)
{
	return txe_id & EFA_RDM_TXE_ID_INDEX_MASK;
}

/**
 * @brief slot generation named by a txe id
 */
static inline uint32_t efa_rdm_txe_id_gen(uint32_t txe_id)
{
	return (txe_id & EFA_RDM_TXE_ID_GEN_MASK) >> EFA_RDM_TXE_ID_GEN_SHIFT;
}

/**
 * @brief Initialize the ope id
 */
static inline uint32_t efa_rdm_ope_get_ope_id(struct efa_rdm_ope *ope)
{
	size_t index = ofi_buf_index(ope);

	/* each index must fit the id field that will carry it */
	if (ope->type == EFA_RDM_RXE) {
		assert(index <= EFA_RDM_OPE_ID_MASK);
		return (uint32_t) index;	/* the clear tag marks it rxe */
	}

	assert(ope->type == EFA_RDM_TXE);
	assert(index <= EFA_RDM_TXE_ID_INDEX_MASK);
	return EFA_RDM_OPE_ID_TAG |
	       ((uint32_t) ope->gen << EFA_RDM_TXE_ID_GEN_SHIFT) |
	       (uint32_t) index;
}
/**
 * @brief The kind of a txe whose protocol is not chosen yet.
 */
static inline uint8_t efa_rdm_txe_kind_of_op(uint32_t op)
{
	switch (op) {
	case ofi_op_msg:
	case ofi_op_tagged:
		return EFA_RDM_TXE_KIND_MSG;
	case ofi_op_write:
	case ofi_op_read_req:
		return EFA_RDM_TXE_KIND_RMA;
	default:
		return EFA_RDM_TXE_KIND_ATOMIC;
	}
}

/**
 * @brief The kind of an rxe allocated for an op, before its protocol narrows it.
 */
static inline uint8_t efa_rdm_rxe_kind_of_op(uint32_t op)
{
	switch (op) {
	case ofi_op_msg:
	case ofi_op_tagged:
		return EFA_RDM_RXE_KIND_MSG_READ;
	case ofi_op_write:
		return EFA_RDM_RXE_KIND_WRITE_READ;
	case ofi_op_read_rsp:
		return EFA_RDM_RXE_KIND_READ_RSP;
	default:
		return EFA_RDM_RXE_KIND_ATOMIC;
	}
}

/**
 * @brief Initialize the txe fields that every TX path needs.
 *
 * Does not touch txe->mr, txe->desc or the MR generation snapshot: the
 * refactored protocol path populates those before the txe is filled, so that
 * protocol selection can attempt memory registration. Callers that have not
 * already populated them must use efa_rdm_txe_construct() instead.
 *
 * Sets txe->kind from txe->proto, which the caller sets first.
 */
void efa_rdm_txe_construct_common(struct efa_rdm_ope *txe,
				  struct efa_rdm_ep *ep,
				  struct efa_rdm_peer *peer,
				  const struct fi_msg *msg,
				  uint32_t op, uint64_t fi_flags,
				  uint32_t internal_flags);

void efa_rdm_txe_construct(struct efa_rdm_ope *txe,
			   struct efa_rdm_ep *ep,
		      	   struct efa_rdm_peer *peer,
			   const struct fi_msg *msg,
			   uint32_t op, uint64_t fi_flags,
			   uint32_t internal_flags);

void efa_rdm_txe_release(struct efa_rdm_ope *txe);

void efa_rdm_txe_continue_after_read_nack(struct efa_rdm_ope *txe);

void efa_rdm_rxe_release(struct efa_rdm_ope *rxe);

void efa_rdm_rxe_release_internal(struct efa_rdm_ope *rxe);

/* The follow flags are applied to the internal_flags field
 * of an efa_rdm_ope*/

/**
 * @brief indicate an ope's receive has been cancel
 *
 * @todo: In future we will send RECV_CANCEL signal to sender,
 * to stop transmitting large message, this flag is also
 * used for fi_discard which has similar behavior.
 */
#define EFA_RDM_RXE_RECV_CANCEL		BIT_ULL(3)

/**
 * @brief Flag to tell if the transmission is using FI_DELIVERY_COMPLETE
 * protocols
 */
#define EFA_RDM_TXE_DELIVERY_COMPLETE_REQUESTED	BIT_ULL(6)

/**
 * @brief flag to tell if an ope encouter RNR when sending packets
 *
 * If an ope has this flag, it is on the ope_queued_list
 * of the endpoint.
 */
#define EFA_RDM_OPE_QUEUED_RNR BIT_ULL(9)

/**
 * @brief Flag to indicate an rxe has an EOR or RECEIPT in flight.
 *
 * This flag is set when an EOR or RECEIPT packet has been sent or
 * queued but its send completion has not yet arrived. While set,
 * the rxe cannot be released.
 *
 * For EOR: set in efa_rdm_pke_handle_rma_read_completion,
 *          cleared in efa_rdm_pke_handle_eor_send_completion.
 * For RECEIPT: set in efa_rdm_ope_handle_recv_completed (before
 *              posting RECEIPT), cleared in
 *              efa_rdm_pke_handle_receipt_send_completion.
 */
#define EFA_RDM_RXE_ACK_IN_FLIGHT BIT_ULL(10)

/**
 * @brief The peer-abort machinery owns this ope's drain-gated cleanup.
 *
 * Set on the first peer-abort failure (rxe: efa_rdm_rxe_mark_peer_aborted_if_needed();
 * txe: the sender-side abort paths) -- one shared bit since an ope is only ever
 * one type, sticky until free. Once every WR using the ope as wr_id has drained
 * (efa_outstanding_tx_ops == 0, nothing queued), the type's drain helper writes
 * the deferred FI_ECANCELED / FI_EFA_ERR_PEER_ABORTED completion and frees the
 * ope. The rxe emits its PEER_ERROR_PKT eagerly at mark time; the txe defers the
 * emit/suppress into its drain helper.
 */
#define EFA_RDM_OPE_PEER_ABORT_PENDING BIT_ULL(20)

/**
 * @brief flag to indicate a txe has already written an cq error entry for RNR
 *
 * This flag is used to prevent writing multiple cq error entries
 * for the same txe
 */
#define EFA_RDM_TXE_WRITTEN_RNR_CQ_ERR_ENTRY BIT_ULL(10)

/**
 * @brief flag to indicate an ope has queued ctrl packet,
 *
 * If this flag is on, the op_entyr is on the ope_queued_list
 * of the endpoint
 */
#define EFA_RDM_OPE_QUEUED_CTRL BIT_ULL(11)

/**
 * @brief flag to indicate an ope has queued read requests
 *
 * When this flag is on, the ope is on ope_queued_list
 * of the endpoint
 */
#define EFA_RDM_OPE_QUEUED_READ 	BIT_ULL(12)

/**
 * @brief flag to indicate that the ope corresponds to a long CTS transfer
 * that's used as a fallback for long read protocol
 *
 */
#define EFA_RDM_OPE_READ_NACK 	BIT_ULL(13)

/**
 * @brief flag to indicate that the ope was queued because it hasn't
 * made a handshake with the peer. Because this happens before
 * EFA provider makes any protocol selection, the progress engine
 * needs to determine the protocol from the peer status when
 * progressing the queued opes.
 */
#define EFA_RDM_OPE_QUEUED_BEFORE_HANDSHAKE	BIT_ULL(14)

/**
 * @brief flag to indicate that the ope was created
 * for internal operations, so it should not generate
 * any cq entry or err entry.
 */
#define EFA_RDM_OPE_INTERNAL			BIT_ULL(15)

/**
 * @brief Flag to indicate that a txe has received a remote
 * acknowledgment (RECEIPT or ATOMRSP).
 *
 * For DC protocols: set in efa_rdm_proto_handle_receipt_recv when
 *                   the RECEIPT packet arrives from the remote.
 * For fetch/compare atomics: set in efa_rdm_pke_handle_atomrsp_recv
 *                            when the ATOMRSP packet arrives.
 *
 * The txe can only be released when both this flag is set AND all
 * outstanding TX ops have completed (efa_outstanding_tx_ops == 0).
 */
#define EFA_RDM_TXE_REMOTE_ACK_RECEIVED		BIT_ULL(16)

/**
 * @brief flag to indicate an ope does not need to report completion to user
 *
 * This flag suppresses the success CQ entry; counters are still
 * updated unless #EFA_RDM_TXE_NO_COUNTER is also set.
 *
 * It is used by emulated injection (per inject semantics, the op
 * completes without a CQ entry but still counts as a completed
 * transfer), by #efa_rdm_ep_trigger_handshake, and by the partial-post
 * error paths (see #EFA_RDM_TXE_NO_COUNTER).
 */
#define EFA_RDM_TXE_NO_COMPLETION	BIT_ULL(17)
/**
 * @brief flag to indicate an ope does not need to increase counter
 *
 * This flag suppresses the counter update; a CQ entry is still
 * written unless #EFA_RDM_TXE_NO_COMPLETION is also set.
 *
 * It is used by #efa_rdm_ep_trigger_handshake, and by the partial-post
 * error paths of efa_rdm_rma_generic_writemsg() /
 * efa_rdm_rma_generic_readmsg(): those paths report the error to the
 * app synchronously (via the return value of the data transfer call)
 * and set EFA_RDM_TXE_NO_COMPLETION | EFA_RDM_TXE_NO_COUNTER so the
 * in-flight segments' deferred completions are fully silent.
 *
 * A non-internal txe with both flags set is an op whose error was
 * already returned synchronously: efa_rdm_txe_handle_error() relies on
 * this combination to suppress the duplicate error CQ entry and error
 * counter. Inject ops set only EFA_RDM_TXE_NO_COMPLETION, so an inject
 * op that fails asynchronously still writes the error CQ entry required
 * by fi_msg(3) / fi_rma(3).
 */
#define EFA_RDM_TXE_NO_COUNTER		BIT_ULL(18)

/**
 * @brief flag to indicate that efa_rdm_ope_handle_recv_completed was called.
 *
 * For txe: this means an emulated read protocol received all data from
 * the remote. For rxe: this means all data has been received and copied
 * to the application buffer. The ope can only be released when both
 * this flag is set AND all outstanding TX ops have completed.
 */
#define EFA_RDM_OPE_RECV_COMPLETED		BIT_ULL(19)

/**
 * @brief flag to indicate the ope has already emitted its PEER_ERROR_PKT.
 */
#define EFA_RDM_PEER_ERROR_EMITTED_OR_SKIPPED	BIT_ULL(21)

/**
 * @brief flag: this txe bumped num_read_msg_in_flight.
 *
 * Set at every site that bumps the counter (LONGREAD RTM sent; first
 * segment of a tail-read RUNTREAD sent); consumed, exactly once per
 * txe, by whichever decrement site resolves the transfer first --
 * EOR, READ_NACK, or PEER_ERROR receipt, or the sender-side abort
 * path -- via efa_rdm_txe_release_read_msg_slot(). An RTM canceled before
 * its first post never set the flag.
 */
#define EFA_RDM_TXE_READ_MSG_COUNTED		BIT_ULL(22)

/**
 * @brief release this txe's num_read_msg_in_flight slot, if it holds one.
 *
 * Test-and-clears EFA_RDM_TXE_READ_MSG_COUNTED so concurrent resolution
 * paths (receiver's terminal packet vs. sender-side abort) decrement
 * exactly once between them. No-op for a txe that never bumped.
 */
void efa_rdm_txe_release_read_msg_slot(struct efa_rdm_ope *txe);

#define EFA_RDM_OPE_QUEUED_FLAGS (EFA_RDM_OPE_QUEUED_RNR | EFA_RDM_OPE_QUEUED_CTRL | EFA_RDM_OPE_QUEUED_READ | EFA_RDM_OPE_QUEUED_BEFORE_HANDSHAKE)

bool efa_rdm_ope_is_internal_atomic_response(const struct efa_rdm_ope *ope, int pkt_type);

/**
 * @brief Whether an ope is in scope for the peer-abort (MR abort) protocol.
 *
 * Only msg/tagged ops are: they own a per-peer msg_id and owe exactly one
 * terminal completion. Emulated RMA and atomic ops are not supported, and
 * device RMA needs no efa protocol cleanup.
 */
static inline bool efa_rdm_ope_is_peer_abort_capable(struct efa_rdm_ope *ope)
{
	return ope->op == ofi_op_msg || ope->op == ofi_op_tagged;
}

void efa_rdm_ope_try_fill_desc(struct efa_rdm_ope *ope, int mr_iov_start, uint64_t access);

int efa_rdm_txe_prepare_to_be_read(struct efa_rdm_ope *txe,
				    struct fi_rma_iov *read_iov);

size_t efa_rdm_ope_mulreq_total_data_size(struct efa_rdm_ope *ope, int pkt_type);

void efa_rdm_txe_handle_error(struct efa_rdm_ope *txe, int err, int prov_errno);

void efa_rdm_rxe_handle_error(struct efa_rdm_ope *rxe, int err, int prov_errno);

bool efa_rdm_rxe_mark_peer_aborted_if_needed(struct efa_rdm_ope *rxe, int prov_errno);

void efa_rdm_rxe_emit_peer_error(struct efa_rdm_ope *rxe, int prov_errno);

void efa_rdm_txe_progress_peer_abort_if_drained(struct efa_rdm_ope *txe);

void efa_rdm_rxe_release_peer_abort_if_drained(struct efa_rdm_ope *rxe);

void efa_rdm_txe_report_completion(struct efa_rdm_ope *txe);

void efa_rdm_rxe_report_completion(struct efa_rdm_ope *rxe);

void efa_rdm_ope_handle_recv_completed(struct efa_rdm_ope *ope);

void efa_rdm_ope_handle_send_completed(struct efa_rdm_ope *ope);

/**
 * @brief Check if a DC or atomic txe is ready for release.
 *
 * Used by: DC eager/medium/longcts msg/tag/write, callback-based DC_WRITE_RTA,
 *          DC CTSDATA, callback-based FETCH_RTA/COMPARE_RTA.
 *
 * These protocols require a remote acknowledgment (RECEIPT for DC,
 * ATOMRSP for fetch/compare atomics) before the txe can complete.
 * The txe is only released when both:
 * 1. The remote ack has arrived (EFA_RDM_TXE_REMOTE_ACK_RECEIVED set)
 * 2. All packet send completions have arrived (efa_outstanding_tx_ops == 0)
 *
 * @param[in] txe TX operation entry to check
 * @return true if txe is ready for release, false otherwise
 */
static inline bool efa_rdm_txe_with_remote_ack_ready_for_release(struct efa_rdm_ope *txe)
{
	return (txe->efa_outstanding_tx_ops == 0 &&
	       (txe->internal_flags & EFA_RDM_TXE_REMOTE_ACK_RECEIVED));
}

/**
 * @brief Whether none of an ope's packets are in flight and none of its work
 * is queued to be sent.
 */
static inline bool efa_rdm_ope_drained(struct efa_rdm_ope *ope)
{
	return ope->efa_outstanding_tx_ops == 0 &&
	       !(ope->internal_flags & EFA_RDM_OPE_QUEUED_FLAGS);
}

/**
 * @brief Whether all of an ope's data is acked, none of its packets are in
 * flight, and none of its work is queued to be sent.
 */
static inline bool efa_rdm_ope_send_done(struct efa_rdm_ope *ope)
{
	return ope->total_len == efa_rdm_ope_sender(ope)->bytes_acked &&
	       ope->efa_outstanding_tx_ops == 0 &&
	       !(ope->internal_flags & EFA_RDM_OPE_QUEUED_FLAGS);
}

/**
 * @brief Check if a longcts rxe is ready for release.
 *
 * Used by: CTS send completion handler for longcts msg/write
 * (both DC and non-DC).
 *
 * The rxe can only be released when all of:
 * 1. Recv completed (EFA_RDM_OPE_RECV_COMPLETED set)
 * 2. All send completions arrived (efa_outstanding_tx_ops == 0)
 * 3. For DC: no ack packet (RECEIPT) is in flight
 *    (EFA_RDM_RXE_ACK_IN_FLIGHT clear). The ACK_IN_FLIGHT check
 *    is needed because RECEIPT may be queued (not yet posted),
 *    in which case efa_outstanding_tx_ops has not been
 *    incremented yet.
 *
 * @param[in] rxe RX operation entry to check
 * @return true if rxe is ready for release, false otherwise
 */
static inline bool efa_rdm_rxe_cts_ready_for_release(struct efa_rdm_ope *rxe)
{
	return (rxe->efa_outstanding_tx_ops == 0 &&
		(rxe->internal_flags & EFA_RDM_OPE_RECV_COMPLETED) &&
		!(rxe->internal_flags & EFA_RDM_RXE_ACK_IN_FLIGHT));
}

/**
 * @brief Check if an emulated read txe is ready for release.
 *
 * Used by: SHORT_RTR and LONGCTS_RTR send completion handlers,
 *          and CTS send completion handler for emulated longcts read.
 *
 * In emulated read, the txe posts an RTR (or CTS for longcts read)
 * and then receives data from the remote. The txe can only be
 * released when both:
 * 1. Recv completed (EFA_RDM_OPE_RECV_COMPLETED set)
 * 2. All send completions arrived (efa_outstanding_tx_ops == 0)
 *
 * @param[in] txe TX operation entry to check
 * @return true if txe is ready for release, false otherwise
 */
static inline bool efa_rdm_txe_emulated_read_ready_for_release(struct efa_rdm_ope *txe)
{
	return (txe->efa_outstanding_tx_ops == 0 &&
	       (txe->internal_flags & EFA_RDM_OPE_RECV_COMPLETED));
}

int efa_rdm_ope_prepare_to_post_read(struct efa_rdm_ope *ope);

void efa_rdm_ope_prepare_to_post_write(struct efa_rdm_ope *ope);

int efa_rdm_ope_post_read(struct efa_rdm_ope *ope);

int efa_rdm_ope_post_remote_write(struct efa_rdm_ope *ope);

int efa_rdm_ope_post_remote_read_or_queue(struct efa_rdm_ope *ope);

int efa_rdm_rxe_post_local_read_or_queue(struct efa_rdm_ope *rxe,
					  size_t rx_data_offset,
					  struct efa_rdm_pke *pkt_entry,
					  char *pkt_data, size_t data_size);

ssize_t efa_rdm_ope_prepare_to_post_send(struct efa_rdm_ope *ope, int pkt_type,
					 size_t *pkt_entry_cnt,
					 size_t *pkt_entry_data_size_vec);

ssize_t efa_rdm_ope_post_send(struct efa_rdm_ope *ope, int pkt_type);

ssize_t efa_rdm_ope_post_send_or_queue(struct efa_rdm_ope *ope, int pkt_type);

ssize_t efa_rdm_ope_repost_ope_queued_before_handshake(struct efa_rdm_ope *ope);

ssize_t efa_rdm_txe_prepare_local_read_pkt_entry(struct efa_rdm_ope *txe);

int efa_rdm_ope_process_queued_ope(struct efa_rdm_ope *ope);

#endif

/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef EFA_PROTO_AV_H
#define EFA_PROTO_AV_H

#include "efa_av.h"

struct efa_rdm_ep;
struct efa_rdm_peer;

/**
 * @brief Protocol AV entry — flat layout with same field prefix as efa_av_entry
 *
 * Cache line 1 (64 bytes): hot fields
 *   [0-31]  ep_addr[32]        — TX hot (qpn@+16, qkey@+20)
 *   [32-39] ah*                — TX hot
 *   [40-47] fi_addr            — RX hot (explicit AV)
 *   [48-55] implicit_fi_addr   — RX hot (implicit AV / CQ progress)
 *   [56-63] shm_fi_addr        — SHM TX path
 *
 * Cache line 2 (cold, control path only):
 *   [64-79]  implicit_av_lru_entry
 *   [80-95]  ah_implicit_conn_list_entry
 *   [96-103] ep_peer_map*
 */
struct efa_proto_av_entry {
	uint8_t			ep_addr[EFA_EP_ADDR_LEN];
	struct efa_ah		*ah;
	fi_addr_t		fi_addr;
	fi_addr_t		implicit_fi_addr;
	fi_addr_t		shm_fi_addr;
	struct dlist_entry	implicit_av_lru_entry;
	struct dlist_entry	ah_implicit_conn_list_entry;
	struct efa_proto_av_entry_ep_peer_map_entry *ep_peer_map;
	struct efa_proto_av	*av; /* back-pointer for AH eviction path */
};

struct efa_proto_av_entry_ep_peer_map_entry {
	struct efa_rdm_ep *ep_ptr;
	struct efa_rdm_peer peer;
	UT_hash_handle hh;
};

/**
 * @brief Protocol AV — embeds efa_av as first member (castable)
 */
struct efa_proto_av {
	struct efa_av		efa_av;
	struct fid_av		*shm_rdm_av;
	struct util_av		util_av_implicit;
	struct efa_cur_reverse_av *cur_reverse_av_implicit;
	struct efa_prv_reverse_av *prv_reverse_av_implicit;
	size_t			used_implicit;
	size_t			shm_used;
	size_t			implicit_av_size;
	struct dlist_entry	implicit_av_lru_list;
	struct efa_ep_addr_hashable *evicted_peers_hashset;
};

static inline struct efa_ep_addr *
efa_proto_av_entry_ep_addr(struct efa_proto_av_entry *entry)
{
	return (struct efa_ep_addr *)entry->ep_addr;
}

/* Address lookup */
struct efa_proto_av_entry *efa_proto_av_addr_to_entry(struct efa_proto_av *av,
						      fi_addr_t fi_addr);

struct efa_proto_av_entry *efa_proto_av_addr_to_entry_implicit(
	struct efa_proto_av *av, fi_addr_t fi_addr);

/* Peer map operations */
void efa_proto_av_entry_ep_peer_map_insert(
	struct efa_proto_av_entry *entry,
	struct efa_proto_av_entry_ep_peer_map_entry *map_entry);

struct efa_rdm_peer *efa_proto_av_entry_ep_peer_map_lookup(
	struct efa_proto_av_entry *entry, struct efa_rdm_ep *ep);

void efa_proto_av_entry_ep_peer_map_remove(
	struct efa_proto_av_entry *entry, struct efa_rdm_ep *ep);

/* SHM AV operations */
int efa_proto_av_entry_rdm_insert_shm_av(struct efa_proto_av *av,
					  struct efa_proto_av_entry *entry);

void efa_proto_av_entry_rdm_deinit(struct efa_proto_av *av,
				   struct efa_proto_av_entry *entry);

/* Implicit AV LRU */
void efa_proto_av_implicit_av_lru_entry_move(struct efa_proto_av *av,
					     struct efa_proto_av_entry *entry);

/* Reverse lookup for protocol path */
fi_addr_t efa_proto_av_reverse_lookup_rdm(struct efa_proto_av *av,
					  uint16_t ahn, uint16_t qpn,
					  struct efa_rdm_pke *pkt_entry);

fi_addr_t efa_proto_av_reverse_lookup_rdm_implicit(struct efa_proto_av *av,
						   uint16_t ahn, uint16_t qpn,
						   struct efa_rdm_pke *pkt_entry);

/* Entry alloc/release */
struct efa_proto_av_entry *efa_proto_av_entry_alloc(
	struct efa_proto_av *av, struct efa_ep_addr *raw_addr,
	uint64_t flags, void *context, bool insert_shm_av,
	bool insert_implicit_av);

void efa_proto_av_entry_release(struct efa_proto_av *av,
				struct efa_proto_av_entry *entry,
				bool release_from_implicit_av);

void efa_proto_av_entry_release_ah_unsafe(struct efa_proto_av *av,
					  struct efa_proto_av_entry *entry,
					  bool release_from_implicit_av);

/* Implicit to explicit migration */
int efa_proto_av_entry_implicit_to_explicit(struct efa_proto_av *av,
					    struct efa_ep_addr *raw_addr,
					    fi_addr_t implicit_fi_addr,
					    fi_addr_t *fi_addr);

/* AV open/close/insert/remove for protocol path */
int efa_proto_av_open(struct fid_domain *domain_fid, struct fi_av_attr *attr,
		      struct fid_av **av_fid, void *context);

int efa_proto_av_insert_one(struct efa_proto_av *av, struct efa_ep_addr *addr,
			    fi_addr_t *fi_addr, uint64_t flags, void *context,
			    bool insert_shm_av, bool insert_implicit_av);

#endif

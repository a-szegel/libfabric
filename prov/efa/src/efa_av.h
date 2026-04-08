/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef EFA_AV_H
#define EFA_AV_H

#include <infiniband/verbs.h>
#include "efa_ah.h"

#define EFA_MIN_AV_SIZE (16384)
#define EFA_SHM_MAX_AV_COUNT       (256)

struct efa_ep_addr {
	uint8_t			raw[EFA_GID_LEN];
	uint16_t		qpn;
	uint16_t		pad;
	uint32_t		qkey;
	struct efa_ep_addr	*next;
};

struct efa_ep_addr_hashable {
	struct efa_ep_addr addr;
	UT_hash_handle	hh;
};

#define EFA_EP_ADDR_LEN sizeof(struct efa_ep_addr)

/**
 * @brief Base AV entry (efa-direct), 48 bytes, single cache line
 *
 * util_av requires ep_addr to be the first element.
 */
struct efa_av_entry {
	uint8_t			ep_addr[EFA_EP_ADDR_LEN]; /* 32B; must be first (util_av) */
	struct efa_ah		*ah;                       /* 8B — TX hot */
	fi_addr_t		fi_addr;                   /* 8B — RX hot */
};

/**
 * @brief Typed accessor — avoids raw casts everywhere
 */
static inline struct efa_ep_addr *efa_av_entry_ep_addr(struct efa_av_entry *entry)
{
	return (struct efa_ep_addr *)entry->ep_addr;
}

struct efa_cur_reverse_av_key {
	uint16_t ahn;
	uint16_t qpn;
};

struct efa_cur_reverse_av {
	struct efa_cur_reverse_av_key key;
	struct efa_av_entry *av_entry;
	UT_hash_handle hh;
};

struct efa_prv_reverse_av_key {
	uint16_t ahn;
	uint16_t qpn;
	uint32_t connid;
};

struct efa_prv_reverse_av {
	struct efa_prv_reverse_av_key key;
	struct efa_av_entry *av_entry;
	UT_hash_handle hh;
};

/**
 * @brief Base AV — contains only what efa-direct needs
 */
struct efa_av {
	struct efa_domain *domain;
	size_t used;
	enum fi_av_type type;
	/* cur_reverse_av is a map from (ahn + qpn) to current (latest) efa_av_entry.
	 * prv_reverse_av is a map from (ahn + qpn + connid) to all previous efa_av_entries.
	 * cur_reverse_av is faster to search because its key size is smaller
	 */
	struct efa_cur_reverse_av *cur_reverse_av;
	struct efa_prv_reverse_av *prv_reverse_av;
	struct util_av util_av;
};

int efa_av_open(struct fid_domain *domain_fid, struct fi_av_attr *attr,
		struct fid_av **av_fid, void *context);

int efa_av_init_util_av(struct efa_domain *efa_domain,
			struct fi_av_attr *attr,
			struct util_av *util_av,
			void *context,
			size_t context_len);

struct efa_av_entry *efa_av_addr_to_entry(struct efa_av *av, fi_addr_t fi_addr);

fi_addr_t efa_av_reverse_lookup(struct efa_av *av, uint16_t ahn, uint16_t qpn);

int efa_av_reverse_av_add(struct efa_av *av,
			  struct efa_cur_reverse_av **cur_reverse_av,
			  struct efa_prv_reverse_av **prv_reverse_av,
			  struct efa_av_entry *av_entry);

void efa_av_reverse_av_remove(struct efa_cur_reverse_av **cur_reverse_av,
			      struct efa_prv_reverse_av **prv_reverse_av,
			      struct efa_av_entry *av_entry);

#endif

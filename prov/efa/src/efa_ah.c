/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright (c) 2016, Cisco Systems, Inc. All rights reserved. */
/* SPDX-FileCopyrightText: Copyright (c) 2013-2015 Intel Corporation, Inc.  All rights reserved. */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa.h"
#include "efa_ah.h"
#include <infiniband/efadv.h>

/**
 * @brief allocate an ibv_ah from GID, reusing existing AH if possible
 *
 * Uses a hash map to store GID to ibv_ah mapping and reuses ibv_ah for
 * the same GID. If ibv_create_ah fails, returns NULL with errno set.
 * The caller is responsible for handling ENOMEM (e.g. by evicting AH
 * entries and retrying).
 *
 * @param[in]	domain		efa domain
 * @param[in]	gid		GID
 * @param[in]	alloc_size	size to allocate (sizeof(efa_ah) or larger for protocol wrapper)
 * @return	pointer to efa_ah on success, NULL on failure (errno set)
 */
struct efa_ah *efa_ah_alloc(struct efa_domain *domain, const uint8_t *gid,
			    size_t alloc_size)
{
	struct ibv_pd *ibv_pd = domain->ibv_pd;
	struct efa_ah *efa_ah;
	struct ibv_ah_attr ibv_ah_attr = { 0 };
	struct efadv_ah_attr efa_ah_attr = { 0 };
	int err;

	assert(alloc_size >= sizeof(struct efa_ah));

	efa_ah = NULL;

	ofi_genlock_lock(&domain->util_domain.lock);
	HASH_FIND(hh, domain->ah_map, gid, EFA_GID_LEN, efa_ah);
	if (efa_ah) {
		efa_ah->refcnt++;
		ofi_genlock_unlock(&domain->util_domain.lock);
		return efa_ah;
	}

	efa_ah = calloc(1, alloc_size);
	if (!efa_ah) {
		errno = FI_ENOMEM;
		EFA_WARN(FI_LOG_AV, "cannot allocate memory for efa_ah\n");
		ofi_genlock_unlock(&domain->util_domain.lock);
		return NULL;
	}

	ibv_ah_attr.port_num = 1;
	ibv_ah_attr.is_global = 1;
	memcpy(ibv_ah_attr.grh.dgid.raw, gid, EFA_GID_LEN);
	efa_ah->ibv_ah = ibv_create_ah(ibv_pd, &ibv_ah_attr);
	if (!efa_ah->ibv_ah) {
		EFA_WARN(FI_LOG_AV,
			 "ibv_create_ah failed! errno: %d\n", errno);
		goto err_free;
	}

	err = efadv_query_ah(efa_ah->ibv_ah, &efa_ah_attr, sizeof(efa_ah_attr));
	if (err) {
		errno = err;
		EFA_WARN(FI_LOG_AV, "efadv_query_ah failed! err: %d\n", err);
		goto err_destroy_ibv_ah;
	}

	efa_ah->refcnt = 1;
	efa_ah->ahn = efa_ah_attr.ahn;
	memcpy(efa_ah->gid, gid, EFA_GID_LEN);
	HASH_ADD(hh, domain->ah_map, gid, EFA_GID_LEN, efa_ah);
	ofi_genlock_unlock(&domain->util_domain.lock);
	return efa_ah;

err_destroy_ibv_ah:
	ibv_destroy_ah(efa_ah->ibv_ah);
err_free:
	free(efa_ah);
	ofi_genlock_unlock(&domain->util_domain.lock);
	return NULL;
}

/**
 * @brief destroy an efa_ah (remove from hash, destroy ibv_ah, free)
 *
 * Caller must hold util_domain.lock.
 *
 * @param[in]	domain	efa domain
 * @param[in]	ah	efa_ah to destroy
 */
void efa_ah_destroy(struct efa_domain *domain, struct efa_ah *ah)
{
	int err;

	assert(ah->refcnt == 0);

	EFA_INFO(FI_LOG_AV, "Destroying AH for ahn %d\n", ah->ahn);
	HASH_DEL(domain->ah_map, ah);

	err = ibv_destroy_ah(ah->ibv_ah);
	if (err)
		EFA_WARN(FI_LOG_AV, "ibv_destroy_ah failed! err=%d\n", err);
	free(ah);
}

/**
 * @brief release an efa_ah, destroying it when refcount reaches zero
 *
 * @param[in]	domain	efa domain
 * @param[in]	ah	efa_ah to release
 */
void efa_ah_release(struct efa_domain *domain, struct efa_ah *ah)
{
	ofi_genlock_lock(&domain->util_domain.lock);

	assert(ah->refcnt > 0);
	ah->refcnt--;

	if (ah->refcnt == 0)
		efa_ah_destroy(domain, ah);

	ofi_genlock_unlock(&domain->util_domain.lock);
}

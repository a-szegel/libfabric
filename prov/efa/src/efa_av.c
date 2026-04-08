/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright (c) 2016, Cisco Systems, Inc. All rights reserved. */
/* SPDX-FileCopyrightText: Copyright (c) 2013-2015 Intel Corporation, Inc.  All rights reserved. */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include <malloc.h>
#include <stdio.h>

#include <infiniband/efadv.h>
#include <ofi_enosys.h>

#include "efa.h"
#include "efa_av.h"

/**
 * @brief find efa_av_entry using fi_addr in the given util_av
 */
static inline struct efa_av_entry *
efa_av_addr_to_entry_impl(struct util_av *util_av, fi_addr_t fi_addr)
{
	struct util_av_entry *util_av_entry;
	struct efa_av_entry *av_entry;

	if (OFI_UNLIKELY(fi_addr == FI_ADDR_UNSPEC || fi_addr == FI_ADDR_NOTAVAIL))
		return NULL;

	if (OFI_LIKELY(ofi_bufpool_ibuf_is_valid(util_av->av_entry_pool, fi_addr)))
		util_av_entry = ofi_bufpool_get_ibuf(util_av->av_entry_pool, fi_addr);
	else
		return NULL;

	av_entry = (struct efa_av_entry *)util_av_entry->data;
	return efa_av_entry_ep_addr(av_entry)->qpn ? av_entry : NULL;
}

/**
 * @brief find efa_av_entry using fi_addr in the explicit AV
 */
struct efa_av_entry *efa_av_addr_to_entry(struct efa_av *av, fi_addr_t fi_addr)
{
	return efa_av_addr_to_entry_impl(&av->util_av, fi_addr);
}

/**
 * @brief find fi_addr for efa endpoint (base, AHN+QPN only)
 */
fi_addr_t efa_av_reverse_lookup(struct efa_av *av, uint16_t ahn, uint16_t qpn)
{
	struct efa_cur_reverse_av *cur_entry;
	struct efa_cur_reverse_av_key cur_key;

	memset(&cur_key, 0, sizeof(cur_key));
	cur_key.ahn = ahn;
	cur_key.qpn = qpn;
	HASH_FIND(hh, av->cur_reverse_av, &cur_key, sizeof(cur_key), cur_entry);

	return (OFI_LIKELY(!!cur_entry)) ? cur_entry->av_entry->fi_addr : FI_ADDR_NOTAVAIL;
}

static inline int efa_av_is_valid_address(struct efa_ep_addr *addr)
{
	struct efa_ep_addr all_zeros = { 0 };

	return memcmp(addr->raw, all_zeros.raw, sizeof(addr->raw));
}

/*
 * @brief Add newly inserted address to the reverse AVs
 */
int efa_av_reverse_av_add(struct efa_av *av,
			  struct efa_cur_reverse_av **cur_reverse_av,
			  struct efa_prv_reverse_av **prv_reverse_av,
			  struct efa_av_entry *av_entry)
{
	struct efa_cur_reverse_av *cur_entry;
	struct efa_prv_reverse_av *prv_entry;
	struct efa_cur_reverse_av_key cur_key;

	memset(&cur_key, 0, sizeof(cur_key));
	cur_key.ahn = av_entry->ah->ahn;
	cur_key.qpn = efa_av_entry_ep_addr(av_entry)->qpn;
	cur_entry = NULL;

	HASH_FIND(hh, *cur_reverse_av, &cur_key, sizeof(cur_key), cur_entry);
	if (!cur_entry) {
		cur_entry = malloc(sizeof(*cur_entry));
		if (!cur_entry) {
			EFA_WARN(FI_LOG_AV, "Cannot allocate memory for cur_reverse_av entry\n");
			return -FI_ENOMEM;
		}

		cur_entry->key.ahn = cur_key.ahn;
		cur_entry->key.qpn = cur_key.qpn;
		cur_entry->av_entry = av_entry;
		HASH_ADD(hh, *cur_reverse_av, key, sizeof(cur_key), cur_entry);

		return 0;
	}

	/* Only RDM endpoint can reach here (dgram uses static connid) */
	prv_entry = malloc(sizeof(*prv_entry));
	if (!prv_entry) {
		EFA_WARN(FI_LOG_AV, "Cannot allocate memory for prv_reverse_av entry\n");
		return -FI_ENOMEM;
	}

	prv_entry->key.ahn = cur_key.ahn;
	prv_entry->key.qpn = cur_key.qpn;
	prv_entry->key.connid = efa_av_entry_ep_addr(cur_entry->av_entry)->qkey;
	prv_entry->av_entry = cur_entry->av_entry;
	HASH_ADD(hh, *prv_reverse_av, key, sizeof(prv_entry->key), prv_entry);

	cur_entry->av_entry = av_entry;
	return 0;
}

/*
 * @brief Remove an address from the reverse AVs
 */
void efa_av_reverse_av_remove(struct efa_cur_reverse_av **cur_reverse_av,
			      struct efa_prv_reverse_av **prv_reverse_av,
			      struct efa_av_entry *av_entry)
{
	struct efa_cur_reverse_av *cur_reverse_av_entry;
	struct efa_prv_reverse_av *prv_reverse_av_entry;
	struct efa_cur_reverse_av_key cur_key;
	struct efa_prv_reverse_av_key prv_key;

	memset(&cur_key, 0, sizeof(cur_key));
	cur_key.ahn = av_entry->ah->ahn;
	cur_key.qpn = efa_av_entry_ep_addr(av_entry)->qpn;
	HASH_FIND(hh, *cur_reverse_av, &cur_key, sizeof(cur_key),
		  cur_reverse_av_entry);
	if (cur_reverse_av_entry) {
		HASH_DEL(*cur_reverse_av, cur_reverse_av_entry);
		free(cur_reverse_av_entry);
	} else {
		memset(&prv_key, 0, sizeof(prv_key));
		prv_key.ahn = av_entry->ah->ahn;
		prv_key.qpn = efa_av_entry_ep_addr(av_entry)->qpn;
		prv_key.connid = efa_av_entry_ep_addr(av_entry)->qkey;
		HASH_FIND(hh, *prv_reverse_av, &prv_key, sizeof(prv_key),
			  prv_reverse_av_entry);
		assert(prv_reverse_av_entry);
		HASH_DEL(*prv_reverse_av, prv_reverse_av_entry);
		free(prv_reverse_av_entry);
	}
}

/**
 * @brief Initialize an efa_av_entry (base path)
 *
 * Caller must hold util_av.lock.
 */
static struct efa_av_entry *efa_av_entry_init(struct efa_av *av,
					      struct efa_ep_addr *raw_addr,
					      uint64_t flags, void *context)
{
	struct util_av_entry *util_av_entry = NULL;
	struct efa_av_entry *av_entry = NULL;
	fi_addr_t fi_addr;
	int err;

	assert(ofi_genlock_held(&av->util_av.lock));

	if (flags & FI_SYNC_ERR)
		memset(context, 0, sizeof(int));

	err = ofi_av_insert_addr(&av->util_av, raw_addr, &fi_addr);
	if (err) {
		EFA_WARN(FI_LOG_AV, "ofi_av_insert_addr failed! Error message: %s\n",
			 fi_strerror(err));
		return NULL;
	}

	util_av_entry = ofi_bufpool_get_ibuf(av->util_av.av_entry_pool, fi_addr);
	av_entry = (struct efa_av_entry *)util_av_entry->data;
	assert(efa_is_same_addr(raw_addr, (struct efa_ep_addr *)av_entry->ep_addr));

	av_entry->fi_addr = fi_addr;
	assert(av->type == FI_AV_TABLE);

	av_entry->ah = efa_ah_alloc(av->domain, raw_addr->raw, false);
	if (!av_entry->ah)
		goto err_release;

	err = efa_av_reverse_av_add(av, &av->cur_reverse_av, &av->prv_reverse_av,
				    av_entry);
	if (err)
		goto err_release_ah;

	av->used++;
	return av_entry;

err_release_ah:
	efa_ah_release(av->domain, av_entry->ah, false);
err_release:
	memset(av_entry->ep_addr, 0, EFA_EP_ADDR_LEN);
	err = ofi_av_remove_addr(&av->util_av, fi_addr);
	if (err)
		EFA_WARN(FI_LOG_AV, "While processing previous failure, ofi_av_remove_addr failed! err=%d\n",
			 err);
	return NULL;
}

/**
 * @brief Release an efa_av_entry (base path)
 *
 * Caller must hold util_av.lock.
 */
static void efa_av_entry_release(struct efa_av *av, struct efa_av_entry *av_entry)
{
	char gidstr[INET6_ADDRSTRLEN];
	int err;

	assert(ofi_genlock_held(&av->util_av.lock));

	efa_av_reverse_av_remove(&av->cur_reverse_av, &av->prv_reverse_av, av_entry);
	efa_ah_release(av->domain, av_entry->ah, false);

	inet_ntop(AF_INET6, efa_av_entry_ep_addr(av_entry)->raw, gidstr, INET6_ADDRSTRLEN);
	EFA_INFO(FI_LOG_AV, "efa_av_entry released! entry[%p] GID[%s] QP[%u]\n",
		 av_entry, gidstr, efa_av_entry_ep_addr(av_entry)->qpn);

	err = ofi_av_remove_addr(&av->util_av, av_entry->fi_addr);
	if (err)
		EFA_WARN(FI_LOG_AV, "ofi_av_remove_addr failed! err=%d\n", err);

	memset(av_entry->ep_addr, 0, EFA_EP_ADDR_LEN);
	av->used--;
}

/**
 * @brief insert one address into AV (base, efa-direct path)
 */
static int efa_av_insert_one(struct efa_av *av, struct efa_ep_addr *addr,
			     fi_addr_t *fi_addr, uint64_t flags, void *context)
{
	struct efa_av_entry *av_entry;
	char raw_gid_str[INET6_ADDRSTRLEN];
	fi_addr_t efa_fiaddr;

	if (!efa_av_is_valid_address(addr)) {
		EFA_WARN(FI_LOG_AV, "Failed to insert bad addr\n");
		*fi_addr = FI_ADDR_NOTAVAIL;
		return -FI_EADDRNOTAVAIL;
	}

	addr->qkey = EFA_DGRAM_CONNID;

	ofi_genlock_lock(&av->util_av.lock);

	memset(raw_gid_str, 0, sizeof(raw_gid_str));
	if (!inet_ntop(AF_INET6, addr->raw, raw_gid_str, INET6_ADDRSTRLEN)) {
		EFA_WARN(FI_LOG_AV, "cannot convert address to string. errno: %d\n", errno);
		*fi_addr = FI_ADDR_NOTAVAIL;
		ofi_genlock_unlock(&av->util_av.lock);
		return -FI_EINVAL;
	}

	EFA_INFO(FI_LOG_AV,
		 "Inserting address GID[%s] QP[%u] QKEY[%u] to explicit AV ....\n",
		 raw_gid_str, addr->qpn, addr->qkey);

	/* Check if already inserted */
	efa_fiaddr = ofi_av_lookup_fi_addr_unsafe(&av->util_av, addr);
	if (efa_fiaddr != FI_ADDR_NOTAVAIL) {
		EFA_INFO(FI_LOG_AV, "Found existing AV entry pointing to this address! fi_addr: %ld\n", efa_fiaddr);
		*fi_addr = efa_fiaddr;
		ofi_genlock_unlock(&av->util_av.lock);
		return 0;
	}

	av_entry = efa_av_entry_init(av, addr, flags, context);
	if (!av_entry) {
		*fi_addr = FI_ADDR_NOTAVAIL;
		ofi_genlock_unlock(&av->util_av.lock);
		return -FI_EADDRNOTAVAIL;
	}

	*fi_addr = av_entry->fi_addr;
	EFA_INFO(FI_LOG_AV,
		 "Successfully inserted address GID[%s] QP[%u] QKEY[%u] to explicit AV. fi_addr: %ld\n",
		 raw_gid_str, addr->qpn, addr->qkey, *fi_addr);

	ofi_genlock_unlock(&av->util_av.lock);
	return 0;
}

static int efa_av_insert(struct fid_av *av_fid, const void *addr,
			 size_t count, fi_addr_t *fi_addr,
			 uint64_t flags, void *context)
{
	struct efa_av *av = container_of(av_fid, struct efa_av, util_av.av_fid);
	int ret = 0, success_cnt = 0;
	size_t i = 0;
	struct efa_ep_addr *addr_i;
	fi_addr_t fi_addr_res;

	if (av->util_av.flags & FI_EVENT)
		return -FI_ENOEQ;

	if ((flags & FI_SYNC_ERR) && (!context || (flags & FI_EVENT)))
		return -FI_EINVAL;

	flags &= ~FI_MORE;
	if (flags)
		return -FI_ENOSYS;

	for (i = 0; i < count; i++) {
		addr_i = (struct efa_ep_addr *) ((uint8_t *)addr + i * EFA_EP_ADDR_LEN);

		ret = efa_av_insert_one(av, addr_i, &fi_addr_res, flags, context);
		if (ret) {
			EFA_WARN(FI_LOG_AV, "insert raw_addr to av failed! ret=%d\n", ret);
			break;
		}

		if (fi_addr)
			fi_addr[i] = fi_addr_res;
		success_cnt++;
	}

	for (; i < count ; i++) {
		if (fi_addr)
			fi_addr[i] = FI_ADDR_NOTAVAIL;
	}

	return success_cnt;
}

static int efa_av_lookup(struct fid_av *av_fid, fi_addr_t fi_addr,
			 void *addr, size_t *addrlen)
{
	struct efa_av *av = container_of(av_fid, struct efa_av, util_av.av_fid);
	struct efa_av_entry *av_entry = NULL;

	if (av->type != FI_AV_TABLE)
		return -FI_EINVAL;

	if (fi_addr == FI_ADDR_NOTAVAIL)
		return -FI_EINVAL;

	ofi_genlock_lock(&av->util_av.lock);
	av_entry = efa_av_addr_to_entry(av, fi_addr);
	ofi_genlock_unlock(&av->util_av.lock);
	if (!av_entry)
		return -FI_EINVAL;

	memcpy(addr, (void *)av_entry->ep_addr, MIN(EFA_EP_ADDR_LEN, *addrlen));
	if (*addrlen > EFA_EP_ADDR_LEN)
		*addrlen = EFA_EP_ADDR_LEN;
	return 0;
}

static int efa_av_remove(struct fid_av *av_fid, fi_addr_t *fi_addr,
			 size_t count, uint64_t flags)
{
	int err = 0;
	size_t i;
	struct efa_av *av;
	struct efa_av_entry *av_entry;

	if (!fi_addr)
		return -FI_EINVAL;

	av = container_of(av_fid, struct efa_av, util_av.av_fid);
	if (av->type != FI_AV_TABLE)
		return -FI_EINVAL;

	ofi_genlock_lock(&av->util_av.lock);
	for (i = 0; i < count; i++) {
		av_entry = efa_av_addr_to_entry(av, fi_addr[i]);
		if (!av_entry) {
			err = -FI_EINVAL;
			break;
		}

		efa_av_entry_release(av, av_entry);
	}

	if (i < count)
		assert(err);

	ofi_genlock_unlock(&av->util_av.lock);
	return err;
}

static const char *efa_av_straddr(struct fid_av *av_fid, const void *addr,
				  char *buf, size_t *len)
{
	return ofi_straddr(buf, len, FI_ADDR_EFA, addr);
}

static struct fi_ops_av efa_av_ops = {
	.size = sizeof(struct fi_ops_av),
	.insert = efa_av_insert,
	.insertsvc = fi_no_av_insertsvc,
	.insertsym = fi_no_av_insertsym,
	.remove = efa_av_remove,
	.lookup = efa_av_lookup,
	.straddr = efa_av_straddr
};

static int efa_av_close(struct fid *fid)
{
	struct efa_av *av;
	struct efa_cur_reverse_av *cur_entry, *curtmp;
	struct efa_prv_reverse_av *prv_entry, *prvtmp;
	int err = 0;

	av = container_of(fid, struct efa_av, util_av.av_fid.fid);

	ofi_genlock_lock(&av->util_av.lock);

	HASH_ITER(hh, av->cur_reverse_av, cur_entry, curtmp) {
		efa_av_entry_release(av, cur_entry->av_entry);
	}

	HASH_ITER(hh, av->prv_reverse_av, prv_entry, prvtmp) {
		efa_av_entry_release(av, prv_entry->av_entry);
	}

	ofi_genlock_unlock(&av->util_av.lock);

	err = ofi_av_close(&av->util_av);
	if (OFI_UNLIKELY(err))
		EFA_WARN(FI_LOG_AV, "Failed to close util av: %s\n",
			fi_strerror(err));

	free(av);
	return err;
}

static struct fi_ops efa_av_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = efa_av_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

/**
 * @brief initialize a util_av
 */
int efa_av_init_util_av(struct efa_domain *efa_domain,
			struct fi_av_attr *attr,
			struct util_av *util_av,
			void *context,
			size_t context_len)
{
	struct util_av_attr util_attr;

	util_attr.addrlen = EFA_EP_ADDR_LEN;
	util_attr.context_len = context_len;
	util_attr.flags = 0;
	return ofi_av_init(&efa_domain->util_domain, attr, &util_attr,
			   util_av, context);
}

int efa_av_open(struct fid_domain *domain_fid, struct fi_av_attr *attr,
		struct fid_av **av_fid, void *context)
{
	struct efa_domain *efa_domain;
	struct efa_av *av;
	int ret, retv;

	if (!attr)
		return -FI_EINVAL;

	if (attr->name)
		return -FI_ENOSYS;

	if (attr->flags)
		return -FI_ENOSYS;

	if (!attr->count)
		attr->count = EFA_MIN_AV_SIZE;
	else
		attr->count = MAX(attr->count, EFA_MIN_AV_SIZE);

	av = calloc(1, sizeof(*av));
	if (!av)
		return -FI_ENOMEM;

	if (attr->type == FI_AV_MAP) {
		EFA_INFO(FI_LOG_AV, "FI_AV_MAP is deprecated in Libfabric 2.x. Please use FI_AV_TABLE. "
					"EFA provider will now switch to using FI_AV_TABLE.\n");
	}
	attr->type = FI_AV_TABLE;

	efa_domain = container_of(domain_fid, struct efa_domain, util_domain.domain_fid);

	{
		size_t universe_size;
		if (fi_param_get_size_t(NULL, "universe_size",
					&universe_size) == FI_SUCCESS)
			attr->count = MAX(attr->count, universe_size);
	}

	ret = efa_av_init_util_av(efa_domain, attr, &av->util_av, context,
				  sizeof(struct efa_av_entry) - EFA_EP_ADDR_LEN);
	if (ret)
		goto err;

	EFA_INFO(FI_LOG_AV, "fi_av_attr:%" PRId64 "\n", attr->flags);

	av->domain = efa_domain;
	av->type = attr->type;
	av->used = 0;

	*av_fid = &av->util_av.av_fid;
	(*av_fid)->fid.fclass = FI_CLASS_AV;
	(*av_fid)->fid.context = context;
	(*av_fid)->fid.ops = &efa_av_fi_ops;
	(*av_fid)->ops = &efa_av_ops;

	return 0;

err:
	free(av);
	return ret;
}

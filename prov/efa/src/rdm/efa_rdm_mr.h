/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef EFA_RDM_MR_H
#define EFA_RDM_MR_H

#include "efa_mr.h"
#include <stddef.h>

struct efa_rdm_mr {
	struct efa_mr		efa_mr;
	bool			inserted_to_mr_map;
	bool			needs_sync;
	/* RDM-specific HMEM data handle */
	void			*hmem_data;
	/* RDM-specific flags */
	uint64_t		flags;
	uint64_t		device;
	/* Used only in MR cache */
	struct ofi_mr_entry	*entry;
	/* Used only in rdm */
	struct fid_mr		*shm_mr;
	/*
	 * Monotonic generation counter bumped on every close.
	 * Preserved across bufpool slot reuse so that in-flight ops
	 * that captured a stale desc can detect the invalidation and
	 * be canceled early.
	 */
	uint32_t		gen;
};

/* Compile-time assertion to ensure safe casting between efa_mr and efa_rdm_mr */
_Static_assert(offsetof(struct efa_rdm_mr, efa_mr) == 0,
               "efa_mr must be the first member of efa_rdm_mr for safe casting");

			   /* RDM specific extern declarations */
extern struct fi_ops_mr efa_domain_mr_cache_ops;
extern int efa_mr_cache_enable;
extern size_t efa_mr_max_cached_count;
extern size_t efa_mr_max_cached_size;
extern struct fi_ops_mr efa_rdm_domain_mr_ops;

/*
 * Multiplier to give some room in the device memory registration limits
 * to allow processes added to a running job to bootstrap.
 */
#define EFA_MR_CACHE_LIMIT_MULT (.9)

/* RDM MR cache functions */
int efa_rdm_mr_cache_open(struct ofi_mr_cache **cache, struct efa_domain *domain);
int efa_rdm_mr_cache_entry_reg(struct ofi_mr_cache *cache,
			       struct ofi_mr_entry *entry);
void efa_rdm_mr_cache_entry_dereg(struct ofi_mr_cache *cache,
				  struct ofi_mr_entry *entry);
int efa_rdm_mr_cache_regv(struct fid_domain *domain_fid, const struct iovec *iov,
			  size_t count, uint64_t access, uint64_t offset,
			  uint64_t requested_key, uint64_t flags,
			  struct fid_mr **mr, void *context);

/**
 * @brief Capture the gen of each efa_rdm_mr in ope->desc[].
 *
 * Must be called after ope->desc[] and ope->iov_count are populated.
 */
static inline void efa_rdm_mr_gen_capture_in_ope_desc(struct efa_rdm_ope *ope)
{
	struct efa_rdm_mr *efa_rdm_mr;
	unsigned int i;

	for (i = 0; i < ope->iov_count; i++) {
		/* We statically assert that efa_mr is first member of efa_rdm_mr */
		efa_rdm_mr = (struct efa_rdm_mr *)ope->desc[i];
		/*
		 * desc[i] can be NULL when the application did not provide memory
		 * descriptors (relying on the provider's MR cache to register
		 * internally). The capture is called in efa_rdm_txe_construct
		 * (where descs may still be NULL) and again at the end of
		 * efa_rdm_ope_try_fill_desc (after NULL slots are filled).
		 * Skip NULL entries here; they will be captured on the second call.
		 */
		if (efa_rdm_mr)
			ope->desc_gen[i] = efa_rdm_mr->gen;
	}
}

#endif /* EFA_RDM_MR_H */

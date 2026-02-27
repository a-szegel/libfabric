/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <string.h>
#include <strings.h>

#define EFA_DIRECT_FABRIC_NAME "efa-direct"
#define MR_MODE_BITS (FI_MR_LOCAL | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_VIRT_ADDR)

struct fi_info *efa_unit_test_alloc_hints(enum fi_ep_type ep_type, char *fabric_name)
{
	struct fi_info *hints;

	hints = fi_allocinfo();
	if (!hints)
		return NULL;

	if (fabric_name)
		hints->fabric_attr->name = strdup(fabric_name);
	hints->ep_attr->type = ep_type;

	/* Use a minimal caps that efa / efa-direct should always support */
	hints->domain_attr->mr_mode = MR_MODE_BITS;

	/* EFA direct and dgram paths require FI_CONTEXT2 */
	if (!fabric_name || !strcasecmp(fabric_name, EFA_DIRECT_FABRIC_NAME))
		hints->mode |= FI_CONTEXT2;

	if (ep_type == FI_EP_DGRAM) {
		hints->mode |= FI_MSG_PREFIX | FI_CONTEXT2;
	}

	return hints;
}

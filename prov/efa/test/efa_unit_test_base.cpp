/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_base.h"

extern "C" {
#include <rdma/fi_errno.h>
}

using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;
using ::testing::SetArgPointee;

void EfaUnitTest::SetUp()
{
	rdma_mock = new ::testing::NiceMock<RdmaCoreMock>();
	g_rdma_core_mock = rdma_mock;

	memset(&resource, 0, sizeof(resource));

	// Set default mock behaviors
	ON_CALL(*rdma_mock, ibv_get_device_list(_))
		.WillByDefault(Return(nullptr));
}

void EfaUnitTest::TearDown()
{
	DestructResource();

	delete rdma_mock;
	g_rdma_core_mock = nullptr;
}

void EfaUnitTest::ConstructResource(enum fi_ep_type ep_type, const char *fabric_name)
{
	// Minimal mock setup - tests override as needed
}

void EfaUnitTest::ConstructResourceEpNotEnabled(enum fi_ep_type ep_type, const char *fabric_name)
{
	ConstructResource(ep_type, fabric_name);
}

void EfaUnitTest::DestructResource()
{
	if (resource.cq) fi_close(&resource.cq->fid);
	if (resource.av) fi_close(&resource.av->fid);
	if (resource.eq) fi_close(&resource.eq->fid);
	if (resource.ep) fi_close(&resource.ep->fid);
	if (resource.domain) fi_close(&resource.domain->fid);
	if (resource.fabric) fi_close(&resource.fabric->fid);
	if (resource.info) fi_freeinfo(resource.info);
	if (resource.hints) fi_freeinfo(resource.hints);

	memset(&resource, 0, sizeof(resource));
}

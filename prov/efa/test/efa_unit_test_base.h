/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef EFA_UNIT_TEST_BASE_H
#define EFA_UNIT_TEST_BASE_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "rdma_core_mocks.h"

extern "C" {
#include "efa.h"
}

struct efa_resource {
	struct fi_info *hints;
	struct fi_info *info;
	struct fid_fabric *fabric;
	struct fid_domain *domain;
	struct fid_ep *ep;
	struct fid_eq *eq;
	struct fid_av *av;
	struct fid_cq *cq;
};

class EfaUnitTest : public ::testing::Test {
protected:
	void SetUp() override;
	void TearDown() override;

	// Mock objects
	::testing::NiceMock<RdmaCoreMock>* rdma_mock;

	// Test resource
	struct efa_resource resource;

	// Helper methods
	void ConstructResource(enum fi_ep_type ep_type, const char *fabric_name);
	void ConstructResourceEpNotEnabled(enum fi_ep_type ep_type, const char *fabric_name);
	void DestructResource();
};

#endif // EFA_UNIT_TEST_BASE_H

/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include <gtest/gtest.h>

extern "C" {
#include "efa_env.h"
#include "ofi_hmem.h"
}

struct efa_env efa_env = {};
struct efa_hmem_info g_efa_hmem_info[OFI_HMEM_MAX] = {};

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

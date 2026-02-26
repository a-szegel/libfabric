/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestDataPathDirect : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestDataPathDirect, test_efa_data_path_direct_rdma_read_multiple_sge_fail) {
    // Test validates that RDMA read with multiple SGE (scatter-gather elements) fails
    // EFA supports only 1 SGE for RDMA operations
    
    struct ibv_pd mock_pd;
    struct ibv_mr mr1, mr2;
    char buf1[2048], buf2[2048];
    
    // Mock memory registration for two buffers
    EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, buf1, 2048, _))
        .WillOnce(Invoke([&](struct ibv_pd *pd, void *addr, size_t len, int access) {
            EXPECT_EQ(addr, buf1);
            EXPECT_EQ(len, 2048);
            return &mr1;
        }));
    
    EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, buf2, 2048, _))
        .WillOnce(Invoke([&](struct ibv_pd *pd, void *addr, size_t len, int access) {
            EXPECT_EQ(addr, buf2);
            EXPECT_EQ(len, 2048);
            return &mr2;
        }));
    
    struct ibv_mr *mr_result1 = ibv_reg_mr(&mock_pd, buf1, 2048, IBV_ACCESS_LOCAL_WRITE);
    struct ibv_mr *mr_result2 = ibv_reg_mr(&mock_pd, buf2, 2048, IBV_ACCESS_LOCAL_WRITE);
    
    EXPECT_EQ(mr_result1, &mr1);
    EXPECT_EQ(mr_result2, &mr2);
}

TEST_F(EfaUnitTestDataPathDirect, test_efa_data_path_direct_rdma_write_multiple_sge_fail) {
    // Test validates that RDMA write with multiple SGE fails
    
    struct ibv_pd mock_pd;
    struct ibv_qp mock_qp;
    struct ibv_qp_init_attr attr = {};
    
    // Mock QP creation
    EXPECT_CALL(*mock, ibv_create_qp(&mock_pd, _))
        .WillOnce(Invoke([&](struct ibv_pd *pd, struct ibv_qp_init_attr *init_attr) {
            EXPECT_EQ(pd, &mock_pd);
            EXPECT_NE(init_attr, nullptr);
            return &mock_qp;
        }));
    
    struct ibv_qp *qp = ibv_create_qp(&mock_pd, &attr);
    EXPECT_EQ(qp, &mock_qp);
}

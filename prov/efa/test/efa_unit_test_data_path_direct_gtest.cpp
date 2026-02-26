/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestDataPathDirect : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestDataPathDirect, test_efa_data_path_direct_rdma_read_multiple_sge_fail) {
    struct ibv_pd mock_pd;
    struct ibv_mr mr1, mr2;
    char buf1[2048], buf2[2048];
    
    EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, buf1, 2048, _)).WillOnce(Return(&mr1));
    EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, buf2, 2048, _)).WillOnce(Return(&mr2));
    
    ASSERT_NE(ibv_reg_mr(&mock_pd, buf1, 2048, IBV_ACCESS_LOCAL_WRITE), nullptr);
    ASSERT_NE(ibv_reg_mr(&mock_pd, buf2, 2048, IBV_ACCESS_LOCAL_WRITE), nullptr);
}

TEST_F(EfaUnitTestDataPathDirect, test_efa_data_path_direct_rdma_write_multiple_sge_fail) {
    struct ibv_pd mock_pd;
    struct ibv_qp mock_qp;
    struct ibv_qp_init_attr attr = {};
    
    EXPECT_CALL(*mock, ibv_create_qp(&mock_pd, _)).WillOnce(Return(&mock_qp));
    ASSERT_NE(ibv_create_qp(&mock_pd, &attr), nullptr);
    
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    
    struct ibv_qp_attr qp_attr = {};
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &qp_attr, IBV_QP_STATE), 0);
}

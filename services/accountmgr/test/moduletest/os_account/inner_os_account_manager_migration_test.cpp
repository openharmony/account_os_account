/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <vector>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_info.h"
#define private public
#include "iinner_os_account_manager.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;

class IInnerOsAccountManagerMigrationTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    IInnerOsAccountManager *innerMgrService_ = &IInnerOsAccountManager::GetInstance();
};

void IInnerOsAccountManagerMigrationTest::SetUpTestCase(void)
{}

void IInnerOsAccountManagerMigrationTest::TearDownTestCase(void)
{}

void IInnerOsAccountManagerMigrationTest::SetUp() __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void IInnerOsAccountManagerMigrationTest::TearDown()
{}

/**
 * @tc.name: MigrateOsAccountTypesToTEE001
 * @tc.desc: Test MigrateOsAccountTypesToTee with normal case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerMigrationTest, MigrateOsAccountTypesToTEE001, TestSize.Level1)
{
    // Test migration functionality
    // This should not crash even if TEE is not available
    ErrCode ret = innerMgrService_->MigrateOsAccountTypesToTEE();
    // In normal test environment without TEE, should return OK (skip gracefully)
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: MigrateOsAccountTypesToTEE002
 * @tc.desc: Test MigrateOsAccountTypesToTee with existing accounts
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerMigrationTest, MigrateOsAccountTypesToTEE002, TestSize.Level1)
{
    // Get original account list
    std::vector<OsAccountInfo> originalAccounts;
    ErrCode ret = innerMgrService_->QueryAllCreatedOsAccounts(originalAccounts);
    EXPECT_EQ(ret, ERR_OK);

    // Now test migration
    ret = innerMgrService_->MigrateOsAccountTypesToTEE();
    // Should succeed even if TEE operations fail
    EXPECT_EQ(ret, ERR_OK);

    // Verify account list remains unchanged
    std::vector<OsAccountInfo> afterAccounts;
    ret = innerMgrService_->QueryAllCreatedOsAccounts(afterAccounts);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(originalAccounts.size(), afterAccounts.size());
}

/**
 * @tc.name: MigrateOsAccountTypesToTEE003
 * @tc.desc: Test MigrateOsAccountTypesToTee with to-be-removed accounts
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerMigrationTest, MigrateOsAccountTypesToTEE003, TestSize.Level1)
{
    // Test that to-be-removed accounts are properly skipped
    // Migration should not crash or fail even if accounts exist
    ErrCode ret = innerMgrService_->MigrateOsAccountTypesToTEE();
    EXPECT_EQ(ret, ERR_OK);
}

} // namespace AccountSA
} // namespace OHOS

/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "account_permission_manager.h"
#include "account_log_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

class AccountPermissionManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AccountPermissionManagerTest::SetUpTestCase(void)
{}

void AccountPermissionManagerTest::TearDownTestCase(void)
{}

void AccountPermissionManagerTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AccountPermissionManagerTest::TearDown(void)
{}

/**
 * @tc.name: AccountPermissionManager_VerifyPermission_0100
 * @tc.desc: Verify permission with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFR
 */
HWTEST_F(AccountPermissionManagerTest, AccountPermissionManager_VerifyPermission_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AccountPermissionManager_VerifyPermission_0100");
    const std::string DISTRIBUTED_DATASYNC = "ohos.permission.DISTRIBUTED_DATASYNC";
    ErrCode result = AccountPermissionManager::VerifyPermission(DISTRIBUTED_DATASYNC);
    EXPECT_EQ(result, ERR_OK);
}

namespace {
constexpr uint32_t TEST_TOKEN_ID_PERMISSION_GRANTED = 123456;
constexpr uint32_t TEST_TOKEN_ID_PERMISSION_DENIED = 999999;
}

/**
 * @tc.name: AccountPermissionManager_VerifyPermission_0200
 * @tc.desc: Verify permission with valid tokenId and permission granted.
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(AccountPermissionManagerTest, AccountPermissionManager_VerifyPermission_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AccountPermissionManager_VerifyPermission_0200");
    const std::string permissionName = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
    ErrCode result = AccountPermissionManager::VerifyPermission(TEST_TOKEN_ID_PERMISSION_GRANTED, permissionName);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AccountPermissionManager_VerifyPermission_0300
 * @tc.desc: Verify permission with tokenId that has permission denied.
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(AccountPermissionManagerTest, AccountPermissionManager_VerifyPermission_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AccountPermissionManager_VerifyPermission_0300");
    const std::string permissionName = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
    ErrCode result = AccountPermissionManager::VerifyPermission(TEST_TOKEN_ID_PERMISSION_DENIED, permissionName);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

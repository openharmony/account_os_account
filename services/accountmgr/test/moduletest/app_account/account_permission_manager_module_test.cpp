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

#include "account_error_no.h"
#include "account_permission_manager.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

class AccountPermissionManagerModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    std::shared_ptr<AccountPermissionManager>
        permissionManagerPtr_ = DelayedSingleton<AccountPermissionManager>::GetInstance();
};

void AccountPermissionManagerModuleTest::SetUpTestCase(void)
{}

void AccountPermissionManagerModuleTest::TearDownTestCase(void)
{
    DelayedSingleton<AccountPermissionManager>::DestroyInstance();
}

void AccountPermissionManagerModuleTest::SetUp(void)
{}

void AccountPermissionManagerModuleTest::TearDown(void)
{}

/**
 * @tc.name: AccountPermissionManager_VerifyPermission_0100
 * @tc.desc: Verify permission with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFR
 */
HWTEST_F(AccountPermissionManagerModuleTest, AccountPermissionManager_VerifyPermission_0100, TestSize.Level0)
{
    ASSERT_NE(permissionManagerPtr_, nullptr);

    ErrCode result = permissionManagerPtr_->VerifyPermission(AccountPermissionManager::DISTRIBUTED_DATASYNC);
    EXPECT_EQ(result, ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR);
}

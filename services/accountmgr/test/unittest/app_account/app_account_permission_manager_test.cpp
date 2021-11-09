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

class AppAccountPermissionManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountPermissionManagerTest::SetUpTestCase(void)
{}

void AppAccountPermissionManagerTest::TearDownTestCase(void)
{}

void AppAccountPermissionManagerTest::SetUp(void)
{}

void AppAccountPermissionManagerTest::TearDown(void)
{}

/**
 * @tc.number: AppAccountPermissionManager_VerifyPermission_0100
 * @tc.name: VerifyPermission
 * @tc.desc: verify permission with valid data.
 */
HWTEST_F(
    AppAccountPermissionManagerTest, AppAccountPermissionManager_VerifyPermission_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountPermissionManager_VerifyPermission_0100");

    auto managerPtr = DelayedSingleton<AccountPermissionManager>::GetInstance();
    ErrCode result = managerPtr->VerifyPermission(AccountPermissionManager::DISTRIBUTED_DATASYNC);
    EXPECT_EQ(result, ERR_OK);
}

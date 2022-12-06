/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "account_log_wrapper.h"
#define private public
#include "app_account_control_manager.h"
#include "app_account_manager_service.h"
#undef private
#include "ipc_skeleton.h"
#include "app_account_manager_service.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AppExecFwk;

class AppAccountManagerServiceModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

namespace {
std::shared_ptr<AppAccountControlManager> g_controlManagerPtr = AppAccountControlManager::GetInstance();
std::shared_ptr<AppAccountManagerService> g_accountManagerService = std::make_shared<AppAccountManagerService>();
} // namespace

void AppAccountManagerServiceModuleTest::SetUpTestCase(void)
{}

void AppAccountManagerServiceModuleTest::TearDownTestCase(void)
{}

void AppAccountManagerServiceModuleTest::SetUp(void)
{}

void AppAccountManagerServiceModuleTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountManagerService_GetBundleNameAndCheckPerm_0100
 * @tc.desc: test GetBundleNameAndCheckPerm VerifyPermission failed
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetBundleNameAndCheckPerm_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetBundleNameAndCheckPerm_0100");

    int32_t callingUid;
    std::string bundleName;
    std::string permName = "";
    int result = g_accountManagerService->GetBundleNameAndCheckPerm(callingUid, bundleName, permName);
    EXPECT_EQ(result, ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR);
}

/**
 * @tc.name: AppAccountManagerService_GetCallingInfo_0100
 * @tc.desc: test GetCallingInfo GetCallingTokenInfoAndAppIndex faliled
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetCallingInfo_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetCallingInfo_0100");

    int32_t callingUid;
    std::string bundleName;
    uint32_t appIndex;
    int result = g_accountManagerService->GetCallingInfo(callingUid, bundleName, appIndex);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_APP_INDEX);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccounts_0100
 * @tc.desc: test GetAllAccounts VerifyPermission faliled
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0100");

    std::string owner = "test";
    std::vector<AppAccountInfo> appAccounts;
    int result = g_accountManagerService->GetAllAccounts(owner, appAccounts);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_APP_INDEX);
}
/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "account_log_wrapper.h"
#define private public
#include "app_account_control_manager.h"
#include "app_account_manager_service.h"
#undef private
#include "mock_inner_app_account_manager.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_OWNER = "com.example.owner";
const std::string STRING_DISABLED_OWNER = "com.example.disabled.owner";
const std::string STRING_SUBPROFILE_AUTH_EXT = "com.example.subprofile.auth.extension";
sptr<IRemoteObject> g_appAccountManagerService;
sptr<IAppAccount> g_appAccountProxy;
sptr<AppAccountManagerService> g_servicePtr;
}  // namespace

class AppAccountManagerServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountManagerServiceTest::SetUpTestCase(void)
{
    g_servicePtr = new (std::nothrow) AppAccountManagerService();
    ASSERT_NE(g_servicePtr, nullptr);
    auto mockInnerManagerPtr = std::make_shared<MockInnerAppAccountManager>();
    g_servicePtr->innerManager_ = mockInnerManagerPtr;

    g_appAccountManagerService = g_servicePtr->AsObject();
    g_appAccountProxy = iface_cast<IAppAccount>(g_appAccountManagerService);
}

void AppAccountManagerServiceTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase!";
}

void AppAccountManagerServiceTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AppAccountManagerServiceTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountManagerService_AddAccount_0100
 * @tc.desc: Add an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountManagerServiceTest, AppAccountManagerService_AddAccount_0100, TestSize.Level1)
{
    int32_t funcResult = -1;
    ErrCode result = g_appAccountProxy->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAccount_0100
 * @tc.desc: Delete an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountManagerServiceTest, AppAccountManagerService_DeleteAccount_0100, TestSize.Level1)
{
    int32_t funcResult = -1;
    ErrCode result = g_appAccountProxy->DeleteAccount(STRING_NAME, funcResult);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CreateAccount_0100
 * @tc.desc: Add an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerServiceTest, AppAccountManagerService_CreateAccount_0100, TestSize.Level1)
{
    CreateAccountOptions option;
    int32_t funcResult = -1;
    ErrCode result = g_appAccountProxy->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(result, ERR_OK);
    result = g_appAccountProxy->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SubscribeAppAccount_0100
 * @tc.desc: Subscribe app accounts with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(
    AppAccountManagerServiceTest, AppAccountManagerService_SubscribeAppAccount_0100, TestSize.Level1)
{
    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo;
    subscribeInfo.SetOwners(owners);

    // subscribe app account
    int32_t funcResult = -1;
    ErrCode result = g_appAccountProxy->SubscribeAppAccount(subscribeInfo, nullptr, funcResult);

    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(funcResult, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: AppAccountManagerService_UnsubscribeAppAccount_0100
 * @tc.desc: Unsubscribe app accounts with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(
    AppAccountManagerServiceTest, AppAccountManagerService_UnsubscribeAppAccount_0100, TestSize.Level1)
{
    // unsubscribe app account
    std::vector<std::string> owners;
    int32_t funcResult = -1;
    ErrCode result = g_appAccountProxy->UnsubscribeAppAccount(nullptr, owners, funcResult);

    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(funcResult, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: AppAccountManagerService_SubscribeAppAccount_0200
 * @tc.desc: Subscribe with disabled owner; excluded under subprofile flag, proceeds otherwise.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountManagerServiceTest, AppAccountManagerService_SubscribeAppAccount_0200, TestSize.Level1)
{
    std::vector<std::string> owners;
    owners.emplace_back(STRING_DISABLED_OWNER);
    AppAccountSubscribeInfo subscribeInfo;
    subscribeInfo.SetOwners(owners);
    int32_t funcResult = -1;
    ErrCode result = g_appAccountProxy->SubscribeAppAccount(subscribeInfo, nullptr, funcResult);
    EXPECT_EQ(result, ERR_OK);
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    // Disabled owner is filtered out by QueryExtensionAbilityInfosV9, existOwners is empty.
    EXPECT_EQ(funcResult, ERR_OK);
#else
    // Disabled is not checked without subprofile flag; proceeds to nullptr eventListener check.
    EXPECT_EQ(funcResult, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
#endif
}

/**
 * @tc.name: AppAccountManagerService_SubscribeAppAccount_0300
 * @tc.desc: Subscribe with owner whose extension appIndex mismatches caller; owner is filtered out.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountManagerServiceTest, AppAccountManagerService_SubscribeAppAccount_0300, TestSize.Level1)
{
    std::vector<std::string> owners;
    owners.emplace_back(STRING_SUBPROFILE_AUTH_EXT);
    AppAccountSubscribeInfo subscribeInfo;
    subscribeInfo.SetOwners(owners);
    int32_t funcResult = -1;
    ErrCode result = g_appAccountProxy->SubscribeAppAccount(subscribeInfo, nullptr, funcResult);
    EXPECT_EQ(result, ERR_OK);
    // Extension appIndex(1) mismatches caller appIndex(0); owner is filtered out, existOwners is empty.
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAuthenticatorInfo_0100
 * @tc.desc: GetAuthenticatorInfo populates callerBundleName via GetCallingInfo.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountManagerServiceTest, AppAccountManagerService_GetAuthenticatorInfo_0100, TestSize.Level1)
{
    AuthenticatorInfo info;
    int32_t funcResult = -1;
    ErrCode result = g_appAccountProxy->GetAuthenticatorInfo(STRING_OWNER, info, funcResult);
    EXPECT_EQ(result, ERR_OK);
}

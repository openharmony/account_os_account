/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <thread>
#include <gmock/gmock.h>
#include "account_log_wrapper.h"
#include "datetime_ex.h"
#define private public
#include "app_account_common.h"
#include "app_account_manager_service.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AppExecFwk;
#ifdef HAS_CES_PART
using namespace OHOS::EventFwk;
#endif // HAS_CES_PART
namespace {
const std::string STRING_NAME = "name";
const std::string AUTH_TYPE = "type";
const std::string STRING_CREDENTIAL_TYPE = "password";
const std::string KEY = "testkey";
const std::string OWNER = "owner";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_BUNDLE_NAME = "com.example.third_party";
std::shared_ptr<AppAccountManagerService> g_accountManagerService =
    std::make_shared<AppAccountManagerService>();
}  // namespace

class AppAccountManagerServiceNotMockModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountManagerServiceNotMockModuleTest::SetUpTestCase(void)
{}

void AppAccountManagerServiceNotMockModuleTest::TearDownTestCase(void)
{}

void AppAccountManagerServiceNotMockModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AppAccountManagerServiceNotMockModuleTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountManagerService_CreateAccount_001
 * @tc.desc: test CreateAccount failed get calling info
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(AppAccountManagerServiceNotMockModuleTest, AppAccountManagerService_CreateAccount_001, TestSize.Level1)
{
    CreateAccountOptions option;
    ErrCode result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_AppAccountManagerService_001
 * @tc.desc: test AppAccountManagerService failed get calling info
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(
    AppAccountManagerServiceNotMockModuleTest, AppAccountManagerService_AppAccountManagerService_001, TestSize.Level1)
{
    bool syncEnable = false;
    ErrCode result = g_accountManagerService->CheckAppAccountSyncEnable(STRING_NAME, syncEnable);
    EXPECT_NE(result, ERR_OK);

    result = g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, false);
    EXPECT_NE(result, ERR_OK);

    result = g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_NE(result, ERR_OK);

    result = g_accountManagerService->DisableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_NE(result, ERR_OK);

    std::string extraInfo;
    result = g_accountManagerService->GetAccountExtraInfo(STRING_NAME, extraInfo);
    EXPECT_NE(result, ERR_OK);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_NE(result, ERR_OK);

    CreateAccountOptions option;
    result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_NE(result, ERR_OK);

    AppAccountSubscribeInfo subscribeInfo;
    result = g_accountManagerService->SubscribeAppAccount(subscribeInfo, nullptr);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAppAccountSyncEnable_002
 * @tc.desc: test appAccountManagerService failed get calling info
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(
    AppAccountManagerServiceNotMockModuleTest, AppAccountManagerService_AppAccountManagerService_002, TestSize.Level1)
{
    ErrCode result = g_accountManagerService->SetAppAccountSyncEnable(STRING_NAME, false);
    EXPECT_NE(result, ERR_OK);

    std::string value;
    result = g_accountManagerService->GetAssociatedData(STRING_NAME, KEY, value);
    EXPECT_NE(result, ERR_OK);

    result = g_accountManagerService->SetAssociatedData(STRING_NAME, KEY, value);
    EXPECT_NE(result, ERR_OK);

    std::string credential;
    result = g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_NE(result, ERR_OK);

    result = g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_NE(result, ERR_OK);

    AuthenticatorSessionRequest request;
    result = g_accountManagerService->GetTokenVisibilityParam(STRING_NAME, AUTH_TYPE, STRING_BUNDLE_NAME, request);
    EXPECT_NE(result, ERR_OK);

    result = g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME, AUTH_TYPE, STRING_BUNDLE_NAME, false);
    EXPECT_NE(result, ERR_OK);

    bool isVisible = false;
    result = g_accountManagerService->SetAuthTokenVisibility(STRING_NAME, AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_NE(result, ERR_OK);

    result = g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME, AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_NE(result, ERR_OK);

    result = g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME, AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_NE(result, ERR_OK);

    AuthenticatorInfo info;
    result = g_accountManagerService->GetAuthenticatorInfo(OWNER, info);
    EXPECT_NE(result, ERR_OK);

    std::vector<OAuthTokenInfo> tokenInfos;
    result = g_accountManagerService->GetAllOAuthTokens(STRING_NAME, OWNER, tokenInfos);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAppAccountSyncEnable_003
 * @tc.desc: test appAccountManagerService failed get calling info
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(
    AppAccountManagerServiceNotMockModuleTest, AppAccountManagerService_AppAccountManagerService_003, TestSize.Level1)
{
    std::set<std::string> oauthList;
    ErrCode result = g_accountManagerService->GetOAuthList(STRING_NAME, AUTH_TYPE, oauthList);
    EXPECT_NE(result, ERR_OK);

    result = g_accountManagerService->GetAuthList(STRING_NAME, AUTH_TYPE, oauthList);
    EXPECT_NE(result, ERR_OK);

    result = g_accountManagerService->GetAuthList(STRING_NAME, AUTH_TYPE, oauthList);
    EXPECT_NE(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccounts(OWNER, appAccounts);
    EXPECT_NE(result, ERR_OK);

    result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_NE(result, ERR_OK);

    result = g_accountManagerService->QueryAllAccessibleAccounts(OWNER, appAccounts);
    EXPECT_NE(result, ERR_OK);

    bool isAccessible = false;
    result = g_accountManagerService->CheckAppAccess(STRING_NAME, STRING_BUNDLE_NAME, isAccessible);
    EXPECT_NE(result, ERR_OK);

    result = g_accountManagerService->DeleteAccountCredential(STRING_NAME, AUTH_TYPE);
    EXPECT_NE(result, ERR_OK);

    SelectAccountsOptions option;
    result = g_accountManagerService->SelectAccountsByOptions(option, nullptr);
    EXPECT_NE(result, ERR_OK);

    VerifyCredentialOptions options;
    result = g_accountManagerService->VerifyCredential(STRING_NAME, OWNER, options, nullptr);
    EXPECT_NE(result, ERR_OK);

    std::vector<std::string> labels;
    result = g_accountManagerService->CheckAccountLabels(STRING_NAME, OWNER, labels, nullptr);
    EXPECT_NE(result, ERR_OK);

    SetPropertiesOptions setOptions;
    result = g_accountManagerService->SetAuthenticatorProperties(OWNER, setOptions, nullptr);
    EXPECT_NE(result, ERR_OK);
}
/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <vector>
#include "account_log_wrapper.h"
#define private public
#include "app_account_manager_service.h"
#undef private

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_EMPTY = "";
const std::string STRING_NAME = "name";
const std::string STRING_SPECIAL_CHARACTERS = "name @#";
const std::string STRING_MAX_SIZE(1025, '1');
const int32_t TEST_MAX_SIZE = 1025;
std::shared_ptr<AppAccountManagerService> g_accountManagerService =
    std::make_shared<AppAccountManagerService>();
}

class AppAccountManagerServiceCheckTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountManagerServiceCheckTest::SetUpTestCase(void)
{}

void AppAccountManagerServiceCheckTest::TearDownTestCase(void)
{}

void AppAccountManagerServiceCheckTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AppAccountManagerServiceCheckTest::TearDown(void)
{}

/**
 * @tc.name: AddAccount_01
 * @tc.desc: Test AddAccount.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, AddAccount_01, TestSize.Level3)
{
    int32_t result = 0;
    g_accountManagerService->AddAccount(STRING_EMPTY, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->AddAccount(STRING_SPECIAL_CHARACTERS, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->AddAccount(STRING_NAME, STRING_MAX_SIZE, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AddAccountImplicitly_01
 * @tc.desc: Test AddAccountImplicitly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, AddAccountImplicitly_01, TestSize.Level3)
{
    int32_t result = 0;
    AAFwk::Want options;
    sptr<IAppAccountAuthenticatorCallback> callback = nullptr;
    g_accountManagerService->AddAccountImplicitly(STRING_EMPTY, STRING_NAME, options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->AddAccountImplicitly(STRING_NAME, STRING_MAX_SIZE, options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: CreateAccount_01
 * @tc.desc: Test CreateAccount.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, CreateAccount_01, TestSize.Level3)
{
    int32_t result = 0;
    CreateAccountOptions options;
    g_accountManagerService->CreateAccount(STRING_EMPTY, options, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    for (int i = 0; i < TEST_MAX_SIZE; ++i) {
        std::string keyValue = STRING_NAME + std::to_string(i);
        options.customData.emplace(keyValue, keyValue);
    }
    g_accountManagerService->CreateAccount(STRING_NAME, options, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    options.customData.clear();
    options.customData = { { STRING_MAX_SIZE, STRING_NAME } };
    g_accountManagerService->CreateAccount(STRING_NAME, options, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    options.customData.clear();
    options.customData = { { STRING_NAME, STRING_MAX_SIZE } };
    g_accountManagerService->CreateAccount(STRING_NAME, options, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: CreateAccountImplicitly_01
 * @tc.desc: Test CreateAccountImplicitly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, CreateAccountImplicitly_01, TestSize.Level3)
{
    int32_t result = 0;
    CreateAccountImplicitlyOptions options;
    options.authType = STRING_MAX_SIZE;
    std::vector<std::string> requiredLabelVec(TEST_MAX_SIZE, STRING_NAME);
    options.requiredLabels = requiredLabelVec;
    sptr<IAppAccountAuthenticatorCallback> callback = nullptr;

    g_accountManagerService->CreateAccountImplicitly(STRING_MAX_SIZE, options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    g_accountManagerService->CreateAccountImplicitly(STRING_NAME, options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    options.authType = STRING_NAME;
    g_accountManagerService->CreateAccountImplicitly(STRING_NAME, options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: DeleteAccount_01
 * @tc.desc: Test DeleteAccount.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, DeleteAccount_01, TestSize.Level3)
{
    int32_t result = 0;
    g_accountManagerService->DeleteAccount(STRING_EMPTY, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->DeleteAccount(STRING_MAX_SIZE, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: GetAccountExtraInfo_01
 * @tc.desc: Test GetAccountExtraInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, GetAccountExtraInfo_01, TestSize.Level3)
{
    int32_t result = 0;
    std::string extraInfo;
    g_accountManagerService->GetAccountExtraInfo(STRING_EMPTY, extraInfo, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->GetAccountExtraInfo(STRING_MAX_SIZE, extraInfo, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->GetAccountExtraInfo(STRING_SPECIAL_CHARACTERS, extraInfo, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SetAccountExtraInfo_01
 * @tc.desc: Test SetAccountExtraInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, SetAccountExtraInfo_01, TestSize.Level3)
{
    int32_t result = 0;
    g_accountManagerService->SetAccountExtraInfo(STRING_EMPTY, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetAccountExtraInfo(STRING_SPECIAL_CHARACTERS, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetAccountExtraInfo(STRING_NAME, STRING_MAX_SIZE, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: EnableAppAccess_01
 * @tc.desc: Test EnableAppAccess.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, EnableAppAccess_01, TestSize.Level3)
{
    int32_t result = 0;
    g_accountManagerService->EnableAppAccess(STRING_EMPTY, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->EnableAppAccess(STRING_SPECIAL_CHARACTERS, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_MAX_SIZE, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: DisableAppAccess_01
 * @tc.desc: Test DisableAppAccess.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, DisableAppAccess_01, TestSize.Level3)
{
    int32_t result = 0;
    g_accountManagerService->DisableAppAccess(STRING_EMPTY, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->DisableAppAccess(STRING_SPECIAL_CHARACTERS, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->DisableAppAccess(STRING_NAME, STRING_MAX_SIZE, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SetAppAccess_01
 * @tc.desc: Test SetAppAccess.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, SetAppAccess_01, TestSize.Level3)
{
    int32_t result = 0;
    g_accountManagerService->SetAppAccess(STRING_EMPTY, STRING_NAME, true, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetAppAccess(STRING_MAX_SIZE, STRING_NAME, true, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetAppAccess(STRING_NAME, STRING_EMPTY, true, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetAppAccess(STRING_NAME, STRING_MAX_SIZE, true, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: CheckAppAccountSyncEnable_01
 * @tc.desc: Test CheckAppAccountSyncEnable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, CheckAppAccountSyncEnable_01, TestSize.Level3)
{
    int32_t result = 0;
    bool syncEnable = true;
    g_accountManagerService->CheckAppAccountSyncEnable(STRING_EMPTY, syncEnable, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->CheckAppAccountSyncEnable(STRING_MAX_SIZE, syncEnable, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SetAppAccountSyncEnable_01
 * @tc.desc: Test SetAppAccountSyncEnable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, SetAppAccountSyncEnable_01, TestSize.Level3)
{
    int32_t result = 0;
    g_accountManagerService->SetAppAccountSyncEnable(STRING_EMPTY, true, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetAppAccountSyncEnable(STRING_MAX_SIZE, true, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SetAssociatedData_01
 * @tc.desc: Test SetAssociatedData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, SetAssociatedData_01, TestSize.Level3)
{
    int32_t result = 0;
    g_accountManagerService->SetAssociatedData(STRING_EMPTY, STRING_NAME, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_MAX_SIZE, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_NAME, STRING_MAX_SIZE, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: GetAccountCredential_01
 * @tc.desc: Test GetAccountCredential.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, GetAccountCredential_01, TestSize.Level3)
{
    int32_t result = 0;
    std::string credential;
    g_accountManagerService->GetAccountCredential(STRING_EMPTY, STRING_NAME, credential, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_MAX_SIZE, credential, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SetAccountCredential_01
 * @tc.desc: Test SetAccountCredential.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, SetAccountCredential_01, TestSize.Level3)
{
    int32_t result = 0;
    g_accountManagerService->SetAccountCredential(STRING_EMPTY, STRING_NAME, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_MAX_SIZE, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_NAME, STRING_MAX_SIZE, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: Authenticate_01
 * @tc.desc: Test Authenticate.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, Authenticate_01, TestSize.Level3)
{
    int32_t result = 0;
    AppAccountStringInfo appAccountStringInfo;
    AAFwk::Want options;
    appAccountStringInfo.name = STRING_MAX_SIZE;
    sptr<IAppAccountAuthenticatorCallback> callback = nullptr;

    g_accountManagerService->Authenticate(appAccountStringInfo, options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    appAccountStringInfo.name = STRING_NAME;
    appAccountStringInfo.owner = STRING_MAX_SIZE;
    g_accountManagerService->Authenticate(appAccountStringInfo, options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    appAccountStringInfo.name = STRING_NAME;
    appAccountStringInfo.owner = STRING_NAME;
    appAccountStringInfo.authType = STRING_MAX_SIZE;
    g_accountManagerService->Authenticate(appAccountStringInfo, options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: GetOAuthToken_01
 * @tc.desc: Test GetOAuthToken.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, GetOAuthToken_01, TestSize.Level3)
{
    int32_t result = 0;
    std::string token;
    g_accountManagerService->GetOAuthToken(STRING_EMPTY, STRING_NAME, STRING_NAME, token, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->GetOAuthToken(STRING_NAME, STRING_MAX_SIZE, STRING_NAME, token, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->GetOAuthToken(STRING_NAME, STRING_NAME, STRING_MAX_SIZE, token, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->GetOAuthToken(STRING_SPECIAL_CHARACTERS, STRING_NAME, STRING_NAME, token, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: GetAuthToken_01
 * @tc.desc: Test GetAuthToken.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, GetAuthToken_01, TestSize.Level3)
{
    int32_t result = 0;
    std::string token;
    g_accountManagerService->GetAuthToken(STRING_EMPTY, STRING_NAME, STRING_NAME, token, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->GetAuthToken(STRING_NAME, STRING_MAX_SIZE, STRING_NAME, token, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->GetAuthToken(STRING_NAME, STRING_NAME, STRING_MAX_SIZE, token, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SetOAuthToken_01
 * @tc.desc: Test SetOAuthToken.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, SetOAuthToken_01, TestSize.Level3)
{
    int32_t result = 0;
    g_accountManagerService->SetOAuthToken(STRING_EMPTY, STRING_NAME, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_MAX_SIZE, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_NAME, STRING_MAX_SIZE, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: DeleteOAuthToken_01
 * @tc.desc: Test DeleteOAuthToken.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, DeleteOAuthToken_01, TestSize.Level3)
{
    int32_t result = 0;
    g_accountManagerService->DeleteOAuthToken(STRING_MAX_SIZE, STRING_NAME, STRING_NAME, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->DeleteOAuthToken(STRING_NAME, STRING_MAX_SIZE, STRING_NAME, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->DeleteOAuthToken(STRING_NAME, STRING_NAME, STRING_MAX_SIZE, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->DeleteOAuthToken(STRING_NAME, STRING_NAME, STRING_NAME, STRING_MAX_SIZE, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->DeleteOAuthToken(STRING_SPECIAL_CHARACTERS, STRING_NAME, STRING_NAME, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: DeleteAuthToken_01
 * @tc.desc: Test DeleteAuthToken.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, DeleteAuthToken_01, TestSize.Level3)
{
    int32_t result = 0;
    g_accountManagerService->DeleteAuthToken(STRING_MAX_SIZE, STRING_NAME, STRING_NAME, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->DeleteAuthToken(STRING_NAME, STRING_MAX_SIZE, STRING_NAME, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->DeleteAuthToken(STRING_NAME, STRING_NAME, STRING_MAX_SIZE, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->DeleteAuthToken(STRING_NAME, STRING_NAME, STRING_NAME, STRING_MAX_SIZE, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SetOAuthTokenVisibility_01
 * @tc.desc: Test SetOAuthTokenVisibility.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, SetOAuthTokenVisibility_01, TestSize.Level3)
{
    int32_t result = 0;
    g_accountManagerService->SetOAuthTokenVisibility(STRING_MAX_SIZE, STRING_NAME, STRING_NAME, true, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME, STRING_MAX_SIZE, STRING_NAME, true, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME, STRING_NAME, STRING_MAX_SIZE, true, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetOAuthTokenVisibility(STRING_SPECIAL_CHARACTERS, STRING_NAME, STRING_NAME, true, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SetAuthTokenVisibility_01
 * @tc.desc: Test SetAuthTokenVisibility.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, SetAuthTokenVisibility_01, TestSize.Level3)
{
    int32_t result = 0;
    g_accountManagerService->SetAuthTokenVisibility(STRING_MAX_SIZE, STRING_NAME, STRING_NAME, true, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetAuthTokenVisibility(STRING_NAME, STRING_MAX_SIZE, STRING_NAME, true, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetAuthTokenVisibility(STRING_NAME, STRING_NAME, STRING_MAX_SIZE, true, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: CheckOAuthTokenVisibility_01
 * @tc.desc: Test CheckOAuthTokenVisibility.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, CheckOAuthTokenVisibility_01, TestSize.Level3)
{
    int32_t result = 0;
    bool isVisible = false;
    g_accountManagerService->CheckOAuthTokenVisibility(STRING_MAX_SIZE, STRING_NAME, STRING_NAME, isVisible, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME, STRING_MAX_SIZE, STRING_NAME, isVisible, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME, STRING_NAME, STRING_MAX_SIZE, isVisible, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->CheckOAuthTokenVisibility(
        STRING_SPECIAL_CHARACTERS, STRING_NAME, STRING_NAME, isVisible, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: CheckAuthTokenVisibility_01
 * @tc.desc: Test CheckAuthTokenVisibility.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, CheckAuthTokenVisibility_01, TestSize.Level3)
{
    int32_t result = 0;
    bool isVisible = false;
    g_accountManagerService->CheckAuthTokenVisibility(STRING_MAX_SIZE, STRING_NAME, STRING_NAME, isVisible, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME, STRING_MAX_SIZE, STRING_NAME, isVisible, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME, STRING_NAME, STRING_MAX_SIZE, isVisible, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: GetAuthenticatorInfo_01
 * @tc.desc: Test GetAuthenticatorInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, GetAuthenticatorInfo_01, TestSize.Level3)
{
    int32_t result = 0;
    AuthenticatorInfo info;
    g_accountManagerService->GetAuthenticatorInfo(STRING_EMPTY, info, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->GetAuthenticatorInfo(STRING_MAX_SIZE, info, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: GetAllOAuthTokens_01
 * @tc.desc: Test GetAllOAuthTokens.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, GetAllOAuthTokens_01, TestSize.Level3)
{
    int32_t result = 0;
    std::vector<OAuthTokenInfo> tokenInfos;
    g_accountManagerService->GetAllOAuthTokens(STRING_EMPTY, STRING_NAME, tokenInfos, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->GetAllOAuthTokens(STRING_NAME, STRING_MAX_SIZE, tokenInfos, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: GetOAuthList_01
 * @tc.desc: Test GetOAuthList.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, GetOAuthList_01, TestSize.Level3)
{
    int32_t result = 0;
    std::set<std::string> oauthList;
    g_accountManagerService->GetOAuthList(STRING_EMPTY, STRING_NAME, oauthList, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->GetOAuthList(STRING_NAME, STRING_MAX_SIZE, oauthList, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->GetOAuthList(STRING_SPECIAL_CHARACTERS, STRING_NAME, oauthList, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: GetAuthList_01
 * @tc.desc: Test GetAuthList.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, GetAuthList_01, TestSize.Level3)
{
    int32_t result = 0;
    std::set<std::string> oauthList;
    g_accountManagerService->GetAuthList(STRING_EMPTY, STRING_NAME, oauthList, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->GetAuthList(STRING_NAME, STRING_MAX_SIZE, oauthList, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: GetAuthenticatorCallback_01
 * @tc.desc: Test GetAuthenticatorCallback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, GetAuthenticatorCallback_01, TestSize.Level3)
{
    int32_t result = 0;
    sptr<IRemoteObject> callback = nullptr;
    g_accountManagerService->GetAuthenticatorCallback(STRING_EMPTY, result, callback);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->GetAuthenticatorCallback(STRING_MAX_SIZE, result, callback);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: GetAllAccounts_01
 * @tc.desc: Test GetAllAccounts.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, GetAllAccounts_01, TestSize.Level3)
{
    int32_t result = 0;
    std::vector<AppAccountInfo> accounts;
    g_accountManagerService->GetAllAccounts(STRING_EMPTY, accounts, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->GetAllAccounts(STRING_MAX_SIZE, accounts, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: QueryAllAccessibleAccounts_01
 * @tc.desc: Test QueryAllAccessibleAccounts.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, QueryAllAccessibleAccounts_01, TestSize.Level3)
{
    int32_t result = 0;
    std::vector<AppAccountInfo> accounts;
    int32_t res = g_accountManagerService->QueryAllAccessibleAccounts(STRING_MAX_SIZE, accounts, result);
    EXPECT_EQ(res, ERR_NONE);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: CheckAppAccess_01
 * @tc.desc: Test CheckAppAccess.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, CheckAppAccess_01, TestSize.Level3)
{
    int32_t result = 0;
    bool isAccessible = false;
    g_accountManagerService->CheckAppAccess(STRING_EMPTY, STRING_NAME, isAccessible, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->CheckAppAccess(STRING_NAME, STRING_MAX_SIZE, isAccessible, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: DeleteAccountCredential_01
 * @tc.desc: Test DeleteAccountCredential.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, DeleteAccountCredential_01, TestSize.Level3)
{
    int32_t result = 0;
    g_accountManagerService->DeleteAccountCredential(STRING_MAX_SIZE, STRING_NAME, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->DeleteAccountCredential(STRING_NAME, STRING_MAX_SIZE, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SelectAccountsByOptions_01
 * @tc.desc: Test SelectAccountsByOptions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, SelectAccountsByOptions_01, TestSize.Level3)
{
    int32_t result = 0;
    SelectAccountsOptions options;
    std::vector<std::string> stringvec(TEST_MAX_SIZE);
    std::vector<std::pair<std::string, std::string>> stringPairVec(TEST_MAX_SIZE);
    options.allowedAccounts = stringPairVec;
    options.allowedOwners = stringvec;
    options.requiredLabels = stringvec;
    sptr<IAppAccountAuthenticatorCallback> callback = nullptr;

    g_accountManagerService->SelectAccountsByOptions(options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    options.allowedAccounts.clear();
    g_accountManagerService->SelectAccountsByOptions(options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    options.allowedOwners.clear();
    g_accountManagerService->SelectAccountsByOptions(options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: VerifyCredential_01
 * @tc.desc: Test VerifyCredential.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, VerifyCredential_01, TestSize.Level3)
{
    int32_t result = 0;
    VerifyCredentialOptions options;
    options.credentialType = STRING_MAX_SIZE;
    options.credential = STRING_MAX_SIZE;
    sptr<IAppAccountAuthenticatorCallback> callback = nullptr;

    g_accountManagerService->VerifyCredential(STRING_MAX_SIZE, STRING_NAME, options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    g_accountManagerService->VerifyCredential(STRING_NAME, STRING_MAX_SIZE, options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    g_accountManagerService->VerifyCredential(STRING_NAME, STRING_NAME, options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    options.credentialType = STRING_NAME;
    g_accountManagerService->VerifyCredential(STRING_NAME, STRING_NAME, options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: CheckAccountLabels_01
 * @tc.desc: Test CheckAccountLabels.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, CheckAccountLabels_01, TestSize.Level3)
{
    int32_t result = 0;
    std::vector<std::string> labels(TEST_MAX_SIZE);
    sptr<IAppAccountAuthenticatorCallback> callback = nullptr;

    g_accountManagerService->CheckAccountLabels(STRING_MAX_SIZE, STRING_NAME, labels, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    g_accountManagerService->CheckAccountLabels(STRING_NAME, STRING_MAX_SIZE, labels, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    g_accountManagerService->CheckAccountLabels(STRING_NAME, STRING_NAME, labels, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SetAuthenticatorProperties_01
 * @tc.desc: Test SetAuthenticatorProperties.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, SetAuthenticatorProperties_01, TestSize.Level3)
{
    int32_t result = 0;
    SetPropertiesOptions options;
    sptr<IAppAccountAuthenticatorCallback> callback = nullptr;
    g_accountManagerService->SetAuthenticatorProperties(STRING_MAX_SIZE, options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_accountManagerService->SetAuthenticatorProperties(STRING_EMPTY, options, callback, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: UnsubscribeAppAccount_01
 * @tc.desc: Test UnsubscribeAppAccount.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceCheckTest, UnsubscribeAppAccount_01, TestSize.Level3)
{
    int32_t result = 0;
    const std::vector<std::string> owners(TEST_MAX_SIZE);
    sptr<IRemoteObject> eventListener = nullptr;
    g_accountManagerService->UnsubscribeAppAccount(eventListener, owners, result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}
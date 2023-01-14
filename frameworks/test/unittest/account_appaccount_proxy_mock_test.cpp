/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include "app_account_manager.h"
#include "app_account_authenticator_callback_stub.h"

namespace OHOS {
namespace AccountTest {
namespace {
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_BUNDLE_NAME = "com.example.third_party";
const std::string STRING_KEY = "key";
const std::string STRING_VALUE = "value";
const std::string STRING_CREDENTIAL_TYPE = "password";
const std::string STRING_CREDENTIAL = "1024";
const std::string STRING_OWNER = "com.example.owner";
const std::string STRING_AUTH_TYPE = "all";
const std::string STRING_ABILITY_NAME = "MainAbility";
const std::string STRING_SESSION_ID = "123456";
const std::string STRING_TOKEN = "1024";
const bool SYNC_ENABLE_FALSE = false;
}

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;

class AuthenticatorCallbackMockTest final : public AccountSA::AppAccountAuthenticatorCallbackStub {
public:
    MOCK_METHOD2(OnResult, void(int32_t resultCode, const AAFwk::Want &result));
    MOCK_METHOD1(OnRequestRedirected, void(AAFwk::Want &request));
    MOCK_METHOD0(OnRequestContinued, void());
};

class AppAccountProxyMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountProxyMockTest::SetUpTestCase(void)
{}

void AppAccountProxyMockTest::TearDownTestCase(void)
{}

void AppAccountProxyMockTest::SetUp(void)
{}

void AppAccountProxyMockTest::TearDown(void)
{}
/**
 * @tc.name: AppAccountManager_AddAccount_0100
 * @tc.desc: Add an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQW
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_AddAccount_0100, TestSize.Level0)
{
    ErrCode result = AppAccountManager::AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_CreateAccount_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_CreateAccount_0100, TestSize.Level1)
{
    CreateAccountOptions option;
    ErrCode result = AppAccountManager::CreateAccount("test", option);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_AddAccountImplicitly_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_AddAccountImplicitly_0100, TestSize.Level1)
{
    AAFwk::Want options;
    options.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) AuthenticatorCallbackMockTest();
    ASSERT_NE(callback, nullptr);
    ErrCode result = AppAccountManager::AddAccountImplicitly(STRING_OWNER, STRING_AUTH_TYPE, options, callback);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_CreateAccountImplicitly_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_CreateAccountImplicitly_0100, TestSize.Level1)
{
    CreateAccountImplicitlyOptions options;
    options.parameters.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) AuthenticatorCallbackMockTest();
    ASSERT_NE(callback, nullptr);
    ErrCode result = AppAccountManager::CreateAccountImplicitly(STRING_OWNER, options, callback);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_DeleteAccount_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQW
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_DeleteAccount_0100, TestSize.Level1)
{
    ErrCode result = AppAccountManager::DeleteAccount(STRING_NAME);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_GetAccountExtraInfo_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_GetAccountExtraInfo_0100, TestSize.Level1)
{
    std::string extraInfo;
    ErrCode result = AppAccountManager::GetAccountExtraInfo(STRING_NAME, extraInfo);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_SetAccountExtraInfo_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_SetAccountExtraInfo_0100, TestSize.Level1)
{
    ErrCode result = AppAccountManager::SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}


/**
 * @tc.name: AppAccountManager_EnableAppAccess_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_EnableAppAccess_0100, TestSize.Level1)
{
    ErrCode result = AppAccountManager::EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_DisableAppAccess_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_DisableAppAccess_0100, TestSize.Level1)
{
    ErrCode result = AppAccountManager::DisableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_SetAppAccess_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_SetAppAccess_0100, TestSize.Level1)
{
    ErrCode result = AppAccountManager::SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, false);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_CheckAppAccountSyncEnable_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_CheckAppAccountSyncEnable_0100, TestSize.Level1)
{
    bool syncEnable = SYNC_ENABLE_FALSE;
    ErrCode result = AppAccountManager::CheckAppAccountSyncEnable(STRING_NAME, syncEnable);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_SetAppAccountSyncEnable_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_SetAppAccountSyncEnable_0100, TestSize.Level1)
{
    ErrCode result = AppAccountManager::SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_FALSE);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_GetAssociatedData_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_GetAssociatedData_0100, TestSize.Level1)
{
    std::string value;
    ErrCode result = AppAccountManager::GetAssociatedData(STRING_NAME, STRING_KEY, value);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_SetAssociatedData_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_SetAssociatedData_0600, TestSize.Level1)
{
    ErrCode result = AppAccountManager::SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_GetAccountCredential_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_GetAccountCredential_0100, TestSize.Level1)
{
    std::string credential;
    ErrCode result = AppAccountManager::GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_SetAccountCredential_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_SetAccountCredential_0100, TestSize.Level1)
{
    ErrCode result = AppAccountManager::SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_GetOAuthToken_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_GetOAuthToken_0100, TestSize.Level1)
{
    std::string token;
    ErrCode result = AppAccountManager::GetOAuthToken(STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, token);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_GetAuthToken_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_GetAuthToken_0100, TestSize.Level1)
{
    std::string token;
    ErrCode result = AppAccountManager::GetAuthToken(STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, token);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_SetOAuthToken_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_SetOAuthToken_0100, TestSize.Level1)
{
    ErrCode result = AppAccountManager::SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_DeleteOAuthToken_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_DeleteOAuthToken_0100, TestSize.Level1)
{
    ErrCode result = AppAccountManager::DeleteOAuthToken(STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, STRING_TOKEN);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_DeleteAuthToken_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_DeleteAuthToken_0100, TestSize.Level1)
{
    ErrCode result = AppAccountManager::DeleteAuthToken(STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, STRING_TOKEN);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_SetOAuthTokenVisibility_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_SetOAuthTokenVisibility_0100, TestSize.Level1)
{
    ErrCode result = AppAccountManager::SetOAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_SetAuthTokenVisibility_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_SetAuthTokenVisibility_0100, TestSize.Level1)
{
    ErrCode result = AppAccountManager::SetAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_CheckOAuthTokenVisibility_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_CheckOAuthTokenVisibility_0100, TestSize.Level1)
{
    bool isVisible = false;
    ErrCode result = AppAccountManager::CheckOAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_CheckAuthTokenVisibility_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_CheckAuthTokenVisibility_0100, TestSize.Level1)
{
    bool isVisible = false;
    ErrCode result = AppAccountManager::CheckAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}


/**
 * @tc.name: AppAccountManager_GetAuthenticatorInfo_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_GetAuthenticatorInfo_0100, TestSize.Level1)
{
    AuthenticatorInfo info;
    ErrCode result = AppAccountManager::GetAuthenticatorInfo(STRING_SESSION_ID, info);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_GetAllOAuthTokens_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_GetAllOAuthTokens_0100, TestSize.Level1)
{
    std::vector<OAuthTokenInfo> tokenInfos;
    ErrCode result = AppAccountManager::GetAllOAuthTokens(STRING_NAME, STRING_OWNER, tokenInfos);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_GetOAuthList_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_GetOAuthList_0100, TestSize.Level1)
{
    std::set<std::string> oauthList;
    ErrCode result = AppAccountManager::GetOAuthList(STRING_OWNER, STRING_AUTH_TYPE, oauthList);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_GetAuthList_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_GetAuthList_0100, TestSize.Level1)
{
    std::set<std::string> oauthList;
    ErrCode result = AppAccountManager::GetAuthList(STRING_OWNER, STRING_AUTH_TYPE, oauthList);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_GetAuthenticatorCallback_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_GetAuthenticatorCallback_0100, TestSize.Level1)
{
    sptr<IRemoteObject> callback;
    ErrCode result = AppAccountManager::GetAuthenticatorCallback(STRING_SESSION_ID, callback);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_GetAllAccounts_0300
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQS
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_GetAllAccounts_0300, TestSize.Level1)
{
    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = AppAccountManager::GetAllAccounts(STRING_OWNER, appAccounts);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_GetAllAccessibleAccounts_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQS
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_GetAllAccessibleAccounts_0100, TestSize.Level1)
{
    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = AppAccountManager::GetAllAccessibleAccounts(appAccounts);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_QueryAllAccessibleAccounts_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQS
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_QueryAllAccessibleAccounts_0100, TestSize.Level1)
{
    std::vector<AppAccountInfo> appAccounts;
    std::string owner = "";
    ErrCode result = AppAccountManager::QueryAllAccessibleAccounts(owner, appAccounts);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_CheckAppAccess_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_CheckAppAccess_0100, TestSize.Level1)
{
    bool isAccess = false;
    ErrCode result = AppAccountManager::CheckAppAccess(STRING_NAME, STRING_BUNDLE_NAME, isAccess);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_DeleteAccountCredential_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_DeleteAccountCredential_0100, TestSize.Level1)
{
    ErrCode result = AppAccountManager::DeleteAccountCredential(STRING_NAME, STRING_CREDENTIAL);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_SelectAccountsByOptions_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_SelectAccountsByOptions_0100, TestSize.Level1)
{
    SelectAccountsOptions options;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) AuthenticatorCallbackMockTest();
    ASSERT_NE(callback, nullptr);
    ErrCode result = AppAccountManager::SelectAccountsByOptions(options, callback);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_VerifyCredential_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_VerifyCredential_0100, TestSize.Level1)
{
    VerifyCredentialOptions options;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) AuthenticatorCallbackMockTest();
    ASSERT_NE(callback, nullptr);
    ErrCode result = AppAccountManager::VerifyCredential(STRING_NAME, STRING_OWNER, options, callback);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_CheckAccountLabels_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_CheckAccountLabels_0100, TestSize.Level1)
{
    std::vector<std::string> labels;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) AuthenticatorCallbackMockTest();
    ASSERT_NE(callback, nullptr);
    labels.emplace_back("test");
    ErrCode result = AppAccountManager::CheckAccountLabels(STRING_NAME, STRING_OWNER, labels, callback);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_SetAuthenticatorProperties_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_SetAuthenticatorProperties_0100, TestSize.Level1)
{
    SetPropertiesOptions options;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) AuthenticatorCallbackMockTest();
    ASSERT_NE(callback, nullptr);
    ErrCode result = AppAccountManager::SetAuthenticatorProperties(STRING_OWNER, options, callback);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_SubscribeAppAccount_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_SubscribeAppAccount_0100, TestSize.Level1)
{
    ErrCode result = AppAccountManager::SubscribeAppAccount(nullptr);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}

/**
 * @tc.name: AppAccountManager_UnsubscribeAppAccount_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountProxyMockTest, AppAccountManager_UnsubscribeAppAccount_0100, TestSize.Level1)
{
    ErrCode result = AppAccountManager::UnsubscribeAppAccount(nullptr);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER, result);
}
}  // namespace AccountTest
}  // namespace OHOS
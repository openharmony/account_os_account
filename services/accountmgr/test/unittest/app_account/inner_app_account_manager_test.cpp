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
#include "app_account_control_manager.h"
#include "app_account_subscribe_manager.h"
#include "app_account_common.h"
#define private public
#include "inner_app_account_manager.h"
#undef private
#include "mock_app_account_control_manager.h"
#include "mock_app_account_subscribe_manager.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_OWNER = "com.example.owner";
const std::string AUTHORIZED_APP = "test";
const std::string KEY = "key";
const std::string VALUE = "value";
const std::string CREDENTIAL_TYPE = "credentialType";
const std::string CREDENTIAL = "credential";
const std::string TOKEN = "token";
const std::string BUNDLE_NAME = "com.example.bundlename";

constexpr std::int32_t UID = 10000;
}  // namespace

class InnerAppAccountManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    void MakeMockObjects();
    void MakeEmptyMockObjects();

    std::shared_ptr<InnerAppAccountManager> innerManagerPtr_;
};

void InnerAppAccountManagerTest::SetUpTestCase(void)
{}

void InnerAppAccountManagerTest::TearDownTestCase(void)
{}

void InnerAppAccountManagerTest::SetUp(void)
{}

void InnerAppAccountManagerTest::TearDown(void)
{}

void InnerAppAccountManagerTest::MakeMockObjects()
{
    auto innerManagerPtr = std::make_shared<InnerAppAccountManager>();

    // make mock control manager
    auto controlManagerPtr = std::make_shared<MockAppAccountControlManager>();
    innerManagerPtr->controlManagerPtr_ = controlManagerPtr;

    // make mock subscribe manager
    auto subscribeManagerPtr = std::make_shared<MockAppAccountSubscribeManager>();
    innerManagerPtr->subscribeManagerPtr_ = subscribeManagerPtr;

    innerManagerPtr_ = innerManagerPtr;
}

void InnerAppAccountManagerTest::MakeEmptyMockObjects()
{
    auto innerManagerPtr = std::make_shared<InnerAppAccountManager>();

    // make empty control manager
    innerManagerPtr->controlManagerPtr_ = nullptr;
    // make empty subscribe manager
    innerManagerPtr->subscribeManagerPtr_ = nullptr;
    // make empty authenticator manager
    innerManagerPtr->authenticatorManagerPtr_ = nullptr;
    // make empty session manager
    innerManagerPtr->sessionManagerPtr_ = nullptr;

    innerManagerPtr_ = innerManagerPtr;
}

/**
 * @tc.name: AppAccount_AddAccount_001
 * @tc.desc: Add an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_AddAccount_001, TestSize.Level0)
{
    MakeMockObjects();

    ErrCode result = innerManagerPtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO, UID, STRING_OWNER, 0);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccount_AddAccount_002
 * @tc.desc: Add an app account with empty managers.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_AddAccount_002, TestSize.Level1)
{
    MakeEmptyMockObjects();

    ErrCode result = innerManagerPtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO, UID, STRING_OWNER, 0);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_AddAccountImplicitly_001
 * @tc.desc: AddAccountImplicitly with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_AddAccountImplicitly_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    ErrCode result = innerManagerPtr_->AddAccountImplicitly(request);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_SESSION_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_CreateAccount_001
 * @tc.desc: Create an app account with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_CreateAccount_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    CreateAccountOptions options;
    ErrCode result = innerManagerPtr_->CreateAccount(STRING_NAME, options, UID, STRING_OWNER, 0);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_CreateAccountImplicitly_001
 * @tc.desc: CreateAccountImplicitly with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_CreateAccountImplicitly_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    ErrCode result = innerManagerPtr_->CreateAccountImplicitly(request);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_SESSION_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_GetAccountExtraInfo_001
 * @tc.desc: GetAccountExtraInfo with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_GetAccountExtraInfo_001, TestSize.Level1)
{
    MakeEmptyMockObjects();
    std::string extraInfo = "STRING_EXTRA_INFO";
    ErrCode result = innerManagerPtr_->GetAccountExtraInfo(STRING_NAME, extraInfo, UID, STRING_OWNER, 0);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_SetAccountExtraInfo_001
 * @tc.desc: SetAccountExtraInfo with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_SetAccountExtraInfo_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    ErrCode result = innerManagerPtr_->SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO, UID, STRING_OWNER, 0);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_EnableAppAccess_001
 * @tc.desc: EnableAppAccess with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_EnableAppAccess_001, TestSize.Level1)
{
    MakeEmptyMockObjects();
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_OWNER;
    ErrCode result = innerManagerPtr_->EnableAppAccess(STRING_NAME, AUTHORIZED_APP, appAccountCallingInfo, false);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_DisableAppAccess_001
 * @tc.desc: DisableAppAccess with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_DisableAppAccess_001, TestSize.Level1)
{
    MakeEmptyMockObjects();
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_OWNER;
    ErrCode result = innerManagerPtr_->DisableAppAccess(STRING_NAME, AUTHORIZED_APP, appAccountCallingInfo, false);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_CheckAppAccess_001
 * @tc.desc: CheckAppAccess with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_CheckAppAccess_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AppAccountCallingInfo appAccountCallingInfo;
    bool isAccessible = false;
    ErrCode result =
        innerManagerPtr_->CheckAppAccess(STRING_NAME, AUTHORIZED_APP, isAccessible, appAccountCallingInfo);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_CheckAppAccountSyncEnable_001
 * @tc.desc: CheckAppAccountSyncEnable with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_CheckAppAccountSyncEnable_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    bool syncEnable = true;
    ErrCode result = innerManagerPtr_->CheckAppAccountSyncEnable(STRING_NAME, syncEnable, UID, STRING_OWNER, 0);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_SetAppAccountSyncEnable_001
 * @tc.desc: SetAppAccountSyncEnable with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_SetAppAccountSyncEnable_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    ErrCode result = innerManagerPtr_->SetAppAccountSyncEnable(STRING_NAME, true, UID, STRING_OWNER, 0);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_GetAssociatedData_001
 * @tc.desc: GetAssociatedData with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_GetAssociatedData_001, TestSize.Level1)
{
    MakeEmptyMockObjects();
    std::string value = "value";
    ErrCode result = innerManagerPtr_->GetAssociatedData(STRING_NAME, KEY, value, UID);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_SetAssociatedData_001
 * @tc.desc: SetAssociatedData with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_SetAssociatedData_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode result = innerManagerPtr_->SetAssociatedData(STRING_NAME, KEY, VALUE, appAccountCallingInfo);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_GetAccountCredential_001
 * @tc.desc: GetAccountCredential with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_GetAccountCredential_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AppAccountCallingInfo appAccountCallingInfo;
    std::string credential = "credential";
    ErrCode result =
        innerManagerPtr_->GetAccountCredential(STRING_NAME, CREDENTIAL_TYPE, credential, appAccountCallingInfo);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_SetAccountCredential_001
 * @tc.desc: SetAccountCredential with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_SetAccountCredential_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode result =
        innerManagerPtr_->SetAccountCredential(STRING_NAME, CREDENTIAL_TYPE, CREDENTIAL, appAccountCallingInfo);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_DeleteAccountCredential_001
 * @tc.desc: DeleteAccountCredential with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_DeleteAccountCredential_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    ErrCode result = innerManagerPtr_->DeleteAccountCredential(STRING_NAME, CREDENTIAL_TYPE, UID, STRING_OWNER, 0);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_Authenticate_001
 * @tc.desc: Authenticate with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_Authenticate_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    ErrCode result = innerManagerPtr_->Authenticate(request);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_GetOAuthToken_001
 * @tc.desc: GetOAuthToken with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_GetOAuthToken_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    std::string token = "token";
    ErrCode result = innerManagerPtr_->GetOAuthToken(request, token);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_SetOAuthToken_001
 * @tc.desc: SetOAuthToken with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_SetOAuthToken_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    ErrCode result = innerManagerPtr_->SetOAuthToken(request);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_DeleteOAuthToken_001
 * @tc.desc: DeleteOAuthToken with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_DeleteOAuthToken_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    ErrCode result = innerManagerPtr_->DeleteOAuthToken(request);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_SetOAuthTokenVisibility_001
 * @tc.desc: SetOAuthTokenVisibility with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_SetOAuthTokenVisibility_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    ErrCode result = innerManagerPtr_->SetOAuthTokenVisibility(request);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_CheckOAuthTokenVisibility_001
 * @tc.desc: CheckOAuthTokenVisibility with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_CheckOAuthTokenVisibility_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    bool isVisible = true;
    ErrCode result = innerManagerPtr_->CheckOAuthTokenVisibility(request, isVisible);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_GetAuthenticatorInfo_001
 * @tc.desc: GetAuthenticatorInfo with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_GetAuthenticatorInfo_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    AuthenticatorInfo info;
    ErrCode result = innerManagerPtr_->GetAuthenticatorInfo(request, info);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_AUTHENTICATOR_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_GetAllOAuthTokens_001
 * @tc.desc: GetAllOAuthTokens with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_GetAllOAuthTokens_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    std::vector<OAuthTokenInfo> tokenInfos;
    ErrCode result = innerManagerPtr_->GetAllOAuthTokens(request, tokenInfos);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_GetOAuthList_001
 * @tc.desc: GetOAuthList with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_GetOAuthList_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    std::set<std::string> oauthList;
    ErrCode result = innerManagerPtr_->GetOAuthList(request, oauthList);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_GetAuthenticatorCallback_001
 * @tc.desc: GetAuthenticatorCallback with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_GetAuthenticatorCallback_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    sptr<IRemoteObject> callback = nullptr;
    ErrCode result = innerManagerPtr_->GetAuthenticatorCallback(request, callback);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_GetAllAccounts_001
 * @tc.desc: GetAllAccounts with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_GetAllAccounts_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = innerManagerPtr_->GetAllAccounts(STRING_OWNER, appAccounts, UID, BUNDLE_NAME, 0);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_GetAllAccessibleAccounts_001
 * @tc.desc: GetAllAccessibleAccounts with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_GetAllAccessibleAccounts_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = innerManagerPtr_->GetAllAccessibleAccounts(appAccounts, UID, BUNDLE_NAME, 0);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_SelectAccountsByOptions_001
 * @tc.desc: SelectAccountsByOptions with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_SelectAccountsByOptions_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    SelectAccountsOptions options;
    ErrCode result = innerManagerPtr_->SelectAccountsByOptions(options, nullptr, UID, BUNDLE_NAME, 0);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_VerifyCredential_001
 * @tc.desc: VerifyCredential with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_VerifyCredential_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    ErrCode result = innerManagerPtr_->VerifyCredential(request);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_SESSION_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_CheckAccountLabels_001
 * @tc.desc: CheckAccountLabels with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_CheckAccountLabels_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    ErrCode result = innerManagerPtr_->CheckAccountLabels(request);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_SESSION_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_SetAuthenticatorProperties_001
 * @tc.desc: SetAuthenticatorProperties with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_SetAuthenticatorProperties_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    AuthenticatorSessionRequest request;
    ErrCode result = innerManagerPtr_->SetAuthenticatorProperties(request);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_OnPackageRemoved_001
 * @tc.desc: OnPackageRemoved with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_OnPackageRemoved_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    ErrCode result = innerManagerPtr_->OnPackageRemoved(UID, BUNDLE_NAME, 0);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_OnUserRemoved_001
 * @tc.desc: OnUserRemoved with empty managers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_OnUserRemoved_001, TestSize.Level1)
{
    MakeEmptyMockObjects();

    ErrCode result = innerManagerPtr_->OnUserRemoved(UID);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_DeleteAccount_001
 * @tc.desc: Delete an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_DeleteAccount_001, TestSize.Level1)
{
    MakeMockObjects();

    ErrCode result = innerManagerPtr_->DeleteAccount(STRING_NAME, UID, STRING_OWNER, 0);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccount_DeleteAccount_002
 * @tc.desc: Delete an app account with empty managers.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_DeleteAccount_002, TestSize.Level1)
{
    MakeEmptyMockObjects();

    ErrCode result = innerManagerPtr_->DeleteAccount(STRING_NAME, UID, STRING_OWNER, 0);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_SubscribeAppAccount_001
 * @tc.desc: Subscribe app accounts with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_SubscribeAppAccount_001, TestSize.Level1)
{
    MakeMockObjects();

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo;
    subscribeInfo.SetOwners(owners);

    // subscribe app account
    ErrCode result = innerManagerPtr_->SubscribeAppAccount(subscribeInfo, nullptr, UID, STRING_OWNER, 0);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_EVENT_LISTENER_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_SubscribeAppAccount_002
 * @tc.desc: Subscribe app accounts with empty managers.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_SubscribeAppAccount_002, TestSize.Level1)
{
    MakeEmptyMockObjects();

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo;
    subscribeInfo.SetOwners(owners);

    // subscribe app account
    ErrCode result = innerManagerPtr_->SubscribeAppAccount(subscribeInfo, nullptr, UID, STRING_OWNER, 0);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_UnsubscribeAppAccount_001
 * @tc.desc: Unsubscribe app accounts with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_UnsubscribeAppAccount_001, TestSize.Level1)
{
    MakeMockObjects();

    // unsubscribe app account
    ErrCode result = innerManagerPtr_->UnsubscribeAppAccount(nullptr);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_EVENT_LISTENER_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_UnsubscribeAppAccount_002
 * @tc.desc: Unsubscribe app accounts with empty managers.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_UnsubscribeAppAccount_002, TestSize.Level1)
{
    MakeEmptyMockObjects();

    // unsubscribe app account
    ErrCode result = innerManagerPtr_->UnsubscribeAppAccount(nullptr);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR);
}

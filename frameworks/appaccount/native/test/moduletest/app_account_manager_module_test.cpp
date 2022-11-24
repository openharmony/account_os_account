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

#include "account_log_wrapper.h"
#define private public
#include "app_account_control_manager.h"
#undef private
#include "app_account_manager.h"
#include "app_account_subscriber.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_NAME_MAX_SIZE =
    "name_1234567"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_AUTHORIZED_APP = "com.example.authorized_app";
const std::string STRING_KEY = "key";
const std::string STRING_VALUE = "value";
const std::string STRING_CREDENTIAL_TYPE = "password";
const std::string STRING_CREDENTIAL = "1024";
const std::string STRING_TOKEN = "1024";
const std::string STRING_OWNER = "com.example.owner";
const std::string STRING_AUTH_TYPE = "all";

const bool SYNC_ENABLE_FALSE = false;
}  // namespace

class AppAccountManagerModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    std::shared_ptr<AppAccountControlManager> controlManagerPtr_;
};

void AppAccountManagerModuleTest::SetUpTestCase(void)
{}

void AppAccountManagerModuleTest::TearDownTestCase(void)
{}

void AppAccountManagerModuleTest::SetUp(void)
{}

void AppAccountManagerModuleTest::TearDown(void)
{}

class AppAccountSubscriberTest : public AppAccountSubscriber {
public:
    explicit AppAccountSubscriberTest(const AppAccountSubscribeInfo &subscribeInfo)
        : AppAccountSubscriber(subscribeInfo)
    {
        ACCOUNT_LOGI("enter");
    }

    ~AppAccountSubscriberTest()
    {}

    virtual void OnAccountsChanged(const std::vector<AppAccountInfo> &accounts)
    {
        ACCOUNT_LOGI("enter");
    }
};

/**
 * @tc.name: AppAccountManager_AddAccount_0100
 * @tc.desc: Add an account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_AddAccount_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManager_AddAccount_0100");

    ErrCode result = AppAccountManager::AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_AddAccount_0200
 * @tc.desc: Add an account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_AddAccount_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_AddAccount_0200");

    ErrCode result = AppAccountManager::AddAccount(STRING_NAME_MAX_SIZE, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_CreateAccount_0100
 * @tc.desc: Add an account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_CreateAccount_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManager_CreateAccount_0100");
    CreateAccountOptions option;
    ErrCode result = AppAccountManager::CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_CreateAccount_0200
 * @tc.desc: Add an account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_CreateAccount_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CreateAccount_0200");
    CreateAccountOptions option;
    option.customData.emplace(STRING_KEY, STRING_VALUE);
    ErrCode result = AppAccountManager::CreateAccount(STRING_NAME_MAX_SIZE, option);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_DeleteAccount_0100
 * @tc.desc: Delete an account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_DeleteAccount_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManager_DeleteAccount_0100");

    ErrCode result = AppAccountManager::DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_GetAccountExtraInfo_0100
 * @tc.desc: Get account extra info with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_GetAccountExtraInfo_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountExtraInfo_0100");

    std::string extraInfo;
    ErrCode result = AppAccountManager::GetAccountExtraInfo(STRING_NAME, extraInfo);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_SetAccountExtraInfo_0100
 * @tc.desc: Set account extra info with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_SetAccountExtraInfo_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountExtraInfo_0100");

    ErrCode result = AppAccountManager::SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_EnableAppAccess_0100
 * @tc.desc: Enable app access with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_EnableAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_EnableAppAccess_0100");

    ErrCode result = AppAccountManager::EnableAppAccess(STRING_NAME, STRING_AUTHORIZED_APP);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_SetAppAccess_0100
 * @tc.desc: Enable app access with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_SetAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAppAccess_0100");

    ErrCode result = AppAccountManager::SetAppAccess(STRING_NAME, STRING_AUTHORIZED_APP, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_DisableAppAccess_0100
 * @tc.desc: Disable app access with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_DisableAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DisableAppAccess_0100");

    ErrCode result = AppAccountManager::DisableAppAccess(STRING_NAME, STRING_AUTHORIZED_APP);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_SetAppAccess_0200
 * @tc.desc: Disable app access with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_SetAppAccess_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAppAccess_0200");

    ErrCode result = AppAccountManager::SetAppAccess(STRING_NAME, STRING_AUTHORIZED_APP, false);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_CheckAppAccountSyncEnable_0100
 * @tc.desc: Check account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_CheckAppAccountSyncEnable_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CheckAppAccountSyncEnable_0100");

    bool syncEnable = SYNC_ENABLE_FALSE;
    ErrCode result = AppAccountManager::CheckAppAccountSyncEnable(STRING_NAME, syncEnable);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_SetAppAccountSyncEnable_0100
 * @tc.desc: Set account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_SetAppAccountSyncEnable_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAppAccountSyncEnable_0100");

    ErrCode result = AppAccountManager::SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_FALSE);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_GetAssociatedData_0100
 * @tc.desc: Get associated data with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_GetAssociatedData_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAssociatedData_0100");

    std::string value;
    ErrCode result = AppAccountManager::GetAssociatedData(STRING_NAME, STRING_KEY, value);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_APP_INDEX);
}

/**
 * @tc.name: AppAccountManager_SetAssociatedData_0100
 * @tc.desc: Set associated data with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_SetAssociatedData_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAssociatedData_0100");

    ErrCode result = AppAccountManager::SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_GetAccountCredential_0100
 * @tc.desc: Get account credential with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_GetAccountCredential_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountCredential_0100");

    std::string credential;
    ErrCode result = AppAccountManager::GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_SetAccountCredential_0100
 * @tc.desc: Set account credential with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_SetAccountCredential_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountCredential_0100");

    ErrCode result = AppAccountManager::SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_GetOAuthToken_0100
 * @tc.desc: Get oauth token with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFU
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_GetOAuthToken_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetOAuthToken_0100");

    std::string token;
    ErrCode result = AppAccountManager::GetOAuthToken(STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_SetOAuthToken_0100
 * @tc.desc: Set oauth token with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFU
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_SetOAuthToken_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetOAuthToken_0100");

    ErrCode result = AppAccountManager::SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_GetAllAccounts_0100
 * @tc.desc: Get all accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFR
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_GetAllAccounts_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAllAccounts_0100");

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = AppAccountManager::GetAllAccounts(STRING_NAME, appAccounts);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_SubscribeAppAccount_0100
 * @tc.desc: Subscribe app account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_SubscribeAppAccount_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SubscribeAppAccount_0100");

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo(owners);

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);

    ErrCode result = AppAccountManager::SubscribeAppAccount(subscriberTestPtr);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_UnsubscribeAppAccount_0100
 * @tc.desc: Unsubscribe app account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_UnsubscribeAppAccount_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_UnsubscribeAppAccount_0100");

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo(owners);

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);

    ErrCode result = AppAccountManager::UnsubscribeAppAccount(subscriberTestPtr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED);
}

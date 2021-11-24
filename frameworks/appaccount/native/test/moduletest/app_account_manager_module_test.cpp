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

#define private public
#include "app_account_control_manager.h"
#undef private
#include "app_account_manager.h"

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

const bool SYNC_ENABLE_FALSE = false;
}  // namespace

class AppAccountManagerModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    void DeleteKvStore(void);

    std::shared_ptr<AppAccountControlManager> controlManagerPtr_;
};

void AppAccountManagerModuleTest::SetUpTestCase(void)
{}

void AppAccountManagerModuleTest::TearDownTestCase(void)
{}

void AppAccountManagerModuleTest::SetUp(void)
{
    DeleteKvStore();
}

void AppAccountManagerModuleTest::TearDown(void)
{
    DeleteKvStore();
}

void AppAccountManagerModuleTest::DeleteKvStore(void)
{
    controlManagerPtr_ = AppAccountControlManager::GetInstance();
    ASSERT_NE(controlManagerPtr_, nullptr);

    auto dataStoragePtr = controlManagerPtr_->GetDataStorage();
    ASSERT_NE(dataStoragePtr, nullptr);

    ErrCode result = dataStoragePtr->DeleteKvStore();
    ASSERT_EQ(result, ERR_OK);

    dataStoragePtr = controlManagerPtr_->GetDataStorage(true);
    ASSERT_NE(dataStoragePtr, nullptr);

    result = dataStoragePtr->DeleteKvStore();
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManager_AddAccount_0100
 * @tc.name: AddAccount
 * @tc.desc: Add an account with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_AddAccount_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_AddAccount_0100");

    ErrCode result = AppAccountManager::AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_AddAccount_0200
 * @tc.name: AddAccount
 * @tc.desc: Add an account with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_AddAccount_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_AddAccount_0200");

    ErrCode result = AppAccountManager::AddAccount(STRING_NAME_MAX_SIZE, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_DeleteAccount_0100
 * @tc.name: DeleteAccount
 * @tc.desc: Delete an account with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_DeleteAccount_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DeleteAccount_0100");

    ErrCode result = AppAccountManager::DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_GetAccountExtraInfo_0100
 * @tc.name: GetAccountExtraInfo
 * @tc.desc: Get account extra info with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_GetAccountExtraInfo_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountExtraInfo_0100");

    std::string extraInfo;
    ErrCode result = AppAccountManager::GetAccountExtraInfo(STRING_NAME, extraInfo);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_SetAccountExtraInfo_0100
 * @tc.name: SetAccountExtraInfo
 * @tc.desc: Set account extra info with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_SetAccountExtraInfo_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountExtraInfo_0100");

    ErrCode result = AppAccountManager::SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_EnableAppAccess_0100
 * @tc.name: EnableAppAccess
 * @tc.desc: Enable app access with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_EnableAppAccess_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_EnableAppAccess_0100");

    ErrCode result = AppAccountManager::EnableAppAccess(STRING_NAME, STRING_AUTHORIZED_APP);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_DisableAppAccess_0100
 * @tc.name: DisableAppAccess
 * @tc.desc: Disable app access with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_DisableAppAccess_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DisableAppAccess_0100");

    ErrCode result = AppAccountManager::DisableAppAccess(STRING_NAME, STRING_AUTHORIZED_APP);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_CheckAppAccountSyncEnable_0100
 * @tc.name: CheckAppAccountSyncEnable
 * @tc.desc: Check account sync enable with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_CheckAppAccountSyncEnable_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CheckAppAccountSyncEnable_0100");

    bool syncEnable = SYNC_ENABLE_FALSE;
    ErrCode result = AppAccountManager::CheckAppAccountSyncEnable(STRING_NAME, syncEnable);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_SetAppAccountSyncEnable_0100
 * @tc.name: SetAppAccountSyncEnable
 * @tc.desc: Set account sync enable with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_SetAppAccountSyncEnable_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAppAccountSyncEnable_0100");

    ErrCode result = AppAccountManager::SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_FALSE);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_GetAssociatedData_0100
 * @tc.name: GetAssociatedData
 * @tc.desc: Get associated data with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_GetAssociatedData_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAssociatedData_0100");

    std::string value;
    ErrCode result = AppAccountManager::GetAssociatedData(STRING_NAME, STRING_KEY, value);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_SetAssociatedData_0100
 * @tc.name: SetAssociatedData
 * @tc.desc: Set associated data with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_SetAssociatedData_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAssociatedData_0100");

    ErrCode result = AppAccountManager::SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_GetAccountCredential_0100
 * @tc.name: GetAccountCredential
 * @tc.desc: Get account credential with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_GetAccountCredential_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountCredential_0100");

    std::string credential;
    ErrCode result = AppAccountManager::GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_SetAccountCredential_0100
 * @tc.name: SetAccountCredential
 * @tc.desc: Set account credential with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_SetAccountCredential_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountCredential_0100");

    ErrCode result = AppAccountManager::SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_GetOAuthToken_0100
 * @tc.name: GetOAuthToken
 * @tc.desc: Get oauth token with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_GetOAuthToken_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetOAuthToken_0100");

    std::string token;
    ErrCode result = AppAccountManager::GetOAuthToken(STRING_NAME, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_SetOAuthToken_0100
 * @tc.name: SetOAuthToken
 * @tc.desc: Set oauth token with invalid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_SetOAuthToken_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetOAuthToken_0100");

    ErrCode result = AppAccountManager::SetOAuthToken(STRING_NAME, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_ClearOAuthToken_0100
 * @tc.name: ClearOAuthToken
 * @tc.desc: Clear oauth token with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_ClearOAuthToken_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_ClearOAuthToken_0100");

    ErrCode result = AppAccountManager::ClearOAuthToken(STRING_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountManager_GetAllAccounts_0100
 * @tc.name: GetAllAccounts
 * @tc.desc: Get all accounts with valid data.
 */
HWTEST_F(AppAccountManagerModuleTest, AppAccountManager_GetAllAccounts_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAllAccounts_0100");

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = AppAccountManager::GetAllAccounts(STRING_NAME, appAccounts);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

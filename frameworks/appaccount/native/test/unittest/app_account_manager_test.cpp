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

#include "account_error_no.h"
#include "app_account_manager.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_NAME_OUT_OF_RANGE =
    "name_12345678"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_EXTRA_INFO_OUT_OF_RANGE =
    "extra_info_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_BUNDLE_NAME = "com.example.third_party";
const std::string STRING_OWNER_OUT_OF_RANGE =
    "owner_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_EMPTY = "";
const std::string STRING_KEY = "key";
const std::string STRING_KEY_OUT_OF_RANGE =
    "key_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_VALUE = "value";
const std::string STRING_VALUE_OUT_OF_RANGE =
    "value_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_CREDENTIAL_TYPE = "password";
const std::string STRING_CREDENTIAL_TYPE_OUT_OF_RANGE =
    "credential_type_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_AUTHORIZED_APP_OUT_OF_RANGE =
    "authorized_app_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_CREDENTIAL = "1024";
const std::string STRING_CREDENTIAL_OUT_OF_RANGE =
    "credential_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_TOKEN = "1024";
const std::string STRING_TOKEN_OUT_OF_RANGE =
    "token_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_OWNER = "com.example.owner";

const bool SYNC_ENABLE_FALSE = false;

constexpr std::size_t SIZE_ZERO = 0;
}  // namespace

class AppAccountManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountManagerTest::SetUpTestCase(void)
{}

void AppAccountManagerTest::TearDownTestCase(void)
{}

void AppAccountManagerTest::SetUp(void)
{}

void AppAccountManagerTest::TearDown(void)
{}

/**
 * @tc.number: AppAccountManager_AddAccount_0100
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_AddAccount_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_AddAccount_0100");

    ErrCode result = AppAccountManager::AddAccount(STRING_EMPTY);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
}

/**
 * @tc.number: AppAccountManager_AddAccount_0200
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_AddAccount_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_AddAccount_0200");

    ErrCode result = AppAccountManager::AddAccount(STRING_NAME_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_AddAccount_0300
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_AddAccount_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_AddAccount_0300");

    ErrCode result = AppAccountManager::AddAccount(STRING_NAME, STRING_EXTRA_INFO_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_EXTRA_INFO_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_DeleteAccount_0100
 * @tc.name: DeleteAccount
 * @tc.desc: Delete an app account with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DeleteAccount_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DeleteAccount_0100");

    ErrCode result = AppAccountManager::DeleteAccount(STRING_EMPTY);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
}

/**
 * @tc.number: AppAccountManager_DeleteAccount_0200
 * @tc.name: DeleteAccount
 * @tc.desc: Delete an app account with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DeleteAccount_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DeleteAccount_0200");

    ErrCode result = AppAccountManager::DeleteAccount(STRING_NAME_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_GetAccountExtraInfo_0100
 * @tc.name: GetAccountExtraInfo
 * @tc.desc: Get extra info of an app account with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAccountExtraInfo_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountExtraInfo_0100");

    std::string extraInfo;
    ErrCode result = AppAccountManager::GetAccountExtraInfo(STRING_EMPTY, extraInfo);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
    EXPECT_EQ(extraInfo, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManager_GetAccountExtraInfo_0200
 * @tc.name: GetAccountExtraInfo
 * @tc.desc: Get extra info of an app account with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAccountExtraInfo_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountExtraInfo_0200");

    std::string extraInfo;
    ErrCode result = AppAccountManager::GetAccountExtraInfo(STRING_NAME_OUT_OF_RANGE, extraInfo);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
    EXPECT_EQ(extraInfo, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManager_SetAccountExtraInfo_0100
 * @tc.name: SetAccountExtraInfo
 * @tc.desc: Set extra info of an app account with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountExtraInfo_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountExtraInfo_0100");

    ErrCode result = AppAccountManager::SetAccountExtraInfo(STRING_EMPTY, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
}

/**
 * @tc.number: AppAccountManager_SetAccountExtraInfo_0200
 * @tc.name: SetAccountExtraInfo
 * @tc.desc: Set extra info of an app account with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountExtraInfo_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountExtraInfo_0200");

    ErrCode result = AppAccountManager::SetAccountExtraInfo(STRING_NAME_OUT_OF_RANGE, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_SetAccountExtraInfo_0300
 * @tc.name: SetAccountExtraInfo
 * @tc.desc: Set extra info of an app account with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountExtraInfo_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountExtraInfo_0300");

    ErrCode result = AppAccountManager::SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_EXTRA_INFO_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_EnableAppAccess_0100
 * @tc.name: EnableAppAccess
 * @tc.desc: Enable app access with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_EnableAppAccess_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_EnableAppAccess_0100");

    ErrCode result = AppAccountManager::EnableAppAccess(STRING_EMPTY, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
}

/**
 * @tc.number: AppAccountManager_EnableAppAccess_0200
 * @tc.name: EnableAppAccess
 * @tc.desc: Enable app access with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_EnableAppAccess_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_EnableAppAccess_0200");

    ErrCode result = AppAccountManager::EnableAppAccess(STRING_NAME_OUT_OF_RANGE, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_EnableAppAccess_0300
 * @tc.name: EnableAppAccess
 * @tc.desc: Enable app access with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_EnableAppAccess_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_EnableAppAccess_0300");

    ErrCode result = AppAccountManager::EnableAppAccess(STRING_NAME, STRING_EMPTY);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_AUTHORIZED_APP_IS_EMPTY);
}

/**
 * @tc.number: AppAccountManager_EnableAppAccess_0400
 * @tc.name: EnableAppAccess
 * @tc.desc: Enable app access with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_EnableAppAccess_0400, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_EnableAppAccess_0400");

    ErrCode result = AppAccountManager::EnableAppAccess(STRING_NAME, STRING_AUTHORIZED_APP_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_AUTHORIZED_APP_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_DisableAppAccess_0100
 * @tc.name: DisableAppAccess
 * @tc.desc: Disable app access with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DisableAppAccess_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DisableAppAccess_0100");

    ErrCode result = AppAccountManager::DisableAppAccess(STRING_EMPTY, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
}

/**
 * @tc.number: AppAccountManager_DisableAppAccess_0200
 * @tc.name: DisableAppAccess
 * @tc.desc: Disable app access with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DisableAppAccess_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DisableAppAccess_0200");

    ErrCode result = AppAccountManager::DisableAppAccess(STRING_NAME_OUT_OF_RANGE, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_DisableAppAccess_0300
 * @tc.name: DisableAppAccess
 * @tc.desc: Disable app access with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DisableAppAccess_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DisableAppAccess_0300");

    ErrCode result = AppAccountManager::DisableAppAccess(STRING_NAME, STRING_EMPTY);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_AUTHORIZED_APP_IS_EMPTY);
}

/**
 * @tc.number: AppAccountManager_DisableAppAccess_0400
 * @tc.name: DisableAppAccess
 * @tc.desc: Disable app access with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DisableAppAccess_0400, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DisableAppAccess_0400");

    ErrCode result = AppAccountManager::DisableAppAccess(STRING_NAME, STRING_AUTHORIZED_APP_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_AUTHORIZED_APP_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_CheckAppAccountSyncEnable_0100
 * @tc.name: CheckAppAccountSyncEnable
 * @tc.desc: Check account sync enable with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CheckAppAccountSyncEnable_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CheckAppAccountSyncEnable_0100");

    bool syncEnable = SYNC_ENABLE_FALSE;
    ErrCode result = AppAccountManager::CheckAppAccountSyncEnable(STRING_EMPTY, syncEnable);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_FALSE);
}

/**
 * @tc.number: AppAccountManager_CheckAppAccountSyncEnable_0200
 * @tc.name: CheckAppAccountSyncEnable
 * @tc.desc: Check account sync enable with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CheckAppAccountSyncEnable_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CheckAppAccountSyncEnable_0200");

    bool syncEnable = SYNC_ENABLE_FALSE;
    ErrCode result = AppAccountManager::CheckAppAccountSyncEnable(STRING_NAME_OUT_OF_RANGE, syncEnable);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_FALSE);
}

/**
 * @tc.number: AppAccountManager_SetAppAccountSyncEnable_0100
 * @tc.name: SetAppAccountSyncEnable
 * @tc.desc: Set account sync enable with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAppAccountSyncEnable_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAppAccountSyncEnable_0100");

    ErrCode result = AppAccountManager::SetAppAccountSyncEnable(STRING_EMPTY, SYNC_ENABLE_FALSE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
}

/**
 * @tc.number: AppAccountManager_SetAppAccountSyncEnable_0200
 * @tc.name: SetAppAccountSyncEnable
 * @tc.desc: Set account sync enable with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAppAccountSyncEnable_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAppAccountSyncEnable_0200");

    ErrCode result = AppAccountManager::SetAppAccountSyncEnable(STRING_NAME_OUT_OF_RANGE, SYNC_ENABLE_FALSE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_GetAssociatedData_0100
 * @tc.name: GetAssociatedData
 * @tc.desc: Get associated data with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAssociatedData_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAssociatedData_0100");

    std::string value;
    ErrCode result = AppAccountManager::GetAssociatedData(STRING_EMPTY, STRING_KEY, value);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
    EXPECT_EQ(value, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManager_GetAssociatedData_0200
 * @tc.name: GetAssociatedData
 * @tc.desc: Get associated data with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAssociatedData_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAssociatedData_0200");

    std::string value;
    ErrCode result = AppAccountManager::GetAssociatedData(STRING_NAME_OUT_OF_RANGE, STRING_KEY, value);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
    EXPECT_EQ(value, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManager_GetAssociatedData_0300
 * @tc.name: GetAssociatedData
 * @tc.desc: Get associated data with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAssociatedData_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAssociatedData_0300");

    std::string value;
    ErrCode result = AppAccountManager::GetAssociatedData(STRING_NAME, STRING_EMPTY, value);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_ASSOCIATED_KEY_IS_EMPTY);
    EXPECT_EQ(value, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManager_GetAssociatedData_0400
 * @tc.name: GetAssociatedData
 * @tc.desc: Get associated data with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAssociatedData_0400, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAssociatedData_0400");

    std::string value;
    ErrCode result = AppAccountManager::GetAssociatedData(STRING_NAME, STRING_KEY_OUT_OF_RANGE, value);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_ASSOCIATED_KEY_OUT_OF_RANGE);
    EXPECT_EQ(value, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManager_SetAssociatedData_0100
 * @tc.name: SetAssociatedData
 * @tc.desc: Set associated data with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAssociatedData_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAssociatedData_0100");

    ErrCode result = AppAccountManager::SetAssociatedData(STRING_EMPTY, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
}

/**
 * @tc.number: AppAccountManager_SetAssociatedData_0200
 * @tc.name: SetAssociatedData
 * @tc.desc: Set associated data with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAssociatedData_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAssociatedData_0200");

    ErrCode result = AppAccountManager::SetAssociatedData(STRING_NAME_OUT_OF_RANGE, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_SetAssociatedData_0300
 * @tc.name: SetAssociatedData
 * @tc.desc: Set associated data with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAssociatedData_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAssociatedData_0300");

    ErrCode result = AppAccountManager::SetAssociatedData(STRING_NAME, STRING_EMPTY, STRING_VALUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_ASSOCIATED_KEY_IS_EMPTY);
}

/**
 * @tc.number: AppAccountManager_SetAssociatedData_0400
 * @tc.name: SetAssociatedData
 * @tc.desc: Set associated data with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAssociatedData_0400, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAssociatedData_0400");

    ErrCode result = AppAccountManager::SetAssociatedData(STRING_NAME, STRING_KEY_OUT_OF_RANGE, STRING_VALUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_ASSOCIATED_KEY_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_SetAssociatedData_0500
 * @tc.name: SetAssociatedData
 * @tc.desc: Set associated data with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAssociatedData_0500, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAssociatedData_0500");

    ErrCode result = AppAccountManager::SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_ASSOCIATED_VALUE_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_GetAccountCredential_0100
 * @tc.name: GetAccountCredential
 * @tc.desc: Get account credential with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAccountCredential_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountCredential_0100");

    std::string credential;
    ErrCode result = AppAccountManager::GetAccountCredential(STRING_EMPTY, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
    EXPECT_EQ(credential, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManager_GetAccountCredential_0200
 * @tc.name: GetAccountCredential
 * @tc.desc: Get account credential with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAccountCredential_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountCredential_0200");

    std::string credential;
    ErrCode result =
        AppAccountManager::GetAccountCredential(STRING_NAME_OUT_OF_RANGE, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
    EXPECT_EQ(credential, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManager_GetAccountCredential_0300
 * @tc.name: GetAccountCredential
 * @tc.desc: Get account credential with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAccountCredential_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountCredential_0300");

    std::string credential;
    ErrCode result = AppAccountManager::GetAccountCredential(STRING_NAME, STRING_EMPTY, credential);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_CREDENTIAL_TYPE_IS_EMPTY);
    EXPECT_EQ(credential, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManager_GetAccountCredential_0400
 * @tc.name: GetAccountCredential
 * @tc.desc: Get account credential with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAccountCredential_0400, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountCredential_0400");

    std::string credential;
    ErrCode result =
        AppAccountManager::GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE_OUT_OF_RANGE, credential);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_CREDENTIAL_TYPE_OUT_OF_RANGE);
    EXPECT_EQ(credential, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManager_SetAccountCredential_0100
 * @tc.name: SetAccountCredential
 * @tc.desc: Set account credential with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountCredential_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountCredential_0100");

    ErrCode result = AppAccountManager::SetAccountCredential(STRING_EMPTY, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
}

/**
 * @tc.number: AppAccountManager_SetAccountCredential_0200
 * @tc.name: SetAccountCredential
 * @tc.desc: Set account credential with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountCredential_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountCredential_0200");

    ErrCode result =
        AppAccountManager::SetAccountCredential(STRING_NAME_OUT_OF_RANGE, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_SetAccountCredential_0300
 * @tc.name: SetAccountCredential
 * @tc.desc: Set account credential with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountCredential_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountCredential_0300");

    ErrCode result = AppAccountManager::SetAccountCredential(STRING_NAME, STRING_EMPTY, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_CREDENTIAL_TYPE_IS_EMPTY);
}

/**
 * @tc.number: AppAccountManager_SetAccountCredential_0400
 * @tc.name: SetAccountCredential
 * @tc.desc: Set account credential with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountCredential_0400, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountCredential_0400");

    ErrCode result =
        AppAccountManager::SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE_OUT_OF_RANGE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_CREDENTIAL_TYPE_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_SetAccountCredential_0500
 * @tc.name: SetAccountCredential
 * @tc.desc: Set account credential with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountCredential_0500, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountCredential_0500");

    ErrCode result =
        AppAccountManager::SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_CREDENTIAL_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_GetOAuthToken_0100
 * @tc.name: GetOAuthToken
 * @tc.desc: Get oauth token with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetOAuthToken_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetOAuthToken_0100");

    std::string token;
    ErrCode result = AppAccountManager::GetOAuthToken(STRING_EMPTY, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
    EXPECT_EQ(token, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManager_GetOAuthToken_0200
 * @tc.name: GetOAuthToken
 * @tc.desc: Get oauth token with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetOAuthToken_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetOAuthToken_0200");

    std::string token;
    ErrCode result = AppAccountManager::GetOAuthToken(STRING_NAME_OUT_OF_RANGE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
    EXPECT_EQ(token, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManager_SetOAuthToken_0100
 * @tc.name: SetOAuthToken
 * @tc.desc: Set oauth token with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetOAuthToken_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetOAuthToken_0100");

    ErrCode result = AppAccountManager::SetOAuthToken(STRING_EMPTY, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
}

/**
 * @tc.number: AppAccountManager_SetOAuthToken_0200
 * @tc.name: SetOAuthToken
 * @tc.desc: Set oauth token with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetOAuthToken_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetOAuthToken_0200");

    ErrCode result = AppAccountManager::SetOAuthToken(STRING_NAME_OUT_OF_RANGE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_SetOAuthToken_0300
 * @tc.name: SetOAuthToken
 * @tc.desc: Set oauth token with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetOAuthToken_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetOAuthToken_0300");

    ErrCode result = AppAccountManager::SetOAuthToken(STRING_NAME, STRING_TOKEN_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_TOKEN_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_ClearOAuthToken_0100
 * @tc.name: ClearOAuthToken
 * @tc.desc: Clear oauth token with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_ClearOAuthToken_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_ClearOAuthToken_0100");

    ErrCode result = AppAccountManager::ClearOAuthToken(STRING_EMPTY);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
}

/**
 * @tc.number: AppAccountManager_ClearOAuthToken_0200
 * @tc.name: ClearOAuthToken
 * @tc.desc: Clear oauth token with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_ClearOAuthToken_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_ClearOAuthToken_0200");

    ErrCode result = AppAccountManager::ClearOAuthToken(STRING_NAME_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountManager_GetAllAccounts_0100
 * @tc.name: GetAllAccounts
 * @tc.desc: Get all accounts with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAllAccounts_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAllAccounts_0100");

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = AppAccountManager::GetAllAccounts(STRING_EMPTY, appAccounts);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_OWNER_IS_EMPTY);
    EXPECT_EQ(appAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.number: AppAccountManager_GetAllAccounts_0200
 * @tc.name: GetAllAccounts
 * @tc.desc: Get all accounts with invalid data.
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAllAccounts_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAllAccounts_0200");

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = AppAccountManager::GetAllAccounts(STRING_OWNER_OUT_OF_RANGE, appAccounts);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_OWNER_OUT_OF_RANGE);
    EXPECT_EQ(appAccounts.size(), SIZE_ZERO);
}

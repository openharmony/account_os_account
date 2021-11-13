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

#include <thread>
#define private public
#include "app_account_control_manager.h"
#include "app_account_manager_service.h"
#undef private
#include "bundle_constants.h"
#include "common_event_manager.h"
#include "common_event_support.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_NAME_TWO = "name_two";
const std::string STRING_NAME_THREE = "name_three";
const std::string STRING_NAME_NOT_EXISTED = "name_not_existed";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_BUNDLE_NAME = "com.example.third_party";
const std::string STRING_EMPTY = "";
const std::string STRING_KEY = "key";
const std::string STRING_KEY_TWO = "key_two";
const std::string STRING_VALUE = "value";
const std::string STRING_VALUE_TWO = "value_two";
const std::string STRING_CREDENTIAL_TYPE = "password";
const std::string STRING_CREDENTIAL = "1024";
const std::string STRING_CREDENTIAL_TYPE_TWO = "token";
const std::string STRING_CREDENTIAL_TWO = "2048";
const std::string STRING_TOKEN = "1024";
const std::string STRING_OWNER = "com.example.owner";

const bool SYNC_ENABLE_TRUE = true;
const bool SYNC_ENABLE_FALSE = false;

constexpr std::int32_t UID = 10000;
constexpr size_t SIZE_ZERO = 0;
constexpr size_t SIZE_ONE = 1;
constexpr size_t SIZE_TWO = 2;
constexpr std::int32_t DELAY_FOR_PACKAGE_REMOVED = 3;
constexpr std::int32_t ACCOUNT_MAX_SIZE = 32;
}  // namespace

class AppAccountManagerServiceModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    void DeleteKvStore(void);

    std::shared_ptr<AppAccountControlManager> controlManagerPtr_;
};

void AppAccountManagerServiceModuleTest::SetUpTestCase(void)
{}

void AppAccountManagerServiceModuleTest::TearDownTestCase(void)
{}

void AppAccountManagerServiceModuleTest::SetUp(void)
{
    DeleteKvStore();
}

void AppAccountManagerServiceModuleTest::TearDown(void)
{
    DeleteKvStore();
}

void AppAccountManagerServiceModuleTest::DeleteKvStore(void)
{
    controlManagerPtr_ = AppAccountControlManager::GetInstance();
    ASSERT_NE(controlManagerPtr_, nullptr);

    auto dataStoragePtr = controlManagerPtr_->GetDataStorage(false, UID);
    ASSERT_NE(dataStoragePtr, nullptr);

    ErrCode result = dataStoragePtr->DeleteKvStore();
    ASSERT_EQ(result, ERR_OK);

    dataStoragePtr = controlManagerPtr_->GetDataStorage(true, UID);
    ASSERT_NE(dataStoragePtr, nullptr);

    result = dataStoragePtr->DeleteKvStore();
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_AddAccount_0100
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccount_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccount_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_AddAccount_0200
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccount_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccount_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME_TWO, STRING_EMPTY);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->DeleteAccount(STRING_NAME_TWO);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_AddAccount_0300
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccount_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccount_0300");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME_THREE, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->DeleteAccount(STRING_NAME_THREE);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_AddAccount_0400
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with invalid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccount_0400, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccount_0400");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ADD_EXISTING_ACCOUNT);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_AddAccount_0500
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with invalid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccount_0500, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccount_0500");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result;
    std::string name;
    for (int index = 0; index < ACCOUNT_MAX_SIZE; index++) {
        name = STRING_NAME + std::to_string(index);
        ACCOUNT_LOGI("index = %{public}d, name = %{public}s", index, name.c_str());
        result = servicePtr->AddAccount(name, STRING_EXTRA_INFO);
        EXPECT_EQ(result, ERR_OK);
    }

    result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_MAX_SIZE);

    for (int index = 0; index < ACCOUNT_MAX_SIZE; index++) {
        name = STRING_NAME + std::to_string(index);
        ACCOUNT_LOGI("index = %{public}d, name = %{public}s", index, name.c_str());
        result = servicePtr->DeleteAccount(name);
        EXPECT_EQ(result, ERR_OK);
    }
}

/**
 * @tc.number: AppAccountManagerService_DeleteAccount_0100
 * @tc.name: DeleteAccount
 * @tc.desc: Delete an app account with invalid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAccount_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAccount_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->DeleteAccount(STRING_NAME_NOT_EXISTED);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.number: AppAccountManagerService_GetAccountExtraInfo_0100
 * @tc.name: GetAccountExtraInfo
 * @tc.desc: Get extra info of an app account with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountExtraInfo_0100,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountExtraInfo_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::string extraInfo;
    result = servicePtr->GetAccountExtraInfo(STRING_NAME, extraInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(extraInfo, STRING_EXTRA_INFO);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_GetAccountExtraInfo_0200
 * @tc.name: GetAccountExtraInfo
 * @tc.desc: Get extra info of an app account with invalid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountExtraInfo_0200,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountExtraInfo_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    std::string extraInfo;
    ErrCode result = servicePtr->GetAccountExtraInfo(STRING_NAME, extraInfo);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
    EXPECT_EQ(extraInfo, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManagerService_SetAccountExtraInfo_0100
 * @tc.name: SetAccountExtraInfo
 * @tc.desc: Set extra info of an app account with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountExtraInfo_0100,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountExtraInfo_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::string extraInfo;
    result = servicePtr->GetAccountExtraInfo(STRING_NAME, extraInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(extraInfo, STRING_EXTRA_INFO);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_SetAccountExtraInfo_0200
 * @tc.name: SetAccountExtraInfo
 * @tc.desc: Set extra info of an app account with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountExtraInfo_0200,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountExtraInfo_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAccountExtraInfo(STRING_NAME, STRING_EMPTY);
    EXPECT_EQ(result, ERR_OK);

    std::string extraInfo;
    result = servicePtr->GetAccountExtraInfo(STRING_NAME, extraInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(extraInfo, STRING_EMPTY);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_SetAccountExtraInfo_0300
 * @tc.name: SetAccountExtraInfo
 * @tc.desc: Set extra info of an app account with invalid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountExtraInfo_0300,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountExtraInfo_0300");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.number: seAppAccountManagerService_EnableAppAccess_0100
 * @tc.name: EnableAppAccess
 * @tc.desc: Enable app access with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, seAppAccountManagerService_EnableAppAccess_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_EnableAppAccess_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->DisableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: seAppAccountManagerService_EnableAppAccess_0200
 * @tc.name: EnableAppAccess
 * @tc.desc: Enable app access with invalid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, seAppAccountManagerService_EnableAppAccess_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_EnableAppAccess_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->EnableAppAccess(STRING_NAME, STRING_OWNER);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_BUNDLE_NAME_IS_THE_SAME);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: seAppAccountManagerService_EnableAppAccess_0300
 * @tc.name: EnableAppAccess
 * @tc.desc: Enable app access with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, seAppAccountManagerService_EnableAppAccess_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_EnableAppAccess_0300");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ENABLE_APP_ACCESS_ALREADY_EXISTS);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: seAppAccountManagerService_EnableAppAccess_0400
 * @tc.name: EnableAppAccess
 * @tc.desc: Enable app access with invalid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, seAppAccountManagerService_EnableAppAccess_0400, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_EnableAppAccess_0400");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.number: seAppAccountManagerService_DisableAppAccess_0100
 * @tc.name: DisableAppAccess
 * @tc.desc: Disable app access with invalid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_DisableAppAccess_0100,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_DisableAppAccess_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->DisableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_DISABLE_APP_ACCESS_NOT_EXISTED);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: seAppAccountManagerService_DisableAppAccess_0200
 * @tc.name: DisableAppAccess
 * @tc.desc: Disable app access with invalid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_DisableAppAccess_0200,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_DisableAppAccess_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->DisableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.number: seAppAccountManagerService_CheckAppAccountSyncEnable_0100
 * @tc.name: CheckAppAccountSyncEnable
 * @tc.desc: Check account sync enable with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_CheckAppAccountSyncEnable_0100,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_CheckAppAccountSyncEnable_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    bool syncEnable = SYNC_ENABLE_FALSE;
    result = servicePtr->CheckAppAccountSyncEnable(STRING_NAME, syncEnable);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_FALSE);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: seAppAccountManagerService_CheckAppAccountSyncEnable_0200
 * @tc.name: CheckAppAccountSyncEnable
 * @tc.desc: Check account sync enable with invalid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_CheckAppAccountSyncEnable_0200,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_CheckAppAccountSyncEnable_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    bool syncEnable = SYNC_ENABLE_FALSE;
    ErrCode result = servicePtr->CheckAppAccountSyncEnable(STRING_NAME, syncEnable);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_FALSE);
}

/**
 * @tc.number: seAppAccountManagerService_SetAppAccountSyncEnable_0100
 * @tc.name: SetAppAccountSyncEnable
 * @tc.desc: Set account sync enable with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_SetAppAccountSyncEnable_0100,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_SetAppAccountSyncEnable_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE);
    EXPECT_EQ(result, ERR_OK);

    bool syncEnable = false;
    result = servicePtr->CheckAppAccountSyncEnable(STRING_NAME, syncEnable);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_TRUE);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: seAppAccountManagerService_SetAppAccountSyncEnable_0200
 * @tc.name: SetAppAccountSyncEnable
 * @tc.desc: Set account sync enable with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_SetAppAccountSyncEnable_0200,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_SetAppAccountSyncEnable_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_FALSE);
    EXPECT_EQ(result, ERR_OK);

    bool syncEnable = false;
    result = servicePtr->CheckAppAccountSyncEnable(STRING_NAME, syncEnable);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_FALSE);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: seAppAccountManagerService_SetAppAccountSyncEnable_0300
 * @tc.name: SetAppAccountSyncEnable
 * @tc.desc: Set account sync enable with invalid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_SetAppAccountSyncEnable_0300,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_SetAppAccountSyncEnable_0300");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.number: AppAccountManagerService_GetAssociatedData_0100
 * @tc.name: GetAssociatedData
 * @tc.desc: Get associated data with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAssociatedData_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAssociatedData_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_OK);

    std::string value;
    result = servicePtr->GetAssociatedData(STRING_NAME, STRING_KEY, value);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_GetAssociatedData_0200
 * @tc.name: GetAssociatedData
 * @tc.desc: Get associated data with invalid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAssociatedData_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAssociatedData_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::string value;
    result = servicePtr->GetAssociatedData(STRING_NAME, STRING_KEY, value);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ASSOCIATED_DATA);
    EXPECT_EQ(value, STRING_EMPTY);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_GetAssociatedData_0300
 * @tc.name: GetAssociatedData
 * @tc.desc: Get associated data with invalid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAssociatedData_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAssociatedData_0300");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    std::string value;
    ErrCode result = servicePtr->GetAssociatedData(STRING_NAME, STRING_KEY, value);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
    EXPECT_EQ(value, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManagerService_GetAssociatedData_0400
 * @tc.name: GetAssociatedData
 * @tc.desc: Get associated data with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAssociatedData_0400, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAssociatedData_0400");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAssociatedData(STRING_NAME, STRING_KEY_TWO, STRING_VALUE_TWO);
    EXPECT_EQ(result, ERR_OK);

    std::string value;
    result = servicePtr->GetAssociatedData(STRING_NAME, STRING_KEY, value);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE);

    result = servicePtr->GetAssociatedData(STRING_NAME, STRING_KEY_TWO, value);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE_TWO);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_SetAssociatedData_0100
 * @tc.name: SetAssociatedData
 * @tc.desc: Set associated data with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAssociatedData_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAssociatedData_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_SetAssociatedData_0200
 * @tc.name: SetAssociatedData
 * @tc.desc: Set associated data with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAssociatedData_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAssociatedData_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE_TWO);
    EXPECT_EQ(result, ERR_OK);

    std::string value;
    result = servicePtr->GetAssociatedData(STRING_NAME, STRING_KEY, value);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE_TWO);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_SetAssociatedData_0300
 * @tc.name: SetAssociatedData
 * @tc.desc: Set associated data with invalid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAssociatedData_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAssociatedData_0300");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.number: AppAccountManagerService_GetAccountCredential_0100
 * @tc.name: GetAccountCredential
 * @tc.desc: Get account credential with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountCredential_0100,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountCredential_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_OK);

    std::string credential;
    result = servicePtr->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(credential, STRING_CREDENTIAL);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_GetAccountCredential_0200
 * @tc.name: GetAccountCredential
 * @tc.desc: Get account credential with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountCredential_0200,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountCredential_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::string credential;
    result = servicePtr->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_CREDENTIAL);
    EXPECT_EQ(credential, STRING_EMPTY);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_GetAccountCredential_0300
 * @tc.name: GetAccountCredential
 * @tc.desc: Get account credential with invalid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountCredential_0300,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountCredential_0300");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    std::string credential;
    ErrCode result = servicePtr->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
    EXPECT_EQ(credential, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManagerService_GetAccountCredential_0400
 * @tc.name: GetAccountCredential
 * @tc.desc: Get account credential with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountCredential_0400,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountCredential_0400");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE_TWO, STRING_CREDENTIAL_TWO);
    EXPECT_EQ(result, ERR_OK);

    std::string credential;
    result = servicePtr->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(credential, STRING_CREDENTIAL);

    result = servicePtr->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE_TWO, credential);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(credential, STRING_CREDENTIAL_TWO);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_SetAccountCredential_0100
 * @tc.name: SetAccountCredential
 * @tc.desc: Set account credential with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountCredential_0100,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountCredential_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_SetAccountCredential_0200
 * @tc.name: SetAccountCredential
 * @tc.desc: Set account credential with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountCredential_0200,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountCredential_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL_TWO);
    EXPECT_EQ(result, ERR_OK);

    std::string credential;
    result = servicePtr->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(credential, STRING_CREDENTIAL_TWO);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_SetAccountCredential_0300
 * @tc.name: SetAccountCredential
 * @tc.desc: Set account credential with invalid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountCredential_0300,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountCredential_0300");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.number: AppAccountManagerService_GetOAuthToken_0100
 * @tc.name: GetOAuthToken
 * @tc.desc: Get oauth token with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_GetOAuthToken_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetOAuthToken_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::string token;
    result = servicePtr->GetOAuthToken(STRING_NAME, token);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(token, STRING_EMPTY);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_GetOAuthToken_0200
 * @tc.name: GetOAuthToken
 * @tc.desc: Get oauth token with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_GetOAuthToken_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetOAuthToken_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetOAuthToken(STRING_NAME, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    std::string token;
    result = servicePtr->GetOAuthToken(STRING_NAME, token);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(token, STRING_TOKEN);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_GetOAuthToken_0300
 * @tc.name: GetOAuthToken
 * @tc.desc: Get oauth token with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_GetOAuthToken_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetOAuthToken_0300");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    std::string token;
    ErrCode result = servicePtr->GetOAuthToken(STRING_NAME, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
    EXPECT_EQ(token, STRING_EMPTY);
}

/**
 * @tc.number: AppAccountManagerService_SetOAuthToken_0100
 * @tc.name: SetOAuthToken
 * @tc.desc: Set oauth token with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_SetOAuthToken_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetOAuthToken_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetOAuthToken(STRING_NAME, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_SetOAuthToken_0200
 * @tc.name: SetOAuthToken
 * @tc.desc: Set oauth token with invalid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_SetOAuthToken_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetOAuthToken_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->SetOAuthToken(STRING_NAME, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.number: AppAccountManagerService_ClearOAuthToken_0100
 * @tc.name: ClearOAuthToken
 * @tc.desc: Clear oauth token with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_ClearOAuthToken_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_ClearOAuthToken_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->SetOAuthToken(STRING_NAME, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->ClearOAuthToken(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);

    std::string token;
    result = servicePtr->GetOAuthToken(STRING_NAME, token);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(token, STRING_EMPTY);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_ClearOAuthToken_0200
 * @tc.name: ClearOAuthToken
 * @tc.desc: Clear oauth token with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_ClearOAuthToken_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_ClearOAuthToken_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->ClearOAuthToken(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);

    std::string token;
    result = servicePtr->GetOAuthToken(STRING_NAME, token);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(token, STRING_EMPTY);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_ClearOAuthToken_0300
 * @tc.name: ClearOAuthToken
 * @tc.desc: Clear oauth token with invalid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_ClearOAuthToken_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_ClearOAuthToken_0300");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->ClearOAuthToken(STRING_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.number: AppAccountManagerService_GetAllAccounts_0100
 * @tc.name: GetAllAccounts
 * @tc.desc: Get all accounts with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = servicePtr->GetAllAccounts(STRING_OWNER, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.number: AppAccountManagerService_GetAllAccounts_0200
 * @tc.name: GetAllAccounts
 * @tc.desc: Get all accounts with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0200, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->AddAccount(STRING_NAME_TWO, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = servicePtr->GetAllAccounts(STRING_OWNER, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_TWO);

    std::string name;
    result = appAccounts.begin()->GetName(name);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(name, STRING_NAME);

    result = (appAccounts.begin() + SIZE_ONE)->GetName(name);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(name, STRING_NAME_TWO);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);

    result = servicePtr->DeleteAccount(STRING_NAME_TWO);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_GetAllAccounts_0300
 * @tc.name: GetAllAccounts
 * @tc.desc: Get all accounts with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0300, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0300");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = servicePtr->GetAllAccounts(STRING_BUNDLE_NAME, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.number: AppAccountManagerService_GetAllAccounts_0400
 * @tc.name: GetAllAccounts
 * @tc.desc: Get all accounts with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0400, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0400");

    controlManagerPtr_ = AppAccountControlManager::GetInstance();
    ASSERT_NE(controlManagerPtr_, nullptr);

    AppAccountInfo appAccountInfo(STRING_NAME, STRING_BUNDLE_NAME);
    ErrCode result = controlManagerPtr_->AddAccount(STRING_NAME, STRING_EMPTY, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    result = controlManagerPtr_->EnableAppAccess(STRING_NAME, STRING_OWNER, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    std::vector<AppAccountInfo> appAccounts;
    result = servicePtr->GetAllAccounts(STRING_BUNDLE_NAME, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    std::string owner;
    result = appAccounts.begin()->GetOwner(owner);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(owner, STRING_BUNDLE_NAME);

    result = controlManagerPtr_->DeleteAccount(STRING_NAME, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_GetAllAccessibleAccounts_0100
 * @tc.name: GetAllAccessibleAccounts
 * @tc.desc: Get all accessiable accounts with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccessibleAccounts_0100,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccessibleAccounts_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = servicePtr->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.number: AppAccountManagerService_GetAllAccessibleAccounts_0200
 * @tc.name: GetAllAccessibleAccounts
 * @tc.desc: Get all accessiable accounts with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccessibleAccounts_0200,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccessibleAccounts_0200");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = servicePtr->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    std::string name;
    result = appAccounts.begin()->GetName(name);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(name, STRING_NAME);

    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_GetAllAccessibleAccounts_0300
 * @tc.name: GetAllAccessibleAccounts
 * @tc.desc: Get all accessiable accounts with valid data.
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccessibleAccounts_0300,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccessibleAccounts_0300");

    controlManagerPtr_ = AppAccountControlManager::GetInstance();
    ASSERT_NE(controlManagerPtr_, nullptr);

    AppAccountInfo appAccountInfo(STRING_NAME, STRING_BUNDLE_NAME);
    ErrCode result = controlManagerPtr_->AddAccount(STRING_NAME, STRING_EMPTY, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    result = controlManagerPtr_->EnableAppAccess(STRING_NAME, STRING_OWNER, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    std::vector<AppAccountInfo> appAccounts;
    result = servicePtr->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    std::string owner;
    result = appAccounts.begin()->GetOwner(owner);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(owner, STRING_BUNDLE_NAME);

    result = controlManagerPtr_->DeleteAccount(STRING_NAME, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_OnPackageRemoved_0100
 * @tc.name: OnPackageRemoved
 * @tc.desc: On package removed with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, AppAccountManagerService_OnPackageRemoved_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_OnPackageRemoved_0100");

    auto dataStoragePtr = controlManagerPtr_->GetDataStorage(false, UID);
    ASSERT_NE(dataStoragePtr, nullptr);

    AppAccountInfo appAccountInfo(STRING_NAME, STRING_BUNDLE_NAME);
    ErrCode result = dataStoragePtr->AddAccountInfoIntoDataStorage(appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    accounts.clear();
    EXPECT_EQ(accounts.size(), SIZE_ZERO);

    result = dataStoragePtr->LoadAllData(accounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accounts.size(), SIZE_ONE);

    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);

    ElementName element;
    element.SetBundleName(STRING_BUNDLE_NAME);

    want.SetElement(element);
    want.SetParam(AppExecFwk::Constants::UID, UID);

    CommonEventData commonEventData;
    commonEventData.SetWant(want);

    CommonEventManager::PublishCommonEvent(commonEventData);

    std::this_thread::sleep_for(std::chrono::seconds(DELAY_FOR_PACKAGE_REMOVED));

    accounts.clear();
    EXPECT_EQ(accounts.size(), SIZE_ZERO);

    result = dataStoragePtr->LoadAllData(accounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accounts.size(), SIZE_ZERO);
}

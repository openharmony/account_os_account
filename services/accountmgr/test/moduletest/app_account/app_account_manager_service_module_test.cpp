/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "app_account_authenticator_callback_stub.h"
#include "app_account_common.h"
#include "app_account_constants.h"
#include "app_account_control_manager.h"
#include "app_account_manager_service.h"
#undef private
#include "bundle_constants.h"
#ifdef HAS_CES_PART
#include "common_event_manager.h"
#include "common_event_support.h"
#endif // HAS_CES_PART
#include "iremote_object.h"
#include "app_account_manager_service.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AppExecFwk;
#ifdef HAS_CES_PART
using namespace OHOS::EventFwk;
#endif // HAS_CES_PART
namespace {
const std::string STRING_NAME = "name";
const std::string STRING_NAME_TWO = "name_two";
const std::string STRING_NAME_THREE = "name_three";
const std::string STRING_NAME_MAX_SIZE =
    "name_1234567"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_NAME_NOT_EXISTED = "name_not_existed";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_BUNDLE_NAME = "com.example.third_party";
const std::string STRING_BUNDLE_NAME_NOT_INSTALLED = "com.example.not_installed";
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
const std::string STRING_TOKEN_TWO = "2048";
const std::string STRING_OWNER = "com.example.owner";
const std::string INVALID_STRING_OWNER = "owner_not_exist";
const std::string STRING_AUTH_TYPE = "read";
const std::string STRING_AUTH_TYPE_TWO = "write";
const std::string STRING_SESSION_ID = "100";
const std::string STRING_ABILITY_NAME = "com.example.owner.MainAbility";
const std::vector<std::string> TEST_LABELS = {
    "test_label1",
    "test_label2",
};

const bool SYNC_ENABLE_TRUE = true;
const bool SYNC_ENABLE_FALSE = false;

constexpr std::int32_t UID = 10000;
constexpr std::int32_t TEST_USER_ID = 101;
constexpr std::size_t SIZE_ZERO = 0;
constexpr std::size_t SIZE_ONE = 1;
constexpr std::size_t SIZE_TWO = 2;
constexpr std::int32_t DELAY_FOR_PACKAGE_REMOVED = 3;
constexpr std::int32_t DELAY_FOR_MESSAGE = 1000;
constexpr std::int32_t WAIT_FOR_ONE_CASE = 1000;
std::shared_ptr<AppAccountManagerService> g_accountManagerService =
    std::make_shared<AppAccountManagerService>();
std::shared_ptr<AppAccountControlManager> g_controlManagerPtr = AppAccountControlManager::GetInstance();
}  // namespace

class MockAuthenticatorCallback final : public AppAccountAuthenticatorCallbackStub {
public:
    MOCK_METHOD2(OnResult, void(int32_t resultCode, const AAFwk::Want &result));
    MOCK_METHOD1(OnRequestRedirected, void(AAFwk::Want &request));
    MOCK_METHOD0(OnRequestContinued, void());
};

class AppAccountManagerServiceModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    void ClearDataStorage();
};

void AppAccountManagerServiceModuleTest::ClearDataStorage()
{
    auto dataStoragePtr = g_controlManagerPtr->GetDataStorage(UID);
    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    dataStoragePtr->LoadAllData(accounts);
    if (!accounts.empty()) {
        for (auto accountPtr : accounts) {
            dataStoragePtr->RemoveValueFromKvStore(accountPtr.first);
        }
    }
    dataStoragePtr->LoadAllData(accounts);
    GTEST_LOG_(INFO) << "AppAccountManagerServiceModuleTest ClearDataStorage end, accounts.size =" << accounts.size();
}

void AppAccountManagerServiceModuleTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "SetUpTestCase";
}

void AppAccountManagerServiceModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase enter";
    auto dataStoragePtr = g_controlManagerPtr->GetDataStorage(UID);
    ASSERT_NE(dataStoragePtr, nullptr);

    ErrCode result = dataStoragePtr->DeleteKvStore();
    ASSERT_EQ(result, ERR_OK);

#ifdef DISTRIBUTED_FEATURE_ENABLED
    dataStoragePtr = g_controlManagerPtr->GetDataStorage(UID, true);
    ASSERT_NE(dataStoragePtr, nullptr);

    result = dataStoragePtr->DeleteKvStore();
    ASSERT_EQ(result, ERR_OK);
    DelayedSingleton<AppAccountControlManager>::DestroyInstance();
#endif // DISTRIBUTED_FEATURE_ENABLED
    GTEST_LOG_(INFO) << "TearDownTestCase exit";
}

void AppAccountManagerServiceModuleTest::SetUp(void)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_ONE_CASE));
    ClearDataStorage();
}

void AppAccountManagerServiceModuleTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountManagerService_AddAccount_0100
 * @tc.desc: Add an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccount_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccount_0100");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_MESSAGE));
}

/**
 * @tc.name: AppAccountManagerService_AddAccount_0200
 * @tc.desc: Add an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccount_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccount_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EMPTY);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_AddAccount_0300
 * @tc.desc: Add an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccount_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccount_0300");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_AddAccount_0400
 * @tc.desc: Add an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccount_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccount_0400");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME_MAX_SIZE, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteAccount(STRING_NAME_MAX_SIZE);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_AddAccount_0500
 * @tc.desc: Add an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccount_0500, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccount_0500");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ADD_EXISTING_ACCOUNT);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CreateAccount_0100
 * @tc.desc: test create app account exception case.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CreateAccount_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_CreateAccount_0100");

    CreateAccountOptions option;
    ErrCode result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_OK);
    result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ADD_EXISTING_ACCOUNT);
    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAccount_0100
 * @tc.desc: Delete an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAccount_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAccount_0100");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);

    auto dataStoragePtr = g_controlManagerPtr->GetDataStorage(UID);
    ASSERT_NE(dataStoragePtr, nullptr);

    std::vector<std::string> accessibleAccounts;
    result = dataStoragePtr->GetAccessibleAccountsFromDataStorage(STRING_BUNDLE_NAME, accessibleAccounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accessibleAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAccount_0200
 * @tc.desc: Delete an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAccount_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAccount_0200");

    ErrCode result = g_accountManagerService->DeleteAccount(STRING_NAME_NOT_EXISTED);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: AppAccountManagerService_GetAccountExtraInfo_0100
 * @tc.desc: Get extra info of an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountExtraInfo_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountExtraInfo_0100");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::string extraInfo;
    result = g_accountManagerService->GetAccountExtraInfo(STRING_NAME, extraInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(extraInfo, STRING_EXTRA_INFO);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAccountExtraInfo_0200
 * @tc.desc: Get extra info of an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountExtraInfo_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountExtraInfo_0200");

    std::string extraInfo;
    ErrCode result = g_accountManagerService->GetAccountExtraInfo(STRING_NAME, extraInfo);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
    EXPECT_EQ(extraInfo, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManagerService_SetAccountExtraInfo_0100
 * @tc.desc: Set extra info of an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountExtraInfo_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountExtraInfo_0100");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::string extraInfo;
    result = g_accountManagerService->GetAccountExtraInfo(STRING_NAME, extraInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(extraInfo, STRING_EXTRA_INFO);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAccountExtraInfo_0200
 * @tc.desc: Set extra info of an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountExtraInfo_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountExtraInfo_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAccountExtraInfo(STRING_NAME, STRING_EMPTY);
    EXPECT_EQ(result, ERR_OK);

    std::string extraInfo;
    result = g_accountManagerService->GetAccountExtraInfo(STRING_NAME, extraInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(extraInfo, STRING_EMPTY);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAccountExtraInfo_0300
 * @tc.desc: Set extra info of an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountExtraInfo_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountExtraInfo_0300");

    ErrCode result = g_accountManagerService->SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: seAppAccountManagerService_EnableAppAccess_0100
 * @tc.desc: Enable app access with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_EnableAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_EnableAppAccess_0100");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DisableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAppAccess_0100
 * @tc.desc: Enable app access with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAppAccess_0100");

    CreateAccountOptions option;
    ErrCode result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, false);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_EnableAppAccess_0200
 * @tc.desc: Enable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_EnableAppAccess_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_EnableAppAccess_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_OWNER);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_BUNDLE_NAME_IS_THE_SAME);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_SetAppAccess_0200
 * @tc.desc: Enable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_SetAppAccess_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_SetAppAccess_0200");

    CreateAccountOptions option;
    ErrCode result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAppAccess(STRING_NAME, STRING_OWNER, true);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_EnableAppAccess_0300
 * @tc.desc: Enable app access with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_EnableAppAccess_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_EnableAppAccess_0300");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ENABLE_APP_ACCESS_ALREADY_EXISTS);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAppAccess_0300
 * @tc.desc: Enable app access with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAppAccess_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAppAccess_0300");

    CreateAccountOptions option;
    ErrCode result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_EnableAppAccess_0400
 * @tc.desc: Enable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_EnableAppAccess_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_EnableAppAccess_0400");

    ErrCode result = g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: AppAccountManagerService_SetAppAccess_0400
 * @tc.desc: Enable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAppAccess_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAppAccess_0400");

    ErrCode result = g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: seAppAccountManagerService_DisableAppAccess_0100
 * @tc.desc: Disable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_DisableAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_DisableAppAccess_0100");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DisableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_DISABLE_APP_ACCESS_NOT_EXISTED);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAppAccess_0500
 * @tc.desc: Disable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAppAccess_0500, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAppAccess_0500");

    CreateAccountOptions option;
    ErrCode result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, false);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_DisableAppAccess_0200
 * @tc.desc: Disable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_DisableAppAccess_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_DisableAppAccess_0200");

    ErrCode result = g_accountManagerService->DisableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: AppAccountManagerService_SetAppAccess_0600
 * @tc.desc: Disable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAppAccess_0600, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAppAccess_0600");

    ErrCode result = g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, false);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: seAppAccountManagerService_CheckAppAccountSyncEnable_0100
 * @tc.desc: Check account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, seAppAccountManagerService_CheckAppAccountSyncEnable_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_CheckAppAccountSyncEnable_0100");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    bool syncEnable = SYNC_ENABLE_FALSE;
    result = g_accountManagerService->CheckAppAccountSyncEnable(STRING_NAME, syncEnable);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_FALSE);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_CheckAppAccountSyncEnable_0200
 * @tc.desc: Check account sync enable with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, seAppAccountManagerService_CheckAppAccountSyncEnable_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_CheckAppAccountSyncEnable_0200");

    bool syncEnable = SYNC_ENABLE_FALSE;
    ErrCode result = g_accountManagerService->CheckAppAccountSyncEnable(STRING_NAME, syncEnable);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_FALSE);
}

/**
 * @tc.name: seAppAccountManagerService_SetAppAccountSyncEnable_0100
 * @tc.desc: Set account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_SetAppAccountSyncEnable_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_SetAppAccountSyncEnable_0100");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE);
    EXPECT_EQ(result, ERR_OK);

    bool syncEnable = SYNC_ENABLE_FALSE;
    result = g_accountManagerService->CheckAppAccountSyncEnable(STRING_NAME, syncEnable);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_TRUE);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_SetAppAccountSyncEnable_0200
 * @tc.desc: Set account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_SetAppAccountSyncEnable_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_SetAppAccountSyncEnable_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_FALSE);
    EXPECT_EQ(result, ERR_OK);

    bool syncEnable = SYNC_ENABLE_FALSE;
    result = g_accountManagerService->CheckAppAccountSyncEnable(STRING_NAME, syncEnable);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_FALSE);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_SetAppAccountSyncEnable_0300
 * @tc.desc: Set account sync enable with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_SetAppAccountSyncEnable_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("seAppAccountManagerService_SetAppAccountSyncEnable_0300");

    ErrCode result = g_accountManagerService->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: AppAccountManagerService_GetAssociatedData_0100
 * @tc.desc: Get associated data with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAssociatedData_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAssociatedData_0100");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_OK);

    std::string value;
    result = g_accountManagerService->GetAssociatedData(STRING_NAME, STRING_KEY, value);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAssociatedData_0200
 * @tc.desc: Get associated data with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAssociatedData_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAssociatedData_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::string value;
    result = g_accountManagerService->GetAssociatedData(STRING_NAME, STRING_KEY, value);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ASSOCIATED_DATA_KEY_NOT_EXIST);
    EXPECT_EQ(value, STRING_EMPTY);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAssociatedData_0300
 * @tc.desc: Get associated data with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAssociatedData_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAssociatedData_0300");

    std::string value;
    ErrCode result = g_accountManagerService->GetAssociatedData(STRING_NAME, STRING_KEY, value);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
    EXPECT_EQ(value, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManagerService_GetAssociatedData_0400
 * @tc.desc: Get associated data with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAssociatedData_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAssociatedData_0400");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY_TWO, STRING_VALUE_TWO);
    EXPECT_EQ(result, ERR_OK);

    std::string value;
    result = g_accountManagerService->GetAssociatedData(STRING_NAME, STRING_KEY, value);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE);

    result = g_accountManagerService->GetAssociatedData(STRING_NAME, STRING_KEY_TWO, value);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE_TWO);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAssociatedData_0100
 * @tc.desc: Set associated data with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAssociatedData_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAssociatedData_0100");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAssociatedData_0200
 * @tc.desc: Set associated data with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAssociatedData_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAssociatedData_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE_TWO);
    EXPECT_EQ(result, ERR_OK);

    std::string value;
    result = g_accountManagerService->GetAssociatedData(STRING_NAME, STRING_KEY, value);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE_TWO);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAssociatedData_0300
 * @tc.desc: Set associated data with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAssociatedData_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAssociatedData_0300");

    ErrCode result = g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: AppAccountManagerService_GetAccountCredential_0100
 * @tc.desc: Get account credential with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountCredential_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountCredential_0100");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_OK);

    std::string credential;
    result = g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(credential, STRING_CREDENTIAL);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAccountCredential_0200
 * @tc.desc: Get account credential with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountCredential_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountCredential_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::string credential;
    result = g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_CREDENTIAL_NOT_EXIST);
    EXPECT_EQ(credential, STRING_EMPTY);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAccountCredential_0300
 * @tc.desc: Get account credential with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountCredential_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountCredential_0300");

    std::string credential;
    ErrCode result = g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
    EXPECT_EQ(credential, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManagerService_GetAccountCredential_0400
 * @tc.desc: Get account credential with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountCredential_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountCredential_0400");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAccountCredential(STRING_NAME,
        STRING_CREDENTIAL_TYPE_TWO, STRING_CREDENTIAL_TWO);
    EXPECT_EQ(result, ERR_OK);

    std::string credential;
    result = g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(credential, STRING_CREDENTIAL);

    result = g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE_TWO, credential);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(credential, STRING_CREDENTIAL_TWO);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAccountCredential_0100
 * @tc.desc: Set account credential with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountCredential_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountCredential_0100");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAccountCredential_0200
 * @tc.desc: Set account credential with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountCredential_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountCredential_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAccountCredential(STRING_NAME,
        STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL_TWO);
    EXPECT_EQ(result, ERR_OK);

    std::string credential;
    result = g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(credential, STRING_CREDENTIAL_TWO);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAccountCredential_0300
 * @tc.desc: Set account credential with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountCredential_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountCredential_0300");

    ErrCode result = g_accountManagerService->SetAccountCredential(STRING_NAME,
        STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_GetOAuthToken_0100
 * @tc.desc: Get oauth token failed with non-existent account.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetOAuthToken_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetOAuthToken_0100");

    std::string token;
    ErrCode result = g_accountManagerService->GetOAuthToken(STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
    EXPECT_EQ(token, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManagerService_GetAuthToken_0100
 * @tc.desc: Get oauth token failed with non-existent account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAuthToken_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAuthToken_0100");

    std::string token;
    ErrCode result = g_accountManagerService->GetAuthToken(STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
    EXPECT_EQ(token, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManagerService_GetOAuthToken_0200
 * @tc.desc: Get oauth token failed for non-existent oauth token.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetOAuthToken_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetOAuthToken_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    std::string token;
    result = g_accountManagerService->GetOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    EXPECT_EQ(token, STRING_EMPTY);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAuthToken_0200
 * @tc.desc: Get oauth token failed for non-existent oauth token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAuthToken_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAuthToken_0200");

    CreateAccountOptions option;
    ErrCode result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    std::string token;
    result = g_accountManagerService->GetAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    EXPECT_EQ(token, STRING_EMPTY);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetOAuthToken_0300
 * @tc.desc: Get oauth token successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetOAuthToken_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetOAuthToken_0300");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    result = g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    std::string token;
    result = g_accountManagerService->GetOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(token, STRING_TOKEN);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAuthToken_0300
 * @tc.desc: Get oauth token successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAuthToken_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAuthToken_0300");

    CreateAccountOptions option;
    ErrCode result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    result = g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    std::string token;
    result = g_accountManagerService->GetAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(token, STRING_TOKEN);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetOAuthToken_0100
 * @tc.desc: Set oauth token failed with non-exist account.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetOAuthToken_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetOAuthToken_0100");

    ErrCode result = g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_SetOAuthToken_0200
 * @tc.desc: Set oauth token successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetOAuthToken_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetOAuthToken_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE_TWO, STRING_TOKEN_TWO);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    std::string token;
    result = g_accountManagerService->GetOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE_TWO, token);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(token, STRING_TOKEN_TWO);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteOAuthToken_0100
 * @tc.desc: Delete oauth token failed with non-exist account.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteOAuthToken_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteOAuthToken_0100");

    ErrCode result = g_accountManagerService->DeleteOAuthToken(STRING_NAME,
        STRING_OWNER, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAuthToken_0100
 * @tc.desc: Delete oauth token failed with non-exist account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAuthToken_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAuthToken_0100");

    ErrCode result = g_accountManagerService->DeleteAuthToken(STRING_NAME,
        STRING_OWNER, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_DeleteOAuthToken_0200
 * @tc.desc: Delete oauth token successfully with non-existent token.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteOAuthToken_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteOAuthToken_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    result = g_accountManagerService->DeleteOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    std::string token;
    result = g_accountManagerService->GetOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    EXPECT_EQ(token, STRING_EMPTY);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAuthToken_0200
 * @tc.desc: Delete oauth token successfully with non-existent token.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAuthToken_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAuthToken_0200");

    CreateAccountOptions option;
    ErrCode result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    result = g_accountManagerService->DeleteAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);

    std::string token;
    result = g_accountManagerService->GetAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    EXPECT_EQ(token, STRING_EMPTY);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteOAuthToken_0300
 * @tc.desc: Delete oauth token successfully with existent token.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteOAuthToken_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteOAuthToken_0300");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    result = g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    std::string token;
    result = g_accountManagerService->GetOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    EXPECT_EQ(token, STRING_EMPTY);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAuthToken_0300
 * @tc.desc: Delete oauth token successfully with non-existent token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAuthToken_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAuthToken_0300");

    CreateAccountOptions option;
    ErrCode result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    result = g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    std::string token;
    result = g_accountManagerService->GetAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(token, STRING_TOKEN);

    result = g_accountManagerService->DeleteAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    token = "";
    result = g_accountManagerService->GetAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    EXPECT_EQ(token, STRING_EMPTY);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAllOAuthTokens_0100
 * @tc.desc: Get all oauth token failed for non-existent account.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllOAuthTokens_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllOAuthTokens_0100");

    std::vector<OAuthTokenInfo> tokenInfos;
    ErrCode result = g_accountManagerService->GetAllOAuthTokens(STRING_NAME, STRING_OWNER, tokenInfos);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_GetAllOAuthTokens_0200
 * @tc.desc: Get all oauth token successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllOAuthTokens_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllOAuthTokens_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    std::vector<OAuthTokenInfo> tokenInfos;
    result = g_accountManagerService->GetAllOAuthTokens(STRING_NAME, owner, tokenInfos);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(tokenInfos.size(), 0);

    result = g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE_TWO, STRING_TOKEN_TWO);
    EXPECT_EQ(result, ERR_OK);

    tokenInfos.clear();
    result = g_accountManagerService->GetAllOAuthTokens(STRING_NAME, owner, tokenInfos);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(tokenInfos.size(), SIZE_TWO);
    EXPECT_EQ(tokenInfos[0].token, STRING_TOKEN);
    EXPECT_EQ(tokenInfos[1].token, STRING_TOKEN_TWO);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetOAuthTokenVisibility_0100
 * @tc.desc: Set oauth token failed with non-existent account.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetOAuthTokenVisibility_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetOAuthTokenVisibility_0100");

    ErrCode result = g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_SetAuthTokenVisibility_0100
 * @tc.desc: Set oauth token failed with non-existent account.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAuthTokenVisibility_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAuthTokenVisibility_0100");

    ErrCode result = g_accountManagerService->SetAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_SetAuthTokenVisibility_0100
 * @tc.desc: Set oauth token failed with non-existent owner.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAuthTokenVisibility_01001, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAuthTokenVisibility_01001");

    CreateAccountOptions option;
    ErrCode result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME_NOT_INSTALLED, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetOAuthTokenVisibility_0200
 * @tc.desc: Set oauth token visibility with non-existent authType successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetOAuthTokenVisibility_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetOAuthTokenVisibility_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    bool isVisible = true;
    result = g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isVisible, false);

    result = g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_OK);

    isVisible = false;
    result = g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isVisible, true);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAuthTokenVisibility_0200
 * @tc.desc: Set oauth token visibility with non-existent authType.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
// STRING_OWNER valid owner
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAuthTokenVisibility_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAuthTokenVisibility_0200");

    CreateAccountOptions option;
    ErrCode result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_OK);

    bool isVisible = false;
    result = g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TYPE_NOT_EXIST);

    result = g_accountManagerService->SetAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TYPE_NOT_EXIST);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetOAuthTokenVisibility_0300
 * @tc.desc: Set oauth token visibility with existent authType successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetOAuthTokenVisibility_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetOAuthTokenVisibility_0300");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    result = g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_OK);

    bool isVisible = false;
    result = g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isVisible, true);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAuthTokenVisibility_0300
 * @tc.desc: Set oauth token visibility with existent authType successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAuthTokenVisibility_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAuthTokenVisibility_0300");

    CreateAccountOptions option;
    ErrCode result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_OK);

    // check self
    bool isVisible = false;
    result = g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_OWNER, isVisible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isVisible, true);

    result = g_accountManagerService->SetAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_OWNER, false);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_BUNDLE_NAME_IS_THE_SAME);

    result = g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_OWNER, isVisible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isVisible, true);

    // check other owners
    result = g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_OK);

    std::set<std::string> authList;
    result = g_accountManagerService->GetOAuthList(STRING_NAME, STRING_AUTH_TYPE, authList);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(authList.size(), SIZE_ONE);

    result = g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, INVALID_STRING_OWNER, isVisible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isVisible, false);

    result = g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isVisible, true);

    result = g_accountManagerService->SetAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, false);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isVisible, false);

    authList.clear();
    result = g_accountManagerService->GetOAuthList(STRING_NAME, STRING_AUTH_TYPE, authList);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(authList.size(), 0);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CheckOAuthTokenVisibility_0100
 * @tc.desc: Check oauth token visibility successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckOAuthTokenVisibility_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckOAuthTokenVisibility_0100");

    bool isVisible = true;
    ErrCode result = g_accountManagerService->CheckOAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
    EXPECT_EQ(isVisible, false);

    result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);
    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    isVisible = true;
    result = g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isVisible, false);

    result = g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_OK);

    isVisible = false;
    result = g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isVisible, true);

    result = g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, false);
    EXPECT_EQ(result, ERR_OK);

    isVisible = true;
    result = g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isVisible, false);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CheckAuthTokenVisibility_0100
 * @tc.desc: Check oauth token visibility with non_exist account.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAuthTokenVisibility_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAuthTokenVisibility_0100");

    bool isVisible = true;
    ErrCode result = g_accountManagerService->CheckAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
    EXPECT_EQ(isVisible, false);
}

/**
 * @tc.name: AppAccountManagerService_GetOAuthList_0100
 * @tc.desc: Get oauth list failed with non-existent account.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetOAuthList_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetOAuthList_0100");

    std::set<std::string> authList;
    ErrCode result = g_accountManagerService->GetOAuthList(STRING_NAME, STRING_AUTH_TYPE, authList);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_GetAuthList_0100
 * @tc.desc: Get oauth list failed with non-existent account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAuthList_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAuthList_0100");

    std::set<std::string> authList;
    ErrCode result = g_accountManagerService->GetAuthList(STRING_NAME, STRING_AUTH_TYPE, authList);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_GetOAuthList_0200
 * @tc.desc: Get oauth list with non-existent authType successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetOAuthList_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetOAuthList_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::set<std::string> authList;
    result = g_accountManagerService->GetOAuthList(STRING_NAME, STRING_AUTH_TYPE, authList);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(authList.size(), SIZE_ZERO);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAuthList_0200
 * @tc.desc: Get oauth list with non-existent authType successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAuthList_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAuthList_0200");

    CreateAccountOptions option;
    ErrCode result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_OK);

    std::set<std::string> authList;
    result = g_accountManagerService->GetAuthList(STRING_NAME, STRING_AUTH_TYPE, authList);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TYPE_NOT_EXIST);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetOAuthList_0300
 * @tc.desc: Get oauth list with existent authType successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetOAuthList_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetOAuthList_0300");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetOAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_BUNDLE_NAME_NOT_INSTALLED, true);
    EXPECT_EQ(result, ERR_OK);

    std::set<std::string> authList;
    result = g_accountManagerService->GetOAuthList(STRING_NAME, STRING_AUTH_TYPE, authList);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(authList.size(), SIZE_TWO);

    auto it = authList.find(STRING_BUNDLE_NAME);
    EXPECT_NE(it, authList.end());
    it = authList.find(STRING_BUNDLE_NAME_NOT_INSTALLED);
    EXPECT_NE(it, authList.end());

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAuthList_0400
 * @tc.desc: Get oauth list with existent authType successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAuthList_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAuthList_0400");

    CreateAccountOptions option;
    ErrCode result = g_accountManagerService->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_OK);

    std::set<std::string> authList;
    result = g_accountManagerService->GetAuthList(STRING_NAME, STRING_AUTH_TYPE, authList);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(authList.size(), SIZE_ONE);

    auto it = authList.find(STRING_BUNDLE_NAME);
    EXPECT_NE(it, authList.end());
    it = authList.find(STRING_BUNDLE_NAME_NOT_INSTALLED);
    EXPECT_EQ(it, authList.end());

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAuthenticatorInfo_0100
 * @tc.desc: Get authenticator info failed for non-existent oauth service.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAuthenticatorInfo_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAuthenticatorInfo_0100");

    AuthenticatorInfo info;
    ErrCode result = g_accountManagerService->GetAuthenticatorInfo(STRING_OWNER, info);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_GetAuthenticatorCallback_0100
 * @tc.desc: Get authenticator callback failed with non-existent sessionId.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAuthenticatorCallback_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAuthenticatorCallback_0100");

    sptr<IRemoteObject> callback;
    ErrCode result = g_accountManagerService->GetAuthenticatorCallback(STRING_SESSION_ID, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_SESSION_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_AddAccountImplicitly_0100
 * @tc.desc: Add account implicitly failed for non-existent oauth service.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccountImplicitly_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccountImplicitly_0100");

    AAFwk::Want options;
    options.SetParam(AccountSA::Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    sptr<IRemoteObject> callback = nullptr;
    ErrCode result = g_accountManagerService->AddAccountImplicitly(
        STRING_OWNER, STRING_AUTH_TYPE, options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_CreateAccountImplicitly_0100
 * @tc.desc: Add account implicitly failed for non-existent oauth service.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CreateAccountImplicitly_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_CreateAccountImplicitly_0100");

    CreateAccountImplicitlyOptions options;
    options.parameters.SetParam(AccountSA::Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    sptr<IRemoteObject> callback = nullptr;
    ErrCode result = g_accountManagerService->CreateAccountImplicitly(
        STRING_OWNER, options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_Authenticate_0100
 * @tc.desc: authenticate failed for non-existent oauth service.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_Authenticate_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_Authenticate_0100");

    AAFwk::Want options;
    options.SetParam(AccountSA::Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    sptr<IRemoteObject> callback = nullptr;
    ErrCode result = g_accountManagerService->Authenticate(STRING_NAME,
        STRING_OWNER, STRING_AUTH_TYPE, options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_Authenticate_v9_0100
 * @tc.desc: test version9 authenticate failed for non-existent oauth service.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_Authenticate_v9_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_Authenticate_0100");

    AAFwk::Want options;
    options.SetParam(AccountSA::Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    options.SetParam(AccountSA::Constants::API_V9, true);
    sptr<IRemoteObject> callback = nullptr;
    ErrCode result = g_accountManagerService->Authenticate(STRING_NAME,
        STRING_OWNER, STRING_AUTH_TYPE, options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccounts_0100
 * @tc.desc: Get all accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0100");

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = g_accountManagerService->GetAllAccounts(STRING_OWNER, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccounts_0200
 * @tc.desc: Get all accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->AddAccount(STRING_NAME_TWO, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccounts(STRING_OWNER, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_TWO);

    std::string name;
    appAccounts.begin()->GetName(name);
    EXPECT_EQ(name, STRING_NAME);

    (appAccounts.begin() + SIZE_ONE)->GetName(name);
    EXPECT_EQ(name, STRING_NAME_TWO);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteAccount(STRING_NAME_TWO);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccounts_0300
 * @tc.desc: Get all accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0300");

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = g_accountManagerService->GetAllAccounts(STRING_BUNDLE_NAME, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccounts_0400
 * @tc.desc: Get all accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0400");

    AppAccountInfo appAccountInfo(STRING_NAME, STRING_BUNDLE_NAME);
    ErrCode result =
        g_controlManagerPtr->AddAccount(STRING_NAME, STRING_EMPTY, UID, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_BUNDLE_NAME;
    result = g_controlManagerPtr->EnableAppAccess(STRING_NAME, STRING_OWNER, appAccountCallingInfo, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccounts(STRING_BUNDLE_NAME, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    std::string owner;
    appAccounts.begin()->GetOwner(owner);
    EXPECT_EQ(owner, STRING_BUNDLE_NAME);

    result = g_controlManagerPtr->DeleteAccount(STRING_NAME, UID, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccounts_0500
 * @tc.desc: Get all accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0500, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0500");

    AppAccountInfo appAccountInfo(STRING_NAME, STRING_BUNDLE_NAME);
    ErrCode result =
        g_controlManagerPtr->AddAccount(STRING_NAME, STRING_EMPTY, UID, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    AppAccountInfo appAccountInfoTwo(STRING_NAME_TWO, STRING_OWNER);
    result = g_controlManagerPtr->AddAccount(STRING_NAME_TWO, STRING_EMPTY, UID, STRING_OWNER, appAccountInfoTwo);
    EXPECT_EQ(result, ERR_OK);

    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_BUNDLE_NAME;
    result =
        g_controlManagerPtr->EnableAppAccess(STRING_NAME, STRING_OWNER, appAccountCallingInfo, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccounts(STRING_BUNDLE_NAME, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    std::string owner;
    appAccounts.begin()->GetOwner(owner);
    EXPECT_EQ(owner, STRING_BUNDLE_NAME);

    std::string name;
    appAccounts.begin()->GetName(name);
    EXPECT_EQ(name, STRING_NAME);

    result = g_controlManagerPtr->DeleteAccount(STRING_NAME, UID, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    result = g_controlManagerPtr->DeleteAccount(STRING_NAME_TWO, UID, STRING_OWNER, appAccountInfoTwo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccounts_0600
 * @tc.desc: Get all accounts with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0600, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0600");

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = g_accountManagerService->GetAllAccounts(STRING_BUNDLE_NAME_NOT_INSTALLED, appAccounts);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccessibleAccounts_0100
 * @tc.desc: Get all accessible accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccessibleAccounts_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccessibleAccounts_0100");

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.name: AppAccountManagerService_QueryAllAccessibleAccounts_0100
 * @tc.desc: Get all accessible accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_QueryAllAccessibleAccounts_0100, TestSize.Level0)
{
    std::vector<AppAccountInfo> appAccounts;
    std::string owner = "";
    ErrCode result = g_accountManagerService->QueryAllAccessibleAccounts(owner, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccessibleAccounts_0200
 * @tc.desc: Get all accessible accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccessibleAccounts_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccessibleAccounts_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    std::string name;
    appAccounts.begin()->GetName(name);
    EXPECT_EQ(name, STRING_NAME);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_QueryAllAccessibleAccounts_0200
 * @tc.desc: Get all accessible accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_QueryAllAccessibleAccounts_0200, TestSize.Level1)
{
    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    std::string owner = "";
    result = g_accountManagerService->QueryAllAccessibleAccounts(owner, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    std::string name;
    appAccounts.begin()->GetName(name);
    EXPECT_EQ(name, STRING_NAME);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccessibleAccounts_0300
 * @tc.desc: Get all accessible accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccessibleAccounts_0300, TestSize.Level1)
{
    AppAccountInfo appAccountInfo(STRING_NAME, STRING_BUNDLE_NAME);
    ErrCode result =
        g_controlManagerPtr->AddAccount(STRING_NAME, STRING_EMPTY, UID, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_BUNDLE_NAME;
    result = g_controlManagerPtr->EnableAppAccess(STRING_NAME, STRING_OWNER, appAccountCallingInfo, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    result = g_accountManagerService->GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    std::string owner;
    appAccounts.begin()->GetOwner(owner);
    EXPECT_EQ(owner, STRING_BUNDLE_NAME);

    // test api9 func
    appAccounts.clear();
    std::string queryOwner = "";
    result = g_accountManagerService->QueryAllAccessibleAccounts(queryOwner, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    owner = "";
    appAccounts.begin()->GetOwner(owner);
    EXPECT_EQ(owner, STRING_BUNDLE_NAME);

    result = g_controlManagerPtr->DeleteAccount(STRING_NAME, UID, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_OnPackageRemoved_0100
 * @tc.desc: On package removed with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_OnPackageRemoved_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_OnPackageRemoved_0100");
    auto dataStoragePtr = g_controlManagerPtr->GetDataStorage(UID);
    ASSERT_NE(dataStoragePtr, nullptr);

    AppAccountInfo appAccountInfo(STRING_NAME, STRING_BUNDLE_NAME);
    ErrCode result = dataStoragePtr->AddAccountInfoIntoDataStorage(appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    result = dataStoragePtr->LoadAllData(accounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accounts.size(), SIZE_ONE);

#ifdef HAS_CES_PART
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);

    ElementName element;
    element.SetBundleName(STRING_BUNDLE_NAME);

    want.SetElement(element);
    want.SetParam(AppExecFwk::Constants::UID, UID);

    CommonEventData commonEventData;
    commonEventData.SetWant(want);

    CommonEventManager::PublishCommonEvent(commonEventData);
#endif // HAS_CES_PART

    std::this_thread::sleep_for(std::chrono::seconds(DELAY_FOR_PACKAGE_REMOVED));

    accounts.clear();
    result = dataStoragePtr->LoadAllData(accounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accounts.size(), SIZE_ZERO);
}

/**
 * @tc.name: AppAccountManagerService_CheckAppAccess_0100
 * @tc.desc: test CheckAppAccess
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAppAccess_0100");
    bool isAccessible = false;
    ErrCode result = g_accountManagerService->CheckAppAccess(
        STRING_NAME, STRING_BUNDLE_NAME_NOT_INSTALLED, isAccessible);
    EXPECT_NE(result, ERR_OK);
    EXPECT_EQ(isAccessible, false);
}

/**
 * @tc.name: AppAccountManagerService_CheckAppAccess_0200
 * @tc.desc: test CheckAppAccess
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAppAccess_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAppAccess_0200");
    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    bool isAccessible = false;
    result = g_accountManagerService->CheckAppAccess(STRING_NAME, STRING_BUNDLE_NAME, isAccessible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isAccessible, false);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CheckAppAccess_0300
 * @tc.desc: test CheckAppAccess
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAppAccess_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAppAccess_0300");
    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);
    bool isAccessible = false;
    result = g_accountManagerService->CheckAppAccess(STRING_NAME, STRING_BUNDLE_NAME, isAccessible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isAccessible, true);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CheckAppAccess_0400
 * @tc.desc: test CheckAppAccess
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAppAccess_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAppAccess_0400");
    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);

    bool isAccessible = false;
    AppAccountCallingInfo appAccountCallingInfo;
    result = g_accountManagerService->GetCallingInfo(
        appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName, appAccountCallingInfo.appIndex);
    EXPECT_EQ(result, ERR_OK);
    result = g_accountManagerService->CheckAppAccess(STRING_NAME, appAccountCallingInfo.bundleName, isAccessible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isAccessible, true);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAccountCredential_0100
 * @tc.desc: test DeleteAccountCredential
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAccountCredential_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAccountCredential_0100");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_OK);

    std::string credential;
    result = g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(credential, STRING_CREDENTIAL);

    result = g_accountManagerService->DeleteAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE);
    EXPECT_EQ(result, ERR_OK);

    credential = "";
    result = g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_NE(result, ERR_OK);
    EXPECT_EQ(credential, "");

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAccountCredential_0200
 * @tc.desc: test DeleteAccountCredential
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAccountCredential_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAccountCredential_0200");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_CREDENTIAL_NOT_EXIST);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAccountCredential_0300
 * @tc.desc: test DeleteAccountCredential
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAccountCredential_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAccountCredential_0300");

    ErrCode result = g_accountManagerService->DeleteAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE);
    EXPECT_NE(result, ERR_OK);
}

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAccountCredential_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAccountCredential_0400");

    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_OK);

    result = g_accountManagerService->DeleteAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE_TWO);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_CREDENTIAL_NOT_EXIST);

    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SelectAccountsByOptions_0100
 * @tc.desc: test SelectAccountsByOptions
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SelectAccountsByOptions_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SelectAccountsByOptions_0100");

    SelectAccountsOptions options;
    options.hasAccounts = false;
    options.hasOwners = false;
    options.hasLabels = false;
    options.allowedAccounts.emplace_back("test_key", "value");
    options.allowedOwners = TEST_LABELS;
    options.requiredLabels = TEST_LABELS;
    sptr<IRemoteObject> callback = new (std::nothrow)MockAuthenticatorCallback();
    ASSERT_NE(callback, nullptr);
    ErrCode result = g_accountManagerService->SelectAccountsByOptions(options, callback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_VerifyCredential_0100
 * @tc.desc: test VerifyCredential
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_VerifyCredential_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_VerifyCredential_0100");
    VerifyCredentialOptions options;
    options.credentialType = STRING_CREDENTIAL_TYPE;
    options.credential = STRING_CREDENTIAL;
    AAFwk::WantParams want;
    options.parameters = want;
    sptr<IRemoteObject> callback = new (std::nothrow)MockAuthenticatorCallback();
    ASSERT_NE(callback, nullptr);
    ErrCode result = g_accountManagerService->VerifyCredential(STRING_NAME, STRING_OWNER, options, callback);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_VerifyCredential_0200
 * @tc.desc: test VerifyCredential
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_VerifyCredential_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_VerifyCredential_0200");
    VerifyCredentialOptions options;
    options.credentialType = STRING_CREDENTIAL_TYPE;
    options.credential = STRING_CREDENTIAL;
    AAFwk::WantParams want;
    options.parameters = want;
    sptr<IRemoteObject> callback = new (std::nothrow)MockAuthenticatorCallback();
    ASSERT_NE(callback, nullptr);
    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);
    result = g_accountManagerService->VerifyCredential(STRING_NAME, STRING_OWNER, options, callback);
    EXPECT_NE(result, ERR_OK);
    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CheckAccountLabels_0100
 * @tc.desc: test CheckAccountLabels
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAccountLabels_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAccountLabels_0100");
    sptr<IRemoteObject> callback = new (std::nothrow)MockAuthenticatorCallback();
    ASSERT_NE(callback, nullptr);
    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);
    result = g_accountManagerService->CheckAccountLabels(STRING_NAME, STRING_OWNER, TEST_LABELS, callback);
    EXPECT_NE(result, ERR_OK);
    result = g_accountManagerService->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CheckAccountLabels_0200
 * @tc.desc: test CheckAccountLabels
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAccountLabels_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAccountLabels_0200");
    sptr<IRemoteObject> callback = new (std::nothrow)MockAuthenticatorCallback();
    ASSERT_NE(callback, nullptr);
    ErrCode result = g_accountManagerService->CheckAccountLabels(STRING_NAME, STRING_OWNER, TEST_LABELS, callback);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAuthenticatorProperties_0100
 * @tc.desc: test SetAuthenticatorProperties
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAuthenticatorProperties_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAuthenticatorProperties_0100");
    SetPropertiesOptions options;
    sptr<IRemoteObject> callback = new (std::nothrow)MockAuthenticatorCallback();
    ASSERT_NE(callback, nullptr);
    ErrCode result = g_accountManagerService->SetAuthenticatorProperties(STRING_OWNER, options, callback);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAuthenticatorProperties_0200
 * @tc.desc: test SetAuthenticatorProperties
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAuthenticatorProperties_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAuthenticatorProperties_0200");
    SetPropertiesOptions options;
    AAFwk::WantParams want;
    options.properties = want;
    sptr<IRemoteObject> callback = new (std::nothrow)MockAuthenticatorCallback();
    ASSERT_NE(callback, nullptr);
    ErrCode result = g_accountManagerService->SetAuthenticatorProperties(STRING_OWNER, options, callback);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_OnPackageRemoved_0200
 * @tc.desc: test OnPackageRemoved
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_OnPackageRemoved_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_OnPackageRemoved_0200");
    ErrCode result = g_accountManagerService->OnPackageRemoved(UID, STRING_OWNER, 0);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_OnUserRemoved_0100
 * @tc.desc: test OnUserRemoved
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_OnUserRemoved_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_OnUserRemoved_0100");
    ErrCode result = g_accountManagerService->OnUserRemoved(TEST_USER_ID);
    EXPECT_EQ(result, ERR_OK);
}


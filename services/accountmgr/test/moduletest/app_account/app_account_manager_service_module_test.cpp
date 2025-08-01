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

#include <thread>
#include <gmock/gmock.h>
#include "account_log_wrapper.h"
#include "datetime_ex.h"
#define private public
#include "app_account_authenticator_callback_stub.h"
#include "app_account_common.h"
#include "app_account_common_event_observer.h"
#include "app_account_constants.h"
#include "app_account_control_manager.h"
#include "app_account_manager_service.h"
#include "os_account_state_subscriber.h"
#undef private
#include "bundle_constants.h"
#ifdef HAS_CES_PART
#include "common_event_manager.h"
#include "common_event_support.h"
#endif // HAS_CES_PART
#include "ipc_skeleton.h"
#include "iremote_object.h"
#include "token_setproc.h"

using namespace testing;
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
const std::string STRING_NAME_MAX_SIZE(512, '1');  // length 512
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
constexpr uint32_t TEST_CODE = 1;
constexpr std::int32_t TEST_ID = 1;
const uid_t ACCOUNT_UID = 3058;
std::shared_ptr<AppAccountManagerService> g_accountManagerService =
    std::make_shared<AppAccountManagerService>();
}  // namespace

class MockAuthenticatorCallback final : public AppAccountAuthenticatorCallbackStub {
public:
    MOCK_METHOD2(OnResult, ErrCode(int32_t resultCode, const AAFwk::Want &result));
    MOCK_METHOD1(OnRequestRedirected, ErrCode(const AAFwk::Want &request));
    MOCK_METHOD0(OnRequestContinued, ErrCode());
    MOCK_METHOD1(CallbackEnter, ErrCode(uint32_t code));
    MOCK_METHOD2(CallbackExit, ErrCode(uint32_t code, int32_t result));
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
    auto dataStoragePtr = AppAccountControlManager::GetInstance().GetDataStorage(UID);
    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    dataStoragePtr->LoadAllData(accounts);
    if (!accounts.empty()) {
        for (auto accountPtr : accounts) {
            dataStoragePtr->RemoveValueFromKvStore(accountPtr.first);
        }
    }
    dataStoragePtr->LoadAllData(accounts);
    ASSERT_EQ(accounts.size(), 0);
}

void AppAccountManagerServiceModuleTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "SetUpTestCase";
}

void AppAccountManagerServiceModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase enter";
    auto dataStoragePtr = AppAccountControlManager::GetInstance().GetDataStorage(UID);
    ASSERT_NE(dataStoragePtr, nullptr);

    ErrCode result = dataStoragePtr->DeleteKvStore();
    ASSERT_EQ(result, ERR_OK);

#ifdef DISTRIBUTED_FEATURE_ENABLED
    dataStoragePtr = AppAccountControlManager::GetInstance().GetDataStorage(UID, true);
    ASSERT_NE(dataStoragePtr, nullptr);

    result = dataStoragePtr->DeleteKvStore();
    ASSERT_EQ(result, ERR_OK);
#endif // DISTRIBUTED_FEATURE_ENABLED
    GTEST_LOG_(INFO) << "TearDownTestCase exit";
}

void AppAccountManagerServiceModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

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
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_AddAccount_0200
 * @tc.desc: Add an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccount_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccount_0200");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EMPTY, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_AddAccount_0300
 * @tc.desc: Add an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccount_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccount_0300");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_AddAccount_0400
 * @tc.desc: Add an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccount_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccount_0400");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME_MAX_SIZE, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->DeleteAccount(STRING_NAME_MAX_SIZE, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_AddAccount_0500
 * @tc.desc: Add an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccount_0500, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccount_0500");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ADD_EXISTING_ACCOUNT);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CreateAccount_0100
 * @tc.desc: test create app account exception case.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CreateAccount_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_CreateAccount_0100");

    CreateAccountOptions option;
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ADD_EXISTING_ACCOUNT);
    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
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

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    auto dataStoragePtr = AppAccountControlManager::GetInstance().GetDataStorage(UID);
    ASSERT_NE(dataStoragePtr, nullptr);

    std::vector<std::string> accessibleAccounts;
    ErrCode result = dataStoragePtr->GetAccessibleAccountsFromDataStorage(STRING_BUNDLE_NAME, accessibleAccounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accessibleAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAccount_0200
 * @tc.desc: Delete an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAccount_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAccount_0200");

    int32_t funcResult = -1;
    g_accountManagerService->DeleteAccount(STRING_NAME_NOT_EXISTED, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: AppAccountManagerService_GetAccountExtraInfo_0100
 * @tc.desc: Get extra info of an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountExtraInfo_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountExtraInfo_0100");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::string extraInfo;
    g_accountManagerService->GetAccountExtraInfo(STRING_NAME, extraInfo, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(extraInfo, STRING_EXTRA_INFO);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAccountExtraInfo_0200
 * @tc.desc: Get extra info of an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountExtraInfo_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountExtraInfo_0200");

    std::string extraInfo;
    int32_t funcResult = -1;
    g_accountManagerService->GetAccountExtraInfo(STRING_NAME, extraInfo, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
    EXPECT_EQ(extraInfo, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManagerService_SetAccountExtraInfo_0100
 * @tc.desc: Set extra info of an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountExtraInfo_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountExtraInfo_0100");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::string extraInfo;
    g_accountManagerService->GetAccountExtraInfo(STRING_NAME, extraInfo, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(extraInfo, STRING_EXTRA_INFO);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAccountExtraInfo_0200
 * @tc.desc: Set extra info of an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountExtraInfo_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountExtraInfo_0200");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetAccountExtraInfo(STRING_NAME, STRING_EMPTY, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::string extraInfo;
    g_accountManagerService->GetAccountExtraInfo(STRING_NAME, extraInfo, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(extraInfo, STRING_EMPTY);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAccountExtraInfo_0300
 * @tc.desc: Set extra info of an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountExtraInfo_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountExtraInfo_0300");

    int32_t funcResult = -1;
    g_accountManagerService->SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: seAppAccountManagerService_EnableAppAccess_0100
 * @tc.desc: Enable app access with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_EnableAppAccess_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("seAppAccountManagerService_EnableAppAccess_0100");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->DisableAppAccess(STRING_NAME, STRING_BUNDLE_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAppAccess_0100
 * @tc.desc: Enable app access with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAppAccess_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAppAccess_0100");

    CreateAccountOptions option;
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, true, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, false, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_EnableAppAccess_0200
 * @tc.desc: Enable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_EnableAppAccess_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("seAppAccountManagerService_EnableAppAccess_0200");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_OWNER, funcResult);
    EXPECT_EQ(funcResult, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_SetAppAccess_0200
 * @tc.desc: Enable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_SetAppAccess_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("seAppAccountManagerService_SetAppAccess_0200");

    CreateAccountOptions option;
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetAppAccess(STRING_NAME, STRING_OWNER, true, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_EnableAppAccess_0300
 * @tc.desc: Enable app access with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_EnableAppAccess_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("seAppAccountManagerService_EnableAppAccess_0300");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ENABLE_APP_ACCESS_ALREADY_EXISTS);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAppAccess_0300
 * @tc.desc: Enable app access with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAppAccess_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAppAccess_0300");

    CreateAccountOptions option;
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, true, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, true, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_EnableAppAccess_0400
 * @tc.desc: Enable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_EnableAppAccess_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("seAppAccountManagerService_EnableAppAccess_0400");

    int32_t funcResult = -1;
    g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: AppAccountManagerService_SetAppAccess_0400
 * @tc.desc: Enable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAppAccess_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAppAccess_0400");

    int32_t funcResult = -1;
    g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, true, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: seAppAccountManagerService_DisableAppAccess_0100
 * @tc.desc: Disable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_DisableAppAccess_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("seAppAccountManagerService_DisableAppAccess_0100");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->DisableAppAccess(STRING_NAME, STRING_BUNDLE_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_DISABLE_APP_ACCESS_NOT_EXISTED);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAppAccess_0500
 * @tc.desc: Disable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAppAccess_0500, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAppAccess_0500");

    CreateAccountOptions option;
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, false, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_DisableAppAccess_0200
 * @tc.desc: Disable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_DisableAppAccess_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("seAppAccountManagerService_DisableAppAccess_0200");

    int32_t funcResult = -1;
    g_accountManagerService->DisableAppAccess(STRING_NAME, STRING_BUNDLE_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: AppAccountManagerService_SetAppAccess_0600
 * @tc.desc: Disable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAppAccess_0600, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAppAccess_0600");

    int32_t funcResult = -1;
    g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, false, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: seAppAccountManagerService_CheckAppAccountSyncEnable_0100
 * @tc.desc: Check account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(
    AppAccountManagerServiceModuleTest, seAppAccountManagerService_CheckAppAccountSyncEnable_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("seAppAccountManagerService_CheckAppAccountSyncEnable_0100");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    bool syncEnable = SYNC_ENABLE_FALSE;
    g_accountManagerService->CheckAppAccountSyncEnable(STRING_NAME, syncEnable, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_FALSE);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_SetAppAccountSyncEnable_0100
 * @tc.desc: Set account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_SetAppAccountSyncEnable_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("seAppAccountManagerService_SetAppAccountSyncEnable_0100");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    bool syncEnable = SYNC_ENABLE_FALSE;
    g_accountManagerService->CheckAppAccountSyncEnable(STRING_NAME, syncEnable, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_TRUE);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_SetAppAccountSyncEnable_0200
 * @tc.desc: Set account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_SetAppAccountSyncEnable_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("seAppAccountManagerService_SetAppAccountSyncEnable_0200");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    funcResult = -1;
    g_accountManagerService->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_FALSE, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    funcResult = -1;
    bool syncEnable = SYNC_ENABLE_TRUE;
    g_accountManagerService->CheckAppAccountSyncEnable(STRING_NAME, syncEnable, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_FALSE);

    funcResult = -1;
    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: seAppAccountManagerService_SetAppAccountSyncEnable_0300
 * @tc.desc: Set account sync enable with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, seAppAccountManagerService_SetAppAccountSyncEnable_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("seAppAccountManagerService_SetAppAccountSyncEnable_0300");

    int32_t funcResult = -1;
    g_accountManagerService->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: AppAccountManagerService_GetAccountCredential_0100
 * @tc.desc: Get account credential with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountCredential_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountCredential_0100");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    funcResult = -1;
    g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::string credential;
    funcResult = -1;
    g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(credential, STRING_CREDENTIAL);

    funcResult = -1;
    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAccountCredential_0200
 * @tc.desc: Get account credential with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountCredential_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountCredential_0200");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::string credential;
    g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_CREDENTIAL_NOT_EXIST);
    EXPECT_EQ(credential, STRING_EMPTY);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAccountCredential_0300
 * @tc.desc: Get account credential with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountCredential_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountCredential_0300");

    std::string credential;
    int32_t funcResult = -1;
    g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
    EXPECT_EQ(credential, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManagerService_GetAccountCredential_0400
 * @tc.desc: Get account credential with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAccountCredential_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAccountCredential_0400");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    funcResult = -1;
    g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    funcResult = -1;
    g_accountManagerService->SetAccountCredential(STRING_NAME,
        STRING_CREDENTIAL_TYPE_TWO, STRING_CREDENTIAL_TWO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    funcResult = -1;
    std::string credential;
    g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(credential, STRING_CREDENTIAL);

    funcResult = -1;
    g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE_TWO, credential, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(credential, STRING_CREDENTIAL_TWO);

    funcResult = -1;
    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAccountCredential_0100
 * @tc.desc: Set account credential with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountCredential_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountCredential_0100");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    funcResult = -1;
    g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    funcResult = -1;
    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAccountCredential_0200
 * @tc.desc: Set account credential with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountCredential_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountCredential_0200");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    funcResult = -1;
    g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    funcResult = -1;
    g_accountManagerService->SetAccountCredential(STRING_NAME,
        STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL_TWO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    funcResult = -1;
    std::string credential;
    g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(credential, STRING_CREDENTIAL_TWO);

    funcResult = -1;
    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAccountCredential_0300
 * @tc.desc: Set account credential with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAccountCredential_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAccountCredential_0300");

    int32_t funcResult = -1;
    g_accountManagerService->SetAccountCredential(STRING_NAME,
        STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
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
    int32_t funcResult = -1;
    g_accountManagerService->GetOAuthToken(STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, token, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
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
    int32_t funcResult = -1;
    g_accountManagerService->GetAuthToken(STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, token, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
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

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    std::string token;
    g_accountManagerService->GetOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    EXPECT_EQ(token, STRING_EMPTY);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
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
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    std::string token;
    g_accountManagerService->GetAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    EXPECT_EQ(token, STRING_EMPTY);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetOAuthToken_0300
 * @tc.desc: Get oauth token successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetOAuthToken_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetOAuthToken_0300");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::string token;
    g_accountManagerService->GetOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(token, STRING_TOKEN);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAuthToken_0300
 * @tc.desc: Get oauth token successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAuthToken_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAuthToken_0300");

    CreateAccountOptions option;
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::string token;
    g_accountManagerService->GetAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(token, STRING_TOKEN);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetOAuthToken_0100
 * @tc.desc: Set oauth token failed with non-exist account.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetOAuthToken_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetOAuthToken_0100");

    int32_t funcResult = -1;
    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_SetOAuthToken_0200
 * @tc.desc: Set oauth token successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetOAuthToken_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetOAuthToken_0200");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE_TWO, STRING_TOKEN_TWO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    std::string token;
    g_accountManagerService->GetOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE_TWO, token, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(token, STRING_TOKEN_TWO);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteOAuthToken_0100
 * @tc.desc: Delete oauth token failed with non-exist account.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteOAuthToken_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteOAuthToken_0100");

    int32_t funcResult = -1;
    g_accountManagerService->DeleteOAuthToken(STRING_NAME,
        STRING_OWNER, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAuthToken_0100
 * @tc.desc: Delete oauth token failed with non-exist account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAuthToken_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAuthToken_0100");

    int32_t funcResult = -1;
    g_accountManagerService->DeleteAuthToken(STRING_NAME,
        STRING_OWNER, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_DeleteOAuthToken_0200
 * @tc.desc: Delete oauth token successfully with non-existent token.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteOAuthToken_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteOAuthToken_0200");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    g_accountManagerService->DeleteOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::string token;
    g_accountManagerService->GetOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    EXPECT_EQ(token, STRING_EMPTY);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAuthToken_0200
 * @tc.desc: Delete oauth token successfully with non-existent token.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAuthToken_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAuthToken_0200");

    CreateAccountOptions option;
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    g_accountManagerService->DeleteAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);

    std::string token;
    g_accountManagerService->GetAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    EXPECT_EQ(token, STRING_EMPTY);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteOAuthToken_0300
 * @tc.desc: Delete oauth token successfully with existent token.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteOAuthToken_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteOAuthToken_0300");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->DeleteOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::string token;
    g_accountManagerService->GetOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    EXPECT_EQ(token, STRING_EMPTY);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAuthToken_0300
 * @tc.desc: Delete oauth token successfully with non-existent token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAuthToken_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAuthToken_0300");

    CreateAccountOptions option;
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::string token;
    g_accountManagerService->GetAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(token, STRING_TOKEN);

    g_accountManagerService->DeleteAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    token = "";
    g_accountManagerService->GetAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    EXPECT_EQ(token, STRING_EMPTY);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAllOAuthTokens_0100
 * @tc.desc: Get all oauth token failed for non-existent account.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllOAuthTokens_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllOAuthTokens_0100");

    std::vector<OAuthTokenInfo> tokenInfos;
    int32_t funcResult = -1;
    g_accountManagerService->GetAllOAuthTokens(STRING_NAME, STRING_OWNER, tokenInfos, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_GetAllOAuthTokens_0200
 * @tc.desc: Get all oauth token successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllOAuthTokens_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllOAuthTokens_0200");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    std::vector<OAuthTokenInfo> tokenInfos;
    g_accountManagerService->GetAllOAuthTokens(STRING_NAME, owner, tokenInfos, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(tokenInfos.size(), static_cast<size_t>(0));

    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE_TWO, STRING_TOKEN_TWO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    tokenInfos.clear();
    g_accountManagerService->GetAllOAuthTokens(STRING_NAME, owner, tokenInfos, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(tokenInfos.size(), SIZE_TWO);
    EXPECT_EQ(tokenInfos[0].token, STRING_TOKEN);
    EXPECT_EQ(tokenInfos[1].token, STRING_TOKEN_TWO);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetOAuthTokenVisibility_0100
 * @tc.desc: Set oauth token failed with non-existent account.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetOAuthTokenVisibility_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetOAuthTokenVisibility_0100");

    int32_t funcResult = -1;
    g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_SetAuthTokenVisibility_0100
 * @tc.desc: Set oauth token failed with non-existent account.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAuthTokenVisibility_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAuthTokenVisibility_0100");

    int32_t funcResult = -1;
    g_accountManagerService->SetAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_SetAuthTokenVisibility_0100
 * @tc.desc: Set oauth token failed with non-existent owner.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAuthTokenVisibility_01001, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAuthTokenVisibility_01001");

    CreateAccountOptions option;
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME_NOT_INSTALLED, true, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_TYPE_NOT_EXIST);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetOAuthTokenVisibility_0200
 * @tc.desc: Set oauth token visibility with non-existent authType successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetOAuthTokenVisibility_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetOAuthTokenVisibility_0200");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    bool isVisible = true;
    g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isVisible, false);

    g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    isVisible = false;
    g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isVisible, true);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAuthTokenVisibility_0200
 * @tc.desc: Set oauth token visibility with non-existent authType.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
// STRING_OWNER valid owner
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAuthTokenVisibility_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAuthTokenVisibility_0200");

    CreateAccountOptions option;
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    bool isVisible = false;
    g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_TYPE_NOT_EXIST);

    g_accountManagerService->SetAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_TYPE_NOT_EXIST);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetOAuthTokenVisibility_0300
 * @tc.desc: Set oauth token visibility with existent authType successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetOAuthTokenVisibility_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetOAuthTokenVisibility_0300");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    bool isVisible = false;
    g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isVisible, true);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAuthTokenVisibility_0300
 * @tc.desc: Set oauth token visibility with existent authType successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAuthTokenVisibility_0300, TestSize.Level0)
{
    CreateAccountOptions option;
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    // check self
    bool isVisible = false;
    g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_OWNER, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isVisible, true);

    g_accountManagerService->SetAuthTokenVisibility(STRING_NAME, STRING_AUTH_TYPE, STRING_OWNER, false, funcResult);
    EXPECT_EQ(funcResult, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_OWNER, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isVisible, true);

    // check other owners
    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::set<std::string> authList;
    g_accountManagerService->GetOAuthList(STRING_NAME, STRING_AUTH_TYPE, authList, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(authList.size(), SIZE_ONE);

    isVisible = true;
    g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, INVALID_STRING_OWNER, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isVisible, false);

    isVisible = false;
    g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isVisible, true);

    g_accountManagerService->SetAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, false, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    isVisible = true;
    g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isVisible, false);

    authList.clear();
    g_accountManagerService->GetOAuthList(STRING_NAME, STRING_AUTH_TYPE, authList, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(authList.size(), 0);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CheckOAuthTokenVisibility_0100
 * @tc.desc: Check oauth token visibility successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckOAuthTokenVisibility_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckOAuthTokenVisibility_0100");

    bool isVisible = true;
    int32_t funcResult = -1;
    g_accountManagerService->CheckOAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
    EXPECT_EQ(isVisible, false);

    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    std::vector<AppAccountInfo> appAccounts;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    isVisible = true;
    g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isVisible, false);

    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    isVisible = false;
    g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isVisible, true);

    g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, false, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    isVisible = true;
    g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isVisible, false);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CheckAuthTokenVisibility_0100
 * @tc.desc: Check oauth token visibility with non_exist account.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAuthTokenVisibility_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAuthTokenVisibility_0100");

    bool isVisible = true;
    int32_t funcResult = -1;
    g_accountManagerService->CheckAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
    EXPECT_EQ(isVisible, false);
}

/**
 * @tc.name: AppAccountManagerService_GetOAuthList_0100
 * @tc.desc: Get oauth list failed with non-existent account.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetOAuthList_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetOAuthList_0100");

    std::set<std::string> authList;
    int32_t funcResult = -1;
    g_accountManagerService->GetOAuthList(STRING_NAME, STRING_AUTH_TYPE, authList, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_GetAuthList_0100
 * @tc.desc: Get oauth list failed with non-existent account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAuthList_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAuthList_0100");

    std::set<std::string> authList;
    int32_t funcResult = -1;
    g_accountManagerService->GetAuthList(STRING_NAME, STRING_AUTH_TYPE, authList, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_GetOAuthList_0200
 * @tc.desc: Get oauth list with non-existent authType successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetOAuthList_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetOAuthList_0200");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::set<std::string> authList;
    g_accountManagerService->GetOAuthList(STRING_NAME, STRING_AUTH_TYPE, authList, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(authList.size(), SIZE_ZERO);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAuthList_0200
 * @tc.desc: Get oauth list with non-existent authType successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAuthList_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAuthList_0200");

    CreateAccountOptions option;
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::set<std::string> authList;
    g_accountManagerService->GetAuthList(STRING_NAME, STRING_AUTH_TYPE, authList, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_TYPE_NOT_EXIST);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetOAuthList_0300
 * @tc.desc: Get oauth list with existent authType successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetOAuthList_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetOAuthList_0300");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetOAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_BUNDLE_NAME_NOT_INSTALLED, true, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::set<std::string> authList;
    g_accountManagerService->GetOAuthList(STRING_NAME, STRING_AUTH_TYPE, authList, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(authList.size(), SIZE_TWO);

    auto it = authList.find(STRING_BUNDLE_NAME);
    EXPECT_NE(it, authList.end());
    it = authList.find(STRING_BUNDLE_NAME_NOT_INSTALLED);
    EXPECT_NE(it, authList.end());

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAuthList_0400
 * @tc.desc: Get oauth list with existent authType successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAuthList_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAuthList_0400");

    CreateAccountOptions option;
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::set<std::string> authList;
    g_accountManagerService->GetAuthList(STRING_NAME, STRING_AUTH_TYPE, authList, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(authList.size(), SIZE_ONE);

    auto it = authList.find(STRING_BUNDLE_NAME);
    EXPECT_NE(it, authList.end());
    it = authList.find(STRING_BUNDLE_NAME_NOT_INSTALLED);
    EXPECT_EQ(it, authList.end());

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAuthenticatorInfo_0100
 * @tc.desc: Get authenticator info failed for non-existent oauth service.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAuthenticatorInfo_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAuthenticatorInfo_0100");

    AuthenticatorInfo info;
    int32_t funcResult = -1;
    g_accountManagerService->GetAuthenticatorInfo(STRING_OWNER, info, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_GetAuthenticatorCallback_0100
 * @tc.desc: Get authenticator callback failed with non-existent sessionId.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAuthenticatorCallback_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAuthenticatorCallback_0100");

    sptr<IRemoteObject> callback;
    int32_t funcResult = -1;
    g_accountManagerService->GetAuthenticatorCallback(STRING_SESSION_ID, funcResult, callback);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_SESSION_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_AddAccountImplicitly_0100
 * @tc.desc: Add account implicitly failed for non-existent oauth service.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_AddAccountImplicitly_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_AddAccountImplicitly_0100");

    AAFwk::Want options;
    sptr<IAppAccountAuthenticatorCallback> callback = nullptr;
    int32_t funcResult = -1;
    g_accountManagerService->AddAccountImplicitly(
        STRING_OWNER, STRING_AUTH_TYPE, options, callback, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_CreateAccountImplicitly_0100
 * @tc.desc: Add account implicitly failed for non-existent oauth service.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CreateAccountImplicitly_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_CreateAccountImplicitly_0100");

    CreateAccountImplicitlyOptions options;
    sptr<IAppAccountAuthenticatorCallback> callback = nullptr;
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccountImplicitly(
        STRING_OWNER, options, callback, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_Authenticate_0100
 * @tc.desc: authenticate failed for non-existent oauth service.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_Authenticate_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_Authenticate_0100");

    AAFwk::Want options;
    sptr<IAppAccountAuthenticatorCallback> callback = nullptr;
    int32_t funcResult = -1;
    AppAccountStringInfo appAccountStringInfo;
    appAccountStringInfo.name = STRING_NAME;
    appAccountStringInfo.owner = STRING_OWNER;
    appAccountStringInfo.authType = STRING_AUTH_TYPE;
    g_accountManagerService->Authenticate(appAccountStringInfo, options, callback, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_Authenticate_v9_0100
 * @tc.desc: test version9 authenticate failed for non-existent oauth service.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_Authenticate_v9_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_Authenticate_0100");

    AAFwk::Want options;
    options.SetParam(AccountSA::Constants::API_V9, true);
    sptr<IAppAccountAuthenticatorCallback> callback = nullptr;
    int32_t funcResult = -1;
    AppAccountStringInfo appAccountStringInfo;
    appAccountStringInfo.name = STRING_NAME;
    appAccountStringInfo.owner = STRING_OWNER;
    appAccountStringInfo.authType = STRING_AUTH_TYPE;
    g_accountManagerService->Authenticate(appAccountStringInfo, options, callback, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST);
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
    int32_t funcResult = -1;
    g_accountManagerService->GetAllAccounts(STRING_OWNER, appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccounts_0200
 * @tc.desc: Get all accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0200");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->AddAccount(STRING_NAME_TWO, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    g_accountManagerService->GetAllAccounts(STRING_OWNER, appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_TWO);

    std::string name;
    appAccounts.begin()->GetName(name);
    EXPECT_EQ(name, STRING_NAME);

    (appAccounts.begin() + SIZE_ONE)->GetName(name);
    EXPECT_EQ(name, STRING_NAME_TWO);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->DeleteAccount(STRING_NAME_TWO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccounts_0300
 * @tc.desc: Get all accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0300");

    std::vector<AppAccountInfo> appAccounts;
    int32_t funcResult = -1;
    g_accountManagerService->GetAllAccounts(STRING_BUNDLE_NAME, appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(appAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccounts_0400
 * @tc.desc: Get all accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0400");

    AppAccountInfo appAccountInfo(STRING_NAME, STRING_BUNDLE_NAME);
    ErrCode result =
        AppAccountControlManager::GetInstance().AddAccount(
            STRING_NAME, STRING_EMPTY, UID, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_BUNDLE_NAME;
    result = AppAccountControlManager::GetInstance().EnableAppAccess(
        STRING_NAME, STRING_OWNER, appAccountCallingInfo, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    int32_t funcResult = -1;
    g_accountManagerService->GetAllAccounts(STRING_BUNDLE_NAME, appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    std::string owner;
    appAccounts.begin()->GetOwner(owner);
    EXPECT_EQ(owner, STRING_BUNDLE_NAME);

    result = AppAccountControlManager::GetInstance().DeleteAccount(
        STRING_NAME, UID, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccounts_0500
 * @tc.desc: Get all accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0500, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0500");

    AppAccountInfo appAccountInfo(STRING_NAME, STRING_BUNDLE_NAME);
    ErrCode result = AppAccountControlManager::GetInstance().AddAccount(
            STRING_NAME, STRING_EMPTY, UID, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    AppAccountInfo appAccountInfoTwo(STRING_NAME_TWO, STRING_OWNER);
    result = AppAccountControlManager::GetInstance().AddAccount(
        STRING_NAME_TWO, STRING_EMPTY, UID, STRING_OWNER, appAccountInfoTwo);
    EXPECT_EQ(result, ERR_OK);

    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_BUNDLE_NAME;
    result = AppAccountControlManager::GetInstance().EnableAppAccess(
            STRING_NAME, STRING_OWNER, appAccountCallingInfo, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    int32_t funcResult = -1;
    g_accountManagerService->GetAllAccounts(STRING_BUNDLE_NAME, appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    std::string owner;
    appAccounts.begin()->GetOwner(owner);
    EXPECT_EQ(owner, STRING_BUNDLE_NAME);

    std::string name;
    appAccounts.begin()->GetName(name);
    EXPECT_EQ(name, STRING_NAME);

    result = AppAccountControlManager::GetInstance().DeleteAccount(
        STRING_NAME, UID, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    result = AppAccountControlManager::GetInstance().DeleteAccount(
        STRING_NAME_TWO, UID, STRING_OWNER, appAccountInfoTwo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccounts_0600
 * @tc.desc: Get all accounts with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0600, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0600");

    std::vector<AppAccountInfo> appAccounts;
    int32_t funcResult = -1;
    g_accountManagerService->GetAllAccounts(STRING_BUNDLE_NAME_NOT_INSTALLED, appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO);
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
    int32_t funcResult = -1;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
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
    int32_t funcResult = -1;
    g_accountManagerService->QueryAllAccessibleAccounts(owner, appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(appAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccessibleAccounts_0200
 * @tc.desc: Get all accessible accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccessibleAccounts_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccessibleAccounts_0200");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    std::string name;
    appAccounts.begin()->GetName(name);
    EXPECT_EQ(name, STRING_NAME);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_QueryAllAccessibleAccounts_0200
 * @tc.desc: Get all accessible accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_QueryAllAccessibleAccounts_0200, TestSize.Level0)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    std::string owner = "";
    g_accountManagerService->QueryAllAccessibleAccounts(owner, appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    std::string name;
    appAccounts.begin()->GetName(name);
    EXPECT_EQ(name, STRING_NAME);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccessibleAccounts_0300
 * @tc.desc: Get all accessible accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccessibleAccounts_0300, TestSize.Level0)
{
    AppAccountInfo appAccountInfo(STRING_NAME, STRING_BUNDLE_NAME);
    ErrCode result = AppAccountControlManager::GetInstance().AddAccount(
        STRING_NAME, STRING_EMPTY, UID, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_BUNDLE_NAME;
    result = AppAccountControlManager::GetInstance().EnableAppAccess(
        STRING_NAME, STRING_OWNER, appAccountCallingInfo, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    int32_t funcResult = -1;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    std::string owner;
    appAccounts.begin()->GetOwner(owner);
    EXPECT_EQ(owner, STRING_BUNDLE_NAME);

    // test api9 func
    appAccounts.clear();
    std::string queryOwner = "";
    g_accountManagerService->QueryAllAccessibleAccounts(queryOwner, appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    owner = "";
    appAccounts.begin()->GetOwner(owner);
    EXPECT_EQ(owner, STRING_BUNDLE_NAME);

    result = AppAccountControlManager::GetInstance().DeleteAccount(
        STRING_NAME, UID, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_OnPackageRemoved_0100
 * @tc.desc: On package removed with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_OnPackageRemoved_0100, TestSize.Level0)
{
    auto dataStoragePtr = AppAccountControlManager::GetInstance().GetDataStorage(UID);
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
    want.SetParam(AppExecFwk::Constants::APP_INDEX, 0);

    CommonEventData commonEventData;
    commonEventData.SetWant(want);

    g_accountManagerService->observer_.OnReceiveEvent(commonEventData);
#endif // HAS_CES_PART

    bool ready = false;
    auto startTime = std::chrono::steady_clock::now();

    while (true) {
        accounts.clear();
        ErrCode ret = dataStoragePtr->LoadAllData(accounts);
        if (ret == ERR_OK && accounts.size() == SIZE_ZERO) {
            ready = true;
            break;
        } else if (std::chrono::steady_clock::now() - startTime > std::chrono::seconds(60)) { // wait event
            break;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    EXPECT_TRUE(ready);
}

/**
 * @tc.name: AppAccountManagerService_CheckAppAccess_0100
 * @tc.desc: test CheckAppAccess
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAppAccess_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAppAccess_0100");
    bool isAccessible = true;
    int32_t funcResult = -1;
    g_accountManagerService->CheckAppAccess(
        STRING_NAME, STRING_BUNDLE_NAME_NOT_INSTALLED, isAccessible, funcResult);
    EXPECT_EQ(isAccessible, false);
}

/**
 * @tc.name: AppAccountManagerService_CheckAppAccess_0200
 * @tc.desc: test CheckAppAccess
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAppAccess_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAppAccess_0200");
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    bool isAccessible = true;
    g_accountManagerService->CheckAppAccess(STRING_NAME, STRING_BUNDLE_NAME, isAccessible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isAccessible, false);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CheckAppAccess_0300
 * @tc.desc: test CheckAppAccess
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAppAccess_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAppAccess_0300");
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    bool isAccessible = false;
    g_accountManagerService->CheckAppAccess(STRING_NAME, STRING_BUNDLE_NAME, isAccessible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isAccessible, true);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CheckAppAccess_0400
 * @tc.desc: test CheckAppAccess
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAppAccess_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAppAccess_0400");
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    bool isAccessible = false;
    AppAccountCallingInfo appAccountCallingInfo;
    g_accountManagerService->GetCallingInfo(
        appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName, appAccountCallingInfo.appIndex);
    EXPECT_EQ(funcResult, ERR_OK);
    g_accountManagerService->CheckAppAccess(STRING_NAME, appAccountCallingInfo.bundleName, isAccessible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isAccessible, true);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAccountCredential_0100
 * @tc.desc: test DeleteAccountCredential
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAccountCredential_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAccountCredential_0100");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    funcResult = -1;
    g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    funcResult = -1;
    std::string credential;
    g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(credential, STRING_CREDENTIAL);

    funcResult = -1;
    g_accountManagerService->DeleteAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    funcResult = -1;
    credential = "";
    g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential, funcResult);
    EXPECT_NE(funcResult, ERR_OK);
    EXPECT_EQ(credential, "");

    funcResult = -1;
    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAccountCredential_0200
 * @tc.desc: test DeleteAccountCredential
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAccountCredential_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAccountCredential_0200");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->DeleteAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_CREDENTIAL_NOT_EXIST);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAccountCredential_0300
 * @tc.desc: test DeleteAccountCredential
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAccountCredential_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAccountCredential_0300");

    int32_t funcResult = -1;
    g_accountManagerService->DeleteAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, funcResult);
    EXPECT_NE(funcResult, ERR_OK);
}

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteAccountCredential_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteAccountCredential_0400");

    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    funcResult = -1;
    g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    funcResult = -1;
    g_accountManagerService->DeleteAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE_TWO, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_CREDENTIAL_NOT_EXIST);

    funcResult = -1;
    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SelectAccountsByOptions_0100
 * @tc.desc: test SelectAccountsByOptions
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SelectAccountsByOptions_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SelectAccountsByOptions_0100");

    SelectAccountsOptions options;
    options.hasAccounts = false;
    options.hasOwners = false;
    options.hasLabels = false;
    options.allowedAccounts.emplace_back("test_key", "value");
    options.allowedOwners = TEST_LABELS;
    options.requiredLabels = TEST_LABELS;
    sptr<MockAuthenticatorCallback> callback = new (std::nothrow)MockAuthenticatorCallback();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(0, _)).Times(1);
    int32_t funcResult = -1;
    g_accountManagerService->SelectAccountsByOptions(options, callback, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_VerifyCredential_0100
 * @tc.desc: test VerifyCredential
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_VerifyCredential_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_VerifyCredential_0100");
    VerifyCredentialOptions options;
    options.credentialType = STRING_CREDENTIAL_TYPE;
    options.credential = STRING_CREDENTIAL;
    AAFwk::WantParams want;
    options.parameters = want;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow)MockAuthenticatorCallback();
    ASSERT_NE(callback, nullptr);
    int32_t funcResult = -1;
    g_accountManagerService->VerifyCredential(STRING_NAME, STRING_OWNER, options, callback, funcResult);
    EXPECT_NE(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_VerifyCredential_0200
 * @tc.desc: test VerifyCredential
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_VerifyCredential_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_VerifyCredential_0200");
    VerifyCredentialOptions options;
    options.credentialType = STRING_CREDENTIAL_TYPE;
    options.credential = STRING_CREDENTIAL;
    AAFwk::WantParams want;
    options.parameters = want;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow)MockAuthenticatorCallback();
    ASSERT_NE(callback, nullptr);
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    g_accountManagerService->VerifyCredential(STRING_NAME, STRING_OWNER, options, callback, funcResult);
    EXPECT_NE(funcResult, ERR_OK);
    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CheckAccountLabels_0100
 * @tc.desc: test CheckAccountLabels
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAccountLabels_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAccountLabels_0100");
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow)MockAuthenticatorCallback();
    ASSERT_NE(callback, nullptr);
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    g_accountManagerService->CheckAccountLabels(STRING_NAME, STRING_OWNER, TEST_LABELS, callback, funcResult);
    EXPECT_NE(funcResult, ERR_OK);
    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CheckAccountLabels_0200
 * @tc.desc: test CheckAccountLabels
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAccountLabels_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAccountLabels_0200");
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow)MockAuthenticatorCallback();
    ASSERT_NE(callback, nullptr);
    int32_t funcResult = -1;
    g_accountManagerService->CheckAccountLabels(STRING_NAME, STRING_OWNER, TEST_LABELS, callback, funcResult);
    EXPECT_NE(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAuthenticatorProperties_0100
 * @tc.desc: test SetAuthenticatorProperties
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAuthenticatorProperties_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAuthenticatorProperties_0100");
    SetPropertiesOptions options;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow)MockAuthenticatorCallback();
    ASSERT_NE(callback, nullptr);
    int32_t funcResult = -1;
    g_accountManagerService->SetAuthenticatorProperties(STRING_OWNER, options, callback, funcResult);
    EXPECT_NE(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAuthenticatorProperties_0200
 * @tc.desc: test SetAuthenticatorProperties
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_SetAuthenticatorProperties_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAuthenticatorProperties_0200");
    SetPropertiesOptions options;
    AAFwk::WantParams want;
    options.properties = want;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow)MockAuthenticatorCallback();
    ASSERT_NE(callback, nullptr);
    int32_t funcResult = -1;
    g_accountManagerService->SetAuthenticatorProperties(STRING_OWNER, options, callback, funcResult);
    EXPECT_NE(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_OnPackageRemoved_0200
 * @tc.desc: test OnPackageRemoved
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_OnPackageRemoved_0200, TestSize.Level0)
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

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_OnUserRemoved_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_OnUserRemoved_0100");
    ErrCode result = g_accountManagerService->OnUserRemoved(TEST_USER_ID);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAllAccounts_0700
 * @tc.desc: test GetAllAccounts With AppClone.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllAccounts_0700, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllAccounts_0700");
    AppAccountInfo appAccountInfo(STRING_NAME, STRING_BUNDLE_NAME);
    appAccountInfo.SetAppIndex(1);
    ErrCode result =
        AppAccountControlManager::GetInstance().AddAccount(
            STRING_NAME, STRING_EMPTY, UID, STRING_BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_BUNDLE_NAME;
    result = AppAccountControlManager::GetInstance().EnableAppAccess(
        STRING_NAME, STRING_OWNER, appAccountCallingInfo, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    int32_t funcResult = -1;
    g_accountManagerService->GetAllAccounts(STRING_BUNDLE_NAME, appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ZERO);

    AppAccountInfo appAccountInfoTwo(STRING_NAME_TWO, STRING_BUNDLE_NAME);
    appAccountInfoTwo.SetAppIndex(0);
    result =
        AppAccountControlManager::GetInstance().AddAccount(
            STRING_NAME_TWO, STRING_EMPTY, UID, STRING_BUNDLE_NAME, appAccountInfoTwo);
    EXPECT_EQ(funcResult, ERR_OK);
    result = AppAccountControlManager::GetInstance().EnableAppAccess(
        STRING_NAME_TWO, STRING_OWNER, appAccountCallingInfo, appAccountInfoTwo);
    EXPECT_EQ(result, ERR_OK);
    g_accountManagerService->GetAllAccounts(STRING_BUNDLE_NAME, appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
}

/**
 * @tc.name: AppAccountManagerService_GetOAuthToken_0400
 * @tc.desc: test GetOAuthToken With AppClone.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetOAuthToken_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetOAuthToken_0400");
    AppAccountInfo appAccountInfo(STRING_NAME, STRING_OWNER);
    appAccountInfo.SetAppIndex(1);
    appAccountInfo.SetOAuthToken(STRING_AUTH_TYPE, STRING_TOKEN);

    ErrCode result =
        AppAccountControlManager::GetInstance().AddAccount(
            STRING_NAME, STRING_EMPTY, UID, STRING_OWNER, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    int32_t funcResult = -1;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    std::string token;
    g_accountManagerService->GetOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, token, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
    EXPECT_EQ(token, "");

    AppAccountInfo appAccountInfoTwo(STRING_NAME_TWO, STRING_OWNER);
    appAccountInfoTwo.SetAppIndex(0);
    result = AppAccountControlManager::GetInstance().AddAccount(
            STRING_NAME_TWO, STRING_EXTRA_INFO, UID, STRING_OWNER, appAccountInfoTwo);
    EXPECT_EQ(result, ERR_OK);
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    ASSERT_EQ(appAccounts.size(), SIZE_TWO);
    g_accountManagerService->SetOAuthToken(STRING_NAME_TWO, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    appAccounts[1].GetOwner(owner);
    g_accountManagerService->GetOAuthToken(STRING_NAME_TWO, owner, STRING_AUTH_TYPE, token, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(token, STRING_TOKEN);
}

/**
 * @tc.name: AppAccountManagerService_DeleteOAuthToken_0400
 * @tc.desc: test DeleteOAuthToken With AppClone.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_DeleteOAuthToken_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_DeleteOAuthToken_0400");
    AppAccountInfo appAccountInfo(STRING_NAME, STRING_OWNER);
    appAccountInfo.SetAppIndex(1);
    ErrCode result = AppAccountControlManager::GetInstance().AddAccount(
            STRING_NAME, STRING_EXTRA_INFO, UID, STRING_OWNER, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    int32_t funcResult = -1;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);
    result = appAccountInfo.SetOAuthToken(STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);

    g_accountManagerService->DeleteOAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);

    AppAccountInfo appAccountInfoTwo(STRING_NAME_TWO, STRING_OWNER);
    appAccountInfoTwo.SetAppIndex(0);
    result = AppAccountControlManager::GetInstance().AddAccount(
            STRING_NAME_TWO, STRING_EXTRA_INFO, UID, STRING_OWNER, appAccountInfoTwo);
    EXPECT_EQ(result, ERR_OK);
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    ASSERT_EQ(appAccounts.size(), SIZE_TWO);
    g_accountManagerService->SetOAuthToken(STRING_NAME_TWO, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    appAccounts[1].GetOwner(owner);
    g_accountManagerService->DeleteOAuthToken(STRING_NAME_TWO, owner, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAllOAuthTokens_0300
 * @tc.desc: test GetAllOAuthTokens With AppClone.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_GetAllOAuthTokens_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAllOAuthTokens_0300");
    AppAccountInfo appAccountInfo(STRING_NAME, STRING_OWNER);
    appAccountInfo.SetAppIndex(0);

    ErrCode result = AppAccountControlManager::GetInstance().AddAccount(
            STRING_NAME, STRING_EXTRA_INFO, UID, STRING_OWNER, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    std::vector<AppAccountInfo> appAccounts;
    int32_t funcResult = -1;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);
    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE_TWO, STRING_TOKEN_TWO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    std::vector<OAuthTokenInfo> tokenInfos;
    g_accountManagerService->GetAllOAuthTokens(STRING_NAME, owner, tokenInfos, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(tokenInfos.size(), SIZE_TWO);
    EXPECT_EQ(tokenInfos[0].token, STRING_TOKEN);
    EXPECT_EQ(tokenInfos[1].token, STRING_TOKEN_TWO);

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    tokenInfos.clear();
    AppAccountInfo appAccountInfoTwo(STRING_NAME_TWO, STRING_OWNER);
    appAccountInfoTwo.SetAppIndex(1);
    appAccountInfoTwo.SetOAuthToken(STRING_AUTH_TYPE, STRING_TOKEN);
    appAccountInfoTwo.SetOAuthToken(STRING_AUTH_TYPE_TWO, STRING_TOKEN_TWO);
    result = AppAccountControlManager::GetInstance().AddAccount(
            STRING_NAME_TWO, STRING_EXTRA_INFO, UID, STRING_OWNER, appAccountInfoTwo);
    EXPECT_EQ(result, ERR_OK);
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    appAccounts[0].GetOwner(owner);
    g_accountManagerService->GetAllOAuthTokens(STRING_NAME, owner, tokenInfos, funcResult);
    ASSERT_EQ(tokenInfos.size(), SIZE_ZERO);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}

/**
 * @tc.name: AppAccountManagerService_CheckAppAccess_0500
 * @tc.desc: test CheckAppAccess With AppClone.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */

HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAppAccess_0500, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAppAccess_0500");
    AppAccountInfo appAccountInfoTwo(STRING_NAME_TWO, STRING_OWNER);
    appAccountInfoTwo.SetAppIndex(0);
    bool isAccessible = false;
    ErrCode result = AppAccountControlManager::GetInstance().AddAccount(
        STRING_NAME_TWO, STRING_EXTRA_INFO, UID, STRING_OWNER, appAccountInfoTwo);
    EXPECT_EQ(result, ERR_OK);
    int32_t funcResult = -1;
    g_accountManagerService->EnableAppAccess(STRING_NAME_TWO, STRING_BUNDLE_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    g_accountManagerService->CheckAppAccess(STRING_NAME_TWO, STRING_BUNDLE_NAME, isAccessible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isAccessible, true);

    AppAccountInfo appAccountInfo(STRING_NAME, STRING_OWNER);
    appAccountInfo.SetAppIndex(1);
    result = AppAccountControlManager::GetInstance().AddAccount(
        STRING_NAME, STRING_EXTRA_INFO, UID, STRING_OWNER, appAccountInfo);
    g_accountManagerService->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
    isAccessible = true;
    g_accountManagerService->CheckAppAccess(STRING_NAME, STRING_BUNDLE_NAME, isAccessible, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
    EXPECT_EQ(isAccessible, false);
}

/**
 * @tc.name: AppAccountManagerService_CheckAuthTokenVisibility_0200
 * @tc.desc: test CheckAuthTokenVisibility With AppClone.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_CheckAuthTokenVisibility_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerService_CheckAuthTokenVisibility_0200");
    CreateAccountOptions option;
    int32_t funcResult = -1;
    g_accountManagerService->CreateAccount(STRING_NAME, option, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    bool isVisible = false;
    g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->SetAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(isVisible, true);

    AppAccountInfo appAccountInfoTwo(STRING_NAME_TWO, STRING_OWNER);
    appAccountInfoTwo.SetAppIndex(1);
    appAccountInfoTwo.SetOAuthToken(STRING_AUTH_TYPE, STRING_TOKEN);
    appAccountInfoTwo.SetOAuthTokenVisibility(
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true, 9);
    ErrCode result = AppAccountControlManager::GetInstance().AddAccount(
            STRING_NAME_TWO, STRING_EXTRA_INFO, UID, STRING_OWNER, appAccountInfoTwo);
    EXPECT_EQ(result, ERR_OK);
    isVisible = false;
    g_accountManagerService->CheckAuthTokenVisibility(STRING_NAME_TWO,
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST);
}
#ifndef SQLITE_DLCLOSE_ENABLE
/**
 * @tc.name: AppAccountControlManager_Transaction_001
 * @tc.desc: test basic kvstore transaction operation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountControlManager_Transaction_001, TestSize.Level2)
{
    auto dataStoragePtr = AppAccountControlManager::GetInstance().GetDataStorage(0, false);
    ASSERT_NE(nullptr, dataStoragePtr);
    std::unique_ptr<bool, std::function<void(bool *)>> rollbackCtrl = nullptr;
    EXPECT_EQ(ERR_OK, StartDbTransaction(dataStoragePtr, rollbackCtrl));
    ASSERT_NE(nullptr, rollbackCtrl);
    std::string testKey = "test";
    std::string testValue = "test1";
    EXPECT_EQ(ERR_OK, dataStoragePtr->PutValueToKvStore(testKey, testValue));
    std::string searchValue = "";

    // commit
    EXPECT_EQ(ERR_OK, CommitDbTransaction(dataStoragePtr, rollbackCtrl));
    EXPECT_EQ(ERR_OK, dataStoragePtr->GetValueFromKvStore(testKey, searchValue));
    ASSERT_EQ(searchValue, testValue);

    EXPECT_EQ(ERR_OK, dataStoragePtr->RemoveValueFromKvStore(testKey));
}

/**
 * @tc.name: AppAccountControlManager_Transaction_002
 * @tc.desc: test basic kvstore transaction operation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountControlManager_Transaction_002, TestSize.Level2)
{
    auto dataStoragePtr = AppAccountControlManager::GetInstance().GetDataStorage(0, false);
    ASSERT_NE(nullptr, dataStoragePtr);
    std::unique_ptr<bool, std::function<void(bool *)>> rollbackCtrl = nullptr;
    EXPECT_EQ(ERR_OK, StartDbTransaction(dataStoragePtr, rollbackCtrl));
    ASSERT_NE(nullptr, rollbackCtrl);
    std::string testKey = "test";
    std::string testValue = "test1";
    EXPECT_EQ(ERR_OK, dataStoragePtr->PutValueToKvStore(testKey, testValue));
    std::string searchValue = "";
    EXPECT_EQ(ERR_OK, dataStoragePtr->GetValueFromKvStore(testKey, searchValue));
    ASSERT_EQ(searchValue, testValue);

    // auto rollback, record cannot be found
    rollbackCtrl = nullptr;
    EXPECT_EQ(ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR,
        dataStoragePtr->GetValueFromKvStore(testKey, searchValue));
}

/**
 * @tc.name: AppAccountControlManager_Transaction_003
 * @tc.desc: test basic kvstore transaction operation, multi thread
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountControlManager_Transaction_003, TestSize.Level2)
{
    auto dataStoragePtr = AppAccountControlManager::GetInstance().GetDataStorage(0, false);
    ASSERT_NE(nullptr, dataStoragePtr);
    std::unique_ptr<bool, std::function<void(bool *)>> rollbackCtrl = nullptr;
    EXPECT_EQ(ERR_OK, StartDbTransaction(dataStoragePtr, rollbackCtrl));
    ASSERT_NE(nullptr, rollbackCtrl);
    std::string testKey = "test";
    std::string testValue = "test1";
    EXPECT_EQ(ERR_OK, dataStoragePtr->PutValueToKvStore(testKey, testValue));

    std::mutex mtx;
    std::condition_variable cv;
    auto threadWork = [&mtx, &cv, &testKey, &testValue]() {
        auto dataStoragePtr = AppAccountControlManager::GetInstance().GetDataStorage(0, false);
        std::string searchValue = "";
        std::unique_ptr<bool, std::function<void(bool *)>> rollbackCtrl = nullptr;
        EXPECT_EQ(ERR_OK, StartDbTransaction(dataStoragePtr, rollbackCtrl));
        ASSERT_NE(nullptr, rollbackCtrl);
        EXPECT_EQ(ERR_OK, dataStoragePtr->GetValueFromKvStore(testKey, searchValue));
        EXPECT_EQ(ERR_OK, CommitDbTransaction(dataStoragePtr, rollbackCtrl));
        ASSERT_EQ(searchValue, testValue);
        cv.notify_one();
    };
    std::thread thread(threadWork);
    std::string threadName = "testThread";
    pthread_setname_np(thread.native_handle(), threadName.c_str());
    thread.detach();

    // commit
    EXPECT_EQ(ERR_OK, CommitDbTransaction(dataStoragePtr, rollbackCtrl));

    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock);
}
#endif // SQLITE_DLCLOSE_ENABLE

/**
 * @tc.name: CallbackEnter01
 * @tc.desc: Test CallbackEnter success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, CallbackEnter01, TestSize.Level3)
{
    setuid(ACCOUNT_UID);
    OsAccountStateSubscriber *subscriber = new OsAccountStateSubscriber();
    EXPECT_EQ(subscriber->CallbackEnter(TEST_CODE), ERR_OK);
}

/**
 * @tc.name: CallbackEnter02
 * @tc.desc: Test CallbackEnter fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, CallbackEnter02, TestSize.Level3)
{
    setuid(TEST_ID);
    OsAccountStateSubscriber *subscriber = new OsAccountStateSubscriber();
    EXPECT_EQ(subscriber->CallbackEnter(TEST_CODE), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: CallbackExit01
 * @tc.desc: Test CallbackExit success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceModuleTest, CallbackExit01, TestSize.Level3)
{
    OsAccountStateSubscriber *subscriber = new OsAccountStateSubscriber();
    EXPECT_EQ(subscriber->CallbackExit(TEST_CODE, TEST_ID), ERR_OK);
}
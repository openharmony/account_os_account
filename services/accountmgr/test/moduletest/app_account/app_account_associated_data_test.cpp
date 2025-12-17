/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include <thread>

#include "account_log_wrapper.h"
#include "accesstoken_kit.h"
#define private public
#include "app_account_common.h"
#include "app_account_constants.h"
#include "app_account_control_manager.h"
#include "app_account_manager_service.h"
#undef private
#include "datetime_ex.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AppExecFwk;
namespace {
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_KEY = "key";
const std::string STRING_KEY_TWO = "key_two";
const std::string STRING_VALUE = "value";
const std::string STRING_VALUE_TWO = "value_two";
const std::string STRING_EMPTY = "";
const std::string STRING_TOKEN = "1024";
const std::string STRING_CREDENTIAL_TYPE = "password";
const std::string STRING_CREDENTIAL = "1024";
const std::string STRING_AUTH_TYPE = "read";
const std::string STRING_AUTH_TYPE_TWO = "write";
const std::string STRING_BUNDLE_NAME = "com.example.third_party";
const bool SYNC_ENABLE_FALSE = false;
constexpr std::size_t SIZE_ONE = 1;
constexpr std::size_t SIZE_BOOL = 2;
constexpr std::int32_t UID = 10000;
std::shared_ptr<AppAccountManagerService> g_accountManagerService =
    std::make_shared<AppAccountManagerService>();
static constexpr int32_t DEFAULT_API_VERSION = 8;
uint64_t g_tokenId = GetSelfTokenID();
static OHOS::Security::AccessToken::PermissionStateFull g_testState1 = {
    .permissionName = "",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {OHOS::Security::AccessToken::PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

static OHOS::Security::AccessToken::HapPolicyParams g_PolicyPrams1 = {
    .apl = OHOS::Security::AccessToken::APL_NORMAL,
    .domain = "test.domain.xxx",
    .permList = {},
    .permStateList = {g_testState1}
};

static OHOS::Security::AccessToken::HapInfoParams g_info = {
    .userID = 0,
    .bundleName = "com.example.owner",
    .instIndex = 0,
    .appIDDesc = "test.demo",
    .apiVersion = DEFAULT_API_VERSION,
    .isSystemApp = true
};
}  // namespace

class AppAccountManagerServiceAssocaitedDataTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    void ClearDataStorage();
};

void AppAccountManagerServiceAssocaitedDataTest::ClearDataStorage()
{
    auto dataStoragePtr = AppAccountControlManager::GetInstance().GetDataStorage(UID);
    ASSERT_NE(dataStoragePtr, nullptr);
    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    dataStoragePtr->LoadAllData(accounts);
    if (!accounts.empty()) {
        for (auto accountPtr : accounts) {
            dataStoragePtr->RemoveValueFromKvStore(accountPtr.first);
        }
    }
    dataStoragePtr->LoadAllData(accounts);
    GTEST_LOG_(INFO) << "ClearDataStorage end, accounts.size =" << accounts.size();
}

void AppAccountManagerServiceAssocaitedDataTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "SetUpTestCase";
}

void AppAccountManagerServiceAssocaitedDataTest::TearDownTestCase(void)
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

void AppAccountManagerServiceAssocaitedDataTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    ClearDataStorage();
}

void AppAccountManagerServiceAssocaitedDataTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountManagerService_GetAssociatedData_0100
 * @tc.desc: Get associated data with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_GetAssociatedData_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAssociatedData_0100");

    int32_t funcResult = -1;
    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    result = g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::string value;
    result = g_accountManagerService->GetAssociatedData(STRING_NAME, STRING_KEY, value, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE);

    result = g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAssociatedData_0200
 * @tc.desc: Get associated data with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_GetAssociatedData_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAssociatedData_0200");

    int32_t funcResult = -1;
    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::string value;
    result = g_accountManagerService->GetAssociatedData(STRING_NAME, STRING_KEY, value, funcResult);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_ASSOCIATED_DATA_KEY_NOT_EXIST);
    EXPECT_EQ(value, STRING_EMPTY);

    result = g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_GetAssociatedData_0300
 * @tc.desc: Get associated data with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_GetAssociatedData_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAssociatedData_0300");

    std::string value;
    int32_t funcResult = -1;
    ErrCode result = g_accountManagerService->GetAssociatedData(STRING_NAME, STRING_KEY, value, funcResult);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
    EXPECT_EQ(value, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManagerService_GetAssociatedData_0400
 * @tc.desc: Get associated data with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_GetAssociatedData_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_GetAssociatedData_0400");

    int32_t funcResult = -1;
    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    result = g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    result = g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY_TWO, STRING_VALUE_TWO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::string value;
    result = g_accountManagerService->GetAssociatedData(STRING_NAME, STRING_KEY, value, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE);

    result = g_accountManagerService->GetAssociatedData(STRING_NAME, STRING_KEY_TWO, value, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE_TWO);

    result = g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAssociatedData_0100
 * @tc.desc: Set associated data with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetAssociatedData_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAssociatedData_0100");

    int32_t funcResult = -1;
    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    result = g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    result = g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAssociatedData_0200
 * @tc.desc: Set associated data with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetAssociatedData_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAssociatedData_0200");

    int32_t funcResult = -1;
    ErrCode result = g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    result = g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    result = g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE_TWO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::string value;
    result = g_accountManagerService->GetAssociatedData(STRING_NAME, STRING_KEY, value, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE_TWO);

    result = g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetAssociatedData_0300
 * @tc.desc: Set associated data with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI5N90B
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetAssociatedData_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAssociatedData_0300");

    int32_t funcResult = -1;
    ErrCode result = g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE, funcResult);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(funcResult, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

void TestAssociatedData()
{
    int32_t num = 100;
    while (num-- > 0) {
        int32_t funcResult = -1;
        std::string associatedDataCpy = STRING_VALUE + std::to_string(num);
        g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY, associatedDataCpy, funcResult);
        EXPECT_EQ(funcResult, ERR_OK);
        AppAccountControlManager::GetInstance().associatedDataCache_.erase(0);

        std::string value;
        g_accountManagerService->GetAssociatedData(STRING_NAME, STRING_KEY, value, funcResult);
        EXPECT_EQ(funcResult, ERR_OK);
        associatedDataCpy = STRING_VALUE + std::to_string(num);
        EXPECT_EQ(value, associatedDataCpy);
    }
}

void TestAppAccess()
{
    int32_t num = 100;
    while (num-- > 0) {
        int32_t funcResult = -1;
        bool setBool = num % SIZE_BOOL;
        g_accountManagerService->SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, setBool, funcResult);
        EXPECT_EQ(funcResult, ERR_OK);

        funcResult = -1;
        bool isAccessible = SYNC_ENABLE_FALSE;
        g_accountManagerService->CheckAppAccess(STRING_NAME, STRING_BUNDLE_NAME, isAccessible, funcResult);
        EXPECT_EQ(funcResult, ERR_OK);
        setBool = num % SIZE_BOOL;
        EXPECT_EQ(isAccessible, setBool);
    }
}

void TestAccountCredential()
{
    int32_t num = 100;
    while (num-- > 0) {
        int32_t funcResult = -1;
        std::string credCpy = STRING_CREDENTIAL + std::to_string(num);
        g_accountManagerService->SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credCpy, funcResult);
        EXPECT_EQ(funcResult, ERR_OK);

        funcResult = -1;
        std::string credential = STRING_CREDENTIAL;
        g_accountManagerService->GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential, funcResult);
        EXPECT_EQ(funcResult, ERR_OK);
        credCpy = STRING_CREDENTIAL + std::to_string(num);
        EXPECT_EQ(credential, credCpy);
    }
}

void TestAppAccountSyncEnable()
{
    int32_t num = 100;
    while (num-- > 0) {
        int32_t funcResult = -1;
        bool setBool = num % SIZE_BOOL;
        g_accountManagerService->SetAppAccountSyncEnable(STRING_NAME, setBool, funcResult);
        EXPECT_EQ(funcResult, ERR_OK);

        funcResult = -1;
        bool syncEnable = SYNC_ENABLE_FALSE;
        g_accountManagerService->CheckAppAccountSyncEnable(STRING_NAME, syncEnable, funcResult);
        EXPECT_EQ(funcResult, ERR_OK);
        setBool = num % SIZE_BOOL;
        EXPECT_EQ(syncEnable, setBool);
    }
}

void TestOAuthTokenVisibility()
{
    int32_t num = 100;
    while (num-- > 0) {
        int32_t funcResult = -1;
        bool setBool = num % SIZE_BOOL;
        g_accountManagerService->SetOAuthTokenVisibility(STRING_NAME,
            STRING_AUTH_TYPE, STRING_BUNDLE_NAME, setBool, funcResult);
        EXPECT_EQ(funcResult, ERR_OK);

        funcResult = -1;
        bool isVisible = SYNC_ENABLE_FALSE;
        g_accountManagerService->CheckOAuthTokenVisibility(STRING_NAME,
            STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, funcResult);
        EXPECT_EQ(funcResult, ERR_OK);
        setBool = num % SIZE_BOOL;
        EXPECT_EQ(isVisible, setBool);
    }
}

void TestAccountExtraInfo()
{
    int32_t num = 100;
    while (num-- > 0) {
        int32_t funcResult = -1;
        std::string extraInfoCpy = STRING_EXTRA_INFO + std::to_string(num);
        g_accountManagerService->SetAccountExtraInfo(
            STRING_NAME, extraInfoCpy, funcResult);
        EXPECT_EQ(funcResult, ERR_OK);

        funcResult = -1;
        std::string extraInfo = STRING_EXTRA_INFO;
        g_accountManagerService->GetAccountExtraInfo(STRING_NAME, extraInfo, funcResult);
        EXPECT_EQ(funcResult, ERR_OK);
        extraInfoCpy = STRING_EXTRA_INFO + std::to_string(num);
        EXPECT_EQ(extraInfo, extraInfoCpy);
    }
}

void TestOAuthToken()
{
    int32_t funcResult = -1;
    std::vector<AppAccountInfo> appAccounts;
    g_accountManagerService->GetAllAccessibleAccounts(appAccounts, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
    std::string owner;
    appAccounts[0].GetOwner(owner);

    int32_t num = 100;
    while (num-- > 0) {
        std::string tokenCpy = STRING_TOKEN + std::to_string(num);
        g_accountManagerService->SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE_TWO, tokenCpy, funcResult);
        EXPECT_EQ(funcResult, ERR_OK);

        std::string token = STRING_TOKEN;
        g_accountManagerService->GetAuthToken(STRING_NAME, owner, STRING_AUTH_TYPE_TWO, token, funcResult);
        EXPECT_EQ(funcResult, ERR_OK);
        tokenCpy = STRING_TOKEN + std::to_string(num);
        EXPECT_EQ(token, tokenCpy);
    }
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_0100
 * @tc.desc: set kvdb by thread, all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_0100, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAssociatedData(TestAssociatedData);
    std::thread threadTestAppAccess(TestAppAccess);
    std::thread threadTestAccountExtraInfo(TestAccountExtraInfo);
    std::thread threadTestAccountCredential(TestAccountCredential);
    std::thread threadTestAppAccountSyncEnable(TestAppAccountSyncEnable);
    std::thread threadTestOAuthTokenVisibility(TestOAuthTokenVisibility);
    std::thread threadTestOAuthToken(TestOAuthToken);
    threadTestAssociatedData.join();
    threadTestAppAccess.join();
    threadTestAccountExtraInfo.join();
    threadTestAccountCredential.join();
    threadTestAppAccountSyncEnable.join();
    threadTestOAuthTokenVisibility.join();
    threadTestOAuthToken.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_0200
 * @tc.desc: set kvdb by thread, TestAssociatedData & TestAppAccess.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_0200, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAssociatedData(TestAssociatedData);
    std::thread threadTestAppAccess(TestAppAccess);
    threadTestAssociatedData.join();
    threadTestAppAccess.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_0300
 * @tc.desc: set kvdb by thread, TestAssociatedData & TestAccountExtraInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_0300, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAssociatedData(TestAssociatedData);
    std::thread threadTestAccountExtraInfo(TestAccountExtraInfo);
    threadTestAssociatedData.join();
    threadTestAccountExtraInfo.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_0400
 * @tc.desc: set kvdb by thread, TestAssociatedData & TestAccountCredential.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_0400, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAssociatedData(TestAssociatedData);
    std::thread threadTestAccountCredential(TestAccountCredential);
    threadTestAssociatedData.join();
    threadTestAccountCredential.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_0500
 * @tc.desc: set kvdb by thread, TestAssociatedData & TestAppAccountSyncEnable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_0500, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAssociatedData(TestAssociatedData);
    std::thread threadTestAppAccountSyncEnable(TestAppAccountSyncEnable);
    threadTestAssociatedData.join();
    threadTestAppAccountSyncEnable.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_0600
 * @tc.desc: set kvdb by thread, TestAssociatedData & TestOAuthTokenVisibility.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_0600, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAssociatedData(TestAssociatedData);
    std::thread threadTestOAuthTokenVisibility(TestOAuthTokenVisibility);
    threadTestAssociatedData.join();
    threadTestOAuthTokenVisibility.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_0700
 * @tc.desc: set kvdb by thread, TestAssociatedData & TestOAuthToken.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_0700, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAssociatedData(TestAssociatedData);
    std::thread threadTestOAuthToken(TestOAuthToken);
    threadTestAssociatedData.join();
    threadTestOAuthToken.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}
/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_0300
 * @tc.desc: set kvdb by thread, TestAppAccess & TestAccountExtraInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_0800, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAppAccess(TestAppAccess);
    std::thread threadTestAccountExtraInfo(TestAccountExtraInfo);
    threadTestAppAccess.join();
    threadTestAccountExtraInfo.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_0900
 * @tc.desc: set kvdb by thread, TestAppAccess & TestAccountCredential.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_0900, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAppAccess(TestAppAccess);
    std::thread threadTestAccountCredential(TestAccountCredential);
    threadTestAppAccess.join();
    threadTestAccountCredential.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_1000
 * @tc.desc: set kvdb by thread, TestAppAccess & TestAppAccountSyncEnable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_1000, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAppAccess(TestAppAccess);
    std::thread threadTestAppAccountSyncEnable(TestAppAccountSyncEnable);
    threadTestAppAccess.join();
    threadTestAppAccountSyncEnable.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_1100
 * @tc.desc: set kvdb by thread, TestAppAccess & TestOAuthTokenVisibility.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_1100, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAppAccess(TestAppAccess);
    std::thread threadTestOAuthTokenVisibility(TestOAuthTokenVisibility);
    threadTestAppAccess.join();
    threadTestOAuthTokenVisibility.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_1200
 * @tc.desc: set kvdb by thread, TestAppAccess & TestOAuthToken.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_1200, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAppAccess(TestAppAccess);
    std::thread threadTestOAuthToken(TestOAuthToken);
    threadTestAppAccess.join();
    threadTestOAuthToken.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}
/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_1300
 * @tc.desc: set kvdb by thread, TestAccountExtraInfo & TestAccountCredential.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_1300, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAccountExtraInfo(TestAccountExtraInfo);
    std::thread threadTestAccountCredential(TestAccountCredential);
    threadTestAccountExtraInfo.join();
    threadTestAccountCredential.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_1400
 * @tc.desc: set kvdb by thread, TestAccountExtraInfo & TestAppAccountSyncEnable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_1400, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAccountExtraInfo(TestAccountExtraInfo);
    std::thread threadTestAppAccountSyncEnable(TestAppAccountSyncEnable);
    threadTestAccountExtraInfo.join();
    threadTestAppAccountSyncEnable.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_1500
 * @tc.desc: set kvdb by thread, TestAccountExtraInfo & TestOAuthTokenVisibility.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_1500, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAccountExtraInfo(TestAccountExtraInfo);
    std::thread threadTestOAuthTokenVisibility(TestOAuthTokenVisibility);
    threadTestAccountExtraInfo.join();
    threadTestOAuthTokenVisibility.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_1600
 * @tc.desc: set kvdb by thread, TestAccountExtraInfo & TestOAuthToken.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_1600, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAccountExtraInfo(TestAccountExtraInfo);
    std::thread threadTestOAuthToken(TestOAuthToken);
    threadTestAccountExtraInfo.join();
    threadTestOAuthToken.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_1700
 * @tc.desc: set kvdb by thread, TestAccountCredential & TestAppAccountSyncEnable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_1700, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAccountCredential(TestAccountCredential);
    std::thread threadTestAppAccountSyncEnable(TestAppAccountSyncEnable);
    threadTestAccountCredential.join();
    threadTestAppAccountSyncEnable.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_1800
 * @tc.desc: set kvdb by thread, TestAccountCredential & TestOAuthTokenVisibility.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_1800, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAccountCredential(TestAccountCredential);
    std::thread threadTestOAuthTokenVisibility(TestOAuthTokenVisibility);
    threadTestAccountCredential.join();
    threadTestOAuthTokenVisibility.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_1900
 * @tc.desc: set kvdb by thread, TestAccountCredential & TestOAuthToken.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_1900, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAccountCredential(TestAccountCredential);
    std::thread threadTestOAuthToken(TestOAuthToken);
    threadTestAccountCredential.join();
    threadTestOAuthToken.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_2000
 * @tc.desc: set kvdb by thread, TestAppAccountSyncEnable & TestOAuthTokenVisibility.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_2000, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAppAccountSyncEnable(TestAppAccountSyncEnable);
    std::thread threadTestOAuthTokenVisibility(TestOAuthTokenVisibility);
    threadTestAppAccountSyncEnable.join();
    threadTestOAuthTokenVisibility.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_2100
 * @tc.desc: set kvdb by thread, TestAppAccountSyncEnable & TestOAuthToken.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_2100, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestAppAccountSyncEnable(TestAppAccountSyncEnable);
    std::thread threadTestOAuthToken(TestOAuthToken);
    threadTestAppAccountSyncEnable.join();
    threadTestOAuthToken.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SetKvdbByThread_2200
 * @tc.desc: set kvdb by thread, TestOAuthTokenVisibility & TestOAuthToken.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetKvdbByThread_2200, TestSize.Level3)
{
    int32_t funcResult = -1;
    g_accountManagerService->AddAccount(STRING_NAME, STRING_EXTRA_INFO, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);

    std::thread threadTestOAuthTokenVisibility(TestOAuthTokenVisibility);
    std::thread threadTestOAuthToken(TestOAuthToken);
    threadTestOAuthTokenVisibility.join();
    threadTestOAuthToken.join();

    g_accountManagerService->DeleteAccount(STRING_NAME, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
}
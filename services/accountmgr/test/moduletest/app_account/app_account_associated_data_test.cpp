/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifdef HAS_CES_PART
using namespace OHOS::EventFwk;
#endif // HAS_CES_PART
namespace {
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_KEY = "key";
const std::string STRING_KEY_TWO = "key_two";
const std::string STRING_VALUE = "value";
const std::string STRING_VALUE_TWO = "value_two";
const std::string STRING_EMPTY = "";
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
    
    OHOS::Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = OHOS::Security::AccessToken::AccessTokenKit::AllocHapToken(g_info, g_PolicyPrams1);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
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
    SetSelfTokenID(g_tokenId);
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
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_GetAssociatedData_0200, TestSize.Level1)
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
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_GetAssociatedData_0300, TestSize.Level1)
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
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_GetAssociatedData_0400, TestSize.Level1)
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
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetAssociatedData_0100, TestSize.Level1)
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
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetAssociatedData_0200, TestSize.Level1)
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
HWTEST_F(AppAccountManagerServiceAssocaitedDataTest, AppAccountManagerService_SetAssociatedData_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerService_SetAssociatedData_0300");

    ErrCode result = g_accountManagerService->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

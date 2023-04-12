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
#include "account_log_wrapper.h"
#define private public
#include "app_account_control_manager.h"
#include "app_account_manager_service.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_NAME_TWO = "name_two";
const std::string STRING_NAME_THREE = "name_three";
const std::string STRING_NAME_NOT_EXISTED = "name_not_existed";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_EXTRA_INFO_TWO = "extra_info_two";
const std::string STRING_BUNDLE_NAME = "com.example.third_party";
const std::string STRING_EMPTY = "";
const std::string STRING_OWNER = "com.example.owner";
const std::string APP_INDEX = "0";
const std::string HYPHEN = "#";

constexpr std::int32_t UID = 10000;
constexpr std::int32_t WAIT_FOR_EXIT = 1000;
const bool SYNC_ENABLE_TRUE = true;
const bool SYNC_ENABLE_FALSE = false;
constexpr std::int32_t WAIT_FOR_KVSTORE = 5000;

constexpr std::size_t SIZE_ZERO = 0;
constexpr std::size_t SIZE_ONE = 1;
}  // namespace

class AppAccountManagerServiceSyncModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    void ClearDataStorage(std::shared_ptr<AppAccountDataStorage> &dataStoragePtr);
    std::shared_ptr<AppAccountManagerService>
        appAccountManagerServicePtr_ = std::make_shared<AppAccountManagerService>();
    std::shared_ptr<AppAccountControlManager> controlManagerPtr_ = AppAccountControlManager::GetInstance();
};

void AppAccountManagerServiceSyncModuleTest::SetUpTestCase(void)
{}

void AppAccountManagerServiceSyncModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase!";
    DelayedSingleton<AppAccountControlManager>::DestroyInstance();
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_EXIT));
}

void AppAccountManagerServiceSyncModuleTest::SetUp(void)
{
    GTEST_LOG_(INFO) << "SetUp enter!";
    auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID);
    ClearDataStorage(dataStoragePtr);
#ifdef DISTRIBUTED_FEATURE_ENABLED
    dataStoragePtr = controlManagerPtr_->GetDataStorage(UID, true);
    ClearDataStorage(dataStoragePtr);
#endif // DISTRIBUTED_FEATURE_ENABLED
    GTEST_LOG_(INFO) << "SetUp exit!";
}

void AppAccountManagerServiceSyncModuleTest::ClearDataStorage(std::shared_ptr<AppAccountDataStorage> &dataStoragePtr)
{
    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    dataStoragePtr->LoadAllData(accounts);
    if (!accounts.empty()) {
        for (auto accountPtr : accounts) {
            dataStoragePtr->RemoveValueFromKvStore(accountPtr.first);
        }
    }
    dataStoragePtr->LoadAllData(accounts);
    GTEST_LOG_(INFO) << "AppAccountManagerServiceSyncModuleTest ClearDataStorage end, accounts.size =" <<
        accounts.size();
}

void AppAccountManagerServiceSyncModuleTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountManagerServiceSync_AddAccount_0100
 * @tc.desc: Set account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountManagerServiceSyncModuleTest, AppAccountManagerServiceSync_AddAccount_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerServiceSync_AddAccount_0100");

    ErrCode result = appAccountManagerServicePtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_KVSTORE));
    auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID);
    ASSERT_NE(dataStoragePtr, nullptr);

    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;

    result = dataStoragePtr->LoadAllData(accounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(accounts.size(), SIZE_ONE);

    auto accountPtr = accounts.begin();
    auto appAccountInfoPtr = std::static_pointer_cast<AppAccountInfo>(accountPtr->second);
    ASSERT_NE(appAccountInfoPtr, nullptr);

    std::string name;
    appAccountInfoPtr->GetName(name);
    EXPECT_EQ(name, STRING_NAME);

    result = appAccountManagerServicePtr_->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerServiceSync_AddAccount_0200
 * @tc.desc: Set account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountManagerServiceSyncModuleTest, AppAccountManagerServiceSync_AddAccount_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceSync_AddAccount_0200");

    ErrCode result = appAccountManagerServicePtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = appAccountManagerServicePtr_->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE);
    EXPECT_EQ(result, ERR_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_KVSTORE));

    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
        result = dataStoragePtr->LoadAllData(accounts);
        EXPECT_EQ(result, ERR_OK);
        ASSERT_EQ(accounts.size(), SIZE_ONE);

        auto accountPtr = accounts.begin();
        auto appAccountInfoPtr = std::static_pointer_cast<AppAccountInfo>(accountPtr->second);
        ASSERT_NE(appAccountInfoPtr, nullptr);

        std::string name;
        appAccountInfoPtr->GetName(name);
        EXPECT_EQ(name, STRING_NAME);
    }
#ifdef DISTRIBUTED_FEATURE_ENABLED
    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID, true);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
        result = dataStoragePtr->LoadAllData(accounts);
        EXPECT_EQ(result, ERR_OK);
        ASSERT_EQ(accounts.size(), SIZE_ONE);

        auto accountPtr = accounts.begin();
        auto appAccountInfoPtr = std::static_pointer_cast<AppAccountInfo>(accountPtr->second);
        ASSERT_NE(appAccountInfoPtr, nullptr);

        std::string name;
        appAccountInfoPtr->GetName(name);
        EXPECT_EQ(name, STRING_NAME);
    }
#endif // DISTRIBUTED_FEATURE_ENABLED

    result = appAccountManagerServicePtr_->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerServiceSync_DeleteAccount_0100
 * @tc.desc: Set account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountManagerServiceSyncModuleTest, AppAccountManagerServiceSync_DeleteAccount_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceSync_DeleteAccount_0100");

    ErrCode result = appAccountManagerServicePtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = appAccountManagerServicePtr_->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE);
    EXPECT_EQ(result, ERR_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_KVSTORE));

    result = appAccountManagerServicePtr_->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);

    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
        result = dataStoragePtr->LoadAllData(accounts);
        EXPECT_EQ(result, ERR_OK);
        EXPECT_EQ(accounts.size(), SIZE_ZERO);
    }
#ifdef DISTRIBUTED_FEATURE_ENABLED
    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID, true);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
        result = dataStoragePtr->LoadAllData(accounts);
        EXPECT_EQ(result, ERR_OK);
        EXPECT_EQ(accounts.size(), SIZE_ZERO);
    }
#endif // DISTRIBUTED_FEATURE_ENABLED
}

/**
 * @tc.name: AppAccountManagerServiceSync_DeleteAccount_0200
 * @tc.desc: Set account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountManagerServiceSyncModuleTest, AppAccountManagerServiceSync_DeleteAccount_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceSync_DeleteAccount_0200");

    ErrCode result = appAccountManagerServicePtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = appAccountManagerServicePtr_->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE);
    EXPECT_EQ(result, ERR_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_KVSTORE));

    result = appAccountManagerServicePtr_->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_FALSE);
    EXPECT_EQ(result, ERR_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_KVSTORE));

    result = appAccountManagerServicePtr_->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
        result = dataStoragePtr->LoadAllData(accounts);
        EXPECT_EQ(result, ERR_OK);
        EXPECT_EQ(accounts.size(), SIZE_ZERO);
    }
}

/**
 * @tc.name: AppAccountManagerServiceSync_SetAccountExtraInfo_0100
 * @tc.desc: Set account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(
    AppAccountManagerServiceSyncModuleTest, AppAccountManagerServiceSync_SetAccountExtraInfo_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceSync_SetAccountExtraInfo_0100");

    ErrCode result = appAccountManagerServicePtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = appAccountManagerServicePtr_->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE);
    EXPECT_EQ(result, ERR_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_KVSTORE));

    result = appAccountManagerServicePtr_->SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;

        result = dataStoragePtr->LoadAllData(accounts);
        EXPECT_EQ(result, ERR_OK);
        ASSERT_EQ(accounts.size(), SIZE_ONE);

        auto accountPtr = accounts.begin();
        auto appAccountInfoPtr = std::static_pointer_cast<AppAccountInfo>(accountPtr->second);

        std::string name;
        appAccountInfoPtr->GetName(name);
        EXPECT_EQ(name, STRING_NAME);

        std::string extraInfo;
        appAccountInfoPtr->GetExtraInfo(extraInfo);
        EXPECT_EQ(extraInfo, STRING_EXTRA_INFO);
    }
#ifdef DISTRIBUTED_FEATURE_ENABLED
    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID, true);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;

        result = dataStoragePtr->LoadAllData(accounts);
        EXPECT_EQ(result, ERR_OK);
        ASSERT_EQ(accounts.size(), SIZE_ONE);

        auto accountPtr = accounts.begin();
        auto appAccountInfoPtr = std::static_pointer_cast<AppAccountInfo>(accountPtr->second);

        std::string name;
        appAccountInfoPtr->GetName(name);
        EXPECT_EQ(name, STRING_NAME);

        std::string extraInfo;
        appAccountInfoPtr->GetExtraInfo(extraInfo);
        EXPECT_EQ(extraInfo, STRING_EXTRA_INFO);
    }
#endif // DISTRIBUTED_FEATURE_ENABLED

    result = appAccountManagerServicePtr_->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerServiceSync_SetAccountExtraInfo_0200
 * @tc.desc: Set account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(
    AppAccountManagerServiceSyncModuleTest, AppAccountManagerServiceSync_SetAccountExtraInfo_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceSync_SetAccountExtraInfo_0200");

    ErrCode result = appAccountManagerServicePtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    ASSERT_EQ(result, ERR_OK);

    result = appAccountManagerServicePtr_->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE);
    EXPECT_EQ(result, ERR_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_KVSTORE));

    result = appAccountManagerServicePtr_->SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = appAccountManagerServicePtr_->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_FALSE);
    EXPECT_EQ(result, ERR_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_KVSTORE));

    result = appAccountManagerServicePtr_->SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO_TWO);
    EXPECT_EQ(result, ERR_OK);

    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;

        result = dataStoragePtr->LoadAllData(accounts);
        EXPECT_EQ(result, ERR_OK);
        ASSERT_EQ(accounts.size(), SIZE_ONE);

        auto accountPtr = accounts.begin();
        EXPECT_NE(accountPtr, accounts.end());

        auto appAccountInfoPtr = std::static_pointer_cast<AppAccountInfo>(accountPtr->second);
        ASSERT_NE(appAccountInfoPtr, nullptr);

        std::string name;
        appAccountInfoPtr->GetName(name);
        EXPECT_EQ(name, STRING_NAME);

        std::string extraInfo;
        appAccountInfoPtr->GetExtraInfo(extraInfo);
        EXPECT_EQ(extraInfo, STRING_EXTRA_INFO_TWO);
    }
#ifdef DISTRIBUTED_FEATURE_ENABLED
    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID, true);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;

        result = dataStoragePtr->LoadAllData(accounts);
        EXPECT_EQ(result, ERR_OK);
        ASSERT_EQ(accounts.size(), SIZE_ONE);

        auto accountPtr = accounts.begin();
        auto appAccountInfoPtr = std::static_pointer_cast<AppAccountInfo>(accountPtr->second);

        std::string name;
        appAccountInfoPtr->GetName(name);
        EXPECT_EQ(name, STRING_NAME);

        std::string extraInfo;
        appAccountInfoPtr->GetExtraInfo(extraInfo);
        EXPECT_EQ(extraInfo, STRING_EXTRA_INFO);
    }
#endif // DISTRIBUTED_FEATURE_ENABLED

    result = appAccountManagerServicePtr_->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerServiceSync_SetAccountExtraInfo_0300
 * @tc.desc: Set account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(
    AppAccountManagerServiceSyncModuleTest, AppAccountManagerServiceSync_SetAccountExtraInfo_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceSync_SetAccountExtraInfo_0300");

    ErrCode result = appAccountManagerServicePtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    ASSERT_EQ(result, ERR_OK);

    result = appAccountManagerServicePtr_->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE);
    EXPECT_EQ(result, ERR_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_KVSTORE));

    result = appAccountManagerServicePtr_->SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = appAccountManagerServicePtr_->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_FALSE);
    EXPECT_EQ(result, ERR_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_KVSTORE));

    result = appAccountManagerServicePtr_->SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO_TWO);
    EXPECT_EQ(result, ERR_OK);

    result = appAccountManagerServicePtr_->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE);
    EXPECT_EQ(result, ERR_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_KVSTORE));

    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
        result = dataStoragePtr->LoadAllData(accounts);
        EXPECT_EQ(result, ERR_OK);
        ASSERT_EQ(accounts.size(), SIZE_ONE);

        auto accountPtr = accounts.begin();
        auto appAccountInfoPtr = std::static_pointer_cast<AppAccountInfo>(accountPtr->second);

        std::string name;
        appAccountInfoPtr->GetName(name);
        EXPECT_EQ(name, STRING_NAME);

        std::string extraInfo;
        appAccountInfoPtr->GetExtraInfo(extraInfo);
        EXPECT_EQ(extraInfo, STRING_EXTRA_INFO_TWO);
    }
#ifdef DISTRIBUTED_FEATURE_ENABLED
    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID, true);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
        result = dataStoragePtr->LoadAllData(accounts);
        EXPECT_EQ(result, ERR_OK);
        ASSERT_EQ(accounts.size(), SIZE_ONE);

        auto accountPtr = accounts.begin();
        auto appAccountInfoPtr = std::static_pointer_cast<AppAccountInfo>(accountPtr->second);

        std::string name;
        appAccountInfoPtr->GetName(name);
        EXPECT_EQ(name, STRING_NAME);

        std::string extraInfo;
        appAccountInfoPtr->GetExtraInfo(extraInfo);
        EXPECT_EQ(extraInfo, STRING_EXTRA_INFO_TWO);
    }
#endif // DISTRIBUTED_FEATURE_ENABLED

    result = appAccountManagerServicePtr_->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerServiceSync_EnableAppAccess_0100
 * @tc.desc: Set account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(AppAccountManagerServiceSyncModuleTest, AppAccountManagerServiceSync_EnableAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceSync_EnableAppAccess_0100");

    ErrCode result = appAccountManagerServicePtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = appAccountManagerServicePtr_->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE);
    EXPECT_EQ(result, ERR_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_KVSTORE));

    result = appAccountManagerServicePtr_->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);

    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::string authorizedAccounts;
        result = dataStoragePtr->GetValueFromKvStore(AppAccountDataStorage::AUTHORIZED_ACCOUNTS, authorizedAccounts);
        ASSERT_EQ(result, ERR_OK);

        auto jsonObject = Json::parse(authorizedAccounts, nullptr, false);
        EXPECT_EQ(jsonObject.is_discarded(), false);

        auto accessibleAccounts = jsonObject[STRING_BUNDLE_NAME].get<std::vector<std::string>>();
        EXPECT_EQ(accessibleAccounts.size(), SIZE_ONE);

        auto accountPtr = accessibleAccounts.begin();
        ASSERT_NE(accountPtr, accessibleAccounts.end());

        EXPECT_EQ(*accountPtr, STRING_OWNER + HYPHEN + APP_INDEX + HYPHEN + STRING_NAME + HYPHEN);
    }
#ifdef DISTRIBUTED_FEATURE_ENABLED
    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID, true);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::string authorizedAccounts;
        result = dataStoragePtr->GetValueFromKvStore(AppAccountDataStorage::AUTHORIZED_ACCOUNTS, authorizedAccounts);
        ASSERT_EQ(result, ERR_OK);

        auto jsonObject = Json::parse(authorizedAccounts, nullptr, false);
        EXPECT_EQ(jsonObject.is_discarded(), false);

        auto accessibleAccounts = jsonObject[STRING_BUNDLE_NAME].get<std::vector<std::string>>();
        EXPECT_EQ(accessibleAccounts.size(), SIZE_ONE);

        auto accountPtr = accessibleAccounts.begin();
        ASSERT_NE(accountPtr, accessibleAccounts.end());

        EXPECT_EQ(*accountPtr, STRING_OWNER + HYPHEN + APP_INDEX + HYPHEN + STRING_NAME + HYPHEN);
    }
#endif // DISTRIBUTED_FEATURE_ENABLED

    result = appAccountManagerServicePtr_->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerServiceSync_EnableAppAccess_0200
 * @tc.desc: Set account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(AppAccountManagerServiceSyncModuleTest, AppAccountManagerServiceSync_EnableAppAccess_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceSync_EnableAppAccess_0200");

    ErrCode result = appAccountManagerServicePtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = appAccountManagerServicePtr_->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE);
    EXPECT_EQ(result, ERR_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_KVSTORE));

    result = appAccountManagerServicePtr_->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);

    result = appAccountManagerServicePtr_->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ENABLE_APP_ACCESS_ALREADY_EXISTS);

    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::string authorizedAccounts;
        result = dataStoragePtr->GetValueFromKvStore(AppAccountDataStorage::AUTHORIZED_ACCOUNTS,
            authorizedAccounts);
        ASSERT_EQ(result, ERR_OK);

        auto jsonObject = Json::parse(authorizedAccounts, nullptr, false);
        EXPECT_EQ(jsonObject.is_discarded(), false);

        auto accessibleAccounts = jsonObject[STRING_BUNDLE_NAME].get<std::vector<std::string>>();
        EXPECT_EQ(accessibleAccounts.size(), SIZE_ONE);

        auto accountPtr = accessibleAccounts.begin();
        ASSERT_NE(accountPtr, accessibleAccounts.end());

        EXPECT_EQ(*accountPtr, STRING_OWNER + HYPHEN + APP_INDEX + HYPHEN + STRING_NAME + HYPHEN);
    }
#ifdef DISTRIBUTED_FEATURE_ENABLED
    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID, true);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::string authorizedAccounts;
        result = dataStoragePtr->GetValueFromKvStore(AppAccountDataStorage::AUTHORIZED_ACCOUNTS,
            authorizedAccounts);
        ASSERT_EQ(result, ERR_OK);

        auto jsonObject = Json::parse(authorizedAccounts, nullptr, false);
        EXPECT_EQ(jsonObject.is_discarded(), false);

        auto accessibleAccounts = jsonObject[STRING_BUNDLE_NAME].get<std::vector<std::string>>();
        EXPECT_EQ(accessibleAccounts.size(), SIZE_ONE);

        auto accountPtr = accessibleAccounts.begin();
        ASSERT_NE(accountPtr, accessibleAccounts.end());

        EXPECT_EQ(*accountPtr, STRING_OWNER + HYPHEN + APP_INDEX + HYPHEN + STRING_NAME + HYPHEN);
    }
#endif // DISTRIBUTED_FEATURE_ENABLED

    result = appAccountManagerServicePtr_->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerServiceSync_DisableAppAccess_0100
 * @tc.desc: Set account sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFS
 */
HWTEST_F(AppAccountManagerServiceSyncModuleTest, AppAccountManagerServiceSync_DisableAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceSync_DisableAppAccess_0100");

    ErrCode result = appAccountManagerServicePtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    result = appAccountManagerServicePtr_->SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_TRUE);
    EXPECT_EQ(result, ERR_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_KVSTORE));

    result = appAccountManagerServicePtr_->EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);

    result = appAccountManagerServicePtr_->DisableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);

    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::string authorizedAccounts;
        result = dataStoragePtr->GetValueFromKvStore(AppAccountDataStorage::AUTHORIZED_ACCOUNTS,
            authorizedAccounts);
        ASSERT_EQ(result, ERR_OK);

        auto jsonObject = Json::parse(authorizedAccounts, nullptr, false);
        EXPECT_EQ(jsonObject.is_discarded(), false);

        auto accessibleAccounts = jsonObject[STRING_BUNDLE_NAME].get<std::vector<std::string>>();
        EXPECT_EQ(accessibleAccounts.size(), SIZE_ZERO);
    }
#ifdef DISTRIBUTED_FEATURE_ENABLED
    {
        auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID, true);
        ASSERT_NE(dataStoragePtr, nullptr);

        std::string authorizedAccounts;
        result = dataStoragePtr->GetValueFromKvStore(AppAccountDataStorage::AUTHORIZED_ACCOUNTS,
            authorizedAccounts);
        ASSERT_EQ(result, ERR_OK);

        auto jsonObject = Json::parse(authorizedAccounts, nullptr, false);
        EXPECT_EQ(jsonObject.is_discarded(), false);

        auto accessibleAccounts = jsonObject[STRING_BUNDLE_NAME].get<std::vector<std::string>>();
        EXPECT_EQ(accessibleAccounts.size(), SIZE_ZERO);
    }
#endif // DISTRIBUTED_FEATURE_ENABLED

    result = appAccountManagerServicePtr_->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

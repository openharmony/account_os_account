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
#include "account_log_wrapper.h"
#include "app_account_data_storage.h"
#define private public
#include "app_account_info.h"
#undef private
#include "app_account_control_manager.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_OWNER = "com.example.owner";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_EXTRA_INFO_TWO = "extra_info_two";
const std::string STRING_BUNDLE_NAME = "com.example.third_party";
const std::string STRING_ACCOUNT_ID = "100";
const std::string STRING_STORE_ID = STRING_ACCOUNT_ID;
const std::string EL2_DATA_STORE_PREFIX = "account_";
const std::string DATA_STORAGE_PATH = "/data/service/el2/100/account/test/app_account/database/";
constexpr std::size_t SIZE_ZERO = 0;
constexpr std::size_t SIZE_ONE = 1;
AccountDataStorageOptions gOptions;
}  // namespace

class AppAccountDataStorageTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    void ClearDataStorage(void);
};

void AppAccountDataStorageTest::SetUpTestCase(void)
{}

void AppAccountDataStorageTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase!";
}

void AppAccountDataStorageTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    GTEST_LOG_(INFO) << "SetUp enter!";
    gOptions.autoSync = false;
    gOptions.securityLevel = DistributedKv::SecurityLevel::S1;
    gOptions.area = DistributedKv::EL2;
    gOptions.baseDir = DATA_STORAGE_PATH;
    ClearDataStorage();
}

void AppAccountDataStorageTest::TearDown(void)
{}

void AppAccountDataStorageTest::ClearDataStorage(void)
{
    auto dataStoragePtr = std::make_shared<AppAccountDataStorage>(EL2_DATA_STORE_PREFIX + STRING_STORE_ID, gOptions);
    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    ErrCode result = dataStoragePtr->LoadAllData(accounts);
    if (!accounts.empty()) {
        for (auto accountPtr : accounts) {
            result = dataStoragePtr->RemoveValueFromKvStore(accountPtr.first);
        }
    }
    result = dataStoragePtr->LoadAllData(accounts);
    GTEST_LOG_(INFO) << "AppAccountDataStorageTest ClearDataStorage end, accounts.size =" << accounts.size();
}

/**
 * @tc.name: AppAccountDataStorage_AddAccountInfo_0100
 * @tc.desc: Add app account info with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountDataStorageTest, AppAccountDataStorage_AddAccountInfo_0100, TestSize.Level3)
{
    ACCOUNT_LOGI("AppAccountDataStorage_AddAccountInfo_0100");

    auto dataStoragePtr = std::make_shared<AppAccountDataStorage>(EL2_DATA_STORE_PREFIX + STRING_STORE_ID, gOptions);
    EXPECT_NE(dataStoragePtr, nullptr);

    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    EXPECT_EQ(accounts.size(), SIZE_ZERO);

    int result = dataStoragePtr->LoadAllData(accounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accounts.size(), SIZE_ZERO);

    AppAccountInfo appAccountInfo(STRING_NAME, STRING_OWNER);
    appAccountInfo.SetExtraInfo(STRING_EXTRA_INFO);
    appAccountInfo.EnableAppAccess(STRING_BUNDLE_NAME);
    result = dataStoragePtr->AddAccountInfo(appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    result = dataStoragePtr->LoadAllData(accounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accounts.size(), SIZE_ONE);

    auto accountPtr = accounts.begin();
    EXPECT_NE(accountPtr, accounts.end());

    auto appAccountInfoPtr = std::static_pointer_cast<AppAccountInfo>(accountPtr->second);
    EXPECT_NE(appAccountInfoPtr, nullptr);

    // get name
    std::string name;
    appAccountInfoPtr->GetName(name);
    EXPECT_EQ(name, STRING_NAME);

    // get extraInfo
    std::string extraInfo;
    appAccountInfoPtr->GetExtraInfo(extraInfo);
    EXPECT_EQ(extraInfo, STRING_EXTRA_INFO);

    // get AuthorizedApps
    std::set<std::string> apps;
    appAccountInfoPtr->GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), SIZE_ONE);
    EXPECT_EQ(*(apps.begin()), STRING_BUNDLE_NAME);

    // delete account
    const std::string id = appAccountInfo.GetPrimeKey();
    result = dataStoragePtr->RemoveValueFromKvStore(id);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountDataStorage_SaveAccountInfo_0100
 * @tc.desc: Save app account info with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountDataStorageTest, AppAccountDataStorage_SaveAccountInfo_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountDataStorage_SaveAccountInfo_0100");

    auto dataStoragePtr = std::make_shared<AppAccountDataStorage>(EL2_DATA_STORE_PREFIX + STRING_STORE_ID, gOptions);
    EXPECT_NE(dataStoragePtr, nullptr);

    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    EXPECT_EQ(accounts.size(), SIZE_ZERO);

    int result = dataStoragePtr->LoadAllData(accounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accounts.size(), SIZE_ZERO);

    AppAccountInfo appAccountInfo(STRING_NAME, STRING_OWNER);
    appAccountInfo.SetExtraInfo(STRING_EXTRA_INFO);
    result = dataStoragePtr->AddAccountInfo(appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    // save another extra info with the same name
    appAccountInfo.SetExtraInfo(STRING_EXTRA_INFO_TWO);
    result = dataStoragePtr->SaveAccountInfo(appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    result = dataStoragePtr->LoadAllData(accounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accounts.size(), SIZE_ONE);

    auto accountPtr = accounts.begin();
    EXPECT_NE(accountPtr, accounts.end());

    auto appAccountInfoPtr = std::static_pointer_cast<AppAccountInfo>(accountPtr->second);
    EXPECT_NE(appAccountInfoPtr, nullptr);

    std::string name;
    appAccountInfoPtr->GetName(name);
    EXPECT_EQ(name, STRING_NAME);

    std::string extraInfo;
    appAccountInfoPtr->GetExtraInfo(extraInfo);
    EXPECT_EQ(extraInfo, STRING_EXTRA_INFO_TWO);

    // delete account
    const std::string id = appAccountInfo.GetPrimeKey();
    result = dataStoragePtr->RemoveValueFromKvStore(id);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountDataStorage_DeleteAccount_0100
 * @tc.desc: Delete an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountDataStorageTest, AppAccountDataStorage_DeleteAccount_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountDataStorage_DeleteAccount_0100");

    auto dataStoragePtr = std::make_shared<AppAccountDataStorage>(EL2_DATA_STORE_PREFIX + STRING_STORE_ID, gOptions);
    EXPECT_NE(dataStoragePtr, nullptr);

    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    EXPECT_EQ(accounts.size(), SIZE_ZERO);

    int result = dataStoragePtr->LoadAllData(accounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accounts.size(), SIZE_ZERO);

    AppAccountInfo appAccountInfo(STRING_NAME, STRING_OWNER);
    result = dataStoragePtr->AddAccountInfo(appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    result = dataStoragePtr->LoadAllData(accounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accounts.size(), SIZE_ONE);

    auto accountPtr = accounts.begin();
    EXPECT_NE(accountPtr, accounts.end());

    auto appAccountInfoPtr = std::static_pointer_cast<AppAccountInfo>(accountPtr->second);
    EXPECT_NE(appAccountInfoPtr, nullptr);

    std::string name;
    appAccountInfoPtr->GetName(name);
    EXPECT_EQ(name, STRING_NAME);

    const std::string id = appAccountInfo.GetPrimeKey();
    result = dataStoragePtr->RemoveValueFromKvStore(id);
    EXPECT_EQ(result, ERR_OK);

    result = dataStoragePtr->LoadAllData(accounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accounts.size(), SIZE_ZERO);
}
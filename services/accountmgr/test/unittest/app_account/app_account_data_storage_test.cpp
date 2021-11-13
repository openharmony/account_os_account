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
#include "app_account_data_storage.h"
#include "app_account_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_OWNER = "com.example.owner";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_EXTRA_INFO_TWO = "extra_info_two";
const std::string STRING_BUNDLE_NAME = "com.example.third_party";
const std::string STRING_ACCOUNT_ID = "0";
const std::string STRING_STORE_ID = STRING_ACCOUNT_ID;

constexpr size_t SIZE_ZERO = 0;
constexpr size_t SIZE_ONE = 1;
}  // namespace

class AppAccountDataStorageTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountDataStorageTest::SetUpTestCase(void)
{}

void AppAccountDataStorageTest::TearDownTestCase(void)
{}

void AppAccountDataStorageTest::SetUp(void)
{
    auto dataStoragePtr = std::make_shared<AppAccountDataStorage>(STRING_STORE_ID);
    EXPECT_NE(dataStoragePtr, nullptr);

    int result = dataStoragePtr->DeleteKvStore();
    EXPECT_EQ(result, ERR_OK);
}

void AppAccountDataStorageTest::TearDown(void)
{}

/**
 * @tc.number: AppAccountDataStorage_DeleteKvStore_0100
 * @tc.name: DeleteKvStore
 * @tc.desc: Delete a KV store.
 */
HWTEST_F(AppAccountDataStorageTest, AppAccountDataStorage_DeleteKvStore_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountDataStorage_DeleteKvStore_0100");

    auto dataStoragePtr = std::make_shared<AppAccountDataStorage>(STRING_STORE_ID);
    EXPECT_NE(dataStoragePtr, nullptr);

    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    EXPECT_EQ(accounts.size(), SIZE_ZERO);

    ErrCode result = dataStoragePtr->LoadAllData(accounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accounts.size(), SIZE_ZERO);

    result = dataStoragePtr->DeleteKvStore();
    EXPECT_EQ(result, ERR_OK);

    result = dataStoragePtr->LoadAllData(accounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accounts.size(), SIZE_ZERO);
}

/**
 * @tc.number: AppAccountDataStorage_AddAccountInfo_0100
 * @tc.name: AddAccountInfo
 * @tc.desc: Add app account info with valid data.
 */
HWTEST_F(AppAccountDataStorageTest, AppAccountDataStorage_AddAccountInfo_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountDataStorage_AddAccountInfo_0100");

    auto dataStoragePtr = std::make_shared<AppAccountDataStorage>(STRING_STORE_ID);
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
    result = appAccountInfoPtr->GetName(name);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(name, STRING_NAME);

    // get extraInfo
    std::string extraInfo;
    result = appAccountInfoPtr->GetExtraInfo(extraInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(extraInfo, STRING_EXTRA_INFO);

    // get AuthorizedApps
    std::set<std::string> apps;
    result = appAccountInfoPtr->GetAuthorizedApps(apps);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(apps.size(), SIZE_ONE);
    EXPECT_EQ(*(apps.begin()), STRING_BUNDLE_NAME);
}

/**
 * @tc.number: AppAccountDataStorage_SaveAccountInfo_0100
 * @tc.name: SaveAccountInfo
 * @tc.desc: Save app account info with valid data.
 */
HWTEST_F(AppAccountDataStorageTest, AppAccountDataStorage_SaveAccountInfo_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountDataStorage_SaveAccountInfo_0100");

    auto dataStoragePtr = std::make_shared<AppAccountDataStorage>(STRING_STORE_ID);
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
    result = appAccountInfoPtr->GetName(name);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(name, STRING_NAME);

    std::string extraInfo;
    result = appAccountInfoPtr->GetExtraInfo(extraInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(extraInfo, STRING_EXTRA_INFO_TWO);
}

/**
 * @tc.number: AppAccountDataStorage_DeleteAccount_0100
 * @tc.name: DeleteAccount
 * @tc.desc: Delete an app account with valid data.
 */
HWTEST_F(AppAccountDataStorageTest, AppAccountDataStorage_DeleteAccount_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountDataStorage_DeleteAccount_0100");

    auto dataStoragePtr = std::make_shared<AppAccountDataStorage>(STRING_STORE_ID);
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
    result = appAccountInfoPtr->GetName(name);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(name, STRING_NAME);

    const std::string id = appAccountInfo.GetPrimeKey();
    result = dataStoragePtr->RemoveInfoByKey(id);
    EXPECT_EQ(result, ERR_OK);

    result = dataStoragePtr->LoadAllData(accounts);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(accounts.size(), SIZE_ZERO);
}

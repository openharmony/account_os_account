/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "account_log_wrapper.h"
#include "app_account_common.h"
#include "app_account_event_listener.h"
#include "app_account_subscriber.h"
#define private public
#include "app_account_subscribe_death_recipient.h"
#include "app_account_subscribe_manager.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const uid_t TEST_UID  = 1;
const std::string TEST_BUNDLE_NAME = "com.example.owner";
const std::string STRING_OWNER = "com.example.owner";
const std::string TEST_OWNER_NAME = "com.bundle.owner";
const uint32_t TEST_APP_INDEX = 0;
}  // namespace

class AppAccountSubscribeManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountSubscribeManagerTest::SetUpTestCase(void)
{}

void AppAccountSubscribeManagerTest::TearDownTestCase(void)
{}

void AppAccountSubscribeManagerTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AppAccountSubscribeManagerTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountSubscribeManager_SubscribeAppAccount_0100
 * @tc.desc: SubscribeAppAccount with nullptr param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSubscribeManagerTest, SubscribeAppAccount_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountSubscribeManager_SubscribeAppAccount_0100");
    ErrCode ret = AppAccountSubscribeManager::GetInstance().SubscribeAppAccount(
        nullptr, nullptr, TEST_UID, TEST_BUNDLE_NAME, TEST_APP_INDEX);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);

    // check eventListener is nullptr.
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info with owners.
    AppAccountSubscribeInfo subscribeInfo(owners);
    auto subscribeInfoPtr = std::make_shared<AppAccountSubscribeInfo>(subscribeInfo);
    ret = AppAccountSubscribeManager::GetInstance().SubscribeAppAccount(
        subscribeInfoPtr, nullptr, TEST_UID, TEST_BUNDLE_NAME, TEST_APP_INDEX);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
    ACCOUNT_LOGI("end AppAccountSubscribeManager_SubscribeAppAccount_0100");
}

/**
 * @tc.name: AppAccountSubscribeManager_UnsubscribeAppAccount_0100
 * @tc.desc: SubscribeAppAccount with nullptr param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSubscribeManagerTest, UnsubscribeAppAccount_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountSubscribeManager_UnsubscribeAppAccount_0100");

    ErrCode ret = AppAccountSubscribeManager::GetInstance().UnsubscribeAppAccount(nullptr);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: AppAccountSubscribeManager_CheckAppAccess_0100
 * @tc.desc: CheckAppAccess with nullptr param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSubscribeManagerTest, CheckAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountSubscribeManager_CheckAppAccess_0100");
    // check subscribeInfoPtr is nullptr.
    ErrCode ret = AppAccountSubscribeManager::GetInstance().CheckAppAccess(
        nullptr, TEST_UID, TEST_BUNDLE_NAME, TEST_APP_INDEX);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: AppAccountSubscribeManager_CheckAppAccess_0200
 * @tc.desc: CheckAppAccess with nullptr param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSubscribeManagerTest, CheckAppAccess_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountSubscribeManager_CheckAppAccess_0200");

    // check subscribeInfoPtr
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);
    AppAccountSubscribeInfo subscribeInfo(owners);
    auto subscribeInfoPtr = std::make_shared<AppAccountSubscribeInfo>(subscribeInfo);

    ErrCode ret = AppAccountSubscribeManager::GetInstance().CheckAppAccess(
        subscribeInfoPtr, TEST_UID, TEST_BUNDLE_NAME, TEST_APP_INDEX);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: AppAccountSubscribeManager_CheckAppAccess_0300
 * @tc.desc: CheckAppAccess with nullptr param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSubscribeManagerTest, CheckAppAccess_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountSubscribeManager_CheckAppAccess_0300");

    // check subscribeInfoPtr
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);
    AppAccountSubscribeInfo subscribeInfo(owners);
    auto subscribeInfoPtr = std::make_shared<AppAccountSubscribeInfo>(subscribeInfo);

    ErrCode ret = AppAccountSubscribeManager::GetInstance().CheckAppAccess(
        subscribeInfoPtr, TEST_UID, TEST_OWNER_NAME, TEST_APP_INDEX);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: AppAccountSubscribeManager_InsertSubscribeRecord_0100
 * @tc.desc: InsertSubscribeRecord with nullptr param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSubscribeManagerTest, InsertSubscribeRecord_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountSubscribeManager_InsertSubscribeRecord_0100");

    // check owners is empty.
    std::vector<std::string> owners;
    ErrCode ret = AppAccountSubscribeManager::GetInstance().InsertSubscribeRecord(owners, nullptr);
    EXPECT_EQ(ret, ERR_APPACCOUNT_SERVICE_OWNERS_SIZE_IS_ZERO);

    // check subscribeRecordPtr is nullptr.
    owners.emplace_back(TEST_BUNDLE_NAME);
    ret = AppAccountSubscribeManager::GetInstance().InsertSubscribeRecord(owners, nullptr);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: AppAccountSubscribeManager_RemoveSubscribeRecord_0100
 * @tc.desc: RemoveSubscribeRecord with nullptr param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSubscribeManagerTest, RemoveSubscribeRecord_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountSubscribeManager_RemoveSubscribeRecord_0100");
    // check eventListener is nullptr.
    ErrCode ret = AppAccountSubscribeManager::GetInstance().RemoveSubscribeRecord(nullptr);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: AppAccountSubscribeManager_GetAccessibleAccountsBySubscribeInfo_0100
 * @tc.desc: GetAccessibleAccountsBySubscribeInfo with nullptr param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSubscribeManagerTest, GetAccessibleAccountsBySubscribeInfo_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountSubscribeManager_GetAccessibleAccountsBySubscribeInfo_0100");

    // check subscribeInfoPtr is nullptr.
    std::vector<AppAccountInfo> accessibleAccounts;
    std::vector<AppAccountInfo> appAccounts;
    ErrCode ret = AppAccountSubscribeManager::GetInstance().
        GetAccessibleAccountsBySubscribeInfo(nullptr, accessibleAccounts, appAccounts);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

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

#define private public
#include "app_account_subscribe_manager.h"
#undef private

#include "account_log_wrapper.h"
#define private public
#include "app_account.h"
#undef private
#include "app_account_event_listener.h"
#include "app_account_manager.h"
#include "app_account_subscriber.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
namespace {
const uid_t UID = 1;
const uint32_t APP_INDEX = 1;
const std::string BUNDLE_NAME = "testname";
const std::string STRING_OWNER = "com.example.owner";
const std::string STRING_OWNER_OUT_OF_RANGE(1200, '1');  // length 1200
}  // namespace

class AppAccountManagerSubscribeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    std::shared_ptr<AppAccountSubscribeManager> appAccountSubscribeManagerPtr =
        std::make_shared<AppAccountSubscribeManager>();
};

void AppAccountManagerSubscribeTest::SetUpTestCase(void)
{}

void AppAccountManagerSubscribeTest::TearDownTestCase(void)
{}

void AppAccountManagerSubscribeTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AppAccountManagerSubscribeTest::TearDown(void)
{}

class AppAccountSubscriberTest : public AppAccountSubscriber {
public:
    explicit AppAccountSubscriberTest(const AppAccountSubscribeInfo &subscribeInfo)
        : AppAccountSubscriber(subscribeInfo)
    {
        ACCOUNT_LOGI("enter");
    }

    ~AppAccountSubscriberTest()
    {}

    virtual void OnAccountsChanged(const std::vector<AppAccountInfo> &accounts)
    {
        ACCOUNT_LOGI("enter");
    }
};

/**
 * @tc.name: AppAccountManagerSubscribe_RestoreListenerRecords_0100
 * @tc.desc: RestoreListenerRecords test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerSubscribeTest, AppAccountManagerSubscribe_RestoreListenerRecords_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerSubscribe_RestoreListenerRecords_0100");

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo(owners);
    // make a subscriber
    std::shared_ptr<AppAccountSubscriber> subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);
    AppAccountEventListener::GetInstance()->appAccountSubscriberList_.emplace_back(subscriberTestPtr);
    AppAccountEventListener::GetInstance()->owner2Subscribers_["100001"] = {subscriberTestPtr};
    AppAccount::GetInstance().RestoreListenerRecords();

    // unsubscribe app account
    ErrCode result = AppAccountManager::UnsubscribeAppAccount(subscriberTestPtr);
    ASSERT_NE(result, ERR_APPACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED);
}

/**
 * @tc.name: AppAccountManagerSubscribe_SubscribeAppAccount_0100
 * @tc.desc: Subscribe app accounts with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(AppAccountManagerSubscribeTest, AppAccountManagerSubscribe_SubscribeAppAccount_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerSubscribe_SubscribeAppAccount_0100");

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo(owners);

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);

    // unsubscribe app account
    ErrCode result = AppAccountManager::UnsubscribeAppAccount(subscriberTestPtr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED);
}

/**
 * @tc.name: AppAccountManagerSubscribe_SubscribeAppAccount_0200
 * @tc.desc: Subscribe app accounts with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(AppAccountManagerSubscribeTest, AppAccountManagerSubscribe_SubscribeAppAccount_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerSubscribe_SubscribeAppAccount_0200");

    // make owners
    std::vector<std::string> owners;

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo(owners);

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);

    // unsubscribe app account
    ErrCode result = AppAccountManager::SubscribeAppAccount(subscriberTestPtr);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManagerSubscribe_SubscribeAppAccount_0300
 * @tc.desc: Subscribe app accounts with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(AppAccountManagerSubscribeTest, AppAccountManagerSubscribe_SubscribeAppAccount_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerSubscribe_SubscribeAppAccount_0300");

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);
    owners.emplace_back(STRING_OWNER_OUT_OF_RANGE);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo(owners);

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);

    // unsubscribe app account
    ErrCode result = AppAccountManager::SubscribeAppAccount(subscriberTestPtr);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManagerSubscribe_SubscribeAppAccount_0400
 * @tc.desc: Subscribe app accounts with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(AppAccountManagerSubscribeTest, AppAccountManagerSubscribe_SubscribeAppAccount_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManagerSubscribe_SubscribeAppAccount_0400");

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo(owners);

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);

    // unsubscribe app account
    ErrCode result = AppAccountManager::SubscribeAppAccount(subscriberTestPtr);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManagerSubscribe_SubscribeAppAccount_0500
 * @tc.desc: Subscribe app accounts failed with subscribeInfoPtr is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerSubscribeTest, AppAccountManagerSubscribe_SubscribeAppAccount_0500, TestSize.Level0)
{
    ASSERT_NE(appAccountSubscribeManagerPtr, nullptr);

    ErrCode result = appAccountSubscribeManagerPtr->SubscribeAppAccount(nullptr, nullptr, UID, BUNDLE_NAME, APP_INDEX);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}


/**
 * @tc.name: AppAccountManagerSubscribe_CheckAppAccess_0100
 * @tc.desc: CheckAppAccess failed with subscribeInfoPtr is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerSubscribeTest, AppAccountManagerSubscribe_CheckAppAccess_0100, TestSize.Level0)
{
    ASSERT_NE(appAccountSubscribeManagerPtr, nullptr);

    ErrCode result = appAccountSubscribeManagerPtr->CheckAppAccess(nullptr, UID, BUNDLE_NAME, APP_INDEX);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: AppAccountManagerSubscribe_InsertSubscribeRecord_0100
 * @tc.desc: InsertSubscribeRecord failed with subscribeInfoPtr is nullptr and owners is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerSubscribeTest, AppAccountManagerSubscribe_InsertSubscribeRecord_0100, TestSize.Level0)
{
    ASSERT_NE(appAccountSubscribeManagerPtr, nullptr);
    std::vector<std::string> owners;

    AppAccountSubscribeInfo subscribeInfo(owners);

    auto subscriberTestPtr = std::shared_ptr<AppAccountSubscribeRecord>();

    ErrCode result = appAccountSubscribeManagerPtr->InsertSubscribeRecord(owners, subscriberTestPtr);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OWNERS_SIZE_IS_ZERO);

    owners.emplace_back(STRING_OWNER);
    result = appAccountSubscribeManagerPtr->InsertSubscribeRecord(owners, nullptr);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: AppAccountManagerSubscribe_RemoveSubscribeRecord_0100
 * @tc.desc: RemoveSubscribeRecord failed with eventListener is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerSubscribeTest, AppAccountManagerSubscribe_RemoveSubscribeRecord_0100, TestSize.Level0)
{
    ASSERT_NE(appAccountSubscribeManagerPtr, nullptr);
    std::vector<std::string> owners;
    ErrCode result = appAccountSubscribeManagerPtr->RemoveSubscribeRecord(nullptr, owners);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: AppAccountManagerSubscribe_GetAccessibleAccountsBySubscribeInfo_0100
 * @tc.desc: RemoveSubscribeRecord failed with subscribeInfoPtr is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerSubscribeTest, AppAccountManagerSubscribe_GetAccessibleAccountsBySubscribeInfo_0100,
    TestSize.Level0)
{
    std::vector<AppAccountInfo> accessibleAccounts;
    std::vector<AppAccountInfo> appAccounts;
    ErrCode result =
        appAccountSubscribeManagerPtr->GetAccessibleAccountsBySubscribeInfo(nullptr, accessibleAccounts, appAccounts);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}
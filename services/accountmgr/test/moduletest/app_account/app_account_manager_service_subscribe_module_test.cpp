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

#define private public
#include "app_account.h"
#include "app_account_control_manager.h"
#undef private
#include "app_account_manager_service.h"
#include "app_account_subscriber.h"
#include "datetime_ex.h"
#include "singleton.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_OWNER = "com.example.owner";
const std::string STRING_BUNDLE_NAME = "com.example.third_party";
const std::string STRING_EXTRA_INFO = "extra_info";
std::mutex mtx;
const time_t TIME_OUT_SECONDS_LIMIT = 5;

constexpr std::int32_t UID = 10000;
}  // namespace

class AppAccountManagerServiceSubscribeModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    void DeleteKvStore(void);

    std::shared_ptr<IAppAccountControl> controlManagerPtr_;
};

void AppAccountManagerServiceSubscribeModuleTest::SetUpTestCase(void)
{}

void AppAccountManagerServiceSubscribeModuleTest::TearDownTestCase(void)
{}

void AppAccountManagerServiceSubscribeModuleTest::SetUp(void)
{
    DeleteKvStore();
}

void AppAccountManagerServiceSubscribeModuleTest::TearDown(void)
{
    DeleteKvStore();
}

void AppAccountManagerServiceSubscribeModuleTest::DeleteKvStore(void)
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

class AppAccountSubscriberTest : public AppAccountSubscriber {
public:
    explicit AppAccountSubscriberTest(const AppAccountSubscribeInfo &subscribeInfo)
        : AppAccountSubscriber(subscribeInfo)
    {
        ACCOUNT_LOGI("enter");
    }

    ~AppAccountSubscriberTest()
    {
        ACCOUNT_LOGI("enter");
    }

    virtual void OnAccountsChanged(const std::vector<AppAccountInfo> &accounts)
    {
        ACCOUNT_LOGI("enter");

        mtx.unlock();

        ErrCode result;
        std::string owner;
        std::string name;
        std::string extraInfo;

        for (auto account : accounts) {
            result = account.GetOwner(owner);
            EXPECT_EQ(result, ERR_OK);
            ACCOUNT_LOGI("owner = %{public}s", owner.c_str());

            result = account.GetName(name);
            EXPECT_EQ(result, ERR_OK);
            ACCOUNT_LOGI("name = %{public}s", name.c_str());

            result = account.GetExtraInfo(extraInfo);
            EXPECT_EQ(result, ERR_OK);
            ACCOUNT_LOGI("extraInfo = %{public}s", extraInfo.c_str());
        }
    }
};

/**
 * @tc.number: AppAccountManagerServiceSubscribe_SubscribeAppAccount_0100
 * @tc.name: SubscribeAppAccount
 * @tc.desc: Subscribe app accounts with valid data.
 */
HWTEST_F(AppAccountManagerServiceSubscribeModuleTest, AppAccountManagerServiceSubscribe_SubscribeAppAccount_0100,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceSubscribe_SubscribeAppAccount_0100");

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo(owners);

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);

    // make an event listener
    sptr<IRemoteObject> appAccountEventListener = nullptr;

    ErrCode subscribeState = DelayedSingleton<AppAccount>::GetInstance()->CreateAppAccountEventListener(
        subscriberTestPtr, appAccountEventListener);
    EXPECT_EQ(subscribeState, AppAccount::INITIAL_SUBSCRIPTION);

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    // subscribe app account
    ErrCode result = servicePtr->SubscribeAppAccount(subscribeInfo, appAccountEventListener);
    EXPECT_EQ(result, ERR_OK);

    // lock the mutex
    mtx.lock();

    // add app account
    result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    // set app account extra info
    result = servicePtr->SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    // record start time
    struct tm startTime = {0};
    EXPECT_EQ(GetSystemCurrentTime(&startTime), true);

    // record current time
    struct tm doingTime = {0};

    int64_t seconds = 0;
    while (!mtx.try_lock()) {
        // get current time and compare it with the start time
        EXPECT_EQ(GetSystemCurrentTime(&doingTime), true);
        seconds = GetSecondsBetween(startTime, doingTime);
        if (seconds >= TIME_OUT_SECONDS_LIMIT) {
            break;
        }
    }

    // unsubscribe app account
    result = servicePtr->UnsubscribeAppAccount(appAccountEventListener);
    EXPECT_EQ(result, ERR_OK);

    // the subscriber should receive the event within 5 seconds
    EXPECT_LT(seconds, TIME_OUT_SECONDS_LIMIT);

    // delete account
    result = servicePtr->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);

    // unlock the mutex
    mtx.unlock();
}

/**
 * @tc.number: AppAccountManagerServiceSubscribe_SubscribeAppAccount_0200
 * @tc.name: SubscribeAppAccount
 * @tc.desc: Subscribe app accounts with valid data.
 */
HWTEST_F(AppAccountManagerServiceSubscribeModuleTest, AppAccountManagerServiceSubscribe_SubscribeAppAccount_0200,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceSubscribe_SubscribeAppAccount_0200");

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo(owners);

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);

    // make an event listener
    sptr<IRemoteObject> appAccountEventListener = nullptr;

    ErrCode subscribeState = DelayedSingleton<AppAccount>::GetInstance()->CreateAppAccountEventListener(
        subscriberTestPtr, appAccountEventListener);
    EXPECT_EQ(subscribeState, AppAccount::INITIAL_SUBSCRIPTION);

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    // subscribe app account
    ErrCode result = servicePtr->SubscribeAppAccount(subscribeInfo, appAccountEventListener);
    EXPECT_EQ(result, ERR_OK);

    // unsubscribe app account
    result = servicePtr->UnsubscribeAppAccount(appAccountEventListener);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerServiceSubscribe_SubscribeAppAccount_0300
 * @tc.name: SubscribeAppAccount
 * @tc.desc: Subscribe app accounts with invalid data.
 */
HWTEST_F(AppAccountManagerServiceSubscribeModuleTest, AppAccountManagerServiceSubscribe_SubscribeAppAccount_0300,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceSubscribe_SubscribeAppAccount_0300");

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_BUNDLE_NAME);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo(owners);

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);

    // make an event listener
    sptr<IRemoteObject> appAccountEventListener = nullptr;

    ErrCode subscribeState = DelayedSingleton<AppAccount>::GetInstance()->CreateAppAccountEventListener(
        subscriberTestPtr, appAccountEventListener);
    EXPECT_EQ(subscribeState, AppAccount::INITIAL_SUBSCRIPTION);

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    // subscribe app account
    ErrCode result = servicePtr->SubscribeAppAccount(subscribeInfo, appAccountEventListener);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_SUBSCRIBE_PERMISSON_DENIED);
}

/**
 * @tc.number: AppAccountManagerServiceSubscribe_SubscribeAppAccount_0400
 * @tc.name: SubscribeAppAccount
 * @tc.desc: Subscribe app accounts with valid data.
 */
HWTEST_F(AppAccountManagerServiceSubscribeModuleTest, AppAccountManagerServiceSubscribe_SubscribeAppAccount_0400,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceSubscribe_SubscribeAppAccount_0400");

    // add an account
    std::string name = STRING_NAME;
    std::string bundleName = STRING_BUNDLE_NAME;
    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->AddAccount(name, STRING_EXTRA_INFO, bundleName, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    // enable app access
    result = controlManagerPtr_->EnableAppAccess(name, STRING_OWNER, bundleName, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(bundleName);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo(owners);

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);

    // make an event listener
    sptr<IRemoteObject> appAccountEventListener = nullptr;

    ErrCode subscribeState = DelayedSingleton<AppAccount>::GetInstance()->CreateAppAccountEventListener(
        subscriberTestPtr, appAccountEventListener);
    EXPECT_EQ(subscribeState, AppAccount::INITIAL_SUBSCRIPTION);

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    // subscribe app account
    result = servicePtr->SubscribeAppAccount(subscribeInfo, appAccountEventListener);
    EXPECT_EQ(result, ERR_OK);

    // unsubscribe app account
    result = servicePtr->UnsubscribeAppAccount(appAccountEventListener);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerServiceSubscribe_SubscribeAppAccount_0500
 * @tc.name: SubscribeAppAccount
 * @tc.desc: Subscribe app accounts with invalid data.
 */
HWTEST_F(AppAccountManagerServiceSubscribeModuleTest, AppAccountManagerServiceSubscribe_SubscribeAppAccount_0500,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceSubscribe_SubscribeAppAccount_0500");

    // add an account
    std::string name = STRING_NAME;
    std::string bundleName = STRING_BUNDLE_NAME;
    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->AddAccount(name, STRING_EXTRA_INFO, bundleName, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    // enable app access
    result = controlManagerPtr_->EnableAppAccess(name, STRING_OWNER, bundleName, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(bundleName);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo(owners);

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);

    // make an event listener
    sptr<IRemoteObject> appAccountEventListener = nullptr;

    ErrCode subscribeState = DelayedSingleton<AppAccount>::GetInstance()->CreateAppAccountEventListener(
        subscriberTestPtr, appAccountEventListener);
    EXPECT_EQ(subscribeState, AppAccount::INITIAL_SUBSCRIPTION);

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    // subscribe app account
    result = servicePtr->SubscribeAppAccount(subscribeInfo, appAccountEventListener);
    EXPECT_EQ(result, ERR_OK);

    // disable app access
    result = controlManagerPtr_->DisableAppAccess(name, STRING_OWNER, bundleName, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    // set extra info
    result = controlManagerPtr_->SetAccountExtraInfo(name, STRING_EXTRA_INFO, bundleName, appAccountInfo);
    EXPECT_EQ(result, ERR_OK);

    // unsubscribe app account
    result = servicePtr->UnsubscribeAppAccount(appAccountEventListener);
    EXPECT_EQ(result, ERR_OK);
}
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

#include "datetime_ex.h"
#define private public
#include "os_account.h"
#include "os_account_manager_service.h"
#undef private
#include "os_account_subscriber.h"
#include "singleton.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
std::mutex mtx;
}  // namespace

class OsAccountManagerServiceSubscribeModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    std::shared_ptr<OsAccountManagerService> osAccountManagerService_;
};

void OsAccountManagerServiceSubscribeModuleTest::SetUpTestCase(void)
{}

void OsAccountManagerServiceSubscribeModuleTest::TearDownTestCase(void)
{}

void OsAccountManagerServiceSubscribeModuleTest::SetUp(void)
{
    osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
}

void OsAccountManagerServiceSubscribeModuleTest::TearDown(void)
{}

class OsAccountSubscriberTest : public OsAccountSubscriber {
public:
    explicit OsAccountSubscriberTest(const OsAccountSubscribeInfo &subscribeInfo) : OsAccountSubscriber(subscribeInfo)
    {
        ACCOUNT_LOGI("enter");
    }

    ~OsAccountSubscriberTest()
    {}

    virtual void OnAccountsChanged(const int &id)
    {
        ACCOUNT_LOGI("enter");

        mtx.unlock();
        EXPECT_EQ(id, id);
        GTEST_LOG_(INFO) << id;
        GTEST_LOG_(INFO) << id_;
    }
    int id_;
};


/**
 * @tc.number: OsAccountManagerServiceSubscribeModuleTest_0001
 * @tc.name: SubscribeOsAccount
 * @tc.desc: Subscribe os accounts activate
 */
HWTEST_F(OsAccountManagerServiceSubscribeModuleTest, OsAccountManagerServiceSubscribeModuleTest_0001,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceSubscribeModuleTest_0001");
    OsAccountSubscribeInfo osAccountSubscribeInfo;
    osAccountSubscribeInfo.SetOsAccountSubscribeType(OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVED);
    osAccountSubscribeInfo.SetName("subscribeActive");

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<OsAccountSubscriberTest>(osAccountSubscribeInfo);

    // make an event listener
    sptr<IRemoteObject> osAccountEventListener = nullptr;

    OsAccountInfo osAccountInfo;
    ErrCode result = osAccountManagerService_->CreateOsAccount("test", 1, osAccountInfo);
    subscriberTestPtr->id_ = osAccountInfo.GetId();
    ErrCode subscribeState = DelayedSingleton<OsAccount>::GetInstance()->CreateOsAccountEventListener(
        subscriberTestPtr, osAccountEventListener);
    EXPECT_EQ(subscribeState, OsAccount::INITIAL_SUBSCRIPTION);

    // subscribe app account
    result = osAccountManagerService_->SubscribeOsAccount(osAccountSubscribeInfo, osAccountEventListener);
    EXPECT_EQ(result, ERR_OK);
    // lock the mutex
    mtx.lock();
    EXPECT_EQ(result, ERR_OK);
    result = osAccountManagerService_->StartOsAccount(osAccountInfo.GetId());
    EXPECT_EQ(result, ERR_OK);
    struct tm startTime = {0};
    EXPECT_EQ(GetSystemCurrentTime(&startTime), true);
    struct tm doingTime = {0};
    int64_t seconds = 0;
    while (!mtx.try_lock()) {
        EXPECT_EQ(GetSystemCurrentTime(&doingTime), true);
        seconds = GetSecondsBetween(startTime, doingTime);
        if (seconds >= 5) {
            break;
        }
    }
    mtx.unlock();
    result = osAccountManagerService_->UnsubscribeOsAccount(osAccountEventListener);
    EXPECT_EQ(result, ERR_OK);
    result = osAccountManagerService_->StopOsAccount(osAccountInfo.GetId());
    EXPECT_EQ(result, ERR_OK);
    osAccountManagerService_->StartOsAccount(osAccountInfo.GetId());
    // unlock the mutex
    result = osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetId());
}

/**
 * @tc.number: OsAccountManagerServiceSubscribeModuleTest_0002
 * @tc.name: SubscribeAppAccount
 * @tc.desc: Subscribe os accounts activating
 */
HWTEST_F(OsAccountManagerServiceSubscribeModuleTest, OsAccountManagerServiceSubscribeModuleTest_0002,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceSubscribeModuleTest_0002");
    OsAccountSubscribeInfo osAccountSubscribeInfo;
    osAccountSubscribeInfo.SetOsAccountSubscribeType(OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
    osAccountSubscribeInfo.SetName("subscribeActiveing");

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<OsAccountSubscriberTest>(osAccountSubscribeInfo);

    // make an event listener
    sptr<IRemoteObject> osAccountEventListener = nullptr;

    OsAccountInfo osAccountInfo;
    ErrCode result = osAccountManagerService_->CreateOsAccount("test", 1, osAccountInfo);
    subscriberTestPtr->id_ = osAccountInfo.GetId();
    ErrCode subscribeState = DelayedSingleton<OsAccount>::GetInstance()->CreateOsAccountEventListener(
        subscriberTestPtr, osAccountEventListener);
    EXPECT_EQ(subscribeState, OsAccount::INITIAL_SUBSCRIPTION);

    // subscribe app account
    result = osAccountManagerService_->SubscribeOsAccount(osAccountSubscribeInfo, osAccountEventListener);
    EXPECT_EQ(result, ERR_OK);
    // lock the mutex
    mtx.lock();
    EXPECT_EQ(result, ERR_OK);
    result = osAccountManagerService_->StartOsAccount(osAccountInfo.GetId());
    EXPECT_EQ(result, ERR_OK);
    struct tm startTime = {0};
    EXPECT_EQ(GetSystemCurrentTime(&startTime), true);
    struct tm doingTime = {0};
    int64_t seconds = 0;
    while (!mtx.try_lock()) {
        EXPECT_EQ(GetSystemCurrentTime(&doingTime), true);
        seconds = GetSecondsBetween(startTime, doingTime);
        if (seconds >= 5) {
            break;
        }
    }
    mtx.unlock();
    result = osAccountManagerService_->UnsubscribeOsAccount(osAccountEventListener);
    EXPECT_EQ(result, ERR_OK);
    result = osAccountManagerService_->StopOsAccount(osAccountInfo.GetId());
    EXPECT_EQ(result, ERR_OK);
    osAccountManagerService_->StartOsAccount(osAccountInfo.GetId());
    // unlock the mutex
    result = osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetId());
}


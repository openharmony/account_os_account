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
#include <thread>
#include "account_log_wrapper.h"
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
std::mutex g_mtx;
std::shared_ptr<OsAccountManagerService> g_osAccountManagerService = nullptr;
const std::int32_t MAIN_ACCOUNT_ID = 100;
const std::int32_t WAIT_A_MOMENT = 3000;
const std::uint32_t MAX_WAIT_FOR_READY_CNT = 100;
}  // namespace

class OsAccountManagerServiceSubscribeModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void OsAccountManagerServiceSubscribeModuleTest::SetUpTestCase(void)
{
    g_osAccountManagerService = std::make_shared<OsAccountManagerService>();
    bool isOsAccountActived = false;
    ErrCode ret = g_osAccountManagerService->IsOsAccountActived(MAIN_ACCOUNT_ID, isOsAccountActived);
    std::uint32_t waitCnt = 0;
    while (ret != ERR_OK || !isOsAccountActived) {
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_A_MOMENT));
        waitCnt++;
        GTEST_LOG_(INFO) << "SetUpTestCase waitCnt " << waitCnt << " ret = " << ret;
        ret = g_osAccountManagerService->IsOsAccountActived(MAIN_ACCOUNT_ID, isOsAccountActived);
        if (waitCnt >= MAX_WAIT_FOR_READY_CNT) {
            GTEST_LOG_(INFO) << "SetUpTestCase waitCnt " << waitCnt;
            GTEST_LOG_(INFO) << "SetUpTestCase wait for ready failed!";
            break;
        }
    }
    GTEST_LOG_(INFO) << "SetUpTestCase finished, waitCnt " << waitCnt;
}

void OsAccountManagerServiceSubscribeModuleTest::TearDownTestCase(void)
{}

void OsAccountManagerServiceSubscribeModuleTest::SetUp(void)
{}

void OsAccountManagerServiceSubscribeModuleTest::TearDown(void)
{}

class OsAccountSubscriberTest : public OsAccountSubscriber {
public:
    explicit OsAccountSubscriberTest(const OsAccountSubscribeInfo &subscribeInfo)
        : OsAccountSubscriber(subscribeInfo), id_(0)
    {
        ACCOUNT_LOGI("enter");
    }

    ~OsAccountSubscriberTest()
    {}

    virtual void OnAccountsChanged(const int &id)
    {
        ACCOUNT_LOGI("enter");

        g_mtx.unlock();
        EXPECT_EQ(id, id);
        GTEST_LOG_(INFO) << id;
        GTEST_LOG_(INFO) << id_;
    }
    int id_;
};

/**
 * @tc.name: OsAccountManagerServiceSubscribeModuleTest_0001
 * @tc.desc: Subscribe os accounts activate
 * @tc.type: FUNC
 * @tc.require: SR000GGVFH
 */
HWTEST_F(OsAccountManagerServiceSubscribeModuleTest, OsAccountManagerServiceSubscribeModuleTest_0001, TestSize.Level1)
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
    ErrCode result = g_osAccountManagerService->CreateOsAccount("test", OsAccountType::GUEST, osAccountInfo);
    subscriberTestPtr->id_ = osAccountInfo.GetLocalId();
    ErrCode subscribeState = DelayedSingleton<OsAccount>::GetInstance()->CreateOsAccountEventListener(
        subscriberTestPtr, osAccountEventListener);
    EXPECT_EQ(subscribeState, OsAccount::INITIAL_SUBSCRIPTION);

    // subscribe app account
    result = g_osAccountManagerService->SubscribeOsAccount(osAccountSubscribeInfo, osAccountEventListener);
    EXPECT_EQ(result, ERR_OK);
    // lock the mutex
    g_mtx.lock();
    EXPECT_EQ(result, ERR_OK);
    result = g_osAccountManagerService->ActivateOsAccount(osAccountInfo.GetLocalId());
    EXPECT_EQ(result, ERR_OK);
    struct tm startTime = {0};
    EXPECT_EQ(GetSystemCurrentTime(&startTime), true);
    struct tm doingTime = {0};
    int64_t seconds = 0;
    while (!g_mtx.try_lock()) {
        EXPECT_EQ(GetSystemCurrentTime(&doingTime), true);
        seconds = GetSecondsBetween(startTime, doingTime);
        if (seconds >= 5) {
            break;
        }
    }
    g_mtx.unlock();
    result = g_osAccountManagerService->UnsubscribeOsAccount(osAccountEventListener);
    EXPECT_EQ(result, ERR_OK);
    g_osAccountManagerService->ActivateOsAccount(Constants::START_USER_ID);
    // unlock the mutex
    result = g_osAccountManagerService->RemoveOsAccount(osAccountInfo.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceSubscribeModuleTest_0002
 * @tc.desc: Subscribe os accounts activating
 * @tc.type: FUNC
 * @tc.require: SR000GGVFH
 */
HWTEST_F(OsAccountManagerServiceSubscribeModuleTest, OsAccountManagerServiceSubscribeModuleTest_0002, TestSize.Level1)
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
    ErrCode result = g_osAccountManagerService->CreateOsAccount("test", OsAccountType::GUEST, osAccountInfo);
    subscriberTestPtr->id_ = osAccountInfo.GetLocalId();
    ErrCode subscribeState = DelayedSingleton<OsAccount>::GetInstance()->CreateOsAccountEventListener(
        subscriberTestPtr, osAccountEventListener);
    EXPECT_EQ(subscribeState, OsAccount::INITIAL_SUBSCRIPTION);

    // subscribe app account
    result = g_osAccountManagerService->SubscribeOsAccount(osAccountSubscribeInfo, osAccountEventListener);
    EXPECT_EQ(result, ERR_OK);
    // lock the mutex
    g_mtx.lock();
    EXPECT_EQ(result, ERR_OK);
    result = g_osAccountManagerService->ActivateOsAccount(osAccountInfo.GetLocalId());
    EXPECT_EQ(result, ERR_OK);
    struct tm startTime = {0};
    EXPECT_EQ(GetSystemCurrentTime(&startTime), true);
    struct tm doingTime = {0};
    int64_t seconds = 0;
    while (!g_mtx.try_lock()) {
        EXPECT_EQ(GetSystemCurrentTime(&doingTime), true);
        seconds = GetSecondsBetween(startTime, doingTime);
        if (seconds >= 5) {
            break;
        }
    }
    g_mtx.unlock();
    result = g_osAccountManagerService->UnsubscribeOsAccount(osAccountEventListener);
    EXPECT_EQ(result, ERR_OK);
    g_osAccountManagerService->ActivateOsAccount(Constants::START_USER_ID);
    // unlock the mutex
    result = g_osAccountManagerService->RemoveOsAccount(osAccountInfo.GetLocalId());
}

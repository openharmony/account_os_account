/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <gtest/hwext/gtest-multithread.h>
#include <new>
#include <string>
#include "account_test_common.h"
#include "ipc_skeleton.h"
#define private public
#include "iinner_os_account_manager.h"
#include "os_account.h"
#undef private
#include "os_account_manager.h"
#define private public
#include "os_account_control_file_manager.h"
#include "os_account_constraint_subscribe_manager.h"
#include "os_account_manager_service.h"
#include "os_account_proxy.h"
#include "os_account_subscribe_manager.h"
#undef private
#include "token_setproc.h"

namespace OHOS {
namespace AccountSA {
using namespace testing;
using namespace testing::mt;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AccountSA::Constants;

namespace {
bool g_flag = false;
constexpr int32_t TEST_COUNT = 100;
constexpr int32_t TEST_ID = 100;
const int32_t SLEEP_TIME = 2;
const std::string CONSTRAINT_WIFI = "constraint.wifi";
}  // namespace
class OsAccountEventManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OsAccountEventManagerTest::SetUpTestCase(void)
{
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
    IInnerOsAccountManager *innerMgrService = &IInnerOsAccountManager::GetInstance();
    std::shared_ptr<OsAccountControlFileManager> osAccountControl =
        std::static_pointer_cast<OsAccountControlFileManager>(innerMgrService->osAccountControl_);
#ifdef ENABLE_FILE_WATCHER
    osAccountControl->eventCallbackFunc_ = nullptr;
    for (auto &fileNameMgr : osAccountControl->accountFileWatcherMgr_.fileNameMgrMap_) {
        fileNameMgr.second->eventCallbackFunc_ = nullptr;
    }
#endif // ENABLE_FILE_WATCHER
#ifdef BUNDLE_ADAPTER_MOCK
    auto osAccountService = new (std::nothrow) OsAccountManagerService();
    ASSERT_NE(osAccountService, nullptr);
    IInnerOsAccountManager::GetInstance().Init();
    OsAccount::GetInstance().proxy_ = new (std::nothrow) OsAccountProxy(osAccountService->AsObject());
    ASSERT_NE(OsAccount::GetInstance().proxy_, nullptr);
#endif
}

void OsAccountEventManagerTest::TearDownTestCase(void)
{}

void OsAccountEventManagerTest::SetUp(void)
{}

void OsAccountEventManagerTest::TearDown(void)
{}

class TestOsAccountSubscriber : public OsAccountSubscriber {
public:
    TestOsAccountSubscriber() {}
    explicit TestOsAccountSubscriber(const OsAccountSubscribeInfo &subscribeInfo): OsAccountSubscriber(subscribeInfo) {}
    void OnAccountsChanged(const int& id) {}
    void OnAccountsSwitch(const int &newId, const int &oldId) override
    {
        // mock operation
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    }
};

void TestWriteReadFileInfo()
{
    g_flag = !g_flag;
    int32_t i = TEST_COUNT;
    if (g_flag) {
        while (i--) {
            // subscribe account
            OsAccountSubscribeInfo subscribeInfo(OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING, "event_test");
            auto subscriber = std::make_shared<TestOsAccountSubscriber>(subscribeInfo);
            EXPECT_NE(nullptr, subscriber);
            sptr<OsAccountEventListener> listener = new (std::nothrow) OsAccountEventListener();
            listener->InsertRecord(subscriber);
            EXPECT_EQ(ERR_OK, OsAccount::GetInstance().proxy_->SubscribeOsAccount(
                listener->GetTotalSubscribeInfo(), listener));
        }
    } else {
        while (i--) {
            IInnerOsAccountManager::
                GetInstance().subscribeManager_.Publish(TEST_ID, OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
            IInnerOsAccountManager::
                GetInstance().subscribeManager_.Publish(TEST_ID, OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED, START_USER_ID);
        }
    }
}

void TestPublishSwitch()
{
    g_flag = !g_flag;
    int32_t i = TEST_COUNT;
    if (g_flag) {
        while (i--) {
            IInnerOsAccountManager::
                GetInstance().subscribeManager_.Publish(TEST_ID, OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING, START_USER_ID);
            IInnerOsAccountManager::
                GetInstance().subscribeManager_.Publish(TEST_ID, OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED, START_USER_ID);
        }
    }
}

/**
 * @tc.name: OsAccountEventManagerTestTest001
 * @tc.desc: Test multiple thread event manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountEventManagerTest, OsAccountEventManagerTestTest001, TestSize.Level1)
{
    GTEST_RUN_TASK(TestWriteReadFileInfo);
}

/**
 * @tc.name: OsAccountSwitchTestTest001
 * @tc.desc: Test multiple thread switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountEventManagerTest, OsAccountSwitchTestTest001, TestSize.Level1)
{
    g_flag = false;
    OsAccountSubscribeInfo subscribeInfoSwitched(OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED, "event_test");
    auto subscriberSwitched = std::make_shared<TestOsAccountSubscriber>(subscribeInfoSwitched);
    EXPECT_NE(nullptr, subscriberSwitched);
    EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(subscriberSwitched));
    OsAccountSubscribeInfo subscribeInfoSwitching(OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING, "event_test");
    auto subscriberSwitching = std::make_shared<TestOsAccountSubscriber>(subscribeInfoSwitching);
    EXPECT_NE(nullptr, subscriberSwitching);
    EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(subscriberSwitching));
    GTEST_RUN_TASK(TestPublishSwitch);
    EXPECT_EQ(ERR_OK, OsAccountManager::UnsubscribeOsAccount(subscriberSwitched));
    EXPECT_EQ(ERR_OK, OsAccountManager::UnsubscribeOsAccount(subscriberSwitching));
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

class MockOsAccountConstraintSubscriber : public OsAccountConstraintSubscriber {
public:
    explicit MockOsAccountConstraintSubscriber(const std::set<std::string> &constraintSet)
        : OsAccountConstraintSubscriber(constraintSet) {}
    void OnConstraintChanged(const OsAccountConstraintStateData &constraintData) {};
};

void TestConstraintSubscibeInfo()
{
    g_flag = !g_flag;
    int32_t i = TEST_COUNT;
    std::set<std::string> constraintSet = {CONSTRAINT_WIFI};
    if (g_flag) {
        while (i--) {
            auto subscriber = std::make_shared<MockOsAccountConstraintSubscriber>(constraintSet);
            EXPECT_NE(nullptr, subscriber);
            sptr<OsAccountConstraintSubscriberManager> listener =
                new (std::nothrow) OsAccountConstraintSubscriberManager();
            listener->InsertSubscriberRecord(subscriber);
            OsAccountConstraintSubscribeInfo info(listener->constraintSet_);
            setuid(i);
            EXPECT_EQ(ERR_OK, OsAccount::GetInstance().proxy_->SubscribeOsAccountConstraints(info, listener));
        }
    } else {
        while (i--) {
            OsAccountConstraintSubscribeManager::GetInstance().Publish(TEST_ID, constraintSet, true);
        }
    }
}

/**
 * @tc.name: OsAccountConstraintSubscribeManager001
 * @tc.desc: Test multiple thread constraint event manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountEventManagerTest, OsAccountConstraintSubscribeManager001, TestSize.Level1)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS"}, tokenID));
    GTEST_RUN_TASK(TestConstraintSubscibeInfo);
    setuid(0);
    ASSERT_TRUE(RecoveryPermission(tokenID, selfTokenId));
}
}  // namespace AccountSA
}  // namespace OHOS
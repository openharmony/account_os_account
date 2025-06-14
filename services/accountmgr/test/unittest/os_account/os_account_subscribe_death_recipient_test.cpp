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
#include <map>
#include <thread>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"

#include "os_account_delete_user_idm_callback.h"
#include "os_account_event_proxy.h"
#include "os_account_subscribe_death_recipient.h"
#define private public
#include "os_account_subscribe_manager.h"
#include "ability_manager_adapter.h"
#undef private
#include "os_account_interface.h"
#include "mock_account_mgr_service.h"
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;
const int32_t SLEEP_TIME = 100;
class OsAccountCoverageTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};


void OsAccountCoverageTest::SetUpTestCase(void)
{}

void OsAccountCoverageTest::TearDownTestCase(void)
{}

void OsAccountCoverageTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountCoverageTest::TearDown(void)
{}

class DelayEventProxy : public OsAccountEventProxy {
public:
    DelayEventProxy() :OsAccountEventProxy(nullptr) {}
    void OnAccountsSwitch(const int &newId, const int &oldId) override
    {
        // mock operation
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    }
};

/*
 * @tc.name: DestructorCrashWhenThreadRunning_001
 * @tc.desc: test if SwitchSubscribeInfo crash when destructor.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountCoverageTest, DestructorCrashWhenThreadRunning_001, TestSize.Level1)
{
    auto obj = std::make_shared<SwitchSubscribeInfo>();
    auto proxy = sptr<IOsAccountEvent>(new DelayEventProxy());
    ASSERT_NE(proxy, nullptr);

    OsAccountStateParcel stateParcel;
    stateParcel.state = OsAccountState::ACTIVATED;
    for (int i = 0; i < 10; ++i) {
        stateParcel.fromId = i - 1;
        stateParcel.toId = i;
        EXPECT_TRUE(obj->ProductTask(proxy, stateParcel));
    }
    obj.reset();
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/*
 * @tc.name: UseAfterFreeScenario_001
 * @tc.desc: test if SwitchSubscribeInfo use after free.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountCoverageTest, UseAfterFreeScenario_001, TestSize.Level1)
{
    auto obj = std::make_shared<SwitchSubscribeInfo>();
    auto proxy = sptr<IOsAccountEvent>(new DelayEventProxy());
    ASSERT_NE(proxy, nullptr);

    OsAccountStateParcel stateParcel;
    stateParcel.state = OsAccountState::ACTIVATED;
    stateParcel.fromId = 0;
    stateParcel.toId = 1;
    EXPECT_TRUE(obj->ProductTask(proxy, stateParcel));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    obj.reset();

    // customer is working
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

/*
 * @tc.name: HighFrequencyLifecycle_001
 * @tc.desc: test if SwitchSubscribeInfo high frequency lifecycle.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountCoverageTest, HighFrequencyLifecycle_001, TestSize.Level1)
{
    OsAccountStateParcel stateParcel;
    stateParcel.state = OsAccountState::ACTIVATED;
    stateParcel.fromId = 0;
    stateParcel.toId = 1;
    for (int i = 0; i < 1000; ++i) {
        auto obj = std::make_shared<SwitchSubscribeInfo>();
        EXPECT_TRUE(obj->ProductTask(sptr<IOsAccountEvent>(new DelayEventProxy()), stateParcel));
        obj.reset();
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
}

/*
 * @tc.name: OnRemoteDiedTest_0100
 * @tc.desc: test if OsAccountSubscribeDeathRecipient's OnRemoteDied function executed as expected in normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountCoverageTest, OnRemoteDiedTest_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "OsAccountCoverageTest, OnRemoteDiedTest_0100, TestSize.Level1";
    OsAccountSubscribeInfo subscribeInfo;
    sptr<MockAccountMgrService> listener = new (std::nothrow) MockAccountMgrService();
    ASSERT_NE(nullptr, listener);

    auto subscribeInfoPtr = std::make_shared<OsAccountSubscribeInfo>(subscribeInfo);

    OsAccountSubscribeManager::GetInstance().SubscribeOsAccount(subscribeInfoPtr, listener);

    int size = OsAccountSubscribeManager::GetInstance().subscribeRecords_.size();
    EXPECT_EQ(size, 1);

    std::shared_ptr<OsAccountSubscribeDeathRecipient> recipient = std::make_shared<OsAccountSubscribeDeathRecipient>();
    ASSERT_NE(nullptr, recipient);
    recipient->OnRemoteDied(listener);
    size = OsAccountSubscribeManager::GetInstance().subscribeRecords_.size();
    EXPECT_EQ(size, 0);
}

/*
 * @tc.name: OnRemoteDiedTest_0200
 * @tc.desc: test if OsAccountSubscribeDeathRecipient's OnRemoteDied function executed
 * as expected when param is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountCoverageTest, OnRemoteDiedTest_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "OsAccountCoverageTest, OnRemoteDiedTest_0200, TestSize.Level1";
    std::shared_ptr<OsAccountSubscribeDeathRecipient> recipient = std::make_shared<OsAccountSubscribeDeathRecipient>();
    ASSERT_NE(nullptr, recipient);
    wptr<IRemoteObject> wptrDeath = nullptr;
    recipient->OnRemoteDied(wptrDeath);
    int size = OsAccountSubscribeManager::GetInstance().subscribeRecords_.size();
    EXPECT_EQ(size, 0);
}

/*
 * @tc.name: OnRemoteDiedTest_0200
 * @tc.desc: test if OsAccountSubscribeDeathRecipient's OnRemoteDied function executed as expected when
 *           sptr param is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountCoverageTest, OnRemoteDiedTest_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "OsAccountCoverageTest, OnRemoteDiedTest_0300, TestSize.Level1";
    std::shared_ptr<OsAccountSubscribeDeathRecipient> recipient = std::make_shared<OsAccountSubscribeDeathRecipient>();
    ASSERT_NE(nullptr, recipient);
    const sptr<IRemoteObject> sptrDeath = nullptr;
    wptr<IRemoteObject> wptrDeath = sptrDeath;
    recipient->OnRemoteDied(wptrDeath);
    int size = OsAccountSubscribeManager::GetInstance().subscribeRecords_.size();
    EXPECT_EQ(size, 0);
}

/*
 * @tc.name: OnRemoteDiedTest_0400
 * @tc.desc: test if AbilityMgrDeathRecipient's OnRemoteDied function executed as expected when
 *           sptr param is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountCoverageTest, OnRemoteDiedTest_0400, TestSize.Level1)
{
    std::shared_ptr<AbilityManagerAdapter::AbilityMgrDeathRecipient> recipient =
        std::make_shared<AbilityManagerAdapter::AbilityMgrDeathRecipient>();
    ASSERT_NE(nullptr, recipient);
    const sptr<IRemoteObject> sptrDeath = nullptr;
    wptr<IRemoteObject> wptrDeath = sptrDeath;
    recipient->OnRemoteDied(wptrDeath);
    EXPECT_EQ(DelayedSingleton<AbilityManagerAdapter>::GetInstance()->deathRecipient_, nullptr);
}

/**
 * @tc.name: SubscribeOsAccount_0001
 * @tc.desc: Test SubscribeOsAccount with nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountCoverageTest, SubscribeOsAccount_0001, TestSize.Level1)
{
    OsAccountSubscribeInfo subscribeInfo;
    sptr<MockAccountMgrService> listener = new (std::nothrow) MockAccountMgrService();
    ASSERT_NE(nullptr, listener);

    auto subscribeInfoPtr = std::make_shared<OsAccountSubscribeInfo>(subscribeInfo);
    ASSERT_NE(nullptr, subscribeInfoPtr);

    ErrCode result = OsAccountSubscribeManager::GetInstance().SubscribeOsAccount(nullptr, listener);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);

    result = OsAccountSubscribeManager::GetInstance().SubscribeOsAccount(subscribeInfoPtr, nullptr);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: UnsubscribeOsAccount_0001
 * @tc.desc: Test UnsubscribeOsAccount with nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountCoverageTest, UnsubscribeOsAccount_0001, TestSize.Level1)
{
    ErrCode result = OsAccountSubscribeManager::GetInstance().UnsubscribeOsAccount(nullptr);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: RemoveSubscribeRecord_0001
 * @tc.desc: Test RemoveSubscribeRecord with nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountCoverageTest, RemoveSubscribeRecord_0001, TestSize.Level1)
{
    ErrCode result = OsAccountSubscribeManager::GetInstance().RemoveSubscribeRecord(nullptr);
    EXPECT_EQ(result, ERR_OK);
}
}  // namespace AccountSA
}  // namespace OHOS

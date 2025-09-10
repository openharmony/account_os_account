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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "os_account_constants.h"
#include "os_account_manager.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string ACCOUNT_NAME = "Zhangsan";
constexpr int32_t SLEEP_SECONDS = 6;
constexpr int32_t TWICE = 2;
}  // namespace
class OsAccountSubscribeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void) {};
    void SetUp(void) override;
    void TearDown(void) override {};
};

void OsAccountSubscribeTest::SetUpTestCase(void)
{
    ASSERT_NE(GetAllAccountPermission(), 0);
}

void OsAccountSubscribeTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

class MockSubscriber {
public:
    MOCK_METHOD3(OnStateChanged, void(OsAccountState state, int32_t fromId, int32_t toId));
    MOCK_METHOD4(OnStateChangedWithDisplayId,
        void(OsAccountState state, int32_t fromId, int32_t toId, std::optional<uint64_t> displayId));
};

class TestSubscriber final : public OsAccountSubscriber {
public:
    TestSubscriber(const OsAccountSubscribeInfo &info, std::shared_ptr<MockSubscriber> &mockSubscriber,
        bool isBlock = false)
        : OsAccountSubscriber(info), info_(info), mockSubscriber_(mockSubscriber), isBlock_(isBlock) {};

    void OnStateChanged(const OsAccountStateData &data) override;

public:
    bool isRemoved_ = false;
    std::mutex mutex_;
    std::condition_variable condVar_;

private:
    OsAccountSubscribeInfo info_;
    std::shared_ptr<MockSubscriber> mockSubscriber_;
    bool isBlock_;
};

void TestSubscriber::OnStateChanged(const OsAccountStateData &data)
{
    ACCOUNT_LOGI("State: %{public}d, fromId: %{public}d, toId: %{public}d, callback is nullptr: %{public}d",
        data.state, data.fromId, data.toId, data.callback == nullptr);
    std::set<OsAccountState> states;
    info_.GetStates(states);
    if (states.find(data.state) == states.end()) {
        ACCOUNT_LOGE("The state=%{public}d is not expected", data.state);
        return;
    }
    if (data.state == OsAccountState::REMOVED) {
        std::lock_guard<std::mutex> lock(mutex_);
        isRemoved_ = true;
        condVar_.notify_one();
    }
    if (mockSubscriber_ != nullptr) {
        mockSubscriber_->OnStateChanged(data.state, data.fromId, data.toId);
    }
    if (isBlock_ && (data.state == OsAccountState::STOPPING || data.state == OsAccountState::LOCKING)) {
        ACCOUNT_LOGI("Sleep start, %{public}d seconds", SLEEP_SECONDS);
        isBlock_ = false;
        sleep(SLEEP_SECONDS);
        ACCOUNT_LOGI("Sleep seconds end");
    }
    if (data.callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr");
        return;
    }
    data.callback->OnComplete();
}

class TestDisplayIdSubscriber final : public OsAccountSubscriber {
public:
    TestDisplayIdSubscriber(const OsAccountSubscribeInfo &info, std::shared_ptr<MockSubscriber> &mockSubscriber)
        : OsAccountSubscriber(info), info_(info), mockSubscriber_(mockSubscriber) {};

    void OnStateChanged(const OsAccountStateData &data) override;

public:
    bool isRemoved_ = false;
    std::mutex mutex_;
    std::condition_variable condVar_;

private:
    OsAccountSubscribeInfo info_;
    std::shared_ptr<MockSubscriber> mockSubscriber_;
};

void TestDisplayIdSubscriber::OnStateChanged(const OsAccountStateData &data)
{
    ACCOUNT_LOGI("State: %{public}d, fromId: %{public}d, toId: %{public}d, displayId: %{public}s",
        data.state, data.fromId, data.toId, data.displayId.has_value() ?
        std::to_string(data.displayId.value()).c_str() : "nullopt");
    std::set<OsAccountState> states;
    info_.GetStates(states);
    if (states.find(data.state) == states.end()) {
        ACCOUNT_LOGE("The state=%{public}d is not expected", data.state);
        return;
    }
    if (data.state == OsAccountState::REMOVED) {
        std::lock_guard<std::mutex> lock(mutex_);
        isRemoved_ = true;
        condVar_.notify_one();
    }
    if (mockSubscriber_ != nullptr) {
        if (data.state == OsAccountState::SWITCHING || data.state == OsAccountState::SWITCHED) {
            mockSubscriber_->OnStateChangedWithDisplayId(data.state, data.fromId, data.toId, data.displayId);
        } else {
            mockSubscriber_->OnStateChanged(data.state, data.fromId, data.toId);
        }
    }
    if (data.callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr");
        return;
    }
    data.callback->OnComplete();
}
void TestStateLockingMachine(int32_t localId, bool isBlock, std::shared_ptr<MockSubscriber> mockSubscriber)
{
#ifdef SUPPORT_LOCK_OS_ACCOUNT
    EXPECT_CALL(*mockSubscriber,
        OnStateChanged(OsAccountState::LOCKING, localId, localId)).Times(Exactly(1));
    EXPECT_CALL(*mockSubscriber,
        OnStateChanged(OsAccountState::LOCKED, localId, localId)).Times(Exactly(1));
    sleep(1);
    if (isBlock) {
        EXPECT_EQ(OsAccountManager::PublishOsAccountLockEvent(localId, true),
            ERR_ACCOUNT_COMMON_OPERATION_TIMEOUT);
    } else {
        EXPECT_EQ(OsAccountManager::PublishOsAccountLockEvent(localId, true), ERR_OK);
    }

    EXPECT_EQ(OsAccountManager::PublishOsAccountLockEvent(localId, false), ERR_OK);
#endif
}

void TestStateMachine(bool withHandshake, bool isBlock)
{
    std::set<OsAccountState> states = { OsAccountState::STOPPING, OsAccountState::CREATED, OsAccountState::SWITCHING,
        OsAccountState::SWITCHED, OsAccountState::UNLOCKED, OsAccountState::STOPPED, OsAccountState::REMOVED,
        OsAccountState::LOCKING, OsAccountState::LOCKED };
    OsAccountSubscribeInfo subscribeInfo(states, withHandshake);
    auto mockSubscriber = std::make_shared<MockSubscriber>();
    auto subscriber = std::make_shared<TestSubscriber>(subscribeInfo, mockSubscriber, isBlock);
    EXPECT_EQ(OsAccountManager::SubscribeOsAccount(subscriber), ERR_OK);
    EXPECT_CALL(*mockSubscriber, OnStateChanged(OsAccountState::CREATED, _, _)).Times(Exactly(1));
    OsAccountInfo info;
    EXPECT_EQ(OsAccountManager::CreateOsAccount(ACCOUNT_NAME, OsAccountType::NORMAL, info), ERR_OK);
    int32_t localId = info.GetLocalId();
    int32_t currentId = -1;
    int32_t fgRet = OsAccountManager::GetForegroundOsAccountLocalId(currentId);
    if (fgRet != ERR_OK) {
        currentId = Constants::START_USER_ID;
    }

    EXPECT_CALL(*mockSubscriber, OnStateChanged(OsAccountState::SWITCHING, _, _)).Times(AtMost(TWICE));
    EXPECT_CALL(*mockSubscriber, OnStateChanged(OsAccountState::SWITCHED, _, _)).Times(AtMost(TWICE));
    EXPECT_CALL(*mockSubscriber, OnStateChanged(OsAccountState::UNLOCKED, _, _))
        .Times(AtLeast(1));
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(localId), ERR_OK);
    EXPECT_CALL(*mockSubscriber, OnStateChanged(OsAccountState::STOPPING, localId, localId)).Times(Exactly(TWICE));
    EXPECT_CALL(*mockSubscriber, OnStateChanged(OsAccountState::STOPPED, localId, localId)).Times(Exactly(TWICE));

    TestStateLockingMachine(localId, isBlock, mockSubscriber);

    EXPECT_EQ(OsAccountManager::ActivateOsAccount(Constants::START_USER_ID), ERR_OK);
    EXPECT_EQ(OsAccountManager::DeactivateOsAccount(localId), ERR_OK);
    EXPECT_CALL(*mockSubscriber, OnStateChanged(OsAccountState::REMOVED, localId, localId)).Times(Exactly(1));
    // RemoveOsAccount will Activate 100, when localId is foreground.
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(localId), ERR_OK);
    std::unique_lock<std::mutex> lock(subscriber->mutex_);
    if (!subscriber->isRemoved_) {
        subscriber->condVar_.wait(lock, [subscriber] { return subscriber->isRemoved_; });
    }
    EXPECT_EQ(OsAccountManager::UnsubscribeOsAccount(subscriber), ERR_OK);
}

/**
 * @tc.name: OsAccountSubscribeTest01
 * @tc.desc: Test subscribing OS account states with handshake mechanism (not timeout)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountSubscribeTest, OsAccountSubscribeTest01, TestSize.Level1)
{
    bool withHandshake = true;
    bool isBlock = false;
    TestStateMachine(withHandshake, isBlock);
    SUCCEED();
}

/**
 * @tc.name: OsAccountSubscribeTest02
 * @tc.desc: Test subscribing OS account states with handshake mechanism (timeout)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountSubscribeTest, OsAccountSubscribeTest02, TestSize.Level1)
{
    bool withHandshake = true;
    bool isBlock = true;
    TestStateMachine(withHandshake, isBlock);
    SUCCEED();
}

/**
 * @tc.name: OsAccountSubscribeTest03
 * @tc.desc: Test subscribing OS account states without handshake mechanism
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountSubscribeTest, OsAccountSubscribeTest03, TestSize.Level1)
{
    bool withHandshake = false;
    bool isBlock = false;
    TestStateMachine(withHandshake, isBlock);
    SUCCEED();
}

/**
 * @tc.name: OsAccountSubscribeTest04
 * @tc.desc: Test subscribe function with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountSubscribeTest, OsAccountSubscribeTest04, TestSize.Level1)
{
    std::set<OsAccountState> states = {};
    OsAccountSubscribeInfo subscribeInfo(states, false);
    auto mockSubscriber = std::make_shared<MockSubscriber>();
    auto subscriber = std::make_shared<TestSubscriber>(subscribeInfo, mockSubscriber);
    EXPECT_EQ(OsAccountManager::SubscribeOsAccount(subscriber), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    for (int32_t i = 0; i <= Constants::MAX_SUBSCRIBED_STATES_SIZE; ++i) {
        states.emplace(static_cast<OsAccountState>(i));
    }
    OsAccountSubscribeInfo subscribeInfo2(states);
    subscriber = std::make_shared<TestSubscriber>(subscribeInfo2, mockSubscriber);
    EXPECT_EQ(OsAccountManager::SubscribeOsAccount(subscriber), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    OsAccountSubscribeInfo subscribeInfo3(OsAccountState::INVALID_TYPE, "");
    subscriber = std::make_shared<TestSubscriber>(subscribeInfo3, mockSubscriber);
    EXPECT_EQ(OsAccountManager::SubscribeOsAccount(subscriber), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OsAccountSubscribeTestWithDisplayId
 * @tc.desc: Test subscribing OS account SWITCHING and SWITCHED states with displayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountSubscribeTest, OsAccountSubscribeTestWithDisplayId, TestSize.Level1)
{
    std::set<OsAccountState> states = {
        OsAccountState::SWITCHING,
        OsAccountState::SWITCHED,
        OsAccountState::CREATED,
        OsAccountState::REMOVED,
        OsAccountState::UNLOCKED
    };
    OsAccountSubscribeInfo subscribeInfo(states, false);
    auto mockSubscriber = std::make_shared<MockSubscriber>();
    auto subscriber = std::make_shared<TestDisplayIdSubscriber>(subscribeInfo, mockSubscriber);
    EXPECT_EQ(OsAccountManager::SubscribeOsAccount(subscriber), ERR_OK);

    EXPECT_CALL(*mockSubscriber, OnStateChanged(OsAccountState::CREATED, _, _)).Times(Exactly(1));
    
    OsAccountInfo info;
    EXPECT_EQ(OsAccountManager::CreateOsAccount(ACCOUNT_NAME, OsAccountType::NORMAL, info), ERR_OK);
    int32_t localId = info.GetLocalId();
    int32_t currentId = -1;
    int32_t fgRet = OsAccountManager::GetForegroundOsAccountLocalId(currentId);
    if (fgRet != ERR_OK) {
        currentId = Constants::START_USER_ID;
    }
    EXPECT_CALL(*mockSubscriber,
        OnStateChangedWithDisplayId(OsAccountState::SWITCHING, _, _, std::optional<uint64_t>(0)))
        .Times(AtMost(TWICE));
    EXPECT_CALL(*mockSubscriber,
        OnStateChangedWithDisplayId(OsAccountState::SWITCHED, _, _, std::optional<uint64_t>(0)))
        .Times(AtMost(TWICE));
    EXPECT_CALL(*mockSubscriber, OnStateChanged(OsAccountState::UNLOCKED, _, _)).Times(AtLeast(1));
    
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(localId), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(Constants::START_USER_ID), ERR_OK);
    EXPECT_CALL(*mockSubscriber, OnStateChanged(OsAccountState::REMOVED, localId, localId)).Times(Exactly(1));
    // RemoveOsAccount will Activate 100, when localId is foreground.
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(localId), ERR_OK);
    std::unique_lock<std::mutex> lock(subscriber->mutex_);
    if (!subscriber->isRemoved_) {
        subscriber->condVar_.wait(lock, [subscriber] { return subscriber->isRemoved_; });
    }
    
    EXPECT_EQ(OsAccountManager::UnsubscribeOsAccount(subscriber), ERR_OK);
    
    SUCCEED();
}

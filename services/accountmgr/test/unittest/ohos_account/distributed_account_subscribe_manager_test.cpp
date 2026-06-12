/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
#include <set>
#include "account_log_wrapper.h"
#include "distributed_account_event_service.h"
#define private public
#include "distributed_account_subscribe_manager.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing;
using namespace testing::ext;

namespace {
constexpr int32_t TEST_LOCAL_ID = 100;
constexpr int32_t TEST_DISTRIBUTED_ACCOUNT_ID = 200;
constexpr int32_t TEST_PREVIOUS_DISTRIBUTED_ACCOUNT_ID = 150;
const DistributedAccountSubProfileEventType TEST_SPACE_EVENT_TYPE = DistributedAccountSubProfileEventType::CREATED;
const DistributedAccountSubProfileEventType TEST_SPACE_EVENT_TYPE_2 = DistributedAccountSubProfileEventType::SWITCHED;
}

class DistributedAccountSubscribeManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DistributedAccountSubscribeManagerTest::SetUpTestCase()
{}

void DistributedAccountSubscribeManagerTest::TearDownTestCase()
{}

void DistributedAccountSubscribeManagerTest::SetUp()
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    std::string testCaseName = std::string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void DistributedAccountSubscribeManagerTest::TearDown()
{}

/**
 * @tc.name: SubscribeDistributedAccountSpaceEvents001
 * @tc.desc: Test SubscribeDistributedAccountSpaceEvents with valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, SubscribeDistributedAccountSpaceEvents001, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types = {TEST_SPACE_EVENT_TYPE};
    sptr<IRemoteObject> eventListener = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener, nullptr);

    ErrCode result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: SubscribeDistributedAccountSpaceEvents002
 * @tc.desc: Test SubscribeDistributedAccountSpaceEvents with multiple types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, SubscribeDistributedAccountSpaceEvents002, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types = {TEST_SPACE_EVENT_TYPE, TEST_SPACE_EVENT_TYPE_2};
    sptr<IRemoteObject> eventListener = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener, nullptr);

    ErrCode result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: SubscribeDistributedAccountSpaceEvents003
 * @tc.desc: Test SubscribeDistributedAccountSpaceEvents with nullptr listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, SubscribeDistributedAccountSpaceEvents003, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types = {TEST_SPACE_EVENT_TYPE};
    sptr<IRemoteObject> eventListener = nullptr;

    ErrCode result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SubscribeDistributedAccountSpaceEvents004
 * @tc.desc: Test SubscribeDistributedAccountSpaceEvents with empty types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, SubscribeDistributedAccountSpaceEvents004, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types;
    sptr<IRemoteObject> eventListener = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener, nullptr);

    ErrCode result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SubscribeDistributedAccountSpaceEvents005
 * @tc.desc: Test SubscribeDistributedAccountSpaceEvents duplicate subscription
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, SubscribeDistributedAccountSpaceEvents005, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types = {TEST_SPACE_EVENT_TYPE};
    sptr<IRemoteObject> eventListener = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener, nullptr);

    ErrCode result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: UnsubscribeDistributedAccountSpaceEvents001
 * @tc.desc: Test UnsubscribeDistributedAccountSpaceEvents with valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, UnsubscribeDistributedAccountSpaceEvents001, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types = {TEST_SPACE_EVENT_TYPE};
    sptr<IRemoteObject> eventListener = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener, nullptr);

    ErrCode result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: UnsubscribeDistributedAccountSpaceEvents002
 * @tc.desc: Test UnsubscribeDistributedAccountSpaceEvents with nullptr listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, UnsubscribeDistributedAccountSpaceEvents002, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types = {TEST_SPACE_EVENT_TYPE};
    sptr<IRemoteObject> eventListener = nullptr;

    ErrCode result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: UnsubscribeDistributedAccountSpaceEvents003
 * @tc.desc: Test UnsubscribeDistributedAccountSpaceEvents with empty types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, UnsubscribeDistributedAccountSpaceEvents003, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types;
    sptr<IRemoteObject> eventListener = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener, nullptr);

    ErrCode result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: UnsubscribeDistributedAccountSpaceEvents004
 * @tc.desc: Test UnsubscribeDistributedAccountSpaceEvents with non-existent listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, UnsubscribeDistributedAccountSpaceEvents004, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types = {TEST_SPACE_EVENT_TYPE};
    sptr<IRemoteObject> eventListener = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener, nullptr);

    ErrCode result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_OHOSACCOUNT_KIT_NO_SPECIFIED_CALLBACK_HAS_BEEN_REGISTERED);
}

/**
 * @tc.name: UnsubscribeDistributedAccountSpaceEvents005
 * @tc.desc: Test UnsubscribeDistributedAccountSpaceEvents partial unsubscribe
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, UnsubscribeDistributedAccountSpaceEvents005, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types = {TEST_SPACE_EVENT_TYPE, TEST_SPACE_EVENT_TYPE_2};
    sptr<IRemoteObject> eventListener = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener, nullptr);

    ErrCode result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_OK);

    std::set<DistributedAccountSubProfileEventType> partialTypes = {TEST_SPACE_EVENT_TYPE};
    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        partialTypes, eventListener);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        {TEST_SPACE_EVENT_TYPE_2}, eventListener);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: PublishSpaceEvent001
 * @tc.desc: Test Publish space event with valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, PublishSpaceEvent001, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types = {TEST_SPACE_EVENT_TYPE};
    sptr<IRemoteObject> eventListener = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener, nullptr);
    sptr<IRemoteObject> eventListener2 = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener2, nullptr);
    ErrCode result = DistributedAccountSubscribeManager::GetInstance().Publish(
        TEST_SPACE_EVENT_TYPE, TEST_LOCAL_ID, TEST_DISTRIBUTED_ACCOUNT_ID, TEST_PREVIOUS_DISTRIBUTED_ACCOUNT_ID);
    EXPECT_EQ(result, ERR_OK);
    result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_OK);
    result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        types, eventListener2);
    EXPECT_EQ(result, ERR_OK);
    result = DistributedAccountSubscribeManager::GetInstance().Publish(
        TEST_SPACE_EVENT_TYPE, TEST_LOCAL_ID, TEST_DISTRIBUTED_ACCOUNT_ID, TEST_PREVIOUS_DISTRIBUTED_ACCOUNT_ID);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        types, eventListener);
    EXPECT_EQ(result, ERR_OK);
    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        types, eventListener2);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: PublishSpaceEvent003
 * @tc.desc: Test Publish space event to multiple subscribers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, PublishSpaceEvent003, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types = {TEST_SPACE_EVENT_TYPE, TEST_SPACE_EVENT_TYPE_2};
    std::set<DistributedAccountSubProfileEventType> types2 = {TEST_SPACE_EVENT_TYPE_2};
    sptr<IRemoteObject> eventListener1 = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener1, nullptr);
    sptr<IRemoteObject> eventListener2 = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener2, nullptr);
    sptr<IRemoteObject> eventListener3 = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener3, nullptr);
    auto subscribeRecordPtr = std::make_shared<DistributedSubscribeRecord>(eventListener1, 100, false);
    subscribeRecordPtr->AddSpaceTypes(types);
    auto subscribeRecordPtr2 = std::make_shared<DistributedSubscribeRecord>(eventListener2, 101, false);
    subscribeRecordPtr2->AddSpaceTypes(types);
    auto subscribeRecordPtr3 = std::make_shared<DistributedSubscribeRecord>(eventListener3, 1, false);
    subscribeRecordPtr3->AddSpaceTypes(types);
    auto subscribeRecordPtr4 = std::make_shared<DistributedSubscribeRecord>(eventListener3, 101, false);
    subscribeRecordPtr4->AddSpaceTypes(types2);

    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.emplace_back(subscribeRecordPtr);
    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.emplace_back(subscribeRecordPtr2);
    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.emplace_back(subscribeRecordPtr3);
    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.emplace_back(subscribeRecordPtr4);
    auto vec = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(TEST_SPACE_EVENT_TYPE, 100);
    auto vec2 = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(TEST_SPACE_EVENT_TYPE_2, 101);

    EXPECT_EQ(vec.size(), 1);
    EXPECT_EQ(vec2.size(), 2);
    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.clear();
}

/**
 * @tc.name: PublishSpaceEvent004
 * @tc.desc: Test Publish space event with different event types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, PublishSpaceEvent004, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types1 = {TEST_SPACE_EVENT_TYPE};
    std::set<DistributedAccountSubProfileEventType> types2 = {TEST_SPACE_EVENT_TYPE_2};
    sptr<IRemoteObject> eventListener1 = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener1, nullptr);
    sptr<IRemoteObject> eventListener2 = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener2, nullptr);

    ErrCode result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        types1, eventListener1);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        types2, eventListener2);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().Publish(
        TEST_SPACE_EVENT_TYPE, TEST_LOCAL_ID, TEST_DISTRIBUTED_ACCOUNT_ID, TEST_PREVIOUS_DISTRIBUTED_ACCOUNT_ID);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().Publish(
        TEST_SPACE_EVENT_TYPE_2, TEST_LOCAL_ID, TEST_DISTRIBUTED_ACCOUNT_ID, TEST_PREVIOUS_DISTRIBUTED_ACCOUNT_ID);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        types1, eventListener1);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        types2, eventListener2);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: MixedSubscribeTest001
 * @tc.desc: Test subscribe both space events and distributed account events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, MixedSubscribeTest001, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> spaceTypes = {TEST_SPACE_EVENT_TYPE};
    sptr<IRemoteObject> eventListener = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener, nullptr);

    ErrCode result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        spaceTypes, eventListener);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, eventListener);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        spaceTypes, eventListener);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, eventListener);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: MixedSubscribeTest002
 * @tc.desc: Test unsubscribe space events when distributed account events still subscribed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, MixedSubscribeTest002, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> spaceTypes = {TEST_SPACE_EVENT_TYPE};
    sptr<IRemoteObject> eventListener = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener, nullptr);

    ErrCode result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        spaceTypes, eventListener);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, eventListener);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        spaceTypes, eventListener);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, eventListener);
    EXPECT_EQ(result, ERR_OK);
    auto temp = DistributedAccountSubscribeManager::GetInstance().subscribeDeathRecipient_;
    DistributedAccountSubscribeManager::GetInstance().subscribeDeathRecipient_ = nullptr;
    sptr<IRemoteObject> eventListener2 = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener2, nullptr);
    result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        spaceTypes, eventListener2);
    EXPECT_EQ(result, ERR_OK);
    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        spaceTypes, eventListener2);
    EXPECT_EQ(result, ERR_OK);
    DistributedAccountSubscribeManager::GetInstance().subscribeDeathRecipient_ = temp;
}

/**
 * @tc.name: OnAccountsChanged001
 * @tc.desc: Test unsubscribe space events when distributed account events still subscribed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, OnAccountsChanged001, TestSize.Level1)
{
    bool result = DistributedAccountSubscribeManager::GetInstance().OnAccountsChanged(nullptr,
        100, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, -1);
    EXPECT_EQ(result, false);
    DistributedAccountSubProfileEventData data;
    result = DistributedAccountSubscribeManager::GetInstance().OnSubProfileAccountsChanged(nullptr, data);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: OnSpaceAccountsChanged001
 * @tc.desc: Test OnSubProfileAccountsChanged with valid eventProxy returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, OnSpaceAccountsChanged001, TestSize.Level1)
{
    sptr<IRemoteObject> eventListener = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener, nullptr);
    auto eventProxy = iface_cast<IDistributedAccountEvent>(eventListener);
    ASSERT_NE(eventProxy, nullptr);

    DistributedAccountSubProfileEventData eventData;
    eventData.type_ = TEST_SPACE_EVENT_TYPE;
    eventData.osAccountId_ = TEST_LOCAL_ID;
    eventData.subspaceId_ = TEST_DISTRIBUTED_ACCOUNT_ID;
    eventData.previousSubspaceId_ = TEST_PREVIOUS_DISTRIBUTED_ACCOUNT_ID;

    bool result = DistributedAccountSubscribeManager::GetInstance().OnSubProfileAccountsChanged(eventProxy, eventData);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: OnSpaceAccountsChanged002
 * @tc.desc: Test OnSubProfileAccountsChanged with nullptr eventProxy returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, OnSpaceAccountsChanged002, TestSize.Level1)
{
    DistributedAccountSubProfileEventData eventData;
    eventData.type_ = TEST_SPACE_EVENT_TYPE;
    eventData.osAccountId_ = TEST_LOCAL_ID;

    bool result = DistributedAccountSubscribeManager::GetInstance().OnSubProfileAccountsChanged(nullptr, eventData);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: GetSubscribersToNotify_EventTypeNotFound001
 * @tc.desc: Test GetSubscribersToNotify when eventType not in spaceTypes_, subscriber should be skipped
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, GetSubscribersToNotify_EventTypeNotFound001, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types = {TEST_SPACE_EVENT_TYPE};
    sptr<IRemoteObject> eventListener = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener, nullptr);

    auto subscribeRecordPtr = std::make_shared<DistributedSubscribeRecord>(eventListener, 100, true);
    subscribeRecordPtr->AddSpaceTypes(types);
    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.emplace_back(subscribeRecordPtr);

    auto vec = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(TEST_SPACE_EVENT_TYPE, 100);
    EXPECT_EQ(vec.size(), 1);

    vec = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(TEST_SPACE_EVENT_TYPE_2, 100);
    EXPECT_EQ(vec.size(), 0);

    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.clear();
}

/**
 * @tc.name: GetSubscribersToNotify_EventTypeNotFound002
 * @tc.desc: Test GetSubscribersToNotify with multiple subscribers, some have eventType, some don't
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, GetSubscribersToNotify_EventTypeNotFound002, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types1 = {TEST_SPACE_EVENT_TYPE};
    std::set<DistributedAccountSubProfileEventType> types2 = {TEST_SPACE_EVENT_TYPE_2};
    sptr<IRemoteObject> eventListener1 = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener1, nullptr);
    sptr<IRemoteObject> eventListener2 = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener2, nullptr);

    auto subscribeRecordPtr1 = std::make_shared<DistributedSubscribeRecord>(eventListener1, 100, true);
    subscribeRecordPtr1->AddSpaceTypes(types1);
    auto subscribeRecordPtr2 = std::make_shared<DistributedSubscribeRecord>(eventListener2, 100, true);
    subscribeRecordPtr2->AddSpaceTypes(types2);

    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.emplace_back(subscribeRecordPtr1);
    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.emplace_back(subscribeRecordPtr2);

    auto vec = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(TEST_SPACE_EVENT_TYPE, 100);
    EXPECT_EQ(vec.size(), 1);

    vec = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(TEST_SPACE_EVENT_TYPE_2, 100);
    EXPECT_EQ(vec.size(), 1);

    vec = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(
        DistributedAccountSubProfileEventType::DELETED, 100);
    EXPECT_EQ(vec.size(), 0);

    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.clear();
}

/**
 * @tc.name: GetSubscribersToNotify_SaCall001
 * @tc.desc: Test GetSubscribersToNotify with isSaCall_=true, should notify for any user's events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, GetSubscribersToNotify_SaCall001, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types = {TEST_SPACE_EVENT_TYPE};
    sptr<IRemoteObject> eventListener = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener, nullptr);

    auto subscribeRecordPtr = std::make_shared<DistributedSubscribeRecord>(eventListener, 100, true);
    subscribeRecordPtr->AddSpaceTypes(types);
    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.emplace_back(subscribeRecordPtr);

    auto vec = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(TEST_SPACE_EVENT_TYPE, 100);
    EXPECT_EQ(vec.size(), 1);

    vec = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(TEST_SPACE_EVENT_TYPE, 200);
    EXPECT_EQ(vec.size(), 1);

    vec = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(TEST_SPACE_EVENT_TYPE, 300);
    EXPECT_EQ(vec.size(), 1);

    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.clear();
}

/**
 * @tc.name: GetSubscribersToNotify_AppCall001
 * @tc.desc: Test GetSubscribersToNotify with isSaCall_=false, only notify for same user's events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, GetSubscribersToNotify_AppCall001, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types = {TEST_SPACE_EVENT_TYPE};
    sptr<IRemoteObject> eventListener = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener, nullptr);

    auto subscribeRecordPtr = std::make_shared<DistributedSubscribeRecord>(eventListener, 100, false);
    subscribeRecordPtr->AddSpaceTypes(types);
    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.emplace_back(subscribeRecordPtr);

    auto vec = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(TEST_SPACE_EVENT_TYPE, 100);
    EXPECT_EQ(vec.size(), 1);

    vec = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(TEST_SPACE_EVENT_TYPE, 200);
    EXPECT_EQ(vec.size(), 0);

    vec = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(TEST_SPACE_EVENT_TYPE, 300);
    EXPECT_EQ(vec.size(), 0);

    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.clear();
}

/**
 * @tc.name: GetSubscribersToNotify_MixedCall001
 * @tc.desc: Test GetSubscribersToNotify with mixed SA and App callers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, GetSubscribersToNotify_MixedCall001, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types = {TEST_SPACE_EVENT_TYPE};
    sptr<IRemoteObject> eventListener1 = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener1, nullptr);
    sptr<IRemoteObject> eventListener2 = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener2, nullptr);
    sptr<IRemoteObject> eventListener3 = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener3, nullptr);

    auto saRecord = std::make_shared<DistributedSubscribeRecord>(eventListener1, 100, true);
    saRecord->AddSpaceTypes(types);
    auto appRecord1 = std::make_shared<DistributedSubscribeRecord>(eventListener2, 100, false);
    appRecord1->AddSpaceTypes(types);
    auto appRecord2 = std::make_shared<DistributedSubscribeRecord>(eventListener3, 200, false);
    appRecord2->AddSpaceTypes(types);

    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.emplace_back(saRecord);
    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.emplace_back(appRecord1);
    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.emplace_back(appRecord2);

    auto vec = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(TEST_SPACE_EVENT_TYPE, 100);
    EXPECT_EQ(vec.size(), 2);

    vec = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(TEST_SPACE_EVENT_TYPE, 200);
    EXPECT_EQ(vec.size(), 2);

    vec = DistributedAccountSubscribeManager::GetInstance().GetSubscribersToNotify(TEST_SPACE_EVENT_TYPE, 300);
    EXPECT_EQ(vec.size(), 1);

    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.clear();
}

/**
 * @tc.name: PublishSpaceEvent_IterateSubscribers001
 * @tc.desc: Test Publish iterates through all subscribers and sends notifications
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedAccountSubscribeManagerTest, PublishSpaceEvent_IterateSubscribers001, TestSize.Level1)
{
    std::set<DistributedAccountSubProfileEventType> types = {TEST_SPACE_EVENT_TYPE};
    sptr<IRemoteObject> eventListener1 = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener1, nullptr);
    sptr<IRemoteObject> eventListener2 = new (std::nothrow) DistributedAccountEventService();
    ASSERT_NE(eventListener2, nullptr);

    ErrCode result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        types, eventListener1);
    EXPECT_EQ(result, ERR_OK);
    result = DistributedAccountSubscribeManager::GetInstance().SubscribeDistributedAccountSpaceEvents(
        types, eventListener2);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().Publish(
        TEST_SPACE_EVENT_TYPE, TEST_LOCAL_ID, TEST_DISTRIBUTED_ACCOUNT_ID, TEST_PREVIOUS_DISTRIBUTED_ACCOUNT_ID);
    EXPECT_EQ(result, ERR_OK);

    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        types, eventListener1);
    EXPECT_EQ(result, ERR_OK);
    result = DistributedAccountSubscribeManager::GetInstance().UnsubscribeDistributedAccountSpaceEvents(
        types, eventListener2);
    EXPECT_EQ(result, ERR_OK);
}
}  // namespace AccountSA
}  // namespace OHOS
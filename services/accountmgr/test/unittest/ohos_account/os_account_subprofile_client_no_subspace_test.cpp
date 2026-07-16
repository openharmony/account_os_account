/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

#include <gtest/gtest.h>
#include <set>
#include <memory>
#include <future>
#include <vector>

#define private public
#include "os_account_subprofile_client.h"
#undef private

#define private public
#include "os_account_sub_profile_event_service.h"
#undef private

#define private public
#include "os_account_info.h"
#undef private

#include "account_error_no.h"
#include "account_info.h"
#include "account_test_common.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "os_account_sub_profile_subscribe_callback.h"
#include "os_account_sub_profile_stub.h"
#include "os_account_subspace_manager_service.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
constexpr int32_t TEST_OS_ACCOUNT_ID = 100;
constexpr int32_t TEST_SUBSPACE_ID = 100001;
constexpr int32_t HEADLESS_SUBSPACE_ID = 100 * 1000;
constexpr int32_t TEST_SUBSPACE_BASE = TEST_OS_ACCOUNT_ID * 1000;
constexpr ErrCode ERR_EXPECTED_FAILURE = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
} // namespace

class OsAccountSubProfileClientNoSubspaceTest : public testing::Test {
public:
    void SetUp() override
    {
        OsAccountSubProfileClient::GetInstance().proxy_ = nullptr;
        OsAccountSubProfileClient::GetInstance().deathRecipient_ = nullptr;
    }
    void TearDown() override
    {
        OsAccountSubProfileClient::GetInstance().proxy_ = nullptr;
        OsAccountSubProfileClient::GetInstance().deathRecipient_ = nullptr;
        auto *eventSvc = OsAccountSubProfileEventService::GetInstance();
        eventSvc->callbackMap_.clear();
        eventSvc->typeMap_.clear();
    }
};

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_GetInstance_Singleton_001
 * @tc.desc: GetInstance returns the same instance on multiple calls.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, GetInstance_Singleton_001, TestSize.Level1)
{
    OsAccountSubProfileClient &instance1 = OsAccountSubProfileClient::GetInstance();
    OsAccountSubProfileClient &instance2 = OsAccountSubProfileClient::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_Create_Fails_Without_Macro
 * @tc.desc: CreateOsAccountSubProfile returns ERR_OS_ACCOUNT_SUBSPACE_LIMIT
 *           when ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE is not defined.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, Create_Fails_Without_Macro, TestSize.Level1)
{
    OsAccountSubspaceResult result;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().CreateOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, result);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_LIMIT);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_Delete_Headless_Fails
 * @tc.desc: DeleteOsAccountSubProfile returns ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED
 *           for the headless subspace (index=0) regardless of the macro.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, Delete_Headless_Fails, TestSize.Level1)
{
    ErrCode ret = OsAccountSubProfileClient::GetInstance().DeleteOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, HEADLESS_SUBSPACE_ID);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_Delete_NonHeadless_Fails
 * @tc.desc: DeleteOsAccountSubProfile returns ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED
 *           for a non-headless subspace when ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
 *           is not defined.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, Delete_NonHeadless_Fails, TestSize.Level1)
{
    ErrCode ret = OsAccountSubProfileClient::GetInstance().DeleteOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_ID);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_Switch_Headless_Fails
 * @tc.desc: SwitchOsAccountSubProfile returns ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED
 *           when trying to switch to the headless subspace.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, Switch_Headless_Fails, TestSize.Level1)
{
    ErrCode ret = OsAccountSubProfileClient::GetInstance().SwitchOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, HEADLESS_SUBSPACE_ID);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_Switch_NonHeadless_Fails
 * @tc.desc: SwitchOsAccountSubProfile returns ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND
 *           for a non-headless subspace when ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
 *           is not defined.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, Switch_NonHeadless_Fails, TestSize.Level1)
{
    ErrCode ret = OsAccountSubProfileClient::GetInstance().SwitchOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_ID);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

// ===== Subscribe/Unsubscribe tests (common paths) =====
class TestSubscribeCallback : public OsAccountSubProfileSubscribeCallback {
public:
    void OnSubProfileChanged(const SubProfileEventData &eventData) override {}
};

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_Subscribe_NullCallback_ReturnsError
 * @tc.desc: SubscribeOsAccountSubProfileEvents returns INVALID_PARAMETER when callback is null.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, Subscribe_NullCallback_ReturnsError, TestSize.Level1)
{
    std::set<OsAccountSubProfileEventType> types = {OsAccountSubProfileEventType::CREATED};

    ErrCode ret = OsAccountSubProfileClient::GetInstance().SubscribeOsAccountSubProfileEvents(types, nullptr);

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_Subscribe_EmptyTypes_ReturnsError
 * @tc.desc: SubscribeOsAccountSubProfileEvents returns INVALID_PARAMETER when types set is empty.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, Subscribe_EmptyTypes_ReturnsError, TestSize.Level1)
{
    auto callback = std::make_shared<TestSubscribeCallback>();
    ASSERT_NE(callback, nullptr);
    std::set<OsAccountSubProfileEventType> emptyTypes;

    ErrCode ret = OsAccountSubProfileClient::GetInstance().SubscribeOsAccountSubProfileEvents(emptyTypes, callback);

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_Unsubscribe_NullCallback_ReturnsError
 * @tc.desc: UnsubscribeOsAccountSubProfileEvents returns NULL_PTR_ERROR when callback is null.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, Unsubscribe_NullCallback_ReturnsError, TestSize.Level1)
{
    ErrCode ret = OsAccountSubProfileClient::GetInstance().UnsubscribeOsAccountSubProfileEvents(nullptr);

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

// ===== OsAccountSubProfileEventService tests =====
class EventServiceCallback : public OsAccountSubProfileSubscribeCallback {
public:
    void OnSubProfileChanged(const SubProfileEventData &eventData) override
    {
        type_ = eventData.type_;
        promise_->set_value();
    }
    std::shared_ptr<std::promise<void>> promise_ = std::make_shared<std::promise<void>>();
    OsAccountSubProfileEventType type_ = OsAccountSubProfileEventType::INVALID_TYPE;
};

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_GetInstance_Singleton
 * @tc.desc: GetInstance returns the same pointer on multiple calls (singleton).
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_GetInstance_Singleton, TestSize.Level1)
{
    auto *svc1 = OsAccountSubProfileEventService::GetInstance();
    auto *svc2 = OsAccountSubProfileEventService::GetInstance();
    EXPECT_EQ(svc1, svc2);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_GetCallbackSize_InitiallyZero
 * @tc.desc: GetCallbackSize returns 0 when no callbacks are registered.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_GetCallbackSize_InitiallyZero, TestSize.Level1)
{
    EXPECT_EQ(OsAccountSubProfileEventService::GetInstance()->GetCallbackSize(), 0);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_AddTypes_IncreasesCallbackSize
 * @tc.desc: AddTypes with a valid callback increases the callback count.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_AddTypes_IncreasesCallbackSize, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb = std::make_shared<EventServiceCallback>();

    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb);
    EXPECT_EQ(svc->GetCallbackSize(), 1);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_AddTypes_NullCallback_NoChange
 * @tc.desc: AddTypes with null callback does not change the callback count.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_AddTypes_NullCallback_NoChange, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    EXPECT_EQ(svc->GetCallbackSize(), 0);

    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, nullptr);
    EXPECT_EQ(svc->GetCallbackSize(), 0);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_AddTypes_EmptyTypes_NoChange
 * @tc.desc: AddTypes with empty types set does not change the callback count.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_AddTypes_EmptyTypes_NoChange, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb = std::make_shared<EventServiceCallback>();

    svc->AddTypes({}, cb);
    EXPECT_EQ(svc->GetCallbackSize(), 0);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_DeleteCallback_RemovesEntry
 * @tc.desc: DeleteCallback removes the entry and decreases the callback count.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_DeleteCallback_RemovesEntry, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb = std::make_shared<EventServiceCallback>();

    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb);
    EXPECT_EQ(svc->GetCallbackSize(), 1);

    svc->DeleteCallback(cb);
    EXPECT_EQ(svc->GetCallbackSize(), 0);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_DeleteCallback_NullCallback_NoChange
 * @tc.desc: DeleteCallback with null callback does not change the callback count.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_DeleteCallback_NullCallback_NoChange, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb = std::make_shared<EventServiceCallback>();

    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb);
    EXPECT_EQ(svc->GetCallbackSize(), 1);

    svc->DeleteCallback(nullptr);
    EXPECT_EQ(svc->GetCallbackSize(), 1);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_DeleteCallback_UnknownCallback_NoChange
 * @tc.desc: DeleteCallback with an unregistered callback does not change the callback count.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_DeleteCallback_UnknownCallback_NoChange, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb1 = std::make_shared<EventServiceCallback>();
    auto cb2 = std::make_shared<EventServiceCallback>();

    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb1);
    EXPECT_EQ(svc->GetCallbackSize(), 1);

    svc->DeleteCallback(cb2);
    EXPECT_EQ(svc->GetCallbackSize(), 1);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_IsAllTypeExist_NullCallback
 * @tc.desc: IsAllTypeExist returns false when callback is null.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_IsAllTypeExist_NullCallback, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    EXPECT_FALSE(svc->IsAllTypeExist({OsAccountSubProfileEventType::CREATED}, nullptr));
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_IsAllTypeExist_EmptyTypes
 * @tc.desc: IsAllTypeExist returns false when types set is empty.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_IsAllTypeExist_EmptyTypes, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb = std::make_shared<EventServiceCallback>();
    EXPECT_FALSE(svc->IsAllTypeExist({}, cb));
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_IsAllTypeExist_AllTypesPresent
 * @tc.desc: IsAllTypeExist returns true when the callback has all specified types registered.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_IsAllTypeExist_AllTypesPresent, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb = std::make_shared<EventServiceCallback>();
    std::set<OsAccountSubProfileEventType> types = {
        OsAccountSubProfileEventType::CREATED,
        OsAccountSubProfileEventType::DELETED,
    };
    svc->AddTypes(types, cb);
    EXPECT_TRUE(svc->IsAllTypeExist(types, cb));
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_IsAllTypeExist_SomeTypesMissing
 * @tc.desc: IsAllTypeExist returns false when the callback is missing some of the specified types.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_IsAllTypeExist_SomeTypesMissing, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb = std::make_shared<EventServiceCallback>();

    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb);
    EXPECT_FALSE(svc->IsAllTypeExist(
        {OsAccountSubProfileEventType::CREATED, OsAccountSubProfileEventType::DELETED}, cb));
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_IsAllTypeExist_UnknownCallback
 * @tc.desc: IsAllTypeExist returns false when the callback is not registered.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_IsAllTypeExist_UnknownCallback, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb1 = std::make_shared<EventServiceCallback>();
    auto cb2 = std::make_shared<EventServiceCallback>();

    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb1);
    EXPECT_FALSE(svc->IsAllTypeExist({OsAccountSubProfileEventType::CREATED}, cb2));
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_GetTypesToRemove_NullCallback
 * @tc.desc: GetTypesToRemove returns empty set when callback is null.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_GetTypesToRemove_NullCallback, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    std::set<OsAccountSubProfileEventType> removed;
    svc->GetTypesToRemove(nullptr, removed);
    EXPECT_TRUE(removed.empty());
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_GetTypesToRemove_UnknownCallback
 * @tc.desc: GetTypesToRemove returns empty set when the callback is not registered.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_GetTypesToRemove_UnknownCallback, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb1 = std::make_shared<EventServiceCallback>();
    auto cb2 = std::make_shared<EventServiceCallback>();

    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb1);
    std::set<OsAccountSubProfileEventType> removed;
    svc->GetTypesToRemove(cb2, removed);
    EXPECT_TRUE(removed.empty());
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_GetTypesToRemove_LastCallbackForType
 * @tc.desc: GetTypesToRemove includes the type when this callback is the only subscriber for that type.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_GetTypesToRemove_LastCallbackForType, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb = std::make_shared<EventServiceCallback>();

    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb);
    std::set<OsAccountSubProfileEventType> removed;
    svc->GetTypesToRemove(cb, removed);
    EXPECT_EQ(removed.size(), 1);
    EXPECT_TRUE(removed.count(OsAccountSubProfileEventType::CREATED) > 0);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_GetTypesToRemove_MultipleCallbacks
 * @tc.desc: GetTypesToRemove excludes the type when multiple callbacks subscribe to the same type.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_GetTypesToRemove_MultipleCallbacks, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb1 = std::make_shared<EventServiceCallback>();
    auto cb2 = std::make_shared<EventServiceCallback>();

    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb1);
    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb2);
    std::set<OsAccountSubProfileEventType> removed;
    svc->GetTypesToRemove(cb1, removed);
    EXPECT_TRUE(removed.empty());
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_GetAllType_InitiallyEmpty
 * @tc.desc: GetAllType returns empty set when no types are registered.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_GetAllType_InitiallyEmpty, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    std::set<OsAccountSubProfileEventType> types;
    svc->GetAllType(types);
    EXPECT_TRUE(types.empty());
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_GetAllType_AfterAdd
 * @tc.desc: GetAllType returns the types that have been registered via AddTypes.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_GetAllType_AfterAdd, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb = std::make_shared<EventServiceCallback>();

    svc->AddTypes({OsAccountSubProfileEventType::CREATED, OsAccountSubProfileEventType::SWITCHED}, cb);
    std::set<OsAccountSubProfileEventType> types;
    svc->GetAllType(types);
    EXPECT_EQ(types.size(), 2);
    EXPECT_TRUE(types.count(OsAccountSubProfileEventType::CREATED) > 0);
    EXPECT_TRUE(types.count(OsAccountSubProfileEventType::SWITCHED) > 0);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_GetAllType_AfterDelete
 * @tc.desc: GetAllType returns empty set after the only callback for a type is deleted.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_GetAllType_AfterDelete, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb = std::make_shared<EventServiceCallback>();

    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb);
    svc->DeleteCallback(cb);
    std::set<OsAccountSubProfileEventType> types;
    svc->GetAllType(types);
    EXPECT_TRUE(types.empty());
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_OnSubProfileAccountsChanged_CallbackInvoked
 * @tc.desc: OnSubProfileChanged calls the matching callback with correct event data via detached thread.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_OnSubProfileAccountsChanged_CallbackInvoked,
    TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb = std::make_shared<EventServiceCallback>();
    auto future = cb->promise_->get_future();

    svc->AddTypes({OsAccountSubProfileEventType::SWITCHED}, cb);
    SubProfileEventData eventData;
    eventData.type_ = OsAccountSubProfileEventType::SWITCHED;
    svc->OnSubProfileChanged(eventData);

    auto status = future.wait_for(std::chrono::seconds(2));
    EXPECT_EQ(status, std::future_status::ready);
    EXPECT_EQ(cb->type_, OsAccountSubProfileEventType::SWITCHED);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_OnSubProfileAccountsChanged_NoMatchingType
 * @tc.desc: OnSubProfileChanged does not call callbacks when no callback registered for the event type.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_OnSubProfileAccountsChanged_NoMatchingType,
    TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb = std::make_shared<EventServiceCallback>();

    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb);
    SubProfileEventData eventData;
    eventData.type_ = OsAccountSubProfileEventType::DELETED;
    ErrCode ret = svc->OnSubProfileChanged(eventData);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(cb->promise_->get_future().wait_for(std::chrono::milliseconds(100)) ==
        std::future_status::ready);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_OnSubProfileAccountsChanged_MultipleCallbacks
 * @tc.desc: OnSubProfileChanged dispatches to all callbacks registered for the event type.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_OnSubProfileAccountsChanged_MultipleCallbacks,
    TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb1 = std::make_shared<EventServiceCallback>();
    auto cb2 = std::make_shared<EventServiceCallback>();
    auto future1 = cb1->promise_->get_future();
    auto future2 = cb2->promise_->get_future();

    svc->AddTypes({OsAccountSubProfileEventType::DELETED}, cb1);
    svc->AddTypes({OsAccountSubProfileEventType::DELETED}, cb2);
    SubProfileEventData eventData;
    eventData.type_ = OsAccountSubProfileEventType::DELETED;
    svc->OnSubProfileChanged(eventData);

    EXPECT_EQ(future1.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(future2.wait_for(std::chrono::seconds(2)), std::future_status::ready);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_AddTypes_MultipleCallbacksSameType
 * @tc.desc: AddTypes accepts multiple distinct callbacks for the same event type.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_AddTypes_MultipleCallbacksSameType, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb1 = std::make_shared<EventServiceCallback>();
    auto cb2 = std::make_shared<EventServiceCallback>();

    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb1);
    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb2);
    EXPECT_EQ(svc->GetCallbackSize(), 2);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_EventService_AddTypes_MergesDuplicateCallback
 * @tc.desc: AddTypes merges additional types into an existing callback entry instead of creating a duplicate.
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, EventService_AddTypes_MergesDuplicateCallback, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb = std::make_shared<EventServiceCallback>();

    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb);
    svc->AddTypes({OsAccountSubProfileEventType::DELETED}, cb);
    EXPECT_EQ(svc->GetCallbackSize(), 1);
    EXPECT_TRUE(svc->IsAllTypeExist(
        {OsAccountSubProfileEventType::CREATED, OsAccountSubProfileEventType::DELETED}, cb));
}

// ===== OsAccountInfo subspace methods =====
class OsAccountInfoSubspaceTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: OsAccountInfoSubspaceTest_GetForegroundSubspaceId_Default_001
 * @tc.desc: Test OsAccountInfo::GetForegroundSubProfileId returns default value.
 */
HWTEST_F(OsAccountInfoSubspaceTest, GetForegroundSubspaceId_Default_001, TestSize.Level1)
{
    OsAccountInfo info;
    info.localId_ = TEST_OS_ACCOUNT_ID;
    info.foregroundSubProfileId_ = -1;
    EXPECT_EQ(info.GetForegroundSubProfileId(), -1);
}

/**
 * @tc.name: OsAccountInfoSubspaceTest_GetForegroundSubspaceId_SetValue_001
 * @tc.desc: Test OsAccountInfo::GetForegroundSubProfileId returns the set value.
 */
HWTEST_F(OsAccountInfoSubspaceTest, GetForegroundSubspaceId_SetValue_001, TestSize.Level1)
{
    OsAccountInfo info;
    info.localId_ = TEST_OS_ACCOUNT_ID;
    int32_t expectedId = TEST_SUBSPACE_BASE + 5;
    info.SetForegroundSubProfileId(expectedId);
    EXPECT_EQ(info.GetForegroundSubProfileId(), expectedId);
}

/**
 * @tc.name: OsAccountInfoSubspaceTest_GetForegroundSubspaceId_SetToBase_001
 * @tc.desc: Test OsAccountInfo::GetForegroundSubProfileId returns the base subspace id.
 */
HWTEST_F(OsAccountInfoSubspaceTest, GetForegroundSubspaceId_SetToBase_001, TestSize.Level1)
{
    OsAccountInfo info;
    info.localId_ = TEST_OS_ACCOUNT_ID;
    info.SetForegroundSubProfileId(TEST_SUBSPACE_BASE);
    EXPECT_EQ(info.GetForegroundSubProfileId(), TEST_SUBSPACE_BASE);
}

/**
 * @tc.name: OsAccountInfoSubspaceTest_SetForegroundSubspaceId_Negative_001
 * @tc.desc: Test OsAccountInfo::SetForegroundSubProfileId accepts negative value.
 */
HWTEST_F(OsAccountInfoSubspaceTest, SetForegroundSubspaceId_Negative_001, TestSize.Level1)
{
    OsAccountInfo info;
    info.localId_ = TEST_OS_ACCOUNT_ID;
    info.SetForegroundSubProfileId(-1);
    EXPECT_EQ(info.GetForegroundSubProfileId(), -1);
}

// ===== OsAccountSubspaceResult Marshalling =====
class SubspaceResultMarshallingTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: SubspaceResultMarshallingTest_Marshalling_Success_001
 * @tc.desc: Test OsAccountSubspaceResult::Marshalling writes data to parcel.
 */
HWTEST_F(SubspaceResultMarshallingTest, Marshalling_Success_001, TestSize.Level1)
{
    OsAccountSubspaceResult result;
    result.id = TEST_SUBSPACE_BASE + 1;
    result.osAccountId = TEST_OS_ACCOUNT_ID;
    result.index = 1;

    Parcel parcel;
    EXPECT_TRUE(result.Marshalling(parcel));

    EXPECT_TRUE(parcel.ReadInt32());
    EXPECT_TRUE(parcel.ReadInt32());
    EXPECT_TRUE(parcel.ReadInt32());
}

/**
 * @tc.name: SubspaceResultMarshallingTest_Unmarshalling_Success_001
 * @tc.desc: Test OsAccountSubspaceResult::Unmarshalling restores data from parcel.
 */
HWTEST_F(SubspaceResultMarshallingTest, Unmarshalling_Success_001, TestSize.Level1)
{
    OsAccountSubspaceResult original;
    original.id = TEST_SUBSPACE_BASE + 2;
    original.osAccountId = TEST_OS_ACCOUNT_ID;
    original.index = 2;

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    OsAccountSubspaceResult *unmarshalled = OsAccountSubspaceResult::Unmarshalling(parcel);
    ASSERT_NE(unmarshalled, nullptr);
    EXPECT_EQ(unmarshalled->id, original.id);
    EXPECT_EQ(unmarshalled->osAccountId, original.osAccountId);
    EXPECT_EQ(unmarshalled->index, original.index);
    delete unmarshalled;
}

/**
 * @tc.name: SubspaceResultMarshallingTest_Unmarshalling_EmptyParcel_001
 * @tc.desc: Test OsAccountSubspaceResult::Unmarshalling returns nullptr for empty parcel.
 */
HWTEST_F(SubspaceResultMarshallingTest, Unmarshalling_EmptyParcel_001, TestSize.Level1)
{
    Parcel emptyParcel;
    OsAccountSubspaceResult *result = OsAccountSubspaceResult::Unmarshalling(emptyParcel);
    EXPECT_EQ(result, nullptr);
}

// ===== SubProfileEventData ReadFromParcel coverage =====
class SubProfileEventDataReadTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: SubProfileEventDataReadTest_InvalidType_001
 * @tc.desc: ReadFromParcel returns false when event type is invalid (line 68).
 */
HWTEST_F(SubProfileEventDataReadTest, InvalidType_001, TestSize.Level1)
{
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(OsAccountSubProfileEventType::INVALID_TYPE));
    SubProfileEventData *data = SubProfileEventData::Unmarshalling(parcel);
    EXPECT_EQ(data, nullptr);
}

/**
 * @tc.name: SubProfileEventDataReadTest_MissingOsAccountId_001
 * @tc.desc: ReadFromParcel returns false when ReadInt32(osAccountId_) fails (line 73).
 */
HWTEST_F(SubProfileEventDataReadTest, MissingOsAccountId_001, TestSize.Level1)
{
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(OsAccountSubProfileEventType::CREATED));
    SubProfileEventData *data = SubProfileEventData::Unmarshalling(parcel);
    EXPECT_EQ(data, nullptr);
}

/**
 * @tc.name: SubProfileEventDataReadTest_MissingSubProfileId_001
 * @tc.desc: ReadFromParcel returns false when ReadInt32(subProfileId_) fails (line 77).
 */
HWTEST_F(SubProfileEventDataReadTest, MissingSubProfileId_001, TestSize.Level1)
{
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(OsAccountSubProfileEventType::CREATED));
    parcel.WriteInt32(TEST_OS_ACCOUNT_ID);
    SubProfileEventData *data = SubProfileEventData::Unmarshalling(parcel);
    EXPECT_EQ(data, nullptr);
}

/**
 * @tc.name: SubProfileEventDataReadTest_MissingPreviousSubProfileId_001
 * @tc.desc: ReadFromParcel returns false when ReadInt32(previousSubProfileId_) fails (line 81).
 */
HWTEST_F(SubProfileEventDataReadTest, MissingPreviousSubProfileId_001, TestSize.Level1)
{
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(OsAccountSubProfileEventType::CREATED));
    parcel.WriteInt32(TEST_OS_ACCOUNT_ID);
    parcel.WriteInt32(TEST_SUBSPACE_BASE + 1);
    SubProfileEventData *data = SubProfileEventData::Unmarshalling(parcel);
    EXPECT_EQ(data, nullptr);
}

/**
 * @tc.name: SubProfileEventDataReadTest_SuccessRoundTrip_001
 * @tc.desc: Marshalling + Unmarshalling round-trip succeeds with valid data (covers success path).
 */
HWTEST_F(SubProfileEventDataReadTest, SuccessRoundTrip_001, TestSize.Level1)
{
    SubProfileEventData original;
    original.type_ = OsAccountSubProfileEventType::SWITCHED;
    original.osAccountId_ = TEST_OS_ACCOUNT_ID;
    original.subProfileId_ = TEST_SUBSPACE_BASE + 5;
    original.previousSubProfileId_ = TEST_SUBSPACE_BASE + 2;

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    SubProfileEventData *unmarshalled = SubProfileEventData::Unmarshalling(parcel);
    ASSERT_NE(unmarshalled, nullptr);
    EXPECT_TRUE(*unmarshalled == original);
    delete unmarshalled;
}

// ===== Subscribe/Unsubscribe proxy paths (lines 262, 267, 312 in os_account_subprofile_client.cpp) =====
class MockSubProfileStub : public OsAccountSubProfileStub {
public:
    ErrCode CreateOsAccountSubProfile(
        int32_t osAccountId, OsAccountSubspaceResult &subspaceResult) override
    {
        return ERR_OK;
    }
    ErrCode DeleteOsAccountSubProfile(
        int32_t osAccountId, int32_t subspaceId) override
    {
        return ERR_OK;
    }
    ErrCode SwitchOsAccountSubProfile(
        int32_t osAccountId, int32_t subspaceId) override
    {
        return ERR_OK;
    }
    ErrCode SubscribeOsAccountSubProfileEvents(
        const std::vector<int32_t> &types,
        const sptr<IRemoteObject> &eventListener) override
    {
        return subscribeRet_;
    }
    ErrCode UnsubscribeOsAccountSubProfileEvents(
        const std::vector<int32_t> &types,
        const sptr<IRemoteObject> &eventListener) override
    {
        return unsubscribeRet_;
    }
    ErrCode subscribeRet_ = ERR_OK;
    ErrCode unsubscribeRet_ = ERR_OK;
};

constexpr std::size_t MAX_SUBSCRIBER_COUNT = 100;

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_Subscribe_AllTypes_AlreadyExist
 * @tc.desc: Subscribe returns OK when all requested types are already registered (line 262 IsAllTypeExist=true).
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, Subscribe_AllTypes_AlreadyExist, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb = std::make_shared<EventServiceCallback>();
    svc->AddTypes({OsAccountSubProfileEventType::CREATED, OsAccountSubProfileEventType::DELETED}, cb);
    EXPECT_EQ(svc->GetCallbackSize(), 1);

    auto stub = sptr<MockSubProfileStub>(new (std::nothrow) MockSubProfileStub());
    ASSERT_NE(stub, nullptr);
    OsAccountSubProfileClient::GetInstance().proxy_ = stub;

    ErrCode ret = OsAccountSubProfileClient::GetInstance().SubscribeOsAccountSubProfileEvents(
        {OsAccountSubProfileEventType::CREATED, OsAccountSubProfileEventType::DELETED}, cb);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(svc->GetCallbackSize(), 1);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_Subscribe_MaxSize_Reached
 * @tc.desc: Subscribe returns MAX_SIZE_ERROR when callback count reaches the limit (line 267).
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, Subscribe_MaxSize_Reached, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    std::vector<std::shared_ptr<EventServiceCallback>> callbacks;
    for (std::size_t i = 0; i < MAX_SUBSCRIBER_COUNT; i++) {
        auto cb = std::make_shared<EventServiceCallback>();
        svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb);
        callbacks.push_back(cb);
    }
    EXPECT_EQ(svc->GetCallbackSize(), MAX_SUBSCRIBER_COUNT);

    auto stub = sptr<MockSubProfileStub>(new (std::nothrow) MockSubProfileStub());
    ASSERT_NE(stub, nullptr);
    OsAccountSubProfileClient::GetInstance().proxy_ = stub;

    auto extraCb = std::make_shared<EventServiceCallback>();
    ErrCode ret = OsAccountSubProfileClient::GetInstance().SubscribeOsAccountSubProfileEvents(
        {OsAccountSubProfileEventType::DELETED}, extraCb);
    EXPECT_EQ(ret, ERR_OHOSACCOUNT_KIT_SUBSCRIBE_MAX_SIZE_ERROR);
    EXPECT_EQ(svc->GetCallbackSize(), MAX_SUBSCRIBER_COUNT);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_Unsubscribe_LastSubscriber_RemovesFromService
 * @tc.desc: Unsubscribe sends IPC to remove types when callback was the last subscriber (line 312 else branch).
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, Unsubscribe_LastSubscriber_RemovesFromService, TestSize.Level1)
{
    auto *svc = OsAccountSubProfileEventService::GetInstance();
    auto cb = std::make_shared<EventServiceCallback>();
    svc->AddTypes({OsAccountSubProfileEventType::CREATED}, cb);
    EXPECT_EQ(svc->GetCallbackSize(), 1);

    auto stub = sptr<MockSubProfileStub>(new (std::nothrow) MockSubProfileStub());
    ASSERT_NE(stub, nullptr);
    OsAccountSubProfileClient::GetInstance().proxy_ = stub;

    ErrCode ret = OsAccountSubProfileClient::GetInstance().UnsubscribeOsAccountSubProfileEvents(cb);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(svc->GetCallbackSize(), 0);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_Subscribe_ProxyError_001
 * @tc.desc: SubscribeOsAccountSubProfileEvents skips AddTypes when proxy call fails (line 285 else branch).
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, Subscribe_ProxyError_001, TestSize.Level1)
{
    sptr<MockSubProfileStub> mockProxy = new (std::nothrow) MockSubProfileStub();
    ASSERT_NE(mockProxy, nullptr);
    mockProxy->subscribeRet_ = ERR_EXPECTED_FAILURE;
    OsAccountSubProfileClient::GetInstance().proxy_ = mockProxy;

    auto callback = std::make_shared<TestSubscribeCallback>();
    ASSERT_NE(callback, nullptr);

    ErrCode ret = OsAccountSubProfileClient::GetInstance().SubscribeOsAccountSubProfileEvents(
        {OsAccountSubProfileEventType::CREATED}, callback);
    EXPECT_EQ(ret, ERR_EXPECTED_FAILURE);
}

/**
 * @tc.name: OsAccountSubProfileClientNoSubspaceTest_Unsubscribe_ProxyError_001
 * @tc.desc: UnsubscribeOsAccountSubProfileEvents returns error when proxy call fails (line 323 if branch).
 */
HWTEST_F(OsAccountSubProfileClientNoSubspaceTest, Unsubscribe_ProxyError_001, TestSize.Level1)
{
    sptr<MockSubProfileStub> mockProxy = new (std::nothrow) MockSubProfileStub();
    ASSERT_NE(mockProxy, nullptr);
    OsAccountSubProfileClient::GetInstance().proxy_ = mockProxy;

    auto callback = std::make_shared<TestSubscribeCallback>();
    ASSERT_NE(callback, nullptr);

    ErrCode subRet = OsAccountSubProfileClient::GetInstance().SubscribeOsAccountSubProfileEvents(
        {OsAccountSubProfileEventType::CREATED}, callback);
    EXPECT_EQ(subRet, ERR_OK);

    mockProxy->unsubscribeRet_ = ERR_EXPECTED_FAILURE;

    ErrCode ret = OsAccountSubProfileClient::GetInstance().UnsubscribeOsAccountSubProfileEvents(callback);
    EXPECT_EQ(ret, ERR_EXPECTED_FAILURE);
}

// ===== OsAccountSubProfileManagerService no-macro paths (lines 125-153) =====
class SubspaceManagerServiceNoMacroTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: SubspaceManagerServiceNoMacroTest_Create_ReturnsLimit_001
 * @tc.desc: CreateOsAccountSubProfile in no-macro build returns ERR_OS_ACCOUNT_SUBSPACE_LIMIT (line 131).
 */
HWTEST_F(SubspaceManagerServiceNoMacroTest, Create_ReturnsLimit_001, TestSize.Level1)
{
    OsAccountSubProfileManagerService service;
    OsAccountSubspaceResult result;
    ErrCode ret = service.CreateOsAccountSubProfile(TEST_OS_ACCOUNT_ID, result);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_LIMIT);
}

/**
 * @tc.name: SubspaceManagerServiceNoMacroTest_Delete_ReturnsRestricted_001
 * @tc.desc: DeleteOsAccountSubProfile in no-macro build returns ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED (line 140).
 */
HWTEST_F(SubspaceManagerServiceNoMacroTest, Delete_ReturnsRestricted_001, TestSize.Level1)
{
    OsAccountSubProfileManagerService service;
    ErrCode ret = service.DeleteOsAccountSubProfile(TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_ID);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED);
}

/**
 * @tc.name: SubspaceManagerServiceNoMacroTest_Switch_SubspaceMismatch_001
 * @tc.desc: SwitchOsAccountSubProfile with non-matching subspaceId returns SUBSPACE_NOT_FOUND (line 150).
 */
HWTEST_F(SubspaceManagerServiceNoMacroTest, Switch_SubspaceMismatch_001, TestSize.Level1)
{
    OsAccountSubProfileManagerService service;
    ErrCode ret = service.SwitchOsAccountSubProfile(TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_ID);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: SubspaceManagerServiceNoMacroTest_Switch_SubspaceMatch_002
 * @tc.desc: SwitchOsAccountSubProfile with matching subspaceId returns ERR_OK (line 152).
 */
HWTEST_F(SubspaceManagerServiceNoMacroTest, Switch_SubspaceMatch_002, TestSize.Level1)
{
    OsAccountSubProfileManagerService service;
    int32_t expectedId = TEST_OS_ACCOUNT_ID * 1000;
    ErrCode ret = service.SwitchOsAccountSubProfile(TEST_OS_ACCOUNT_ID, expectedId);
    EXPECT_EQ(ret, ERR_OK);
}

// ===== OsAccountSubProfileManagerService Subscribe/Unsubscribe common paths (lines 156-208) =====
class SubspaceManagerServiceSubscribeTest : public testing::Test {
public:
    void SetUp() override
    {
        service_ = sptr<OsAccountSubProfileManagerService>(new (std::nothrow) OsAccountSubProfileManagerService());
        ASSERT_NE(service_, nullptr);
        listener_ = service_;
    }
    void TearDown() override {}
    sptr<OsAccountSubProfileManagerService> service_;
    sptr<IRemoteObject> listener_;
};

/**
 * @tc.name: SubspaceManagerServiceSubscribeTest_Subscribe_NullListener_001
 * @tc.desc: Subscribe with null eventListener returns INVALID_PARAMETER (line 164).
 */
HWTEST_F(SubspaceManagerServiceSubscribeTest, Subscribe_NullListener_001, TestSize.Level1)
{
    ErrCode ret = service_->SubscribeOsAccountSubProfileEvents(
        {static_cast<int32_t>(OsAccountSubProfileEventType::CREATED)}, nullptr);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SubspaceManagerServiceSubscribeTest_Subscribe_EmptyTypes_001
 * @tc.desc: Subscribe with empty typeInts returns INVALID_PARAMETER (line 164).
 */
HWTEST_F(SubspaceManagerServiceSubscribeTest, Subscribe_EmptyTypes_001, TestSize.Level1)
{
    ErrCode ret = service_->SubscribeOsAccountSubProfileEvents({}, listener_);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SubspaceManagerServiceSubscribeTest_Subscribe_TooManyTypes_001
 * @tc.desc: Subscribe with typeInts.size() > INVALID_TYPE returns INVALID_PARAMETER (line 168).
 */
HWTEST_F(SubspaceManagerServiceSubscribeTest, Subscribe_TooManyTypes_001, TestSize.Level1)
{
    std::vector<int32_t> tooMany = {0, 1, 2, 3, 4};
    ErrCode ret = service_->SubscribeOsAccountSubProfileEvents(tooMany, listener_);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SubspaceManagerServiceSubscribeTest_Subscribe_InvalidTypeValue_001
 * @tc.desc: Subscribe with invalid type returns INVALID_PARAMETER (line 174).
 */
HWTEST_F(SubspaceManagerServiceSubscribeTest, Subscribe_InvalidTypeValue_001, TestSize.Level1)
{
    ErrCode ret = service_->SubscribeOsAccountSubProfileEvents({99}, listener_);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SubspaceManagerServiceSubscribeTest_Unsubscribe_NullListener_001
 * @tc.desc: Unsubscribe with null eventListener returns INVALID_PARAMETER (line 191).
 */
HWTEST_F(SubspaceManagerServiceSubscribeTest, Unsubscribe_NullListener_001, TestSize.Level1)
{
    ErrCode ret = service_->UnsubscribeOsAccountSubProfileEvents(
        {static_cast<int32_t>(OsAccountSubProfileEventType::CREATED)}, nullptr);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SubspaceManagerServiceSubscribeTest_Unsubscribe_EmptyTypes_001
 * @tc.desc: Unsubscribe with empty typeInts returns INVALID_PARAMETER (line 191).
 */
HWTEST_F(SubspaceManagerServiceSubscribeTest, Unsubscribe_EmptyTypes_001, TestSize.Level1)
{
    ErrCode ret = service_->UnsubscribeOsAccountSubProfileEvents({}, listener_);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SubspaceManagerServiceSubscribeTest_Unsubscribe_TooManyTypes_001
 * @tc.desc: Unsubscribe with typeInts.size() > INVALID_TYPE returns INVALID_PARAMETER (line 195).
 */
HWTEST_F(SubspaceManagerServiceSubscribeTest, Unsubscribe_TooManyTypes_001, TestSize.Level1)
{
    std::vector<int32_t> tooMany = {0, 1, 2, 3, 4};
    ErrCode ret = service_->UnsubscribeOsAccountSubProfileEvents(tooMany, listener_);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SubspaceManagerServiceSubscribeTest_Unsubscribe_InvalidTypeValue_001
 * @tc.desc: Unsubscribe with invalid type returns INVALID_PARAMETER (line 201).
 */
HWTEST_F(SubspaceManagerServiceSubscribeTest, Unsubscribe_InvalidTypeValue_001, TestSize.Level1)
{
    ErrCode ret = service_->UnsubscribeOsAccountSubProfileEvents({-1}, listener_);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SubspaceManagerServiceSubscribeTest_SubscribeThenUnsubscribe_ValidTypes_001
 * @tc.desc: Subscribe then Unsubscribe with valid types hits subscribe manager (lines 205, 207).
 */
HWTEST_F(SubspaceManagerServiceSubscribeTest, SubscribeThenUnsubscribe_ValidTypes_001, TestSize.Level1)
{
    std::vector<int32_t> typeInts = {
        static_cast<int32_t>(OsAccountSubProfileEventType::CREATED),
        static_cast<int32_t>(OsAccountSubProfileEventType::DELETED),
        static_cast<int32_t>(OsAccountSubProfileEventType::SWITCHING),
        static_cast<int32_t>(OsAccountSubProfileEventType::SWITCHED)
    };
    ErrCode subRet = service_->SubscribeOsAccountSubProfileEvents(typeInts, listener_);
    EXPECT_EQ(subRet, ERR_OK);
    ErrCode unsubRet = service_->UnsubscribeOsAccountSubProfileEvents(typeInts, listener_);
    EXPECT_EQ(unsubRet, ERR_OK);
}

// ===== OsAccountSubProfileManagerService CheckSystemApp failure paths (lines 160, 187) =====
class SubspaceManagerServiceCheckSystemAppTest : public testing::Test {
public:
    void SetUp() override
    {
        oldTokenId_ = IPCSkeleton::GetSelfTokenID();
        uint64_t noPermTokenId = 0;
        ASSERT_TRUE(AllocPermission({}, noPermTokenId, false));
        service_ = sptr<OsAccountSubProfileManagerService>(new (std::nothrow) OsAccountSubProfileManagerService());
        ASSERT_NE(service_, nullptr);
        listener_ = service_;
    }
    void TearDown() override
    {
        listener_ = nullptr;
        service_ = nullptr;
        uint64_t currentToken = IPCSkeleton::GetSelfTokenID();
        ASSERT_TRUE(RecoveryPermission(currentToken, oldTokenId_));
    }
    sptr<OsAccountSubProfileManagerService> service_;
    sptr<IRemoteObject> listener_;
    uint64_t oldTokenId_;
};

#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

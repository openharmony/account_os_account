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
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

#include <gtest/gtest.h>
#include <set>
#include <string>
#include <thread>
#include <vector>

#define private public
#include "os_account_sub_profile_subscribe_manager.h"
#include "os_account_sub_profile_subscribe_death_recipient.h"
#include "os_account_sub_profile_subscribe_callback.h"

#undef private

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "accesstoken_kit.h"
#include "mock_space_dependencies.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
constexpr int32_t TEST_OS_ACCOUNT_ID = 100;
constexpr int32_t TEST_OTHER_ACCOUNT_ID = 200;
constexpr int32_t TEST_SUB_PROFILE_ID = 100001;
constexpr int32_t TEST_OTHER_SUB_PROFILE_ID = 100002;
constexpr int32_t TEST_PREV_SUB_PROFILE_ID = -1;

class MockRemoteObject : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject(u"MockRemoteObject") {}

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        deathRecipient_ = recipient;
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        deathRecipient_ = nullptr;
        return true;
    }

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }

    bool IsProxyObject() const override
    {
        return false;
    }

    int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        return 0;
    }

    sptr<DeathRecipient> deathRecipient_;
};
}

class OsAccountSubProfileSubscribeManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        allPermTokenId_ = GetAllAccountPermission();
        ASSERT_NE(allPermTokenId_, 0);
    }

    static void TearDownTestCase()
    {
        if (allPermTokenId_ != 0) {
            Security::AccessToken::AccessTokenKit::DeleteToken(
                static_cast<Security::AccessToken::AccessTokenID>(allPermTokenId_));
        }
    }

    void SetUp() override
    {
        ASSERT_EQ(SetSelfTokenID(allPermTokenId_), 0);
        ResetMockState();
        auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
        mgr.subscribeRecords_.clear();
        mgr.subscribeDeathRecipient_ = sptr<IRemoteObject::DeathRecipient>(
            new (std::nothrow) OsAccountSubProfileSubscribeDeathRecipient());
    }

    void TearDown() override
    {
        ResetMockState();
        auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
        mgr.subscribeRecords_.clear();
    }

    static uint64_t allPermTokenId_;
};

uint64_t OsAccountSubProfileSubscribeManagerTest::allPermTokenId_ = 0;

class SubProfileEventDataTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

class SubProfileSubscribeRecordTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

// ======================== SubProfileEventData Tests ========================

/**
 * @tc.name: MarshallingAndUnmarshalling_001
 * @tc.desc: 验证 SubProfileEventData 序列化和反序列化 CREATED 事件，所有字段值保持一致
 */
HWTEST_F(SubProfileEventDataTest, MarshallingAndUnmarshalling_001, TestSize.Level1)
{
    SubProfileEventData originalData;
    originalData.type_ = OsAccountSubProfileEventType::CREATED;
    originalData.osAccountId_ = TEST_OS_ACCOUNT_ID;
    originalData.subProfileId_ = TEST_SUB_PROFILE_ID;
    originalData.previousSubProfileId_ = TEST_PREV_SUB_PROFILE_ID;

    Parcel parcel;
    ASSERT_TRUE(originalData.Marshalling(parcel));

    SubProfileEventData *unmarshalledData = SubProfileEventData::Unmarshalling(parcel);
    ASSERT_NE(unmarshalledData, nullptr);

    EXPECT_EQ(unmarshalledData->type_, OsAccountSubProfileEventType::CREATED);
    EXPECT_EQ(unmarshalledData->osAccountId_, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(unmarshalledData->subProfileId_, TEST_SUB_PROFILE_ID);
    EXPECT_EQ(unmarshalledData->previousSubProfileId_, TEST_PREV_SUB_PROFILE_ID);

    delete unmarshalledData;
}

/**
 * @tc.name: Unmarshalling_EmptyParcel_005
 * @tc.desc: 验证空 Parcel 反序列化返回 nullptr，异常输入保护正确
 */
HWTEST_F(SubProfileEventDataTest, Unmarshalling_EmptyParcel_005, TestSize.Level1)
{
    Parcel parcel;
    SubProfileEventData *result = SubProfileEventData::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: OperatorEquals_IdenticalData_006
 * @tc.desc: 验证相同 SubProfileEventData 对象相等运算符返回 true
 */
HWTEST_F(SubProfileEventDataTest, OperatorEquals_IdenticalData_006, TestSize.Level1)
{
    SubProfileEventData data1;
    data1.type_ = OsAccountSubProfileEventType::CREATED;
    data1.osAccountId_ = TEST_OS_ACCOUNT_ID;
    data1.subProfileId_ = TEST_SUB_PROFILE_ID;
    data1.previousSubProfileId_ = TEST_PREV_SUB_PROFILE_ID;

    SubProfileEventData data2;
    data2.type_ = OsAccountSubProfileEventType::CREATED;
    data2.osAccountId_ = TEST_OS_ACCOUNT_ID;
    data2.subProfileId_ = TEST_SUB_PROFILE_ID;
    data2.previousSubProfileId_ = TEST_PREV_SUB_PROFILE_ID;

    EXPECT_TRUE(data1 == data2);
}

/**
 * @tc.name: OperatorEquals_DifferentType_007
 * @tc.desc: 验证不同事件类型的 SubProfileEventData 对象相等运算符返回 false
 */
HWTEST_F(SubProfileEventDataTest, OperatorEquals_DifferentType_007, TestSize.Level1)
{
    SubProfileEventData data1;
    data1.type_ = OsAccountSubProfileEventType::CREATED;

    SubProfileEventData data2;
    data2.type_ = OsAccountSubProfileEventType::DELETED;

    EXPECT_FALSE(data1 == data2);
}

/**
 * @tc.name: OperatorEquals_DifferentOsAccountId_008
 * @tc.desc: 验证不同 osAccountId 的 SubProfileEventData 对象相等运算符返回 false
 */
HWTEST_F(SubProfileEventDataTest, OperatorEquals_DifferentOsAccountId_008, TestSize.Level1)
{
    SubProfileEventData data1;
    data1.osAccountId_ = TEST_OS_ACCOUNT_ID;

    SubProfileEventData data2;
    data2.osAccountId_ = TEST_OTHER_ACCOUNT_ID;

    EXPECT_FALSE(data1 == data2);
}

/**
 * @tc.name: OperatorEquals_DifferentSubProfileId_009
 * @tc.desc: 验证不同 subProfileId 的 SubProfileEventData 对象相等运算符返回 false
 */
HWTEST_F(SubProfileEventDataTest, OperatorEquals_DifferentSubProfileId_009, TestSize.Level1)
{
    SubProfileEventData data1;
    data1.subProfileId_ = TEST_SUB_PROFILE_ID;

    SubProfileEventData data2;
    data2.subProfileId_ = TEST_OTHER_SUB_PROFILE_ID;

    EXPECT_FALSE(data1 == data2);
}

// ======================== OsAccountSubProfileSubscribeRecord Tests ========================

/**
 * @tc.name: AddTypes_SingleType_001
 * @tc.desc: 验证订阅记录添加单个事件类型后 size 为 1，且该类型存在
 */
HWTEST_F(SubProfileSubscribeRecordTest, AddTypes_SingleType_001, TestSize.Level1)
{
    OsAccountSubProfileSubscribeRecord record;
    std::set<OsAccountSubProfileEventType> types = {OsAccountSubProfileEventType::CREATED};
    record.AddTypes(types);

    EXPECT_EQ(record.types_.size(), 1u);
    EXPECT_NE(record.types_.find(OsAccountSubProfileEventType::CREATED), record.types_.end());
}

/**
 * @tc.name: AddTypes_MultipleTypes_002
 * @tc.desc: 验证订阅记录添加多个不同事件类型后 size 正确
 */
HWTEST_F(SubProfileSubscribeRecordTest, AddTypes_MultipleTypes_002, TestSize.Level1)
{
    OsAccountSubProfileSubscribeRecord record;
    std::set<OsAccountSubProfileEventType> types = {
        OsAccountSubProfileEventType::CREATED,
        OsAccountSubProfileEventType::DELETED,
        OsAccountSubProfileEventType::SWITCHED
    };
    record.AddTypes(types);

    EXPECT_EQ(record.types_.size(), 3u);
}

/**
 * @tc.name: AddTypes_MergeDuplicate_003
 * @tc.desc: 验证重复添加相同事件类型时自动去重，size 为不重复类型数量
 */
HWTEST_F(SubProfileSubscribeRecordTest, AddTypes_MergeDuplicate_003, TestSize.Level1)
{
    OsAccountSubProfileSubscribeRecord record;
    record.AddTypes({OsAccountSubProfileEventType::CREATED});
    record.AddTypes({OsAccountSubProfileEventType::CREATED, OsAccountSubProfileEventType::DELETED});

    EXPECT_EQ(record.types_.size(), 2u);
}

/**
 * @tc.name: RemoveTypes_ExistingType_004
 * @tc.desc: 验证移除已注册的事件类型后该类型不再存在于记录中
 */
HWTEST_F(SubProfileSubscribeRecordTest, RemoveTypes_ExistingType_004, TestSize.Level1)
{
    OsAccountSubProfileSubscribeRecord record;
    record.AddTypes({
        OsAccountSubProfileEventType::CREATED,
        OsAccountSubProfileEventType::DELETED,
        OsAccountSubProfileEventType::SWITCHED
    });

    record.RemoveTypes({OsAccountSubProfileEventType::DELETED});

    EXPECT_EQ(record.types_.size(), 2u);
    EXPECT_EQ(record.types_.find(OsAccountSubProfileEventType::DELETED), record.types_.end());
}

/**
 * @tc.name: RemoveTypes_NonExistentType_005
 * @tc.desc: 验证移除未注册的事件类型时 size 不变，不影响已有记录
 */
HWTEST_F(SubProfileSubscribeRecordTest, RemoveTypes_NonExistentType_005, TestSize.Level1)
{
    OsAccountSubProfileSubscribeRecord record;
    record.AddTypes({OsAccountSubProfileEventType::CREATED});

    record.RemoveTypes({OsAccountSubProfileEventType::DELETED});

    EXPECT_EQ(record.types_.size(), 1u);
}

/**
 * @tc.name: RemoveTypes_AllTypes_006
 * @tc.desc: 验证移除所有已注册事件类型后 types 集合为空
 */
HWTEST_F(SubProfileSubscribeRecordTest, RemoveTypes_AllTypes_006, TestSize.Level1)
{
    OsAccountSubProfileSubscribeRecord record;
    record.AddTypes({
        OsAccountSubProfileEventType::CREATED,
        OsAccountSubProfileEventType::DELETED
    });

    record.RemoveTypes({
        OsAccountSubProfileEventType::CREATED,
        OsAccountSubProfileEventType::DELETED
    });

    EXPECT_TRUE(record.types_.empty());
}

/**
 * @tc.name: RemoveTypes_EmptySet_007
 * @tc.desc: 验证传入空集合移除事件类型时 size 不变
 */
HWTEST_F(SubProfileSubscribeRecordTest, RemoveTypes_EmptySet_007, TestSize.Level1)
{
    OsAccountSubProfileSubscribeRecord record;
    record.AddTypes({OsAccountSubProfileEventType::CREATED});

    std::set<OsAccountSubProfileEventType> emptyTypes;
    record.RemoveTypes(emptyTypes);

    EXPECT_EQ(record.types_.size(), 1u);
}

// ======================== OsAccountSubProfileSubscribeManager Tests ========================

/**
 * @tc.name: Subscribe_NullEventListener_ReturnsError
 * @tc.desc: 验证传入空 eventListener 订阅时返回 INVALID_PARAMETER
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Subscribe_NullEventListener_ReturnsError, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    std::set<OsAccountSubProfileEventType> types = {OsAccountSubProfileEventType::CREATED};

    ErrCode ret = mgr.SubscribeOsAccountSubProfileEvents(types, nullptr);

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_TRUE(mgr.subscribeRecords_.empty());
}

/**
 * @tc.name: Subscribe_EmptyTypes_ReturnsError
 * @tc.desc: 验证传入空 types 集合订阅时返回 INVALID_PARAMETER
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Subscribe_EmptyTypes_ReturnsError, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);
    std::set<OsAccountSubProfileEventType> emptyTypes;

    ErrCode ret = mgr.SubscribeOsAccountSubProfileEvents(emptyTypes, listener);

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_TRUE(mgr.subscribeRecords_.empty());
}

/**
 * @tc.name: Subscribe_ValidRequest_AddsRecord
 * @tc.desc: 验证有效订阅请求正确添加记录，listener 和 localId 赋值正确
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Subscribe_ValidRequest_AddsRecord, TestSize.Level1)
{
    MockSetCallingUid(200000);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);
    std::set<OsAccountSubProfileEventType> types = {OsAccountSubProfileEventType::CREATED};

    ErrCode ret = mgr.SubscribeOsAccountSubProfileEvents(types, listener);

    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(mgr.subscribeRecords_.size(), 1u);
    EXPECT_EQ(mgr.subscribeRecords_[0]->eventListener_, sptr<IRemoteObject>(listener));
    EXPECT_NE(mgr.subscribeRecords_[0]->types_.find(OsAccountSubProfileEventType::CREATED),
        mgr.subscribeRecords_[0]->types_.end());
    EXPECT_EQ(mgr.subscribeRecords_[0]->localId_, 1);
}

/**
 * @tc.name: Subscribe_ValidRequest_CheckNotifyAllUsers
 * @tc.desc: 验证 callingUid 为 0 时订阅记录的 isNotifyAllUsers 为 true
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Subscribe_ValidRequest_CheckNotifyAllUsers, TestSize.Level1)
{
    MockSetCallingUid(0);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);
    std::set<OsAccountSubProfileEventType> types = {OsAccountSubProfileEventType::CREATED};

    ErrCode ret = mgr.SubscribeOsAccountSubProfileEvents(types, listener);

    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(mgr.subscribeRecords_.size(), 1u);
    EXPECT_TRUE(mgr.subscribeRecords_[0]->isNotifyAllUsers_);
    EXPECT_EQ(mgr.subscribeRecords_[0]->localId_, 0);
}

/**
 * @tc.name: Subscribe_DuplicateListener_MergesTypes
 * @tc.desc: 验证同一 listener 多次订阅时事件类型合并，不产生重复记录
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Subscribe_DuplicateListener_MergesTypes, TestSize.Level1)
{
    MockSetCallingUid(200000);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    ErrCode ret1 = mgr.SubscribeOsAccountSubProfileEvents(
        {OsAccountSubProfileEventType::CREATED}, listener);
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(mgr.subscribeRecords_.size(), 1u);

    ErrCode ret2 = mgr.SubscribeOsAccountSubProfileEvents(
        {OsAccountSubProfileEventType::DELETED, OsAccountSubProfileEventType::SWITCHED}, listener);
    EXPECT_EQ(ret2, ERR_OK);

    EXPECT_EQ(mgr.subscribeRecords_.size(), 1u);
    EXPECT_EQ(mgr.subscribeRecords_[0]->types_.size(), 3u);
    EXPECT_NE(mgr.subscribeRecords_[0]->types_.find(OsAccountSubProfileEventType::CREATED),
        mgr.subscribeRecords_[0]->types_.end());
    EXPECT_NE(mgr.subscribeRecords_[0]->types_.find(OsAccountSubProfileEventType::DELETED),
        mgr.subscribeRecords_[0]->types_.end());
    EXPECT_NE(mgr.subscribeRecords_[0]->types_.find(OsAccountSubProfileEventType::SWITCHED),
        mgr.subscribeRecords_[0]->types_.end());
}

/**
 * @tc.name: Subscribe_MultipleListeners
 * @tc.desc: 验证多个不同 listener 订阅时各自生成独立记录
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Subscribe_MultipleListeners, TestSize.Level1)
{
    MockSetCallingUid(200000);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener1 = new (std::nothrow) MockRemoteObject();
    sptr<MockRemoteObject> listener2 = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener1, nullptr);
    ASSERT_NE(listener2, nullptr);

    ErrCode ret1 = mgr.SubscribeOsAccountSubProfileEvents(
        {OsAccountSubProfileEventType::CREATED}, listener1);
    EXPECT_EQ(ret1, ERR_OK);

    ErrCode ret2 = mgr.SubscribeOsAccountSubProfileEvents(
        {OsAccountSubProfileEventType::DELETED}, listener2);
    EXPECT_EQ(ret2, ERR_OK);

    EXPECT_EQ(mgr.subscribeRecords_.size(), 2u);
}

/**
 * @tc.name: Unsubscribe_NullEventListener_ReturnsError
 * @tc.desc: 验证传入空 eventListener 取消订阅时返回 INVALID_PARAMETER
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Unsubscribe_NullEventListener_ReturnsError, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    std::set<OsAccountSubProfileEventType> types = {OsAccountSubProfileEventType::CREATED};

    ErrCode ret = mgr.UnsubscribeOsAccountSubProfileEvents(types, nullptr);

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: Unsubscribe_EmptyTypes_ReturnsError
 * @tc.desc: 验证传入空 types 集合取消订阅时返回 INVALID_PARAMETER
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Unsubscribe_EmptyTypes_ReturnsError, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);
    std::set<OsAccountSubProfileEventType> emptyTypes;

    ErrCode ret = mgr.UnsubscribeOsAccountSubProfileEvents(emptyTypes, listener);

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: Unsubscribe_NonExistentListener_ReturnsError
 * @tc.desc: 验证取消订阅未注册的 listener 时返回未注册错误
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Unsubscribe_NonExistentListener_ReturnsError, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    ErrCode ret = mgr.UnsubscribeOsAccountSubProfileEvents(
        {OsAccountSubProfileEventType::CREATED}, listener);

    EXPECT_EQ(ret, ERR_OHOSACCOUNT_KIT_NO_SPECIFIED_CALLBACK_HAS_BEEN_REGISTERED);
}

/**
 * @tc.name: Unsubscribe_RemovesTypesOnly
 * @tc.desc: 验证取消订阅部分类型时仅移除指定类型，记录保留
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Unsubscribe_RemovesTypesOnly, TestSize.Level1)
{
    MockSetCallingUid(200000);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    mgr.SubscribeOsAccountSubProfileEvents(
        {OsAccountSubProfileEventType::CREATED, OsAccountSubProfileEventType::DELETED}, listener);
    ASSERT_EQ(mgr.subscribeRecords_.size(), 1u);

    ErrCode ret = mgr.UnsubscribeOsAccountSubProfileEvents(
        {OsAccountSubProfileEventType::CREATED}, listener);

    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(mgr.subscribeRecords_.size(), 1u);
    EXPECT_EQ(mgr.subscribeRecords_[0]->types_.size(), 1u);
    EXPECT_NE(mgr.subscribeRecords_[0]->types_.find(OsAccountSubProfileEventType::DELETED),
        mgr.subscribeRecords_[0]->types_.end());
    EXPECT_EQ(mgr.subscribeRecords_[0]->types_.find(OsAccountSubProfileEventType::CREATED),
        mgr.subscribeRecords_[0]->types_.end());
}

/**
 * @tc.name: Unsubscribe_RemovesRecordWhenTypesEmpty
 * @tc.desc: 验证取消订阅所有类型后记录被整体移除
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Unsubscribe_RemovesRecordWhenTypesEmpty, TestSize.Level1)
{
    MockSetCallingUid(200000);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    mgr.SubscribeOsAccountSubProfileEvents({OsAccountSubProfileEventType::CREATED}, listener);
    ASSERT_EQ(mgr.subscribeRecords_.size(), 1u);

    ErrCode ret = mgr.UnsubscribeOsAccountSubProfileEvents(
        {OsAccountSubProfileEventType::CREATED}, listener);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(mgr.subscribeRecords_.empty());
}

/**
 * @tc.name: FindSubscribeRecordByEventListener_Found
 * @tc.desc: 验证通过已注册的 listener 查找返回对应记录
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, FindSubscribeRecordByEventListener_Found, TestSize.Level1)
{
    MockSetCallingUid(200000);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    mgr.SubscribeOsAccountSubProfileEvents({OsAccountSubProfileEventType::CREATED}, listener);

    auto found = mgr.FindSubscribeRecordByEventListener(listener);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->eventListener_, sptr<IRemoteObject>(listener));
}

/**
 * @tc.name: FindSubscribeRecordByEventListener_NotFound
 * @tc.desc: 验证通过未注册的 listener 查找返回 nullptr
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, FindSubscribeRecordByEventListener_NotFound, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    auto found = mgr.FindSubscribeRecordByEventListener(listener);
    EXPECT_EQ(found, nullptr);
}

/**
 * @tc.name: FindSubscribeRecordByEventListener_NullInput
 * @tc.desc: 验证传入 nullptr 查找时返回 nullptr
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, FindSubscribeRecordByEventListener_NullInput, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();

    auto found = mgr.FindSubscribeRecordByEventListener(nullptr);
    EXPECT_EQ(found, nullptr);
}

/**
 * @tc.name: GetSubscribersToNotify_MatchingType
 * @tc.desc: 验证获取匹配事件类型的订阅者返回正确的 listener
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, GetSubscribersToNotify_MatchingType, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    auto record = std::make_shared<OsAccountSubProfileSubscribeRecord>(listener, 1, false);
    record->AddTypes({OsAccountSubProfileEventType::CREATED});
    mgr.subscribeRecords_.push_back(record);

    auto subscribers = mgr.GetSubscribersToNotify(OsAccountSubProfileEventType::CREATED, 1);
    ASSERT_EQ(subscribers.size(), 1u);
    EXPECT_EQ(subscribers[0], sptr<IRemoteObject>(listener));
}

/**
 * @tc.name: GetSubscribersToNotify_NonMatchingType
 * @tc.desc: 验证获取不匹配事件类型的订阅者返回空集合
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, GetSubscribersToNotify_NonMatchingType, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    auto record = std::make_shared<OsAccountSubProfileSubscribeRecord>(listener, 1, false);
    record->AddTypes({OsAccountSubProfileEventType::CREATED});
    mgr.subscribeRecords_.push_back(record);

    auto subscribers = mgr.GetSubscribersToNotify(OsAccountSubProfileEventType::DELETED, 1);
    EXPECT_TRUE(subscribers.empty());
}

/**
 * @tc.name: GetSubscribersToNotify_NotifyAllUsers
 * @tc.desc: 验证 isNotifyAllUsers 为 true 时任意 localId 都能匹配
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, GetSubscribersToNotify_NotifyAllUsers, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    auto record = std::make_shared<OsAccountSubProfileSubscribeRecord>(listener, 1, true);
    record->AddTypes({OsAccountSubProfileEventType::CREATED});
    mgr.subscribeRecords_.push_back(record);

    auto subscribers = mgr.GetSubscribersToNotify(OsAccountSubProfileEventType::CREATED, 999);
    ASSERT_EQ(subscribers.size(), 1u);
    EXPECT_EQ(subscribers[0], sptr<IRemoteObject>(listener));
}

/**
 * @tc.name: GetSubscribersToNotify_FiltersByLocalId
 * @tc.desc: 验证 isNotifyAllUsers 为 false 时按 localId 过滤订阅者
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, GetSubscribersToNotify_FiltersByLocalId, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    auto record = std::make_shared<OsAccountSubProfileSubscribeRecord>(listener, 1, false);
    record->AddTypes({OsAccountSubProfileEventType::CREATED});
    mgr.subscribeRecords_.push_back(record);

    auto subscribers = mgr.GetSubscribersToNotify(OsAccountSubProfileEventType::CREATED, 2);
    EXPECT_TRUE(subscribers.empty());
}

/**
 * @tc.name: GetSubscribersToNotify_MultipleRecords
 * @tc.desc: 验证多个订阅记录匹配时返回所有符合条件的 listener
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, GetSubscribersToNotify_MultipleRecords, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener1 = new (std::nothrow) MockRemoteObject();
    sptr<MockRemoteObject> listener2 = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener1, nullptr);
    ASSERT_NE(listener2, nullptr);

    auto record1 = std::make_shared<OsAccountSubProfileSubscribeRecord>(listener1, 1, false);
    record1->AddTypes({OsAccountSubProfileEventType::CREATED});
    mgr.subscribeRecords_.push_back(record1);

    auto record2 = std::make_shared<OsAccountSubProfileSubscribeRecord>(listener2, 1, false);
    record2->AddTypes({OsAccountSubProfileEventType::CREATED});
    mgr.subscribeRecords_.push_back(record2);

    auto subscribers = mgr.GetSubscribersToNotify(OsAccountSubProfileEventType::CREATED, 1);
    ASSERT_EQ(subscribers.size(), 2u);
}

/**
 * @tc.name: GetSubscribersToNotify_EmptyRecords
 * @tc.desc: 验证无订阅记录时获取订阅者返回空集合
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, GetSubscribersToNotify_EmptyRecords, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();

    auto subscribers = mgr.GetSubscribersToNotify(OsAccountSubProfileEventType::CREATED, 1);
    EXPECT_TRUE(subscribers.empty());
}

// ======================== DeathRecipient Tests ========================

/**
 * @tc.name: DeathRecipient_OnRemoteDied_NullRemote
 * @tc.desc: 验证传入空 remote 死亡通知不产生错误，订阅记录保持不变
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, DeathRecipient_OnRemoteDied_NullRemote, TestSize.Level1)
{
    OsAccountSubProfileSubscribeDeathRecipient recipient;
    wptr<IRemoteObject> nullRemote;

    recipient.OnRemoteDied(nullRemote);

    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    EXPECT_TRUE(mgr.subscribeRecords_.empty());
}

/**
 * @tc.name: DeathRecipient_OnRemoteDied_ValidRemote
 * @tc.desc: 验证有效 remote 死亡通知后对应订阅记录被清理
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, DeathRecipient_OnRemoteDied_ValidRemote, TestSize.Level1)
{
    MockSetCallingUid(200000);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    mgr.SubscribeOsAccountSubProfileEvents({OsAccountSubProfileEventType::CREATED}, listener);
    ASSERT_EQ(mgr.subscribeRecords_.size(), 1u);

    OsAccountSubProfileSubscribeDeathRecipient recipient;
    wptr<IRemoteObject> remote(listener);
    recipient.OnRemoteDied(remote);

    EXPECT_EQ(mgr.subscribeRecords_.size(), 0u);
}

/**
 * @tc.name: DeathRecipient_SubscribeAddsDeathRecipient
 * @tc.desc: 验证订阅操作正确设置死亡通知回调
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, DeathRecipient_SubscribeAddsDeathRecipient, TestSize.Level1)
{
    MockSetCallingUid(200000);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    EXPECT_EQ(listener->deathRecipient_, nullptr);

    mgr.SubscribeOsAccountSubProfileEvents({OsAccountSubProfileEventType::CREATED}, listener);

    EXPECT_NE(listener->deathRecipient_, nullptr);
}

/**
 * @tc.name: DeathRecipient_SendRequestOnNullProxy
 * @tc.desc: 验证 null proxy 发送变化通知时返回 false
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, DeathRecipient_SendRequestOnNullProxy, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();

    SubProfileEventData eventData;
    eventData.type_ = OsAccountSubProfileEventType::CREATED;
    eventData.osAccountId_ = TEST_OS_ACCOUNT_ID;
    eventData.subProfileId_ = TEST_SUB_PROFILE_ID;

    bool result = mgr.OnSubProfileChanged(nullptr, eventData);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Publish_NoSubscribers
 * @tc.desc: 验证无订阅者时发布事件返回成功
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Publish_NoSubscribers, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();

    ErrCode ret = mgr.Publish(OsAccountSubProfileEventType::CREATED,
        TEST_OS_ACCOUNT_ID, TEST_SUB_PROFILE_ID, TEST_PREV_SUB_PROFILE_ID);

    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: Publish_WithSubscriber
 * @tc.desc: 验证存在匹配订阅者时发布事件返回成功
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Publish_WithSubscriber, TestSize.Level1)
{
    MockSetCallingUid(200000);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    mgr.SubscribeOsAccountSubProfileEvents({OsAccountSubProfileEventType::CREATED}, listener);
    ErrCode ret = mgr.Publish(OsAccountSubProfileEventType::CREATED, 1,
        TEST_SUB_PROFILE_ID, TEST_PREV_SUB_PROFILE_ID);
    EXPECT_EQ(ret, ERR_OK);
}

// ======================== Concurrent Tests (T-01) ========================

/**
 * @tc.name: Concurrent_SubscribeAndUnsubscribe
 * @tc.desc: 验证并发订阅和取消订阅操作的线程安全性
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Concurrent_SubscribeAndUnsubscribe, TestSize.Level1)
{
    MockSetCallingUid(200000);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();

    std::vector<sptr<MockRemoteObject>> listeners;
    constexpr int32_t THREAD_COUNT = 10;
    for (int32_t i = 0; i < THREAD_COUNT; ++i) {
        listeners.emplace_back(new (std::nothrow) MockRemoteObject());
    }

    std::vector<std::thread> threads;
    for (int32_t i = 0; i < THREAD_COUNT; ++i) {
        threads.emplace_back([&mgr, &listeners, i]() {
            mgr.SubscribeOsAccountSubProfileEvents(
                {OsAccountSubProfileEventType::CREATED}, listeners[i]);
        });
    }
    for (auto &t : threads) {
        t.join();
    }
    EXPECT_EQ(mgr.subscribeRecords_.size(), THREAD_COUNT);

    threads.clear();
    for (int32_t i = 0; i < THREAD_COUNT; ++i) {
        threads.emplace_back([&mgr, &listeners, i]() {
            mgr.UnsubscribeOsAccountSubProfileEvents(listeners[i]);
        });
    }
    for (auto &t : threads) {
        t.join();
    }
    EXPECT_TRUE(mgr.subscribeRecords_.empty());
}

/**
 * @tc.name: Concurrent_SubscribeSameListener
 * @tc.desc: 验证同一 listener 并发订阅多次时最终仅有一条记录
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Concurrent_SubscribeSameListener, TestSize.Level1)
{
    MockSetCallingUid(200000);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    std::vector<std::thread> threads;
    constexpr int32_t THREAD_COUNT = 10;
    for (int32_t i = 0; i < THREAD_COUNT; ++i) {
        threads.emplace_back([&mgr, &listener]() {
            mgr.SubscribeOsAccountSubProfileEvents(
                {OsAccountSubProfileEventType::CREATED}, listener);
        });
    }
    for (auto &t : threads) {
        t.join();
    }
    EXPECT_EQ(mgr.subscribeRecords_.size(), 1u);
}

/**
 * @tc.name: Concurrent_SubscribeDifferentTypes
 * @tc.desc: 验证同一 listener 并发订阅不同事件类型时类型合并正确
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Concurrent_SubscribeDifferentTypes, TestSize.Level1)
{
    MockSetCallingUid(200000);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    std::vector<std::thread> threads;
    std::set<OsAccountSubProfileEventType> allTypes = {
        OsAccountSubProfileEventType::CREATED,
        OsAccountSubProfileEventType::DELETED,
        OsAccountSubProfileEventType::SWITCHING,
        OsAccountSubProfileEventType::SWITCHED
    };
    for (auto type : allTypes) {
        threads.emplace_back([&mgr, &listener, type]() {
            mgr.SubscribeOsAccountSubProfileEvents({type}, listener);
        });
    }
    for (auto &t : threads) {
        t.join();
    }
    ASSERT_EQ(mgr.subscribeRecords_.size(), 1u);
    EXPECT_EQ(mgr.subscribeRecords_[0]->types_.size(), allTypes.size());
}

// ======================== End-to-End Event Flow Tests (T-02) ========================

/**
 * @tc.name: Publish_WithMultipleTypes
 * @tc.desc: 验证同一 subscriber 发布多种事件类型时均返回成功
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Publish_WithMultipleTypes, TestSize.Level1)
{
    MockSetCallingUid(200000);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    mgr.SubscribeOsAccountSubProfileEvents({
        OsAccountSubProfileEventType::CREATED,
        OsAccountSubProfileEventType::DELETED
    }, listener);
    ErrCode ret1 = mgr.Publish(OsAccountSubProfileEventType::CREATED, 1,
        TEST_SUB_PROFILE_ID, TEST_PREV_SUB_PROFILE_ID);
    EXPECT_EQ(ret1, ERR_OK);
    ErrCode ret2 = mgr.Publish(OsAccountSubProfileEventType::DELETED, 1,
        TEST_SUB_PROFILE_ID, TEST_PREV_SUB_PROFILE_ID);
    EXPECT_EQ(ret2, ERR_OK);
}

/**
 * @tc.name: Publish_WithMultipleSubscribers
 * @tc.desc: 验证多个 subscriber 订阅同一事件时发布均能送达
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Publish_WithMultipleSubscribers, TestSize.Level1)
{
    MockSetCallingUid(200000);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener1 = new (std::nothrow) MockRemoteObject();
    sptr<MockRemoteObject> listener2 = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener1, nullptr);
    ASSERT_NE(listener2, nullptr);
    mgr.SubscribeOsAccountSubProfileEvents({OsAccountSubProfileEventType::CREATED}, listener1);
    mgr.SubscribeOsAccountSubProfileEvents({OsAccountSubProfileEventType::CREATED}, listener2);
    ErrCode ret = mgr.Publish(OsAccountSubProfileEventType::CREATED, 1,
        TEST_SUB_PROFILE_ID, TEST_PREV_SUB_PROFILE_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(mgr.subscribeRecords_.size(), 2u);
}

/**
 * @tc.name: Publish_DoesNotDeleteSubscribers
 * @tc.desc: 验证多次发布事件后订阅记录不会被删除
 */
HWTEST_F(OsAccountSubProfileSubscribeManagerTest, Publish_DoesNotDeleteSubscribers, TestSize.Level1)
{
    MockSetCallingUid(200000);
    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    sptr<MockRemoteObject> listener = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(listener, nullptr);

    mgr.SubscribeOsAccountSubProfileEvents({OsAccountSubProfileEventType::CREATED}, listener);
    ASSERT_EQ(mgr.subscribeRecords_.size(), 1u);
    for (int i = 0; i < 5; ++i) {
        mgr.Publish(OsAccountSubProfileEventType::CREATED, 1,
            TEST_SUB_PROFILE_ID, TEST_PREV_SUB_PROFILE_ID);
    }
    EXPECT_EQ(mgr.subscribeRecords_.size(), 1u);
}

#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

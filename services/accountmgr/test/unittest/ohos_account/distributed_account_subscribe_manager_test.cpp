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

class MockDistributedAccountEventListener : public IRemoteStub<IDistributedAccountEvent> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }
    ErrCode OnAccountsChanged(const DistributedAccountEventData &eventData) override
    {
        return ERR_OK;
    }
};

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
{
    DistributedAccountSubscribeManager::GetInstance().subscribeRecords_.clear();
}

/**
 * @tc.name: Subscribe_UnsubscribeWithMultipleTypes_RemainingTypes_001
 * @tc.desc: Unsubscribe one type when subscriber has multiple types (line 100 TRUE branch).
 */
HWTEST_F(DistributedAccountSubscribeManagerTest,
    Subscribe_UnsubscribeWithMultipleTypes_RemainingTypes_001, TestSize.Level1)
{
    auto listener = sptr<MockDistributedAccountEventListener>(new (std::nothrow) MockDistributedAccountEventListener());
    ASSERT_NE(listener, nullptr);

    auto &manager = DistributedAccountSubscribeManager::GetInstance();
    ErrCode subRet = manager.SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, listener);
    EXPECT_EQ(subRet, ERR_OK);

    subRet = manager.SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT, listener);
    EXPECT_EQ(subRet, ERR_OK);

    ErrCode unsubRet = manager.UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, listener);
    EXPECT_EQ(unsubRet, ERR_OK);
    unsubRet = manager.UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT, listener);
    EXPECT_EQ(unsubRet, ERR_OK);
}
}
}

/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"
#define private public
#define protected public
#include "os_account_state_reply_callback_service.h"
#undef protected
#undef private

namespace OHOS {
using namespace testing::ext;
using namespace OHOS::AccountSA;
namespace AccountSA {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

class OsAccountStateReplyCallbackServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp();
    void TearDown() {};
};

void OsAccountStateReplyCallbackServiceTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

/**
 * @tc.name: OsAccountStateReplyCallbackServiceTest_0001
 * @tc.desc: Test the STOPPING state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStateReplyCallbackServiceTest, OsAccountStateReplyCallbackServiceTest_0001, TestSize.Level3)
{
    OsAccountStateReplyCallbackService service(
        100, // Test ID
        OsAccountState::STOPPING,
        nullptr,
        nullptr,
        99 // Invalid subscriberUid
    );
    EXPECT_EQ(service.OnComplete(), ERR_OK);
    EXPECT_EQ(g_resultCodeStr, "stop");
}

/**
 * @tc.name: OsAccountStateReplyCallbackServiceTest_0002
 * @tc.desc: Test the STOPPED state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStateReplyCallbackServiceTest, OsAccountStateReplyCallbackServiceTest_0002, TestSize.Level3)
{
    OsAccountStateReplyCallbackService service(
        100, // Test ID
        OsAccountState::STOPPED,
        nullptr,
        nullptr,
        99 // Invalid subscriberUid
    );
    EXPECT_EQ(service.OnComplete(), ERR_OK);
    EXPECT_EQ(g_resultCodeStr, "stop");
}

/**
 * @tc.name: OsAccountStateReplyCallbackServiceTest_0003
 * @tc.desc: Test the ACTIVATED state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStateReplyCallbackServiceTest, OsAccountStateReplyCallbackServiceTest_0003, TestSize.Level3)
{
    OsAccountStateReplyCallbackService service(
        100, // Test ID
        OsAccountState::ACTIVATED,
        nullptr,
        nullptr,
        99 // Invalid subscriberUid
    );
    EXPECT_EQ(service.OnComplete(), ERR_OK);
    EXPECT_EQ(g_resultCodeStr, "activate");
}

/**
 * @tc.name: OsAccountStateReplyCallbackServiceTest_0004
 * @tc.desc: Test the ACTIVATING state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStateReplyCallbackServiceTest, OsAccountStateReplyCallbackServiceTest_0004, TestSize.Level3)
{
    OsAccountStateReplyCallbackService service(
        100, // Test ID
        OsAccountState::ACTIVATING,
        nullptr,
        nullptr,
        99 // Invalid subscriberUid
    );
    EXPECT_EQ(service.OnComplete(), ERR_OK);
    EXPECT_EQ(g_resultCodeStr, "activate");
}

/**
 * @tc.name: OsAccountStateReplyCallbackServiceTest_0005
 * @tc.desc: Test the CREATED state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStateReplyCallbackServiceTest, OsAccountStateReplyCallbackServiceTest_0005, TestSize.Level3)
{
    OsAccountStateReplyCallbackService service(
        100, // Test ID
        OsAccountState::CREATED,
        nullptr,
        nullptr,
        99 // Invalid subscriberUid
    );
    EXPECT_EQ(service.OnComplete(), ERR_OK);
    EXPECT_EQ(g_resultCodeStr, "create");
}

/**
 * @tc.name: OsAccountStateReplyCallbackServiceTest_0006
 * @tc.desc: Test the REMOVED state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStateReplyCallbackServiceTest, OsAccountStateReplyCallbackServiceTest_0006, TestSize.Level3)
{
    OsAccountStateReplyCallbackService service(
        100, // Test ID
        OsAccountState::REMOVED,
        nullptr,
        nullptr,
        99 // Invalid subscriberUid
    );
    EXPECT_EQ(service.OnComplete(), ERR_OK);
    EXPECT_EQ(g_resultCodeStr, "remove");
}

/**
 * @tc.name: OsAccountStateReplyCallbackServiceTest_0007
 * @tc.desc: Test the SWITCHING state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStateReplyCallbackServiceTest, OsAccountStateReplyCallbackServiceTest_0007, TestSize.Level3)
{
    OsAccountStateReplyCallbackService service(
        100, // Test ID
        OsAccountState::SWITCHING,
        nullptr,
        nullptr,
        99 // Invalid subscriberUid
    );
    EXPECT_EQ(service.OnComplete(), ERR_OK);
    EXPECT_EQ(g_resultCodeStr, "switch");
}

/**
 * @tc.name: OsAccountStateReplyCallbackServiceTest_0008
 * @tc.desc: Test the SWITCHED state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStateReplyCallbackServiceTest, OsAccountStateReplyCallbackServiceTest_0008, TestSize.Level3)
{
    OsAccountStateReplyCallbackService service(
        100, // Test ID
        OsAccountState::SWITCHED,
        nullptr,
        nullptr,
        99 // Invalid subscriberUid
    );
    EXPECT_EQ(service.OnComplete(), ERR_OK);
    EXPECT_EQ(g_resultCodeStr, "switch");
}

/**
 * @tc.name: OsAccountStateReplyCallbackServiceTest_0009
 * @tc.desc: Test the UNLOCKED state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStateReplyCallbackServiceTest, OsAccountStateReplyCallbackServiceTest_0009, TestSize.Level3)
{
    OsAccountStateReplyCallbackService service(
        100, // Test ID
        OsAccountState::UNLOCKED,
        nullptr,
        nullptr,
        99 // Invalid subscriberUid
    );
    EXPECT_EQ(service.OnComplete(), ERR_OK);
    EXPECT_EQ(g_resultCodeStr, "unlock");
}

/**
 * @tc.name: OsAccountStateReplyCallbackServiceTest_0010
 * @tc.desc: Test the default state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStateReplyCallbackServiceTest, OsAccountStateReplyCallbackServiceTest_0010, TestSize.Level3)
{
    OsAccountStateReplyCallbackService service(
        100, // Test ID
        static_cast<OsAccountState>(99), // default
        nullptr,
        nullptr,
        99 // Invalid subscriberUid
    );
    EXPECT_EQ(service.OnComplete(), ERR_OK);
    EXPECT_EQ(g_resultCodeStr, "");
}

/**
 * @tc.name: ForceComplete_Normal
 * @tc.desc: ForceComplete pops the queue and notifies the condition variable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStateReplyCallbackServiceTest, ForceComplete_Normal, TestSize.Level1)
{
    auto cv = std::make_shared<std::condition_variable>();
    auto queue = std::make_shared<SafeQueue<uint8_t>>();
    queue->Push(1);
    OsAccountStateReplyCallbackService service(100, OsAccountState::STOPPING, cv, queue, 99);
    service.ForceComplete();
    EXPECT_EQ(queue->Size(), 0);
}

/**
 * @tc.name: ForceComplete_Idempotent
 * @tc.desc: A second ForceComplete call is a no-op (queue size remains 0).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStateReplyCallbackServiceTest, ForceComplete_Idempotent, TestSize.Level1)
{
    auto cv = std::make_shared<std::condition_variable>();
    auto queue = std::make_shared<SafeQueue<uint8_t>>();
    queue->Push(1);
    OsAccountStateReplyCallbackService service(100, OsAccountState::STOPPING, cv, queue, 99);
    service.ForceComplete();
    service.ForceComplete(); // second call should be no-op
    EXPECT_EQ(queue->Size(), 0);
}

/**
 * @tc.name: ForceComplete_NullQueue
 * @tc.desc: ForceComplete with nullptr queue/cv hits the early-return branch in CompleteInner.
 *           isCompleted_ must still be set to true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStateReplyCallbackServiceTest, ForceComplete_NullQueue, TestSize.Level1)
{
    OsAccountStateReplyCallbackService service(100, OsAccountState::STOPPING, nullptr, nullptr, 99);
    service.ForceComplete(); // CompleteInner: nullptr branch, logs and returns early
    EXPECT_TRUE(service.isCompleted_);
}
}
}
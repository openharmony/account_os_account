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
#include <string>
#include "account_log_wrapper.h"
#include "distributed_account_event_service.h"
#include "distributed_account_subscribe_manager.h"


namespace OHOS {
namespace AccountSA {
using namespace testing;
using namespace testing::mt;
using namespace testing::ext;
namespace {
constexpr int32_t TEST_COUNT = 100;
constexpr int32_t TEST_ID = 100;
constexpr DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE TEST_TYPE = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;
const char THREAD_OHOS_ACCOUNT_EVENT_TEST[] = "TestOhosAccountEvent";
IDistributedAccountSubscribe &mgr = DistributedAccountSubscribeManager::GetInstance();
}  // namespace
class OhosAccountEventManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp();
    void TearDown() {}
};

void OhosAccountEventManagerTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void TestPulishOhosAccountEvent()
{
    for (int32_t i = 0; i < TEST_COUNT; i++) {
        mgr.Publish(TEST_ID, TEST_TYPE);
    }
}

void TestSubscribeOhosAccountEvent()
{
    sptr<IRemoteObject> callbacks[TEST_COUNT];
    for (int32_t i = 0; i < TEST_COUNT; i++) {
        callbacks[i] = new (std::nothrow) DistributedAccountEventService();
        EXPECT_EQ(ERR_OK, mgr.SubscribeDistributedAccountEvent(TEST_TYPE, callbacks[i]));
    }
    auto task = [] { TestPulishOhosAccountEvent(); };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_OHOS_ACCOUNT_EVENT_TEST);
    taskThread.detach();
    for (int32_t i = 0; i < TEST_COUNT; i++) {
        EXPECT_EQ(ERR_OK, mgr.UnsubscribeDistributedAccountEvent(callbacks[i]));
    }
}

/**
 * @tc.name: OsAccountEventManagerTestTest001
 * @tc.desc: Test multiple thread event manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountEventManagerTest, OhosAccountEventManagerMulTest001, TestSize.Level1)
{
    TestSubscribeOhosAccountEvent();
}
}  // namespace AccountSA
}  // namespace OHOS
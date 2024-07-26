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
#define private public
#include "iinner_os_account_manager.h"
#include "os_account.h"
#undef private
#include "os_account_manager.h"
#define private public
#include "os_account_control_file_manager.h"
#include "os_account_manager_service.h"
#include "os_account_proxy.h"
#include "os_account_subscribe_manager.h"
#undef private


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
    osAccountControl->eventCallbackFunc_ = nullptr;
    for (auto &fileNameMgr : osAccountControl->accountFileWatcherMgr_.fileNameMgrMap_) {
        fileNameMgr.second->eventCallbackFunc_ = nullptr;
    }
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
            EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(subscriber));
            std::lock_guard<std::mutex> lock(OsAccount::GetInstance().eventListenersMutex_);
            OsAccount::GetInstance().eventListeners_.erase(subscriber);
        }
    } else {
        while (i--) {
            IInnerOsAccountManager::
                GetInstance().subscribeManager_.Publish(TEST_ID, OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
            IInnerOsAccountManager::
                GetInstance().subscribeManager_.Publish(START_USER_ID, TEST_ID, OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED);
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
}  // namespace AccountSA
}  // namespace OHOS
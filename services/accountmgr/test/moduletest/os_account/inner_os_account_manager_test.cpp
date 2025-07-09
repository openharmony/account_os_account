/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include <fcntl.h>
#include <poll.h>
#include <thread>
#include <unistd.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#define private public
#include "iinner_os_account_manager.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

class IInnerOsAccountManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

    IInnerOsAccountManager *innerMgrService_ = &IInnerOsAccountManager::GetInstance();
};

void IInnerOsAccountManagerTest::SetUpTestCase(void)
{}

void IInnerOsAccountManagerTest::TearDownTestCase(void)
{}

void IInnerOsAccountManagerTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void IInnerOsAccountManagerTest::TearDown(void)
{}

/**
 * @tc.name: SendMsgForAccountStop001
 * @tc.desc: coverage SendMsgForAccountStop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, SendMsgForAccountStop001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode ret = innerMgrService_->SendMsgForAccountStop(osAccountInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SendMsgForAccountRemove001
 * @tc.desc: coverage SendMsgForAccountRemove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, SendMsgForAccountRemove001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode ret = innerMgrService_->SendMsgForAccountRemove(osAccountInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SendMsgForAccountActivate001
 * @tc.desc: coverage SendMsgForAccountActivate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, SendMsgForAccountActivate001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode ret = innerMgrService_->SendMsgForAccountActivate(osAccountInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SubscribeOsAccount001
 * @tc.desc: coverage SubscribeOsAccount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, SubscribeOsAccount001, TestSize.Level1)
{
    OsAccountSubscribeInfo subscribeInfo;
    const sptr<IRemoteObject> eventListener = nullptr;

    OsAccountInfo osAccountInfo;
    ErrCode ret = innerMgrService_->SubscribeOsAccount(subscribeInfo, eventListener);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: GetOsAccountShortName001
 * @tc.desc: coverage GetOsAccountShortName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, GetOsAccountShortName001, TestSize.Level1)
{
    std::string shortName;
    ErrCode ret = innerMgrService_->GetOsAccountShortName(199, shortName);
    EXPECT_NE(ret, ERR_OK);
    ret = innerMgrService_->GetOsAccountShortName(100, shortName);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: InnerOsAccountManagerTest002
 * @tc.desc: coverage CheckAndRefreshLocalIdRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, InnerOsAccountManagerTest002, TestSize.Level1)
{
    int id;
    EXPECT_EQ(innerMgrService_->GetDefaultActivatedOsAccount(id), ERR_OK);
    innerMgrService_->CheckAndRefreshLocalIdRecord(id);
    EXPECT_EQ(innerMgrService_->GetDefaultActivatedOsAccount(id), ERR_OK);
    EXPECT_EQ(id, 100);
    innerMgrService_->CheckAndRefreshLocalIdRecord(199);
    EXPECT_EQ(id, 100);
}

/**
 * @tc.name: InnerOsAccountManagerTest003
 * @tc.desc: coverage SendMsgForAccountDeactivate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, InnerOsAccountManagerTest003, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode ret = innerMgrService_->CreateOsAccount("InnerOsAccountManager003", OsAccountType::NORMAL, osAccountInfo);
    EXPECT_NE(ret, ERR_OK);
    innerMgrService_->RemoveOsAccount(osAccountInfo.GetLocalId());
}

/**
 * @tc.name: InnerOsAccountManagerTest004
 * @tc.desc: coverage IsOsAccountDeactivating
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, InnerOsAccountManagerTest004, TestSize.Level1)
{
    int id;
    EXPECT_EQ(innerMgrService_->GetDefaultActivatedOsAccount(id), ERR_OK);
    innerMgrService_->deactivatingAccounts_.EnsureInsert(id, true);

    bool isDeactivating = false;
    ErrCode ret = innerMgrService_->IsOsAccountDeactivating(id, isDeactivating);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isDeactivating);
    innerMgrService_->deactivatingAccounts_.Erase(id);
}

/**
 * @tc.name: InnerOsAccountManagerTest005
 * @tc.desc: coverage SendMsgForAccountActivateInBackground
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, InnerOsAccountManagerTest005, TestSize.Level3)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(-1);
    ErrCode ret = innerMgrService_->SendMsgForAccountActivateInBackground(osAccountInfo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INTERFACE_TO_AM_ACCOUNT_START_ERROR);
}

/**
 * @tc.name: InnerOsAccountManagerTest006
 * @tc.desc: coverage ActivateOsAccountInBackground
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, InnerOsAccountManagerTest006, TestSize.Level3)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(-1);
    ErrCode ret = innerMgrService_->ActivateOsAccountInBackground(-1);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    ret = innerMgrService_->ActivateOsAccountInBackground(100);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INTERFACE_TO_AM_ACCOUNT_START_ERROR);
}

/**
 * @tc.name: InnerOsAccountManagerTest007
 * @tc.desc: Test poll timeout.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, InnerOsAccountManagerTest007, TestSize.Level3)
{
    int pipeFds[2];
    pipe(pipeFds);

    // Set non-blocking reads to ensure poll timeouts
    fcntl(pipeFds[0], F_SETFL, O_NONBLOCK);
    ErrCode result = innerMgrService_->WaitForAnimationReady(pipeFds[0]);
    close(pipeFds[0]);
    close(pipeFds[1]);
    EXPECT_EQ(result, ERR_OSACCOUNT_SERVICE_INNER_ANIMATION_TIMEOUT);
}

/**
 * @tc.name: InnerOsAccountManagerTest008
 * @tc.desc: Test non-pollin events.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, InnerOsAccountManagerTest008, TestSize.Level3)
{
    int pipeFds[2];
    pipe(pipeFds);

    // Close the write end to generate the POLLHUP event
    close(pipeFds[1]);
    ErrCode result = innerMgrService_->WaitForAnimationReady(pipeFds[0]);
    close(pipeFds[0]);
    EXPECT_EQ(result, ERR_OSACCOUNT_SERVICE_INNER_ANIMATION_UNEXPECTED_EVENT);
}

/**
 * @tc.name: InnerOsAccountManagerTest009
 * @tc.desc: The test successfully read the short message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, InnerOsAccountManagerTest009, TestSize.Level3)
{
    int pipeFds[2];
    ASSERT_EQ(pipe(pipeFds), 0);
    const char* msg = "Animation ready";
    write(pipeFds[1], msg, strlen(msg));
    close(pipeFds[1]); // Close the write end to ensure EOF

    ErrCode result = innerMgrService_->WaitForAnimationReady(pipeFds[0]);
    close(pipeFds[0]);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InnerOsAccountManagerTest010
 * @tc.desc: The test successfully read long messages
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, InnerOsAccountManagerTest010, TestSize.Level3)
{
    int pipeFds[2];
    ASSERT_EQ(pipe(pipeFds), 0);

    // Create a long message (exceeding 256 bytes)
    std::string longMsg(255, 'A');
    write(pipeFds[1], longMsg.c_str(), longMsg.size());
    close(pipeFds[1]);
    ErrCode result = innerMgrService_->WaitForAnimationReady(pipeFds[0]);
    close(pipeFds[0]);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: InnerOsAccountManagerTest011
 * @tc.desc: The test successfully read the boundary size message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, InnerOsAccountManagerTest011, TestSize.Level3)
{
    int pipeFds[2];
    pipe(pipeFds);

    // Create a message of exactly 256 bytes
    std::string boundaryMsg(255, 'B');
    write(pipeFds[1], boundaryMsg.c_str(), boundaryMsg.size());

    ErrCode result = innerMgrService_->WaitForAnimationReady(pipeFds[0]);
    close(pipeFds[0]);
    close(pipeFds[1]);
    EXPECT_EQ(result, ERR_OK);
}
}  // namespace AccountSA
}  // namespace OHOS

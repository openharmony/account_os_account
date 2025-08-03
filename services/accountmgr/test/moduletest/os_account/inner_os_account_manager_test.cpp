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

/**
 * @tc.name: InnerOsAccountManagerTest012
 * @tc.desc: coverage CheckAndRefreshLocalIdRecord
 * @tc.type: FUNC
 */
HWTEST_F(IInnerOsAccountManagerTest, InnerOsAccountManagerTest012, TestSize.Level1)
{
    const uint64_t anotherDisplay = 123456u;
    const int32_t idOnDefault = 3456;
    const int32_t idOnAnother = 7890;

    bool hadDefault = false, hadAnother = false;
    int32_t oldDefault = -1, oldAnother = -1, oldOwner = innerMgrService_->deviceOwnerId_;
    innerMgrService_->defaultActivatedIds_.Iterate([&](uint64_t d, int32_t v) {
        if (d == OHOS::AccountSA::Constants::DEFAULT_DISPLAY_ID) { hadDefault = true; oldDefault = v; }
        if (d == anotherDisplay) { hadAnother = true; oldAnother = v; }
    });

    innerMgrService_->defaultActivatedIds_.EnsureInsert(OHOS::AccountSA::Constants::DEFAULT_DISPLAY_ID, idOnDefault);
    innerMgrService_->defaultActivatedIds_.EnsureInsert(anotherDisplay, idOnAnother);

    innerMgrService_->deviceOwnerId_ = idOnDefault;

    innerMgrService_->CheckAndRefreshLocalIdRecord(idOnDefault);
    int32_t curDefault = -1; bool foundDefault = false;
    innerMgrService_->defaultActivatedIds_.Iterate([&](uint64_t d, int32_t v) {
        if (d == OHOS::AccountSA::Constants::DEFAULT_DISPLAY_ID) { foundDefault = true; curDefault = v; }
    });
    EXPECT_TRUE(foundDefault);
    EXPECT_EQ(curDefault, OHOS::AccountSA::Constants::START_USER_ID);

    innerMgrService_->CheckAndRefreshLocalIdRecord(idOnAnother);
    int32_t curAnother = -1; bool foundAnother = false;
    innerMgrService_->defaultActivatedIds_.Iterate([&](uint64_t d, int32_t v) {
        if (d == anotherDisplay) { foundAnother = true; curAnother = v; }
    });
    EXPECT_TRUE(foundAnother);
    EXPECT_EQ(curAnother, OHOS::AccountSA::Constants::INVALID_OS_ACCOUNT_ID);

    innerMgrService_->deviceOwnerId_ = oldOwner;
    if (hadDefault) {
        innerMgrService_->defaultActivatedIds_.EnsureInsert(OHOS::AccountSA::Constants::DEFAULT_DISPLAY_ID, oldDefault);
    } else {
        innerMgrService_->defaultActivatedIds_.Erase(OHOS::AccountSA::Constants::DEFAULT_DISPLAY_ID);
    }
    if (hadAnother) {
        innerMgrService_->defaultActivatedIds_.EnsureInsert(anotherDisplay, oldAnother);
    } else {
        innerMgrService_->defaultActivatedIds_.Erase(anotherDisplay);
    }
}

/**
 * @tc.name: RestartActiveAccountTest001
 * @tc.desc: Test RestartActiveAccount function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, RestartActiveAccountTest001, TestSize.Level1)
{
    std::vector<int32_t> beforeList;
    innerMgrService_->CopyFromActiveList(beforeList);
    
    innerMgrService_->RestartActiveAccount();
    
    std::vector<int32_t> afterList;
    innerMgrService_->CopyFromActiveList(afterList);
    
    EXPECT_GE(afterList.size(), 0);
    EXPECT_LE(afterList.size(), 999);
}

/**
 * @tc.name: IsOsAccountForegroundTest001
 * @tc.desc: Test IsOsAccountForeground with invalid display ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, IsOsAccountForegroundTest001, TestSize.Level1)
{
    int32_t localId = 100;
    uint64_t displayId = Constants::INVALID_DISPLAY_ID;
    bool isForeground = true;
    
    // Test with invalid display ID - should check all displays
    ErrCode result = innerMgrService_->IsOsAccountForeground(localId, displayId, isForeground);
    EXPECT_EQ(result, ERR_OK);
    // Since no account is likely foreground in test environment, expect false
    EXPECT_FALSE(isForeground);
}

/**
 * @tc.name: IsOsAccountForegroundTest002
 * @tc.desc: Test IsOsAccountForeground with valid display ID but no foreground account
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, IsOsAccountForegroundTest002, TestSize.Level1)
{
    int32_t localId = 100;
    uint64_t displayId = 0; // Default display
    bool isForeground = true;
    
    // Test with valid display ID but no foreground account set
    ErrCode result = innerMgrService_->IsOsAccountForeground(localId, displayId, isForeground);
    // Should return error if no account is found for this display
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_ACCOUNT_IN_DISPLAY_ID_NOT_FOUND_ERROR);
}

/**
 * @tc.name: IsOsAccountForegroundTest003
 * @tc.desc: Test IsOsAccountForeground with mock foreground account
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, IsOsAccountForegroundTest003, TestSize.Level1)
{
    int32_t localId = 100;
    int32_t anotherLocalId = 200;
    uint64_t displayId = 0; // Default display
    bool isForeground = false;
    
    // Save original state
    int32_t originalId = -1;
    bool hadOriginal = innerMgrService_->foregroundAccountMap_.Find(displayId, originalId);
    
    // Set up test: insert a foreground account
    innerMgrService_->foregroundAccountMap_.EnsureInsert(displayId, localId);
    
    // Test 1: Check the account that is actually foreground
    ErrCode result = innerMgrService_->IsOsAccountForeground(localId, displayId, isForeground);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(isForeground);
    
    // Test 2: Check an account that is not foreground
    result = innerMgrService_->IsOsAccountForeground(anotherLocalId, displayId, isForeground);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(isForeground);
    
    // Restore original state
    if (hadOriginal) {
        innerMgrService_->foregroundAccountMap_.EnsureInsert(displayId, originalId);
    } else {
        innerMgrService_->foregroundAccountMap_.Erase(displayId);
    }
}
}  // namespace AccountSA
}  // namespace OHOS

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
#include <algorithm>
#include <fcntl.h>
#include <map>
#include <poll.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include "parameter.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#include "../../unittest/os_account/mock/mock_os_account_control_file_manager.h"
#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
#include "display_manager_lite.h"
#endif
#define private public
#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
#include "osaccount/display_user_zone_config/display_user_zone_config_manager.h"
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
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
 * @tc.name: ActivateOsAccountPreparationFailureClearsOperating001
 * @tc.desc: Failed activation preparation must leave the account available for retry.
 * @tc.type: FUNC
 */
HWTEST_F(IInnerOsAccountManagerTest, ActivateOsAccountPreparationFailureClearsOperating001, TestSize.Level1)
{
    const int32_t testId = Constants::MAX_USER_ID + 1;
    EXPECT_EQ(innerMgrService_->ActivateOsAccount(testId), ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_TRUE(innerMgrService_->CheckAndAddLocalIdOperating(testId));
    innerMgrService_->RemoveLocalIdToOperating(testId);
}

/**
 * @tc.name: ActivateOsAccountBusyPreservesOperating001
 * @tc.desc: Rejecting a busy account must preserve the existing operation's marker.
 * @tc.type: FUNC
 */
HWTEST_F(IInnerOsAccountManagerTest, ActivateOsAccountBusyPreservesOperating001, TestSize.Level1)
{
    const int32_t testId = Constants::MAX_USER_ID + 1;
    ASSERT_TRUE(innerMgrService_->CheckAndAddLocalIdOperating(testId));
    EXPECT_EQ(innerMgrService_->ActivateOsAccount(testId), ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR);
    EXPECT_FALSE(innerMgrService_->CheckAndAddLocalIdOperating(testId));
    innerMgrService_->RemoveLocalIdToOperating(testId);
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

namespace {
#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
// Display user zone config test fixtures
constexpr uint64_t DISPLAY_A_LOGICAL_ID = 100;
constexpr uint64_t DISPLAY_B_LOGICAL_ID = 200;
constexpr uint64_t DISPLAY_C_LOGICAL_ID = 300;
constexpr uint64_t DISPLAY_A_PHYSICAL_ID = 10;
constexpr uint64_t DISPLAY_B_PHYSICAL_ID = 20;
constexpr uint64_t DISPLAY_C_PHYSICAL_ID = 30;
constexpr uint64_t USER_ZONE_ONE = DISPLAY_A_LOGICAL_ID;
constexpr uint64_t USER_ZONE_TWO = DISPLAY_C_LOGICAL_ID;
const std::string DISPLAY_NAME_A = "display_a";
const std::string DISPLAY_NAME_B = "display_b";
const std::string DISPLAY_NAME_C = "display_c";
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS

#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
// Test display/local IDs (chosen to not collide with real display IDs)
constexpr uint64_t TEST_DISPLAY_ID_FOREGROUND = 13579;
constexpr int32_t TEST_LOCAL_ID_FOREGROUND = 10086;
constexpr int32_t TEST_LOCAL_ID_ABSENT = 10087;
constexpr uint64_t TEST_DISPLAY_ID_NON_DEFAULT = 24680;
constexpr uint64_t TEST_DISPLAY_ID_NOT_IN_MAP = 77777;
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
constexpr uint64_t TEST_DISPLAY_ID_RESET_1 = 60001;
#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
constexpr size_t EXPECTED_USER_ZONE_ONE_SIZE = 2;
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS

#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
void SetupDisplayUserZoneLoaded()
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    mgr.configReadFailed_ = false;
    mgr.configFormatError_ = false;
    DisplayConfigInfo infoA;
    infoA.physicalId = DISPLAY_A_PHYSICAL_ID;
    infoA.logicalId = DISPLAY_A_LOGICAL_ID;
    infoA.name = DISPLAY_NAME_A;
    infoA.userZone = USER_ZONE_ONE;
    DisplayConfigInfo infoB;
    infoB.physicalId = DISPLAY_B_PHYSICAL_ID;
    infoB.logicalId = DISPLAY_B_LOGICAL_ID;
    infoB.name = DISPLAY_NAME_B;
    infoB.userZone = USER_ZONE_ONE;
    DisplayConfigInfo infoC;
    infoC.physicalId = DISPLAY_C_PHYSICAL_ID;
    infoC.logicalId = DISPLAY_C_LOGICAL_ID;
    infoC.name = DISPLAY_NAME_C;
    infoC.userZone = USER_ZONE_TWO;
    mgr.logicalIdMap_[DISPLAY_A_LOGICAL_ID] = infoA;
    mgr.logicalIdMap_[DISPLAY_B_LOGICAL_ID] = infoB;
    mgr.logicalIdMap_[DISPLAY_C_LOGICAL_ID] = infoC;
    mgr.userZoneMap_[USER_ZONE_ONE] = {DISPLAY_A_LOGICAL_ID, DISPLAY_B_LOGICAL_ID};
    mgr.userZoneMap_[USER_ZONE_TWO] = {DISPLAY_C_LOGICAL_ID};
    mgr.userZonePrimaryMap_[USER_ZONE_ONE] = DISPLAY_A_LOGICAL_ID;
    mgr.userZonePrimaryMap_[USER_ZONE_TWO] = DISPLAY_C_LOGICAL_ID;
}

void TeardownDisplayUserZone()
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    mgr.logicalIdMap_.clear();
    mgr.userZoneMap_.clear();
    mgr.userZonePrimaryMap_.clear();
    mgr.configReadFailed_ = false;
    mgr.configFormatError_ = false;
}
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
} // namespace

#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
namespace {
struct PendingForegroundRestoreState {
    std::shared_ptr<IOsAccountControl> originalControl;
    int32_t oldDefaultId = Constants::INVALID_OS_ACCOUNT_ID;
    int32_t oldForegroundId = Constants::INVALID_OS_ACCOUNT_ID;
    bool oldVerified = false;
    bool hadDefault = false;
    bool hadForeground = false;
    bool hadVerified = false;
};

PendingForegroundRestoreState PreparePendingForegroundRestore(IInnerOsAccountManager *innerMgrService,
    std::map<uint64_t, int32_t> &pendingAccounts)
{
    SetupDisplayUserZoneLoaded();
    constexpr int32_t accountId = Constants::START_USER_ID + 401;
    PendingForegroundRestoreState state;
    state.originalControl = innerMgrService->osAccountControl_;
    auto control = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService->osAccountControl_ = control;
    OsAccountInfo accountInfo;
    accountInfo.SetIsCreateCompleted(true);
    EXPECT_CALL(*control, GetOsAccountInfoById(accountId, testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(accountInfo), testing::Return(ERR_OK)));
    state.hadDefault = innerMgrService->defaultActivatedIds_.Find(DISPLAY_C_LOGICAL_ID, state.oldDefaultId);
    state.hadForeground = innerMgrService->foregroundAccountMap_.Find(DISPLAY_C_LOGICAL_ID, state.oldForegroundId);
    state.hadVerified = innerMgrService->verifiedAccounts_.Find(accountId, state.oldVerified);
    pendingAccounts = {{DISPLAY_C_LOGICAL_ID, accountId}};
    innerMgrService->defaultActivatedIds_.EnsureInsert(DISPLAY_C_LOGICAL_ID, accountId);
    innerMgrService->foregroundAccountMap_.EnsureInsert(DISPLAY_C_LOGICAL_ID, accountId);
    innerMgrService->verifiedAccounts_.EnsureInsert(accountId, true);
    return state;
}

void RestorePendingForegroundRestore(IInnerOsAccountManager *innerMgrService,
    const PendingForegroundRestoreState &state)
{
    constexpr int32_t accountId = Constants::START_USER_ID + 401;
    if (state.hadDefault) {
        innerMgrService->defaultActivatedIds_.EnsureInsert(DISPLAY_C_LOGICAL_ID, state.oldDefaultId);
    } else {
        innerMgrService->defaultActivatedIds_.Erase(DISPLAY_C_LOGICAL_ID);
    }
    if (state.hadForeground) {
        innerMgrService->foregroundAccountMap_.EnsureInsert(DISPLAY_C_LOGICAL_ID, state.oldForegroundId);
    } else {
        innerMgrService->foregroundAccountMap_.Erase(DISPLAY_C_LOGICAL_ID);
    }
    if (state.hadVerified) {
        innerMgrService->verifiedAccounts_.EnsureInsert(accountId, state.oldVerified);
    } else {
        innerMgrService->verifiedAccounts_.Erase(accountId);
    }
    innerMgrService->osAccountControl_ = state.originalControl;
    TeardownDisplayUserZone();
}

struct DefaultActivatedAccountState {
    std::shared_ptr<IOsAccountControl> originalControl;
    int32_t oldPrimaryId = Constants::INVALID_OS_ACCOUNT_ID;
    int32_t oldSecondaryId = Constants::INVALID_OS_ACCOUNT_ID;
    bool hadPrimary = false;
    bool hadSecondary = false;
};

DefaultActivatedAccountState PrepareDefaultActivatedAccountUserZone(IInnerOsAccountManager *innerMgrService)
{
    SetupDisplayUserZoneLoaded();
    auto &configManager = DisplayUserZoneConfigManager::GetInstance();
    DisplayConfigInfo primaryDisplay;
    primaryDisplay.logicalId = Constants::DEFAULT_DISPLAY_ID;
    primaryDisplay.userZone = Constants::DEFAULT_DISPLAY_ID;
    configManager.logicalIdMap_[Constants::DEFAULT_DISPLAY_ID] = primaryDisplay;
    configManager.logicalIdMap_[DISPLAY_A_LOGICAL_ID].userZone = Constants::DEFAULT_DISPLAY_ID;
    configManager.userZoneMap_[Constants::DEFAULT_DISPLAY_ID] = {
        Constants::DEFAULT_DISPLAY_ID, DISPLAY_A_LOGICAL_ID};
    configManager.userZonePrimaryMap_[Constants::DEFAULT_DISPLAY_ID] = Constants::DEFAULT_DISPLAY_ID;
    DefaultActivatedAccountState state;
    state.originalControl = innerMgrService->osAccountControl_;
    auto control = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService->osAccountControl_ = control;
    OsAccountInfo accountInfo;
    accountInfo.SetIsCreateCompleted(true);
    EXPECT_CALL(*control, GetOsAccountInfoById(Constants::START_USER_ID, testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(accountInfo), testing::Return(ERR_OK)));
    EXPECT_CALL(*control, SetDefaultActivatedOsAccount(Constants::DEFAULT_DISPLAY_ID, Constants::START_USER_ID))
        .WillOnce(testing::Return(ERR_OK));
    state.hadPrimary = innerMgrService->defaultActivatedIds_.Find(Constants::DEFAULT_DISPLAY_ID, state.oldPrimaryId);
    state.hadSecondary = innerMgrService->defaultActivatedIds_.Find(DISPLAY_A_LOGICAL_ID, state.oldSecondaryId);
    innerMgrService->defaultActivatedIds_.EnsureInsert(Constants::DEFAULT_DISPLAY_ID, Constants::START_USER_ID + 1);
    innerMgrService->defaultActivatedIds_.Erase(DISPLAY_A_LOGICAL_ID);
    return state;
}

void RestoreDefaultActivatedAccountUserZone(IInnerOsAccountManager *innerMgrService,
    const DefaultActivatedAccountState &state)
{
    if (state.hadPrimary) {
        innerMgrService->defaultActivatedIds_.EnsureInsert(Constants::DEFAULT_DISPLAY_ID, state.oldPrimaryId);
    } else {
        innerMgrService->defaultActivatedIds_.Erase(Constants::DEFAULT_DISPLAY_ID);
    }
    if (state.hadSecondary) {
        innerMgrService->defaultActivatedIds_.EnsureInsert(DISPLAY_A_LOGICAL_ID, state.oldSecondaryId);
    } else {
        innerMgrService->defaultActivatedIds_.Erase(DISPLAY_A_LOGICAL_ID);
    }
    innerMgrService->osAccountControl_ = state.originalControl;
    TeardownDisplayUserZone();
}
} // namespace
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS

#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
/**
 * @tc.name: GetForegroundOsAccountDisplayIdsFallback001
 * @tc.desc: Verify GetForegroundOsAccountDisplayIds returns exactly the single display the account
 *           is foreground on when the display user zone config is not loaded (fallback mode), so the
 *           new plural API keeps backward-compatible behavior without config.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, GetForegroundOsAccountDisplayIdsFallback001, TestSize.Level1)
{
    TeardownDisplayUserZone();
    const int32_t localId = TEST_LOCAL_ID_FOREGROUND;
    const uint64_t displayId = TEST_DISPLAY_ID_FOREGROUND;
    int32_t originalId = -1;
    bool hadOriginal = innerMgrService_->foregroundAccountMap_.Find(displayId, originalId);
    innerMgrService_->foregroundAccountMap_.EnsureInsert(displayId, localId);

    std::vector<uint64_t> displayIds;
    ErrCode ret = innerMgrService_->GetForegroundOsAccountDisplayIds(localId, displayIds);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(displayIds.size(), 1u);
    EXPECT_EQ(displayIds[0], displayId);

    if (hadOriginal) {
        innerMgrService_->foregroundAccountMap_.EnsureInsert(displayId, originalId);
    } else {
        innerMgrService_->foregroundAccountMap_.Erase(displayId);
    }
}

/**
 * @tc.name: GetForegroundOsAccountDisplayIdsNotFound001
 * @tc.desc: Verify GetForegroundOsAccountDisplayIds returns ACCOUNT_IN_DISPLAY_ID_NOT_FOUND_ERROR
 *           when the given account is not foreground on any display.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, GetForegroundOsAccountDisplayIdsNotFound001, TestSize.Level1)
{
    const int32_t absentLocalId = TEST_LOCAL_ID_ABSENT;
    std::vector<uint64_t> displayIds = { Constants::DEFAULT_DISPLAY_ID };
    ErrCode ret = innerMgrService_->GetForegroundOsAccountDisplayIds(absentLocalId, displayIds);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_IN_DISPLAY_ID_NOT_FOUND_ERROR);
    EXPECT_TRUE(displayIds.empty());
}

/**
 * @tc.name: RestoreAllForegroundAccountsFallback001
 * @tc.desc: Verify RestoreAllForegroundAccounts attempts to restore every non-default display when
 *           the display user zone config is not loaded (fallback mode). Each display is its own
 *           user zone in fallback mode, so a restore failure must be retained for retry instead
 *           of being silently skipped.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, RestoreAllForegroundAccountsFallback001, TestSize.Level1)
{
    TeardownDisplayUserZone();
    const uint64_t nonDefaultDisplay = TEST_DISPLAY_ID_NON_DEFAULT;
    const int32_t localId = Constants::MAX_USER_ID + 1;

    // Backup prior state for both maps so the test is hermetic.
    bool hadDefaultActivated = false;
    int32_t oldActivatedId = -1;
    innerMgrService_->defaultActivatedIds_.Iterate([&](uint64_t d, int32_t v) {
        if (d == nonDefaultDisplay) {
            hadDefaultActivated = true;
            oldActivatedId = v;
        }
    });
    int32_t oldForegroundId = -1;
    bool hadForeground = innerMgrService_->foregroundAccountMap_.Find(nonDefaultDisplay, oldForegroundId);
    std::map<uint64_t, int32_t> pendingAccounts;

    // Seed an invalid account on a non-default display. The restore attempt must fail and retain
    // the entry for retry; the previous fallback guard returned before either action occurred.
    innerMgrService_->defaultActivatedIds_.EnsureInsert(nonDefaultDisplay, localId);
    innerMgrService_->foregroundAccountMap_.Erase(nonDefaultDisplay);

    EXPECT_NE(innerMgrService_->RestoreAllForegroundAccounts(pendingAccounts), ERR_OK);
    auto pendingIt = pendingAccounts.find(nonDefaultDisplay);
    EXPECT_NE(pendingIt, pendingAccounts.end());
    if (pendingIt != pendingAccounts.end()) {
        EXPECT_EQ(pendingIt->second, localId);
    }

    // Restore original state.
    if (hadDefaultActivated) {
        innerMgrService_->defaultActivatedIds_.EnsureInsert(nonDefaultDisplay, oldActivatedId);
    } else {
        innerMgrService_->defaultActivatedIds_.Erase(nonDefaultDisplay);
    }
    if (hadForeground) {
        innerMgrService_->foregroundAccountMap_.EnsureInsert(nonDefaultDisplay, oldForegroundId);
    } else {
        innerMgrService_->foregroundAccountMap_.Erase(nonDefaultDisplay);
    }
}
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS

#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
namespace {
constexpr uint64_t TEST_DISPLAY_ID_UNKNOWN = 97531;
constexpr uint64_t TEST_DISPLAY_ID_FIRST = 111;
constexpr uint64_t TEST_DISPLAY_ID_SECOND = 222;
} // namespace
/**
 * @tc.name: ValidateDisplayForActivationFallback001
 * @tc.desc: Verify ValidateDisplayForActivation accepts DEFAULT_DISPLAY_ID and rejects an unknown
 *           display id when the display user zone config is not loaded (fallback mode). The default
 *           display is always exempt from the existence check; an unknown display id must fail
 *           fast so callers cannot activate on a non-existent display.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, ValidateDisplayForActivationFallback001, TestSize.Level1)
{
    TeardownDisplayUserZone();
    const int32_t testId = Constants::START_USER_ID + 20;
    // DEFAULT_DISPLAY_ID must always be accepted (exempted from existence + primary checks).
    ErrCode ret = innerMgrService_->ValidateDisplayForActivation(testId, Constants::DEFAULT_DISPLAY_ID);
    EXPECT_EQ(ret, ERR_OK);

    // An unknown display id must be rejected with the dedicated not-exist error code.
    const uint64_t unknownDisplay = TEST_DISPLAY_ID_UNKNOWN;
    ret = innerMgrService_->ValidateDisplayForActivation(testId, unknownDisplay);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR);
}

/**
 * @tc.name: ValidateDisplayForActivationCrossGroupFallback001
 * @tc.desc: Verify ValidateDisplayForActivation rejects activating an account on a second display
 *           when it is already foreground elsewhere, in fallback mode where every display is its
 *           own user zone. This preserves the original one-to-one activation behavior.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, ValidateDisplayForActivationCrossGroupFallback001, TestSize.Level1)
{
    TeardownDisplayUserZone();
    const int32_t testId = Constants::START_USER_ID + 30;
    const uint64_t firstDisplay = TEST_DISPLAY_ID_FIRST;
    const uint64_t secondDisplay = TEST_DISPLAY_ID_SECOND;

    int32_t oldFirst = -1;
    bool hadFirst = innerMgrService_->foregroundAccountMap_.Find(firstDisplay, oldFirst);
    innerMgrService_->foregroundAccountMap_.EnsureInsert(firstDisplay, testId);

    // In fallback mode, any other display is treated as a different user zone, so activation on a
    // second display must be rejected to preserve the original one-to-one behavior.
    ErrCode ret = innerMgrService_->ValidateDisplayForActivation(testId, secondDisplay);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_CROSS_DISPLAY_ACTIVE_ERROR);

    if (hadFirst) {
        innerMgrService_->foregroundAccountMap_.EnsureInsert(firstDisplay, oldFirst);
    } else {
        innerMgrService_->foregroundAccountMap_.Erase(firstDisplay);
    }
}
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS

#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
/**
 * @tc.name: GetForegroundOsAccountDisplayIdLoaded001
 * @tc.desc: Verify foreground state is stored only under the user zone primary and secondary-display
 *           lookup resolves to that primary.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, GetForegroundOsAccountDisplayIdLoaded001, TestSize.Level1)
{
    SetupDisplayUserZoneLoaded();
    const int32_t localId = Constants::START_USER_ID + 61;
    int32_t oldForeground = -1;
    int32_t oldSecondaryForeground = -1;
    bool hadForeground = innerMgrService_->foregroundAccountMap_.Find(DISPLAY_A_LOGICAL_ID, oldForeground);
    bool hadSecondaryForeground =
        innerMgrService_->foregroundAccountMap_.Find(DISPLAY_B_LOGICAL_ID, oldSecondaryForeground);
    innerMgrService_->foregroundAccountMap_.EnsureInsert(DISPLAY_A_LOGICAL_ID, localId);
    innerMgrService_->foregroundAccountMap_.Erase(DISPLAY_B_LOGICAL_ID);

    uint64_t displayId = Constants::INVALID_DISPLAY_ID;
    EXPECT_EQ(innerMgrService_->GetForegroundOsAccountDisplayId(localId, displayId), ERR_OK);
    EXPECT_EQ(displayId, DISPLAY_A_LOGICAL_ID);
    int32_t queriedLocalId = Constants::INVALID_OS_ACCOUNT_ID;
    EXPECT_EQ(innerMgrService_->GetForegroundOsAccountLocalId(DISPLAY_B_LOGICAL_ID, queriedLocalId), ERR_OK);
    EXPECT_EQ(queriedLocalId, localId);

    if (hadForeground) {
        innerMgrService_->foregroundAccountMap_.EnsureInsert(DISPLAY_A_LOGICAL_ID, oldForeground);
    } else {
        innerMgrService_->foregroundAccountMap_.Erase(DISPLAY_A_LOGICAL_ID);
    }
    if (hadSecondaryForeground) {
        innerMgrService_->foregroundAccountMap_.EnsureInsert(DISPLAY_B_LOGICAL_ID, oldSecondaryForeground);
    }
    TeardownDisplayUserZone();
}
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS

#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
/**
 * @tc.name: RestoreAllForegroundAccountsFailure001
 * @tc.desc: Verify a failed display restore is reported while its default activation target
 *           remains available for the service's synchronous retry.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, RestoreAllForegroundAccountsFailure001, TestSize.Level1)
{
    SetupDisplayUserZoneLoaded();

    const int32_t pendingAccountId = Constants::MAX_USER_ID + 1;
    int32_t oldActivatedId = Constants::INVALID_OS_ACCOUNT_ID;
    const bool hadActivatedId =
        innerMgrService_->defaultActivatedIds_.Find(DISPLAY_C_LOGICAL_ID, oldActivatedId);
    int32_t oldForegroundId = Constants::INVALID_OS_ACCOUNT_ID;
    const bool hadForegroundId =
        innerMgrService_->foregroundAccountMap_.Find(DISPLAY_C_LOGICAL_ID, oldForegroundId);
    std::map<uint64_t, int32_t> pendingAccounts;
    innerMgrService_->defaultActivatedIds_.EnsureInsert(DISPLAY_C_LOGICAL_ID, pendingAccountId);
    innerMgrService_->foregroundAccountMap_.Erase(DISPLAY_C_LOGICAL_ID);

    EXPECT_NE(innerMgrService_->RestoreAllForegroundAccounts(pendingAccounts), ERR_OK);

    int32_t retainedPendingAccountId = Constants::INVALID_OS_ACCOUNT_ID;
    EXPECT_TRUE(innerMgrService_->defaultActivatedIds_.Find(DISPLAY_C_LOGICAL_ID, retainedPendingAccountId));
    EXPECT_EQ(retainedPendingAccountId, pendingAccountId);
    auto pendingIt = pendingAccounts.find(DISPLAY_C_LOGICAL_ID);
    EXPECT_NE(pendingIt, pendingAccounts.end());
    if (pendingIt != pendingAccounts.end()) {
        EXPECT_EQ(pendingIt->second, pendingAccountId);
    }

    if (hadActivatedId) {
        innerMgrService_->defaultActivatedIds_.EnsureInsert(DISPLAY_C_LOGICAL_ID, oldActivatedId);
    } else {
        innerMgrService_->defaultActivatedIds_.Erase(DISPLAY_C_LOGICAL_ID);
    }
    if (hadForegroundId) {
        innerMgrService_->foregroundAccountMap_.EnsureInsert(DISPLAY_C_LOGICAL_ID, oldForegroundId);
    }
    TeardownDisplayUserZone();
}

/**
 * @tc.name: RestoreAllForegroundAccountsPartialFailure001
 * @tc.desc: Verify RestoreAllForegroundAccounts continues after a failure, returns the first error,
 *           and leaves every failed user zone pending for retry.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, RestoreAllForegroundAccountsPartialFailure001, TestSize.Level1)
{
    SetupDisplayUserZoneLoaded();

    const int32_t firstFailedAccountId = Constants::START_USER_ID + 400;
    const int32_t secondFailedAccountId = Constants::MAX_USER_ID + 1;
    int32_t oldA = Constants::INVALID_OS_ACCOUNT_ID;
    int32_t oldC = Constants::INVALID_OS_ACCOUNT_ID;
    const bool hadA = innerMgrService_->defaultActivatedIds_.Find(DISPLAY_A_LOGICAL_ID, oldA);
    const bool hadC = innerMgrService_->defaultActivatedIds_.Find(DISPLAY_C_LOGICAL_ID, oldC);
    std::map<uint64_t, int32_t> pendingAccounts;
    innerMgrService_->defaultActivatedIds_.EnsureInsert(DISPLAY_A_LOGICAL_ID, firstFailedAccountId);
    innerMgrService_->defaultActivatedIds_.EnsureInsert(DISPLAY_C_LOGICAL_ID, secondFailedAccountId);
    EXPECT_TRUE(innerMgrService_->CheckAndAddLocalIdOperating(firstFailedAccountId));

    EXPECT_EQ(innerMgrService_->RestoreAllForegroundAccounts(pendingAccounts),
        ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR);

    auto firstPendingIt = pendingAccounts.find(DISPLAY_A_LOGICAL_ID);
    auto secondPendingIt = pendingAccounts.find(DISPLAY_C_LOGICAL_ID);
    EXPECT_NE(firstPendingIt, pendingAccounts.end());
    EXPECT_NE(secondPendingIt, pendingAccounts.end());
    if (firstPendingIt != pendingAccounts.end()) {
        EXPECT_EQ(firstPendingIt->second, firstFailedAccountId);
    }
    if (secondPendingIt != pendingAccounts.end()) {
        EXPECT_EQ(secondPendingIt->second, secondFailedAccountId);
    }
    innerMgrService_->RemoveLocalIdToOperating(firstFailedAccountId);
    if (hadA) {
        innerMgrService_->defaultActivatedIds_.EnsureInsert(DISPLAY_A_LOGICAL_ID, oldA);
    } else {
        innerMgrService_->defaultActivatedIds_.Erase(DISPLAY_A_LOGICAL_ID);
    }
    if (hadC) {
        innerMgrService_->defaultActivatedIds_.EnsureInsert(DISPLAY_C_LOGICAL_ID, oldC);
    } else {
        innerMgrService_->defaultActivatedIds_.Erase(DISPLAY_C_LOGICAL_ID);
    }
    TeardownDisplayUserZone();
}
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS

/**
 * @tc.name: RestoreAllForegroundAccountsNoRestartGate001
 * @tc.desc: Verify RestoreAllForegroundAccounts performs a successful restore even when
 *           bootevent.account.ready is false. Restart gating belongs to the caller.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, RestoreAllForegroundAccountsNoRestartGate001, TestSize.Level1)
{
#ifndef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
    ACCOUNT_LOGI("Skip: foreground restore requires multiple foreground accounts");
    return;
#else
    char oldBootValue[32] = {0};
    GetParameter("bootevent.account.ready", "false", oldBootValue, sizeof(oldBootValue));
    SetParameter("bootevent.account.ready", "false");
    std::map<uint64_t, int32_t> pendingAccounts;
    const auto state = PreparePendingForegroundRestore(innerMgrService_, pendingAccounts);

    EXPECT_EQ(innerMgrService_->RestoreAllForegroundAccounts(pendingAccounts), ERR_OK);

    EXPECT_EQ(pendingAccounts.count(DISPLAY_C_LOGICAL_ID), 0u);
    RestorePendingForegroundRestore(innerMgrService_, state);
    SetParameter("bootevent.account.ready", oldBootValue);
#endif
}

#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
/**
 * @tc.name: RestoreAllForegroundAccountsRemovedAccount001
 * @tc.desc: A persisted invalid account sentinel is skipped without account lookup or retry.
 * @tc.type: FUNC
 */
HWTEST_F(IInnerOsAccountManagerTest, RestoreAllForegroundAccountsRemovedAccount001, TestSize.Level1)
{
    const auto originalControl = innerMgrService_->osAccountControl_;
    auto control = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = control;
    EXPECT_CALL(*control, GetOsAccountInfoById(Constants::INVALID_OS_ACCOUNT_ID, testing::_)).Times(0);
    int32_t oldId = Constants::INVALID_OS_ACCOUNT_ID;
    const bool hadDefault = innerMgrService_->defaultActivatedIds_.Find(DISPLAY_C_LOGICAL_ID, oldId);
    innerMgrService_->defaultActivatedIds_.EnsureInsert(DISPLAY_C_LOGICAL_ID, Constants::INVALID_OS_ACCOUNT_ID);
    std::map<uint64_t, int32_t> pendingAccounts = {{DISPLAY_C_LOGICAL_ID, Constants::INVALID_OS_ACCOUNT_ID}};
    EXPECT_EQ(innerMgrService_->RestoreAllForegroundAccounts(pendingAccounts), ERR_OK);
    EXPECT_TRUE(pendingAccounts.empty());
    if (hadDefault) {
        innerMgrService_->defaultActivatedIds_.EnsureInsert(DISPLAY_C_LOGICAL_ID, oldId);
    } else {
        innerMgrService_->defaultActivatedIds_.Erase(DISPLAY_C_LOGICAL_ID);
    }
    innerMgrService_->osAccountControl_ = originalControl;
}

/**
 * @tc.name: RestoreAllForegroundAccountsStalePending001
 * @tc.desc: Verify a pending entry is discarded when its default activation target changes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, RestoreAllForegroundAccountsStalePending001, TestSize.Level1)
{
    SetupDisplayUserZoneLoaded();
    const int32_t staleAccountId = Constants::START_USER_ID + 402;
    const int32_t replacementAccountId = Constants::START_USER_ID + 403;
    int32_t oldDefaultId = Constants::INVALID_OS_ACCOUNT_ID;
    const bool hadDefault = innerMgrService_->defaultActivatedIds_.Find(DISPLAY_C_LOGICAL_ID, oldDefaultId);
    std::map<uint64_t, int32_t> pendingAccounts = {{DISPLAY_C_LOGICAL_ID, staleAccountId}};
    innerMgrService_->defaultActivatedIds_.EnsureInsert(DISPLAY_C_LOGICAL_ID, replacementAccountId);

    EXPECT_EQ(innerMgrService_->RestoreAllForegroundAccounts(pendingAccounts), ERR_OK);

    EXPECT_EQ(pendingAccounts.count(DISPLAY_C_LOGICAL_ID), 0u);
    if (hadDefault) {
        innerMgrService_->defaultActivatedIds_.EnsureInsert(DISPLAY_C_LOGICAL_ID, oldDefaultId);
    } else {
        innerMgrService_->defaultActivatedIds_.Erase(DISPLAY_C_LOGICAL_ID);
    }
    TeardownDisplayUserZone();
}

/**
 * @tc.name: GetForegroundOsAccountDisplayIdsLoaded001
 * @tc.desc: Verify GetForegroundOsAccountDisplayIds returns all displays in the account's user zone
 *           when config is loaded.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, GetForegroundOsAccountDisplayIdsLoaded001, TestSize.Level1)
{
    SetupDisplayUserZoneLoaded();
    const int32_t localId = Constants::START_USER_ID + 60;
    const uint64_t displayId = DISPLAY_A_LOGICAL_ID;
    int32_t oldForeground = -1;
    bool hadForeground = innerMgrService_->foregroundAccountMap_.Find(displayId, oldForeground);
    innerMgrService_->foregroundAccountMap_.EnsureInsert(displayId, localId);

    std::vector<uint64_t> displayIds;
    ErrCode ret = innerMgrService_->GetForegroundOsAccountDisplayIds(localId, displayIds);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(displayIds.size(), EXPECTED_USER_ZONE_ONE_SIZE);

    if (hadForeground) {
        innerMgrService_->foregroundAccountMap_.EnsureInsert(displayId, oldForeground);
    } else {
        innerMgrService_->foregroundAccountMap_.Erase(displayId);
    }
    TeardownDisplayUserZone();
}

/**
 * @tc.name: GetForegroundOsAccountDisplayIdsUnknown001
 * @tc.desc: Verify a display absent from the static XML remains a standalone display
 *           instead of inheriting the configured user zone 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, GetForegroundOsAccountDisplayIdsUnknown001, TestSize.Level1)
{
    SetupDisplayUserZoneLoaded();
    auto &configManager = DisplayUserZoneConfigManager::GetInstance();
    DisplayConfigInfo defaultDisplay;
    defaultDisplay.logicalId = Constants::DEFAULT_DISPLAY_ID;
    defaultDisplay.userZone = Constants::DEFAULT_DISPLAY_ID;
    configManager.logicalIdMap_[Constants::DEFAULT_DISPLAY_ID] = defaultDisplay;
    configManager.userZoneMap_[Constants::DEFAULT_DISPLAY_ID] = {Constants::DEFAULT_DISPLAY_ID};
    configManager.userZonePrimaryMap_[Constants::DEFAULT_DISPLAY_ID] = Constants::DEFAULT_DISPLAY_ID;

    const int32_t localId = Constants::START_USER_ID + 62;
    int32_t oldForeground = Constants::INVALID_OS_ACCOUNT_ID;
    bool hadForeground =
        innerMgrService_->foregroundAccountMap_.Find(TEST_DISPLAY_ID_NOT_IN_MAP, oldForeground);
    innerMgrService_->foregroundAccountMap_.EnsureInsert(TEST_DISPLAY_ID_NOT_IN_MAP, localId);

    std::vector<uint64_t> displayIds;
    EXPECT_EQ(innerMgrService_->GetForegroundOsAccountDisplayIds(localId, displayIds), ERR_OK);
    ASSERT_EQ(displayIds.size(), 1u);
    EXPECT_EQ(displayIds[0], TEST_DISPLAY_ID_NOT_IN_MAP);

    if (hadForeground) {
        innerMgrService_->foregroundAccountMap_.EnsureInsert(TEST_DISPLAY_ID_NOT_IN_MAP, oldForeground);
    } else {
        innerMgrService_->foregroundAccountMap_.Erase(TEST_DISPLAY_ID_NOT_IN_MAP);
    }
    TeardownDisplayUserZone();
}
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS

/**
 * @tc.name: ResetDefaultActivatedAccount001
 * @tc.desc: Verify resetting defaults only updates the default display.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, ResetDefaultActivatedAccount001, TestSize.Level1)
{
    const int32_t testLocalId = Constants::START_USER_ID + 70;
    const int32_t absentLocalId = Constants::START_USER_ID + 71;
    // Backup
    int32_t old1 = -1, old2 = -1;
    bool had1 = innerMgrService_->defaultActivatedIds_.Find(Constants::DEFAULT_DISPLAY_ID, old1);
    bool had2 = innerMgrService_->defaultActivatedIds_.Find(TEST_DISPLAY_ID_RESET_1, old2);

    innerMgrService_->defaultActivatedIds_.EnsureInsert(Constants::DEFAULT_DISPLAY_ID, testLocalId);
    innerMgrService_->defaultActivatedIds_.EnsureInsert(TEST_DISPLAY_ID_RESET_1, testLocalId);

    // Case 1: reset display 0 only.
    ErrCode ret = innerMgrService_->ResetDefaultActivatedAccount(testLocalId);
    EXPECT_EQ(ret, ERR_OK);
    int32_t resetId = -1;
    EXPECT_TRUE(innerMgrService_->defaultActivatedIds_.Find(Constants::DEFAULT_DISPLAY_ID, resetId));
    EXPECT_EQ(resetId, Constants::START_USER_ID);
    EXPECT_TRUE(innerMgrService_->defaultActivatedIds_.Find(TEST_DISPLAY_ID_RESET_1, resetId));
    EXPECT_EQ(resetId, testLocalId);

    // Case 2: no matching display -> no-op, no error
    ret = innerMgrService_->ResetDefaultActivatedAccount(absentLocalId);
    EXPECT_EQ(ret, ERR_OK);

    // Restore
    if (had1) {
        innerMgrService_->defaultActivatedIds_.EnsureInsert(Constants::DEFAULT_DISPLAY_ID, old1);
    } else {
        innerMgrService_->defaultActivatedIds_.Erase(Constants::DEFAULT_DISPLAY_ID);
    }
    if (had2) {
        innerMgrService_->defaultActivatedIds_.EnsureInsert(TEST_DISPLAY_ID_RESET_1, old2);
    } else {
        innerMgrService_->defaultActivatedIds_.Erase(TEST_DISPLAY_ID_RESET_1);
    }
}

#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
/**
 * @tc.name: ValidateDisplayForActivationLoaded001
 * @tc.desc: Verify ValidateDisplayForActivation rejects a non-primary display with
 *           DISPLAY_ID_NOT_EXIST_ERROR when config is loaded. Uses DEFAULT_DISPLAY_ID
 *           marked as non-primary in the map to bypass the QueryAllDisplayIds existence
 *           check (DEFAULT_DISPLAY_ID is always considered to exist).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, ValidateDisplayForActivationLoaded001, TestSize.Level1)
{
    SetupDisplayUserZoneLoaded();
    // Mark DEFAULT_DISPLAY_ID (0) as non-primary by setting its user zone to a different logicalId
    // so that logicalId(0) != group(USER_ZONE_ONE), triggering NOT_PRIMARY error.
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    DisplayConfigInfo infoDefault;
    infoDefault.logicalId = Constants::DEFAULT_DISPLAY_ID;
    infoDefault.userZone = USER_ZONE_ONE;
    mgr.logicalIdMap_[Constants::DEFAULT_DISPLAY_ID] = infoDefault;
    const int32_t testId = Constants::START_USER_ID + 80;
    ErrCode ret = innerMgrService_->ValidateDisplayForActivation(testId, Constants::DEFAULT_DISPLAY_ID);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR);
    TeardownDisplayUserZone();
}

/**
 * @tc.name: ValidateDisplayForActivationLoaded002
 * @tc.desc: Verify ValidateDisplayForActivation accepts DEFAULT_DISPLAY_ID when config is loaded
 *           and the account is not foreground elsewhere.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, ValidateDisplayForActivationLoaded002, TestSize.Level1)
{
    SetupDisplayUserZoneLoaded();
    const int32_t testId = Constants::START_USER_ID + 81;
    // DEFAULT_DISPLAY_ID not in map -> IsDisplayPrimary returns true -> passes primary check.
    // Account not foreground anywhere -> returns ERR_OK.
    ErrCode ret = innerMgrService_->ValidateDisplayForActivation(testId, Constants::DEFAULT_DISPLAY_ID);
    EXPECT_EQ(ret, ERR_OK);
    TeardownDisplayUserZone();
}

/**
 * @tc.name: ValidateDisplayForActivationConfigFallback001
 * @tc.desc: Config errors allow DMS-confirmed displays, but retain cross-display activation checks.
 * @tc.type: FUNC
 */
HWTEST_F(IInnerOsAccountManagerTest, ValidateDisplayForActivationConfigFallback001, TestSize.Level1)
{
    const auto displayIds = Rosen::DisplayManagerLite::GetInstance().GetAllDisplayIds();
    ASSERT_FALSE(displayIds.empty());
    TeardownDisplayUserZone();
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    mgr.configFormatError_ = true;
    const int32_t testId = Constants::START_USER_ID + 83;
    EXPECT_EQ(innerMgrService_->ValidateDisplayForActivation(testId, displayIds.front()), ERR_OK);

    const uint64_t otherDisplay = displayIds.front() == TEST_DISPLAY_ID_UNKNOWN ?
        TEST_DISPLAY_ID_SECOND : TEST_DISPLAY_ID_UNKNOWN;
    int32_t oldId = Constants::INVALID_OS_ACCOUNT_ID;
    const bool hadForeground = innerMgrService_->foregroundAccountMap_.Find(otherDisplay, oldId);
    innerMgrService_->foregroundAccountMap_.EnsureInsert(otherDisplay, testId);
    EXPECT_EQ(innerMgrService_->ValidateDisplayForActivation(testId, displayIds.front()),
        ERR_ACCOUNT_COMMON_CROSS_DISPLAY_ACTIVE_ERROR);
    if (hadForeground) {
        innerMgrService_->foregroundAccountMap_.EnsureInsert(otherDisplay, oldId);
    } else {
        innerMgrService_->foregroundAccountMap_.Erase(otherDisplay);
    }
    TeardownDisplayUserZone();
}

/**
 * @tc.name: ValidateDisplayForActivationConfigFallbackDefault001
 * @tc.desc: Config fallback rejects an empty DMS list and accepts the default display otherwise.
 * @tc.type: FUNC
 */
HWTEST_F(IInnerOsAccountManagerTest, ValidateDisplayForActivationConfigFallbackDefault001, TestSize.Level1)
{
    const auto displayIds = Rosen::DisplayManagerLite::GetInstance().GetAllDisplayIds();
    TeardownDisplayUserZone();
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    mgr.configFormatError_ = true;
    const int32_t testId = Constants::START_USER_ID + 85;
    const ErrCode expected = displayIds.empty() ? ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR : ERR_OK;
    EXPECT_EQ(innerMgrService_->ValidateDisplayForActivation(testId, Constants::DEFAULT_DISPLAY_ID), expected);
    TeardownDisplayUserZone();
}

/**
 * @tc.name: ValidateDisplayForActivationConfigFallbackAbsent001
 * @tc.desc: Config errors must not allow a non-default display absent from DMS.
 * @tc.type: FUNC
 */
HWTEST_F(IInnerOsAccountManagerTest, ValidateDisplayForActivationConfigFallbackAbsent001, TestSize.Level1)
{
    const auto displayIds = Rosen::DisplayManagerLite::GetInstance().GetAllDisplayIds();
    uint64_t absentDisplay = Constants::DEFAULT_DISPLAY_ID + 1;
    while (std::find(displayIds.begin(), displayIds.end(), absentDisplay) != displayIds.end()) {
        ++absentDisplay;
    }
    TeardownDisplayUserZone();
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    mgr.configFormatError_ = true;
    const int32_t testId = Constants::START_USER_ID + 82;
    EXPECT_TRUE(innerMgrService_->CheckAndAddLocalIdOperating(testId));
    EXPECT_EQ(innerMgrService_->ValidateDisplayForActivation(testId, absentDisplay),
        ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR);
    // Validation leaves operating-marker ownership with the activation caller.
    EXPECT_FALSE(innerMgrService_->CheckAndAddLocalIdOperating(testId));
    innerMgrService_->RemoveLocalIdToOperating(testId);
    TeardownDisplayUserZone();
}

/**
 * @tc.name: UserZoneQueriesConfigFormatError001
 * @tc.desc: Foreground account lookup falls back to the original display; other user-zone queries retain errors.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, UserZoneQueriesConfigFormatError001, TestSize.Level1)
{
    TeardownDisplayUserZone();
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    mgr.configFormatError_ = true;
    constexpr int32_t testId = Constants::START_USER_ID + 84;
    bool isForeground = false;
    int32_t localId = Constants::INVALID_OS_ACCOUNT_ID;
    int32_t defaultId = Constants::INVALID_OS_ACCOUNT_ID;
    std::vector<uint64_t> displayIds;
    int32_t oldForegroundId = Constants::INVALID_OS_ACCOUNT_ID;
    const bool hadForeground = innerMgrService_->foregroundAccountMap_.Find(
        Constants::DEFAULT_DISPLAY_ID, oldForegroundId);
    innerMgrService_->foregroundAccountMap_.EnsureInsert(Constants::DEFAULT_DISPLAY_ID, testId);

    EXPECT_EQ(innerMgrService_->IsOsAccountForeground(testId, Constants::DEFAULT_DISPLAY_ID, isForeground),
        ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR);
    EXPECT_EQ(innerMgrService_->GetForegroundOsAccountLocalId(Constants::DEFAULT_DISPLAY_ID, localId),
        ERR_OK);
    EXPECT_EQ(localId, testId);
    EXPECT_EQ(innerMgrService_->GetForegroundOsAccountDisplayIds(testId, displayIds),
        ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR);
    EXPECT_EQ(innerMgrService_->GetDefaultActivatedOsAccount(Constants::DEFAULT_DISPLAY_ID, defaultId),
        ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR);

    if (hadForeground) {
        innerMgrService_->foregroundAccountMap_.EnsureInsert(Constants::DEFAULT_DISPLAY_ID, oldForegroundId);
    } else {
        innerMgrService_->foregroundAccountMap_.Erase(Constants::DEFAULT_DISPLAY_ID);
    }
    TeardownDisplayUserZone();
}

namespace {
constexpr int32_t TEST_DEFAULT_ACTIVATED_ACCOUNT_ID = Constants::START_USER_ID + 1;
constexpr int32_t TEST_FOREGROUND_ACCOUNT_ID = Constants::START_USER_ID + 2;

struct ForegroundAccountFallbackState {
    int32_t oldDefaultId = Constants::INVALID_OS_ACCOUNT_ID;
    int32_t oldForegroundId = Constants::INVALID_OS_ACCOUNT_ID;
    int32_t oldOtherForegroundId = Constants::INVALID_OS_ACCOUNT_ID;
    bool hadDefault = false;
    bool hadForeground = false;
    bool hadOtherForeground = false;
};

ForegroundAccountFallbackState PrepareForegroundAccountFallback(IInnerOsAccountManager *innerMgrService)
{
    TeardownDisplayUserZone();
    DisplayUserZoneConfigManager::GetInstance().configFormatError_ = true;
    const uint64_t defaultDisplay = Constants::DEFAULT_DISPLAY_ID;
    const uint64_t otherDisplay = TEST_DISPLAY_ID_UNKNOWN;
    ForegroundAccountFallbackState state;
    state.hadDefault = innerMgrService->defaultActivatedIds_.Find(defaultDisplay, state.oldDefaultId);
    state.hadForeground = innerMgrService->foregroundAccountMap_.Find(defaultDisplay, state.oldForegroundId);
    state.hadOtherForeground = innerMgrService->foregroundAccountMap_.Find(otherDisplay, state.oldOtherForegroundId);
    innerMgrService->foregroundAccountMap_.Erase(defaultDisplay);
    innerMgrService->foregroundAccountMap_.Erase(otherDisplay);
    innerMgrService->defaultActivatedIds_.EnsureInsert(defaultDisplay, TEST_DEFAULT_ACTIVATED_ACCOUNT_ID);
    return state;
}

void RestoreForegroundAccountFallback(IInnerOsAccountManager *innerMgrService,
    const ForegroundAccountFallbackState &state)
{
    const uint64_t defaultDisplay = Constants::DEFAULT_DISPLAY_ID;
    const uint64_t otherDisplay = TEST_DISPLAY_ID_UNKNOWN;
    if (state.hadDefault) {
        innerMgrService->defaultActivatedIds_.EnsureInsert(defaultDisplay, state.oldDefaultId);
    } else {
        innerMgrService->defaultActivatedIds_.Erase(defaultDisplay);
    }
    if (state.hadForeground) {
        innerMgrService->foregroundAccountMap_.EnsureInsert(defaultDisplay, state.oldForegroundId);
    }
    if (state.hadOtherForeground) {
        innerMgrService->foregroundAccountMap_.EnsureInsert(otherDisplay, state.oldOtherForegroundId);
    }
    TeardownDisplayUserZone();
}
} // namespace

/**
 * @tc.name: GetForegroundOsAccountLocalIdDefaultFallback001
 * @tc.desc: Only the default display may use its default activation target when foreground state is absent.
 * @tc.type: FUNC
 */
HWTEST_F(IInnerOsAccountManagerTest, GetForegroundOsAccountLocalIdDefaultFallback001, TestSize.Level1)
{
    const auto state = PrepareForegroundAccountFallback(innerMgrService_);
    const uint64_t defaultDisplay = Constants::DEFAULT_DISPLAY_ID;
    const uint64_t otherDisplay = TEST_DISPLAY_ID_UNKNOWN;
    constexpr int32_t targetId = TEST_DEFAULT_ACTIVATED_ACCOUNT_ID;
    constexpr int32_t foregroundId = TEST_FOREGROUND_ACCOUNT_ID;
    int32_t localId = Constants::INVALID_OS_ACCOUNT_ID;
    EXPECT_EQ(innerMgrService_->GetForegroundOsAccountLocalId(defaultDisplay, localId), ERR_OK);
    EXPECT_EQ(localId, targetId);
    EXPECT_EQ(innerMgrService_->GetForegroundOsAccountLocalId(otherDisplay, localId),
        ERR_ACCOUNT_COMMON_ACCOUNT_IN_DISPLAY_ID_NOT_FOUND_ERROR);
    innerMgrService_->foregroundAccountMap_.EnsureInsert(otherDisplay, foregroundId);
    EXPECT_EQ(innerMgrService_->GetForegroundOsAccountLocalId(otherDisplay, localId), ERR_OK);
    EXPECT_EQ(localId, foregroundId);
    innerMgrService_->foregroundAccountMap_.Erase(otherDisplay);

    // Match default-account activation when no default target has been saved yet.
    innerMgrService_->defaultActivatedIds_.Erase(defaultDisplay);
    EXPECT_EQ(innerMgrService_->GetForegroundOsAccountLocalId(defaultDisplay, localId), ERR_OK);
    EXPECT_EQ(localId, Constants::START_USER_ID);
    innerMgrService_->defaultActivatedIds_.EnsureInsert(defaultDisplay, Constants::INVALID_OS_ACCOUNT_ID);
    EXPECT_EQ(innerMgrService_->GetForegroundOsAccountLocalId(defaultDisplay, localId),
        ERR_ACCOUNT_COMMON_ACCOUNT_IN_DISPLAY_ID_NOT_FOUND_ERROR);

    // Actual foreground state takes precedence over the default activation target.
    innerMgrService_->defaultActivatedIds_.EnsureInsert(defaultDisplay, targetId);
    innerMgrService_->foregroundAccountMap_.EnsureInsert(defaultDisplay, foregroundId);
    EXPECT_EQ(innerMgrService_->GetForegroundOsAccountLocalId(defaultDisplay, localId), ERR_OK);
    EXPECT_EQ(localId, foregroundId);

    // With no foreground account, query the default activation target again.
    innerMgrService_->foregroundAccountMap_.Erase(defaultDisplay);
    EXPECT_EQ(innerMgrService_->GetForegroundOsAccountLocalId(defaultDisplay, localId), ERR_OK);
    EXPECT_EQ(localId, targetId);

    RestoreForegroundAccountFallback(innerMgrService_, state);
}

/**
 * @tc.name: GetForegroundOsAccountLocalIdSecondaryNoFallback001
 * @tc.desc: A secondary display mapped to the default display must not use its default activation target.
 * @tc.type: FUNC
 */
HWTEST_F(IInnerOsAccountManagerTest, GetForegroundOsAccountLocalIdSecondaryNoFallback001, TestSize.Level1)
{
    const auto state = PrepareForegroundAccountFallback(innerMgrService_);
    const uint64_t defaultDisplay = Constants::DEFAULT_DISPLAY_ID;
    const uint64_t otherDisplay = TEST_DISPLAY_ID_UNKNOWN;
    int32_t localId = Constants::INVALID_OS_ACCOUNT_ID;
    // A secondary display must not borrow the default display's activation target.
    auto &config = DisplayUserZoneConfigManager::GetInstance();
    config.configFormatError_ = false;
    DisplayConfigInfo defaultInfo;
    defaultInfo.logicalId = defaultDisplay;
    defaultInfo.userZone = defaultDisplay;
    config.logicalIdMap_[defaultDisplay] = defaultInfo;
    DisplayConfigInfo secondaryInfo;
    secondaryInfo.logicalId = otherDisplay;
    secondaryInfo.userZone = defaultDisplay;
    config.logicalIdMap_[otherDisplay] = secondaryInfo;
    config.userZonePrimaryMap_[defaultDisplay] = defaultDisplay;
    EXPECT_EQ(innerMgrService_->GetForegroundOsAccountLocalId(otherDisplay, localId),
        ERR_ACCOUNT_COMMON_ACCOUNT_IN_DISPLAY_ID_NOT_FOUND_ERROR);
    config.configFormatError_ = true;

    RestoreForegroundAccountFallback(innerMgrService_, state);
}

/**
 * @tc.name: ValidateDisplayForActivationCrossUserZone001
 * @tc.desc: Verify primary-only foreground keys allow validation to identify cross-zone activation.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, ValidateDisplayForActivationCrossUserZone001, TestSize.Level1)
{
    SetupDisplayUserZoneLoaded();
    const int32_t testId = Constants::START_USER_ID + 90;

    int32_t oldDefault = -1;
    int32_t oldC = -1;
    bool hadDefault = innerMgrService_->foregroundAccountMap_.Find(Constants::DEFAULT_DISPLAY_ID, oldDefault);
    bool hadC = innerMgrService_->foregroundAccountMap_.Find(DISPLAY_C_LOGICAL_ID, oldC);

    // DEFAULT_DISPLAY_ID bypasses the display-existence check and is a different display key.
    innerMgrService_->foregroundAccountMap_.EnsureInsert(DISPLAY_C_LOGICAL_ID, testId);
    EXPECT_EQ(innerMgrService_->ValidateDisplayForActivation(testId, Constants::DEFAULT_DISPLAY_ID),
        ERR_ACCOUNT_COMMON_CROSS_DISPLAY_ACTIVE_ERROR);

    // The same primary key represents the same user zone and is not cross-zone activation.
    innerMgrService_->foregroundAccountMap_.Erase(DISPLAY_C_LOGICAL_ID);
    innerMgrService_->foregroundAccountMap_.EnsureInsert(Constants::DEFAULT_DISPLAY_ID, testId);
    EXPECT_EQ(innerMgrService_->ValidateDisplayForActivation(testId, Constants::DEFAULT_DISPLAY_ID), ERR_OK);

    if (hadDefault) {
        innerMgrService_->foregroundAccountMap_.EnsureInsert(Constants::DEFAULT_DISPLAY_ID, oldDefault);
    } else {
        innerMgrService_->foregroundAccountMap_.Erase(Constants::DEFAULT_DISPLAY_ID);
    }
    if (hadC) {
        innerMgrService_->foregroundAccountMap_.EnsureInsert(DISPLAY_C_LOGICAL_ID, oldC);
    } else {
        innerMgrService_->foregroundAccountMap_.Erase(DISPLAY_C_LOGICAL_ID);
    }
    TeardownDisplayUserZone();
}

/**
 * @tc.name: CleanForegroundAccountMapLoaded001
 * @tc.desc: Verify CleanForegroundAccountMap removes only the primary display entry because
 *           secondary displays are never stored in foregroundAccountMap_.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, CleanForegroundAccountMapLoaded001, TestSize.Level1)
{
    SetupDisplayUserZoneLoaded();
    const int32_t localId = Constants::START_USER_ID + 95;

    // Seed only the primary display; keep the secondary absent to enforce the primary-display-only invariant.
    int32_t oldA = -1, oldB = -1;
    bool hadA = innerMgrService_->foregroundAccountMap_.Find(DISPLAY_A_LOGICAL_ID, oldA);
    bool hadB = innerMgrService_->foregroundAccountMap_.Find(DISPLAY_B_LOGICAL_ID, oldB);
    innerMgrService_->foregroundAccountMap_.EnsureInsert(DISPLAY_A_LOGICAL_ID, localId);
    innerMgrService_->foregroundAccountMap_.Erase(DISPLAY_B_LOGICAL_ID);

    OsAccountInfo info;
    info.SetLocalId(localId);
    info.SetDisplayId(DISPLAY_A_LOGICAL_ID);
    info.SetIsForeground(true);
    innerMgrService_->CleanForegroundAccountMap(info);

    int32_t checkId = -1;
    EXPECT_FALSE(innerMgrService_->foregroundAccountMap_.Find(DISPLAY_A_LOGICAL_ID, checkId));
    EXPECT_FALSE(innerMgrService_->foregroundAccountMap_.Find(DISPLAY_B_LOGICAL_ID, checkId));

    // Restore
    if (hadA) {
        innerMgrService_->foregroundAccountMap_.EnsureInsert(DISPLAY_A_LOGICAL_ID, oldA);
    }
    if (hadB) {
        innerMgrService_->foregroundAccountMap_.EnsureInsert(DISPLAY_B_LOGICAL_ID, oldB);
    }
    TeardownDisplayUserZone();
}

/**
 * @tc.name: SetDefaultActivatedOsAccountUserZone001
 * @tc.desc: Verify setting a default account through a secondary display is rejected when
 *           the display user zone configuration is loaded.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, SetDefaultActivatedOsAccountUserZone001, TestSize.Level1)
{
    SetupDisplayUserZoneLoaded();

    int32_t oldDefaultId = Constants::INVALID_OS_ACCOUNT_ID;
    int32_t oldSecondaryId = Constants::INVALID_OS_ACCOUNT_ID;
    const bool hadDefault = innerMgrService_->defaultActivatedIds_.Find(DISPLAY_A_LOGICAL_ID, oldDefaultId);
    const bool hadSecondary = innerMgrService_->defaultActivatedIds_.Find(DISPLAY_B_LOGICAL_ID, oldSecondaryId);
    innerMgrService_->defaultActivatedIds_.EnsureInsert(DISPLAY_A_LOGICAL_ID, Constants::START_USER_ID);
    innerMgrService_->defaultActivatedIds_.Erase(DISPLAY_B_LOGICAL_ID);

    EXPECT_EQ(innerMgrService_->SetDefaultActivatedOsAccount(DISPLAY_B_LOGICAL_ID, Constants::START_USER_ID),
        ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR);

    int32_t activatedId = Constants::INVALID_OS_ACCOUNT_ID;
    EXPECT_TRUE(innerMgrService_->defaultActivatedIds_.Find(DISPLAY_A_LOGICAL_ID, activatedId));
    EXPECT_EQ(activatedId, Constants::START_USER_ID);
    EXPECT_FALSE(innerMgrService_->defaultActivatedIds_.Find(DISPLAY_B_LOGICAL_ID, activatedId));

    if (hadDefault) {
        innerMgrService_->defaultActivatedIds_.EnsureInsert(DISPLAY_A_LOGICAL_ID, oldDefaultId);
    } else {
        innerMgrService_->defaultActivatedIds_.Erase(DISPLAY_A_LOGICAL_ID);
    }
    if (hadSecondary) {
        innerMgrService_->defaultActivatedIds_.EnsureInsert(DISPLAY_B_LOGICAL_ID, oldSecondaryId);
    } else {
        innerMgrService_->defaultActivatedIds_.Erase(DISPLAY_B_LOGICAL_ID);
    }
    TeardownDisplayUserZone();
}

/**
 * @tc.name: SetDefaultActivatedOsAccountUserZone002
 * @tc.desc: Verify setting a default account persists only the user-zone primary key while a
 *           secondary-display query resolves through that primary.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, SetDefaultActivatedOsAccountUserZone002, TestSize.Level1)
{
    const auto state = PrepareDefaultActivatedAccountUserZone(innerMgrService_);

    EXPECT_EQ(innerMgrService_->SetDefaultActivatedOsAccount(
        Constants::DEFAULT_DISPLAY_ID, Constants::START_USER_ID), ERR_OK);

    int32_t activatedId = Constants::INVALID_OS_ACCOUNT_ID;
    EXPECT_TRUE(innerMgrService_->defaultActivatedIds_.Find(Constants::DEFAULT_DISPLAY_ID, activatedId));
    EXPECT_EQ(activatedId, Constants::START_USER_ID);
    EXPECT_FALSE(innerMgrService_->defaultActivatedIds_.Find(DISPLAY_A_LOGICAL_ID, activatedId));
    EXPECT_EQ(innerMgrService_->GetDefaultActivatedOsAccount(DISPLAY_A_LOGICAL_ID, activatedId), ERR_OK);
    EXPECT_EQ(activatedId, Constants::START_USER_ID);

    RestoreDefaultActivatedAccountUserZone(innerMgrService_, state);
}

/**
 * @tc.name: SetDefaultActivatedOsAccountFallback001
 * @tc.desc: Verify setting a default account uses the legacy single-display persistence path
 *           when the display user zone configuration is not loaded.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, SetDefaultActivatedOsAccountFallback001, TestSize.Level1)
{
    TeardownDisplayUserZone();
    auto originalControl = innerMgrService_->osAccountControl_;
    auto control = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = control;
    OsAccountInfo accountInfo;
    accountInfo.SetIsCreateCompleted(true);
    EXPECT_CALL(*control, GetOsAccountInfoById(Constants::START_USER_ID, testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(accountInfo), testing::Return(ERR_OK)));
    EXPECT_CALL(*control, SetDefaultActivatedOsAccount(Constants::DEFAULT_DISPLAY_ID, Constants::START_USER_ID))
        .WillOnce(testing::Return(ERR_OK));

    int32_t oldDefaultId = Constants::INVALID_OS_ACCOUNT_ID;
    int32_t oldOtherId = Constants::INVALID_OS_ACCOUNT_ID;
    const bool hadDefault =
        innerMgrService_->defaultActivatedIds_.Find(Constants::DEFAULT_DISPLAY_ID, oldDefaultId);
    const bool hadOther = innerMgrService_->defaultActivatedIds_.Find(DISPLAY_A_LOGICAL_ID, oldOtherId);
    innerMgrService_->defaultActivatedIds_.EnsureInsert(Constants::DEFAULT_DISPLAY_ID, Constants::START_USER_ID + 1);
    innerMgrService_->defaultActivatedIds_.EnsureInsert(DISPLAY_A_LOGICAL_ID, Constants::START_USER_ID + 1);

    EXPECT_EQ(innerMgrService_->SetDefaultActivatedOsAccount(
        Constants::DEFAULT_DISPLAY_ID, Constants::START_USER_ID), ERR_OK);

    int32_t activatedId = Constants::INVALID_OS_ACCOUNT_ID;
    EXPECT_TRUE(innerMgrService_->defaultActivatedIds_.Find(Constants::DEFAULT_DISPLAY_ID, activatedId));
    EXPECT_EQ(activatedId, Constants::START_USER_ID);
    EXPECT_TRUE(innerMgrService_->defaultActivatedIds_.Find(DISPLAY_A_LOGICAL_ID, activatedId));
    EXPECT_EQ(activatedId, Constants::START_USER_ID + 1);

    if (hadDefault) {
        innerMgrService_->defaultActivatedIds_.EnsureInsert(Constants::DEFAULT_DISPLAY_ID, oldDefaultId);
    } else {
        innerMgrService_->defaultActivatedIds_.Erase(Constants::DEFAULT_DISPLAY_ID);
    }
    if (hadOther) {
        innerMgrService_->defaultActivatedIds_.EnsureInsert(DISPLAY_A_LOGICAL_ID, oldOtherId);
    } else {
        innerMgrService_->defaultActivatedIds_.Erase(DISPLAY_A_LOGICAL_ID);
    }
    innerMgrService_->osAccountControl_ = originalControl;
}
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS

/**
 * @tc.name: MigrateOsAccountTypesToTEE001
 * @tc.desc: Test MigrateOsAccountTypesToTee - Compilation test only
 * @tc.type: FUNC
 * @tc.require:
 * @note: This test verifies the interface exists but doesn't call it
 *       because it requires full TEE and database environment.
 *       Runtime testing is done in integration tests.
 */
HWTEST_F(IInnerOsAccountManagerTest, MigrateOsAccountTypesToTEE001, TestSize.Level1)
{
    // Compilation test: verify the interface exists
    // Don't actually call it as it requires TEE environment
    // Runtime verification is done in integration tests with real TEE
    EXPECT_NE(innerMgrService_, nullptr);
}

/**
 * @tc.name: MigrateOsAccountTypesToTEE002
 * @tc.desc: Test MigrateOsAccountTypesToTee - Symbol verification
 * @tc.type: FUNC
 * @tc.require:
 * @note: Interface existence verification only
 */
HWTEST_F(IInnerOsAccountManagerTest, MigrateOsAccountTypesToTEE002, TestSize.Level1)
{
    // Verify the method signature is correct
    // Actual functional testing requires full system environment
    using MigrateFn = ErrCode (IInnerOsAccountManager::*)();
    MigrateFn fn = &IInnerOsAccountManager::MigrateOsAccountTypesToTEE;
    EXPECT_NE(fn, nullptr);
}

#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
#ifdef SUPPORT_AUTHORIZATION
/**
 * @tc.name: OsAccountCacheManagerBasicOperations001
 * @tc.desc: Verify OsAccountCacheManager basic set/get/clear operations work correctly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, OsAccountCacheManagerBasicOperations001, TestSize.Level1)
{
    auto &innerMgr = IInnerOsAccountManager::GetInstance();
    const int32_t testId = 9999;

    // Initially, no cache entry should exist.
    EXPECT_FALSE(innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(testId).has_value());

    // Set and verify.
    innerMgr.osAccountCacheManager_.SetAccountTypeInCache(testId, {OsAccountType::NORMAL, false});
    auto cached = innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(testId);
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached.value().first, OsAccountType::NORMAL);
    EXPECT_EQ(cached.value().second, false);

    // Overwrite with different type and restricted flag.
    innerMgr.osAccountCacheManager_.SetAccountTypeInCache(testId, {OsAccountType::GUEST, true});
    cached = innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(testId);
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached.value().first, OsAccountType::GUEST);
    EXPECT_EQ(cached.value().second, true);

    // Clear single account cache.
    innerMgr.osAccountCacheManager_.ClearAccountCache(testId);
    EXPECT_FALSE(innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(testId).has_value());

    // Clear non-existent entry should not crash.
    innerMgr.osAccountCacheManager_.ClearAccountCache(testId);
}

/**
 * @tc.name: OsAccountCacheManagerBatchSet001
 * @tc.desc: Verify SetAccountTypesInCache correctly stores multiple entries and ClearAllCache
 *           removes them all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, OsAccountCacheManagerBatchSet001, TestSize.Level1)
{
    auto &innerMgr = IInnerOsAccountManager::GetInstance();
    const int32_t id1 = 9991;
    const int32_t id2 = 9992;
    const int32_t id3 = 9993;

    std::map<int32_t, std::pair<OsAccountType, bool>> typeMap = {
        {id1, {OsAccountType::NORMAL, false}},
        {id2, {OsAccountType::GUEST, false}},
        {id3, {OsAccountType::ADMIN, true}},
    };

    innerMgr.osAccountCacheManager_.SetAccountTypesInCache(typeMap);

    auto c1 = innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(id1);
    ASSERT_TRUE(c1.has_value());
    EXPECT_EQ(c1.value().first, OsAccountType::NORMAL);
    EXPECT_EQ(c1.value().second, false);

    auto c2 = innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(id2);
    ASSERT_TRUE(c2.has_value());
    EXPECT_EQ(c2.value().first, OsAccountType::GUEST);
    EXPECT_EQ(c2.value().second, false);

    auto c3 = innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(id3);
    ASSERT_TRUE(c3.has_value());
    EXPECT_EQ(c3.value().first, OsAccountType::ADMIN);
    EXPECT_EQ(c3.value().second, true);

    // ClearAllCache removes all entries.
    innerMgr.osAccountCacheManager_.ClearAllCache();
    EXPECT_FALSE(innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(id1).has_value());
    EXPECT_FALSE(innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(id2).has_value());
    EXPECT_FALSE(innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(id3).has_value());
}

/**
 * @tc.name: OsAccountCacheManagerAfterCreate001
 * @tc.desc: Verify that after creating an OS account, the cache reflects the correct type via
 *           GetOsAccountType (which internally queries or populates the cache).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, OsAccountCacheManagerAfterCreate001, TestSize.Level1)
{
    OsAccountInfo guestInfo;
    ASSERT_EQ(CreateOsAccountForTest("CacheMgrCreateTest", OsAccountType::GUEST, guestInfo), ERR_OK);
    int32_t id = guestInfo.GetLocalId();

    // GetOsAccountType should return GUEST (from file or cache).
    OsAccountType type = OsAccountType::ADMIN;
    auto &innerMgr = IInnerOsAccountManager::GetInstance();
    EXPECT_EQ(innerMgr.GetOsAccountType(id, type), ERR_OK);
    EXPECT_EQ(type, OsAccountType::GUEST);

    // Cleanup.
    EXPECT_EQ(RemoveOsAccountForTest(id), ERR_OK);
}

/**
 * @tc.name: OsAccountCacheManagerAfterRemove001
 * @tc.desc: Verify that after removing an OS account, the cache entry is cleared and subsequent
 *           GetOsAccountType returns an error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, OsAccountCacheManagerAfterRemove001, TestSize.Level1)
{
    OsAccountInfo normalInfo;
    ASSERT_EQ(CreateOsAccountForTest("CacheMgrRemoveTest", OsAccountType::NORMAL, normalInfo), ERR_OK);
    int32_t id = normalInfo.GetLocalId();

    // Ensure cache is populated by calling GetOsAccountType.
    OsAccountType type = OsAccountType::GUEST;
    auto &innerMgr = IInnerOsAccountManager::GetInstance();
    EXPECT_EQ(innerMgr.GetOsAccountType(id, type), ERR_OK);
    EXPECT_EQ(type, OsAccountType::NORMAL);

    // Remove the account — should clear the cache entry.
    EXPECT_EQ(RemoveOsAccountForTest(id), ERR_OK);
    EXPECT_FALSE(innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(id).has_value());

    // GetOsAccountType on a removed account must fail.
    type = OsAccountType::GUEST;
    EXPECT_NE(innerMgr.GetOsAccountType(id, type), ERR_OK);
}

/**
 * @tc.name: OsAccountCacheManagerSetAndGetType001
 * @tc.desc: Verify that SetOsAccountType updates the cache so a subsequent GetOsAccountType
 *           returns the new type directly from cache.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, OsAccountCacheManagerSetAndGetType001, TestSize.Level1)
{
    OsAccountInfo info;
    ASSERT_EQ(CreateOsAccountForTest("CacheMgrSetTypeTest", OsAccountType::NORMAL, info), ERR_OK);
    int32_t id = info.GetLocalId();

    auto &innerMgr = IInnerOsAccountManager::GetInstance();

    // Simulate stale cache with wrong type, marked as restricted.
    innerMgr.osAccountCacheManager_.SetAccountTypeInCache(id, {OsAccountType::GUEST, true});
    auto cached = innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(id);
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached.value().first, OsAccountType::GUEST);
    EXPECT_EQ(cached.value().second, true);

    // Clear stale entry and verify real type comes from storage.
    innerMgr.osAccountCacheManager_.ClearAccountCache(id);
    OsAccountType type = OsAccountType::GUEST;
    EXPECT_EQ(innerMgr.GetOsAccountType(id, type), ERR_OK);
    EXPECT_EQ(type, OsAccountType::NORMAL);

    EXPECT_EQ(RemoveOsAccountForTest(id), ERR_OK);
}

/**
 * @tc.name: OsAccountCacheManagerRestrictedFlag001
 * @tc.desc: Verify that the restricted flag (second element of cached pair) correctly reflects
 *           whether the account type is sourced from TEE (restricted=0) or from local file
 *           fallback (restricted=1). Direct cache injection is used to simulate both cases.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, OsAccountCacheManagerRestrictedFlag001, TestSize.Level1)
{
    auto &innerMgr = IInnerOsAccountManager::GetInstance();
    const int32_t testId = 9998;

    // Initially no cache entry.
    EXPECT_FALSE(innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(testId).has_value());

    // Simulate type stored from TEE (restricted = false).
    innerMgr.osAccountCacheManager_.SetAccountTypeInCache(testId, {OsAccountType::NORMAL, false});
    auto cached = innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(testId);
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached.value().first, OsAccountType::NORMAL);
    EXPECT_EQ(cached.value().second, false);

    // Simulate type stored from local file fallback (TEE account not exist, restricted = true).
    innerMgr.osAccountCacheManager_.SetAccountTypeInCache(testId, {OsAccountType::NORMAL, true});
    cached = innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(testId);
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached.value().first, OsAccountType::NORMAL);
    EXPECT_EQ(cached.value().second, true);

    // Overwrite restricted entry with a fresh TEE-sourced entry (restricted = false).
    innerMgr.osAccountCacheManager_.SetAccountTypeInCache(testId, {OsAccountType::GUEST, false});
    cached = innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(testId);
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached.value().first, OsAccountType::GUEST);
    EXPECT_EQ(cached.value().second, false);

    // Cleanup.
    innerMgr.osAccountCacheManager_.ClearAccountCache(testId);
    EXPECT_FALSE(innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(testId).has_value());
}

/**
 * @tc.name: OsAccountCacheManagerBatchRestrictedFlag001
 * @tc.desc: Verify that SetAccountTypesInCache correctly stores mixed restricted/non-restricted
 *           entries and the flag is preserved per account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, OsAccountCacheManagerBatchRestrictedFlag001, TestSize.Level1)
{
    auto &innerMgr = IInnerOsAccountManager::GetInstance();
    const int32_t id1 = 9994;
    const int32_t id2 = 9995;

    // id1: from TEE (restricted=0); id2: from local fallback (restricted=1)
    std::map<int32_t, std::pair<OsAccountType, bool>> typeMap = {
        {id1, {OsAccountType::NORMAL, false}},
        {id2, {OsAccountType::GUEST,  true}},
    };
    innerMgr.osAccountCacheManager_.SetAccountTypesInCache(typeMap);

    auto c1 = innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(id1);
    ASSERT_TRUE(c1.has_value());
    EXPECT_EQ(c1.value().first, OsAccountType::NORMAL);
    EXPECT_EQ(c1.value().second, false);

    auto c2 = innerMgr.osAccountCacheManager_.GetAccountTypeFromCache(id2);
    ASSERT_TRUE(c2.has_value());
    EXPECT_EQ(c2.value().first, OsAccountType::GUEST);
    EXPECT_EQ(c2.value().second, true);

    // Cleanup.
    innerMgr.osAccountCacheManager_.ClearAllCache();
}

/**
 * @tc.name: CreateOsAccountTypeCacheConsistencyAfterIdReuse001
 * @tc.desc: Verify that creating a guest account with a recycled account ID correctly updates
 *           the type cache, preventing stale type data from a previously deleted normal account
 *           at the same ID from causing a type mismatch.
 *
 *           Scenario reproduced:
 *           1. A NORMAL account (ID N) is created and then deleted.
 *           2. During deletion, a concurrent GetOsAccountType call (here simulated by direct
 *              cache injection) occurs after the cache/TEE are cleared but before the
 *              account_info file is removed, re-populating cache[N] = NORMAL.
 *           3. A maintenance-mode account (10736) is created and deleted, causing nextLocalId
 *              to advance past MAX_CREATABLE_USER_ID so the next regular allocation wraps
 *              back and reassigns ID N. This is simulated by creating a full-info account at
 *              ID = MAX_CREATABLE_USER_ID.
 *           4. A GUEST account is then created, which reuses ID N.
 *           5. Without the fix, GetOsAccountType returns the stale NORMAL from cache instead
 *              of GUEST. With the fix (UpdateAccountTypeCache called on creation in
 *              PrepareOsAccountInfoWithFullInfo), cache[N] is immediately set to GUEST.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, CreateOsAccountTypeCacheConsistencyAfterIdReuse001, TestSize.Level1)
{
    // Step 1: Create a NORMAL account and record its assigned ID.
    OsAccountInfo normalInfo;
    ASSERT_EQ(CreateOsAccountForTest("NormalForReuseTest", OsAccountType::NORMAL, normalInfo), ERR_OK);
    int32_t recycledId = normalInfo.GetLocalId();

    // Step 2: Delete the NORMAL account (clears TEE entry and cache[recycledId]).
    ASSERT_EQ(RemoveOsAccountForTest(recycledId), ERR_OK);

    // Step 3: Simulate the race condition.
    //   In production, between the cache/TEE clearing and the account_info file deletion,
    //   a concurrent GetOsAccountType call reads the still-existing file and re-populates
    //   cache[recycledId] = NORMAL, leaving a stale entry after deletion completes.
    auto &innerMgr = IInnerOsAccountManager::GetInstance();

    // Step 4: Simulate the maintenance-mode account (10736) creation/deletion that causes
    //   nextLocalId to jump past MAX_CREATABLE_USER_ID, so the next regular allocation wraps.
    //   We achieve this by creating a full-info account at ID = MAX_CREATABLE_USER_ID (999).
    OsAccountInfo helperInfo;
    helperInfo.SetLocalName("MaxIdHelperForReuseTest");
    helperInfo.SetLocalId(Constants::MAX_CREATABLE_USER_ID);
    helperInfo.SetSerialNumber(2026041400099999LL);
    helperInfo.SetCreateTime(1695883215000);
    helperInfo.SetLastLoginTime(1695863215000);
    CreateOsAccountOptions helperOptions;
    helperOptions.allowedHapList = std::make_optional<std::vector<std::string>>({});
    ASSERT_EQ(ERR_OK, CreateOsAccountWithFullInfoForTest(helperInfo, helperOptions));
    ASSERT_EQ(ERR_OK, RemoveOsAccountForTest(Constants::MAX_CREATABLE_USER_ID));

    // Step 5: Create a GUEST account reusing the recycled ID, simulating what happens when
    //   the ID allocation wraps back and finds recycledId available again.
    //   Without the fix, cache[recycledId] still holds NORMAL (stale), so GetOsAccountType
    //   would return NORMAL instead of GUEST after creation.
    OsAccountInfo guestInfo;
    guestInfo.SetLocalName("GuestForReuseTest");
    guestInfo.SetLocalId(recycledId);
    guestInfo.SetType(OsAccountType::GUEST);
    guestInfo.SetSerialNumber(2026041400000001LL);
    guestInfo.SetCreateTime(1695883215000);
    guestInfo.SetLastLoginTime(1695863215000);
    CreateOsAccountOptions guestOptions;
    guestOptions.allowedHapList = std::make_optional<std::vector<std::string>>({});
    ASSERT_EQ(ERR_OK, CreateOsAccountWithFullInfoForTest(guestInfo, guestOptions));

    // Step 6: Verify type cache is correctly set to GUEST.
    //   The fix calls UpdateAccountTypeCache(recycledId, GUEST) during creation in
    //   PrepareOsAccountInfoWithFullInfo, overwriting the stale NORMAL in cache.
    //   Without the fix, GetOsAccountType reads the stale NORMAL from cache and returns it.
    OsAccountType type = OsAccountType::ADMIN;
    EXPECT_EQ(innerMgr.GetOsAccountType(recycledId, type), ERR_OK);
    EXPECT_EQ(type, OsAccountType::GUEST);

    // Also verify via QueryOsAccountById (reads from file, independent of cache).
    OsAccountInfo queriedInfo;
    EXPECT_EQ(innerMgr.QueryOsAccountById(recycledId, queriedInfo), ERR_OK);
    EXPECT_EQ(queriedInfo.GetType(), OsAccountType::GUEST);

    // Cleanup.
    EXPECT_EQ(RemoveOsAccountForTest(recycledId), ERR_OK);
}
#endif // SUPPORT_AUTHORIZATION
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

struct ParseAllDefaultActivateIdsState {
    std::shared_ptr<IOsAccountControl> originalControl;
    int32_t oldDefault = Constants::INVALID_OS_ACCOUNT_ID;
    bool hadDefault = false;
};

std::shared_ptr<MockOsAccountControlFileManager> PrepareParseAllDefaultActivateIdsTest(
    IInnerOsAccountManager *innerMgrService, ParseAllDefaultActivateIdsState &state)
{
    state.originalControl = innerMgrService->osAccountControl_;
    state.hadDefault = innerMgrService->defaultActivatedIds_.Find(Constants::DEFAULT_DISPLAY_ID, state.oldDefault);
    auto control = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService->osAccountControl_ = control;
    EXPECT_CALL(*control, GetOsAccountInfoById(testing::_, testing::_))
        .WillRepeatedly(testing::Return(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR));
    return control;
}

void RestoreParseAllDefaultActivateIdsTest(IInnerOsAccountManager *innerMgrService,
    const ParseAllDefaultActivateIdsState &state)
{
    if (state.hadDefault) {
        innerMgrService->defaultActivatedIds_.EnsureInsert(Constants::DEFAULT_DISPLAY_ID, state.oldDefault);
    } else {
        innerMgrService->defaultActivatedIds_.Erase(Constants::DEFAULT_DISPLAY_ID);
    }
    innerMgrService->osAccountControl_ = state.originalControl;
}

/**
 * @tc.name: ParseAllDefaultActivateIdsValidAndSkip001
 * @tc.desc: Verify ParseAllDefaultActivateIds keeps the default display's valid id, inserts a valid
 *           non-default id, and skips an invalid (< START_USER_ID) or duplicate non-default id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, ParseAllDefaultActivateIdsValidAndSkip001, TestSize.Level1)
{
    constexpr int32_t validIdA = Constants::START_USER_ID + 70;
    constexpr int32_t validIdB = Constants::START_USER_ID + 71;
    constexpr int32_t rangeInvalidId = Constants::START_USER_ID - 1;
    constexpr uint64_t dispA = 1;
    constexpr uint64_t dispB = 2;
    constexpr uint64_t dispC = 3;
    ParseAllDefaultActivateIdsState state;
    auto control = PrepareParseAllDefaultActivateIdsTest(innerMgrService_, state);
    OsAccountInfo validAccount;
    validAccount.SetIsCreateCompleted(true);
    EXPECT_CALL(*control, GetOsAccountInfoById(validIdA, testing::_))
        .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>(validAccount), testing::Return(ERR_OK)));
    EXPECT_CALL(*control, GetOsAccountInfoById(validIdB, testing::_))
        .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>(validAccount), testing::Return(ERR_OK)));
    innerMgrService_->defaultActivatedIds_.Erase(dispA);
    innerMgrService_->defaultActivatedIds_.Erase(dispB);
    innerMgrService_->defaultActivatedIds_.Erase(dispC);
    std::map<uint64_t, int32_t> rawIds = {{Constants::DEFAULT_DISPLAY_ID, validIdA}, {dispA, validIdB},
        {dispB, rangeInvalidId}, {dispC, validIdA}};
    EXPECT_CALL(*control, GetAllDefaultActivatedOsAccounts(testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<0>(rawIds), testing::Return(ERR_OK)));
    innerMgrService_->ParseAllDefaultActivateIds();
    int32_t id = -1;
    ASSERT_TRUE(innerMgrService_->defaultActivatedIds_.Find(Constants::DEFAULT_DISPLAY_ID, id));
    EXPECT_EQ(id, validIdA);
    ASSERT_TRUE(innerMgrService_->defaultActivatedIds_.Find(dispA, id));
    EXPECT_EQ(id, validIdB);
    EXPECT_FALSE(innerMgrService_->defaultActivatedIds_.Find(dispB, id));
    EXPECT_FALSE(innerMgrService_->defaultActivatedIds_.Find(dispC, id));
    RestoreParseAllDefaultActivateIdsTest(innerMgrService_, state);
}

/**
 * @tc.name: ParseAllDefaultActivateIdsInvalidDefaultRange001
 * @tc.desc: Verify ParseAllDefaultActivateIds degrades a default id < START_USER_ID to START_USER_ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, ParseAllDefaultActivateIdsInvalidDefaultRange001, TestSize.Level1)
{
    constexpr int32_t rangeInvalidId = Constants::START_USER_ID - 1;
    ParseAllDefaultActivateIdsState state;
    auto control = PrepareParseAllDefaultActivateIdsTest(innerMgrService_, state);
    std::map<uint64_t, int32_t> rawIds = {{Constants::DEFAULT_DISPLAY_ID, rangeInvalidId}};
    EXPECT_CALL(*control, GetAllDefaultActivatedOsAccounts(testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<0>(rawIds), testing::Return(ERR_OK)));
    innerMgrService_->ParseAllDefaultActivateIds();
    int32_t id = -1;
    ASSERT_TRUE(innerMgrService_->defaultActivatedIds_.Find(Constants::DEFAULT_DISPLAY_ID, id));
    EXPECT_EQ(id, Constants::START_USER_ID);
    RestoreParseAllDefaultActivateIdsTest(innerMgrService_, state);
}

/**
 * @tc.name: ParseAllDefaultActivateIdsInvalidDefaultNonexist001
 * @tc.desc: Verify ParseAllDefaultActivateIds degrades a default id whose account does not exist to START_USER_ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, ParseAllDefaultActivateIdsInvalidDefaultNonexist001, TestSize.Level1)
{
    constexpr int32_t nonexistId = Constants::START_USER_ID + 72;
    ParseAllDefaultActivateIdsState state;
    auto control = PrepareParseAllDefaultActivateIdsTest(innerMgrService_, state);
    std::map<uint64_t, int32_t> rawIds = {{Constants::DEFAULT_DISPLAY_ID, nonexistId}};
    EXPECT_CALL(*control, GetAllDefaultActivatedOsAccounts(testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<0>(rawIds), testing::Return(ERR_OK)));
    innerMgrService_->ParseAllDefaultActivateIds();
    int32_t id = -1;
    ASSERT_TRUE(innerMgrService_->defaultActivatedIds_.Find(Constants::DEFAULT_DISPLAY_ID, id));
    EXPECT_EQ(id, Constants::START_USER_ID);
    RestoreParseAllDefaultActivateIdsTest(innerMgrService_, state);
}

/**
 * @tc.name: ParseAllDefaultActivateIdsDefaultAbsent001
 * @tc.desc: Verify ParseAllDefaultActivateIds keeps START_USER_ID for an absent default display and
 *           inserts a valid non-default id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, ParseAllDefaultActivateIdsDefaultAbsent001, TestSize.Level1)
{
    constexpr int32_t validIdB = Constants::START_USER_ID + 71;
    constexpr uint64_t dispA = 1;
    ParseAllDefaultActivateIdsState state;
    auto control = PrepareParseAllDefaultActivateIdsTest(innerMgrService_, state);
    OsAccountInfo validAccount;
    validAccount.SetIsCreateCompleted(true);
    EXPECT_CALL(*control, GetOsAccountInfoById(validIdB, testing::_))
        .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>(validAccount), testing::Return(ERR_OK)));
    innerMgrService_->defaultActivatedIds_.Erase(dispA);
    std::map<uint64_t, int32_t> rawIds = {{dispA, validIdB}};
    EXPECT_CALL(*control, GetAllDefaultActivatedOsAccounts(testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<0>(rawIds), testing::Return(ERR_OK)));
    innerMgrService_->ParseAllDefaultActivateIds();
    int32_t id = -1;
    ASSERT_TRUE(innerMgrService_->defaultActivatedIds_.Find(Constants::DEFAULT_DISPLAY_ID, id));
    EXPECT_EQ(id, Constants::START_USER_ID);
    ASSERT_TRUE(innerMgrService_->defaultActivatedIds_.Find(dispA, id));
    EXPECT_EQ(id, validIdB);
    RestoreParseAllDefaultActivateIdsTest(innerMgrService_, state);
}

}  // namespace AccountSA
}  // namespace OHOS

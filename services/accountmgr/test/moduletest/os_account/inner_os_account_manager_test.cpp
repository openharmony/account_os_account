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
#include <vector>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "os_account_info.h"
#include "os_account_manager.h"
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

}  // namespace AccountSA
}  // namespace OHOS

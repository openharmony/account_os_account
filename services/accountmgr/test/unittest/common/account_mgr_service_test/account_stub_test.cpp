/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include <cerrno>
#include <gtest/gtest.h>

#include "account_log_wrapper.h"
#define private public
#include "account_mgr_service.h"
#include "account_stub.h"
#undef private
#include "account_info.h"
#include "account_test_common.h"
#include "iaccount.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "parcel.h"
#include "token_setproc.h"
#include "want.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const uid_t TEST_UID = 100;
const uid_t ROOT_UID = 0;
const std::string TEST_ACCOUNT_NAME = "TestAccountName";
const std::string TEST_ACCOUNT_UID = "TestAccountUid";
const std::string INVALID_ACCOUNT_EVENT = "InvalidAccountEvent";
const std::string TEST_BUNDLE_NAME = "TestBundleName";
const int32_t INVALID_USERID = -1;
const std::string TEST_NICKNAME = "NickName_Test";
const std::string TEST_AVATAR = "Avatar_Test";
const std::string KEY_ACCOUNT_INFO_SCALABLEDATA = "age";
std::string g_eventLogin = OHOS_ACCOUNT_EVENT_LOGIN;
const std::string STRING_TEST_NAME = "test_account_name";
} // namespace

class AccountStubModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    sptr<AccountMgrService> accountService_ = nullptr;
};

void AccountStubModuleTest::SetUpTestCase(void) {}

void AccountStubModuleTest::TearDownTestCase(void) {}

void AccountStubModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest* test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo* testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    accountService_ = new (std::nothrow) AccountMgrService();
    ASSERT_NE(accountService_, nullptr);
}

void AccountStubModuleTest::TearDown(void) {}

/**
 * @tc.name: AccountStubModuleTest_UpdateOhosAccountInfo_001
 * @tc.desc: UpdateOhosAccountInfo permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_UpdateOhosAccountInfo_001, TestSize.Level3)
{
    setuid(TEST_UID);
    std::string accountName = "";
    std::string uid = "";
    std::string eventStr = "";
    EXPECT_EQ(accountService_->UpdateOhosAccountInfo(accountName, uid, eventStr),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_UpdateOhosAccountInfo_002
 * @tc.desc: UpdateOhosAccountInfo without accountName.
 * @tc.type: coverage
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_UpdateOhosAccountInfo_002, TestSize.Level3)
{
    uint64_t selfTokenid = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("accountmgr"));
    setuid(ROOT_UID);
    std::string accountName = "";
    std::string uid = TEST_ACCOUNT_UID;
    std::string eventStr = INVALID_ACCOUNT_EVENT;
    EXPECT_EQ(accountService_->UpdateOhosAccountInfo(accountName, uid, eventStr), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    SetSelfTokenID(selfTokenid);
}

/**
 * @tc.name: AccountStubModuleTest_UpdateOhosAccountInfo_003
 * @tc.desc: UpdateOhosAccountInfo without uid.
 * @tc.type: coverage
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_UpdateOhosAccountInfo_003, TestSize.Level3)
{
    uint64_t selfTokenid = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("accountmgr"));
    setuid(ROOT_UID);
    std::string accountName = TEST_ACCOUNT_NAME;
    std::string uid = "";
    std::string eventStr = INVALID_ACCOUNT_EVENT;
    EXPECT_EQ(accountService_->UpdateOhosAccountInfo(accountName, uid, eventStr), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    SetSelfTokenID(selfTokenid);
}

/**
 * @tc.name: AccountStubModuleTest_UpdateOhosAccountInfo_004
 * @tc.desc: UpdateOhosAccountInfo with invalid event.
 * @tc.type: coverage
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_UpdateOhosAccountInfo_004, TestSize.Level3)
{
    uint64_t selfTokenid = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("accountmgr"));
    setuid(ROOT_UID);
    std::string accountName = TEST_ACCOUNT_NAME;
    std::string uid = TEST_ACCOUNT_UID;
    std::string eventStr = INVALID_ACCOUNT_EVENT;
    EXPECT_EQ(accountService_->UpdateOhosAccountInfo(accountName, uid, eventStr), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    SetSelfTokenID(selfTokenid);
}

/**
 * @tc.name: AccountStubModuleTest_SetOhosAccountInfo_001
 * @tc.desc: SetOhosAccountInfo permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_SetOhosAccountInfo_001, TestSize.Level3)
{
    setuid(TEST_UID);
    OhosAccountInfo ohosAccountInfo;
    std::string eventStr = INVALID_ACCOUNT_EVENT;
    EXPECT_EQ(accountService_->SetOhosAccountInfo(ohosAccountInfo, eventStr),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_SetOhosAccountInfo_003
 * @tc.desc: SetOhosAccountInfo with nickname oversize.
 * @tc.type: coverage
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_SetOhosAccountInfo_003, TestSize.Level3)
{
    uint64_t selfTokenid = IPCSkeleton::GetSelfTokenID();
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission(ALL_ACCOUNT_PERMISSION_LIST, tokenID));
    setuid(ROOT_UID);
    OhosAccountInfo info;
    info.nickname_ = std::string(Constants::NICKNAME_MAX_SIZE + 1, '#');
    std::string eventStr = INVALID_ACCOUNT_EVENT;
    EXPECT_EQ(accountService_->SetOhosAccountInfo(info, eventStr),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    SetSelfTokenID(selfTokenid);
}

/**
 * @tc.name: AccountStubModuleTest_SetOsAccountDistributedInfo_001
 * @tc.desc: SetOsAccountDistributedInfo permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_SetOsAccountDistributedInfo_001, TestSize.Level3)
{
    setuid(TEST_UID);
    int32_t localId = INVALID_USERID;
    OhosAccountInfo ohosAccountInfo;
    std::string eventStr = INVALID_ACCOUNT_EVENT;
    EXPECT_EQ(accountService_->SetOsAccountDistributedInfo(localId, ohosAccountInfo, eventStr),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_QueryOhosAccountInfo_001
 * @tc.desc: SetOhosAccountInfoByUserId permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_QueryOhosAccountInfo_001, TestSize.Level3)
{
    setuid(TEST_UID);
    std::string bundleName = TEST_ACCOUNT_NAME;
    std::string uid = TEST_ACCOUNT_UID;
    int32_t status = INVALID_USERID;
    EXPECT_EQ(accountService_->QueryOhosAccountInfo(bundleName, uid, status),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_GetOhosAccountInfo_001
 * @tc.desc: GetOhosAccountInfo permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_GetOhosAccountInfo_001, TestSize.Level3)
{
    setuid(TEST_UID);
    OhosAccountInfo info;
    EXPECT_EQ(accountService_->GetOhosAccountInfo(info), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_GetOsAccountDistributedInfo_001
 * @tc.desc: GetOsAccountDistributedInfo permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_GetOsAccountDistributedInfo_001, TestSize.Level3)
{
    setuid(TEST_UID);
    int32_t localId = INVALID_USERID;
    OhosAccountInfo info;
    EXPECT_EQ(accountService_->GetOsAccountDistributedInfo(localId, info), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_GetOsAccountDistributedInfo_002
 * @tc.desc: GetOsAccountDistributedInfo permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_GetOsAccountDistributedInfo_002, TestSize.Level3)
{
    setuid(TEST_UID);
    int32_t localId = INVALID_USERID;
    std::string accountName = TEST_ACCOUNT_NAME;
    std::string uid = TEST_ACCOUNT_UID;
    int32_t status = INVALID_USERID;
    EXPECT_EQ(accountService_->QueryOsAccountDistributedInfo(localId, accountName, uid, status),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_QueryDistributedVirtualDeviceId_001
 * @tc.desc: QueryDistributedVirtualDeviceId permission error.
 * @tc.type: coverage
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_QueryDistributedVirtualDeviceId_001, TestSize.Level3)
{
    setuid(TEST_UID);
    std::string bundleName = TEST_ACCOUNT_NAME;
    int32_t localId = INVALID_USERID;
    std::string dvid = TEST_ACCOUNT_UID;
    EXPECT_EQ(accountService_->QueryDistributedVirtualDeviceId(bundleName, localId, dvid),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_QueryDistributedVirtualDeviceId_004
 * @tc.desc: QueryDistributedVirtualDeviceId with invalid localId.
 * @tc.type: coverage
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_QueryDistributedVirtualDeviceId_004, TestSize.Level3)
{
    uint64_t selfTokenid = IPCSkeleton::GetSelfTokenID();
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission(ALL_ACCOUNT_PERMISSION_LIST, tokenID));
    setuid(ROOT_UID);
    std::string bundleName = TEST_ACCOUNT_NAME;
    int32_t localId = INVALID_USERID;
    std::string dvid = "";
    EXPECT_EQ(accountService_->QueryDistributedVirtualDeviceId(bundleName, localId, dvid),
        ERR_ACCOUNT_DATADEAL_NOT_READY);
    SetSelfTokenID(selfTokenid);
}

/**
 * @tc.name: SubscribeDistributedAccountEvent_001
 * @tc.desc: Test SubscribeDistributedAccountEvent with eventListener is null.
 * @tc.type: FUNC
 */
HWTEST_F(AccountStubModuleTest, SubscribeDistributedAccountEvent_001, TestSize.Level3)
{
    uint64_t selfTokenid = IPCSkeleton::GetSelfTokenID();
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission(ALL_ACCOUNT_PERMISSION_LIST, tokenID));
    sptr<IRemoteObject> eventListener = nullptr;
    EXPECT_EQ(accountService_->SubscribeDistributedAccountEvent(TEST_UID, eventListener),
        ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
    SetSelfTokenID(selfTokenid);
}

/**
 * @tc.name: UnSubscribeDistributedAccountEvent_001
 * @tc.desc: Test UnSubscribeDistributedAccountEvent with eventListener is null.
 * @tc.type: FUNC
 */
HWTEST_F(AccountStubModuleTest, UnSubscribeDistributedAccountEvent_001, TestSize.Level3)
{
    uint64_t selfTokenid = IPCSkeleton::GetSelfTokenID();
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission(ALL_ACCOUNT_PERMISSION_LIST, tokenID));
    sptr<IRemoteObject> eventListener = nullptr;
    EXPECT_EQ(accountService_->UnsubscribeDistributedAccountEvent(TEST_UID, eventListener),
        ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
    SetSelfTokenID(selfTokenid);
}
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "account_info_parcel.h"
#define private public
#include "account_mgr_service.h"
#include "account_stub.h"
#undef private
#include "parcel.h"
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
} // namespace

class AccountStubModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    sptr<AccountMgrService> accountServie_ = nullptr;
};

void AccountStubModuleTest::SetUpTestCase(void)
{}

void AccountStubModuleTest::TearDownTestCase(void)
{}

void AccountStubModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    accountServie_ = new (std::nothrow) AccountMgrService();
    ASSERT_NE(accountServie_, nullptr);
}

void AccountStubModuleTest::TearDown(void)
{}

/**
 * @tc.name: AccountStubModuleTest_CmdUpdateOhosAccountInfo_001
 * @tc.desc: CmdUpdateOhosAccountInfo permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdUpdateOhosAccountInfo_001, TestSize.Level3)
{
    setuid(TEST_UID);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(accountServie_->CmdUpdateOhosAccountInfo(data, reply), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_CmdUpdateOhosAccountInfo_002
 * @tc.desc: CmdUpdateOhosAccountInfo without accountName.
 * @tc.type: coverage
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdUpdateOhosAccountInfo_002, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(accountServie_->CmdUpdateOhosAccountInfo(data, reply), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
}

/**
 * @tc.name: AccountStubModuleTest_CmdUpdateOhosAccountInfo_003
 * @tc.desc: CmdUpdateOhosAccountInfo without uid.
 * @tc.type: coverage
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdUpdateOhosAccountInfo_003, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteString16(Str8ToStr16(TEST_ACCOUNT_NAME));
    EXPECT_EQ(accountServie_->CmdUpdateOhosAccountInfo(data, reply), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
}

/**
 * @tc.name: AccountStubModuleTest_CmdUpdateOhosAccountInfo_004
 * @tc.desc: CmdUpdateOhosAccountInfo with invalid event.
 * @tc.type: coverage
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdUpdateOhosAccountInfo_004, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteString16(Str8ToStr16(TEST_ACCOUNT_NAME));
    data.WriteString16(Str8ToStr16(TEST_ACCOUNT_UID));
    data.WriteString16(Str8ToStr16(INVALID_ACCOUNT_EVENT));
    EXPECT_EQ(accountServie_->CmdUpdateOhosAccountInfo(data, reply), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AccountStubModuleTest_CmdSetOhosAccountInfo_001
 * @tc.desc: CmdSetOhosAccountInfo permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdSetOhosAccountInfo_001, TestSize.Level3)
{
    setuid(TEST_UID);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(accountServie_->CmdSetOhosAccountInfo(data, reply), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_CmdSetOhosAccountInfo_002
 * @tc.desc: CmdSetOhosAccountInfo without OhosAccountInfo.
 * @tc.type: coverage
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdSetOhosAccountInfo_002, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(accountServie_->CmdSetOhosAccountInfo(data, reply), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
}

/**
 * @tc.name: AccountStubModuleTest_CmdSetOhosAccountInfo_003
 * @tc.desc: CmdSetOhosAccountInfo with nickname oversize.
 * @tc.type: coverage
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdSetOhosAccountInfo_003, TestSize.Level3)
{
    OhosAccountInfo info;
    info.nickname_ = std::string(Constants::NICKNAME_MAX_SIZE + 1, '#');
    MessageParcel data;
    MessageParcel reply;
    WriteOhosAccountInfo(data, info);
    EXPECT_EQ(accountServie_->CmdSetOhosAccountInfo(data, reply), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AccountStubModuleTest_CmdSetOhosAccountInfoByUserId_001
 * @tc.desc: CmdSetOhosAccountInfoByUserId permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdSetOhosAccountInfoByUserId_001, TestSize.Level3)
{
    setuid(TEST_UID);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(accountServie_->CmdSetOhosAccountInfo(data, reply), ERR_OK);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_CmdQueryOhosAccountInfo_001
 * @tc.desc: CmdSetOhosAccountInfoByUserId permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdQueryOhosAccountInfo_001, TestSize.Level3)
{
    setuid(TEST_UID);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(accountServie_->CmdQueryOhosAccountInfo(data, reply), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_CmdGetOhosAccountInfo_001
 * @tc.desc: CmdGetOhosAccountInfo permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdGetOhosAccountInfo_001, TestSize.Level3)
{
    setuid(TEST_UID);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(accountServie_->CmdGetOhosAccountInfo(data, reply), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_CmdGetOhosAccountInfoByUserId_001
 * @tc.desc: CmdGetOhosAccountInfoByUserId permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdGetOhosAccountInfoByUserId_001, TestSize.Level3)
{
    setuid(TEST_UID);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(accountServie_->CmdGetOhosAccountInfoByUserId(data, reply), ERR_OK);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_CmdQueryOhosAccountInfoByUserId_001
 * @tc.desc: CmdQueryOhosAccountInfoByUserId permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdQueryOhosAccountInfoByUserId_001, TestSize.Level3)
{
    setuid(TEST_UID);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(accountServie_->CmdGetOhosAccountInfoByUserId(data, reply), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_CmdQueryDVIDByBundleName_001
 * @tc.desc: CmdQueryDVIDByBundleName permission error.
 * @tc.type: coverage
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdQueryDVIDByBundleName_001, TestSize.Level3)
{
    setuid(TEST_UID);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(accountServie_->CmdQueryDVIDByBundleName(data, reply), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_CmdQueryDVIDByBundleName_002
 * @tc.desc: CmdQueryDVIDByBundleName without bundleName.
 * @tc.type: coverage
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdQueryDVIDByBundleName_002, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(accountServie_->CmdQueryDVIDByBundleName(data, reply), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
}

/**
 * @tc.name: AccountStubModuleTest_CmdQueryDVIDByBundleName_003
 * @tc.desc: CmdQueryDVIDByBundleName without localId.
 * @tc.type: coverage
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdQueryDVIDByBundleName_003, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(TEST_BUNDLE_NAME);
    EXPECT_EQ(accountServie_->CmdQueryDVIDByBundleName(data, reply), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
}

/**
 * @tc.name: AccountStubModuleTest_CmdQueryDVIDByBundleName_004
 * @tc.desc: CmdQueryDVIDByBundleName with invalid localId.
 * @tc.type: coverage
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdQueryDVIDByBundleName_004, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteInt32(INVALID_USERID);
    EXPECT_EQ(accountServie_->CmdQueryDVIDByBundleName(data, reply), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_ACCOUNT_DATADEAL_NOT_READY);
}
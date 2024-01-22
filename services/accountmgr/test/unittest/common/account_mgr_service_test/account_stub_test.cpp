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
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdUpdateOhosAccountInfo_001, TestSize.Level0)
{
    setuid(TEST_UID);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(accountServie_->CmdUpdateOhosAccountInfo(data, reply), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_CmdSetOhosAccountInfo_001
 * @tc.desc: CmdSetOhosAccountInfo permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdSetOhosAccountInfo_001, TestSize.Level0)
{
    setuid(TEST_UID);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(accountServie_->CmdSetOhosAccountInfo(data, reply), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_CmdSetOhosAccountInfoByUserId_001
 * @tc.desc: CmdSetOhosAccountInfoByUserId permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdSetOhosAccountInfoByUserId_001, TestSize.Level0)
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
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdQueryOhosAccountInfo_001, TestSize.Level0)
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
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdGetOhosAccountInfo_001, TestSize.Level0)
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
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdGetOhosAccountInfoByUserId_001, TestSize.Level0)
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
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdQueryOhosAccountInfoByUserId_001, TestSize.Level0)
{
    setuid(TEST_UID);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(accountServie_->CmdGetOhosAccountInfoByUserId(data, reply), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: AccountStubModuleTest_CmdQueryOhosQuitTips_001
 * @tc.desc: CmdQueryOhosQuitTips permission error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStubModuleTest, AccountStubModuleTest_CmdQueryOhosQuitTips_001, TestSize.Level0)
{
    setuid(TEST_UID);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(accountServie_->CmdQueryOhosQuitTips(data, reply), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}
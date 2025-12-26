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
#include "os_account_constants.h"
#include "os_account_manager.h"
#include "os_account_info.h"
#define private public
#include "iinner_os_account_manager.h"
#undef private
#include "os_account_control_file_manager.h"
#include "os_account_paramter_mock_test.h"

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

const int TEST_USER_ID10 = 10;

class OsAccountInnerAccountmgrMockCov : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    IInnerOsAccountManager *innerMgrService_ = &IInnerOsAccountManager::GetInstance();
};


void OsAccountInnerAccountmgrMockCov::SetUpTestCase(void)
{}

void OsAccountInnerAccountmgrMockCov::TearDownTestCase(void)
{}

void OsAccountInnerAccountmgrMockCov::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
}

void OsAccountInnerAccountmgrMockCov::TearDown(void)
{}

/**
 * @tc.name: SendMsgForAccountStopTest001
 * @tc.desc: Test SendMsgForAccountStop fail
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountInnerAccountmgrMockCov, SendMsgForAccountStopTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    g_errType = ERR_INTERFACE_CHECKALLAPPDIED;
    ErrCode errCode = innerMgrService_->SendMsgForAccountStop(osAccountInfo);
    EXPECT_EQ(errCode, ERR_INTERFACE_FAILED);

    g_errType = ERR_INTERFACE_STORAGE_STOP;
    errCode = innerMgrService_->SendMsgForAccountStop(osAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER);
}

/**
 * @tc.name: SendMsgForAccountRemoveTest001
 * @tc.desc: Test SendMsgForAccountRemove fail
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountInnerAccountmgrMockCov, SendMsgForAccountRemoveTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    g_errType = ERR_INTERFACE_STORAGE_REMOVE;
    ErrCode errCode = innerMgrService_->SendMsgForAccountRemove(osAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER);

    g_errType = ERR_INTERFACE_IDM_DELETE;
    errCode = innerMgrService_->SendMsgForAccountRemove(osAccountInfo);
    EXPECT_EQ(errCode, ERR_INTERFACE_FAILED);
}

/**
 * @tc.name: SendToStorageAndAMSAccountStartTest001
 * @tc.desc: Test SendToStorageAndAMSAccountStart fail
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountInnerAccountmgrMockCov, SendToStorageAndAMSAccountStartTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    g_errType = ERR_INTERFACE_STORAGE_START;
    ErrCode errCode = innerMgrService_->SendToStorageAndAMSAccountStart(osAccountInfo, true, 0, false, 0);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER);
}

/**
 * @tc.name: SendMsgForAccountDeactivateTest001
 * @tc.desc: Test SendMsgForAccountDeactivate fail
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountInnerAccountmgrMockCov, SendMsgForAccountDeactivateTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    g_errType = ERR_INTERFACE_AMS_DEACTIVATION;
    ErrCode errCode = innerMgrService_->SendMsgForAccountDeactivate(osAccountInfo);
    EXPECT_EQ(errCode, ERR_INTERFACE_FAILED);
}

/**
 * @tc.name: InitTest001
 * @tc.desc: Test Init fail
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountInnerAccountmgrMockCov, InitTest001, TestSize.Level1)
{
    const std::set<int32_t> initAccounts = { Constants::START_USER_ID };
    g_errType = ERR_INTERFACE_BMS_CREATE;
    bool ret = innerMgrService_->Init(initAccounts);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: CheckAndAddLocalIdOperatingTest001
 * @tc.desc: Test CheckAndAddLocalIdOperating fail
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountInnerAccountmgrMockCov, CheckAndAddLocalIdOperatingTest001, TestSize.Level1)
{
    bool ret = innerMgrService_->CheckAndAddLocalIdOperating(TEST_USER_ID10);
    EXPECT_EQ(ret, true);
    ret = innerMgrService_->CheckAndAddLocalIdOperating(TEST_USER_ID10);
    EXPECT_EQ(ret, false);

    ErrCode errCode = innerMgrService_->DeactivateOsAccount(TEST_USER_ID10, false);
    EXPECT_EQ(errCode, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR);

    DomainAccountInfo domainInfo;
    errCode = innerMgrService_->UpdateAccountInfoByDomainAccountInfo(TEST_USER_ID10, domainInfo);
    EXPECT_EQ(errCode, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR);

    errCode = innerMgrService_->SetOsAccountToBeRemoved(TEST_USER_ID10, false);
    EXPECT_EQ(errCode, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR);
}
}  // namespace AccountSA
}  // namespace OHOS

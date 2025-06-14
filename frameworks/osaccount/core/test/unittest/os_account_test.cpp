/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include <memory>
#include <thread>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "account_proxy.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "os_account_proxy.h"
#define private public
#include "os_account.h"
#undef private
#include "singleton.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_EMPTY = "";
const std::string STRING_NAME = "name";
const std::int32_t MAIN_ACCOUNT_ID = 100;
const std::int32_t WAIT_A_MOMENT = 3000;
const std::int32_t ILLEGAL_LOCAL_ID = -1;
const std::string STRING_NAME_OUT_OF_RANGE(1200, '1'); // length 1200
const std::string STRING_PHOTO_OUT_OF_RANGE(1024 * 1024 + 1, '1'); // length 1024*1024+1
const std::string STRING_DOMAIN_NAME_OUT_OF_RANGE(200, '1'); // length 200
const std::string STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE(600, '1'); // length 600
const std::string STRING_CONSTRAINT_OUT_OF_RANGE(200, '1'); // length 200
const std::vector<std::string> CONSTANTS_VECTOR {
    "constraint.print",
    "constraint.screen.timeout.set",
    "constraint.share.into.profile"
};
const std::string STRING_DOMAIN_VALID = "TestDomainUT";
const std::string STRING_DOMAIN_ACCOUNT_NAME_VALID = "TestDomainAccountNameUT";
std::shared_ptr<OsAccount> g_osAccount = nullptr;
sptr<IOsAccount> osAccountProxy_ = nullptr;
const std::uint32_t MAX_WAIT_FOR_READY_CNT = 10;
}  // namespace
class OsAccountTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void OsAccountTest::SetUpTestCase(void)
{
    ASSERT_TRUE(MockTokenId("accountmgr"));
    g_osAccount = std::make_shared<OsAccount>();
    GTEST_LOG_(INFO) << "SetUpTestCase enter";
    bool isOsAccountActived = false;
    ErrCode ret = g_osAccount->IsOsAccountActived(MAIN_ACCOUNT_ID, isOsAccountActived);
    std::uint32_t waitCnt = 0;
    while (ret != ERR_OK || !isOsAccountActived) {
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_A_MOMENT));
        waitCnt++;
        GTEST_LOG_(INFO) << "SetUpTestCase waitCnt " << waitCnt << " ret = " << ret;
        ret = g_osAccount->IsOsAccountActived(MAIN_ACCOUNT_ID, isOsAccountActived);
        if (waitCnt >= MAX_WAIT_FOR_READY_CNT) {
            GTEST_LOG_(INFO) << "SetUpTestCase waitCnt " << waitCnt;
            GTEST_LOG_(INFO) << "SetUpTestCase wait for ready failed!";
            break;
        }
    }

    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
    sptr<IAccount> accountProxy = iface_cast<AccountProxy>(remoteObject);
    EXPECT_NE(accountProxy, nullptr);
    auto osAccountRemoteObject = accountProxy->GetOsAccountService();
    osAccountProxy_ = iface_cast<IOsAccount>(osAccountRemoteObject);
    EXPECT_NE(osAccountProxy_, nullptr);
    GTEST_LOG_(INFO) << "SetUpTestCase finished, waitCnt " << waitCnt;
}

void OsAccountTest::TearDownTestCase(void)
{}

void OsAccountTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountTest::TearDown(void)
{}

/**
 * @tc.name: OsAccountTest001
 * @tc.desc: Test CreateOsAccount string name out of range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = g_osAccount->CreateOsAccount(STRING_NAME_OUT_OF_RANGE, OsAccountType::GUEST, osAccountInfo);
    osAccountInfo.SetShortName("shortName");
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OsAccountTest002
 * @tc.desc: Test CreateOsAccount string name is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest002, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = g_osAccount->CreateOsAccount(STRING_EMPTY, OsAccountType::GUEST, osAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OsAccountTest003
 * @tc.desc: Test RemoveOsAccount Id error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest003, TestSize.Level1)
{
    ErrCode errCode = g_osAccount->RemoveOsAccount(0);
    EXPECT_EQ(errCode, ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
    errCode = g_osAccount->RemoveOsAccount(100);
    EXPECT_EQ(errCode, ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
    errCode = g_osAccount->RemoveOsAccount(1100);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountTest004
 * @tc.desc: Test SetOsAccountName string name out of range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest004, TestSize.Level1)
{
    ErrCode errCode = g_osAccount->SetOsAccountName(100, STRING_NAME_OUT_OF_RANGE);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OsAccountTest005
 * @tc.desc: Test SetOsAccountName name is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest005, TestSize.Level1)
{
    ErrCode errCode = g_osAccount->SetOsAccountName(100, STRING_EMPTY);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OsAccountTest006
 * @tc.desc: Test SetOsAccountProfilePhoto string photo out of range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest006, TestSize.Level1)
{
    ErrCode errCode = g_osAccount->SetOsAccountProfilePhoto(100, STRING_PHOTO_OUT_OF_RANGE);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OsAccountTest007
 * @tc.desc: Test SetDomainInfo with valid info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest007, TestSize.Level1)
{
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    bool checkValid = (domainInfo.accountName_ == STRING_DOMAIN_ACCOUNT_NAME_VALID);
    EXPECT_EQ(checkValid, true);
    checkValid = (domainInfo.domain_ == STRING_DOMAIN_VALID);
    EXPECT_EQ(checkValid, true);

    domainInfo.Clear();
    checkValid = (domainInfo.accountName_ == "");
    EXPECT_EQ(checkValid, true);
    checkValid = (domainInfo.domain_ == "");
    EXPECT_EQ(checkValid, true);
}

/**
 * @tc.name: OsAccountTest008
 * @tc.desc: Test SetDomainInfo with valid info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest008, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    EXPECT_EQ(osAccountInfo.SetDomainInfo(domainInfo), true);

    DomainAccountInfo getDomainInfo;
    osAccountInfo.GetDomainInfo(getDomainInfo);

    bool checkValid = (getDomainInfo.accountName_ == domainInfo.accountName_);
    EXPECT_EQ(checkValid, true);
    checkValid = (getDomainInfo.domain_ == domainInfo.domain_);
    EXPECT_EQ(checkValid, true);
}

/**
 * @tc.name: OsAccountTest009
 * @tc.desc: Test SetDomainInfo with in valid info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest009, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    DomainAccountInfo domainInfoNameInvalid(STRING_DOMAIN_NAME_OUT_OF_RANGE, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    EXPECT_EQ(osAccountInfo.SetDomainInfo(domainInfoNameInvalid), false);

    DomainAccountInfo domainInfoAccountInvalid(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE);
    EXPECT_EQ(osAccountInfo.SetDomainInfo(domainInfoAccountInvalid), false);
}

/**
 * @tc.name: OsAccountTest011
 * @tc.desc: Test CreateOsAccount name is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountTest, OsAccountTest011, TestSize.Level1)
{
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
        osAccountProxy_->CreateOsAccount(STRING_EMPTY, type, osAccountInfo));
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountTest016
 * @tc.desc: Test IsOsAccountConstraintEnable/CheckOsAccountConstraintEnabled constraint is illegal.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest016, TestSize.Level1)
{
    bool isConstraintEnable;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
        osAccountProxy_->IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, STRING_EMPTY, isConstraintEnable));
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
        osAccountProxy_->CheckOsAccountConstraintEnabled(MAIN_ACCOUNT_ID, STRING_EMPTY, isConstraintEnable));

    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, osAccountProxy_->IsOsAccountConstraintEnable(
        MAIN_ACCOUNT_ID, STRING_CONSTRAINT_OUT_OF_RANGE, isConstraintEnable));
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, osAccountProxy_->CheckOsAccountConstraintEnabled(
        MAIN_ACCOUNT_ID, STRING_CONSTRAINT_OUT_OF_RANGE, isConstraintEnable));
}

/**
 * @tc.name: OsAccountTest017
 * @tc.desc: Test SetGlobalOsAccountConstraints local id is illegal.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest017, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR,
        osAccountProxy_->SetGlobalOsAccountConstraints(CONSTANTS_VECTOR, false, ILLEGAL_LOCAL_ID, false));
}

/**
 * @tc.name: OsAccountTest018
 * @tc.desc: Test SetSpecificOsAccountConstraints local id is illegal.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest018, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR, osAccountProxy_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, false, ILLEGAL_LOCAL_ID, MAIN_ACCOUNT_ID, false));
    EXPECT_EQ(ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR, osAccountProxy_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, false, MAIN_ACCOUNT_ID, ILLEGAL_LOCAL_ID, false));
}

/**
 * @tc.name: OsAccountTest019
 * @tc.desc: test ResetOsAccountProxy normal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest019, TestSize.Level1)
{
    EXPECT_EQ(g_osAccount->ResetOsAccountProxy(), ERR_OK);
}

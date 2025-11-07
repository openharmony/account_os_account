/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "account_dump_helper.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#define private public
#include "account_mgr_service.h"
#undef private
#include "account_proxy.h"
#include "iaccount.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
static OhosAccountInfo g_oldInfo;

const std::string KEY_ACCOUNT_EVENT_LOGIN = "LOGIN";
const std::string KEY_ACCOUNT_EVENT_LOGOUT = "LOGOUT";
const std::string KEY_ACCOUNT_EVENT_TOKEN_INVALID = "TOKEN_INVALID";
const std::string KEY_ACCOUNT_EVENT_LOGOFF = "LOGOFF";
std::string g_eventLogin = OHOS_ACCOUNT_EVENT_LOGIN;
std::string g_eventLogout = OHOS_ACCOUNT_EVENT_LOGOUT;
std::string g_eventTokenInvalid = OHOS_ACCOUNT_EVENT_TOKEN_INVALID;
std::string g_eventLogoff = OHOS_ACCOUNT_EVENT_LOGOFF;
const std::string TEST_ACCOUNT_NAME = "TestAccountName";
const std::string TEST_ACCOUNT_UID = "123456789";
const std::string TEST_EXPECTED_UID = "15E2B0D3C33891EBB0F1EF609EC419420C20E320CE94C65FBC8C3312448EB225";
const std::string TEST_DIFF_ACCOUNT_NAME = "TestDiffAccountName";
const std::string TEST_DIFF_ACCOUNT_UID = "9876432";
const std::string TEST_DIFF_EXPECTED_UID = "FB293C538C2CD118B0441AB3B2EC429A5EA629286A04F31E0CC2EFB96525ADCC";

std::shared_ptr<AccountMgrService> g_accountMgrService = nullptr;

sptr<IAccount> GetAccountMgr()
{
    sptr<ISystemAbilityManager> systemMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemMgr == nullptr) {
        return nullptr;
    }

    sptr<IRemoteObject> accountObj = systemMgr->GetSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
    return iface_cast<IAccount>(accountObj);
}
}

class AccountMgrServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AccountMgrServiceTest::SetUpTestCase()
{
    ASSERT_TRUE(MockTokenId("accountmgr"));
    sptr<IAccount> accountMgr = GetAccountMgr();
    if (!accountMgr) {
        std::cout << "AccountMgrServiceTest::SetUpTestCase  failed" << std::endl;
        return;
    }
    std::string accountName;
    std::string uid;
    int32_t status;
    ErrCode ret = accountMgr->QueryOhosAccountInfo(accountName, uid, status);
    if (ret != ERR_OK) {
        std::cout << "AccountMgrServiceTest::SetUpTestCase GET old info failed" << std::endl;
    }
    g_oldInfo.name_ = accountName;
    g_oldInfo.uid_ = uid;
    g_oldInfo.status_ = status;
    g_accountMgrService = std::make_shared<AccountMgrService>();
}

void AccountMgrServiceTest::TearDownTestCase()
{
    std::cout << "AccountMgrServiceTest::TearDownTestCase" << std::endl;
}

void AccountMgrServiceTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AccountMgrServiceTest::TearDown() {}

/**
 * @tc.name: AccountMgrServiceOhosLoginTest001
 * @tc.desc: Test ohos account login and logout
 * @tc.type: FUNC
 * @tc.require: SR000GGVG1
 */
HWTEST_F(AccountMgrServiceTest, AccountMgrServiceOhosLoginTest001, TestSize.Level2)
{
    sptr<IAccount> accountMgr = GetAccountMgr();
    ASSERT_TRUE(accountMgr != nullptr);

    // login
    ErrCode ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogin);
    EXPECT_EQ(ERR_OK, ret);

    // status check
    std::string accountName;
    std::string uid;
    int32_t status;
    ErrCode result = accountMgr->QueryOhosAccountInfo(accountName, uid, status);
    EXPECT_EQ(ERR_OK, result);
    ret = (uid == TEST_EXPECTED_UID);
    EXPECT_EQ(true, ret);
    ret = (accountName == TEST_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (status == ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(true, ret);

    // logout
    ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogoff);
    EXPECT_EQ(ERR_OK, ret);

    // status check
    result = accountMgr->QueryOhosAccountInfo(accountName, uid, status);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(uid, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountName, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(status, ACCOUNT_STATE_UNBOUND);
}

/**
 * @tc.name: AccountMgrServiceOhosLoginTest002
 * @tc.desc: Test ohos account repeat login will fail
 * @tc.type: FUNC
 * @tc.require: SR000GGVG1
 */
HWTEST_F(AccountMgrServiceTest, AccountMgrServiceOhosLoginTest002, TestSize.Level2)
{
    sptr<IAccount> accountMgr = GetAccountMgr();
    ASSERT_TRUE(accountMgr != nullptr);

    // login
    ErrCode ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogin);
    EXPECT_EQ(ERR_OK, ret);

    // status check
    std::string accountName;
    std::string uid;
    int32_t status;
    ErrCode result = accountMgr->QueryOhosAccountInfo(accountName, uid, status);
    EXPECT_EQ(ERR_OK, result);
    ret = (uid == TEST_EXPECTED_UID);
    EXPECT_EQ(true, ret);
    ret = (accountName == TEST_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (status == ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(true, ret);

    // repeat login
    ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogin);
    EXPECT_EQ(ERR_OK, ret);

    // repeat login
    ret = accountMgr->UpdateOhosAccountInfo(TEST_DIFF_ACCOUNT_NAME, TEST_DIFF_ACCOUNT_UID, g_eventLogin);
    EXPECT_NE(ERR_OK, ret);

    // logout
    ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogoff);
    EXPECT_EQ(ERR_OK, ret);

    // status check
    result = accountMgr->QueryOhosAccountInfo(accountName, uid, status);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(uid, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountName, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(status, ACCOUNT_STATE_UNBOUND);
}

/**
 * @tc.name: AccountMgrServiceOhosLogoffTest001
 * @tc.desc: Test ohos account login and logoff
 * @tc.type: FUNC
 * @tc.require: SR000GGVG1
 */
HWTEST_F(AccountMgrServiceTest, AccountMgrServiceOhosLogoffTest001, TestSize.Level2)
{
    sptr<IAccount> accountMgr = GetAccountMgr();
    ASSERT_TRUE(accountMgr != nullptr);

    // login
    // param 1: name, param 2: UID, param 3: status
    ErrCode ret = accountMgr->UpdateOhosAccountInfo(TEST_DIFF_ACCOUNT_NAME, TEST_DIFF_ACCOUNT_UID, g_eventLogin);
    EXPECT_EQ(ERR_OK, ret);

    // status check
    std::string accountName;
    std::string uid;
    int32_t status;
    ErrCode result = accountMgr->QueryOhosAccountInfo(accountName, uid, status);
    EXPECT_EQ(ERR_OK, result);
    ret = (uid == TEST_DIFF_EXPECTED_UID);
    EXPECT_EQ(true, ret);
    ret = (accountName == TEST_DIFF_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (status == ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(true, ret);

    // logoff
    ret = accountMgr->UpdateOhosAccountInfo(TEST_DIFF_ACCOUNT_NAME, TEST_DIFF_ACCOUNT_UID, g_eventLogoff);
    EXPECT_EQ(ERR_OK, ret);

    // status check
    result = accountMgr->QueryOhosAccountInfo(accountName, uid, status);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(uid, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountName, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(status, ACCOUNT_STATE_UNBOUND);
}

/**
 * @tc.name: AccountMgrServiceOhosTokenInvalidTest001
 * @tc.desc: Test ohos account login and token invalid
 * @tc.type: FUNC
 * @tc.require: SR000GGVG1
 */
HWTEST_F(AccountMgrServiceTest, AccountMgrServiceOhosTokenInvalidTest001, TestSize.Level2)
{
    sptr<IAccount> accountMgr = GetAccountMgr();
    ASSERT_TRUE(accountMgr != nullptr);

    // login
    ErrCode ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogin);
    EXPECT_EQ(ERR_OK, ret);

    // status check
    std::string accountName;
    std::string uid;
    int32_t status;
    ErrCode result = accountMgr->QueryOhosAccountInfo(accountName, uid, status);
    EXPECT_EQ(ERR_OK, result);
    ret = (uid == TEST_EXPECTED_UID);
    EXPECT_EQ(true, ret);
    ret = (accountName == TEST_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (status == ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(true, ret);

    // token invalid
    ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventTokenInvalid);
    EXPECT_EQ(ERR_OK, ret);

    // status check
    result = accountMgr->QueryOhosAccountInfo(accountName, uid, status);
    EXPECT_EQ(ERR_OK, result);
    ret = (uid == TEST_EXPECTED_UID);
    EXPECT_EQ(true, ret);
    ret = (accountName == TEST_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (status == ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(true, ret);

    // login again after token invalid
    ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogin);
    EXPECT_EQ(ERR_OK, ret);

    // status check
    result = accountMgr->QueryOhosAccountInfo(accountName, uid, status);
    EXPECT_EQ(ERR_OK, result);
    ret = (uid == TEST_EXPECTED_UID);
    EXPECT_EQ(true, ret);
    ret = (accountName == TEST_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (status == ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(true, ret);

    // logout
    ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogoff);
    EXPECT_EQ(ERR_OK, ret);

    // status check
    result = accountMgr->QueryOhosAccountInfo(accountName, uid, status);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(uid, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountName, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(status, ACCOUNT_STATE_UNBOUND);
}

/**
 * @tc.name: AccountMgrServiceGetAppAccountService001
 * @tc.desc: Test GetAppAccountService appAccountManagerService is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountMgrServiceTest, AccountMgrServiceGetAppAccountService001, TestSize.Level2)
{
    ASSERT_NE(g_accountMgrService, nullptr);
    g_accountMgrService->appAccountManagerService_ = nullptr;
    sptr<IRemoteObject> servicePtr = nullptr;
    g_accountMgrService->GetAppAccountService(servicePtr);
#ifdef HAS_APP_ACCOUNT_PART
    ASSERT_NE(servicePtr, nullptr);
#else
    ASSERT_EQ(servicePtr, nullptr);
#endif // HAS_APP_ACCOUNT_PART
}

/**
 * @tc.name: AccountMgrServiceGetOsAccountService001
 * @tc.desc: Test GetOsAccountService osAccountManagerService is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountMgrServiceTest, AccountMgrServiceGetOsAccountServicee001, TestSize.Level2)
{
    ASSERT_NE(g_accountMgrService, nullptr);
    g_accountMgrService->osAccountManagerService_ = nullptr;
    sptr<IRemoteObject> servicePtr = nullptr;
    g_accountMgrService->GetOsAccountService(servicePtr);
    ASSERT_NE(servicePtr, nullptr);
}

/**
 * @tc.name: AccountMgrServiceGetAccountIAMService001
 * @tc.desc: Test GetAccountIAMService accountIAMService is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountMgrServiceTest, AccountMgrServiceGetAccountIAMService001, TestSize.Level2)
{
    ASSERT_NE(g_accountMgrService, nullptr);
    g_accountMgrService->state_ = ServiceRunningState::STATE_RUNNING;
    g_accountMgrService->OnStart();
    g_accountMgrService->accountIAMService_ = nullptr;
    sptr<IRemoteObject> servicePtr = nullptr;
    g_accountMgrService->GetAccountIAMService(servicePtr);
#ifdef HAS_USER_AUTH_PART
    ASSERT_NE(servicePtr, nullptr);
#else
    ASSERT_EQ(servicePtr, nullptr);
#endif // HAS_USER_AUTH_PART
}

/**
 * @tc.name: AccountMgrServiceOnStart001
 * @tc.desc: Test GetAccountIAMService start and stop service
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountMgrServiceTest, AccountMgrServiceOnStart001, TestSize.Level2)
{
    ASSERT_NE(g_accountMgrService, nullptr);
    g_accountMgrService->state_ = ServiceRunningState::STATE_RUNNING;
    bool result = g_accountMgrService->Init();
    ASSERT_EQ(result, false);
    g_accountMgrService->OnStart();
    ASSERT_EQ(g_accountMgrService->state_, ServiceRunningState::STATE_RUNNING);
    g_accountMgrService->OnStop();
    ASSERT_EQ(g_accountMgrService->state_, STATE_NOT_START);
}

/**
 * @tc.name: AccountMgrServiceDump001
 * @tc.desc: Test Dump failed with invlaied fd and dumpHelper is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountMgrServiceTest, AccountMgrServiceDump001, TestSize.Level2)
{
    ASSERT_NE(g_accountMgrService, nullptr);
    int32_t invalidFd = -1;
    std::vector<std::u16string> args;
    int32_t result = g_accountMgrService->Dump(invalidFd, args);
    ASSERT_EQ(result, ERR_ACCOUNT_MGR_DUMP_ERROR);

    int32_t fd = 1;
    g_accountMgrService->dumpHelper_ = nullptr;
    result = g_accountMgrService->Dump(fd, args);
    ASSERT_EQ(result, ERR_ACCOUNT_MGR_DUMP_ERROR);
}

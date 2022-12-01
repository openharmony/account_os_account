/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "account_helper_data.h"
#include "account_info.h"
#include "account_log_wrapper.h"
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
static std::pair<bool, OhosAccountInfo> g_oldInfo;

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
    return iface_cast<AccountProxy>(accountObj);
}

std::string GetAccountEventStr(const std::map<std::string, std::string> &accountEventMap,
    const std::string &eventKey, const std::string &defaultValue)
{
    const auto &it = accountEventMap.find(eventKey);
    if (it != accountEventMap.end()) {
        return it->second;
    }
    return defaultValue;
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
    sptr<IAccount> accountMgr = GetAccountMgr();
    if (!accountMgr) {
        std::cout << "AccountMgrServiceTest::SetUpTestCase  failed" << std::endl;
        return;
    }
    g_oldInfo = accountMgr->QueryOhosAccountInfo();
    if (!g_oldInfo.first) {
        std::cout << "AccountMgrServiceTest::SetUpTestCase GET old info failed" << std::endl;
    }

    const std::map<std::string, std::string> accountEventMap = AccountHelperData::GetAccountEventMap();
    g_eventLogin = GetAccountEventStr(accountEventMap, KEY_ACCOUNT_EVENT_LOGIN, OHOS_ACCOUNT_EVENT_LOGIN);
    g_eventLogout = GetAccountEventStr(accountEventMap, KEY_ACCOUNT_EVENT_LOGOUT, OHOS_ACCOUNT_EVENT_LOGOUT);
    g_eventTokenInvalid = GetAccountEventStr(accountEventMap, KEY_ACCOUNT_EVENT_TOKEN_INVALID,
        OHOS_ACCOUNT_EVENT_TOKEN_INVALID);
    g_eventLogoff = GetAccountEventStr(accountEventMap, KEY_ACCOUNT_EVENT_LOGOFF, OHOS_ACCOUNT_EVENT_LOGOFF);

    g_accountMgrService = std::make_shared<AccountMgrService>();
}

void AccountMgrServiceTest::TearDownTestCase()
{
    std::cout << "AccountMgrServiceTest::TearDownTestCase" << std::endl;
}

void AccountMgrServiceTest::SetUp() {}

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
    bool ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogin);
    EXPECT_EQ(true, ret);

    // status check
    std::pair<bool, OhosAccountInfo> testInfo = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, testInfo.first);
    ret = (testInfo.second.uid_ == TEST_EXPECTED_UID);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.name_ == TEST_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.status_ == ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(true, ret);

    // logout
    ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogout);
    EXPECT_EQ(true, ret);

    // status check
    testInfo = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, testInfo.first);
    ret = (testInfo.second.uid_ == DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.name_ == DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.status_ == ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(true, ret);
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
    bool ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogin);
    EXPECT_EQ(true, ret);

    // status check
    std::pair<bool, OhosAccountInfo> testInfo = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, testInfo.first);
    ret = (testInfo.second.uid_ == TEST_EXPECTED_UID);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.name_ == TEST_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.status_ == ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(true, ret);

    // repeat login
    ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogin);
    EXPECT_EQ(true, ret);

    // repeat login
    ret = accountMgr->UpdateOhosAccountInfo(TEST_DIFF_ACCOUNT_NAME, TEST_DIFF_ACCOUNT_UID, g_eventLogin);
    EXPECT_EQ(false, ret);

    // logout
    ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogout);
    EXPECT_EQ(true, ret);

    // status check
    testInfo = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, testInfo.first);
    ret = (testInfo.second.uid_ == DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.name_ == DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.status_ == ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(true, ret);
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
    bool ret = accountMgr->UpdateOhosAccountInfo(TEST_DIFF_ACCOUNT_NAME, TEST_DIFF_ACCOUNT_UID, g_eventLogin);
    EXPECT_EQ(true, ret);

    // status check
    std::pair<bool, OhosAccountInfo> testInfo = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, testInfo.first);
    ret = (testInfo.second.uid_ == TEST_DIFF_EXPECTED_UID);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.name_ == TEST_DIFF_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.status_ == ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(true, ret);

    // logoff
    ret = accountMgr->UpdateOhosAccountInfo(TEST_DIFF_ACCOUNT_NAME, TEST_DIFF_ACCOUNT_UID, g_eventLogoff);
    EXPECT_EQ(true, ret);

    // status check
    testInfo = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, testInfo.first);
    ret = (testInfo.second.uid_ == DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.name_ == DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.status_ == ACCOUNT_STATE_LOGOFF);
    EXPECT_EQ(true, ret);
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
    bool ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogin);
    EXPECT_EQ(true, ret);

    // status check
    std::pair<bool, OhosAccountInfo> testInfo = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, testInfo.first);
    ret = (testInfo.second.uid_ == TEST_EXPECTED_UID);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.name_ == TEST_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.status_ == ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(true, ret);

    // token invalid
    ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventTokenInvalid);
    EXPECT_EQ(true, ret);

    // status check
    testInfo = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, testInfo.first);
    ret = (testInfo.second.uid_ == TEST_EXPECTED_UID);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.name_ == TEST_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.status_ == ACCOUNT_STATE_NOTLOGIN);
    EXPECT_EQ(true, ret);

    // login again after token invalid
    ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogin);
    EXPECT_EQ(true, ret);

    // status check
    testInfo = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, testInfo.first);
    ret = (testInfo.second.uid_ == TEST_EXPECTED_UID);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.name_ == TEST_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.status_ == ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(true, ret);

    // logout
    ret = accountMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, g_eventLogout);
    EXPECT_EQ(true, ret);

    // status check
    testInfo = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, testInfo.first);
    ret = (testInfo.second.uid_ == DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.name_ == DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(true, ret);
    ret = (testInfo.second.status_ == ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(true, ret);
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
    auto servicePtr = g_accountMgrService->GetAppAccountService();
    ASSERT_EQ(servicePtr, nullptr);
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
    auto servicePtr = g_accountMgrService->GetOsAccountService();
    ASSERT_EQ(servicePtr, nullptr);
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
    auto servicePtr = g_accountMgrService->GetAccountIAMService();
    ASSERT_EQ(servicePtr, nullptr);
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
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
        std::cout << "TearDownTestCase::GetAccountMgr failed" << std::endl;
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
}

void AccountMgrServiceTest::TearDownTestCase()
{
    if (g_oldInfo.first) {
        sptr<IAccount> accountMgr = GetAccountMgr();
        if (!accountMgr) {
            std::cout << "TearDownTestCase::GetAccountMgr failed" << std::endl;
            return;
        }

        auto name = g_oldInfo.second.name_;
        auto uid = g_oldInfo.second.uid_;
        bool ret = false;
        switch (g_oldInfo.second.status_) {
            case ACCOUNT_STATE_UNBOUND:
            case ACCOUNT_STATE_LOGOFF:
                break;
            case ACCOUNT_STATE_LOGIN:
                ret = accountMgr->UpdateOhosAccountInfo(name, uid, g_eventLogin);
                if (!ret) {
                    std::cout << "TearDownTestCase RESUME to LOGIN failed" << std::endl;
                }
                break;
            case ACCOUNT_STATE_NOTLOGIN:
                ret = accountMgr->UpdateOhosAccountInfo(name, uid, g_eventLogin);
                if (!ret) {
                    std::cout << "TearDownTestCase RESUME to LOGIN failed" << std::endl;
                }
                ret = accountMgr->UpdateOhosAccountInfo(name, uid, g_eventTokenInvalid);
                if (!ret) {
                    std::cout << "TearDownTestCase RESUME to NOTLOGIN failed" << std::endl;
                }
                break;
            default:
                break;
        }
    }
}

void AccountMgrServiceTest::SetUp() {}

void AccountMgrServiceTest::TearDown() {}

/**
 * @tc.name: AccountMgrServiceSetOhosIdStatusLoginTest001
 * @tc.desc: Test ohos account status
 * @tc.type: FUNC
 * @tc.require: AR000CUF5H SR000CUF5T
 */
HWTEST_F(AccountMgrServiceTest, AccountMgrServiceSetOhosIdStatusLoginTest001, TestSize.Level2)
{
    /**
     * @tc.steps: step1. get AccountMgrService Iinterface
     * @tc.expected: step1. The current account is not set
     */
    sptr<IAccount> accountMgr = GetAccountMgr();
    ASSERT_TRUE(accountMgr != nullptr);

    std::pair<bool, OhosAccountInfo> info = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, info.first);
    bool ret = false;
    switch (info.second.status_) {
        case ACCOUNT_STATE_LOGIN:
        case ACCOUNT_STATE_NOTLOGIN:
            ret = accountMgr->UpdateOhosAccountInfo(info.second.name_,
                info.second.uid_, g_eventLogout);
            EXPECT_EQ(true, ret);
            info = accountMgr->QueryOhosAccountInfo();
            EXPECT_EQ(true, info.first);
            EXPECT_EQ(ACCOUNT_STATE_UNBOUND, info.second.status_);
            break;
        default:
            break;
    }

    // update status with test info
    std::string name("User001");
    std::string uid("1001");
    ret = accountMgr->UpdateOhosAccountInfo(name, uid, g_eventLogin);
    EXPECT_EQ(true, ret);
    // param 1: name, param 2: UID, param 3: status
    std::pair<bool, OhosAccountInfo> testInfo = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, testInfo.first);
    EXPECT_EQ(uid, testInfo.second.uid_);
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, testInfo.second.status_);

    ret = accountMgr->UpdateOhosAccountInfo(name, uid, g_eventLogout);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.name: AccountMgrServiceSetOhosIdStatusLogoffTest002
 * @tc.desc: Test ohos account status
 * @tc.type: FUNC
 * @tc.require: AR000CUF64 AR000CUF5K AR000CUF5O
 */
HWTEST_F(AccountMgrServiceTest, AccountMgrServiceSetOhosIdStatusLogoffTest002, TestSize.Level2)
{
    /**
     * @tc.steps: step1. get AccountMgrService Iinterface
     * @tc.expected: step1. The current account is not set
     */
    sptr<IAccount> accountMgr = GetAccountMgr();
    ASSERT_TRUE(accountMgr != nullptr);

    std::pair<bool, OhosAccountInfo> retInfo = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, retInfo.first);
    std::string name(retInfo.second.name_);
    std::string uid(retInfo.second.uid_);
    bool ret = false;
    switch (retInfo.second.status_) {
        case ACCOUNT_STATE_LOGIN:
        case ACCOUNT_STATE_NOTLOGIN:
            ret = accountMgr->UpdateOhosAccountInfo(name, uid, g_eventLogout);
            EXPECT_EQ(true, ret);
            break;
        default:
            break;
    }
    // update status with test info
    name = "User002";
    uid = "1002";
    // param 1: name, param 2: UID, param 3: status
    ret = accountMgr->UpdateOhosAccountInfo(name, uid, g_eventLogin);
    EXPECT_EQ(true, ret);

    ret = accountMgr->UpdateOhosAccountInfo(name, uid, g_eventLogoff);
    EXPECT_EQ(true, ret);

    std::pair<bool, OhosAccountInfo> testInfo = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, testInfo.first);
    EXPECT_EQ(ACCOUNT_STATE_LOGOFF, testInfo.second.status_);
}

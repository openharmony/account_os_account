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

sptr<IAccount> GetAccountMgr()
{
    sptr<ISystemAbilityManager> systemMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemMgr == nullptr) {
        return nullptr;
    }

    sptr<IRemoteObject> accountObj = systemMgr->GetSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
    return iface_cast<AccountProxy>(accountObj);
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
        std::string eventStr;
        bool ret = false;
        switch (g_oldInfo.second.status_) {
            case ACCOUNT_STATE_UNBOUND:
            case ACCOUNT_STATE_LOGOFF:
                break;
            case ACCOUNT_STATE_LOGIN:
                eventStr = OHOS_ACCOUNT_EVENT_LOGIN;
                ret = accountMgr->UpdateOhosAccountInfo(name, uid, eventStr);
                if (!ret) {
                    std::cout << "TearDownTestCase RESUME to LOGIN failed" << std::endl;
                }
                break;
            case ACCOUNT_STATE_NOTLOGIN:
                eventStr = OHOS_ACCOUNT_EVENT_LOGIN;
                ret = accountMgr->UpdateOhosAccountInfo(name, uid, eventStr);
                if (!ret) {
                    std::cout << "TearDownTestCase RESUME to LOGIN failed" << std::endl;
                }
                eventStr = OHOS_ACCOUNT_EVENT_TOKEN_INVALID;
                ret = accountMgr->UpdateOhosAccountInfo(name, uid, eventStr);
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
                info.second.uid_, OHOS_ACCOUNT_EVENT_LOGOUT);
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
    std::string eventStr(OHOS_ACCOUNT_EVENT_LOGIN);
    ret = accountMgr->UpdateOhosAccountInfo(name, uid, eventStr);
    EXPECT_EQ(true, ret);
    // param 1: name, param 2: UID, param 3: status
    std::pair<bool, OhosAccountInfo> testInfo = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, testInfo.first);
    EXPECT_EQ(uid, testInfo.second.uid_);
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, testInfo.second.status_);

    eventStr = OHOS_ACCOUNT_EVENT_LOGOUT;
    ret = accountMgr->UpdateOhosAccountInfo(name, uid, eventStr);
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
    std::string eventStr;
    bool ret = false;
    switch (retInfo.second.status_) {
        case ACCOUNT_STATE_LOGIN:
        case ACCOUNT_STATE_NOTLOGIN:
            eventStr = OHOS_ACCOUNT_EVENT_LOGOUT;
            ret = accountMgr->UpdateOhosAccountInfo(name, uid, eventStr);
            EXPECT_EQ(true, ret);
            break;
        default:
            break;
    }
    // update status with test info
    name = "User002";
    uid = "1002";
    eventStr = OHOS_ACCOUNT_EVENT_LOGIN;
    // param 1: name, param 2: UID, param 3: status
    ret = accountMgr->UpdateOhosAccountInfo(name, uid, eventStr);
    EXPECT_EQ(true, ret);

    eventStr = OHOS_ACCOUNT_EVENT_LOGOFF;
    ret = accountMgr->UpdateOhosAccountInfo(name, uid, eventStr);
    EXPECT_EQ(true, ret);

    std::pair<bool, OhosAccountInfo> testInfo = accountMgr->QueryOhosAccountInfo();
    EXPECT_EQ(true, testInfo.first);
    EXPECT_EQ(ACCOUNT_STATE_LOGOFF, testInfo.second.status_);
}

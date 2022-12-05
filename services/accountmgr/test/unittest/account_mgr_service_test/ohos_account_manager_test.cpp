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

#include "ohos_account_manager.h"
#include "account_helper_data.h"
#include "account_info.h"
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string KEY_ACCOUNT_EVENT_LOGIN = "LOGIN";
const std::string KEY_ACCOUNT_EVENT_LOGOUT = "LOGOUT";
const std::string KEY_ACCOUNT_EVENT_TOKEN_INVALID = "TOKEN_INVALID";
const std::string TEST_UID = "TestUid";
const std::string TEST_NAME = "TestName";
const std::string TEST_EVENT_STR = "TesteventStr";
std::string g_eventLogin = OHOS_ACCOUNT_EVENT_LOGIN;
std::string g_eventLogout = OHOS_ACCOUNT_EVENT_LOGOUT;
std::string g_eventTokenInvalid = OHOS_ACCOUNT_EVENT_TOKEN_INVALID;

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

class OhosAccountManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void OhosAccountManagerTest::SetUpTestCase()
{
    const std::map<std::string, std::string> accountEventMap = AccountHelperData::GetAccountEventMap();
    g_eventLogin = GetAccountEventStr(accountEventMap, KEY_ACCOUNT_EVENT_LOGIN, OHOS_ACCOUNT_EVENT_LOGIN);
    g_eventLogout = GetAccountEventStr(accountEventMap, KEY_ACCOUNT_EVENT_LOGOUT, OHOS_ACCOUNT_EVENT_LOGOUT);
    g_eventTokenInvalid = GetAccountEventStr(accountEventMap, KEY_ACCOUNT_EVENT_TOKEN_INVALID,
        OHOS_ACCOUNT_EVENT_TOKEN_INVALID);
}

void OhosAccountManagerTest::TearDownTestCase() {}
void OhosAccountManagerTest::SetUp() {}
void OhosAccountManagerTest::TearDown() {}

/**
 * @tc.name: OhosAccountManagerTest001
 * @tc.desc: Account manager login OhosAccount faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest001, TestSize.Level0)
{
    OhosAccountManager accountManager;
    OhosAccountInfo accountInfo;
    accountInfo.name_ = TEST_NAME;
    accountInfo.uid_ = TEST_UID;
    accountManager.OnInitialize();
    auto ret = accountManager.LoginOhosAccount(accountInfo, g_eventLogin);
    EXPECT_EQ(false, ret);

    ret = accountManager.HandleOhosAccountTokenInvalidEvent(accountInfo, g_eventTokenInvalid);
    EXPECT_EQ(false, ret);
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, accountManager.GetCurrentOhosAccountState());
}

/**
 * @tc.name: OhosAccountManagerTest002
 * @tc.desc: test GetOhosAccountInfoByUserId with invalid user id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest002, TestSize.Level0)
{
    OhosAccountManager accountManager;
    accountManager.OnInitialize();
    std::int32_t testUserId = 200; // 200 is test user id.
    AccountInfo info;
    ErrCode ret = accountManager.GetAccountInfoByUserId(testUserId, info);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: OhosAccountManagerTest003
 * @tc.desc: test HandleEvent GetCallingUserID failed..
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest003, TestSize.Level0)
{
    OhosAccountManager accountManager;
    accountManager.OnInitialize();
    AccountInfo curOhosAccount;
    ErrCode ret = accountManager.HandleEvent(curOhosAccount, TEST_EVENT_STR);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: OhosAccountManagerTest004
 * @tc.desc: test LogoutOhosAccount GetCallingUserID failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest004, TestSize.Level0)
{
    OhosAccountManager accountManager;
    accountManager.OnInitialize();
    OhosAccountInfo curOhosAccount;
    ErrCode ret = accountManager.LogoutOhosAccount(curOhosAccount, TEST_EVENT_STR);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: OhosAccountManagerTest005
 * @tc.desc: test LogoffOhosAccount GetCallingUserID failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest005, TestSize.Level0)
{
    OhosAccountManager accountManager;
    accountManager.OnInitialize();
    OhosAccountInfo curOhosAccount;
    ErrCode ret = accountManager.LogoffOhosAccount(curOhosAccount, TEST_EVENT_STR);
    EXPECT_EQ(false, ret);
}

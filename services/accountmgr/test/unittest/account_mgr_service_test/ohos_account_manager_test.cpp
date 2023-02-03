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
#include <thread>

#include "ohos_account_manager.h"
#include "accesstoken_kit.h"
#include "account_helper_data.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#ifdef HAS_CES_PART
#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "common_event_subscribe_info.h"
#include "matching_skills.h"
#endif // HAS_CES_PART
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
const int DELAY_FOR_OPERATION = 250;
const int ACCOUNT_UID = 100;

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

class AccountCommonEventSubscriber final : public EventFwk::CommonEventSubscriber {
public:
    explicit AccountCommonEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
        : CommonEventSubscriber(subscribeInfo)
    {}
    void OnReceiveEvent(const EventFwk::CommonEventData &data)
    {
        auto want = data.GetWant();
        std::string action = want.GetAction();
        if (action == EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGIN) {
            firstLoginStatus = true;
        }
        if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_INFO_UPDATED) {
            secondLoginStatus = true;
        }
    }
    bool GetStatusLoginFirst()
    {
        return firstLoginStatus;
    }
    bool GetStatusLoginSecond()
    {
        return secondLoginStatus;
    }

private:
    bool firstLoginStatus = false;
    bool secondLoginStatus = false;
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

/**
 * @tc.name: OhosAccountManagerTest006
 * @tc.desc: test LoginOhosAccount first login and second login public different commonevent.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest006, TestSize.Level0)
{
    setuid(ACCOUNT_UID * UID_TRANSFORM_DIVISOR);
    // create common event subscribe
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_INFO_UPDATED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGIN);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<AccountCommonEventSubscriber> subscriberPtr =
        std::make_shared<AccountCommonEventSubscriber>(subscribeInfo);
    ASSERT_NE(subscriberPtr, nullptr);
    bool result = EventFwk::CommonEventManager::SubscribeCommonEvent(subscriberPtr);
    ASSERT_EQ(result, true);

    OhosAccountManager accountManager;
    accountManager.OnInitialize();
    AccountInfo curAccountInfo;
    curAccountInfo.ohosAccountInfo_.name_ = "name";
    curAccountInfo.ohosAccountInfo_.uid_ = "test";
    bool ret = accountManager.LoginOhosAccount(curAccountInfo.ohosAccountInfo_, g_eventLogin);
    ASSERT_EQ(ret, true);
    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));
    ASSERT_EQ(subscriberPtr->GetStatusLoginFirst(), true);
    ret = accountManager.LoginOhosAccount(curAccountInfo.ohosAccountInfo_, g_eventLogin);
    ASSERT_EQ(ret, true);
    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));
    ASSERT_EQ(subscriberPtr->GetStatusLoginSecond(), true);
    ret = accountManager.LogoutOhosAccount(curAccountInfo.ohosAccountInfo_, g_eventLogout);
    EXPECT_EQ(true, ret);
}

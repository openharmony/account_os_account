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
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>

#define private public
#include "ohos_account_manager.h"
#undef private
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
#include "os_account_manager.h"
using namespace testing;
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
const std::string OVERSIZE_NAME =
    "TestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestT"
    "stTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTestTes"
    "TestTestTestTestTestTestTestTestTestTestTestTestTestTesttest";
std::string g_eventLogin = OHOS_ACCOUNT_EVENT_LOGIN;
std::string g_eventLogout = OHOS_ACCOUNT_EVENT_LOGOUT;
std::string g_eventTokenInvalid = OHOS_ACCOUNT_EVENT_TOKEN_INVALID;
const std::string STRING_TEST_NAME = "test_account_name";
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

class MockSubscriberListener {
public:
    MOCK_METHOD1(OnReceiveEvent, void(const std::string &action));
};

class AccountCommonEventSubscriber final : public EventFwk::CommonEventSubscriber {
public:
    AccountCommonEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo,
        const std::shared_ptr<MockSubscriberListener> &listener)
        : CommonEventSubscriber(subscribeInfo), listener_(listener)
    {}

    void OnReceiveEvent(const EventFwk::CommonEventData &data)
    {
        if (listener_ == nullptr) {
            return;
        }
        auto want = data.GetWant();
        listener_->OnReceiveEvent(want.GetAction());
        std::unique_lock<std::mutex> lock(mutex);
        isReady = true;
        cv.notify_one();
        return;
    }

    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;
private:
    const std::shared_ptr<MockSubscriberListener> listener_;
};

void OhosAccountManagerTest::SetUpTestCase()
{
    OhosAccountManager::GetInstance().OnInitialize();
    const std::map<std::string, std::string> accountEventMap = AccountHelperData::GetAccountEventMap();
    g_eventLogin = GetAccountEventStr(accountEventMap, KEY_ACCOUNT_EVENT_LOGIN, OHOS_ACCOUNT_EVENT_LOGIN);
    g_eventLogout = GetAccountEventStr(accountEventMap, KEY_ACCOUNT_EVENT_LOGOUT, OHOS_ACCOUNT_EVENT_LOGOUT);
    g_eventTokenInvalid = GetAccountEventStr(accountEventMap, KEY_ACCOUNT_EVENT_TOKEN_INVALID,
        OHOS_ACCOUNT_EVENT_TOKEN_INVALID);
}

void OhosAccountManagerTest::TearDownTestCase() {}
void OhosAccountManagerTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}
void OhosAccountManagerTest::TearDown() {}

/**
 * @tc.name: OhosAccountManagerTest001
 * @tc.desc: Account manager login OhosAccount faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest001, TestSize.Level0)
{
    OhosAccountInfo accountInfo;
    accountInfo.name_ = TEST_NAME;
    accountInfo.uid_ = TEST_UID;
    auto ret = OhosAccountManager::GetInstance().LoginOhosAccount(-1, accountInfo, g_eventLogin);
    EXPECT_EQ(false, ret);

    ret = OhosAccountManager::GetInstance().HandleOhosAccountTokenInvalidEvent(-1, accountInfo, g_eventTokenInvalid);
    EXPECT_EQ(false, ret);
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, OhosAccountManager::GetInstance().GetCurrentOhosAccountState());
}

/**
 * @tc.name: OhosAccountManagerTest002
 * @tc.desc: test GetOhosAccountInfoByUserId with invalid user id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest002, TestSize.Level0)
{
    std::int32_t testUserId = 200; // 200 is test user id.
    AccountInfo info;
    ErrCode ret = OhosAccountManager::GetInstance().GetAccountInfoByUserId(testUserId, info);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: OhosAccountManagerTest003
 * @tc.desc: test HandleEvent GetCallingUserID failed..
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest003, TestSize.Level0)
{
    AccountInfo curOhosAccount;
    ErrCode ret = OhosAccountManager::GetInstance().HandleEvent(curOhosAccount, TEST_EVENT_STR);
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
    OhosAccountInfo curOhosAccount;
    ErrCode ret = OhosAccountManager::GetInstance().LogoutOhosAccount(ACCOUNT_UID, curOhosAccount, TEST_EVENT_STR);
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
    OhosAccountInfo curOhosAccount;
    ErrCode ret = OhosAccountManager::GetInstance().LogoffOhosAccount(ACCOUNT_UID, curOhosAccount, TEST_EVENT_STR);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: OhosAccountManagerTest006
 * @tc.desc: test LoginOhosAccount first login and second login public different commonevent.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest006, TestSize.Level0)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount(STRING_TEST_NAME, OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    // create common event subscribe
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto listener = std::make_shared<MockSubscriberListener>();
    std::shared_ptr<AccountCommonEventSubscriber> subscriberPtr =
        std::make_shared<AccountCommonEventSubscriber>(subscribeInfo, listener);
    bool result = EventFwk::CommonEventManager::SubscribeCommonEvent(subscriberPtr);
    ASSERT_EQ(result, true);

    AccountInfo curAccountInfo;
    curAccountInfo.ohosAccountInfo_.name_ = "name";
    curAccountInfo.ohosAccountInfo_.uid_ = "test";
    EXPECT_CALL(*listener,
        OnReceiveEvent(EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN)).Times(Exactly(1));
    bool ret = OhosAccountManager::GetInstance().LoginOhosAccount(
        osAccountInfoOne.GetLocalId(), curAccountInfo.ohosAccountInfo_, g_eventLogin);
    EXPECT_EQ(ret, true);
    ret = OhosAccountManager::GetInstance().LoginOhosAccount(
        osAccountInfoOne.GetLocalId(), curAccountInfo.ohosAccountInfo_, g_eventLogin);
    EXPECT_EQ(ret, true);
    std::unique_lock<std::mutex> lock(subscriberPtr->mutex);
    subscriberPtr->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = subscriberPtr]() { return lockCallback->isReady; });
    ret = OhosAccountManager::GetInstance().LogoutOhosAccount(
        osAccountInfoOne.GetLocalId(), curAccountInfo.ohosAccountInfo_, g_eventLogout);
    EXPECT_EQ(true, ret);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriberPtr), true);
}

/**
 * @tc.name: OhosAccountManagerTest007
 * @tc.desc: test login and logout.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest007, TestSize.Level0)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount(STRING_TEST_NAME, OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    // create common event subscribe
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto listener = std::make_shared<MockSubscriberListener>();
    std::shared_ptr<AccountCommonEventSubscriber> subscriberPtr =
        std::make_shared<AccountCommonEventSubscriber>(subscribeInfo, listener);
    ASSERT_NE(subscriberPtr, nullptr);
    bool result = EventFwk::CommonEventManager::SubscribeCommonEvent(subscriberPtr);
    EXPECT_EQ(result, true);

    AccountInfo curAccountInfo;
    curAccountInfo.ohosAccountInfo_.name_ = "name1";
    curAccountInfo.ohosAccountInfo_.uid_ = "test1";
    bool ret = OhosAccountManager::GetInstance().LoginOhosAccount(
        osAccountInfoOne.GetLocalId(), curAccountInfo.ohosAccountInfo_, g_eventLogin);
    EXPECT_EQ(ret, true);
    EXPECT_CALL(*listener,
        OnReceiveEvent(EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT)).Times(Exactly(1));
    ret = OhosAccountManager::GetInstance().LogoutOhosAccount(
        osAccountInfoOne.GetLocalId(), curAccountInfo.ohosAccountInfo_, g_eventLogout);
    std::unique_lock<std::mutex> lock(subscriberPtr->mutex);
    subscriberPtr->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = subscriberPtr]() { return lockCallback->isReady; });
    EXPECT_EQ(true, ret);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    result = EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriberPtr);
    EXPECT_EQ(result, true);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OhosAccountManagerTest07
 * @tc.desc: test OhosAccountStateChange event is invalid .
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest07, TestSize.Level0)
{
    EXPECT_EQ(OhosAccountManager::GetInstance().OhosAccountStateChange("test", "testuid", "testevent"), false);
}

/**
 * @tc.name: OhosAccountManagerTest010
 * @tc.desc: test LoginOhosAccount CheckOhosAccountCanBind not ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest008, TestSize.Level0)
{
    OhosAccountInfo curOhosAccountInfo;
    EXPECT_EQ(OhosAccountManager::GetInstance().LoginOhosAccount(0, curOhosAccountInfo, "test"), false);
}

/**
 * @tc.name: OhosAccountManagerTest011
 * @tc.desc: test LogoutOhosAccount CheckOhosAccountCanBind not ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest009, TestSize.Level0)
{
    OhosAccountInfo curOhosAccountInfo;
    EXPECT_EQ(OhosAccountManager::GetInstance().LogoutOhosAccount(0, curOhosAccountInfo, "test"), false);
}

/**
 * @tc.name: OhosAccountManagerTest012
 * @tc.desc: test LogoffOhosAccount CheckOhosAccountCanBind not ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest010, TestSize.Level0)
{
    OhosAccountInfo curOhosAccountInfo;
    EXPECT_EQ(OhosAccountManager::GetInstance().LogoffOhosAccount(0, curOhosAccountInfo, "test"), false);
}

/**
 * @tc.name: OhosAccountManagerTest013
 * @tc.desc: test HandleOhosAccountTokenInvalidEvent CheckOhosAccountCanBind not ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest011, TestSize.Level0)
{
    OhosAccountInfo curOhosAccountInfo;
    EXPECT_EQ(
        OhosAccountManager::GetInstance().HandleOhosAccountTokenInvalidEvent(0, curOhosAccountInfo, "test"), false);
}

/**
 * @tc.name: OhosAccountManagerTest015
 * @tc.desc: test CheckOhosAccountCanBind newOhosUid is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest012, TestSize.Level0)
{
    AccountInfo curOhosAccountInfo;
    OhosAccountInfo newOhosAccountInfo;
    EXPECT_EQ(OhosAccountManager::GetInstance().CheckOhosAccountCanBind(curOhosAccountInfo, newOhosAccountInfo, "test"),
        false);
}

/**
 * @tc.name: OhosAccountManagerTest_013
 * @tc.desc: test class AccountInfo 'operator=='
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest_013, TestSize.Level0)
{
    AccountInfo accountInfoSrc;
    OhosAccountInfo ohosAccountInfo;
    ohosAccountInfo.uid_ = ACCOUNT_UID;
    accountInfoSrc.ohosAccountInfo_ = ohosAccountInfo;
    
    AccountInfo accountInfoTar;
    accountInfoTar.ohosAccountInfo_ = ohosAccountInfo;
    bool ret = (accountInfoSrc == accountInfoTar);
    EXPECT_EQ(ret, true);
}
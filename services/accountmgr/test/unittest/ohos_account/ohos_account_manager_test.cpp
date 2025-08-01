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
const int ACCOUNT_MGR_UID = 3058;
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
    setuid(ACCOUNT_MGR_UID);
    setgid(ACCOUNT_MGR_UID);
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
 * @tc.name: OhosAccountManagerTest000
 * @tc.desc: Account manager login OhosAccount faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest000, TestSize.Level3)
{
    OhosAccountInfo accountInfo;
    accountInfo.name_ = TEST_NAME;
    accountInfo.uid_ = TEST_UID;
    auto ret = OhosAccountManager::GetInstance().LoginOhosAccount(-1, accountInfo, g_eventLogin);
    EXPECT_EQ(ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR, ret);

    ret = OhosAccountManager::GetInstance().HandleOhosAccountTokenInvalidEvent(-1, accountInfo, g_eventTokenInvalid);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, ret);
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, OhosAccountManager::GetInstance().GetCurrentOhosAccountState());
}

/**
 * @tc.name: OhosAccountManagerTest001
 * @tc.desc: test GetOhosAccountInfoByUserId with invalid user id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest001, TestSize.Level3)
{
    std::int32_t testUserId = 200; // 200 is test user id.
    AccountInfo info;
    ErrCode ret = OhosAccountManager::GetInstance().GetAccountInfoByUserId(testUserId, info);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: OhosAccountManagerTest002
 * @tc.desc: test HandleEvent GetCallingUserID failed..
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest002, TestSize.Level3)
{
    AccountInfo curOhosAccount;
    ErrCode ret = OhosAccountManager::GetInstance().HandleEvent(curOhosAccount, TEST_EVENT_STR);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: OhosAccountManagerTest003
 * @tc.desc: test LogoutOhosAccount GetCallingUserID failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest003, TestSize.Level3)
{
    OhosAccountInfo curOhosAccount;
    ErrCode ret = OhosAccountManager::GetInstance().LogoutOhosAccount(ACCOUNT_UID, curOhosAccount, TEST_EVENT_STR);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, ret);
}

/**
 * @tc.name: OhosAccountManagerTest004
 * @tc.desc: test LogoffOhosAccount GetCallingUserID failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest004, TestSize.Level3)
{
    OhosAccountInfo curOhosAccount;
    ErrCode ret = OhosAccountManager::GetInstance().LogoffOhosAccount(ACCOUNT_UID, curOhosAccount, TEST_EVENT_STR);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, ret);
}

/**
 * @tc.name: OhosAccountManagerTest005
 * @tc.desc: test LoginOhosAccount first login and second login public different commonevent.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest005, TestSize.Level3)
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
 * @tc.name: OhosAccountManagerTest006
 * @tc.desc: test login and logout.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest006, TestSize.Level3)
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
 * @tc.name: OhosAccountManagerTest007
 * @tc.desc: test OhosAccountStateChange event is invalid .
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest007, TestSize.Level3)
{
    EXPECT_EQ(OhosAccountManager::GetInstance().OhosAccountStateChange("test", "testuid", "testevent"),
              ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OhosAccountManagerTest008
 * @tc.desc: test LoginOhosAccount CheckOhosAccountCanBind not ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest008, TestSize.Level3)
{
    OhosAccountInfo curOhosAccountInfo;
    EXPECT_EQ(OhosAccountManager::GetInstance().LoginOhosAccount(0, curOhosAccountInfo, "test"),
              ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR);
}

/**
 * @tc.name: OhosAccountManagerTest009
 * @tc.desc: test LogoutOhosAccount CheckOhosAccountCanBind not ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest009, TestSize.Level3)
{
    OhosAccountInfo curOhosAccountInfo;
    EXPECT_EQ(OhosAccountManager::GetInstance().LogoutOhosAccount(0, curOhosAccountInfo, "test"),
              ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OhosAccountManagerTest010
 * @tc.desc: test LogoffOhosAccount CheckOhosAccountCanBind not ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest010, TestSize.Level3)
{
    OhosAccountInfo curOhosAccountInfo;
    EXPECT_EQ(OhosAccountManager::GetInstance().LogoffOhosAccount(0, curOhosAccountInfo, "test"),
              ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OhosAccountManagerTest011
 * @tc.desc: test HandleOhosAccountTokenInvalidEvent CheckOhosAccountCanBind not ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest011, TestSize.Level3)
{
    OhosAccountInfo curOhosAccountInfo;
    EXPECT_EQ(OhosAccountManager::GetInstance().HandleOhosAccountTokenInvalidEvent(0, curOhosAccountInfo, "test"),
              ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OhosAccountManagerTest012
 * @tc.desc: test CheckOhosAccountCanBind newOhosUid is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest012, TestSize.Level3)
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
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest_013, TestSize.Level3)
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

/**
 * @tc.name: OhosAccountManagerTest014
 * @tc.desc: test AnonymizeOhosAccountInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest014, TestSize.Level3)
{
    OhosAccountInfo ohosAccountInfo;
    std::string bundleName = "";
    ohosAccountInfo.uid_ = "test_uid";
    ohosAccountInfo.name_ = "test_name";
    ohosAccountInfo.nickname_ = "test_nickname";
    ohosAccountInfo.avatar_ = "test_avatar";
    OhosAccountManager::GetInstance().AnonymizeOhosAccountInfo(ohosAccountInfo, bundleName);
    EXPECT_EQ(ohosAccountInfo.uid_, "4FC58A21C100CE1835B8F9991D738B56965D14B24E1761FBDFFC69AC5E0B667A");
    EXPECT_EQ(ohosAccountInfo.name_, "t**********");
    EXPECT_EQ(ohosAccountInfo.nickname_, "t**********");
    EXPECT_EQ(ohosAccountInfo.avatar_, "**********");

    ohosAccountInfo.uid_ = "";
    OhosAccountManager::GetInstance().AnonymizeOhosAccountInfo(ohosAccountInfo, bundleName);
    EXPECT_NE(ohosAccountInfo.uid_, "4FC58A21C100CE1835B8F9991D738B56965D14B24E1761FBDFFC69AC5E0B667A");

    ohosAccountInfo.name_ = "";
    OhosAccountManager::GetInstance().AnonymizeOhosAccountInfo(ohosAccountInfo, bundleName);
    EXPECT_NE(ohosAccountInfo.name_, "t**********");

    ohosAccountInfo.nickname_ = "";
    OhosAccountManager::GetInstance().AnonymizeOhosAccountInfo(ohosAccountInfo, bundleName);
    EXPECT_NE(ohosAccountInfo.nickname_, "t**********");

    ohosAccountInfo.avatar_ = "";
    OhosAccountManager::GetInstance().AnonymizeOhosAccountInfo(ohosAccountInfo, bundleName);
    EXPECT_NE(ohosAccountInfo.avatar_, "**********");
}

/**
 * @tc.name: OhosAccountManagerTest015
 * @tc.desc: test ExtractFirstUtf8Char.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest015, TestSize.Level3)
{
    std::string input = ""; // Test an empty string
    std::string result = OhosAccountManager::GetInstance().ExtractFirstUtf8Char(input);
    EXPECT_EQ(result, "");

    input = "A"; // Test single-byte ASCII characters
    result = OhosAccountManager::GetInstance().ExtractFirstUtf8Char(input);
    EXPECT_EQ(result, "A");

    input = "\xC3\xB1"; // Test double-byte UTF-8 characters
    result = OhosAccountManager::GetInstance().ExtractFirstUtf8Char(input);
    EXPECT_EQ(result, "\xC3\xB1");

    input = "\xE4\xB8\xAD"; // Test three-byte UTF-8 characters
    result = OhosAccountManager::GetInstance().ExtractFirstUtf8Char(input);
    EXPECT_EQ(result, "\xE4\xB8\xAD");

    input = "\xF0\x90\x8D\x88"; // Test four-byte UTF-8 characters
    result = OhosAccountManager::GetInstance().ExtractFirstUtf8Char(input);
    EXPECT_EQ(result, "\xF0\x90\x8D\x88");

    input = "\x80"; // Test for illegal first byte (0x80, consecutive bytes)
    result = OhosAccountManager::GetInstance().ExtractFirstUtf8Char(input);
    EXPECT_EQ(result, "");

    input = "\xF8"; // Test illegal first byte (0xF8, out of range)
    result = OhosAccountManager::GetInstance().ExtractFirstUtf8Char(input);
    EXPECT_EQ(result, "");

    input = "\xC3"; // Test truncated double-byte characters
    result = OhosAccountManager::GetInstance().ExtractFirstUtf8Char(input);
    EXPECT_EQ(result, "\xC3");

    input = "\xE4\xB8"; // Test truncated three-byte characters
    result = OhosAccountManager::GetInstance().ExtractFirstUtf8Char(input);
    EXPECT_EQ(result, "\xE4\xB8");

    input = "\xF0\x90"; // Test the truncated four-byte character
    result = OhosAccountManager::GetInstance().ExtractFirstUtf8Char(input);
    EXPECT_EQ(result, "\xF0\x90");

    input = "Hello 世界 𐍈"; // Test the first character in a multi-character string
    result = OhosAccountManager::GetInstance().ExtractFirstUtf8Char(input);
    EXPECT_EQ(result, "H"); // The first character 'H' should be returned

    input = "\x80\xC3\xB1"; // Illegal bytes followed by valid characters
    result = OhosAccountManager::GetInstance().ExtractFirstUtf8Char(input);
    EXPECT_EQ(result, ""); // An empty string should be returned
}

/**
 * @tc.name: OhosAccountManagerTest015
 * @tc.desc: test GetCurOhosAccountAndCheckMatch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTest016, TestSize.Level3)
{
    std::string input = "";
    AccountInfo info;
    std::string inputUid;
    bool result = OhosAccountManager::GetInstance().GetCurOhosAccountAndCheckMatch(info, input, input, 100);
    EXPECT_EQ(result, false);
    result = OhosAccountManager::GetInstance().GetCurOhosAccountAndCheckMatch(info, TEST_NAME, TEST_NAME, 100);
    EXPECT_EQ(result, false);
}
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <map>
#include <thread>

#include "accesstoken_kit.h"
#include "account_error_no.h"
#ifdef HAS_CES_PART
#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "common_event_subscribe_info.h"
#include "matching_skills.h"
#endif // HAS_CES_PART
#include "os_account_constants.h"
#define private public
#include "os_account_manager_service.h"
#include "os_account_interface.h"
#include "os_account_info.h"
#include "account_log_wrapper.h"
#undef private
#include "os_account_subscribe_manager.h"
#include "token_setproc.h"

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;
using namespace Security::AccessToken;

const int TEST_USER_ID10 = 10;
const int INVALID_USERID = -1;
const int TEST_USER_ID55 = 55;
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
const int ACCOUNT_UID = 3058;
const int DELAY_FOR_OPERATION = 250;
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
const std::string ACCOUNT_NAME = "TEST";
const std::string ACCOUNT_SET_NAME = "TEST2";
const std::string ACCOUNT_PHOTO =
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA0AAAAPCAYAAAA/"
    "I0V3AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAACwSURBVDhPvZLBDYMwDEV/"
    "ugsXRjAT0EHCOuFIBwkbdIRewi6unbiAyoGgSn1SFH85+Yq/"
    "4ljARW62X+LHS8uIzjm4dXUYF+utzBikB52Jo5e5iEPKqpACk7R9NM2RvWm5tIkD2czLCUFNKLD6IjdMHFHDzws285MgGrT0xCtp3WOKHo+"
    "7q0mP0DZW9pNmoEFUzrQjp5cCnaen2kSJXLFD8ghbXyZCMQf/8e8Ns1XVAG/XAgqKzVnJFAAAAABJRU5ErkJggg==";
const AccessTokenID accountMgrTokenID = AccessTokenKit::GetNativeTokenId("accountmgr");

class OsAccountInnerAccmgrCoverageTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
public:
    IInnerOsAccountManager *innerMgrService_ = &IInnerOsAccountManager::GetInstance();
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
        if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_INFO_UPDATED) {
            if (data.GetCode() == localId_) {
                status = true;
            }
        }
    }
    bool GetStatus()
    {
        return status;
    }
    void ResetStatus()
    {
        status = false;
    }
public:
    int32_t localId_ = INVALID_USERID;
private:
    bool status = false;
};

void OsAccountInnerAccmgrCoverageTest::SetUpTestCase(void)
{
    SetSelfTokenID(accountMgrTokenID);
}

void OsAccountInnerAccmgrCoverageTest::TearDownTestCase(void)
{}

void OsAccountInnerAccmgrCoverageTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountInnerAccmgrCoverageTest::TearDown(void)
{}


/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest001
 * @tc.desc: CreateBaseAdminAccount coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest001, TestSize.Level1)
{
    innerMgrService_->CreateBaseAdminAccount();

    std::shared_ptr<IOsAccountControl> osAccountControl = innerMgrService_->osAccountControl_;
    bool isExistsAccount = false;

    osAccountControl->IsOsAccountExists(Constants::ADMIN_LOCAL_ID, isExistsAccount);
    EXPECT_EQ(true, isExistsAccount);
}


/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest002
 * @tc.desc: CreateBaseAdminAccount coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest002, TestSize.Level1)
{
    innerMgrService_->CreateBaseStandardAccount();

    std::shared_ptr<IOsAccountControl> osAccountControl = innerMgrService_->osAccountControl_;
    bool isExistsAccount = false;

    osAccountControl->IsOsAccountExists(Constants::START_USER_ID, isExistsAccount);
    EXPECT_EQ(true, isExistsAccount);
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest005
 * @tc.desc: CreateBaseAdminAccount coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest005, TestSize.Level1)
{
    bool ret = false;
    innerMgrService_->PushIdIntoActiveList(TEST_USER_ID10);
    innerMgrService_->PushIdIntoActiveList(TEST_USER_ID10);
    ret = innerMgrService_->IsOsAccountIDInActiveList(TEST_USER_ID10);
    EXPECT_EQ(ret, true);

    innerMgrService_->EraseIdFromActiveList(TEST_USER_ID10);
    ret = innerMgrService_->IsOsAccountIDInActiveList(TEST_USER_ID10);
    EXPECT_EQ(ret, false);

    innerMgrService_->EraseIdFromActiveList(TEST_USER_ID55);
    ret = innerMgrService_->IsOsAccountIDInActiveList(TEST_USER_ID55);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest007
 * @tc.desc: CreateBaseAdminAccount coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest007, TestSize.Level1)
{
    bool ret = false;
    innerMgrService_->CheckAndAddLocalIdOperating(TEST_USER_ID10);
    ret = innerMgrService_->CheckAndAddLocalIdOperating(TEST_USER_ID10);
    EXPECT_EQ(ret, false);

    innerMgrService_->RemoveLocalIdToOperating(TEST_USER_ID10);
    ret = innerMgrService_->CheckAndAddLocalIdOperating(TEST_USER_ID10);
    EXPECT_EQ(ret, true);

    innerMgrService_->RemoveLocalIdToOperating(TEST_USER_ID10);
    ret = innerMgrService_->CheckAndAddLocalIdOperating(TEST_USER_ID10);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest008
 * @tc.desc: Test SetOsAccountName set local name, photo publish common event.
 * @tc.type: FUNC
 * @tc.require: issuesI66BFB
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest008, TestSize.Level1)
{
    // create common event subscribe
    setuid(ACCOUNT_UID);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_INFO_UPDATED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<AccountCommonEventSubscriber> subscriberPtr =
        std::make_shared<AccountCommonEventSubscriber>(subscribeInfo);
    ASSERT_NE(subscriberPtr, nullptr);
    bool result = EventFwk::CommonEventManager::SubscribeCommonEvent(subscriberPtr);
    ASSERT_EQ(result, true);

    OsAccountInfo osAccountInfo;
    int errCode = innerMgrService_->CreateOsAccount(ACCOUNT_NAME, OsAccountType::NORMAL, osAccountInfo);
    subscriberPtr->localId_ = osAccountInfo.GetLocalId();
    ASSERT_EQ(errCode, ERR_OK);
    errCode = innerMgrService_->SendMsgForAccountDeactivate(osAccountInfo);
    EXPECT_NE(errCode, ERR_OK);
    int localID = osAccountInfo.GetLocalId();
    errCode = innerMgrService_->SetOsAccountName(localID, ACCOUNT_SET_NAME);
    ASSERT_EQ(errCode, ERR_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));
    ASSERT_EQ(subscriberPtr->GetStatus(), true);
    subscriberPtr->ResetStatus();
    errCode = innerMgrService_->SetOsAccountName(localID, ACCOUNT_SET_NAME);
    ASSERT_EQ(errCode, ERR_OK);
    ASSERT_EQ(subscriberPtr->GetStatus(), false);
    subscriberPtr->ResetStatus();
    errCode = innerMgrService_->SetOsAccountProfilePhoto(localID, ACCOUNT_PHOTO);
    ASSERT_EQ(errCode, ERR_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));
    ASSERT_EQ(subscriberPtr->GetStatus(), true);
    subscriberPtr->ResetStatus();
    errCode = innerMgrService_->SetOsAccountProfilePhoto(localID, ACCOUNT_PHOTO);
    ASSERT_EQ(errCode, ERR_OK);
    ASSERT_EQ(subscriberPtr->GetStatus(), false);
    errCode = innerMgrService_->RemoveOsAccount(localID);
    ASSERT_EQ(errCode, ERR_OK);
    result = EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriberPtr);
    ASSERT_EQ(result, true);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/*
 * @tc.name: SetOsAccountCredentialId001
 * @tc.desc: Test SetOsAccountCredentialId with invalid userid.
 * @tc.type: FUNC
 * @tc.require: #I6JV5X
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, SetOsAccountCredentialId001, TestSize.Level1)
{
    int32_t invalidUserId = -1;
    ErrCode errCode = innerMgrService_->SetOsAccountCredentialId(invalidUserId, 0);
    ASSERT_NE(errCode, ERR_OK);
}

/*
 * @tc.name: SetOsAccountCredentialId002
 * @tc.desc: Test SetOsAccountCredentialId with valid userid.
 * @tc.type: FUNC
 * @tc.require: #I6JV5X
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountInnerAccmgrCoverageTest, SetOsAccountCredentialId002, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = innerMgrService_->CreateOsAccount(ACCOUNT_NAME, OsAccountType::NORMAL, osAccountInfo);
    ASSERT_EQ(errCode, ERR_OK);

    int32_t localID = osAccountInfo.GetLocalId();

    ASSERT_EQ(innerMgrService_->SetOsAccountCredentialId(localID, 0), ERR_OK);

    ASSERT_EQ(innerMgrService_->RemoveOsAccount(localID), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
}  // namespace AccountSA
}  // namespace OHOS

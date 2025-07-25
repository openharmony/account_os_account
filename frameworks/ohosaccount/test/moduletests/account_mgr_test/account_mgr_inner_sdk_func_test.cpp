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

#include "file_ex.h"
#include <fstream>
#include <iostream>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#ifdef BUNDLE_ADAPTER_MOCK
#define private public
#include "account_mgr_service.h"
#undef private
#endif
#include "account_proxy.h"
#include "account_info.h"
#include "iaccount.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "ohos_account_constants.h"
#define private public
#include "ohos_account_kits.h"
#undef private
#include "os_account_manager.h"
#ifdef BUNDLE_ADAPTER_MOCK
#define private public
#include "ohos_account_kits_impl.h"
#include "os_account.h"
#include "os_account_manager_service.h"
#include "os_account_proxy.h"
#undef private
#endif
#include "system_ability_definition.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AccountSA::Constants;
using namespace OHOS::Security::AccessToken;
namespace {
static std::pair<bool, OhosAccountInfo> g_oldInfo;

const std::int32_t LOCAL_ID = 101;
const std::int32_t INVALID_LOCAL_ID = 0;
const std::string KEY_ACCOUNT_EVENT_LOGIN = "LOGIN";
const std::string KEY_ACCOUNT_EVENT_LOGOUT = "LOGOUT";
const std::string KEY_ACCOUNT_EVENT_TOKEN_INVALID = "TOKEN_INVALID";
const std::string KEY_ACCOUNT_EVENT_LOGOFF = "LOGOFF";
const std::string KEY_ACCOUNT_INFO_SCALABLEDATA = "age";
std::string g_eventLogin = OHOS_ACCOUNT_EVENT_LOGIN;
std::string g_eventLogout = OHOS_ACCOUNT_EVENT_LOGOUT;
std::string g_eventTokenInvalid = OHOS_ACCOUNT_EVENT_TOKEN_INVALID;
std::string g_eventLogoff = OHOS_ACCOUNT_EVENT_LOGOFF;
const std::string TEST_ACCOUNT_NAME = "TestAccountName";
const std::string TEST_NICKNAME = "NickName_Test";
const std::string TEST_AVATAR = "Avatar_Test";
const std::string TEST_ACCOUNT_UID = "123456789";
const std::string TEST_EXPECTED_UID = "15E2B0D3C33891EBB0F1EF609EC419420C20E320CE94C65FBC8C3312448EB225";
const std::string TEST_DIFF_ACCOUNT_NAME = "TestDiffAccountName";
const std::string TEST_DIFF_ACCOUNT_UID = "9876432";
const std::string TEST_DIFF_EXPECTED_UID = "FB293C538C2CD118B0441AB3B2EC429A5EA629286A04F31E0CC2EFB96525ADCC";
const std::string TEST_EMPTY_STRING = "";
const std::string STRING_TEST_NAME = "test_account_name";
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
const int32_t ACCOUNT_SA_UID = 3058; // this is accountmgr uid
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
static void RemoveOsAccountWithPermission(const int32_t id)
{
    AccessTokenID originaltoken = GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("accountmgr"));
    ASSERT_EQ(0, setuid(ACCOUNT_SA_UID));
    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(id));
    ASSERT_EQ(0, setuid(0));
    ASSERT_EQ(0, SetSelfTokenID(originaltoken));
};
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
}

class AccountMgrInnerSdkFuncTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AccountMgrInnerSdkFuncTest::SetUpTestCase(void)
{
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
#ifdef BUNDLE_ADAPTER_MOCK
    auto servicePtr = new (std::nothrow) AccountMgrService();
    ASSERT_NE(servicePtr, nullptr);
    servicePtr->state_ = STATE_RUNNING;
    OhosAccountKitsImpl::GetInstance().accountProxy_ = new (std::nothrow) AccountProxy(servicePtr->AsObject());
    ASSERT_NE(OhosAccountKitsImpl::GetInstance().accountProxy_, nullptr);
    auto osAccountService = new (std::nothrow) OsAccountManagerService();
    ASSERT_NE(osAccountService, nullptr);
    IInnerOsAccountManager::GetInstance().Init();
    IInnerOsAccountManager::GetInstance().ActivateDefaultOsAccount();
    OhosAccountManager::GetInstance().OnInitialize();
    OsAccount::GetInstance().proxy_ = new (std::nothrow) OsAccountProxy(osAccountService->AsObject());
    ASSERT_NE(OsAccount::GetInstance().proxy_, nullptr);
#endif
}

void AccountMgrInnerSdkFuncTest::TearDownTestCase(void)
{
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
}

void AccountMgrInnerSdkFuncTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AccountMgrInnerSdkFuncTest::TearDown(void)
{}

/**
 * @tc.name: GetDeviceAccountIdTest
 * @tc.desc: get device account info test
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AccountMgrInnerSdkFuncTest, GetDeviceAccountIdTest, TestSize.Level3)
{
    std::int32_t id;
    auto ret = OhosAccountKits::GetInstance().QueryDeviceAccountId(id);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: GetOhosAccountInfoTest
 * @tc.desc: get ohos account info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, GetOhosAccountInfoTest, TestSize.Level3)
{
    auto ret = OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    EXPECT_EQ(true, ret.first);
}

/**
 * @tc.name: GetDefaultOhosAccountInfoTest
 * @tc.desc: get default ohos account info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, GetDefaultOhosAccountInfoTest, TestSize.Level1)
{
    std::unique_ptr<OhosAccountInfo> accountInfo = std::make_unique<OhosAccountInfo>();
    ASSERT_TRUE(accountInfo != nullptr);
}

/**
 * @tc.name: UidTranslateTest
 * @tc.desc: translate uid to deviceAccountId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, UidTranslateTest, TestSize.Level3)
{
    std::int32_t testUid = 1000000;   // uid for test
    std::int32_t expectedUserID = 5;  // the expected result user ID
    auto ret = OhosAccountKits::GetInstance().GetDeviceAccountIdByUID(testUid);
    EXPECT_EQ(expectedUserID, ret);
}

/**
 * @tc.name: SetOhosAccountInfo002
 * @tc.desc: Test ohos account repeat login will fail
 * @tc.type: FUNC
 * @tc.require: issueI5RWXT
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo002, TestSize.Level3)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount("OhosAccountInfo002", OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    OhosAccountInfo accountInfo;
    OhosAccountInfo accountInfoget;
    accountInfo.name_ = TEST_ACCOUNT_NAME;
    accountInfo.status_ = ACCOUNT_STATE_UNBOUND;
    accountInfo.uid_ = TEST_ACCOUNT_UID;
    accountInfo.nickname_ = TEST_NICKNAME;
    accountInfo.avatar_ = TEST_AVATAR;
    accountInfo.scalableData_.SetParam(KEY_ACCOUNT_INFO_SCALABLEDATA, 123);

    auto ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogin);
    EXPECT_EQ(ret, ERR_OK);
    ret = OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(accountInfoget.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(accountInfoget.nickname_, TEST_NICKNAME);
    EXPECT_EQ(accountInfoget.avatar_, TEST_AVATAR);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA),
        accountInfo.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA));

    ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogin);
    EXPECT_EQ(ret, ERR_OK);
    accountInfo.name_ = TEST_DIFF_ACCOUNT_NAME;
    accountInfo.uid_ = TEST_DIFF_ACCOUNT_UID;
    ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogin);
    EXPECT_EQ(ret, ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR);
    // logout
    accountInfo.name_ = TEST_ACCOUNT_NAME;
    accountInfo.uid_ = TEST_ACCOUNT_UID;
    ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogoff);
    EXPECT_EQ(ret, ERR_OK);
    ret = OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_UNBOUND);
    RemoveOsAccountWithPermission(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: SetOhosAccountInfo004
 * @tc.desc: Test ohos account login and token invalid
 * @tc.type: FUNC
 * @tc.require: issueI5RWXT
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo004, TestSize.Level3)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount("OhosAccountInfo004", OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    OhosAccountInfo accountInfo;
    OhosAccountInfo accountInfoget;
    accountInfo.name_ = TEST_ACCOUNT_NAME;
    accountInfo.status_ = ACCOUNT_STATE_UNBOUND;
    accountInfo.uid_ = TEST_ACCOUNT_UID;
    accountInfo.nickname_ = TEST_NICKNAME;
    accountInfo.avatar_ = TEST_AVATAR;
    accountInfo.scalableData_.SetParam(KEY_ACCOUNT_INFO_SCALABLEDATA, 123);

    EXPECT_EQ(OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogin), ERR_OK);
    EXPECT_EQ(OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget), ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(accountInfoget.nickname_, TEST_NICKNAME);
    EXPECT_EQ(accountInfoget.avatar_, TEST_AVATAR);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA),
        accountInfo.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA));

    EXPECT_EQ(OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventTokenInvalid), ERR_OK);
    EXPECT_EQ(OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget), ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(accountInfoget.nickname_, TEST_NICKNAME);
    EXPECT_EQ(accountInfoget.avatar_, TEST_AVATAR);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA),
        accountInfo.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA));

    EXPECT_EQ(OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogin), ERR_OK);
    EXPECT_EQ(OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget), ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(accountInfoget.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(accountInfoget.nickname_, TEST_NICKNAME);
    EXPECT_EQ(accountInfoget.avatar_, TEST_AVATAR);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA),
        accountInfo.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA));

    EXPECT_EQ(OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogoff), ERR_OK);
    EXPECT_EQ(OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget), ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfoget.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA), TEST_EMPTY_STRING);
    RemoveOsAccountWithPermission(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: SetOhosAccountInfo005
 * @tc.desc: Test ohos account with invalid nickname
 * @tc.type: FUNC
 * @tc.require: issueI5RWXT
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo005, TestSize.Level3)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount("OhosAccountInfo005", OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    OhosAccountInfo accountInfo;
    OhosAccountInfo accountInfoget;
    accountInfo.name_ = TEST_ACCOUNT_NAME;
    accountInfo.status_ = ACCOUNT_STATE_UNBOUND;
    accountInfo.uid_ = TEST_ACCOUNT_UID;
    accountInfo.avatar_ = TEST_AVATAR;
    accountInfo.scalableData_.SetParam(KEY_ACCOUNT_INFO_SCALABLEDATA, 123);
    accountInfo.nickname_ = "";
    for (std::size_t i = 0; i < Constants::NICKNAME_MAX_SIZE + 1; i++) {
        accountInfo.nickname_.push_back('a');
    }

    auto ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogin);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    ret = OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_UNBOUND);
    RemoveOsAccountWithPermission(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: SetOhosAccountInfo006
 * @tc.desc: Test ohos account with invalid avatar
 * @tc.type: FUNC
 * @tc.require: issueI5RWXT
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo006, TestSize.Level3)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount("OhosAccountInfo006", OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    OhosAccountInfo accountInfo;
    OhosAccountInfo accountInfoget;
    accountInfo.name_ = TEST_ACCOUNT_NAME;
    accountInfo.status_ = ACCOUNT_STATE_UNBOUND;
    accountInfo.uid_ = TEST_ACCOUNT_UID;
    accountInfo.nickname_ = TEST_NICKNAME;
    accountInfo.avatar_ = ""; // 10*1024*1024
    accountInfo.scalableData_.SetParam(KEY_ACCOUNT_INFO_SCALABLEDATA, 123);
    for (std::size_t i = 0; i < Constants::AVATAR_MAX_SIZE + 1; i++) {
        accountInfo.avatar_.push_back('a');
    }


    auto ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogin);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    ret = OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_UNBOUND);
    RemoveOsAccountWithPermission(osAccountInfoOne.GetLocalId());
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: SetOhosAccountInfo007
 * @tc.desc: Test SetOhosAccountInfo with invalid event.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXT
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo007, TestSize.Level3)
{
    OhosAccountInfo accountInfo;
    OhosAccountInfo accountInfoget;
    accountInfo.name_ = TEST_DIFF_ACCOUNT_NAME;
    accountInfo.status_ = ACCOUNT_STATE_UNBOUND;
    accountInfo.uid_ = TEST_DIFF_ACCOUNT_UID;
    accountInfo.nickname_ = TEST_NICKNAME;
    accountInfo.avatar_ = TEST_AVATAR;
    accountInfo.scalableData_.SetParam(KEY_ACCOUNT_INFO_SCALABLEDATA, 123);

    std::string eventStr = "invalid_test_event";

    auto ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, eventStr);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: SetOhosAccountInfo008
 * @tc.desc: Test ohos account login and logout and get info by target userid.
 * @tc.type: FUNC
 * @tc.require: issueI6ZFWR issueI6ZFYI
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo008, TestSize.Level3)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount("OhosAccountInfo008", OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    OhosAccountInfo accountInfo;
    OhosAccountInfo accountInfoget;
    accountInfo.name_ = TEST_ACCOUNT_NAME;
    accountInfo.status_ = ACCOUNT_STATE_UNBOUND;
    accountInfo.uid_ = TEST_ACCOUNT_UID;
    accountInfo.nickname_ = TEST_NICKNAME;
    accountInfo.avatar_ = TEST_AVATAR;
    accountInfo.scalableData_.SetParam(KEY_ACCOUNT_INFO_SCALABLEDATA, 123);

    auto ret = OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(
        osAccountInfoOne.GetLocalId(), accountInfo, g_eventLogin);
    EXPECT_EQ(ret, ERR_OK);
    ret = OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(osAccountInfoOne.GetLocalId(), accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(accountInfoget.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(accountInfoget.nickname_, TEST_NICKNAME);
    EXPECT_EQ(accountInfoget.avatar_, TEST_AVATAR);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA),
        accountInfo.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA));

    ret = OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(
        osAccountInfoOne.GetLocalId(), accountInfo, g_eventLogoff);
    EXPECT_EQ(ret, ERR_OK);
    ret = OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(
        osAccountInfoOne.GetLocalId(), accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfoget.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(accountInfoget.nickname_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.avatar_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA), TEST_EMPTY_STRING);
    RemoveOsAccountWithPermission(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: SetOhosAccountInfo009
 * @tc.desc: Test ohos account repeat login and get info by userid will fail
 * @tc.type: FUNC
 * @tc.require: issueI6ZFWR issueI6ZFYI
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo009, TestSize.Level3)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount("OhosAccountInfo009", OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    OhosAccountInfo accountInfo;
    OhosAccountInfo accountInfoget;
    accountInfo.name_ = TEST_ACCOUNT_NAME;
    accountInfo.status_ = ACCOUNT_STATE_UNBOUND;
    accountInfo.uid_ = TEST_ACCOUNT_UID;
    accountInfo.nickname_ = TEST_NICKNAME;
    accountInfo.avatar_ = TEST_AVATAR;
    accountInfo.scalableData_.SetParam(KEY_ACCOUNT_INFO_SCALABLEDATA, 123);

    auto ret = OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(
        osAccountInfoOne.GetLocalId(), accountInfo, g_eventLogin);
    EXPECT_EQ(ret, ERR_OK);
    ret = OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(osAccountInfoOne.GetLocalId(), accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(accountInfoget.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(accountInfoget.nickname_, TEST_NICKNAME);
    EXPECT_EQ(accountInfoget.avatar_, TEST_AVATAR);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA),
        accountInfo.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA));

    ret = OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(
        osAccountInfoOne.GetLocalId(), accountInfo, g_eventLogin);
    EXPECT_EQ(ret, ERR_OK);
    accountInfo.name_ = TEST_DIFF_ACCOUNT_NAME;
    accountInfo.uid_ = TEST_DIFF_ACCOUNT_UID;
    ret = OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(
        osAccountInfoOne.GetLocalId(), accountInfo, g_eventLogin);
    EXPECT_EQ(ret, ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR);
    // logout
    accountInfo.name_ = TEST_ACCOUNT_NAME;
    accountInfo.uid_ = TEST_ACCOUNT_UID;
    ret = OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(
        osAccountInfoOne.GetLocalId(), accountInfo, g_eventLogoff);
    EXPECT_EQ(ret, ERR_OK);
    ret = OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(osAccountInfoOne.GetLocalId(), accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfoget.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(accountInfoget.nickname_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.avatar_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA), TEST_EMPTY_STRING);
    RemoveOsAccountWithPermission(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: SetOhosAccountInfo010
 * @tc.desc: Test ohos account login and logoff and get info by userid
 * @tc.type: FUNC
 * @tc.require: issueI6ZFWR issueI6ZFYI
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo010, TestSize.Level3)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount(STRING_TEST_NAME, OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    OhosAccountInfo accountInfo;
    OhosAccountInfo accountInfoget;
    accountInfo.name_ = TEST_DIFF_ACCOUNT_NAME;
    accountInfo.status_ = ACCOUNT_STATE_UNBOUND;
    accountInfo.uid_ = TEST_DIFF_ACCOUNT_UID;
    accountInfo.nickname_ = TEST_NICKNAME;
    accountInfo.avatar_ = TEST_AVATAR;
    accountInfo.scalableData_.SetParam(KEY_ACCOUNT_INFO_SCALABLEDATA, 123);

    auto ret = OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(
        osAccountInfoOne.GetLocalId(), accountInfo, g_eventLogin);
    EXPECT_EQ(ret, ERR_OK);
    ret = OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(osAccountInfoOne.GetLocalId(), accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, TEST_DIFF_EXPECTED_UID);
    EXPECT_EQ(accountInfoget.name_, TEST_DIFF_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(accountInfoget.nickname_, TEST_NICKNAME);
    EXPECT_EQ(accountInfoget.avatar_, TEST_AVATAR);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA),
        accountInfo.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA));

    ret = OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(
        osAccountInfoOne.GetLocalId(), accountInfo, g_eventLogoff);
    EXPECT_EQ(ret, ERR_OK);
    ret = OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(osAccountInfoOne.GetLocalId(), accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfoget.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(accountInfoget.nickname_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.avatar_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA), TEST_EMPTY_STRING);
    RemoveOsAccountWithPermission(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: SetOhosAccountInfo011
 * @tc.desc: Test ohos account login and token invalid and get info by userid
 * @tc.type: FUNC
 * @tc.require: issueI6ZFWR issueI6ZFYI
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo011, TestSize.Level3)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount(STRING_TEST_NAME, OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    int32_t localId = osAccountInfoOne.GetLocalId();
    OhosAccountInfo accountInfo;
    OhosAccountInfo accountInfoget;
    accountInfo.name_ = TEST_ACCOUNT_NAME;
    accountInfo.status_ = ACCOUNT_STATE_UNBOUND;
    accountInfo.uid_ = TEST_ACCOUNT_UID;
    accountInfo.nickname_ = TEST_NICKNAME;
    accountInfo.avatar_ = TEST_AVATAR;
    accountInfo.scalableData_.SetParam(KEY_ACCOUNT_INFO_SCALABLEDATA, 123);

    EXPECT_EQ(OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(localId, accountInfo, g_eventLogin), ERR_OK);
    EXPECT_EQ(OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(localId, accountInfoget), ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(accountInfoget.nickname_, TEST_NICKNAME);
    EXPECT_EQ(accountInfoget.avatar_, TEST_AVATAR);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA),
        accountInfo.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA));

    EXPECT_EQ(
        OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(localId, accountInfo, g_eventTokenInvalid), ERR_OK);
    EXPECT_EQ(OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(localId, accountInfoget), ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(accountInfoget.nickname_, TEST_NICKNAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(accountInfoget.avatar_, TEST_AVATAR);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA),
        accountInfo.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA));

    EXPECT_EQ(OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(localId, accountInfo, g_eventLogin), ERR_OK);
    EXPECT_EQ(OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(localId, accountInfoget), ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(accountInfoget.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(accountInfoget.nickname_, TEST_NICKNAME);
    EXPECT_EQ(accountInfoget.avatar_, TEST_AVATAR);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA),
        accountInfo.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA));

    EXPECT_EQ(OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(localId, accountInfo, g_eventLogoff), ERR_OK);
    EXPECT_EQ(OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(localId, accountInfoget), ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfoget.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA), TEST_EMPTY_STRING);
    RemoveOsAccountWithPermission(localId);
}

/**
 * @tc.name: SetOhosAccountInfo012
 * @tc.desc: Test ohos account with big avatar
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo012, TestSize.Level3)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount("OhosAccountInfo012", OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    OhosAccountInfo accountInfo;
    OhosAccountInfo accountInfoget;
    accountInfo.name_ = TEST_ACCOUNT_NAME;
    accountInfo.status_ = ACCOUNT_STATE_UNBOUND;
    accountInfo.uid_ = TEST_ACCOUNT_UID;
    accountInfo.nickname_ = TEST_NICKNAME;
    accountInfo.avatar_ = ""; // 10*1024*1024
    accountInfo.scalableData_.SetParam(KEY_ACCOUNT_INFO_SCALABLEDATA, 123);
    for (std::size_t i = 0; i < Constants::AVATAR_MAX_SIZE - 1; i++) {
        accountInfo.avatar_.push_back('a');
    }

    auto ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogin);
    EXPECT_EQ(ret, ERR_OK);
    ret = OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    RemoveOsAccountWithPermission(osAccountInfoOne.GetLocalId());
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: SetOhosAccountInfo013
 * @tc.desc: Test SetOhosAccountInfo with invalid userId.
 * @tc.type: FUNC
 * @tc.require: issueI6ZFWR issueI6ZFYI
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo013, TestSize.Level3)
{
    OhosAccountInfo accountInfo;
    auto ret = OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(LOCAL_ID, accountInfo, g_eventLogin);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, ret);
}

/**
 * @tc.name: SetOhosAccountInfo014
 * @tc.desc: Test SetOhosAccountInfo with invalid userId.
 * @tc.type: FUNC
 * @tc.require: issueI6ZFWR issueI6ZFYI
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo014, TestSize.Level3)
{
    OhosAccountInfo accountInfo;
    auto ret = OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(INVALID_LOCAL_ID, accountInfo, g_eventLogin);
    EXPECT_EQ(ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR, ret);
}

#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
/**
 * @tc.name: SetOhosAccountInfo015
 * @tc.desc: Test ohos account with big name_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo015, TestSize.Level3)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount(
        "SetOhosAccountInfo015", OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    OhosAccountInfo accountInfo;
    OhosAccountInfo accountInfoget;
    for (std::size_t i = 0; i < 256 + 1; i++) { // The max value of name is 256
        accountInfo.name_.push_back('a');
    }
    accountInfo.status_ = ACCOUNT_STATE_UNBOUND;
    accountInfo.uid_ = TEST_ACCOUNT_UID;
    accountInfo.nickname_ = TEST_NICKNAME;
    accountInfo.avatar_ = "";
    accountInfo.scalableData_.SetParam(KEY_ACCOUNT_INFO_SCALABLEDATA, 123);
    auto ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogin);
    EXPECT_EQ(ret, ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR);

    accountInfo.name_ = TEST_ACCOUNT_NAME;
    for (std::size_t i = 0; i < 512 + 1; i++) { // The max value of uid_ is 512
        accountInfo.uid_.push_back('a');
    }
    ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogin);
    EXPECT_EQ(ret, ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR);

    std::string eventLogin;
    for (std::size_t i = 0; i < 1024 + 1; i++) { // The max value of eventLogin is 1024
        eventLogin.push_back('a');
    }
    accountInfo.uid_ = TEST_ACCOUNT_UID;
    ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, eventLogin);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    RemoveOsAccountWithPermission(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: GetOsAccountDistributedInfo
 * @tc.desc: Test GetOhosAccountInfoByUserId with invalid userId.
 * @tc.type: FUNC
 * @tc.require: issueI6ZFWR issueI6ZFYI
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, GetOhosAccountInfoByUserId001, TestSize.Level3)
{
    OhosAccountInfo accountInfo;
    auto ret = OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(LOCAL_ID, accountInfo);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, ret);
}

/**
 * @tc.name: GetOhosAccountInfoByUserId001
 * @tc.desc: Test GetOhosAccountInfoByUserId with invalid userId.
 * @tc.type: FUNC
 * @tc.require: issueI6ZFWR issueI6ZFYI
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, GetOhosAccountInfoByUserId002, TestSize.Level3)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount(STRING_TEST_NAME, OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    OhosAccountInfo accountInfo;
    auto ret = OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(INVALID_LOCAL_ID, accountInfo);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(accountInfo.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfo.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(accountInfo.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(accountInfo.nickname_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfo.avatar_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfo.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA), TEST_EMPTY_STRING);
    RemoveOsAccountWithPermission(osAccountInfoOne.GetLocalId());
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: GetOhosAccountInfoByUserIdTest
 * @tc.desc: Test GetOhosAccountInfoByUserId with invalid userId.
 * @tc.type: FUNC
 * @tc.require: issueI5X50F
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, GetOhosAccountInfoByUserId003, TestSize.Level3)
{
    OhosAccountInfo accountInfo;
    std::int32_t testUserId = 200; // 200 is test user id.
    auto ret = OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(testUserId, accountInfo);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: QueryOhosAccountInfoByUserIdTest
 * @tc.desc: Test QueryOhosAccountInfoByUserId with invalid userId.
 * @tc.type: FUNC
 * @tc.require: issueI5X50F
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, QueryOhosAccountInfoByUserId, TestSize.Level3)
{
    std::int32_t testUserId = -1; // -1 is test user id.
    auto ret = OhosAccountKits::GetInstance().QueryOsAccountDistributedInfo(testUserId);
    EXPECT_NE(true, ret.first);
}

/**
 * @tc.name: GetOhosAccountInfoByUserIdPermissionTest001
 * @tc.desc: Test GetOhosAccountInfoByUserId with invalid hap permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, GetOhosAccountInfoByUserIdPermissionTest001, TestSize.Level3)
{
    uint64_t tokenId;
    ASSERT_TRUE(AllocPermission({"ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS"}, tokenId));
    setuid(ACCOUNT_SA_UID);
    OhosAccountInfo ohosAccountInfo;
    int32_t localId = 100; // default localId.
    ErrCode ret = OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(localId, ohosAccountInfo);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED, ret);
    setuid(0);
    ASSERT_TRUE(RecoveryPermission(tokenId, 0));
}

/**
 * @tc.name: GetOhosAccountInfoByUserIdPermissionTest002
 * @tc.desc: Test GetOhosAccountInfoByUserId with hap permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, GetOhosAccountInfoByUserIdPermissionTest002, TestSize.Level3)
{
    uint64_t tokenId;
    ASSERT_TRUE(AllocPermission(
        {"ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS", "ohos.permission.GET_DISTRIBUTED_ACCOUNTS"}, tokenId));
    setuid(ACCOUNT_SA_UID);
    OhosAccountInfo ohosAccountInfo;
    int32_t localId = 100; // default localId.
    ErrCode ret = OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(localId, ohosAccountInfo);
    EXPECT_EQ(ERR_OK, ret);
    setuid(0);
    ASSERT_TRUE(RecoveryPermission(tokenId, 0));
}

/**
 * @tc.name: GetOhosAccountInfoByUserIdPermissionTest003
 * @tc.desc: Test GetOhosAccountInfoByUserId with invalid sa permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, GetOhosAccountInfoByUserIdPermissionTest003, TestSize.Level3)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("security_component_service"));
    setuid(ACCOUNT_SA_UID);
    OhosAccountInfo ohosAccountInfo;
    int32_t localId = 100; // default localId.
    ErrCode ret = OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(localId, ohosAccountInfo);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED, ret);
    setuid(0);
    ASSERT_EQ(0, SetSelfTokenID(selfTokenId));
}

/**
 * @tc.name: GetOhosAccountInfoByUserIdPermissionTest004
 * @tc.desc: Test GetOhosAccountInfoByUserId with sa permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, GetOhosAccountInfoByUserIdPermissionTest004, TestSize.Level3)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("foundation"));
    setuid(ACCOUNT_SA_UID);
    OhosAccountInfo ohosAccountInfo;
    int32_t localId = 100; // default localId.
    ErrCode ret = OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(localId, ohosAccountInfo);
    EXPECT_EQ(ERR_OK, ret);
    setuid(0);
    ASSERT_EQ(0, SetSelfTokenID(selfTokenId));
}

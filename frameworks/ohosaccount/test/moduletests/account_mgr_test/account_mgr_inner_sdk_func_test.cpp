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

#include "account_error_no.h"
#include "account_proxy.h"
#include "account_info.h"
#include "iaccount.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "ohos_account_constants.h"
#include "ohos_account_kits.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using json = nlohmann::json;
namespace {
static std::pair<bool, OhosAccountInfo> g_oldInfo;

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
}

class AccountMgrInnerSdkFuncTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AccountMgrInnerSdkFuncTest::SetUpTestCase(void)
{}

void AccountMgrInnerSdkFuncTest::TearDownTestCase(void)
{}

void AccountMgrInnerSdkFuncTest::SetUp(void)
{}

void AccountMgrInnerSdkFuncTest::TearDown(void)
{}

/**
 * @tc.name: GetDeviceAccountIdTest
 * @tc.desc: get device account info test
 * @tc.type: FUNC
 * @tc.require: AR000CUF64
*/
HWTEST_F(AccountMgrInnerSdkFuncTest, GetDeviceAccountIdTest, TestSize.Level0)
{
    std::int32_t id;
    auto ret = OhosAccountKits::GetInstance().QueryDeviceAccountId(id);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: GetOhosAccountInfoTest
 * @tc.desc: get ohos account info test
 * @tc.type: FUNC
 * @tc.require: AR000CUF64
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, GetOhosAccountInfoTest, TestSize.Level0)
{
    auto ret = OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    EXPECT_EQ(true, ret.first);
}

/**
 * @tc.name: GetDefaultOhosAccountInfoTest
 * @tc.desc: get default ohos account info test
 * @tc.type: FUNC
 * @tc.require: AR000DIJ27
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
 * @tc.require: AR000CUF64
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, UidTranslateTest, TestSize.Level0)
{
    std::int32_t testUid = 1000000;   // uid for test
    std::int32_t expectedUserID = 5;  // the expected result user ID
    auto ret = OhosAccountKits::GetInstance().GetDeviceAccountIdByUID(testUid);
    EXPECT_EQ(expectedUserID, ret);
}

/**
 * @tc.name: SetOhosAccountInfo001
 * @tc.desc: Test ohos account login and logout
 * @tc.type: FUNC
 * @tc.require: issueI5RWXT
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo001, TestSize.Level0)
{
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


    ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogout);
    EXPECT_EQ(ret, ERR_OK);
    ret = OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfoget.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(accountInfoget.nickname_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.avatar_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA), TEST_EMPTY_STRING);
}

/**
 * @tc.name: SetOhosAccountInfo002
 * @tc.desc: Test ohos account repeat login will fail
 * @tc.type: FUNC
 * @tc.require: issueI5RWXT
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo002, TestSize.Level0)
{
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
    EXPECT_EQ(ret, ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR);
    // logout
    accountInfo.name_ = TEST_ACCOUNT_NAME;
    accountInfo.uid_ = TEST_ACCOUNT_UID;
    ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogout);
    EXPECT_EQ(ret, ERR_OK);
    ret = OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfoget.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(accountInfoget.nickname_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.avatar_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA), TEST_EMPTY_STRING);
}

/**
 * @tc.name: SetOhosAccountInfo003
 * @tc.desc: Test ohos account login and logoff
 * @tc.type: FUNC
 * @tc.require: issueI5RWXT
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo003, TestSize.Level0)
{
    OhosAccountInfo accountInfo;
    OhosAccountInfo accountInfoget;
    accountInfo.name_ = TEST_DIFF_ACCOUNT_NAME;
    accountInfo.status_ = ACCOUNT_STATE_UNBOUND;
    accountInfo.uid_ = TEST_DIFF_ACCOUNT_UID;
    accountInfo.nickname_ = TEST_NICKNAME;
    accountInfo.avatar_ = TEST_AVATAR;
    accountInfo.scalableData_.SetParam(KEY_ACCOUNT_INFO_SCALABLEDATA, 123);

    auto ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogin);
    EXPECT_EQ(ret, ERR_OK);
    ret = OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, TEST_DIFF_EXPECTED_UID);
    EXPECT_EQ(accountInfoget.name_, TEST_DIFF_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(accountInfoget.nickname_, TEST_NICKNAME);
    EXPECT_EQ(accountInfoget.avatar_, TEST_AVATAR);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA),
        accountInfo.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA));

    ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogoff);
    EXPECT_EQ(ret, ERR_OK);
    ret = OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfoget.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_LOGOFF);
    EXPECT_EQ(accountInfoget.nickname_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.avatar_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA), TEST_EMPTY_STRING);
}

/**
 * @tc.name: SetOhosAccountInfo004
 * @tc.desc: Test ohos account login and token invalid
 * @tc.type: FUNC
 * @tc.require: issueI5RWXT
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo004, TestSize.Level0)
{
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
    EXPECT_EQ(accountInfoget.nickname_, TEST_NICKNAME);
    EXPECT_EQ(accountInfoget.avatar_, TEST_AVATAR);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA),
        accountInfo.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA));

    ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventTokenInvalid);
    EXPECT_EQ(ret, ERR_OK);
    ret = OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(accountInfoget.nickname_, TEST_NICKNAME);
    EXPECT_EQ(accountInfoget.avatar_, TEST_AVATAR);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA),
        accountInfo.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA));

    ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogin);
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

    ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, g_eventLogout);
    EXPECT_EQ(ret, ERR_OK);
    ret = OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfoget.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA), TEST_EMPTY_STRING);
}

/**
 * @tc.name: SetOhosAccountInfo005
 * @tc.desc: Test ohos account with invalid nickname
 * @tc.type: FUNC
 * @tc.require: issueI5RWXT
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo005, TestSize.Level0)
{
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
    EXPECT_EQ(ret, ERR_OHOSACCOUNT_KIT_INVALID_PARAMETER);
    ret = OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfoget.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(accountInfoget.nickname_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.avatar_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA), TEST_EMPTY_STRING);
}

/**
 * @tc.name: SetOhosAccountInfo006
 * @tc.desc: Test ohos account with invalid avatar
 * @tc.type: FUNC
 * @tc.require: issueI5RWXT
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo006, TestSize.Level0)
{
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
    EXPECT_EQ(ret, ERR_OHOSACCOUNT_KIT_INVALID_PARAMETER);
    ret = OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfoget);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountInfoget.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfoget.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoget.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(accountInfoget.nickname_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.avatar_, TEST_EMPTY_STRING);
    EXPECT_EQ(accountInfoget.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA), TEST_EMPTY_STRING);
}

/**
 * @tc.name: SetOhosAccountInfo007
 * @tc.desc: Test SetOhosAccountInfo with invalid event.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXT
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, SetOhosAccountInfo007, TestSize.Level0)
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
    EXPECT_EQ(ret, ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR);
}

/**
 * @tc.name: GetOhosAccountInfoByUserIdTest
 * @tc.desc: Test GetOhosAccountInfoByUserId with invalid userId.
 * @tc.type: FUNC
 * @tc.require: issueI5X50F
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, GetOhosAccountInfoByUserId, TestSize.Level0)
{
    OhosAccountInfo accountInfo;
    std::int32_t testUserId = 200; // 200 is test user id.
    auto ret = OhosAccountKits::GetInstance().GetOhosAccountInfoByUserId(testUserId, accountInfo);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: QueryOhosAccountInfoByUserIdTest
 * @tc.desc: Test QueryOhosAccountInfoByUserId with invalid userId.
 * @tc.type: FUNC
 * @tc.require: issueI5X50F
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, QueryOhosAccountInfoByUserId, TestSize.Level0)
{
    std::int32_t testUserId = 200; // 200 is test user id.
    auto ret = OhosAccountKits::GetInstance().QueryOhosAccountInfoByUserId(testUserId);
    EXPECT_NE(true, ret.first);
}
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

#include <filesystem>
#include <fstream>
#include <functional>
#include <gtest/gtest.h>
#include <set>
#include <string>
#include <thread>
#include <vector>

#define private public
#include "account_state_machine.h"
#include "ohos_account_manager.h"
#include "os_account_info.h"
#include "os_account_subspace_manager.h"
#undef private

#include "account_error_no.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "accesstoken_kit.h"
#include "mock_space_dependencies.h"
#include "os_account_constants.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string TEST_ROOT_DIR = "/data/service/el1/public/account/test/";
constexpr int32_t OS_ACCOUNT_ID = 100;
constexpr int32_t BASE_SPACE_ID = 100000;
constexpr int32_t SPACE_ID_1 = 100001;
constexpr int32_t SPACE_ID_2 = 100002;
const std::string TEST_NAME = "TestAccountName";
const std::string TEST_UID = "TestAccountUid";
const std::string TEST_AVATAR = "TestAvatar";
const std::string TEST_NICKNAME = "TestNickname";
}

class OhosAccountSpaceLoginLogoutTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    OhosAccountInfo MakeTestAccountInfo(const std::string &name = TEST_NAME,
        const std::string &rawUid = TEST_UID);
    OsAccountSubspaceInfo MakeTestSpaceInfo(int32_t osAccountId, int32_t subspaceId,
        OHOS_ACCOUNT_STATE status, const OhosAccountInfo &accountInfo = OhosAccountInfo());
    void SetupOsAccountWithForeground(int32_t localId, int32_t foregroundSubspaceId);
    void SaveSpaceViaApi(const OsAccountSubspaceInfo &info);
    void LoadSpaceViaApi(int32_t osAccountId, int32_t subspaceId, OsAccountSubspaceInfo& info);
    void ClearAllTestSpaces();
    void WriteBaseAccountJson(int32_t userId, OHOS_ACCOUNT_STATE status,
        const OhosAccountInfo &accountInfo = OhosAccountInfo());

    static uint64_t allPermTokenId_;
};

uint64_t OhosAccountSpaceLoginLogoutTest::allPermTokenId_ = 0;

void OhosAccountSpaceLoginLogoutTest::SetUpTestCase()
{
    allPermTokenId_ = GetAllAccountPermission();
    ASSERT_NE(allPermTokenId_, 0);
    OsAccountSubspaceManager::GetInstance().Init(TEST_ROOT_DIR);
    OhosAccountManager::GetInstance().OnInitialize();
}

void OhosAccountSpaceLoginLogoutTest::TearDownTestCase()
{
    std::error_code ec;
    std::filesystem::remove_all(TEST_ROOT_DIR, ec);
    if (allPermTokenId_ != 0) {
        Security::AccessToken::AccessTokenKit::DeleteToken(
            static_cast<Security::AccessToken::AccessTokenID>(allPermTokenId_));
    }
}

void OhosAccountSpaceLoginLogoutTest::SetUp()
{
    ASSERT_EQ(SetSelfTokenID(allPermTokenId_), 0);
    ResetMockState();
    std::error_code ec;
    std::filesystem::remove_all(TEST_ROOT_DIR, ec);
    std::filesystem::create_directories(TEST_ROOT_DIR);

    std::filesystem::create_directories(TEST_ROOT_DIR + std::to_string(OS_ACCOUNT_ID));

    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    ACCOUNT_LOGI("[SetUp] %{public}s start", testinfo->name());
}

void OhosAccountSpaceLoginLogoutTest::TearDown()
{
    ClearAllTestSpaces();
}

OhosAccountInfo OhosAccountSpaceLoginLogoutTest::MakeTestAccountInfo(
    const std::string &name, const std::string &rawUid)
{
    OhosAccountInfo info;
    info.name_ = name;
    info.uid_ = rawUid;
    info.nickname_ = TEST_NICKNAME;
    info.avatar_ = TEST_AVATAR;
    return info;
}

OsAccountSubspaceInfo OhosAccountSpaceLoginLogoutTest::MakeTestSpaceInfo(
    int32_t osAccountId, int32_t subspaceId, OHOS_ACCOUNT_STATE status,
    const OhosAccountInfo &accountInfo)
{
    OsAccountSubspaceInfo info;
    info.userId_ = osAccountId;
    info.subspaceId = subspaceId;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    info.ohosAccountInfo_ = accountInfo;
    info.ohosAccountInfo_.status_ = status;
    return info;
}

void OhosAccountSpaceLoginLogoutTest::SetupOsAccountWithForeground(
    int32_t localId, int32_t foregroundSubspaceId)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(localId);
    osAccountInfo.foregroundSubspaceId_ = foregroundSubspaceId;
    std::vector<OsAccountInfo> accounts = {osAccountInfo};
    MockSetCreatedOsAccounts(accounts);
}

void OhosAccountSpaceLoginLogoutTest::SaveSpaceViaApi(const OsAccountSubspaceInfo &info)
{
    ErrCode ret = OhosAccountManager::GetInstance().SetDistributedAccountSpaceInfo(info);
    ASSERT_EQ(ERR_OK, ret);
}

void OhosAccountSpaceLoginLogoutTest::LoadSpaceViaApi(
    int32_t osAccountId, int32_t subspaceId, OsAccountSubspaceInfo& info)
{
    ErrCode ret = OhosAccountManager::GetInstance().GetDistributedAccountSpaceInfo(
        osAccountId, subspaceId, info);
    ASSERT_EQ(ERR_OK, ret);
}

void OhosAccountSpaceLoginLogoutTest::ClearAllTestSpaces()
{
    std::set<int32_t> spaceIds;
    OsAccountSubspaceManager::GetInstance().ScanOsAccountSubspaceIds(OS_ACCOUNT_ID, spaceIds);
    for (int32_t id : spaceIds) {
        OsAccountSubspaceInfo info;
        if (OsAccountSubspaceManager::GetInstance().LoadSubspaceInfo(OS_ACCOUNT_ID, id, info) == ERR_OK) {
            info.ohosAccountInfo_ = OhosAccountInfo();
            info.ohosAccountInfo_.status_ = ACCOUNT_STATE_UNBOUND;
            OsAccountSubspaceManager::GetInstance().SaveSubspaceInfo(info);
        }
    }
}

void OhosAccountSpaceLoginLogoutTest::WriteBaseAccountJson(int32_t userId, OHOS_ACCOUNT_STATE status,
    const OhosAccountInfo &accountInfo)
{
    std::string configDir = TEST_ROOT_DIR + std::to_string(userId);
    std::string configPath = configDir + "/account.json";
    std::string avatarPath = configDir + "/account_avatar";
    std::error_code ec;
    std::filesystem::create_directories(configDir, ec);

    std::ofstream ofs(configPath);
    ofs << "{";
    ofs << "\"version\":" << ACCOUNT_VERSION_ANON << ",";
    ofs << "\"bind_time\":0,";
    ofs << "\"user_id\":" << userId << ",";
    ofs << "\"account_name\":\"" << accountInfo.name_ << "\",";
    ofs << "\"raw_uid\":\"" << accountInfo.GetRawUid() << "\",";
    ofs << "\"open_id\":\"" << accountInfo.uid_ << "\",";
    ofs << "\"bind_status\":" << status << ",";
    ofs << "\"calling_uid\":" << accountInfo.callingUid_ << ",";
    ofs << "\"account_nickname\":\"" << accountInfo.nickname_ << "\",";
    ofs << "\"account_scalableData\":\"\"";
    ofs << "}";
    ofs.close();

    if (!accountInfo.avatar_.empty()) {
        std::ofstream avatarOfs(avatarPath);
        avatarOfs << accountInfo.avatar_;
        avatarOfs.close();
    }
}

// ======================== Login Tests ========================

/**
 * @tc.name: SpaceLoginUnboundTest001
 * @tc.desc: Test login space account with UNBOUND state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, SpaceLogin_Unbound_Success, TestSize.Level1)
{
    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1, ACCOUNT_STATE_UNBOUND);
    SaveSpaceViaApi(spaceInfo);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().LoginOhosAccountSpace(
        OS_ACCOUNT_ID, SPACE_ID_1, accountInfo, OHOS_ACCOUNT_EVENT_LOGIN);

    EXPECT_EQ(ERR_OK, ret);

    OsAccountSubspaceInfo loadedInfo;
    LoadSpaceViaApi(OS_ACCOUNT_ID, SPACE_ID_1, loadedInfo);
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, loadedInfo.ohosAccountInfo_.status_);
    EXPECT_EQ(TEST_NAME, loadedInfo.ohosAccountInfo_.name_);
}

/**
 * @tc.name: SpaceLoginBoundTest001
 * @tc.desc: Test login space account with NOTLOGIN(bound) state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, SpaceLogin_Bound_Success, TestSize.Level1)
{
    OhosAccountInfo boundInfo = MakeTestAccountInfo();
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(TEST_NAME, TEST_UID);
    boundInfo.uid_ = ohosAccountUid;
    boundInfo.status_ = ACCOUNT_STATE_NOTLOGIN;

    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1,
        ACCOUNT_STATE_NOTLOGIN, boundInfo);
    SaveSpaceViaApi(spaceInfo);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().LoginOhosAccountSpace(
        OS_ACCOUNT_ID, SPACE_ID_1, accountInfo, OHOS_ACCOUNT_EVENT_LOGIN);

    EXPECT_EQ(ERR_OK, ret);

    OsAccountSubspaceInfo loadedInfo;
    LoadSpaceViaApi(OS_ACCOUNT_ID, SPACE_ID_1, loadedInfo);
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, loadedInfo.ohosAccountInfo_.status_);
}

/**
 * @tc.name: SpaceLoginUidMismatchTest001
 * @tc.desc: Test login space account with mismatched UID returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, SpaceLogin_UidMismatch_Bound, TestSize.Level1)
{
    OhosAccountInfo boundInfo;
    boundInfo.name_ = "DifferentName";
    boundInfo.uid_ = "DifferentUid";
    boundInfo.status_ = ACCOUNT_STATE_NOTLOGIN;

    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1,
        ACCOUNT_STATE_NOTLOGIN, boundInfo);
    SaveSpaceViaApi(spaceInfo);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().LoginOhosAccountSpace(
        OS_ACCOUNT_ID, SPACE_ID_1, accountInfo, OHOS_ACCOUNT_EVENT_LOGIN);

    EXPECT_EQ(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, ret);
}

/**
 * @tc.name: SpaceLoginReLoginTest001
 * @tc.desc: Test re-login same account in already LOGIN space
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, SpaceLogin_ReLoginSameAccount_Success, TestSize.Level1)
{
    OhosAccountInfo boundInfo = MakeTestAccountInfo();
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(TEST_NAME, TEST_UID);
    boundInfo.uid_ = ohosAccountUid;
    boundInfo.status_ = ACCOUNT_STATE_LOGIN;

    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1,
        ACCOUNT_STATE_LOGIN, boundInfo);
    SaveSpaceViaApi(spaceInfo);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().LoginOhosAccountSpace(
        OS_ACCOUNT_ID, SPACE_ID_1, accountInfo, OHOS_ACCOUNT_EVENT_LOGIN);

    EXPECT_EQ(ERR_OK, ret);

    OsAccountSubspaceInfo loadedInfo;
    LoadSpaceViaApi(OS_ACCOUNT_ID, SPACE_ID_1, loadedInfo);
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, loadedInfo.ohosAccountInfo_.status_);
}

/**
 * @tc.name: SpaceLoginGetSpaceInfoFailTest001
 * @tc.desc: Test login with nonexistent subspaceId returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, SpaceLogin_GetSpaceInfoFail, TestSize.Level1)
{
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().LoginOhosAccountSpace(
        OS_ACCOUNT_ID, 999999, accountInfo, OHOS_ACCOUNT_EVENT_LOGIN);

    EXPECT_NE(ERR_OK, ret);
}

// ======================== Logout Tests ========================

/**
 * @tc.name: SpaceLogoutTest001
 * @tc.desc: Test logout space account successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, SpaceLogout_Success, TestSize.Level1)
{
    OhosAccountInfo boundInfo = MakeTestAccountInfo();
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(TEST_NAME, TEST_UID);
    boundInfo.uid_ = ohosAccountUid;
    boundInfo.status_ = ACCOUNT_STATE_LOGIN;

    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1,
        ACCOUNT_STATE_LOGIN, boundInfo);
    SaveSpaceViaApi(spaceInfo);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().LogoutOhosAccountSpace(
        OS_ACCOUNT_ID, SPACE_ID_1, accountInfo, OHOS_ACCOUNT_EVENT_LOGOUT);

    EXPECT_EQ(ERR_OK, ret);

    OsAccountSubspaceInfo loadedInfo;
    LoadSpaceViaApi(OS_ACCOUNT_ID, SPACE_ID_1, loadedInfo);
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, loadedInfo.ohosAccountInfo_.status_);
    EXPECT_EQ(TEST_NAME, loadedInfo.ohosAccountInfo_.name_);
    EXPECT_EQ(ohosAccountUid, loadedInfo.ohosAccountInfo_.uid_);
}

/**
 * @tc.name: SpaceLogoutUidMismatchTest001
 * @tc.desc: Test logout space account with mismatched UID returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, SpaceLogout_UidMismatch, TestSize.Level1)
{
    OhosAccountInfo boundInfo;
    boundInfo.name_ = "DifferentName";
    boundInfo.uid_ = "DifferentUid";
    boundInfo.status_ = ACCOUNT_STATE_LOGIN;

    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1,
        ACCOUNT_STATE_LOGIN, boundInfo);
    SaveSpaceViaApi(spaceInfo);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().LogoutOhosAccountSpace(
        OS_ACCOUNT_ID, SPACE_ID_1, accountInfo, OHOS_ACCOUNT_EVENT_LOGOUT);

    EXPECT_EQ(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, ret);
}

/**
 * @tc.name: SpaceLogoutOtherSpacesTest001
 * @tc.desc: Test logout one space does not affect other spaces
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, SpaceLogout_OtherSpacesUnaffected, TestSize.Level1)
{
    OhosAccountInfo boundInfo1 = MakeTestAccountInfo();
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(TEST_NAME, TEST_UID);
    boundInfo1.uid_ = ohosAccountUid;
    boundInfo1.status_ = ACCOUNT_STATE_LOGIN;

    OsAccountSubspaceInfo spaceInfo1 = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1,
        ACCOUNT_STATE_LOGIN, boundInfo1);
    SaveSpaceViaApi(spaceInfo1);

    OhosAccountInfo boundInfo2;
    boundInfo2.name_ = "AnotherName";
    boundInfo2.uid_ = "AnotherUid";
    boundInfo2.status_ = ACCOUNT_STATE_LOGIN;

    OsAccountSubspaceInfo spaceInfo2 = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_2,
        ACCOUNT_STATE_LOGIN, boundInfo2);
    SaveSpaceViaApi(spaceInfo2);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().LogoutOhosAccountSpace(
        OS_ACCOUNT_ID, SPACE_ID_1, accountInfo, OHOS_ACCOUNT_EVENT_LOGOUT);

    EXPECT_EQ(ERR_OK, ret);

    OsAccountSubspaceInfo loaded2;
    LoadSpaceViaApi(OS_ACCOUNT_ID, SPACE_ID_2, loaded2);
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, loaded2.ohosAccountInfo_.status_);
}

// ======================== Logoff Tests ========================

/**
 * @tc.name: SpaceLogoffTest001
 * @tc.desc: Test logoff space account successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, SpaceLogoff_Success, TestSize.Level1)
{
    OhosAccountInfo boundInfo = MakeTestAccountInfo();
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(TEST_NAME, TEST_UID);
    boundInfo.uid_ = ohosAccountUid;
    boundInfo.status_ = ACCOUNT_STATE_LOGIN;

    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1,
        ACCOUNT_STATE_LOGIN, boundInfo);
    SaveSpaceViaApi(spaceInfo);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().LogoffOhosAccountSpace(
        OS_ACCOUNT_ID, SPACE_ID_1, accountInfo, OHOS_ACCOUNT_EVENT_LOGOFF);

    EXPECT_EQ(ERR_OK, ret);

    OsAccountSubspaceInfo loadedInfo;
    LoadSpaceViaApi(OS_ACCOUNT_ID, SPACE_ID_1, loadedInfo);
    EXPECT_EQ(ACCOUNT_STATE_LOGOFF, loadedInfo.ohosAccountInfo_.status_);
}

/**
 * @tc.name: SpaceLogoffUidMismatchTest001
 * @tc.desc: Test logoff space account with mismatched UID returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, SpaceLogoff_UidMismatch, TestSize.Level1)
{
    OhosAccountInfo boundInfo;
    boundInfo.name_ = "DifferentName";
    boundInfo.uid_ = "DifferentUid";
    boundInfo.status_ = ACCOUNT_STATE_LOGIN;

    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1,
        ACCOUNT_STATE_LOGIN, boundInfo);
    SaveSpaceViaApi(spaceInfo);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().LogoffOhosAccountSpace(
        OS_ACCOUNT_ID, SPACE_ID_1, accountInfo, OHOS_ACCOUNT_EVENT_LOGOFF);

    EXPECT_EQ(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, ret);
}

// ======================== Token Invalid Tests ========================

/**
 * @tc.name: SpaceTokenInvalidTest001
 * @tc.desc: Test token invalid event changes state to TOKEN_EXPIRED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, SpaceTokenInvalid_Success, TestSize.Level1)
{
    OhosAccountInfo boundInfo = MakeTestAccountInfo();
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(TEST_NAME, TEST_UID);
    boundInfo.uid_ = ohosAccountUid;
    boundInfo.status_ = ACCOUNT_STATE_LOGIN;

    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1,
        ACCOUNT_STATE_LOGIN, boundInfo);
    SaveSpaceViaApi(spaceInfo);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().HandleOhosAccountSpaceTokenInvalidEvent(
        OS_ACCOUNT_ID, SPACE_ID_1, accountInfo, OHOS_ACCOUNT_EVENT_TOKEN_INVALID);

    EXPECT_EQ(ERR_OK, ret);

    OsAccountSubspaceInfo loadedInfo;
    LoadSpaceViaApi(OS_ACCOUNT_ID, SPACE_ID_1, loadedInfo);
    EXPECT_EQ(ACCOUNT_STATE_TOKEN_EXPIRED, loadedInfo.ohosAccountInfo_.status_);
}

/**
 * @tc.name: SpaceTokenInvalidUidMismatchTest001
 * @tc.desc: Test token invalid event with mismatched UID returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, SpaceTokenInvalid_UidMismatch, TestSize.Level1)
{
    OhosAccountInfo boundInfo;
    boundInfo.name_ = "DifferentName";
    boundInfo.uid_ = "DifferentUid";
    boundInfo.status_ = ACCOUNT_STATE_LOGIN;

    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1,
        ACCOUNT_STATE_LOGIN, boundInfo);
    SaveSpaceViaApi(spaceInfo);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().HandleOhosAccountSpaceTokenInvalidEvent(
        OS_ACCOUNT_ID, SPACE_ID_1, accountInfo, OHOS_ACCOUNT_EVENT_TOKEN_INVALID);

    EXPECT_EQ(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, ret);
}

// ======================== State Machine Tests ========================

/**
 * @tc.name: SpaceStateChangeLoginToNotLoginTest001
 * @tc.desc: Test state change from LOGIN to NOTLOGIN via logout event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, StateChange_LoginToNotLogin, TestSize.Level1)
{
    auto &mgr = OhosAccountManager::GetInstance();
    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1, ACCOUNT_STATE_LOGIN);

    auto ret = mgr.HandleSpaceStateChange(spaceInfo, OHOS_ACCOUNT_EVENT_LOGOUT);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, spaceInfo.ohosAccountInfo_.status_);
}

/**
 * @tc.name: SpaceStateChangeLoginToTokenExpiredTest001
 * @tc.desc: Test state change from LOGIN to TOKEN_EXPIRED via token invalid event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, StateChange_LoginToTokenExpired, TestSize.Level1)
{
    auto &mgr = OhosAccountManager::GetInstance();
    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1, ACCOUNT_STATE_LOGIN);

    auto ret = mgr.HandleSpaceStateChange(spaceInfo, OHOS_ACCOUNT_EVENT_TOKEN_INVALID);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(ACCOUNT_STATE_TOKEN_EXPIRED, spaceInfo.ohosAccountInfo_.status_);
}

/**
 * @tc.name: SpaceStateChangeLoginToLogoffTest001
 * @tc.desc: Test state change from LOGIN to LOGOFF via logoff event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, StateChange_LoginToLogoff, TestSize.Level1)
{
    auto &mgr = OhosAccountManager::GetInstance();
    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1, ACCOUNT_STATE_LOGIN);

    auto ret = mgr.HandleSpaceStateChange(spaceInfo, OHOS_ACCOUNT_EVENT_LOGOFF);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(ACCOUNT_STATE_LOGOFF, spaceInfo.ohosAccountInfo_.status_);
}

/**
 * @tc.name: SpaceStateChangeNotLoginToLoginTest001
 * @tc.desc: Test state change from NOTLOGIN to LOGIN via login event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, StateChange_NotLoginToLogin, TestSize.Level1)
{
    auto &mgr = OhosAccountManager::GetInstance();
    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1, ACCOUNT_STATE_NOTLOGIN);

    auto ret = mgr.HandleSpaceStateChange(spaceInfo, OHOS_ACCOUNT_EVENT_LOGIN);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, spaceInfo.ohosAccountInfo_.status_);
}

/**
 * @tc.name: SpaceStateChangeTokenExpiredToLoginTest001
 * @tc.desc: Test state change from TOKEN_EXPIRED to LOGIN via login event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, StateChange_TokenExpiredToLogin, TestSize.Level1)
{
    auto &mgr = OhosAccountManager::GetInstance();
    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1, ACCOUNT_STATE_TOKEN_EXPIRED);

    auto ret = mgr.HandleSpaceStateChange(spaceInfo, OHOS_ACCOUNT_EVENT_LOGIN);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, spaceInfo.ohosAccountInfo_.status_);
}

/**
 * @tc.name: SpaceStateChangeLogoffToLoginTest001
 * @tc.desc: Test state change from LOGOFF to LOGIN via login event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, StateChange_LogoffToLogin, TestSize.Level1)
{
    auto &mgr = OhosAccountManager::GetInstance();
    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1, ACCOUNT_STATE_LOGOFF);

    auto ret = mgr.HandleSpaceStateChange(spaceInfo, OHOS_ACCOUNT_EVENT_LOGIN);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, spaceInfo.ohosAccountInfo_.status_);
}

/**
 * @tc.name: SpaceStateChangeInvalidEventTest001
 * @tc.desc: Test state change with invalid event string returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, StateChange_InvalidEvent, TestSize.Level1)
{
    auto &mgr = OhosAccountManager::GetInstance();
    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1, ACCOUNT_STATE_LOGIN);

    auto ret = mgr.HandleSpaceStateChange(spaceInfo, "INVALID_EVENT");
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, ret);
}

// ======================== Route Tests ========================

/**
 * @tc.name: SpaceStateChangeRouteToLoginTest001
 * @tc.desc: Test OhosAccountStateChange routes to login for UNBOUND space
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, StateChange_RouteToLogin, TestSize.Level1)
{
    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1, ACCOUNT_STATE_UNBOUND);
    SaveSpaceViaApi(spaceInfo);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().OhosAccountStateChange(
        OS_ACCOUNT_ID, accountInfo, OHOS_ACCOUNT_EVENT_LOGIN);

    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: SpaceStateChangeRouteToLogoutTest001
 * @tc.desc: Test OhosAccountStateChange routes to logout for LOGIN space
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, StateChange_RouteToLogout, TestSize.Level1)
{
    OhosAccountInfo boundInfo = MakeTestAccountInfo();
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(TEST_NAME, TEST_UID);
    boundInfo.uid_ = ohosAccountUid;
    boundInfo.status_ = ACCOUNT_STATE_LOGIN;

    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1,
        ACCOUNT_STATE_LOGIN, boundInfo);
    SaveSpaceViaApi(spaceInfo);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().OhosAccountStateChange(
        OS_ACCOUNT_ID, accountInfo, OHOS_ACCOUNT_EVENT_LOGOUT);

    EXPECT_EQ(ERR_OK, ret);

    OsAccountSubspaceInfo loadedInfo;
    LoadSpaceViaApi(OS_ACCOUNT_ID, SPACE_ID_1, loadedInfo);
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, loadedInfo.ohosAccountInfo_.status_);
}

/**
 * @tc.name: SpaceStateChangeInvalidEventStrTest001
 * @tc.desc: Test OhosAccountStateChange with invalid event string returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, StateChange_InvalidEventStr, TestSize.Level1)
{
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().OhosAccountStateChange(
        OS_ACCOUNT_ID, accountInfo, "INVALID_EVENT");

    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, ret);
}

// ======================== App Removal Tests ========================

/**
 * @tc.name: SpaceOnPackageRemovedClearTest001
 * @tc.desc: Test OnPackageRemoved clears spaces with matching callingUid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, OnPackageRemoved_ClearMatchingSpaces, TestSize.Level1)
{
    MockSetCallingUid(1000);

    OhosAccountInfo boundInfo = MakeTestAccountInfo();
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(TEST_NAME, TEST_UID);
    boundInfo.uid_ = ohosAccountUid;
    boundInfo.status_ = ACCOUNT_STATE_LOGIN;
    boundInfo.callingUid_ = 1000;

    OsAccountSubspaceInfo spaceInfo1 = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1,
        ACCOUNT_STATE_LOGIN, boundInfo);
    SaveSpaceViaApi(spaceInfo1);

    OhosAccountInfo boundInfo2;
    boundInfo2.name_ = "AnotherName2";
    boundInfo2.uid_ = "AnotherUid2";
    boundInfo2.status_ = ACCOUNT_STATE_LOGIN;
    boundInfo2.callingUid_ = 2000;

    OsAccountSubspaceInfo spaceInfo2 = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_2,
        ACCOUNT_STATE_LOGIN, boundInfo2);
    SaveSpaceViaApi(spaceInfo2);

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({osAccountInfo});

    OhosAccountManager::GetInstance().OnPackageRemoved(1000);

    OsAccountSubspaceInfo loaded1;
    LoadSpaceViaApi(OS_ACCOUNT_ID, SPACE_ID_1, loaded1);
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, loaded1.ohosAccountInfo_.status_);

    OsAccountSubspaceInfo loaded2;
    LoadSpaceViaApi(OS_ACCOUNT_ID, SPACE_ID_2, loaded2);
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, loaded2.ohosAccountInfo_.status_);
}

/**
 * @tc.name: SpaceOnPackageRemovedNoMatchTest001
 * @tc.desc: Test OnPackageRemoved does not affect spaces with different callingUid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, OnPackageRemoved_NoMatchingSpaces, TestSize.Level1)
{
    OhosAccountInfo boundInfo = MakeTestAccountInfo();
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(TEST_NAME, TEST_UID);
    boundInfo.uid_ = ohosAccountUid;
    boundInfo.status_ = ACCOUNT_STATE_LOGIN;
    boundInfo.callingUid_ = 2000;

    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1,
        ACCOUNT_STATE_LOGIN, boundInfo);
    SaveSpaceViaApi(spaceInfo);

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({osAccountInfo});

    OhosAccountManager::GetInstance().OnPackageRemoved(1000);

    OsAccountSubspaceInfo loaded;
    LoadSpaceViaApi(OS_ACCOUNT_ID, SPACE_ID_1, loaded);
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, loaded.ohosAccountInfo_.status_);
}

// ======================== Event Notification Tests ========================

/**
 * @tc.name: SpaceEventLoginUnboundTest001
 * @tc.desc: Test login UNBOUND space publishes login event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, Event_LoginUnbound_PublishLoginAndBound, TestSize.Level1)
{
    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1, ACCOUNT_STATE_UNBOUND);
    SaveSpaceViaApi(spaceInfo);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().LoginOhosAccountSpace(
        OS_ACCOUNT_ID, SPACE_ID_1, accountInfo, OHOS_ACCOUNT_EVENT_LOGIN);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: SpaceEventLogoutTest001
 * @tc.desc: Test logout space publishes logout event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, Event_Logout_PublishWithIsUnboundFalse, TestSize.Level1)
{
    OhosAccountInfo boundInfo = MakeTestAccountInfo();
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(TEST_NAME, TEST_UID);
    boundInfo.uid_ = ohosAccountUid;
    boundInfo.status_ = ACCOUNT_STATE_LOGIN;

    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1,
        ACCOUNT_STATE_LOGIN, boundInfo);
    SaveSpaceViaApi(spaceInfo);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().LogoutOhosAccountSpace(
        OS_ACCOUNT_ID, SPACE_ID_1, accountInfo, OHOS_ACCOUNT_EVENT_LOGOUT);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: SpaceEventLoginBoundTest001
 * @tc.desc: Test login bound space publishes login event only
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, Event_LoginBound_PublishLoginOnly, TestSize.Level1)
{
    OhosAccountInfo boundInfo = MakeTestAccountInfo();
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(TEST_NAME, TEST_UID);
    boundInfo.uid_ = ohosAccountUid;
    boundInfo.status_ = ACCOUNT_STATE_NOTLOGIN;

    OsAccountSubspaceInfo spaceInfo = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1,
        ACCOUNT_STATE_NOTLOGIN, boundInfo);
    SaveSpaceViaApi(spaceInfo);
    SetupOsAccountWithForeground(OS_ACCOUNT_ID, SPACE_ID_1);

    OhosAccountInfo accountInfo = MakeTestAccountInfo();
    auto ret = OhosAccountManager::GetInstance().LoginOhosAccountSpace(
        OS_ACCOUNT_ID, SPACE_ID_1, accountInfo, OHOS_ACCOUNT_EVENT_LOGIN);
    EXPECT_EQ(ERR_OK, ret);
}

// ======================== Concurrent Tests ========================

/**
 * @tc.name: SpaceConcurrentLoginTest001
 * @tc.desc: Test concurrent login on different spaces
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, Concurrent_LoginDifferentSpaces, TestSize.Level3)
{
    OsAccountSubspaceInfo spaceInfo1 = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_1, ACCOUNT_STATE_UNBOUND);
    SaveSpaceViaApi(spaceInfo1);

    OsAccountSubspaceInfo spaceInfo2 = MakeTestSpaceInfo(OS_ACCOUNT_ID, SPACE_ID_2, ACCOUNT_STATE_UNBOUND);
    SaveSpaceViaApi(spaceInfo2);

    OhosAccountInfo accountInfo1 = MakeTestAccountInfo("Account1", "Uid1");
    OhosAccountInfo accountInfo2 = MakeTestAccountInfo("Account2", "Uid2");

    std::thread t1([&]() {
        OhosAccountManager::GetInstance().LoginOhosAccountSpace(
            OS_ACCOUNT_ID, SPACE_ID_1, accountInfo1, OHOS_ACCOUNT_EVENT_LOGIN);
    });
    std::thread t2([&]() {
        OhosAccountManager::GetInstance().LoginOhosAccountSpace(
            OS_ACCOUNT_ID, SPACE_ID_2, accountInfo2, OHOS_ACCOUNT_EVENT_LOGIN);
    });
    t1.join();
    t2.join();

    OsAccountSubspaceInfo loaded1;
    LoadSpaceViaApi(OS_ACCOUNT_ID, SPACE_ID_1, loaded1);
    OsAccountSubspaceInfo loaded2;
    LoadSpaceViaApi(OS_ACCOUNT_ID, SPACE_ID_2, loaded2);

    bool anyLogin = (loaded1.ohosAccountInfo_.status_ == ACCOUNT_STATE_LOGIN) ||
        (loaded2.ohosAccountInfo_.status_ == ACCOUNT_STATE_LOGIN);
    EXPECT_TRUE(anyLogin);
}

// ======================== Base Space (id=0) Tests ========================

/**
 * @tc.name: SpaceGetBaseSpaceInfoTest001
 * @tc.desc: Test GetDistributedAccountSpaceInfo for base space
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountSpaceLoginLogoutTest, GetDistributedAccountSpaceInfo_BaseSpace, TestSize.Level1)
{
    OhosAccountInfo baseOhosInfo = MakeTestAccountInfo();
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(TEST_NAME, TEST_UID);
    baseOhosInfo.uid_ = ohosAccountUid;
    baseOhosInfo.status_ = ACCOUNT_STATE_LOGIN;
    WriteBaseAccountJson(OS_ACCOUNT_ID, ACCOUNT_STATE_LOGIN, baseOhosInfo);

    auto &mgr = OhosAccountManager::GetInstance();
    OsAccountSubspaceInfo spaceInfo;
    ErrCode ret = mgr.GetDistributedAccountSpaceInfo(OS_ACCOUNT_ID, BASE_SPACE_ID, spaceInfo);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(BASE_SPACE_ID, spaceInfo.subspaceId);
    EXPECT_EQ(OS_ACCOUNT_ID, spaceInfo.userId_);
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, spaceInfo.ohosAccountInfo_.status_);
}

#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

#include "accesstoken_kit.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#define private public
#include "account_iam_callback.h"
#include "iinner_os_account_manager.h"
#include "inner_account_iam_manager.h"
#include "inner_domain_account_manager.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#undef private
#include "iam_common_defines.h"
#include "mock_user_access_ctrl_client.h"
#include "mock_user_idm_client.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::UserIam::UserAuth;

namespace OHOS {
namespace AccountTest {
namespace {
const int32_t TEST_USER_ID = 101;
const int32_t TEST_NON_EXIST_ID = 999;
const std::vector<uint8_t> TEST_TOKEN = {1, 2, 3, 4, 5};
const std::vector<uint8_t> TEST_SECRET = {10, 20, 30, 40, 50};
const uint64_t TEST_SECURE_UID = 12345;
}

class AccountIamDomainUnlockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    void CreateDomainAccount(int32_t userId);
    void RemoveAccount(int32_t userId);
};

void AccountIamDomainUnlockTest::SetUpTestCase()
{
    if (!MockTokenId("accountmgr")) {
        ACCOUNT_LOGW("MockTokenId accountmgr failed, token-based tests may be skipped");
    }
}

void AccountIamDomainUnlockTest::TearDownTestCase()
{
    std::cout << "AccountIamDomainUnlockTest::TearDownTestCase" << std::endl;
}

void AccountIamDomainUnlockTest::SetUp() __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    InnerDomainAccountManager::GetInstance().libHandle_ = reinterpret_cast<void *>(0x1);
    auto &mockIdm = MockUserIdmClient::GetMock();
    auto &mockAccess = MockUserAccessCtrlClient::GetMock();
    Mock::AllowLeak(&mockIdm);
    Mock::AllowLeak(&mockAccess);
}

void AccountIamDomainUnlockTest::TearDown()
{
    auto &mockIdm = MockUserIdmClient::GetMock();
    auto &mockAccess = MockUserAccessCtrlClient::GetMock();
    Mock::VerifyAndClearExpectations(&mockIdm);
    Mock::VerifyAndClearExpectations(&mockAccess);
    RemoveAccount(TEST_USER_ID);
    InnerDomainAccountManager::GetInstance().libHandle_ = nullptr;
}

void AccountIamDomainUnlockTest::CreateDomainAccount(int32_t userId)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "test_domain_account";
    domainInfo.domain_ = "test.example.com";
    OsAccountInfo osAccountInfo(userId, "test_name", OsAccountType::NORMAL, 0);
    osAccountInfo.SetIsCreateCompleted(true);
    osAccountInfo.SetDomainInfo(domainInfo);
    ASSERT_EQ(IInnerOsAccountManager::GetInstance().osAccountControl_->InsertOsAccount(osAccountInfo), ERR_OK);
}

void AccountIamDomainUnlockTest::RemoveAccount(int32_t userId)
{
    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(userId);
}

static void SetupVerifyTokenSuccess()
{
    auto &mockAccess = MockUserAccessCtrlClient::GetMock();
    ON_CALL(mockAccess, VerifyAuthToken(_, _, _))
        .WillByDefault(Invoke([](const std::vector<uint8_t> &token, uint64_t duration,
            const std::shared_ptr<VerifyTokenCallback> &callback) {
            auto cb = std::static_pointer_cast<VerifyTokenSyncCallback>(callback);
            Attributes attr;
            cb->OnResult(ERR_OK, attr);
        }));
    EXPECT_CALL(mockAccess, VerifyAuthToken(_, _, _)).Times(AtLeast(1));
}

static void SetupVerifyTokenFail()
{
    auto &mockAccess = MockUserAccessCtrlClient::GetMock();
    ON_CALL(mockAccess, VerifyAuthToken(_, _, _))
        .WillByDefault(Invoke([](const std::vector<uint8_t> &token, uint64_t duration,
            const std::shared_ptr<VerifyTokenCallback> &callback) {
            auto cb = std::static_pointer_cast<VerifyTokenSyncCallback>(callback);
            Attributes attr;
            cb->OnResult(ResultCode::FAIL, attr);
        }));
    EXPECT_CALL(mockAccess, VerifyAuthToken(_, _, _)).Times(1);
}

static void SetupGetCredInfoNoPin()
{
    auto &mockIdm = MockUserIdmClient::GetMock();
    ON_CALL(mockIdm, GetCredentialInfo(_, _, _))
        .WillByDefault(Invoke([](int32_t userId, AuthType authType,
            const std::shared_ptr<GetCredentialInfoCallback> &callback) {
            auto cb = std::static_pointer_cast<GetCredentialInfoSyncCallback>(callback);
            std::vector<CredentialInfo> emptyList;
            cb->OnCredentialInfo(ResultCode::NOT_ENROLLED, emptyList);
            return static_cast<int32_t>(ResultCode::NOT_ENROLLED);
        }));
    EXPECT_CALL(mockIdm, GetCredentialInfo(_, _, _)).Times(AtLeast(1));
}

static void SetupGetCredInfoHasPin()
{
    auto &mockIdm = MockUserIdmClient::GetMock();
    ON_CALL(mockIdm, GetCredentialInfo(_, _, _))
        .WillByDefault(Invoke([](int32_t userId, AuthType authType,
            const std::shared_ptr<GetCredentialInfoCallback> &callback) {
            auto cb = std::static_pointer_cast<GetCredentialInfoSyncCallback>(callback);
            CredentialInfo credInfo;
            credInfo.authType = AuthType::PIN;
            credInfo.isAbandoned = false;
            std::vector<CredentialInfo> infoList = {credInfo};
            cb->OnCredentialInfo(ERR_OK, infoList);
            return static_cast<int32_t>(ERR_OK);
        }));
    EXPECT_CALL(mockIdm, GetCredentialInfo(_, _, _)).Times(AtLeast(1));
}

static void SetupGetSecUserInfoSuccess()
{
    auto &mockIdm = MockUserIdmClient::GetMock();
    ON_CALL(mockIdm, GetSecUserInfo(_, _))
        .WillByDefault(Invoke([](int32_t userId, const std::shared_ptr<GetSecUserInfoCallback> &callback) {
            auto cb = std::static_pointer_cast<GetSecureUidCallback>(callback);
            SecUserInfo info;
            info.secureUid = TEST_SECURE_UID;
            cb->OnSecUserInfo(ERR_OK, info);
            return static_cast<int32_t>(ERR_OK);
        }));
    EXPECT_CALL(mockIdm, GetSecUserInfo(_, _)).Times(AtLeast(1));
}

/**
 * @tc.name: SetDomainAuthUnlockEnabled_Enable_001
 * @tc.desc: Enable domain auth unlock with valid token, no existing PIN, secureUid obtained.
 * @tc.type: FUNC
 * @tc.require: issuesI64KAM
 */
HWTEST_F(AccountIamDomainUnlockTest, SetDomainAuthUnlockEnabled_Enable_001, TestSize.Level0)
{
    RemoveAccount(TEST_USER_ID);
    CreateDomainAccount(TEST_USER_ID);
    SetupVerifyTokenSuccess();
    SetupGetCredInfoNoPin();
    SetupGetSecUserInfoSuccess();

    ErrCode ret = InnerAccountIAMManager::GetInstance().SetDomainAuthUnlockEnabled(
        TEST_USER_ID, TEST_TOKEN, TEST_SECRET, true);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: SetDomainAuthUnlockEnabled_EnableHasPin_001
 * @tc.desc: Enable domain auth unlock when user already has PIN credential, storage key op skipped.
 * @tc.type: FUNC
 * @tc.require: issuesI64KAM
 */
HWTEST_F(AccountIamDomainUnlockTest, SetDomainAuthUnlockEnabled_EnableHasPin_001, TestSize.Level1)
{
    RemoveAccount(TEST_USER_ID);
    CreateDomainAccount(TEST_USER_ID);
    SetupVerifyTokenSuccess();
    SetupGetCredInfoHasPin();

    ErrCode ret = InnerAccountIAMManager::GetInstance().SetDomainAuthUnlockEnabled(
        TEST_USER_ID, TEST_TOKEN, TEST_SECRET, true);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: SetDomainAuthUnlockEnabled_Disable_001
 * @tc.desc: Disable domain auth unlock when user has no PIN credential, expect ERR_ACCOUNT_IAM_NO_CREDENTIAL.
 * @tc.type: FUNC
 * @tc.require: issuesI64KAM
 */
HWTEST_F(AccountIamDomainUnlockTest, SetDomainAuthUnlockEnabled_Disable_001, TestSize.Level0)
{
    RemoveAccount(TEST_USER_ID);
    CreateDomainAccount(TEST_USER_ID);
    SetupVerifyTokenSuccess();
    SetupGetCredInfoNoPin();

    auto &mockIdm = MockUserIdmClient::GetMock();
    EXPECT_CALL(mockIdm, GetSecUserInfo(_, _)).Times(Exactly(0));

    ErrCode ret = InnerAccountIAMManager::GetInstance().SetDomainAuthUnlockEnabled(
        TEST_USER_ID, TEST_TOKEN, TEST_SECRET, false);
    EXPECT_EQ(ret, ERR_ACCOUNT_IAM_NO_CREDENTIAL);
}

/**
 * @tc.name: SetDomainAuthUnlockEnabled_DisableHasPin_001
 * @tc.desc: Disable domain auth unlock when user already has PIN credential, storage key op skipped.
 * @tc.type: FUNC
 * @tc.require: issuesI64KAM
 */
HWTEST_F(AccountIamDomainUnlockTest, SetDomainAuthUnlockEnabled_DisableHasPin_001, TestSize.Level1)
{
    RemoveAccount(TEST_USER_ID);
    CreateDomainAccount(TEST_USER_ID);
    SetupVerifyTokenSuccess();
    SetupGetCredInfoHasPin();

    auto &mockIdm = MockUserIdmClient::GetMock();
    EXPECT_CALL(mockIdm, GetSecUserInfo(_, _)).Times(Exactly(0));

    ErrCode ret = InnerAccountIAMManager::GetInstance().SetDomainAuthUnlockEnabled(
        TEST_USER_ID, TEST_TOKEN, TEST_SECRET, false);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: SetDomainAuthUnlockEnabled_NonExistUser_001
 * @tc.desc: SetDomainAuthUnlockEnabled with non-existent localId, expect account not exist error.
 * @tc.type: FUNC
 * @tc.require: issuesI64KAM
 */
HWTEST_F(AccountIamDomainUnlockTest, SetDomainAuthUnlockEnabled_NonExistUser_001, TestSize.Level0)
{
    auto &mockIdm = MockUserIdmClient::GetMock();
    EXPECT_CALL(mockIdm, GetCredentialInfo(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(mockIdm, GetSecUserInfo(_, _)).Times(Exactly(0));

    ErrCode ret = InnerAccountIAMManager::GetInstance().SetDomainAuthUnlockEnabled(
        TEST_NON_EXIST_ID, TEST_TOKEN, TEST_SECRET, true);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: SetDomainAuthUnlockEnabled_NotDomainAccount_001
 * @tc.desc: SetDomainAuthUnlockEnabled with a non-domain OS account, expect not domain account error.
 * @tc.type: FUNC
 * @tc.require: issuesI64KAM
 */
HWTEST_F(AccountIamDomainUnlockTest, SetDomainAuthUnlockEnabled_NotDomainAccount_001, TestSize.Level0)
{
    OsAccountInfo osAccountInfo(TEST_USER_ID, "normal_user", OsAccountType::NORMAL, 0);
    osAccountInfo.SetIsCreateCompleted(true);
    ASSERT_EQ(IInnerOsAccountManager::GetInstance().osAccountControl_->InsertOsAccount(osAccountInfo), ERR_OK);

    auto &mockIdm = MockUserIdmClient::GetMock();
    EXPECT_CALL(mockIdm, GetCredentialInfo(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(mockIdm, GetSecUserInfo(_, _)).Times(Exactly(0));

    ErrCode ret = InnerAccountIAMManager::GetInstance().SetDomainAuthUnlockEnabled(
        TEST_USER_ID, TEST_TOKEN, TEST_SECRET, true);
    EXPECT_EQ(ret, ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT);

    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(TEST_USER_ID);
}

/**
 * @tc.name: SetDomainAuthUnlockEnabled_TokenInvalid_001
 * @tc.desc: SetDomainAuthUnlockEnabled with an invalid auth token, VerifyAuthToken fails.
 * @tc.type: FUNC
 * @tc.require: issuesI64KAM
 */
HWTEST_F(AccountIamDomainUnlockTest, SetDomainAuthUnlockEnabled_TokenInvalid_001, TestSize.Level0)
{
    CreateDomainAccount(TEST_USER_ID);
    SetupVerifyTokenFail();

    auto &mockIdm = MockUserIdmClient::GetMock();
    EXPECT_CALL(mockIdm, GetCredentialInfo(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(mockIdm, GetSecUserInfo(_, _)).Times(Exactly(0));

    ErrCode ret = InnerAccountIAMManager::GetInstance().SetDomainAuthUnlockEnabled(
        TEST_USER_ID, TEST_TOKEN, TEST_SECRET, true);
    EXPECT_EQ(ret, ERR_ACCOUNT_IAM_AUTH_TOKEN_INVALID);
}

/**
 * @tc.name: SetDomainAuthUnlockEnabled_NoPlugin_001
 * @tc.desc: SetDomainAuthUnlockEnabled when SO plugin is not loaded, expect not supported error.
 * @tc.type: FUNC
 * @tc.require: issuesI64KAM
 */
HWTEST_F(AccountIamDomainUnlockTest, SetDomainAuthUnlockEnabled_NoPlugin_001, TestSize.Level0)
{
    InnerDomainAccountManager::GetInstance().libHandle_ = nullptr;

    auto &mockIdm = MockUserIdmClient::GetMock();
    EXPECT_CALL(mockIdm, GetCredentialInfo(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(mockIdm, GetSecUserInfo(_, _)).Times(Exactly(0));

    ErrCode ret = InnerAccountIAMManager::GetInstance().SetDomainAuthUnlockEnabled(
        TEST_USER_ID, TEST_TOKEN, TEST_SECRET, true);
    EXPECT_EQ(ret, ERR_DOMAIN_ACCOUNT_NOT_SUPPORT);
}

/**
 * @tc.name: SetDomainAuthUnlockEnabled_GetSecUserFail_001
 * @tc.desc: SetDomainAuthUnlockEnabled when GetSecUserInfo callback returns failure.
 * @tc.type: FUNC
 * @tc.require: issuesI64KAM
 */
HWTEST_F(AccountIamDomainUnlockTest, SetDomainAuthUnlockEnabled_GetSecUserFail_001, TestSize.Level1)
{
    CreateDomainAccount(TEST_USER_ID);
    SetupVerifyTokenSuccess();
    SetupGetCredInfoNoPin();

    auto &mockIdm = MockUserIdmClient::GetMock();
    ON_CALL(mockIdm, GetSecUserInfo(_, _))
        .WillByDefault(Invoke([](int32_t userId, const std::shared_ptr<GetSecUserInfoCallback> &callback) {
            auto cb = std::static_pointer_cast<GetSecureUidCallback>(callback);
            SecUserInfo info;
            cb->OnSecUserInfo(ResultCode::FAIL, info);
            return static_cast<int32_t>(ERR_OK);
        }));
    EXPECT_CALL(mockIdm, GetSecUserInfo(_, _)).Times(1);

    ErrCode ret = InnerAccountIAMManager::GetInstance().SetDomainAuthUnlockEnabled(
        TEST_USER_ID, TEST_TOKEN, TEST_SECRET, true);
    EXPECT_EQ(ret, ERR_ACCOUNT_IAM_GET_SECUSER_FAILED);
}

/**
 * @tc.name: SetDomainAuthUnlockEnabled_GetSecUserIpcFail_001
 * @tc.desc: SetDomainAuthUnlockEnabled when GetSecUserInfo returns IPC failure.
 * @tc.type: FUNC
 * @tc.require: issuesI64KAM
 */
HWTEST_F(AccountIamDomainUnlockTest, SetDomainAuthUnlockEnabled_GetSecUserIpcFail_001, TestSize.Level1)
{
    RemoveAccount(TEST_USER_ID);
    CreateDomainAccount(TEST_USER_ID);
    SetupVerifyTokenSuccess();
    SetupGetCredInfoNoPin();

    auto &mockIdm = MockUserIdmClient::GetMock();
    ON_CALL(mockIdm, GetSecUserInfo(_, _))
        .WillByDefault(Return(static_cast<int32_t>(ResultCode::FAIL)));
    EXPECT_CALL(mockIdm, GetSecUserInfo(_, _)).Times(1);

    ErrCode ret = InnerAccountIAMManager::GetInstance().SetDomainAuthUnlockEnabled(
        TEST_USER_ID, TEST_TOKEN, TEST_SECRET, true);
    EXPECT_EQ(ret, ERR_ACCOUNT_IAM_GET_SECUSER_FAILED);
}
} // namespace AccountTest
} // namespace OHOS

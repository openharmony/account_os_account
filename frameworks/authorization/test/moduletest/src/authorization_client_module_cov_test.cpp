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

#include <gtest/gtest.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "authorization_client.h"
#include "authorization_common.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "os_account_constants.h"
#include "tee_client_api.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AccountSA::Constants;

namespace {
const std::string PRIVILEGE_NAME = "ohos.privilege.manage_local_accounts";
const std::string PRIVILEGE_NAME_TEST = "test.privilege.manage_local_accounts";
}

class AuthorizationClientModuleCovTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AuthorizationClientModuleCovTest::SetUpTestCase(void)
{}

void AuthorizationClientModuleCovTest::TearDownTestCase(void)
{}

void AuthorizationClientModuleCovTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AuthorizationClientModuleCovTest::TearDown(void)
{}

#ifdef SUPPORT_AUTHORIZATION
/**
 * @tc.name: CheckAuthorization001
 * @tc.desc: check authorization, check valid privilege
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorization001, TestSize.Level0)
{
    std::string privilege = PRIVILEGE_NAME;
    bool isAuthorized = true;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorization(
        privilege, isAuthorized);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(isAuthorized, false);

    errCode = AuthorizationClient::GetInstance().ReleaseAuthorization(privilege);
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: CheckAuthorization002
 * @tc.desc: check authorization, check invalid privilege
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorization002, TestSize.Level0)
{
    std::string privilege = PRIVILEGE_NAME_TEST;
    bool isAuthorized = true;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorization(
        privilege, isAuthorized);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_EQ(isAuthorized, false);

    errCode = AuthorizationClient::GetInstance().ReleaseAuthorization(privilege);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: CheckAuthorization003
 * @tc.desc: check authorization, test systemapp
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorization003, TestSize.Level0)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission(ALL_ACCOUNT_PERMISSION_LIST, tokenID, false));
    std::string privilege = PRIVILEGE_NAME_TEST;
    bool isAuthorized = true;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorization(
        privilege, isAuthorized);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
    EXPECT_EQ(isAuthorized, false);

    ASSERT_TRUE(RecoveryPermission(tokenID, selfTokenId));
}

/**
 * @tc.name: CheckAuthorizationWithPid001
 * @tc.desc: check authorization  with pid, check valid privilege
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorizationWithPid001, TestSize.Level0)
{
    int32_t pid = -1;
    std::string privilege = PRIVILEGE_NAME;
    bool isAuthorized = true;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorization(
        privilege, pid, isAuthorized);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(isAuthorized, false);
}

/**
 * @tc.name: CheckAuthorizationWithPid002
 * @tc.desc: check authorization with pid, check invalid privilege
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorizationWithPid002, TestSize.Level0)
{
    int32_t pid = -1;
    std::string privilege = PRIVILEGE_NAME_TEST;
    bool isAuthorized = true;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorization(
        privilege, pid, isAuthorized);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_EQ(isAuthorized, false);
}

/**
 * @tc.name: CheckAuthorizationWithPid003
 * @tc.desc: check authorization with pid, check valid privilege
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorizationWithPid003, TestSize.Level0)
{
    int32_t pid = 1024;
    std::string privilege = PRIVILEGE_NAME;
    bool isAuthorized = true;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorization(
        privilege, pid, isAuthorized);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(isAuthorized, false);
}

/**
 * @tc.name: CheckAuthorizationWithToken001
 * @tc.desc: check authorization with token, token is empty and valid privilege
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorizationWithToken001, TestSize.Level0)
{
    int32_t pid = 0;
    std::string privilege = PRIVILEGE_NAME;
    bool isAuthorized = true;
    std::vector<uint8_t> token = {};
    CheckAuthorizationResult result;
    result.isAuthorized = isAuthorized;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorizationToken(
        token, privilege, pid, result);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(result.isAuthorized, false);
}

/**
 * @tc.name: CheckAuthorizationWithToken002
 * @tc.desc: check authorization with token, token is empty and invalid privilege
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorizationWithToken002, TestSize.Level0)
{
    int32_t pid = 0;
    std::string privilege = PRIVILEGE_NAME_TEST;
    bool isAuthorized = true;
    std::vector<uint8_t> token = {};
    CheckAuthorizationResult result;
    result.isAuthorized = isAuthorized;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorizationToken(
        token, privilege, pid, result);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_EQ(result.isAuthorized, false);
}

/**
 * @tc.name: CheckAuthorizationWithToken003
 * @tc.desc: check authorization with token, token is not empty and valid privilege
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorizationWithToken003, TestSize.Level0)
{
    int32_t pid = 0;
    std::string privilege = PRIVILEGE_NAME;
    bool isAuthorized = true;
    std::vector<uint8_t> token = {1, 2, 3, 4};
    CheckAuthorizationResult result;
    result.isAuthorized = isAuthorized;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorizationToken(
        token, privilege, pid, result);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(result.isAuthorized, false);
}

#else
/**
 * @tc.name: CheckAuthorization001
 * @tc.desc: check authorization.
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorization001, TestSize.Level0)
{
    std::string privilege = PRIVILEGE_NAME_TEST;
    bool isAuthorized = true;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorization(
        privilege, isAuthorized);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_EQ(isAuthorized, false);

    EXPECT_EQ(AuthorizationClient::GetInstance().ReleaseAuthorization(privilege),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: CheckAuthorization002
 * @tc.desc: check authorization.
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorization002, TestSize.Level0)
{
    std::string privilege = PRIVILEGE_NAME;
    bool isAuthorized = true;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorization(
        privilege, isAuthorized);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(isAuthorized, false);

    EXPECT_EQ(AuthorizationClient::GetInstance().ReleaseAuthorization(privilege), ERR_OK);
}

/**
 * @tc.name: CheckAuthorization003
 * @tc.desc: check authorization.
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorization003, TestSize.Level0)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission(ALL_ACCOUNT_PERMISSION_LIST, tokenID, false));
    std::string privilege = PRIVILEGE_NAME;
    bool isAuthorized = true;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorization(
        privilege, isAuthorized);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
    EXPECT_EQ(isAuthorized, false);

    EXPECT_EQ(AuthorizationClient::GetInstance().ReleaseAuthorization(privilege),
        ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    ASSERT_TRUE(RecoveryPermission(tokenID, selfTokenId));
}

/**
 * @tc.name: CheckAuthorization001
 * @tc.desc: check authorization.
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorizationWithPid001, TestSize.Level0)
{
    int32_t pid = 0;
    std::string privilege = PRIVILEGE_NAME_TEST;
    bool isAuthorized = false;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorization(
        privilege, pid, isAuthorized);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_EQ(isAuthorized, true);
}

/**
 * @tc.name: CheckAuthorization002
 * @tc.desc: check authorization.
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorizationWithPid002, TestSize.Level0)
{
    int32_t pid = 0;
    std::string privilege = PRIVILEGE_NAME;
    bool isAuthorized = false;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorization(
        privilege, pid, isAuthorized);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(isAuthorized, true);
}

/**
 * @tc.name: CheckAuthorization003
 * @tc.desc: check authorization.
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorizationWithPid003, TestSize.Level0)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission(ALL_ACCOUNT_PERMISSION_LIST, tokenID, false));
    int32_t pid = 0;
    std::string privilege = PRIVILEGE_NAME;
    bool isAuthorized = false;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorization(
        privilege, pid, isAuthorized);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
    EXPECT_EQ(isAuthorized, true);

    ASSERT_TRUE(RecoveryPermission(tokenID, selfTokenId));
}

/**
 * @tc.name: CheckAuthorizationWithToken001
 * @tc.desc: check authorization.
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorizationWithToken001, TestSize.Level0)
{
    int32_t pid = 0;
    std::string privilege = PRIVILEGE_NAME_TEST;
    bool isAuthorized = false;
    std::vector<uint8_t> token = { 1, 2, 3, 4 };
    CheckAuthorizationResult result;
    result.isAuthorized = isAuthorized;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorizationToken(
        token, privilege, pid, result);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_EQ(result.isAuthorized, true);
}

/**
 * @tc.name: CheckAuthorizationWithToken002
 * @tc.desc: check authorization.
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorizationWithToken002, TestSize.Level0)
{
    int32_t pid = 0;
    std::string privilege = PRIVILEGE_NAME;
    bool isAuthorized = false;
    std::vector<uint8_t> token = {};
    CheckAuthorizationResult result;
    result.isAuthorized = isAuthorized;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorizationToken(
        token, privilege, pid, result);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_EQ(result.isAuthorized, true);
}

/**
 * @tc.name: CheckAuthorizationWithToken003
 * @tc.desc: check authorization.
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorizationWithToken003, TestSize.Level0)
{
    int32_t pid = 0;
    std::string privilege = PRIVILEGE_NAME;
    bool isAuthorized = false;
    std::vector<uint8_t> token = { 1, 2, 3, 4 };
    CheckAuthorizationResult result;
    result.isAuthorized = isAuthorized;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorizationToken(
        token, privilege, pid, result);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(result.isAuthorized, true);
}

/**
 * @tc.name: CheckAuthorizationWithToken004
 * @tc.desc: check authorization.
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorizationWithToken004, TestSize.Level0)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission(ALL_ACCOUNT_PERMISSION_LIST, tokenID, false));
    int32_t pid = 0;
    std::string privilege = PRIVILEGE_NAME;
    bool isAuthorized = false;
    std::vector<uint8_t> token = { 1, 2, 3, 4 };
    CheckAuthorizationResult result;
    result.isAuthorized = isAuthorized;
    ErrCode errCode = AuthorizationClient::GetInstance().CheckAuthorizationToken(
        token, privilege, pid, result);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
    EXPECT_EQ(result.isAuthorized, true);

    ASSERT_TRUE(RecoveryPermission(tokenID, selfTokenId));
}
#endif // SUPPORT_AUTHORIZATION
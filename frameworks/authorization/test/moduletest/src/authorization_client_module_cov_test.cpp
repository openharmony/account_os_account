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

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include <gtest/gtest.h>
#define private public
#include "authorization_client.h"
#undef private
#include "accesstoken_kit.h"
#include "authorization_callback.h"
#include "authorization_common.h"
#include "ipc_skeleton.h"
#include "os_account_constants.h"
#include "os_account_info.h"
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

class MockAuthorizationResultCallback final : public AccountSA::AuthorizationCallback {
public:
    MockAuthorizationResultCallback() = default;
    ErrCode OnResult(int32_t resultCode, const AccountSA::AuthorizationResult& result) override { return ERR_OK; }

    ErrCode OnConnectAbility(const AccountSA::ConnectAbilityInfo& info, const sptr<IRemoteObject>& callback) override
    {
        return ERR_OK;
    }
};

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

#ifdef SUPPORT_AUTHORIZATION
/**
 * @tc.name: RegisterAuthAppRemoteObject001
 * @tc.desc: register auth app remote object when already registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, RegisterAuthAppRemoteObject001, TestSize.Level0)
{
    ErrCode errCode = AuthorizationClient::GetInstance().RegisterAuthAppRemoteObject();
    EXPECT_EQ(errCode, ERR_OK);

    ErrCode errCode2 = AuthorizationClient::GetInstance().RegisterAuthAppRemoteObject();
    EXPECT_EQ(errCode2, ERR_OK);

    AuthorizationClient::GetInstance().UnRegisterAuthAppRemoteObject();
}

/**
 * @tc.name: AcquireAuthorization003
 * @tc.desc: acquire authorization with nullptr callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, AcquireAuthorization003, TestSize.Level0)
{
    std::string privilege = PRIVILEGE_NAME;
    AcquireAuthorizationOptions options;
    std::shared_ptr<MockAuthorizationResultCallback> callback = nullptr;
    ErrCode errCode = AuthorizationClient::GetInstance().AcquireAuthorization(privilege, options, callback);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AcquireAuthorization002
 * @tc.desc: acquire authorization when callback service already exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, AcquireAuthorization002, TestSize.Level0)
{
    std::string privilege = PRIVILEGE_NAME;
    AcquireAuthorizationOptions options;
    auto callback = std::make_shared<MockAuthorizationResultCallback>();
    ErrCode errCode = AuthorizationClient::GetInstance().AcquireAuthorization(privilege, options, callback);
    EXPECT_NE(ERR_OK, errCode);
}

/**
 * @tc.name: EraseAuthCallBack001
 * @tc.desc: erase auth callback when callback service exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, EraseAuthCallBack001, TestSize.Level0)
{
    AuthorizationClient::GetInstance().EraseAuthCallBack();
    auto callback = std::make_shared<MockAuthorizationResultCallback>();

    std::string privilege = PRIVILEGE_NAME;
    AcquireAuthorizationOptions options;

    ErrCode errCode = AuthorizationClient::GetInstance().AcquireAuthorization(privilege, options, callback);
    EXPECT_NE(errCode, ERR_OK);
}

/**
 * @tc.name: GetInstance001
 * @tc.desc: test GetInstance singleton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, GetInstance001, TestSize.Level0)
{
    auto& instance1 = AuthorizationClient::GetInstance();
    auto& instance2 = AuthorizationClient::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

#else
/**
 * @tc.name: RegisterAuthAppRemoteObject001
 * @tc.desc: register auth app remote object without SUPPORT_AUTHORIZATION
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, RegisterAuthAppRemoteObject001, TestSize.Level0)
{
    ErrCode errCode = AuthorizationClient::GetInstance().RegisterAuthAppRemoteObject();
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: UnRegisterAuthAppRemoteObject001
 * @tc.desc: unregister auth app remote object without SUPPORT_AUTHORIZATION
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, UnRegisterAuthAppRemoteObject001, TestSize.Level0)
{
    AuthorizationClient::GetInstance().EraseAuthCallBack();
    ErrCode errCode = AuthorizationClient::GetInstance().UnRegisterAuthAppRemoteObject();
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: AcquireAuthorization001
 * @tc.desc: acquire authorization without SUPPORT_AUTHORIZATION
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, AcquireAuthorization001, TestSize.Level0)
{
    std::string privilege = PRIVILEGE_NAME;
    AcquireAuthorizationOptions options;
    auto callback = std::make_shared<MockAuthorizationResultCallback>();
    ErrCode errCode = AuthorizationClient::GetInstance().AcquireAuthorization(privilege, options, callback);
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: GetInstance001
 * @tc.desc: test GetInstance singleton without SUPPORT_AUTHORIZATION
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, GetInstance001, TestSize.Level0)
{
    auto& instance1 = AuthorizationClient::GetInstance();
    auto& instance2 = AuthorizationClient::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}
#endif // SUPPORT_AUTHORIZATION

/**
 * @tc.name: ConnectAbilityInfo001
 * @tc.desc: ConnectAbilityInfo Marshalling successfully.
 * @tc.type: FUNC
 *
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, ConnectAbilityInfo001, TestSize.Level3)
{
    ConnectAbilityInfo connectAbilityInfo;
    std::vector<uint8_t> challenge;
    connectAbilityInfo.privilege = PRIVILEGE_NAME_TEST;
    connectAbilityInfo.description = PRIVILEGE_NAME_TEST;
    connectAbilityInfo.bundleName = PRIVILEGE_NAME_TEST;
    connectAbilityInfo.abilityName = PRIVILEGE_NAME_TEST;
    connectAbilityInfo.callingUid = 0;
    connectAbilityInfo.callingPid = 0;
    connectAbilityInfo.challenge = challenge;
    connectAbilityInfo.timeout = 0;
    connectAbilityInfo.callingBundleName = PRIVILEGE_NAME_TEST;
    ConnectAbilityInfo connectAbilityInfo3 = connectAbilityInfo;
    ConnectAbilityInfo connectAbilityInfo2;
    connectAbilityInfo2 = connectAbilityInfo3;
    Parcel parcel;
    connectAbilityInfo2.Marshalling(parcel);
    ConnectAbilityInfo* result = connectAbilityInfo2.Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    std::shared_ptr<ConnectAbilityInfo> resultPtr(result);
    EXPECT_EQ(result->description, PRIVILEGE_NAME_TEST);
}

/**
 * @tc.name: AcquireAuthorizationOptions001
 * @tc.desc: AcquireAuthorizationOptions Marshalling successfully with
 * default values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, AcquireAuthorizationOptions001, TestSize.Level3)
{
    AcquireAuthorizationOptions options;
    Parcel parcel;
    bool ret = options.Marshalling(parcel);
    EXPECT_TRUE(ret);

    AcquireAuthorizationOptions* result = options.Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    std::shared_ptr<AcquireAuthorizationOptions> resultPtr(result);
    EXPECT_EQ(result->hasContext, false);
    EXPECT_EQ(result->isReuseNeeded, true);
    EXPECT_EQ(result->isInteractionAllowed, true);
    EXPECT_EQ(result->isContextValid, false);
    EXPECT_TRUE(result->challenge.empty());
}

/**
 * @tc.name: AcquireAuthorizationOptions002
 * @tc.desc: AcquireAuthorizationOptions Marshalling successfully with
 * custom values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, AcquireAuthorizationOptions002, TestSize.Level3)
{
    AcquireAuthorizationOptions options;
    options.hasContext = true;
    options.challenge = {1, 2, 3, 4, 5};
    options.isReuseNeeded = false;
    options.isInteractionAllowed = false;
    options.isContextValid = true;

    Parcel parcel;
    bool ret = options.Marshalling(parcel);
    EXPECT_TRUE(ret);

    AcquireAuthorizationOptions* result = options.Unmarshalling(parcel);
    std::shared_ptr<AcquireAuthorizationOptions> resultPtr(result);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->hasContext, true);
    EXPECT_EQ(result->isReuseNeeded, false);
    EXPECT_EQ(result->isInteractionAllowed, false);
    EXPECT_EQ(result->isContextValid, true);
    EXPECT_EQ(result->challenge.size(), 5);
    EXPECT_EQ(result->challenge[0], 1);
    EXPECT_EQ(result->challenge[4], 5);
}

/**
 * @tc.name: AcquireAuthorizationOptions003
 * @tc.desc: AcquireAuthorizationOptions with large challenge data.
 *
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, AcquireAuthorizationOptions003, TestSize.Level3)
{
    AcquireAuthorizationOptions options;
    options.hasContext = true;
    options.challenge = std::vector<uint8_t>(1000, 0xAB);
    options.isReuseNeeded = true;
    options.isInteractionAllowed = true;
    options.isContextValid = false;

    Parcel parcel;
    bool ret = options.Marshalling(parcel);
    EXPECT_TRUE(ret);

    AcquireAuthorizationOptions* result = options.Unmarshalling(parcel);
    std::shared_ptr<AcquireAuthorizationOptions> resultPtr(result);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->hasContext, true);
    EXPECT_EQ(result->challenge.size(), 1000);
    EXPECT_EQ(result->challenge[0], 0xAB);
    EXPECT_EQ(result->challenge[999], 0xAB);
}

/**
 * @tc.name: AcquireAuthorizationOptions004
 * @tc.desc: AcquireAuthorizationOptions with empty challenge.
 *
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, AcquireAuthorizationOptions004, TestSize.Level3)
{
    AcquireAuthorizationOptions options;
    options.hasContext = false;
    options.challenge = {};
    options.isReuseNeeded = true;
    options.isInteractionAllowed = false;
    options.isContextValid = true;

    Parcel parcel;
    bool ret = options.Marshalling(parcel);
    EXPECT_TRUE(ret);

    AcquireAuthorizationOptions* result = options.Unmarshalling(parcel);
    std::shared_ptr<AcquireAuthorizationOptions> resultPtr(result);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->hasContext, false);
    EXPECT_TRUE(result->challenge.empty());
    EXPECT_EQ(result->isReuseNeeded, true);
    EXPECT_EQ(result->isInteractionAllowed, false);
    EXPECT_EQ(result->isContextValid, true);
}

/**
 * @tc.name: AcquireAuthorizationOptions005
 * @tc.desc: AcquireAuthorizationOptions with all boolean combinations.

 * * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, AcquireAuthorizationOptions005, TestSize.Level3)
{
    AcquireAuthorizationOptions options;
    options.hasContext = true;
    options.challenge = {0xFF, 0x00, 0xAA, 0x55};
    options.isReuseNeeded = false;
    options.isInteractionAllowed = true;
    options.isContextValid = false;

    Parcel parcel;
    bool ret = options.Marshalling(parcel);
    EXPECT_TRUE(ret);

    AcquireAuthorizationOptions* result = options.Unmarshalling(parcel);
    std::shared_ptr<AcquireAuthorizationOptions> resultPtr(result);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->hasContext, true);
    EXPECT_EQ(result->isReuseNeeded, false);
    EXPECT_EQ(result->isInteractionAllowed, true);
    EXPECT_EQ(result->isContextValid, false);
    EXPECT_EQ(result->challenge.size(), 4);
    EXPECT_EQ(result->challenge[0], 0xFF);
    EXPECT_EQ(result->challenge[1], 0x00);
    EXPECT_EQ(result->challenge[2], 0xAA);
    EXPECT_EQ(result->challenge[3], 0x55);
}

/**
 * @tc.name: AuthorizationResult001
 * @tc.desc: AuthorizationResult

 * * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, AuthorizationResult001, TestSize.Level3)
{
    AuthorizationResult result1;
    result1.privilege = "test";
    result1.token = {0xFF, 0x00, 0xAA, 0x55};
    AuthorizationResult result3 = result1;
    AuthorizationResult result2;
    result2 = result3;

    Parcel parcel;
    bool ret = result2.Marshalling(parcel);
    EXPECT_TRUE(ret);

    AuthorizationResult* result = result2.Unmarshalling(parcel);
    std::shared_ptr<AuthorizationResult> resultPtr(result);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->privilege, "test");
}

/**
 * @tc.name: TransVectorU8ToString001
 * @tc.desc: TransVectorU8ToString with empty vector.
 * @tc.type: FUNC
 *
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, TransVectorU8ToString001, TestSize.Level3)
{
    std::vector<uint8_t> vec = {};
    std::string str;
    TransVectorU8ToString(vec, str);
    EXPECT_TRUE(str.empty());
}

/**
 * @tc.name: TransVectorU8ToString004
 * @tc.desc: TransVectorU8ToString with multiple bytes mixed values.
 *
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, TransVectorU8ToString004, TestSize.Level3)
{
    std::vector<uint8_t> vec = {0x00, 0x01, 0x0F, 0x10, 0xAB, 0xFF};
    std::string str;
    TransVectorU8ToString(vec, str);
    EXPECT_EQ(str, "00010F10ABFF");
}

/**
 * @tc.name: TransStringToVectorU8001
 * @tc.desc: TransStringToVectorU8 with empty string.
 * @tc.type: FUNC
 *
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, TransStringToVectorU8001, TestSize.Level3)
{
    std::string str = "";
    std::vector<uint8_t> vec;
    TransStringToVectorU8(vec, str);
    EXPECT_TRUE(vec.empty());
}

/**
 * @tc.name: TransStringToVectorU8002
 * @tc.desc: TransStringToVectorU8 with single character.
 * @tc.type: FUNC
 *
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, TransStringToVectorU8002, TestSize.Level3)
{
    std::string str = "A";
    std::vector<uint8_t> vec;
    TransStringToVectorU8(vec, str);
    ASSERT_EQ(vec.size(), 1);
    EXPECT_EQ(vec[0], 'A');
}

/**
 * @tc.name: TransStringToVectorU8003
 * @tc.desc: TransStringToVectorU8 with multiple characters.
 * @tc.type:
 * FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, TransStringToVectorU8003, TestSize.Level3)
{
    std::string str = "Hello";
    std::vector<uint8_t> vec;
    TransStringToVectorU8(vec, str);
    ASSERT_EQ(vec.size(), 5);
}

/**
 * @tc.name: CheckAuthorizationResult_Marshalling_0100
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorizationResult_Marshalling_0100, TestSize.Level3)
{
    CheckAuthorizationResult result;
    result.isAuthorized = false;
    result.challenge = {};
    result.iamToken = {};
    Parcel parcel;
    EXPECT_TRUE(result.Marshalling(parcel));
    EXPECT_NE(result.Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: CheckAuthorizationResult_Marshalling_0200
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, CheckAuthorizationResult_Marshalling_0200, TestSize.Level3)
{
    CheckAuthorizationResult result;
    result.isAuthorized = false;
    result.challenge = {};
    result.iamToken = {};
    Parcel parcel;
    EXPECT_TRUE(result.Marshalling(parcel));
    EXPECT_TRUE(result.ReadFromParcel(parcel));
}

/**
 * @tc.name: CheckAuthorizationResult_Marshalling_0100
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, RemoveOsAccountOptions_Marshalling_0100, TestSize.Level3)
{
    RemoveOsAccountOptions options;
    Parcel parcel;
    EXPECT_TRUE(options.Marshalling(parcel));
    EXPECT_NE(options.Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: CheckAuthorizationResult_Marshalling_0200
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationClientModuleCovTest, RemoveOsAccountOptions_Marshalling_0200, TestSize.Level3)
{
    RemoveOsAccountOptions options;
    Parcel parcel;
    EXPECT_TRUE(options.Marshalling(parcel));
    EXPECT_TRUE(options.ReadFromParcel(parcel));
}
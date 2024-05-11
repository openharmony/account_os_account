/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "accesstoken_kit.h"
#define private public
#include "account_iam_callback_service.h"
#include "account_iam_client.h"
#undef private
#ifdef PROXY_MOCK
#define private public
#include "account_iam_service.h"
#include "account_iam_mgr_proxy.h"
#undef private
#endif
#include "account_log_wrapper.h"
#include "token_setproc.h"

namespace OHOS {
namespace AccountTest {
namespace {
    const int32_t TEST_USER_ID = 200;
    const uint64_t TEST_CONTEXT_ID = 122;
    const std::vector<uint8_t> TEST_CHALLENGE = {1, 2, 3, 4};
}

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

class MockIDMCallback final : public IDMCallback {
public:
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override
    {
        return;
    }
    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        result_ = result;
        return;
    }

public:
    int32_t result_ = -1;
};

class MockGetCredInfoCallback final : public GetCredInfoCallback {
public:
    void OnCredentialInfo(int32_t result, const std::vector<CredentialInfo> &infoList)override
    {
        return;
    }
};

class MockGetSetPropCallback final : public GetSetPropCallback {
public:
    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        result_ = result;
        return;
    }

public:
    int32_t result_ = -1;
};

class MockGetEnrolledIdCallback final : public GetEnrolledIdCallback {
public:
    void OnEnrolledId(int32_t result, uint64_t enrolledId) override
    {
        result_ = result;
        return;
    }

public:
    int32_t result_ = -1;
};

#ifdef HAS_PIN_AUTH_PART
class MockIInputer : public OHOS::AccountSA::IInputer {
public:
    virtual ~MockIInputer() {}
    void OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
        std::shared_ptr<IInputerData> inputerData) override
    {
        return;
    }
};
#endif

class MockPreRemoteAuthCallback final : public AccountSA::PreRemoteAuthCallback {
public:
    void OnResult(int32_t result) override
    {
        result_ = result;
    }

public:
    int32_t result_ = -1;
};

class AccountIAMClientNoPermissionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AccountIAMClientNoPermissionTest::SetUpTestCase(void)
{
#ifdef PROXY_MOCK
    sptr<IAccountIAM> service = new (std::nothrow) AccountIAMService();
    ASSERT_NE(service, nullptr);
    AccountIAMClient::GetInstance().proxy_ = new (std::nothrow) AccountIAMMgrProxy(service->AsObject());
    ASSERT_NE(AccountIAMClient::GetInstance().proxy_, nullptr);
#endif
}

void AccountIAMClientNoPermissionTest::TearDownTestCase(void)
{}

void AccountIAMClientNoPermissionTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AccountIAMClientNoPermissionTest::TearDown(void)
{}

/**
 * @tc.name: AccountIAMClientNoPermission_OpenSession_0100
 * @tc.desc: Open Session without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_OpenSession_0100, TestSize.Level0)
{
    std::vector<uint8_t> challenge;
    int32_t res = AccountIAMClient::GetInstance().OpenSession(0, challenge);
    EXPECT_TRUE(res == ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    AccountIAMClient::GetInstance().CloseSession(0);
}

/**
 * @tc.name: AccountIAMClientNoPermission_CloseSession_0100
 * @tc.desc: Close Session without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_CloseSession_0100, TestSize.Level0)
{
    std::vector<uint8_t> challenge;
    int32_t res = AccountIAMClient::GetInstance().CloseSession(0);
    EXPECT_TRUE(res == ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: AccountIAMClientNoPermission_AddCredential_0100
 * @tc.desc: Add credential without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_AddCredential_0100, TestSize.Level0)
{
    CredentialParameters testPara = {};
    auto callback = std::make_shared<MockIDMCallback>();
    ASSERT_NE(callback, nullptr);
    AccountIAMClient::GetInstance().AddCredential(TEST_USER_ID, testPara, callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: AccountIAMClientNoPermission_UpdateCredential_0100
 * @tc.desc: Update credential without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_UpdateCredential_0100, TestSize.Level0)
{
    CredentialParameters testPara = {};
    auto callback = std::make_shared<MockIDMCallback>();
    ASSERT_NE(callback, nullptr);
    AccountIAMClient::GetInstance().UpdateCredential(TEST_USER_ID, testPara, callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: AccountIAMClientNoPermission_Cancel_0100
 * @tc.desc: Cancel without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_Cancel_0100, TestSize.Level0)
{
    int32_t res = AccountIAMClient::GetInstance().Cancel(TEST_USER_ID);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: AccountIAMClientNoPermission_DelCred_0100
 * @tc.desc: Delete credential without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_DelCred_0100, TestSize.Level0)
{
    uint64_t testCredentialId = 111;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    auto callback = std::make_shared<MockIDMCallback>();
    ASSERT_NE(callback, nullptr);
    AccountIAMClient::GetInstance().DelCred(TEST_USER_ID, testCredentialId, testAuthToken, callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: AccountIAMClientNoPermission_DelUser_0100
 * @tc.desc: Delete user without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_DelUser_0100, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    auto callback = std::make_shared<MockIDMCallback>();
    ASSERT_NE(callback, nullptr);
    AccountIAMClient::GetInstance().DelUser(TEST_USER_ID, testAuthToken, callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: AccountIAMClientNoPermission_GetCredentialInfo_0100
 * @tc.desc: Get credential info without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_GetCredentialInfo_0100, TestSize.Level0)
{
    auto callback = std::make_shared<MockGetCredInfoCallback>();
    ASSERT_NE(callback, nullptr);
    int32_t res = AccountIAMClient::GetInstance().GetCredentialInfo(TEST_USER_ID, AuthType::PIN, callback);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: AccountIAMClientNoPermission_GetEnrolledId_0100
 * @tc.desc: Get credential info without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_GetEnrolledId_0100, TestSize.Level0)
{
    auto callback = std::make_shared<MockGetEnrolledIdCallback>();
    ASSERT_NE(callback, nullptr);
    AccountIAMClient::GetInstance().GetEnrolledId(TEST_USER_ID, AuthType::PIN, callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: AccountIAMClientNoPermission_GetAvailableStatus_0100
 * @tc.desc: Get available status without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_GetAvailableStatus_0100, TestSize.Level0)
{
    int32_t status;
    int32_t res = AccountIAMClient::GetInstance().GetAvailableStatus(AuthType::FACE, AuthTrustLevel::ATL1, status);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: AccountIAMClientNoPermission_GetProperty_0100
 * @tc.desc: Get property without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_GetProperty_0100, TestSize.Level0)
{
    GetPropertyRequest testRequest = {};
    auto callback = std::make_shared<MockGetSetPropCallback>();
    ASSERT_NE(callback, nullptr);
    AccountIAMClient::GetInstance().GetProperty(TEST_USER_ID, testRequest, callback);
}

/**
 * @tc.name: AccountIAMClientNoPermission_SetProperty_0100
 * @tc.desc: Set property without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_SetProperty_0100, TestSize.Level0)
{
    SetPropertyRequest testRequest = {};
    auto callback = std::make_shared<MockGetSetPropCallback>();
    ASSERT_NE(callback, nullptr);
    AccountIAMClient::GetInstance().SetProperty(TEST_USER_ID, testRequest, callback);
}

#ifdef HAS_PIN_AUTH_PART
/**
 * @tc.name: AccountIAMClientNoPermission_RegisterInputer_0100
 * @tc.desc: RegisterInputer without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_RegisterInputer_0100, TestSize.Level0)
{
    std::shared_ptr<MockIInputer> inputer = std::make_shared<MockIInputer>();
    int32_t res = AccountIAMClient::GetInstance().RegisterInputer(AuthType::PIN, inputer);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    AccountIAMClient::GetInstance().UnregisterInputer(AuthType::PIN);
}
#endif

/**
 * @tc.name: AccountIAMClientNoPermission_AuthUser_0100
 * @tc.desc: Auth user without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_AuthUser_0100, TestSize.Level0)
{
    SetPropertyRequest testRequest = {};
    auto callback = std::make_shared<MockIDMCallback>();
    ASSERT_NE(callback, nullptr);
    AuthOptions authOptions;
    authOptions.accountId = TEST_USER_ID;
    int32_t res = AccountIAMClient::GetInstance().AuthUser(
        authOptions, TEST_CHALLENGE, AuthType::PIN, AuthTrustLevel::ATL1, callback);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.name: AccountIAMClientNoPermission_CancelAuth_0100
 * @tc.desc: Cancel authentication without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_CancelAuth_0100, TestSize.Level0)
{
    int32_t res = AccountIAMClient::GetInstance().CancelAuth(TEST_CONTEXT_ID);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: AccountIAMClientNoPermission_prepareRemoteAuth_0100
 * @tc.desc: prepare remote authentication without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientNoPermissionTest, AccountIAMClientNoPermission_prepareRemoteAuth_0100, TestSize.Level0)
{
    auto callback = std::make_shared<MockPreRemoteAuthCallback>();
    ASSERT_NE(callback, nullptr);
    int32_t res = AccountIAMClient::GetInstance().PrepareRemoteAuth("testString", callback);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}
}  // namespace AccountTest
}  // namespace OHOS
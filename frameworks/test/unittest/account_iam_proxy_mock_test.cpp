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
#include "account_iam_client.h"
#include "account_log_wrapper.h"

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
using namespace OHOS::UserIam::UserAuth;

class AccountIAMProxyMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AccountIAMProxyMockTest::SetUpTestCase(void)
{}

void AccountIAMProxyMockTest::TearDownTestCase(void)
{}

void AccountIAMProxyMockTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AccountIAMProxyMockTest::TearDown(void)
{}

class IDMCallbackMockTest final : public AccountSA::IDMCallback {
public:
    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo)
    {
        result_ = result;
    }
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) {}
    int32_t result_;
};

class GetSetPropCallbackMockTest final : public AccountSA::GetSetPropCallback {
public:
    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo)
    {
        result_ = result;
    }
    int32_t result_;
};

class PreRemoteAuthCallbackMockTest final : public AccountSA::PreRemoteAuthCallback {
public:
    void OnResult(int32_t result) override
    {
        result_ = result;
    }
    int32_t result_;
};

/**
 * @tc.name: AccountIAMClient_OpenSession_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMProxyMockTest, AccountIAMClient_OpenSession_0100, TestSize.Level0)
{
    std::vector<uint8_t> challenge;
    ASSERT_EQ(ERR_ACCOUNT_COMMON_GET_PROXY, AccountIAMClient::GetInstance().OpenSession(TEST_USER_ID, challenge));
}

/**
 * @tc.name: AccountIAMClient_CloseSession_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMProxyMockTest, AccountIAMClient_CloseSession_0100, TestSize.Level0)
{
    ASSERT_EQ(ERR_ACCOUNT_COMMON_GET_PROXY, AccountIAMClient::GetInstance().CloseSession(TEST_USER_ID));
}

/**
 * @tc.name: AccountIAMClient_AddCredential_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMProxyMockTest, AccountIAMClient_AddCredential_0100, TestSize.Level0)
{
    CredentialParameters testPara = {};
    auto testCallback = std::make_shared<IDMCallbackMockTest>();
    ASSERT_NE(testCallback, nullptr);
    AccountIAMClient::GetInstance().AddCredential(TEST_USER_ID, testPara, testCallback);
    ASSERT_EQ(ERR_ACCOUNT_COMMON_GET_PROXY, testCallback->result_);
}

/**
 * @tc.name: AccountIAMClient_UpdateCredential_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMProxyMockTest, AccountIAMClient_UpdateCredential_0100, TestSize.Level0)
{
    CredentialParameters testPara = {};
    auto testCallback = std::make_shared<IDMCallbackMockTest>();
    ASSERT_NE(testCallback, nullptr);
    AccountIAMClient::GetInstance().UpdateCredential(TEST_USER_ID, testPara, testCallback);
    ASSERT_EQ(ERR_ACCOUNT_COMMON_GET_PROXY, testCallback->result_);
}

/**
 * @tc.name: AccountIAMClient_Cancel_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMProxyMockTest, AccountIAMClient_Cancel_0100, TestSize.Level0)
{
    ASSERT_EQ(ERR_ACCOUNT_COMMON_GET_PROXY, AccountIAMClient::GetInstance().Cancel(TEST_USER_ID));
}

/**
 * @tc.name: AccountIAMClient_DelCred_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMProxyMockTest, AccountIAMClient_DelCred_0100, TestSize.Level0)
{
    uint64_t testCredentialId = 111;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    auto testCallback = std::make_shared<IDMCallbackMockTest>();
    ASSERT_NE(testCallback, nullptr);
    AccountIAMClient::GetInstance().DelCred(TEST_USER_ID, testCredentialId, testAuthToken, testCallback);
    ASSERT_EQ(ERR_ACCOUNT_COMMON_GET_PROXY, testCallback->result_);
}

/**
 * @tc.name: AccountIAMClient_DelUser_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMProxyMockTest, AccountIAMClient_DelUser_0100, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    auto testCallback = std::make_shared<IDMCallbackMockTest>();
    ASSERT_NE(testCallback, nullptr);
    AccountIAMClient::GetInstance().DelUser(TEST_USER_ID, testAuthToken, testCallback);
    ASSERT_EQ(ERR_ACCOUNT_COMMON_GET_PROXY, testCallback->result_);
}

/**
 * @tc.name: AccountIAMClient_GetCredentialInfo_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMProxyMockTest, AccountIAMClient_GetCredentialInfo_0100, TestSize.Level0)
{
    ASSERT_EQ(ERR_ACCOUNT_COMMON_GET_PROXY,
        AccountIAMClient::GetInstance().GetCredentialInfo(TEST_USER_ID, AuthType::PIN, nullptr));
}

/**
 * @tc.name: AccountIAMClient_AuthUser_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMProxyMockTest, AccountIAMClient_AuthUser_0100, TestSize.Level0)
{
    SetPropertyRequest testRequest = {};
    auto testCallback = std::make_shared<IDMCallbackMockTest>();
    ASSERT_NE(testCallback, nullptr);
    AuthOptions authOptions;
    authOptions.accountId = TEST_USER_ID;
    ASSERT_EQ(static_cast<uint64_t>(0), AccountIAMClient::GetInstance().AuthUser(
        authOptions, TEST_CHALLENGE, AuthType::PIN, AuthTrustLevel::ATL1, testCallback));
}

/**
 * @tc.name: AccountIAMClient_CancelAuth_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMProxyMockTest, AccountIAMClient_CancelAuth_0100, TestSize.Level0)
{
    ASSERT_EQ(ERR_ACCOUNT_COMMON_GET_PROXY, AccountIAMClient::GetInstance().CancelAuth(TEST_CONTEXT_ID));
}

/**
 * @tc.name: AccountIAMClient_GetAvailableStatus_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMProxyMockTest, AccountIAMClient_GetAvailableStatus_0100, TestSize.Level0)
{
    int32_t status;
    int32_t ret = AccountIAMClient::GetInstance().GetAvailableStatus(AuthType::FACE, AuthTrustLevel::ATL1, status);
    ASSERT_EQ(ERR_ACCOUNT_COMMON_GET_PROXY, ret);
}

/**
 * @tc.name: AccountIAMClient_GetProperty_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMProxyMockTest, AccountIAMClient_GetProperty_0100, TestSize.Level0)
{
    GetPropertyRequest testRequest = {};
    auto testCallback = std::make_shared<GetSetPropCallbackMockTest>();
    ASSERT_NE(testCallback, nullptr);
    AccountIAMClient::GetInstance().GetProperty(TEST_USER_ID, testRequest, testCallback);
    ASSERT_EQ(ERR_ACCOUNT_COMMON_GET_PROXY, testCallback->result_);
}

/**
 * @tc.name: AccountIAMClient_SetProperty_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMProxyMockTest, AccountIAMClient_SetProperty_0100, TestSize.Level0)
{
    SetPropertyRequest testRequest = {};
    auto testCallback = std::make_shared<GetSetPropCallbackMockTest>();
    ASSERT_NE(testCallback, nullptr);
    AccountIAMClient::GetInstance().SetProperty(TEST_USER_ID, testRequest, testCallback);
    ASSERT_EQ(ERR_ACCOUNT_COMMON_GET_PROXY, testCallback->result_);
}

/**
 * @tc.name: AccountIAMClient_GetAccountState_0100
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMProxyMockTest, AccountIAMClient_GetAccountState_0100, TestSize.Level0)
{
    EXPECT_EQ(IDLE, AccountIAMClient::GetInstance().GetAccountState(TEST_USER_ID));
}

/**
 * @tc.name: AccountIAMClient_PrepareRemoteAuth_0100
 * @tc.desc: Test func PrepareRemoteAuth.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMProxyMockTest, AccountIAMClient_PrepareRemoteAuth_0100, TestSize.Level0)
{
    auto testCallback = std::make_shared<PreRemoteAuthCallbackMockTest>();
    ASSERT_NE(testCallback, nullptr);
    AccountIAMClient::GetInstance().PrepareRemoteAuth("testString", testCallback);
    EXPECT_NE(testCallback->result_, 0);
}
}  // namespace AccountTest
}  // namespace OHOS
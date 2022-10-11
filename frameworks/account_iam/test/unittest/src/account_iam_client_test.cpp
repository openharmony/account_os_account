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

#include "accesstoken_kit.h"
#include "account_iam_client.h"
#include "account_iam_client_test_callback.h"
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

class AccountIAMClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AccountIAMClientTest::SetUpTestCase(void)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.settings", 0);
    SetSelfTokenID(tokenId);
}

void AccountIAMClientTest::TearDownTestCase(void)
{}

void AccountIAMClientTest::SetUp(void)
{}

void AccountIAMClientTest::TearDown(void)
{}

/**
 * @tc.name: AccountIAMClient_OpenSession_0100
 * @tc.desc: Open Session.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_OpenSession_0100, TestSize.Level0)
{
    std::vector<uint8_t> challenge;
    AccountIAMClient::GetInstance().OpenSession(0, challenge);
    EXPECT_TRUE(challenge.size() != 0);
    AccountIAMClient::GetInstance().CloseSession(0);
}

/**
 * @tc.name: AccountIAMClient_AddCredential_0100
 * @tc.desc: Add credential.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_AddCredential_0100, TestSize.Level0)
{
    CredentialParameters testPara = {};
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(1));
    AccountIAMClient::GetInstance().AddCredential(TEST_USER_ID, testPara, testCallback);
}

/**
 * @tc.name: AccountIAMClient_UpdateCredential_0100
 * @tc.desc: Update credential.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_UpdateCredential_0100, TestSize.Level0)
{
    CredentialParameters testPara = {};
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(1));
    AccountIAMClient::GetInstance().UpdateCredential(TEST_USER_ID, testPara, testCallback);
}

/**
 * @tc.name: AccountIAMClient_Cancel_0100
 * @tc.desc: Cancel.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_Cancel_0100, TestSize.Level0)
{
    uint64_t testChallenge = 0;
    int32_t ret = AccountIAMClient::GetInstance().Cancel(TEST_USER_ID, testChallenge);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: AccountIAMClient_DelCred_0100
 * @tc.desc: Delete credential.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_DelCred_0100, TestSize.Level0)
{
    uint64_t testCredentialId = 111;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(1));
    AccountIAMClient::GetInstance().DelCred(TEST_USER_ID, testCredentialId, testAuthToken, testCallback);
}

/**
 * @tc.name: AccountIAMClient_DelUser_0100
 * @tc.desc: Delete user.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_DelUser_0100, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(1));
    AccountIAMClient::GetInstance().DelUser(TEST_USER_ID, testAuthToken, testCallback);
}

/**
 * @tc.name: AccountIAMClient_GetCredentialInfo_0100
 * @tc.desc: Get credential info.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_GetCredentialInfo_0100, TestSize.Level0)
{
    auto testCallback = std::make_shared<MockGetCredInfoCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnCredentialInfo(_)).Times(Exactly(1));
    AccountIAMClient::GetInstance().GetCredentialInfo(TEST_USER_ID, AuthType::PIN, testCallback);
}

/**
 * @tc.name: AccountIAMClient_GetAvailableStatus_0100
 * @tc.desc: Get available status.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_GetAvailableStatus_0100, TestSize.Level0)
{
    int32_t status;
    int32_t ret = AccountIAMClient::GetInstance().GetAvailableStatus(AuthType::FACE, AuthTrustLevel::ATL1, status);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: AccountIAMClient_GetProperty_0100
 * @tc.desc: Get property.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_GetProperty_0100, TestSize.Level0)
{
    GetPropertyRequest testRequest = {};
    auto testCallback = std::make_shared<MockGetSetPropCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    AccountIAMClient::GetInstance().GetProperty(TEST_USER_ID, testRequest, testCallback);
}

/**
 * @tc.name: AccountIAMClient_SetProperty_0100
 * @tc.desc: Set property.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_SetProperty_0100, TestSize.Level0)
{
    SetPropertyRequest testRequest = {};
    auto testCallback = std::make_shared<MockGetSetPropCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    AccountIAMClient::GetInstance().SetProperty(TEST_USER_ID, testRequest, testCallback);
}

/**
 * @tc.name: AccountIAMClient_AuthUser_0100
 * @tc.desc: Auth user.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_AuthUser_0100, TestSize.Level0)
{
    SetPropertyRequest testRequest = {};
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    AccountIAMClient::GetInstance().AuthUser(
        TEST_USER_ID, TEST_CHALLENGE, AuthType::PIN, AuthTrustLevel::ATL1, testCallback);
}

/**
 * @tc.name: AccountIAMClient_Auth_0100
 * @tc.desc: Auth current user.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_Auth_0100, TestSize.Level0)
{
    SetPropertyRequest testRequest = {};
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    AccountIAMClient::GetInstance().Auth(TEST_CHALLENGE, AuthType::PIN, AuthTrustLevel::ATL1, testCallback);
}

/**
 * @tc.name: AccountIAMClient_CancelAuth_0100
 * @tc.desc: Cancel authentication.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_CancelAuth_0100, TestSize.Level0)
{
    int32_t ret = AccountIAMClient::GetInstance().CancelAuth(TEST_CONTEXT_ID);
    EXPECT_NE(ret, 0);
}
}  // namespace AccountTest
}  // namespace OHOS
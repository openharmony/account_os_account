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
#include <unistd.h>

#include "accesstoken_kit.h"
#include "account_log_wrapper.h"
#include "account_error_no.h"
#include "account_iam_callback_stub.h"
#include "inner_account_iam_manager.h"
#include "iam_common_defines.h"
#include "token_setproc.h"
#include "parameter.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace Security::AccessToken;

namespace OHOS {
namespace AccountTest {
namespace {
    const int32_t TEST_USER_ID = 101;
    const std::vector<uint8_t> TEST_CHALLENGE = {1, 2, 3, 4};
    static bool g_fscryptEnable = false;
    const uid_t ACCOUNT_UID = 3058;
}

class MockIIDMCallback : public IDMCallbackStub {
public:
    MOCK_METHOD2(OnResult, void(int32_t result, const AccountSA::Attributes &extraInfo));
    MOCK_METHOD3(OnAcquireInfo, void(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo));
};

class AccountIamManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static bool FscryptEnable()
{
    const int bufferLen = 128;
    char fscryptValue[bufferLen] = {0};
    int ret = GetParameter("fscrypt.policy.config", "", fscryptValue, bufferLen - 1);
    if (ret <= 0) {
        return false;
    }
    return true;
}

void AccountIamManagerTest::SetUpTestCase()
{
    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("accountmgr");
    SetSelfTokenID(tokenId);
    setuid(ACCOUNT_UID);
    g_fscryptEnable = FscryptEnable();
}

void AccountIamManagerTest::TearDownTestCase()
{
    std::cout << "AccountIamManagerTest::TearDownTestCase" << std::endl;
}

void AccountIamManagerTest::SetUp()
{
}

void AccountIamManagerTest::TearDown()
{
}

/**
 * @tc.name: OpenSession001
 * @tc.desc: Open Session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, OpenSession001, TestSize.Level2)
{
    std::vector<uint8_t> challenge;
    InnerAccountIAMManager::GetInstance().OpenSession(TEST_USER_ID, challenge); // 1111: invalid userid
    EXPECT_TRUE(challenge.size() != 0);

    InnerAccountIAMManager::GetInstance().CloseSession(0);
    InnerAccountIAMManager::GetInstance().CloseSession(TEST_USER_ID);
}

/**
 * @tc.name: AddCredential001
 * @tc.desc: Add credential.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, AddCredential001, TestSize.Level0)
{
    CredentialParameters testPara = {};
    sptr<MockIIDMCallback> testCallback = new(std::nothrow) MockIIDMCallback();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(1));
    InnerAccountIAMManager::GetInstance().AddCredential(TEST_USER_ID, testPara, nullptr);
    InnerAccountIAMManager::GetInstance().AddCredential(TEST_USER_ID, testPara, testCallback);
}

/**
 * @tc.name: UpdateCredential001
 * @tc.desc: Update credential.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, UpdateCredential001, TestSize.Level0)
{
    CredentialParameters testPara = {};
    sptr<MockIIDMCallback> testCallback = new(std::nothrow) MockIIDMCallback();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(2));
    InnerAccountIAMManager::GetInstance().UpdateCredential(TEST_USER_ID, testPara, nullptr);
    InnerAccountIAMManager::GetInstance().UpdateCredential(TEST_USER_ID, testPara, testCallback);

    testPara.token = {1, 2, 3};
    InnerAccountIAMManager::GetInstance().UpdateCredential(TEST_USER_ID, testPara, testCallback);
}

/**
 * @tc.name: Cancel001
 * @tc.desc: Cancel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, Cancel001, TestSize.Level0)
{
    int32_t ret = InnerAccountIAMManager::GetInstance().Cancel(TEST_USER_ID);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: DelCred001
 * @tc.desc: Delete credential.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, DelCred001, TestSize.Level0)
{
    uint64_t testCredentialId = 111;
    std::vector<uint8_t> testAuthToken;
    sptr<MockIIDMCallback> testCallback = new(std::nothrow) MockIIDMCallback();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(2));
    InnerAccountIAMManager::GetInstance().DelCred(TEST_USER_ID, testCredentialId, testAuthToken, nullptr);

    InnerAccountIAMManager::GetInstance().DelCred(TEST_USER_ID, testCredentialId, testAuthToken, testCallback);

    testAuthToken = {1, 2, 3, 4};
    InnerAccountIAMManager::GetInstance().DelCred(TEST_USER_ID, testCredentialId, testAuthToken, testCallback);
}

/**
 * @tc.name: DelUser001
 * @tc.desc: Delete user.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, DelUser001, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    sptr<MockIIDMCallback> testCallback = new(std::nothrow) MockIIDMCallback();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(2));
    InnerAccountIAMManager::GetInstance().DelUser(TEST_USER_ID, testAuthToken, nullptr);
    InnerAccountIAMManager::GetInstance().DelUser(TEST_USER_ID, testAuthToken, testCallback);

    testAuthToken = {1, 2, 3, 4};
    InnerAccountIAMManager::GetInstance().DelUser(TEST_USER_ID, testAuthToken, testCallback);
}

/**
 * @tc.name: AuthUser001
 * @tc.desc: Auth user.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, AuthUser001, TestSize.Level0)
{
    SetPropertyRequest testRequest = {};
    sptr<MockIIDMCallback> testCallback = new(std::nothrow) MockIIDMCallback();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    uint64_t contextId = InnerAccountIAMManager::GetInstance().AuthUser(
        TEST_USER_ID, TEST_CHALLENGE, AuthType::PIN, AuthTrustLevel::ATL1, nullptr);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_NULL_PTR_ERROR, contextId);

    contextId = InnerAccountIAMManager::GetInstance().AuthUser(
        TEST_USER_ID, TEST_CHALLENGE, AuthType::PIN, AuthTrustLevel::ATL1, testCallback);
    InnerAccountIAMManager::GetInstance().CancelAuth(contextId);
}

/**
 * @tc.name: GetState001
 * @tc.desc: Get state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, GetState001, TestSize.Level0)
{
    int32_t userId = 4444; // 1111: invalid userId
    EXPECT_EQ(IDLE, InnerAccountIAMManager::GetInstance().GetState(userId));

    EXPECT_NE(IDLE, InnerAccountIAMManager::GetInstance().GetState(TEST_USER_ID));
}

/**
 * @tc.name: GetChallenge001
 * @tc.desc: Get Challenge.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, GetChallenge001, TestSize.Level2)
{
    std::vector<uint8_t> challenge;
    InnerAccountIAMManager::GetInstance().OpenSession(TEST_USER_ID, challenge);

    sptr<MockIIDMCallback> testCallback = new(std::nothrow) MockIIDMCallback();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    uint64_t contextId = InnerAccountIAMManager::GetInstance().AuthUser(
        TEST_USER_ID, TEST_CHALLENGE, AuthType::PIN, AuthTrustLevel::ATL1, testCallback);

    std::vector<uint8_t> outChallenge;
    InnerAccountIAMManager::GetInstance().GetChallenge(TEST_USER_ID, outChallenge);
    EXPECT_TRUE(outChallenge.size() != 0);

    InnerAccountIAMManager::GetInstance().GetChallenge(12345, outChallenge); // 12345: userId
    EXPECT_TRUE(outChallenge.empty());
    InnerAccountIAMManager::GetInstance().CloseSession(TEST_USER_ID);

    InnerAccountIAMManager::GetInstance().CancelAuth(contextId);
}

/**
 * @tc.name: ActivateUserKey001
 * @tc.desc: ActivateUserKey.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, ActivateUserKey001, TestSize.Level2)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    std::vector<uint8_t> testSecret = {1, 2, 3, 4};

    EXPECT_EQ(ERR_OK, InnerAccountIAMManager::GetInstance().ActivateUserKey(TEST_USER_ID, testAuthToken, testSecret));

    int32_t userId = 112;
    EXPECT_EQ(ERR_OK, InnerAccountIAMManager::GetInstance().ActivateUserKey(TEST_USER_ID, testAuthToken, testSecret));

    // userid is out of range
    userId = 11112;
    EXPECT_NE(ERR_OK, InnerAccountIAMManager::GetInstance().ActivateUserKey(userId, testAuthToken, testSecret));
}

/**
 * @tc.name: UpdateUserKey001
 * @tc.desc: UpdateUserKey.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, UpdateUserKey001, TestSize.Level2)
{
    uint64_t testCreId = 111;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    std::vector<uint8_t> testSecret = {1, 2, 3, 4};

    int32_t res = InnerAccountIAMManager::GetInstance().UpdateUserKey(TEST_USER_ID, testCreId, testAuthToken, testSecret);
    EXPECT_EQ(g_fscryptEnable ? -2 : 0, res);

    uint64_t testNewCreId = 222;
    std::vector<uint8_t> testNewSecret;
    EXPECT_EQ(ERR_OK,
        InnerAccountIAMManager::GetInstance().UpdateUserKey(TEST_USER_ID, testCreId, testAuthToken, testNewSecret));
    EXPECT_EQ(ERR_OK,
        InnerAccountIAMManager::GetInstance().UpdateUserKey(TEST_USER_ID, testNewCreId, testAuthToken, testNewSecret));
}

/**
 * @tc.name: RemoveUserKey001
 * @tc.desc: RemoveUserKey.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, RemoveUserKey001, TestSize.Level2)
{
    int32_t userId = 2222;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};

    int32_t res = InnerAccountIAMManager::GetInstance().RemoveUserKey(TEST_USER_ID, testAuthToken);
    EXPECT_EQ(g_fscryptEnable ? -2 : 0, res);
    EXPECT_EQ(ERR_OK, InnerAccountIAMManager::GetInstance().RemoveUserKey(userId, testAuthToken));
}

/**
 * @tc.name: RestoreUserKey001
 * @tc.desc: RestoreUserKey.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, RestoreUserKey001, TestSize.Level2)
{
    int32_t userId = 2222;
    uint64_t testOldCreId = 111;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    std::vector<uint8_t> testSecret = {1, 2, 3, 4};

    int32_t res =
        InnerAccountIAMManager::GetInstance().UpdateUserKey(TEST_USER_ID, testOldCreId, testAuthToken, testSecret);
    EXPECT_EQ(g_fscryptEnable ? -2 : 0, res);

    uint64_t testNewCreId = 222;
    EXPECT_NE(ERR_OK, InnerAccountIAMManager::GetInstance().RestoreUserKey(userId, 0, testAuthToken));
    EXPECT_EQ(ERR_OK, InnerAccountIAMManager::GetInstance().RestoreUserKey(userId, testNewCreId, testAuthToken));
    res = InnerAccountIAMManager::GetInstance().RestoreUserKey(TEST_USER_ID, 0, testAuthToken);
    EXPECT_EQ(g_fscryptEnable ? -2 : 0, res);
    EXPECT_EQ(ERR_OK, InnerAccountIAMManager::GetInstance().RestoreUserKey(TEST_USER_ID, testNewCreId, testAuthToken));
    EXPECT_EQ(ERR_OK, InnerAccountIAMManager::GetInstance().RestoreUserKey(TEST_USER_ID, testOldCreId, testAuthToken));
}
}  // namespace AccountTest
}  // namespace OHOS

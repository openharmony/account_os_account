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

#include <gtest/gtest.h>
#include "accesstoken_kit.h"
#define private public
#include "account_iam_service.h"
#undef private
#include "account_iam_callback_stub.h"
#include "account_log_wrapper.h"
#include "iremote_stub.h"
#include "token_setproc.h"

namespace OHOS {
namespace AccountTest {

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;
namespace {
constexpr int32_t TEST_DEFAULT_ID = -1;
constexpr int32_t TEST_EXIST_ID = 100;
constexpr int32_t TEST_NOT_EXIST_ID = 1;
}

class MockIIDMCallback : public IDMCallbackStub {
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

class MockGetCredInfoCallback : public GetCredInfoCallbackStub {
public:
    void OnCredentialInfo(const std::vector<CredentialInfo> &infoList)override
    {
        return;
    }
};

class MockGetEnrolledIdCallback : public GetEnrolledIdCallbackStub {
public:
    void OnEnrolledId(int32_t result, uint64_t enrolledId) override
    {
        result_ = result;
        return;
    }
public:
    int32_t result_ = -1;
};

class MockGetSetPropCallback : public GetSetPropCallbackStub {
public:
    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        result_ = result;
        return;
    }

public:
    int32_t result_ = -1;
};

class AccountIamServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    sptr<AccountIAMService> accountIAMService_ = nullptr;
};

void AccountIamServiceTest::SetUpTestCase(void)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.settings", 0);
    SetSelfTokenID(tokenId);
}

void AccountIamServiceTest::TearDownTestCase(void)
{}

void AccountIamServiceTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    if (accountIAMService_ == nullptr) {
        accountIAMService_ = new (std::nothrow) AccountIAMService();
    }
}

void AccountIamServiceTest::TearDown(void)
{}

/**
 * @tc.name: AccountIAMService_OpenSession_0100
 * @tc.desc: OpenSession test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_OpenSession_0100, TestSize.Level0)
{
    std::vector<uint8_t> challenge;
    int32_t res = accountIAMService_->OpenSession(0, challenge);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AccountIAMService_OpenSession_0200
 * @tc.desc: OpenSession test account not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_OpenSession_0200, TestSize.Level0)
{
    std::vector<uint8_t> challenge;
    int32_t res = accountIAMService_->OpenSession(TEST_NOT_EXIST_ID, challenge);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: AccountIAMService_CloseSession_0100
 * @tc.desc: CloseSession test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_CloseSession_0100, TestSize.Level0)
{
    int32_t res = accountIAMService_->CloseSession(0);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AccountIAMService_CloseSession_0200
 * @tc.desc: CloseSession test account not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_CloseSession_0200, TestSize.Level0)
{
    int32_t res = accountIAMService_->CloseSession(TEST_NOT_EXIST_ID);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: AccountIAMService_AddCredential_0100
 * @tc.desc: AddCredential test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_AddCredential_0100, TestSize.Level0)
{
    CredentialParameters creInfo = {};
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    ASSERT_NE(callback, nullptr);
    accountIAMService_->AddCredential(0, creInfo, callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AccountIAMService_AddCredential_0200
 * @tc.desc: AddCredential test account not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_AddCredential_0200, TestSize.Level0)
{
    CredentialParameters creInfo = {};
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    ASSERT_NE(callback, nullptr);
    accountIAMService_->AddCredential(TEST_NOT_EXIST_ID, creInfo, callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: AccountIAMService_UpdateCredential_0100
 * @tc.desc: UpdateCredential test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_UpdateCredential_0100, TestSize.Level0)
{
    CredentialParameters creInfo = {};
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    ASSERT_NE(callback, nullptr);
    accountIAMService_->UpdateCredential(0, creInfo, callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AccountIAMService_UpdateCredential_0200
 * @tc.desc: UpdateCredential test account not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_UpdateCredential_0200, TestSize.Level0)
{
    CredentialParameters creInfo = {};
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    ASSERT_NE(callback, nullptr);
    accountIAMService_->UpdateCredential(TEST_NOT_EXIST_ID, creInfo, callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: AccountIAMService_Cancel_0100
 * @tc.desc: Cancel test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_Cancel_0100, TestSize.Level0)
{
    int32_t res = accountIAMService_->Cancel(0);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AccountIAMService_DelCred_0100
 * @tc.desc: DelCred test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_DelCred_0100, TestSize.Level0)
{
    std::vector<uint8_t> token;
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    ASSERT_NE(callback, nullptr);
    accountIAMService_->DelCred(0, 0, token, callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AccountIAMService_DelUser_0100
 * @tc.desc: DelUser test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_DelUser_0100, TestSize.Level0)
{
    std::vector<uint8_t> token;
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    ASSERT_NE(callback, nullptr);
    accountIAMService_->DelUser(0, token, callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AccountIAMService_GetCredentialInfo_0100
 * @tc.desc: GetCredentialInfo test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_GetCredentialInfo_0100, TestSize.Level0)
{
    sptr<MockGetCredInfoCallback> callback = new (std::nothrow) MockGetCredInfoCallback();
    ASSERT_NE(callback, nullptr);
    int32_t res = accountIAMService_->GetCredentialInfo(0, AuthType::PIN, callback);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AccountIAMService_GetCredentialInfo_0200
 * @tc.desc: GetCredentialInfo test account not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_GetCredentialInfo_0200, TestSize.Level0)
{
    sptr<MockGetCredInfoCallback> callback = new (std::nothrow) MockGetCredInfoCallback();
    ASSERT_NE(callback, nullptr);
    int32_t res = accountIAMService_->GetCredentialInfo(TEST_NOT_EXIST_ID, AuthType::PIN, callback);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: AccountIAMService_GetCredentialInfo_0300
 * @tc.desc: GetCredentialInfo test authType is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_GetCredentialInfo_0300, TestSize.Level0)
{
    sptr<MockGetCredInfoCallback> callback = new (std::nothrow) MockGetCredInfoCallback();
    ASSERT_NE(callback, nullptr);
    int32_t res =
        accountIAMService_->GetCredentialInfo(TEST_EXIST_ID, static_cast<AuthType>(IAMAuthType::TYPE_END), callback);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AccountIAMService_GetEnrolledId_0100
 * @tc.desc: GetCredentialInfo test default account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_GetEnrolledId_0100, TestSize.Level0)
{
    sptr<MockGetEnrolledIdCallback> callback = new (std::nothrow) MockGetEnrolledIdCallback();
    ASSERT_NE(callback, nullptr);
    // -1 is default account and indicates querying the current account
    accountIAMService_->GetEnrolledId(TEST_DEFAULT_ID, AuthType::PIN, callback);
    EXPECT_NE(callback->result_, ERR_OK);
}

/**
 * @tc.name: AccountIAMService_GetEnrolledId_0200
 * @tc.desc: GetCredentialInfo test account not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_GetEnrolledId_0200, TestSize.Level0)
{
    sptr<MockGetEnrolledIdCallback> callback = new (std::nothrow) MockGetEnrolledIdCallback();
    ASSERT_NE(callback, nullptr);
    accountIAMService_->GetEnrolledId(TEST_NOT_EXIST_ID, AuthType::PIN, callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: AccountIAMService_GetEnrolledId_0300
 * @tc.desc: GetCredentialInfo test authType is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_GetEnrolledId_0300, TestSize.Level0)
{
    sptr<MockGetEnrolledIdCallback> callback = new (std::nothrow) MockGetEnrolledIdCallback();
    ASSERT_NE(callback, nullptr);
    accountIAMService_->GetEnrolledId(TEST_EXIST_ID, static_cast<AuthType>(IAMAuthType::TYPE_END), callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**

 * @tc.name: AccountIAMService_GetEnrolledId_0400
 * @tc.desc: GetCredentialInfo test authType is not support.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_GetEnrolledId_0400, TestSize.Level0)
{
    sptr<MockGetEnrolledIdCallback> callback = new (std::nothrow) MockGetEnrolledIdCallback();
    ASSERT_NE(callback, nullptr);
    accountIAMService_->GetEnrolledId(TEST_EXIST_ID, static_cast<AuthType>(IAMAuthType::DOMAIN), callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE);
}

/**
 * @tc.name: AccountIAMService_AuthUser_0100
 * @tc.desc: AuthUser test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_AuthUser_0100, TestSize.Level0)
{
    std::vector<uint8_t> challenge;
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    ASSERT_NE(callback, nullptr);
    AccountSA::AuthParam authParam = {
        .userId = 0,
        .challenge = challenge,
        .authType = AuthType::PIN,
        .authTrustLevel = AuthTrustLevel::ATL1
    };
    uint64_t contextId = 0;
    ErrCode res = accountIAMService_->AuthUser(authParam, callback, contextId);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AccountIAMService_AuthUser_0200
 * @tc.desc: AuthUser test account not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_AuthUser_0200, TestSize.Level0)
{
    std::vector<uint8_t> challenge;
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    ASSERT_NE(callback, nullptr);
    AccountSA::AuthParam authParam = {
        .userId = TEST_NOT_EXIST_ID,
        .challenge = challenge,
        .authType = AuthType::PIN,
        .authTrustLevel = AuthTrustLevel::ATL1
    };
    uint64_t contextId = 0;
    ErrCode res = accountIAMService_->AuthUser(authParam, callback, contextId);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: AccountIAMService_GetAvailableStatus_0100
 * @tc.desc: GetAvailableStatus test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_GetAvailableStatus_0100, TestSize.Level0)
{
    int32_t status;
    int32_t res = accountIAMService_->GetAvailableStatus(static_cast<AuthType>(-1), AuthTrustLevel::ATL1, status);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    res = accountIAMService_->GetAvailableStatus(AuthType::PIN, static_cast<AuthTrustLevel>(0), status);
    EXPECT_EQ(res, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AccountIAMService_GetProperty_0100
 * @tc.desc: GetProperty test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_GetProperty_0100, TestSize.Level0)
{
    GetPropertyRequest request;
    sptr<MockGetSetPropCallback> callback = new (std::nothrow) MockGetSetPropCallback();
    ASSERT_NE(callback, nullptr);
    accountIAMService_->GetProperty(0, request, callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AccountIAMService_GetProperty_0200
 * @tc.desc: GetProperty test account not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_GetProperty_0200, TestSize.Level0)
{
    GetPropertyRequest request;
    sptr<MockGetSetPropCallback> callback = new (std::nothrow) MockGetSetPropCallback();
    ASSERT_NE(callback, nullptr);
    accountIAMService_->GetProperty(TEST_NOT_EXIST_ID, request, callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: AccountIAMService_SetProperty_0100
 * @tc.desc: SetProperty test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamServiceTest, AccountIAMService_SetProperty_0100, TestSize.Level0)
{
    SetPropertyRequest request;
    sptr<MockGetSetPropCallback> callback = new (std::nothrow) MockGetSetPropCallback();
    ASSERT_NE(callback, nullptr);
    accountIAMService_->SetProperty(0, request, callback);
    EXPECT_EQ(callback->result_, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}
}  // namespace AccountTest
}  // namespace OHOS
/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "accesstoken_kit.h"
#define private public
#include "account_iam_callback.h"
#include "iinner_os_account_manager.h"
#include "os_account_info.h"
#undef private
#include "account_iam_client.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "domain_account_client.h"
#include "inner_account_iam_manager.h"
#include "iinner_os_account_manager.h"
#include "ipc_skeleton.h"
#include "iremote_stub.h"
#include "mock_domain_plugin.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS::UserIam::UserAuth;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
namespace AccountSA {
UpdateCredInfo::~UpdateCredInfo() {}
}

namespace AccountTest {
namespace {
const int32_t DEFAULT_USER_ID = 100;
const int32_t TEST_USER_ID = 200;
const int32_t TEST_MODULE = 5;
const int32_t TEST_ACQUIRE_INFO = 10;
static AccessTokenID g_accountMgrTokenID = 0;
} // namespace

#ifdef HAS_PIN_AUTH_PART
class MockIInputer final : public IInputer {
public:
    virtual ~MockIInputer() {}
    void OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
        std::shared_ptr<IInputerData> inputerData) override
    {
        return;
    }
};
#endif

class MockIIDMCallback : public IDMCallbackStub {
public:
ErrCode OnAcquireInfo(int32_t module, uint32_t acquireInfo, const std::vector<uint8_t>& extraInfoBuffer) override
    {
        module_ = module;
        acquireInfo_ = acquireInfo;
        return ERR_OK;
    }
    ErrCode OnResult(int32_t resultCode, const std::vector<uint8_t>& extraInfoBuffer) override
    {
        ACCOUNT_LOGI("OnResult result:%{public}d", resultCode);
        result_ = resultCode;
        return ERR_OK;
    }

public:
    int32_t result_ = -1;
    int32_t module_ = 0;
    uint32_t acquireInfo_ = 0;
};
class MockGetCredInfoCallback {
public:
    MOCK_METHOD1(OnResult, void(int32_t result));
};

class TestGetCredInfoCallback final : public GetCredInfoCallback {
public:
    explicit TestGetCredInfoCallback(const std::shared_ptr<MockGetCredInfoCallback> &callback) : callback_(callback)
    {}
    void OnCredentialInfo(int32_t result, const std::vector<CredentialInfo> &infoList)
    {
        ACCOUNT_LOGI("OnCredentialInfo result:%{public}d", result);
        int infoListSize = infoList.size();
        callback_->OnResult(infoListSize);
        std::unique_lock<std::mutex> lock(mutex);
        isReady = true;
        cv.notify_one();
        return;
    }
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;
private:
    std::shared_ptr<MockGetCredInfoCallback> callback_;
};

class MockGetEnrolledIdCallback
    : public GetEnrolledIdCallbackStub {
public:
    MOCK_METHOD2(OnEnrolledId, ErrCode(int32_t resultCode, uint64_t enrolledId));
};

class MockGetSetPropCallback
    : public GetSetPropCallbackStub {
public:
    MOCK_METHOD2(OnResult, ErrCode(int32_t resultCode, const std::vector<uint8_t>& extraInfoBuffer));
};

class MockGetCredInfoCallback1
    : public GetCredInfoCallbackStub {
public:
    MOCK_METHOD2(OnCredentialInfo, ErrCode(int32_t resultCode, const std::vector<CredentialInfoIam>& infoList));
};

class MockPrepareRemoteAuthCallbackWrapper
    : public PreRemoteAuthCallbackStub {
public:
    MOCK_METHOD1(OnResult, ErrCode(int32_t resultCode));
};

class AccountIamCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    IInnerOsAccountManager *innerMgrService_ = &IInnerOsAccountManager::GetInstance();
};

void AccountIamCallbackTest::SetUpTestCase(void)
{
    g_accountMgrTokenID = GetTokenIdFromProcess("accountmgr");
    SetSelfTokenID(g_accountMgrTokenID);
}

void AccountIamCallbackTest::TearDownTestCase(void)
{}

void AccountIamCallbackTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AccountIamCallbackTest::TearDown(void)
{}

/**
 * @tc.name: AuthCallback_IsTokenFromRemoteDevice_0100
 * @tc.desc: IsTokenFromRemoteDevice test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_IsTokenFromRemoteDevice_0100, TestSize.Level0)
{
    AuthCallback userAuthCallback(TEST_USER_ID, AuthType::PIN, AccountSA::AuthIntent::DEFAULT, nullptr);
    Attributes extraInfo;
    userAuthCallback.isRemoteAuth_ = false;
    EXPECT_FALSE(userAuthCallback.IsTokenFromRemoteDevice(extraInfo));

    userAuthCallback.isRemoteAuth_ = true;
    EXPECT_FALSE(userAuthCallback.IsTokenFromRemoteDevice(extraInfo));

    std::vector<uint64_t> value(10);
    EXPECT_EQ(extraInfo.SetUint64ArrayValue(Attributes::ATTR_TOKEN_FROM_REMOTE_DEVICE, value), true);
    EXPECT_FALSE(userAuthCallback.IsTokenFromRemoteDevice(extraInfo));

    EXPECT_EQ(extraInfo.SetBoolValue(Attributes::ATTR_TOKEN_FROM_REMOTE_DEVICE, true), true);
    EXPECT_TRUE(userAuthCallback.IsTokenFromRemoteDevice(extraInfo));
}

/**
 * @tc.name: AuthCallback_OnResult_0100
 * @tc.desc: OnResult with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_OnResult_0100, TestSize.Level0)
{
    auto userAuthCallback = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::PIN, AccountSA::AuthIntent::DEFAULT, nullptr);
    EXPECT_NE(userAuthCallback->callerTokenId_, 0);
    auto userAuthCallback2 = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::FINGERPRINT, AccountSA::AuthIntent::DEFAULT, nullptr);
    EXPECT_EQ(userAuthCallback2->callerTokenId_, 0);
    EXPECT_TRUE(userAuthCallback->innerCallback_ == nullptr);
    Attributes extraInfo;
    userAuthCallback->OnResult(0, extraInfo);
    sptr<AuthCallbackDeathRecipient> deathRecipient = new (std::nothrow) AuthCallbackDeathRecipient();
    deathRecipient->OnRemoteDied(nullptr);
    deathRecipient->contextId_ = 1;
    deathRecipient->OnRemoteDied(nullptr);
    sptr<IDMCallbackDeathRecipient> idmDeathRecipient = new (std::nothrow) IDMCallbackDeathRecipient(0);
    idmDeathRecipient->OnRemoteDied(nullptr);
    idmDeathRecipient->userId_ = 1;
    idmDeathRecipient->OnRemoteDied(nullptr);

    auto userAuthCallback3 = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::PIN, AccountSA::AuthIntent::DEFAULT, false, nullptr);
    EXPECT_NE(userAuthCallback3->callerTokenId_, 0);
    auto userAuthCallback4 = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::FINGERPRINT, AccountSA::AuthIntent::DEFAULT, false, nullptr);
    EXPECT_EQ(userAuthCallback4->callerTokenId_, 0);
}

/**
 * @tc.name: AuthCallback_OnResult_0200
 * @tc.desc: OnResult test with PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_OnResult_0200, TestSize.Level0)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(DEFAULT_USER_ID, "com.ohos.settings", 0);
    SetSelfTokenID(tokenId);
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::PIN, AccountSA::AuthIntent::DEFAULT, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    Attributes extraInfo;
    int32_t errCode = 0;
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    errCode = 10; // result != 0
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    SetSelfTokenID(g_accountMgrTokenID);
}

/**
 * @tc.name: AuthCallback_OnResult_0201
 * @tc.desc: OnResult test with the user is deactivating.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_OnResult_0201, TestSize.Level0)
{
    OsAccountInfo osAccountInfo(TEST_USER_ID, "testAuthUser", OsAccountType::NORMAL, 0);
    EXPECT_EQ(IInnerOsAccountManager::GetInstance().osAccountControl_->InsertOsAccount(osAccountInfo), ERR_OK);
    int32_t testUserId = osAccountInfo.GetLocalId();
    // test no set deactivated status
    bool isLoggedIn = false;
    IInnerOsAccountManager::GetInstance().loggedInAccounts_.Find(testUserId, isLoggedIn);
    if (isLoggedIn) {
    IInnerOsAccountManager::GetInstance().loggedInAccounts_.Erase(testUserId);
    }
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(
    testUserId, AuthType::PIN, AccountSA::AuthIntent::DEFAULT, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    Attributes extraInfo;
    int32_t errCode = 0;
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    IInnerOsAccountManager::GetInstance().loggedInAccounts_.Find(testUserId, isLoggedIn);
    EXPECT_EQ(isLoggedIn, true);

    // test set deactivated status
    IInnerOsAccountManager::GetInstance().loggedInAccounts_.Erase(testUserId);
    IInnerOsAccountManager::GetInstance().deactivatingAccounts_.EnsureInsert(testUserId, true);
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    EXPECT_EQ(IInnerOsAccountManager::GetInstance().loggedInAccounts_.Find(testUserId, isLoggedIn), false);
    IInnerOsAccountManager::GetInstance().deactivatingAccounts_.Erase(testUserId);
    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(testUserId);
}

#ifdef SUPPORT_LOCK_OS_ACCOUNT
/**
 * @tc.name: AuthCallback_OnResult_0202
 * @tc.desc: OnResult test with the user is deactivating.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_OnResult_0202, TestSize.Level0)
{
    OsAccountInfo osAccountInfo(TEST_USER_ID, "testAuthUser", OsAccountType::NORMAL, 0);
    EXPECT_EQ(IInnerOsAccountManager::GetInstance().osAccountControl_->InsertOsAccount(osAccountInfo), ERR_OK);
    int32_t testUserId = osAccountInfo.GetLocalId();
    // test no set deactivated status
    bool isLoggedIn = false;
    IInnerOsAccountManager::GetInstance().loggedInAccounts_.Find(testUserId, isLoggedIn);
    if (isLoggedIn) {
    IInnerOsAccountManager::GetInstance().loggedInAccounts_.Erase(testUserId);
    }
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(
    testUserId, AuthType::PIN, AccountSA::AuthIntent::DEFAULT, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    Attributes extraInfo;
    int32_t errCode = 0;
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    IInnerOsAccountManager::GetInstance().loggedInAccounts_.Find(testUserId, isLoggedIn);
    EXPECT_EQ(isLoggedIn, true);

    // test set deactivated status
    IInnerOsAccountManager::GetInstance().loggedInAccounts_.Erase(testUserId);
    IInnerOsAccountManager::GetInstance().lockingAccounts_.EnsureInsert(testUserId, true);
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    EXPECT_EQ(IInnerOsAccountManager::GetInstance().loggedInAccounts_.Find(testUserId, isLoggedIn), false);
    IInnerOsAccountManager::GetInstance().lockingAccounts_.Erase(testUserId);
    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(testUserId);
}
#endif

/**
 * @tc.name: AuthCallback_OnResult_0300
 * @tc.desc: OnResult test with not PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_OnResult_0300, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::FACE, AccountSA::AuthIntent::DEFAULT, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    Attributes extraInfo;
    int32_t errCode = 1;
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    errCode = 10; // result != 0 && authType_ != AuthType::PIN
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
}

/**
 * @tc.name: AuthCallback_OnResult_0400
 * @tc.desc: OnResult test with ReEnroll flag.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_OnResult_0400, TestSize.Level0)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(DEFAULT_USER_ID, "com.ohos.settings", 0);
    SetSelfTokenID(tokenId);
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::PIN, AccountSA::AuthIntent::DEFAULT, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    Attributes extraInfo;
    EXPECT_EQ(extraInfo.SetBoolValue(Attributes::ATTR_RE_ENROLL_FLAG, true), true);
    int32_t errCode = 0;
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    userAuthCallback->isRemoteAuth_ = true;
    EXPECT_EQ(extraInfo.SetBoolValue(Attributes::ATTR_TOKEN_FROM_REMOTE_DEVICE, true), true);
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    errCode = 10; // result != 0
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    SetSelfTokenID(g_accountMgrTokenID);
}

/**
 * @tc.name: AuthCallback_OnResult_0500
 * @tc.desc: OnResult test with PRIVATE_PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_OnResult_0500, TestSize.Level0)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(DEFAULT_USER_ID, "com.ohos.settings", 0);
    SetSelfTokenID(tokenId);
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::PRIVATE_PIN, AccountSA::AuthIntent::DEFAULT, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    Attributes extraInfo;
    EXPECT_EQ(extraInfo.SetBoolValue(Attributes::ATTR_RE_ENROLL_FLAG, true), true);
    int32_t errCode = 0;
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    errCode = 10; // result != 0
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    SetSelfTokenID(g_accountMgrTokenID);
}

/**
 * @tc.name: AuthCallback_OnResult_0600
 * @tc.desc: OnResult test with PRIVATE_PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_OnResult_0600, TestSize.Level0)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(DEFAULT_USER_ID, "com.ohos.settings", 0);
    SetSelfTokenID(tokenId);
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::PIN, AccountSA::AuthIntent::QUESTION_AUTH, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    Attributes extraInfo;
    EXPECT_EQ(extraInfo.SetBoolValue(Attributes::ATTR_RE_ENROLL_FLAG, true), true);
    int32_t errCode = 0;
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    errCode = 10; // result != 0
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    SetSelfTokenID(g_accountMgrTokenID);
}

/**
 * @tc.name: AuthCallback_HandleReEnroll_0100
 * @tc.desc: HandleReEnroll authType_ != AuthType::PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_HandleReEnroll_0100, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::FINGERPRINT, AccountSA::AuthIntent::DEFAULT, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    Attributes extraInfo;
    EXPECT_EQ(extraInfo.SetBoolValue(Attributes::ATTR_RE_ENROLL_FLAG, true), true);
    userAuthCallback->HandleReEnroll(extraInfo, 100, {});
}

/**
 * @tc.name: AuthCallback_UnlockAccount_0100
 * @tc.desc: UnlockAccount authType_！=PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_UnlockAccount_0100, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::FINGERPRINT, AccountSA::AuthIntent::DEFAULT, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    bool isUpdateVerifiedStatus = true;
    EXPECT_EQ(ERR_OK, userAuthCallback->UnlockAccount(0, {}, {}, isUpdateVerifiedStatus));
}

/**
 * @tc.name: AuthCallback_UnlockAccount_0200
 * @tc.desc: UnlockAccount authType==PIN, secret is not empty， isVerified=true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_UnlockAccount_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::PIN, AccountSA::AuthIntent::DEFAULT, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    std::vector<uint8_t> secret = {8, 8, 8, 8, 8, 8, 8};
    bool isUpdateVerifiedStatus = true;
    bool isVerified = false;
    innerMgrService_->IsOsAccountVerified(100, isVerified);
    innerMgrService_->SetOsAccountIsVerified(100, true);
    EXPECT_EQ(ERR_OK, userAuthCallback->UnlockAccount(100, {}, secret, isUpdateVerifiedStatus));
    innerMgrService_->SetOsAccountIsVerified(100, isVerified);
}

/**
 * @tc.name: AuthCallback_UnlockAccount_0300
 * @tc.desc: UnlockAccount authType==PIN, secret is not empty， isVerified=false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_UnlockAccount_0300, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::PIN, AccountSA::AuthIntent::DEFAULT, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    std::vector<uint8_t> secret = {8, 8, 8, 8, 8, 8, 8};
    bool isUpdateVerifiedStatus = true;
    EXPECT_EQ(ERR_OK, userAuthCallback->UnlockAccount(-1, {}, secret, isUpdateVerifiedStatus));
}

/**
 * @tc.name: AuthCallback_UnlockUserScreen_0100
 * @tc.desc: UnlockUserScreen isUpdateVerifiedStatus=true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_UnlockUserScreen_0100, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::PIN, AccountSA::AuthIntent::DEFAULT, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    bool isUpdateVerifiedStatus = true;
    EXPECT_EQ(ERR_OK, userAuthCallback->UnlockUserScreen(-1, {}, {}, isUpdateVerifiedStatus));

    std::vector<uint8_t> secret = {8, 8, 8, 8, 8, 8, 8};
    isUpdateVerifiedStatus = false;
    EXPECT_NE(ERR_OK, userAuthCallback->UnlockUserScreen(-1, {}, secret, isUpdateVerifiedStatus));

    bool isVerified = false;
    innerMgrService_->IsOsAccountVerified(100, isVerified);
    innerMgrService_->SetOsAccountIsVerified(100, true);
    EXPECT_EQ(ERR_OK, userAuthCallback->UnlockUserScreen(100, {}, secret, isUpdateVerifiedStatus));
    innerMgrService_->SetOsAccountIsVerified(100, isVerified);
}

/**
 * @tc.name: AuthCallback_UnlockUserScreen_0200
 * @tc.desc: UnlockUserScreen isUpdateVerifiedStatus=false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_UnlockUserScreen_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::RECOVERY_KEY, AccountSA::AuthIntent::DEFAULT, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    std::vector<uint8_t> secret = {8, 8, 8, 8, 8, 8, 8};
    bool isUpdateVerifiedStatus = false;
    EXPECT_EQ(ERR_OK, userAuthCallback->UnlockUserScreen(-1, {}, secret, isUpdateVerifiedStatus));
}

/**
 * @tc.name: UpdateCredCallback_InnerOnResult_0100
 * @tc.desc: InnerOnResult isUpdateVerifiedStatus=false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, UpdateCredCallback_InnerOnResult_0100, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    CredentialParameters credInfo = {
        .authType = AuthType::PIN,
        .pinType = {},
        .token = {}
    };
    auto updateCredCallback = std::make_shared<UpdateCredCallback>(
        TEST_USER_ID, credInfo, nullptr);
    Attributes extraInfo;
    updateCredCallback->OnAcquireInfo(0, 0, extraInfo);
    auto updateCredCallback1 = std::make_shared<UpdateCredCallback>(
        TEST_USER_ID, credInfo, callback);
    EXPECT_TRUE(updateCredCallback1->innerCallback_ != nullptr);
    updateCredCallback1->OnAcquireInfo(0, 0, extraInfo);
    std::vector<uint8_t> secret = {8, 8, 8, 8, 8, 8, 8};
    updateCredCallback1->InnerOnResult(0, extraInfo);
}

/**
 * @tc.name: VerifyTokenCallbackWrapper_InnerOnResult_0100
 * @tc.desc: Test InnerOnResult.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, VerifyTokenCallbackWrapper_InnerOnResult_0100, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    std::vector<uint8_t> token = {0, 0, 0, 0, 0, 0, 0};
    auto verifyTokenCallbackWrapper = std::make_shared<VerifyTokenCallbackWrapper>(
        TEST_USER_ID, token, 12345678, callback);
    EXPECT_TRUE(verifyTokenCallbackWrapper->innerCallback_ != nullptr);
    Attributes extraInfo;
    verifyTokenCallbackWrapper->InnerOnResult(2, extraInfo);
    EXPECT_EQ(callback->result_, 2);

    verifyTokenCallbackWrapper->userId_ = -1;
    verifyTokenCallbackWrapper->InnerOnResult(ERR_OK, extraInfo);
    EXPECT_EQ(callback->result_, ResultCode::FAIL);
}

/**
 * @tc.name: CommitDelCredCallback_OnResult_0100
 * @tc.desc: Test OnResult.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, CommitDelCredCallback_OnResult_0100, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    std::vector<uint8_t> token = {0, 0, 0, 0, 0, 0, 0};
    auto commitDelCredCallback = std::make_shared<CommitDelCredCallback>(TEST_USER_ID, callback);
    EXPECT_TRUE(commitDelCredCallback->innerCallback_ != nullptr);
    Attributes extraInfo;
    commitDelCredCallback->OnResult(10, extraInfo);
    EXPECT_EQ(callback->result_, 10);
    commitDelCredCallback->OnResult(ERR_OK, extraInfo);
    EXPECT_EQ(callback->result_, ERR_OK);
}

/**
 * @tc.name: CommitCredUpdateCallback_InnerOnResult_0100
 * @tc.desc: Test InnerOnResult.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, CommitCredUpdateCallback_InnerOnResult_0100, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    std::vector<uint8_t> oldSecret = {0, 0, 0, 0, 0, 0, 0};
    Attributes extraInfo;
    extraInfo.SetUint8ArrayValue(Attributes::ATTR_OLD_ROOT_SECRET, oldSecret);
    UpdateCredInfo updateCredInfo(extraInfo);
    auto commitCredUpdateCallbacknull = std::make_shared<CommitCredUpdateCallback>(
        TEST_USER_ID, updateCredInfo, nullptr);
    commitCredUpdateCallbacknull->InnerOnResult(0, extraInfo);
    auto commitCredUpdateCallback = std::make_shared<CommitCredUpdateCallback>(
        TEST_USER_ID, updateCredInfo, callback);
    EXPECT_TRUE(commitCredUpdateCallback->innerCallback_ != nullptr);

    commitCredUpdateCallback->InnerOnResult(10, extraInfo);
    EXPECT_EQ(callback->result_, 10);
    commitCredUpdateCallback->InnerOnResult(0, extraInfo);
    EXPECT_EQ(callback->result_, 0);
}

/**
 * @tc.name: GetSecUserInfoCallbackWrapper_OnSecUserInfo_0100
 * @tc.desc: Test OnSecUserInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, GetSecUserInfoCallbackWrapper_OnSecUserInfo_0100, TestSize.Level0)
{
    sptr<MockGetEnrolledIdCallback> callback = new (std::nothrow) MockGetEnrolledIdCallback();
    ASSERT_NE(callback, nullptr);

    auto getSecUserInfoCallbackWrappernull = std::make_shared<GetSecUserInfoCallbackWrapper>(
        TEST_USER_ID, AuthType::PIN, nullptr);
    SecUserInfo info;
    EXPECT_TRUE(getSecUserInfoCallbackWrappernull->innerCallback_ == nullptr);
    getSecUserInfoCallbackWrappernull->OnSecUserInfo(0, info);

    auto getSecUserInfoCallbackWrapper = std::make_shared<GetSecUserInfoCallbackWrapper>(
        TEST_USER_ID, AuthType::PIN, callback);
    EXPECT_TRUE(getSecUserInfoCallbackWrapper->innerCallback_ != nullptr);

    EXPECT_CALL(*callback, OnEnrolledId(10, _)).Times(1);
    getSecUserInfoCallbackWrapper->OnSecUserInfo(10, info);

    EnrolledInfo info1;
    info1.authType = AuthType::PIN;
    info.enrolledInfo.emplace_back(info1);
    EXPECT_CALL(*callback, OnEnrolledId(ERR_OK, _)).Times(1);
    getSecUserInfoCallbackWrapper->OnSecUserInfo(ERR_OK, info);
}

/**
 * @tc.name: AuthCallback_OnAcquireInfo_0100
 * @tc.desc: OnAcquireInfo with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_OnAcquireInfo_0100, TestSize.Level0)
{
    auto userAuthCallback = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::PIN, AccountSA::AuthIntent::DEFAULT, nullptr);
    EXPECT_TRUE(userAuthCallback->innerCallback_ == nullptr);
    Attributes extraInfo;
    userAuthCallback->OnAcquireInfo(0, 0, extraInfo);
}

#ifdef HAS_PIN_AUTH_PART
/**
 * @tc.name: AuthCallback_OnAcquireInfo_0200
 * @tc.desc: OnAcquireInfo with not nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_OnAcquireInfo_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(
        TEST_USER_ID, AuthType::PIN, AccountSA::AuthIntent::DEFAULT, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    Attributes extraInfo;
    userAuthCallback->OnAcquireInfo(TEST_MODULE, TEST_ACQUIRE_INFO, extraInfo);
    EXPECT_EQ(TEST_MODULE, callback->module_);
    EXPECT_EQ(TEST_ACQUIRE_INFO, callback->acquireInfo_);
}
#endif

/**
 * @tc.name: AddCredCallback_OnResult_0100
 * @tc.desc: OnResult with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AddCredCallback_OnResult_0100, TestSize.Level0)
{
    CredentialParameters credInfo = {};
    Attributes extraInfo;
    auto addCredCallback = std::make_shared<AddCredCallback>(TEST_USER_ID, credInfo, nullptr);
    EXPECT_TRUE(addCredCallback->innerCallback_ == nullptr);
    addCredCallback->OnResult(0, extraInfo);
}

/**
 * @tc.name: AddCredCallback_OnResult_0200
 * @tc.desc: OnResult with PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AddCredCallback_OnResult_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    CredentialParameters credInfo = {};
    credInfo.authType = AuthType::PIN;
    Attributes extraInfo;
    auto addCredCallback = std::make_shared<AddCredCallback>(TEST_USER_ID, credInfo, callback);
    EXPECT_TRUE(addCredCallback->innerCallback_ != nullptr);
    int32_t errCode = 0;
    addCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    errCode = 10;
    addCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
}

/**
 * @tc.name: AddCredCallback_OnResult_0300
 * @tc.desc: OnResult with not PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AddCredCallback_OnResult_0300, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    CredentialParameters credInfo = {};
    credInfo.authType = AuthType::FACE;
    Attributes extraInfo;
    auto addCredCallback = std::make_shared<AddCredCallback>(TEST_USER_ID, credInfo, callback);
    EXPECT_TRUE(addCredCallback->innerCallback_ != nullptr);
    int32_t errCode = 0;
    addCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    errCode = 10;
    addCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
}

/**
 * @tc.name: AddCredCallback_OnAcquireInfo_0100
 * @tc.desc: OnAcquireInfo with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AddCredCallback_OnAcquireInfo_0100, TestSize.Level0)
{
    CredentialParameters credInfo = {};
    Attributes extraInfo;
    auto addCredCallback = std::make_shared<AddCredCallback>(TEST_USER_ID, credInfo, nullptr);
    EXPECT_TRUE(addCredCallback->innerCallback_ == nullptr);
    addCredCallback->OnAcquireInfo(0, 0, extraInfo);
}

/**
 * @tc.name: AddCredCallback_OnAcquireInfo_0200
 * @tc.desc: OnAcquireInfo with not nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AddCredCallback_OnAcquireInfo_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    CredentialParameters credInfo = {};
    Attributes extraInfo;
    auto addCredCallback = std::make_shared<AddCredCallback>(TEST_USER_ID, credInfo, callback);
    EXPECT_TRUE(addCredCallback->innerCallback_ != nullptr);
    addCredCallback->OnAcquireInfo(TEST_MODULE, TEST_ACQUIRE_INFO, extraInfo);
    EXPECT_EQ(TEST_MODULE, callback->module_);
    EXPECT_EQ(TEST_ACQUIRE_INFO, callback->acquireInfo_);
}

/**
 * @tc.name: DelCredCallback_OnResult_0100
 * @tc.desc: OnResult with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, DelCredCallback_OnResult_0100, TestSize.Level0)
{
    Attributes extraInfo;
    std::vector<uint8_t> token;
    auto delCredCallback = std::make_shared<DelCredCallback>(TEST_USER_ID, false, token, nullptr);
    EXPECT_TRUE(delCredCallback->innerCallback_ == nullptr);
    delCredCallback->OnResult(0, extraInfo);
}

/**
 * @tc.name: DelCredCallback_OnResult_0200
 * @tc.desc: Test OnResult.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, DelCredCallback_OnResult_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    std::vector<uint8_t> token = {0, 0, 0, 0, 0, 0, 0};
    Attributes extraInfo;
    auto delCredCallback = std::make_shared<DelCredCallback>(
        TEST_USER_ID, true, token, callback);
    EXPECT_TRUE(delCredCallback->innerCallback_ != nullptr);

    delCredCallback->OnResult(10, extraInfo);
    EXPECT_EQ(callback->result_, 10);
    delCredCallback->OnResult(0, extraInfo);
    EXPECT_EQ(callback->result_, 0);
}

/**
 * @tc.name: DelCredCallback_OnResult_0300
 * @tc.desc: OnResult with not PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, DelCredCallback_OnResult_0300, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    Attributes extraInfo;
    std::vector<uint8_t> token;
    auto delCredCallback = std::make_shared<DelCredCallback>(TEST_USER_ID, false, token, callback);
    EXPECT_TRUE(delCredCallback->innerCallback_ != nullptr);
    IAMState state = InnerAccountIAMManager::GetInstance().GetState(TEST_USER_ID);
    InnerAccountIAMManager::GetInstance().SetState(TEST_USER_ID, IDLE);
    int32_t errCode = 0;
    delCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    errCode = 10;
    delCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    InnerAccountIAMManager::GetInstance().SetState(TEST_USER_ID, state);
}

/**
 * @tc.name: DelCredCallback_OnAcquireInfo_0100
 * @tc.desc: OnAcquireInfo with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, DelCredCallback_OnAcquireInfo_0100, TestSize.Level0)
{
    Attributes extraInfo;
    std::vector<uint8_t> token;
    auto delCredCallback = std::make_shared<DelCredCallback>(TEST_USER_ID, false, token, nullptr);
    EXPECT_TRUE(delCredCallback->innerCallback_ == nullptr);
    delCredCallback->OnAcquireInfo(0, 0, extraInfo);
}

/**
 * @tc.name: DelCredCallback_OnAcquireInfo_0200
 * @tc.desc: OnAcquireInfo with not nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, DelCredCallback_OnAcquireInfo_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    Attributes extraInfo;
    std::vector<uint8_t> token;
    auto delCredCallback = std::make_shared<DelCredCallback>(TEST_USER_ID, false, token, callback);
    EXPECT_TRUE(delCredCallback->innerCallback_ != nullptr);
    delCredCallback->OnAcquireInfo(TEST_MODULE, TEST_ACQUIRE_INFO, extraInfo);
    EXPECT_EQ(TEST_MODULE, callback->module_);
    EXPECT_EQ(TEST_ACQUIRE_INFO, callback->acquireInfo_);
}

/**
 * @tc.name: GetCredInfoCallbackWrapper_OnCredentialInfo_0100
 * @tc.desc: OnCredentialInfo with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, GetCredInfoCallbackWrapper_OnCredentialInfo_0100, TestSize.Level0)
{
    auto getCredInfoCallback = std::make_shared<GetCredInfoCallbackWrapper>(0, 0, nullptr);
    EXPECT_TRUE(getCredInfoCallback->innerCallback_ == nullptr);
    std::vector<CredentialInfo> infoList;
    getCredInfoCallback->OnCredentialInfo(0, infoList);
}

/**
 * @tc.name: GetCredInfoCallbackWrapper_OnCredentialInfo_0200
 * @tc.desc: Test OnCredentialInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, GetCredInfoCallbackWrapper_OnCredentialInfo_0200, TestSize.Level0)
{
    sptr<MockGetCredInfoCallback1> callback = new (std::nothrow) MockGetCredInfoCallback1();
    ASSERT_NE(callback, nullptr);

    CredentialInfo credentialInfo;
    std::vector<CredentialInfo> infoList = {credentialInfo};
    auto getCredInfoCallbackWrapper = std::make_shared<GetCredInfoCallbackWrapper>(
        TEST_USER_ID, 1, callback);
    EXPECT_TRUE(getCredInfoCallbackWrapper->innerCallback_ != nullptr);

    EXPECT_CALL(*callback, OnCredentialInfo(0, _)).Times(1);
    getCredInfoCallbackWrapper->OnCredentialInfo(10, infoList);

    EXPECT_CALL(*callback, OnCredentialInfo(9, _)).Times(1);
    getCredInfoCallbackWrapper->OnCredentialInfo(9, infoList);

    getCredInfoCallbackWrapper->authType_ = 0;
    EXPECT_CALL(*callback, OnCredentialInfo(0, _)).Times(1);
    getCredInfoCallbackWrapper->OnCredentialInfo(0, infoList);
}

/**
 * @tc.name: GetPropCallbackWrapper_OnResult_0100
 * @tc.desc: OnResult with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, GetPropCallbackWrapper_OnResult_0100, TestSize.Level0)
{
    Attributes extraInfo;
    auto getPropCallback = std::make_shared<GetPropCallbackWrapper>(DEFAULT_USER_ID, nullptr);
    EXPECT_TRUE(getPropCallback->innerCallback_ == nullptr);
    getPropCallback->OnResult(0, extraInfo);
}

/**
 * @tc.name: GetPropCallbackWrapper_OnResult_0100
 * @tc.desc: Test OnResult.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, GetPropCallbackWrapper_OnResult_0200, TestSize.Level0)
{
    Attributes extraInfo;
    sptr<MockGetSetPropCallback> callback = new (std::nothrow) MockGetSetPropCallback();
    auto getPropCallbackWrapper = std::make_shared<GetPropCallbackWrapper>(TEST_USER_ID, callback);
    EXPECT_TRUE(getPropCallbackWrapper->innerCallback_ != nullptr);

    EXPECT_CALL(*callback, OnResult(10, _)).Times(1);
    getPropCallbackWrapper->OnResult(10, extraInfo);
    EXPECT_CALL(*callback, OnResult(0, _)).Times(1);
    getPropCallbackWrapper->OnResult(0, extraInfo);
}

/**
 * @tc.name: SetPropCallbackWrapper_OnResult_0100
 * @tc.desc: OnResult with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, SetPropCallbackWrapper_OnResult_0100, TestSize.Level0)
{
    Attributes extraInfo;
    auto setPropCallback = std::make_shared<SetPropCallbackWrapper>(DEFAULT_USER_ID, nullptr);
    EXPECT_TRUE(setPropCallback->innerCallback_ == nullptr);
    setPropCallback->OnResult(0, extraInfo);
}

/**
 * @tc.name: SetPropCallbackWrapper_OnResult_0200
 * @tc.desc: Test OnResult.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, SetPropCallbackWrapper_OnResult_0200, TestSize.Level0)
{
    sptr<MockGetSetPropCallback> callback = new (std::nothrow) MockGetSetPropCallback();
    std::vector<uint8_t> token = {0, 0, 0, 0, 0, 0, 0};
    Attributes extraInfo;
    auto setPropCallbackWrapper = std::make_shared<SetPropCallbackWrapper>(TEST_USER_ID, callback);
    EXPECT_TRUE(setPropCallbackWrapper->innerCallback_ != nullptr);

    EXPECT_CALL(*callback, OnResult(10, _)).Times(1);
    setPropCallbackWrapper->OnResult(10, extraInfo);
    EXPECT_CALL(*callback, OnResult(0, _)).Times(1);
    setPropCallbackWrapper->OnResult(0, extraInfo);
}

/**
 * @tc.name: PrepareRemoteAuthCallbackWrapper_OnResult_0100
 * @tc.desc: Test OnResult.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, PrepareRemoteAuthCallbackWrapper_OnResult_0100, TestSize.Level0)
{
    sptr<MockPrepareRemoteAuthCallbackWrapper> callback = new (std::nothrow) MockPrepareRemoteAuthCallbackWrapper();

    auto prepareRemoteAuthCallbackWrapperNull = std::make_shared<PrepareRemoteAuthCallbackWrapper>(nullptr);
    EXPECT_TRUE(prepareRemoteAuthCallbackWrapperNull->innerCallback_ == nullptr);
    EXPECT_CALL(*callback, OnResult(10)).Times(0);
    prepareRemoteAuthCallbackWrapperNull->OnResult(10);

    auto prepareRemoteAuthCallbackWrapper = std::make_shared<PrepareRemoteAuthCallbackWrapper>(callback);
    EXPECT_TRUE(prepareRemoteAuthCallbackWrapper->innerCallback_ != nullptr);

    EXPECT_CALL(*callback, OnResult(10)).Times(1);
    prepareRemoteAuthCallbackWrapper->OnResult(10);
    EXPECT_CALL(*callback, OnResult(0)).Times(1);
    prepareRemoteAuthCallbackWrapper->OnResult(0);
}

#ifdef SUPPORT_DOMAIN_ACCOUNTS
/**
 * @tc.name: GetDomainAuthStatusInfoCallback_OnResult_0100
 * @tc.desc: Test OnResult.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, GetDomainAuthStatusInfoCallback_OnResult_0100, TestSize.Level0)
{
    sptr<MockGetSetPropCallback> callback = new (std::nothrow) MockGetSetPropCallback();
    std::vector<uint8_t> token = {0, 0, 0, 0, 0, 0, 0};
    GetPropertyRequest request;
    Parcel parcel;

    auto getDomainAuthStatusInfoCallbackNull = std::make_shared<GetDomainAuthStatusInfoCallback>(request, nullptr);
    EXPECT_TRUE(getDomainAuthStatusInfoCallbackNull->innerCallback_ == nullptr);
    getDomainAuthStatusInfoCallbackNull->OnResult(10, parcel);

    auto getDomainAuthStatusInfoCallback = std::make_shared<GetDomainAuthStatusInfoCallback>(request, callback);
    EXPECT_TRUE(getDomainAuthStatusInfoCallback->innerCallback_ != nullptr);

    EXPECT_CALL(*callback, OnResult(ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR, _)).Times(1);
    getDomainAuthStatusInfoCallback->OnResult(10, parcel);

    parcel.WriteInt32(10);
    parcel.WriteInt32(20);
    EXPECT_CALL(*callback, OnResult(0, _)).Times(1);
    getDomainAuthStatusInfoCallback->OnResult(0, parcel);
}
#endif
} // namespace AccountTest
} // namespace OHOS
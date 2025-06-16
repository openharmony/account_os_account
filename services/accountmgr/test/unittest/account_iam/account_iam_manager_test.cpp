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
#include <unistd.h>
#include <vector>

#include "accesstoken_kit.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "iam_common_defines.h"
#define private public
#include "iinner_os_account_manager.h"
#include "inner_account_iam_manager.h"
#undef private
#include "id_m_callback_stub.h"
#include "istorage_manager.h"
#include "parameter.h"
#include "pre_remote_auth_callback_stub.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace Security::AccessToken;
using namespace StorageManager;

namespace OHOS {
namespace AccountTest {
namespace {
    const int32_t TEST_EXIST_ID = 100;
    const int32_t TEST_USER_ID = 101;
    const int32_t UPDATE_USER_ID = 102;
    const int32_t UPDATE_FAIL_USER_ID = 103;
    const std::vector<uint8_t> TEST_CHALLENGE = {1, 2, 3, 4};
    static bool g_fscryptEnable = false;
    const uid_t ACCOUNT_UID = 3058;
    const int32_t WAIT_TIME = 20;
}

class MockDeathRecipient : public IRemoteObject {
public:
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override;
    int32_t GetObjectRefCount() override;
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override;
    int Dump(int fd, const std::vector<std::u16string> &args) override;
};

bool MockDeathRecipient::AddDeathRecipient(const sptr<DeathRecipient> &recipient)
{
    return true;
}

int32_t MockDeathRecipient::GetObjectRefCount()
{
    return 0;
}

int MockDeathRecipient::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    return 0;
}

bool MockDeathRecipient::RemoveDeathRecipient(const sptr<DeathRecipient> &recipient)
{
    return true;
}

int MockDeathRecipient::Dump(int fd, const std::vector<std::u16string> &args)
{
    return 0;
}

class MockIIDMCallback : public IDMCallbackStub {
public:
    MOCK_METHOD2(OnResult, ErrCode(int32_t resultCode, const std::vector<uint8_t>& extraInfoBuffer));
    MOCK_METHOD3(
        OnAcquireInfo, ErrCode(int32_t module, uint32_t acquireInfo, const std::vector<uint8_t>& extraInfoBuffer));
};

class TestIIDMCallback : public IDMCallbackStub {
public:
    explicit TestIIDMCallback(const std::shared_ptr<MockIIDMCallback> &callback) : callback_(callback)
    {}
    ErrCode OnResult(int32_t resultCode, const std::vector<uint8_t>& extraInfoBuffer)
    {
        callback_->OnResult(resultCode, extraInfoBuffer);
        std::unique_lock<std::mutex> lock(mutex);
        isReady = true;
        cv.notify_one();
        return ERR_OK;
    }
    ErrCode OnAcquireInfo(int32_t module, uint32_t acquireInfo, const std::vector<uint8_t>& extraInfoBuffer)
    {
        callback_->OnAcquireInfo(module, acquireInfo, extraInfoBuffer);
        return ERR_OK;
    }
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;

private:
    std::shared_ptr<MockIIDMCallback> callback_;
};

class MockIIDMCallback2 : public IDMCallbackStub {
public:
    ErrCode OnAcquireInfo(int32_t module, uint32_t acquireInfo, const std::vector<uint8_t>& extraInfoBuffer) override
    {
        module_ = module;
        acquireInfo_ = acquireInfo;
        return ERR_OK;
    }
    ErrCode OnResult(int32_t resultCode, const std::vector<uint8_t>& extraInfoBuffer) override
    {
        result_ = resultCode;
        return ERR_OK;
    }

public:
    int32_t result_ = -1;
    int32_t module_ = 0;
    uint32_t acquireInfo_ = 0;
};

class MockPreRemoteAuthCallback : public PreRemoteAuthCallbackStub {
public:
    MOCK_METHOD1(OnResult, ErrCode(int32_t resultCode));
};

class TestPreRemoteAuthCallback : public PreRemoteAuthCallbackStub {
public:
    explicit TestPreRemoteAuthCallback(const std::shared_ptr<MockPreRemoteAuthCallback> &callback) : callback_(callback)
    {}
    ErrCode OnResult(int32_t resultCode)
    {
        callback_->OnResult(resultCode);
        return ERR_OK;
    }

private:
    std::shared_ptr<MockPreRemoteAuthCallback> callback_;
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
    ASSERT_TRUE(MockTokenId("accountmgr"));
    setuid(ACCOUNT_UID);
    g_fscryptEnable = FscryptEnable();
}

void AccountIamManagerTest::TearDownTestCase()
{
    std::cout << "AccountIamManagerTest::TearDownTestCase" << std::endl;
}

void AccountIamManagerTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
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
HWTEST_F(AccountIamManagerTest, OpenSession001, TestSize.Level0)
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
    std::shared_ptr<MockIIDMCallback> callback = std::make_shared<MockIIDMCallback>();
    EXPECT_NE(callback, nullptr);
    sptr<TestIIDMCallback> testCallback = new(std::nothrow) TestIIDMCallback(callback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_, _)).Times(Exactly(0));
    InnerAccountIAMManager::GetInstance().AddCredential(TEST_USER_ID, testPara, nullptr);
    InnerAccountIAMManager::GetInstance().AddCredential(TEST_USER_ID, testPara, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
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
    std::shared_ptr<MockIIDMCallback> callback = std::make_shared<MockIIDMCallback>();
    EXPECT_NE(callback, nullptr);
    sptr<TestIIDMCallback> testCallback = new(std::nothrow) TestIIDMCallback(callback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_, _)).Times(Exactly(2));
    InnerAccountIAMManager::GetInstance().UpdateCredential(TEST_USER_ID, testPara, nullptr);
    InnerAccountIAMManager::GetInstance().UpdateCredential(TEST_USER_ID, testPara, testCallback);
    {
        std::unique_lock<std::mutex> lock(testCallback->mutex);
        testCallback->cv.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    }

    testPara.token = {1, 2, 3};
    InnerAccountIAMManager::GetInstance().UpdateCredential(TEST_USER_ID, testPara, testCallback);
    {
        std::unique_lock<std::mutex> lock(testCallback->mutex);
        testCallback->cv.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    }
}

/**
 * @tc.name: Cancel001
 * @tc.desc: Cancel with .
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, Cancel001, TestSize.Level0)
{
    InnerAccountIAMManager::GetInstance().SetState(TEST_USER_ID, AFTER_OPEN_SESSION);
    int32_t ret = InnerAccountIAMManager::GetInstance().Cancel(TEST_USER_ID);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: Cancel002
 * @tc.desc: Cancel after add credential.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, Cancel002, TestSize.Level0)
{
    InnerAccountIAMManager::GetInstance().SetState(TEST_USER_ID, AFTER_ADD_CRED);
    int32_t ret = InnerAccountIAMManager::GetInstance().Cancel(TEST_USER_ID);
    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

/**
 * @tc.name: Cancel003
 * @tc.desc: Cancel with invalid user id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, Cancel003, TestSize.Level0)
{
    InnerAccountIAMManager::GetInstance().SetState(TEST_USER_ID, AFTER_ADD_CRED);
    int32_t ret = InnerAccountIAMManager::GetInstance().Cancel(TEST_USER_ID);
    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
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
    std::shared_ptr<MockIIDMCallback> callback = std::make_shared<MockIIDMCallback>();
    EXPECT_NE(callback, nullptr);
    sptr<TestIIDMCallback> testCallback = new(std::nothrow) TestIIDMCallback(callback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_, _)).Times(Exactly(2));
    InnerAccountIAMManager::GetInstance().DelCred(TEST_USER_ID, testCredentialId, testAuthToken, nullptr);

    InnerAccountIAMManager::GetInstance().DelCred(TEST_USER_ID, testCredentialId, testAuthToken, testCallback);
    {
        std::unique_lock<std::mutex> lock(testCallback->mutex);
        testCallback->cv.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    }

    testAuthToken = {1, 2, 3, 4};
    InnerAccountIAMManager::GetInstance().DelCred(TEST_USER_ID, testCredentialId, testAuthToken, testCallback);
    {
        std::unique_lock<std::mutex> lock(testCallback->mutex);
        testCallback->cv.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    }
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
    std::shared_ptr<MockIIDMCallback> callback = std::make_shared<MockIIDMCallback>();
    EXPECT_NE(callback, nullptr);
    sptr<TestIIDMCallback> testCallback = new(std::nothrow) TestIIDMCallback(callback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_, _)).Times(Exactly(2));
    InnerAccountIAMManager::GetInstance().DelUser(TEST_USER_ID, testAuthToken, nullptr);
    InnerAccountIAMManager::GetInstance().DelUser(TEST_USER_ID, testAuthToken, testCallback);
    {
        std::unique_lock<std::mutex> lock(testCallback->mutex);
        testCallback->cv.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    }

    testAuthToken = {1, 2, 3, 4};
    InnerAccountIAMManager::GetInstance().DelUser(TEST_USER_ID, testAuthToken, testCallback);
    {
        std::unique_lock<std::mutex> lock(testCallback->mutex);
        testCallback->cv.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    }
}

/**
 * @tc.name: AuthUser001
 * @tc.desc: Auth user.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, AuthUser001, TestSize.Level0)
{
    std::shared_ptr<MockIIDMCallback> callback = std::make_shared<MockIIDMCallback>();
    EXPECT_NE(callback, nullptr);
    sptr<TestIIDMCallback> testCallback = new(std::nothrow) TestIIDMCallback(callback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_, _)).Times(0);
    AccountSA::AuthParam authParam;
    authParam.userId = TEST_EXIST_ID;
    authParam.challenge = TEST_CHALLENGE;
    authParam.authType = AuthType::PIN;
    authParam.authTrustLevel = AuthTrustLevel::ATL1;
    uint64_t contextId = 0;
    ErrCode errCode = InnerAccountIAMManager::GetInstance().AuthUser(authParam, nullptr, contextId);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_NULL_PTR_ERROR, errCode);

    errCode = InnerAccountIAMManager::GetInstance().AuthUser(authParam, testCallback, contextId);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT, errCode);
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
 * @tc.name: ActivateUserKey001
 * @tc.desc: ActivateUserKey.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, ActivateUserKey001, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    std::vector<uint8_t> testSecret = {1, 2, 3, 4};

    auto &innerIamMgr_ = InnerAccountIAMManager::GetInstance();

    EXPECT_NE(ERR_OK, innerIamMgr_.ActivateUserKey(TEST_USER_ID, testAuthToken, testSecret));

    int32_t userId = 112;
    EXPECT_NE(ERR_OK, innerIamMgr_.ActivateUserKey(userId, testAuthToken, testSecret));

    // userid is out of range
    userId = 11112;
    EXPECT_NE(ERR_OK, innerIamMgr_.ActivateUserKey(userId, testAuthToken, testSecret));
}

/**
 * @tc.name: GetLockScreenStatus001
 * @tc.desc: GetLockScreenStatus coverage test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, GetLockScreenStatus001, TestSize.Level0)
{
    auto &innerIamMgr_ = InnerAccountIAMManager::GetInstance();

    bool getLockStatus = false;
    EXPECT_EQ(ERR_OK, innerIamMgr_.GetLockScreenStatus(100, getLockStatus));
}

/**
 * @tc.name: UnlockUserScreen001
 * @tc.desc: UnlockUserScreen coverage test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, UnlockUserScreen001, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    std::vector<uint8_t> testSecret = {1, 2, 3, 4};

    auto &innerIamMgr_ = InnerAccountIAMManager::GetInstance();

    EXPECT_EQ(ERR_OK, innerIamMgr_.UnlockUserScreen(100, testAuthToken, testSecret));
}

/**
 * @tc.name: PrepareStartUser001
 * @tc.desc: PrepareStartUser coverage test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, PrepareStartUser001, TestSize.Level0)
{
    auto &innerIamMgr_ = InnerAccountIAMManager::GetInstance();

    EXPECT_EQ(ERR_OK, innerIamMgr_.PrepareStartUser(100));
}

/**
 * @tc.name: CheckNeedReactivateUserKey001
 * @tc.desc: CheckNeedReactivateUserKey coverage test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, CheckNeedReactivateUserKey001, TestSize.Level0)
{
    auto &innerIamMgr_ = InnerAccountIAMManager::GetInstance();

    bool isNeedReactivateUserKey = false;
    EXPECT_EQ(ERR_OK, innerIamMgr_.CheckNeedReactivateUserKey(100, isNeedReactivateUserKey));
}

/**
 * @tc.name: UpdateCredCallback_OnResult_0001
 * @tc.desc: OnResult with not PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, UpdateCredCallback_OnResult_0001, TestSize.Level0)
{
    sptr<MockIIDMCallback2> callback = new (std::nothrow) MockIIDMCallback2();
    CredentialParameters credInfo = {};
    credInfo.authType = AuthType::PIN;
    Attributes extraInfo;
    auto updateCredCallback = std::make_shared<UpdateCredCallback>(UPDATE_USER_ID, credInfo, callback);

    EXPECT_TRUE(updateCredCallback->innerCallback_ != nullptr);
    int32_t errCode = 10;
    updateCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    errCode = 0;
    updateCredCallback->OnResult(errCode, extraInfo);
    EXPECT_NE(errCode, callback->result_);
}

/**
 * @tc.name: UpdateCredCallback_OnResult_0002
 * @tc.desc: OnResult with not PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, UpdateCredCallback_OnResult_0002, TestSize.Level0)
{
    sptr<MockIIDMCallback2> callback = new (std::nothrow) MockIIDMCallback2();
    CredentialParameters credInfo = {};
    credInfo.authType = AuthType::PIN;
    Attributes extraInfo;
    auto updateCredCallback = std::make_shared<UpdateCredCallback>(UPDATE_FAIL_USER_ID, credInfo, callback);
    EXPECT_TRUE(updateCredCallback->innerCallback_ != nullptr);
    int32_t errCode = 0;
    updateCredCallback->OnResult(errCode, extraInfo);
    EXPECT_NE(errCode, callback->result_);

    UpdateCredInfo extraUpdateInfo;
    auto commitUpdateCredCallback = std::make_shared<CommitCredUpdateCallback>(UPDATE_FAIL_USER_ID,
        extraUpdateInfo, callback);
    commitUpdateCredCallback->OnResult(errCode, extraInfo);
    commitUpdateCredCallback->OnResult(1, extraInfo);
}

/**
 * @tc.name: PrepareRemoteAuth001
 * @tc.desc: PrepareRemoteAuth.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, PrepareRemoteAuth001, TestSize.Level0)
{
    ErrCode errCode = InnerAccountIAMManager::GetInstance().PrepareRemoteAuth("testString", nullptr);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_NULL_PTR_ERROR, errCode);

    std::shared_ptr<MockPreRemoteAuthCallback> callback = std::make_shared<MockPreRemoteAuthCallback>();
    EXPECT_NE(callback, nullptr);
    sptr<TestPreRemoteAuthCallback> testCallback = new(std::nothrow) TestPreRemoteAuthCallback(callback);
    EXPECT_NE(testCallback, nullptr);

    InnerAccountIAMManager::GetInstance().PrepareRemoteAuth("testString", testCallback);
}

/**
 * @tc.name: testAuthUser001
 * @tc.desc: test auth when the user is deactivating.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, testAuthUser001, TestSize.Level0)
{
    IInnerOsAccountManager::GetInstance().deactivatingAccounts_.EnsureInsert(TEST_EXIST_ID, true);
    std::shared_ptr<MockIIDMCallback> callback = std::make_shared<MockIIDMCallback>();
    EXPECT_NE(callback, nullptr);
    sptr<TestIIDMCallback> testCallback = new(std::nothrow) TestIIDMCallback(callback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_, _)).Times(0);
    AccountSA::AuthParam authParam;
    authParam.userId = TEST_EXIST_ID;
    authParam.challenge = TEST_CHALLENGE;
    authParam.authType = AuthType::PIN;
    authParam.authTrustLevel = AuthTrustLevel::ATL1;
    uint64_t contextId = 0;
    ErrCode errCode = InnerAccountIAMManager::GetInstance().AuthUser(authParam, testCallback, contextId);
    EXPECT_EQ(ERR_IAM_BUSY, errCode);
    IInnerOsAccountManager::GetInstance().deactivatingAccounts_.Erase(TEST_EXIST_ID);
}

#ifdef SUPPORT_LOCK_OS_ACCOUNT
/**
 * @tc.name: testAuthUser002
 * @tc.desc: test auth when the user is locking.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, testAuthUser002, TestSize.Level0)
{
    IInnerOsAccountManager::GetInstance().lockingAccounts_.EnsureInsert(TEST_EXIST_ID, true);
    std::shared_ptr<MockIIDMCallback> callback = std::make_shared<MockIIDMCallback>();
    EXPECT_NE(callback, nullptr);
    sptr<TestIIDMCallback> testCallback = new(std::nothrow) TestIIDMCallback(callback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_, _)).Times(0);
    AccountSA::AuthParam authParam = {
        .userId = TEST_EXIST_ID,
        .challenge = TEST_CHALLENGE,
        .authType = AuthType::PIN,
        .authTrustLevel = AuthTrustLevel::ATL1
    };
    uint64_t contextId = 0;
    ErrCode errCode = InnerAccountIAMManager::GetInstance().AuthUser(authParam, testCallback, contextId);
    EXPECT_EQ(ERR_IAM_BUSY, errCode);
    IInnerOsAccountManager::GetInstance().lockingAccounts_.Erase(TEST_EXIST_ID);
}
#endif
}  // namespace AccountTest
}  // namespace OHOS

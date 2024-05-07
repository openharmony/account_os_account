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
#include <gtest/gtest.h>
#include <unistd.h>
#include <vector>

#include "accesstoken_kit.h"
#include "account_error_no.h"
#include "account_iam_callback_stub.h"
#include "account_log_wrapper.h"
#include "iam_common_defines.h"
#define private public
#include "inner_account_iam_manager.h"
#undef private
#include "istorage_manager.h"
#include "parameter.h"
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
    const int32_t TEST_OTHER_ID = 112;
    const int32_t TEST_ID = 2222;
    const int32_t ERROR_STORAGE_KEY_NOT_EXIST = -2;
    const std::vector<uint8_t> TEST_CHALLENGE = {1, 2, 3, 4};
    static bool g_fscryptEnable = false;
    const uid_t ACCOUNT_UID = 3058;
    const int32_t WAIT_TIME = 20;
}

class MockStorageMgrProxy : public StorageManager::IStorageManager {
public:
    MockStorageMgrProxy()
    {}
    ~MockStorageMgrProxy()
    {}
    int32_t UpdateUserAuth(uint32_t userId, uint64_t secureUid,
                            const std::vector<uint8_t> &token,
                            const std::vector<uint8_t> &oldSecret,
                            const std::vector<uint8_t> &newSecret);

    int32_t PrepareAddUser(int32_t userId, uint32_t flags)
    {
        return 0;
    }

    int32_t RemoveUser(int32_t userId, uint32_t flags)
    {
        return 0;
    }

    int32_t PrepareStartUser(int32_t userId)
    {
        return 0;
    }

    int32_t StopUser(int32_t userId)
    {
        return 0;
    }

    int32_t GetFreeSizeOfVolume(std::string volumeUuid, int64_t &freeSize)
    {
        return 0;
    }

    int32_t GetTotalSizeOfVolume(std::string volumeUuid, int64_t &totalSize)
    {
        return 0;
    }

    int32_t GetBundleStats(std::string pkgName, BundleStats &bundleStats)
    {
        return 0;
    }

    int32_t GetSystemSize(int64_t &systemSize)
    {
        return 0;
    }

    int32_t GetTotalSize(int64_t &totalSize)
    {
        return 0;
    }

    int32_t GetFreeSize(int64_t &freeSize)
    {
        return 0;
    }

    int32_t GetUserStorageStats(StorageStats &storageStats)
    {
        return 0;
    }

    int32_t GetUserStorageStats(int32_t userId, StorageStats &storageStats)
    {
        return 0;
    }

    int32_t GetUserStorageStatsByType(int32_t userId, StorageStats &storageStats, std::string type)
    {
        return 0;
    }

    int32_t GetCurrentBundleStats(BundleStats &bundleStats)
    {
        return 0;
    }

    int32_t NotifyVolumeCreated(VolumeCore vc)
    {
        return 0;
    }

    int32_t NotifyVolumeMounted(std::string volumeId, int fsType, std::string fsUuid,
                            std::string path, std::string description)
    {
        return 0;
    }

    int32_t NotifyVolumeStateChanged(std::string volumeId, VolumeState state)
    {
        return 0;
    }

    int32_t Mount(std::string volumeId)
    {
        return 0;
    }

    int32_t Unmount(std::string volumeId)
    {
        return 0;
    }

    int32_t GetAllVolumes(std::vector<VolumeExternal> &vecOfVol)
    {
        return 0;
    }

    int32_t NotifyDiskCreated(Disk disk)
    {
        return 0;
    }

    int32_t NotifyDiskDestroyed(std::string diskId)
    {
        return 0;
    }

    int32_t Partition(std::string diskId, int32_t type)
    {
        return 0;
    }

    int32_t GetAllDisks(std::vector<Disk> &vecOfDisk)
    {
        return 0;
    }

    int32_t GetVolumeByUuid(std::string fsUuid, VolumeExternal &vc)
    {
        return 0;
    }

    int32_t GetVolumeById(std::string volumeId, VolumeExternal &vc)
    {
        return 0;
    }

    int32_t SetVolumeDescription(std::string fsUuid, std::string description)
    {
        return 0;
    }

    int32_t Format(std::string volumeId, std::string fsType)
    {
        return 0;
    }

    int32_t GetDiskById(std::string diskId, Disk &disk)
    {
        return 0;
    }

    int32_t GenerateUserKeys(uint32_t userId, uint32_t flags)
    {
        return 0;
    }

    int32_t DeleteUserKeys(uint32_t userId)
    {
        return 0;
    }

    int32_t ActiveUserKey(uint32_t userId, const std::vector<uint8_t> &token, const std::vector<uint8_t> &secret)
    {
        if (userId == TEST_USER_ID) {
            return 0;
        }
        if (userId == TEST_OTHER_ID) {
            return ERROR_STORAGE_KEY_NOT_EXIST;
        }
        return -1;
    }

    int32_t InactiveUserKey(uint32_t userId)
    {
        return 0;
    }

    int32_t LockUserScreen(uint32_t userId)
    {
        return 0;
    }

    int32_t GetLockScreenStatus(uint32_t userId, bool &lockScreenStatus)
    {
        return 0;
    }

    int32_t GenerateAppkey(uint32_t appUid, std::string &keyId)
    {
        return 0;
    }

    int32_t DeleteAppkey(const std::string keyId)
    {
        return 0;
    }

    int32_t UnlockUserScreen(uint32_t userId)
    {
        return 0;
    }

    int32_t MountDfsDocs(int32_t userId, const std::string &relativePath,
        const std::string &networkId, const std::string &deviceId)
    {
        return 0;
    }

    int32_t UpdateKeyContext(uint32_t userId)
    {
        return g_fscryptEnable ? ERROR_STORAGE_KEY_NOT_EXIST : 0;
    }

    std::vector<int32_t> CreateShareFile(const std::vector<std::string> &uriList, uint32_t tokenId, uint32_t flag)
    {
        return std::vector<int32_t>{0};
    }

    int32_t DeleteShareFile(uint32_t tokenId, const std::vector<std::string> &uriList)
    {
        return 0;
    }

    int32_t SetBundleQuota(const std::string &bundleName, int32_t uid, const std::string &bundleDataDirPath,
        int32_t limitSizeMb)
    {
        return 0;
    }

    int32_t UpdateMemoryPara(int32_t size, int32_t &oldSize)
    {
        return 0;
    }

    int32_t GetBundleStatsForIncrease(uint32_t userId, const std::vector<std::string> &bundleNames,
        const std::vector<int64_t> &incrementalBackTimes, std::vector<int64_t> &pkgFileSizes)
    {
        return 0;
    }

    sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    }
};

int32_t MockStorageMgrProxy::UpdateUserAuth(uint32_t userId, uint64_t secureUid,
                                            const std::vector<uint8_t> &token,
                                            const std::vector<uint8_t> &oldSecret,
                                            const std::vector<uint8_t> &newSecret)
{
    const uint32_t dataSize = 4;
    if (userId == UPDATE_USER_ID) {
        return 0;
    }
    if (userId == UPDATE_FAIL_USER_ID) {
        return -1;
    }
    if (!g_fscryptEnable) {
        return 0;
    }
    if (newSecret.size() == dataSize || userId == TEST_OTHER_ID) {
        return g_fscryptEnable ? ERROR_STORAGE_KEY_NOT_EXIST : 0;
    }
    if (userId == TEST_ID) {
        if (token.size() != dataSize) {
            return ERROR_STORAGE_KEY_NOT_EXIST;
        }
    }
    std::cout << "mock UpdateUserAuth enter" << std::endl;
    return 0;
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
    MOCK_METHOD2(OnResult, void(int32_t result, const AccountSA::Attributes &extraInfo));
    MOCK_METHOD3(OnAcquireInfo, void(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo));
};

class TestIIDMCallback : public IDMCallbackStub {
public:
    explicit TestIIDMCallback(const std::shared_ptr<MockIIDMCallback> &callback) : callback_(callback)
    {}
    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo)
    {
        callback_->OnResult(result, extraInfo);
        std::unique_lock<std::mutex> lock(mutex);
        isReady = true;
        cv.notify_one();
        return;
    }
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo)
    {
        callback_->OnAcquireInfo(module, acquireInfo, extraInfo);
    }
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;

private:
    std::shared_ptr<MockIIDMCallback> callback_;
};

class MockIIDMCallback2 : public IDMCallbackStub {
public:
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override
    {
        module_ = module;
        acquireInfo_ = acquireInfo;
        return;
    }
    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        result_ = result;
        return;
    }

public:
    int32_t result_ = -1;
    int32_t module_ = 0;
    uint32_t acquireInfo_ = 0;
};

class MockPreRemoteAuthCallback : public PreRemoteAuthCallbackStub {
public:
    MOCK_METHOD1(OnResult, void(int32_t result));
};

class TestPreRemoteAuthCallback : public PreRemoteAuthCallbackStub {
public:
    explicit TestPreRemoteAuthCallback(const std::shared_ptr<MockPreRemoteAuthCallback> &callback) : callback_(callback)
    {}
    void OnResult(int32_t result)
    {
        callback_->OnResult(result);
        return;
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
    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("accountmgr");
    SetSelfTokenID(tokenId);
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
    EXPECT_CALL(*callback, OnResult(_, _)).Times(Exactly(1));
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
    SetPropertyRequest testRequest = {};
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
 * @tc.name: GetChallenge001
 * @tc.desc: Get Challenge.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, GetChallenge001, TestSize.Level2)
{
    std::vector<uint8_t> challenge;
    InnerAccountIAMManager::GetInstance().OpenSession(TEST_USER_ID, challenge);

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
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT);

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

    auto &innerIamMgr_ = InnerAccountIAMManager::GetInstance();
    sptr<MockStorageMgrProxy> ptr = new (std::nothrow) MockStorageMgrProxy();
    ASSERT_NE(ptr, nullptr);
    innerIamMgr_.storageMgrProxy_ = ptr;

    EXPECT_EQ(ERR_OK, innerIamMgr_.ActivateUserKey(TEST_USER_ID, testAuthToken, testSecret));

    int32_t userId = 112;
    EXPECT_EQ(ERR_OK, innerIamMgr_.ActivateUserKey(userId, testAuthToken, testSecret));

    // userid is out of range
    userId = 11112;
    EXPECT_NE(ERR_OK, innerIamMgr_.ActivateUserKey(userId, testAuthToken, testSecret));
    innerIamMgr_.storageMgrProxy_ = nullptr;
}

/**
 * @tc.name: UpdateStorageKey001
 * @tc.desc: UpdateStorageKey.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, UpdateStorageKey001, TestSize.Level2)
{
    uint64_t testCreId = 111;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    std::vector<uint8_t> testSecret = {1, 2, 3, 4};
    std::vector<uint8_t> token = {};
    auto &innerIamMgr_ = InnerAccountIAMManager::GetInstance();
    sptr<MockStorageMgrProxy> ptr = new (std::nothrow) MockStorageMgrProxy();
    ASSERT_NE(ptr, nullptr);
    innerIamMgr_.storageMgrProxy_ = ptr;

    int32_t res =
        innerIamMgr_.UpdateStorageKey(TEST_USER_ID, testCreId, token, testSecret, testSecret);
    EXPECT_EQ(g_fscryptEnable ? -2 : 0, res);
    innerIamMgr_.storageMgrProxy_ = nullptr;
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
    auto &innerIamMgr_ = InnerAccountIAMManager::GetInstance();
    sptr<MockStorageMgrProxy> ptr = new (std::nothrow) MockStorageMgrProxy();
    ASSERT_NE(ptr, nullptr);
    innerIamMgr_.storageMgrProxy_ = ptr;

    EXPECT_TRUE(updateCredCallback->innerCallback_ != nullptr);
    int32_t errCode = 10;
    updateCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    errCode = 0;
    updateCredCallback->OnResult(errCode, extraInfo);
    EXPECT_NE(errCode, callback->result_);
    innerIamMgr_.storageMgrProxy_ = nullptr;
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
    auto &innerIamMgr_ = InnerAccountIAMManager::GetInstance();
    sptr<MockStorageMgrProxy> ptr = new (std::nothrow) MockStorageMgrProxy();
    ASSERT_NE(ptr, nullptr);
    innerIamMgr_.storageMgrProxy_ = ptr;

    EXPECT_TRUE(updateCredCallback->innerCallback_ != nullptr);
    int32_t errCode = 0;
    updateCredCallback->OnResult(errCode, extraInfo);
    EXPECT_NE(errCode, callback->result_);

    auto commitUpdateCredCallback = std::make_shared<CommitCredUpdateCallback>(UPDATE_FAIL_USER_ID, callback);
    commitUpdateCredCallback->OnResult(errCode, extraInfo);
    commitUpdateCredCallback->OnResult(1, extraInfo);
    innerIamMgr_.storageMgrProxy_ = nullptr;
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
}  // namespace AccountTest
}  // namespace OHOS

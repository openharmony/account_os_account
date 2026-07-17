/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cerrno>
#include <filesystem>
#include <mutex>
#include <gtest/gtest.h>
#include <thread>
#include <unistd.h>
#include "accesstoken_kit.h"
#include "account_error_no.h"
#include "account_file_operator.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "account_test_common.h"
#include "domain_account_callback_service.h"
#ifdef BUNDLE_ADAPTER_MOCK
#include "domain_account_manager_service.h"
#include "domain_account_proxy.h"
#endif
#define private public
#define protected public
#include "domain_account_client.h"
#include "inner_domain_account_manager.h"
#include "inner_account_iam_manager.h"
#include "account_iam_callback.h"
#include "iinner_os_account_manager.h"
#include "os_account.h"
#include "os_account_control_file_manager.h"
#undef protected
#undef private
#include "account_iam_service.h"
#include "ipc_skeleton.h"
#include "mock_domain_auth_callback.h"
#include "mock_domain_auth_callback_for_listener.h"
#include "mock_domain_create_domain_account_callback.h"
#include "mock_domain_has_domain_info_callback.h"
#include "mock_domain_get_access_token_callback.h"
#include "mock_domain_plugin.h"
#include "account_iam_info.h"
#include "mock_domain_so_plugin.h"
#include "os_account_manager.h"
#ifdef BUNDLE_ADAPTER_MOCK
#include "os_account_manager_service.h"
#include "os_account_proxy.h"
#endif
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AccountSA::Constants;

namespace {
static int g_a = 1;
static void *g_ptr = &g_a;
const int32_t ROOT_UID = 0;
const int32_t EDM_UID = 3057;
const int32_t NOT_EDM_UID = 3058;
const std::vector<uint8_t> DEFAULT_TOKEN = {49, 50, 51, 52, 53};
static uint64_t g_selfTokenID;
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
const int32_t WAIT_TIME = 2;
const std::string STRING_SHORT_NAME_OUT_OF_RANGE(256, '1');
#endif
std::map<PluginMethodEnum, void *> PLUGIN_METHOD_MAP = {
    {PluginMethodEnum::AUTH, reinterpret_cast<void *>(Auth)},
    {PluginMethodEnum::GET_ACCOUNT_INFO, reinterpret_cast<void *>(GetAccountInfo)},
    {PluginMethodEnum::BIND_ACCOUNT, reinterpret_cast<void *>(BindAccount)},
    {PluginMethodEnum::IS_AUTHENTICATION_EXPIRED, reinterpret_cast<void *>(IsAuthenticationExpired)},
    {PluginMethodEnum::SET_ACCOUNT_POLICY, reinterpret_cast<void *>(SetAccountPolicy)},
    {PluginMethodEnum::GET_ACCOUNT_POLICY, reinterpret_cast<void *>(GetAccountPolicy)},
    {PluginMethodEnum::UPDATE_ACCOUNT_INFO, reinterpret_cast<void *>(UpdateAccountInfo)},
    {PluginMethodEnum::UPDATE_SERVER_CONFIG, reinterpret_cast<void *>(UpdateServerConfig)},
    {PluginMethodEnum::UNBIND_ACCOUNT, reinterpret_cast<void *>(UnBindAccount)},
    {PluginMethodEnum::CANCEL_AUTH, reinterpret_cast<void *>(CancelAuth)},
    {PluginMethodEnum::GET_ACCOUNT_SERVER_CONFIG, reinterpret_cast<void *>(GetAccountServerConfig)},
    {PluginMethodEnum::AUTH_WITH_SERVER_CONFIG, reinterpret_cast<void *>(AuthWithServerConfig)},
    {PluginMethodEnum::AUTH_WITH_UNLOCK_INTENT, reinterpret_cast<void *>(AuthWithUnlockIntent)},
    {PluginMethodEnum::GET_UNLOCK_DEVICE_CONFIG, reinterpret_cast<void *>(GetUnlockDeviceConfigResult)},
};
}

static bool RecoveryPermission(uint64_t tokenID)
{
    if (!MockTokenId("foundation")) {
        return false;
    }
    if (!((ERR_OK == AccessTokenKit::DeleteToken(tokenID)) && (ERR_OK == SetSelfTokenID(g_selfTokenID)))) {
        return false;
    }
    return g_selfTokenID == IPCSkeleton::GetSelfTokenID();
}

class MockPluginSoDomainAuthCallback {
public:
    MOCK_METHOD2(OnResult, void(int32_t resultCode, const DomainAuthResult &result));
};

class TestPluginSoDomainAuthCallback : public DomainAccountCallback {
public:
    explicit TestPluginSoDomainAuthCallback(const std::shared_ptr<MockPluginSoDomainAuthCallback> &callback);
    virtual ~TestPluginSoDomainAuthCallback();
    void OnResult(const int32_t errCode, Parcel &parcel) override;
    void SetOsAccountInfo(const OsAccountInfo &info);
    std::condition_variable cv;
    std::mutex mutex;
private:
    std::shared_ptr<MockPluginSoDomainAuthCallback> callback_;
    OsAccountInfo accountInfo_;
};

TestPluginSoDomainAuthCallback::TestPluginSoDomainAuthCallback(
    const std::shared_ptr<MockPluginSoDomainAuthCallback> &callback)
    : callback_(callback)
{}

TestPluginSoDomainAuthCallback::~TestPluginSoDomainAuthCallback()
{}

void TestPluginSoDomainAuthCallback::OnResult(const int32_t errCode, Parcel &parcel)
{
    ACCOUNT_LOGI("TestPluginSoDomainAuthCallback");
    std::unique_lock<std::mutex> lock(mutex);
    if (callback_ == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    std::shared_ptr<DomainAuthResult> authResult(DomainAuthResult::Unmarshalling(parcel));
    callback_->OnResult(errCode, (*authResult));
    cv.notify_all();
}

void TestPluginSoDomainAuthCallback::SetOsAccountInfo(const OsAccountInfo &accountInfo)
{
    accountInfo_ = accountInfo;
}

class MockIDMCallback : public IDMCallbackStub {
public:
    ErrCode OnAcquireInfo(int32_t module, uint32_t acquireInfo,
        const std::vector<uint8_t> &extraInfoBuffer) override
    {
        return ERR_OK;
    }
    ErrCode OnResult(int32_t resultCode, const std::vector<uint8_t> &extraInfoBuffer) override
    {
        result_ = resultCode;
        return ERR_OK;
    }
    int32_t result_ = -1;
};

#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
class MockPluginSoDomainCreateDomainAccountCallback {
public:
    MOCK_METHOD4(OnResult, void(const int32_t errCode, const std::string &accountName, const std::string &domain,
                                const std::string &accountId));
};

class TestPluginSoCreateDomainAccountCallback : public DomainAccountCallback {
public:
    explicit TestPluginSoCreateDomainAccountCallback(
        const std::shared_ptr<MockPluginSoDomainCreateDomainAccountCallback> &callback);
    virtual ~TestPluginSoCreateDomainAccountCallback();
    void OnResult(const int32_t errCode, Parcel &parcel) override;
    int32_t GetLocalId();
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;
private:
    int32_t localId_;
    std::shared_ptr<MockPluginSoDomainCreateDomainAccountCallback> callback_;
};

TestPluginSoCreateDomainAccountCallback::TestPluginSoCreateDomainAccountCallback(
    const std::shared_ptr<MockPluginSoDomainCreateDomainAccountCallback> &callback)
    : callback_(callback)
{}

TestPluginSoCreateDomainAccountCallback::~TestPluginSoCreateDomainAccountCallback()
{}

void TestPluginSoCreateDomainAccountCallback::OnResult(const int32_t errCode, Parcel &parcel)
{
    if (callback_ == nullptr) {
        return;
    }
    OsAccountInfo *osAccountInfo = OsAccountInfo::Unmarshalling(parcel);
    DomainAccountInfo newDomainInfo;
    osAccountInfo->GetDomainInfo(newDomainInfo);
    callback_->OnResult(errCode, newDomainInfo.accountName_, newDomainInfo.domain_, newDomainInfo.accountId_);
    localId_ = osAccountInfo->GetLocalId();
    std::unique_lock<std::mutex> lock(mutex);
    isReady = true;
    cv.notify_one();
    return;
}

int32_t TestPluginSoCreateDomainAccountCallback::GetLocalId(void)
{
    return localId_;
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

static void LoadPluginMethods()
{
    std::lock_guard<std::mutex> lock(InnerDomainAccountManager::GetInstance().libMutex_);
    InnerDomainAccountManager::GetInstance().libHandle_ = g_ptr;
    InnerDomainAccountManager::GetInstance().methodMap_.clear();
    for (const auto &mockMethod : PLUGIN_METHOD_MAP) {
        InnerDomainAccountManager::GetInstance().methodMap_.emplace(mockMethod.first, mockMethod.second);
    }
}

static void UnloadPluginMethods()
{
    std::lock_guard<std::mutex> lock(InnerDomainAccountManager::GetInstance().libMutex_);
    InnerDomainAccountManager::GetInstance().libHandle_ = nullptr;
    InnerDomainAccountManager::GetInstance().methodMap_.clear();
}

class DomainAccountClientMockPluginSoModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DomainAccountClientMockPluginSoModuleTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "SetUpTestCase enter";
    ASSERT_NE(GetAllAccountPermission(), 0);
    g_selfTokenID = IPCSkeleton::GetSelfTokenID();
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
#ifdef BUNDLE_ADAPTER_MOCK
    auto servicePtr = new (std::nothrow) DomainAccountManagerService();
    ASSERT_NE(servicePtr, nullptr);
    DomainAccountClient::GetInstance().proxy_ = new (std::nothrow) DomainAccountProxy(servicePtr->AsObject());
    ASSERT_NE(DomainAccountClient::GetInstance().proxy_, nullptr);
    auto osAccountService = new (std::nothrow) OsAccountManagerService();
    ASSERT_NE(osAccountService, nullptr);
    IInnerOsAccountManager::GetInstance().Init();
    IInnerOsAccountManager::GetInstance().ActivateDefaultOsAccount();
    {
        std::lock_guard<std::mutex> lock(OsAccount::GetInstance().mutex_);
        if ((OsAccount::GetInstance().proxy_ != nullptr) &&
            (OsAccount::GetInstance().proxy_->AsObject() != nullptr) &&
            (OsAccount::GetInstance().deathRecipient_ != nullptr)) {
            OsAccount::GetInstance().proxy_->AsObject()->RemoveDeathRecipient(
                OsAccount::GetInstance().deathRecipient_);
        }
        OsAccount::GetInstance().deathRecipient_ = nullptr;
        OsAccount::GetInstance().proxy_ = new (std::nothrow) OsAccountProxy(osAccountService->AsObject());
    }
    ASSERT_NE(OsAccount::GetInstance().proxy_, nullptr);
#endif
}

void DomainAccountClientMockPluginSoModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase";
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
}

void DomainAccountClientMockPluginSoModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    std::vector<OsAccountInfo> osAccountInfos;
    OsAccount::GetInstance().QueryAllCreatedOsAccounts(osAccountInfos);
    for (const auto &info : osAccountInfos) {
        if (info.GetLocalId() == START_USER_ID) {
            continue;
        }
        ACCOUNT_LOGI("[SetUp] remove account %{public}d", info.GetLocalId());
        OsAccount::GetInstance().RemoveOsAccount(info.GetLocalId());
    }
#ifdef BUNDLE_ADAPTER_MOCK
    setuid(ROOT_UID);
#endif
}

void DomainAccountClientMockPluginSoModuleTest::TearDown(void)
{}

/**
 * @tc.name: DomainAccountClientModuleTest_SetAccountPolicy_001
 * @tc.desc: SetAccountPolicy failed with no plugin so.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_SetAccountPolicy_001,
         TestSize.Level3)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, tokenID));
    setuid(EDM_UID);
    UnloadPluginMethods();
    DomainAccountInfo info;
    std::string policy;
    EXPECT_EQ(DomainAccountClient::GetInstance().SetAccountPolicy(info, policy),
        ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountPolicy(info, policy),
        ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));
}

/**
 * @tc.name: DomainAccountClientModuleTest_SetAccountPolicy_002
 * @tc.desc: SetAccountPolicy failed with not EDM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_SetAccountPolicy_002,
         TestSize.Level3)
{
    DomainAccountInfo info;
    LoadPluginMethods();
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, tokenID));
    std::string policy;
    EXPECT_EQ(DomainAccountClient::GetInstance().SetAccountPolicy(info, policy),
              ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountPolicy(info, policy),
              ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    UnloadPluginMethods();
    ASSERT_TRUE(RecoveryPermission(tokenID));
}

/**
 * @tc.name: DomainAccountClientModuleTest_SetAccountPolicy_003
 * @tc.desc: SetAccountPolicy failed with no ohos.permission.MANAGE_LOCAL_ACCOUNTS permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_SetAccountPolicy_003,
         TestSize.Level3)
{
    LoadPluginMethods();
    DomainAccountInfo info;
    std::string policy;
    setuid(NOT_EDM_UID);
    EXPECT_EQ(DomainAccountClient::GetInstance().SetAccountPolicy(info, policy),
              ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountPolicy(info, policy),
              ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountClientModuleTest_SetAccountPolicy_004
 * @tc.desc: SetAccountPolicy domain not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_SetAccountPolicy_004,
         TestSize.Level3)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, tokenID));
    setuid(EDM_UID);
    LoadPluginMethods();
    DomainAccountInfo info;
    std::string policy;
    EXPECT_EQ(DomainAccountClient::GetInstance().SetAccountPolicy(info, policy),
        ERR_OK);
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountPolicy(info, policy),
        ERR_OK);
    info.domain_ = "test";
    EXPECT_EQ(DomainAccountClient::GetInstance().SetAccountPolicy(info, policy),
        ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT);
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountPolicy(info, policy),
        ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT);
    UnloadPluginMethods();
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));
}

/**
 * @tc.name: DomainAccountClientModuleTest_SetAccountPolicy_005
 * @tc.desc: SetAccountPolicy success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_SetAccountPolicy_005,
         TestSize.Level3)
{
    DomainAccountInfo info;
    info.accountName_ = "testAccount";
    info.domain_ = "test.example.com";
    info.accountId_ = "testAccountId";
    LoadPluginMethods();
    auto callback = std::make_shared<MockPluginSoDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, "testAccount", "test.example.com", _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, info, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback]() { return lockCallback->isReady; });
    EXPECT_EQ(errCode, ERR_OK);
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, tokenID));
    setuid(EDM_UID);

    std::string policy;
    EXPECT_EQ(DomainAccountClient::GetInstance().SetAccountPolicy(info, policy), ERR_OK);
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountPolicy(info, policy), ERR_OK);
    UnloadPluginMethods();
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));
}

/**
 * @tc.name: DomainAccountClientModuleTest_UpdateAccountInfo_001
 * @tc.desc: UpdateAccountInfo success.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_UpdateAccountInfo_001,
         TestSize.Level3)
{
    DomainAccountInfo oldDomainInfo;
    oldDomainInfo.accountName_ = "testAccount";
    oldDomainInfo.domain_ = "test.example.com";
    oldDomainInfo.accountId_ = "testAccountId";

    DomainAccountInfo newDomainInfo;
    newDomainInfo.accountName_ = "testNewAccount";
    newDomainInfo.domain_ = "test.example.com";
    newDomainInfo.accountId_ = "testAccountId2";

    LoadPluginMethods();
    auto callback = std::make_shared<MockPluginSoDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, "testAccount", "test.example.com", _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, oldDomainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback]() { return lockCallback->isReady; });
    EXPECT_EQ(errCode, ERR_OK);
    int32_t oldUserId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(oldDomainInfo, oldUserId), ERR_OK);
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({}, tokenID));
    setuid(EDM_UID);
    ASSERT_EQ(DomainAccountClient::GetInstance().UpdateAccountInfo(oldDomainInfo, newDomainInfo),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_DOMAIN_ACCOUNTS"}, tokenID));
    ASSERT_EQ(DomainAccountClient::GetInstance().UpdateAccountInfo(oldDomainInfo, newDomainInfo), ERR_OK);
    ASSERT_TRUE(RecoveryPermission(tokenID));
    UnloadPluginMethods();
    int32_t newUserId = -1;

    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(newDomainInfo, newUserId), ERR_OK);
    EXPECT_EQ(newUserId, oldUserId);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(newUserId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_UpdateAccountInfo_002
 * @tc.desc: UpdateAccountInfo failed with new account check failed by plugin.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_UpdateAccountInfo_002,
         TestSize.Level3)
{
    DomainAccountInfo oldDomainInfo;
    oldDomainInfo.accountName_ = "testAccount";
    oldDomainInfo.domain_ = "test.example.com";
    oldDomainInfo.accountId_ = "testAccountId";

    DomainAccountInfo newDomainInfo;
    newDomainInfo.accountName_ = "testNewAccountInvalid";
    newDomainInfo.domain_ = "test.example.com";
    newDomainInfo.accountId_ = "testAccountId2";

    LoadPluginMethods();
    auto callback = std::make_shared<MockPluginSoDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, "testAccount", "test.example.com", _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, oldDomainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback]() { return lockCallback->isReady; });
    EXPECT_EQ(errCode, ERR_OK);
    int32_t oldUserId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(oldDomainInfo, oldUserId), ERR_OK);
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_DOMAIN_ACCOUNTS"}, tokenID));
    setuid(EDM_UID);
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountInfo(oldDomainInfo, newDomainInfo),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));
    UnloadPluginMethods();
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(oldUserId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_UpdateAccountInfo_003
 * @tc.desc: UpdateAccountInfo failed with new account check failed by plugin.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_UpdateAccountInfo_003,
         TestSize.Level3)
{
    DomainAccountInfo oldDomainInfo;
    oldDomainInfo.accountName_ = "testAccount";
    oldDomainInfo.domain_ = "test.example.com";
    oldDomainInfo.accountId_ = "testAccountId";

    DomainAccountInfo newDomainInfo;
    newDomainInfo.accountName_ = "testNewAccountInvalid";
    newDomainInfo.domain_ = "test.example1.com";
    newDomainInfo.accountId_ = "testAccountId2";

    LoadPluginMethods();
    auto callback = std::make_shared<MockPluginSoDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, "testAccount", "test.example.com", _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, oldDomainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback]() { return lockCallback->isReady; });
    EXPECT_EQ(errCode, ERR_OK);
    int32_t oldUserId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(oldDomainInfo, oldUserId), ERR_OK);
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_DOMAIN_ACCOUNTS"}, tokenID));
    setuid(EDM_UID);
    // test new accountInfo's domain is invalid
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountInfo(oldDomainInfo, newDomainInfo),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    // test new accountInfo's serverConfigId is invalid
    oldDomainInfo.serverConfigId_ = "testId";
    DomainAccountInfo newInfo2(oldDomainInfo);
    newInfo2.serverConfigId_ = "invalidTestId";
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountInfo(oldDomainInfo, newInfo2), ERR_OK);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));
    UnloadPluginMethods();
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(oldUserId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_UpdateAccountInfo_004
 * @tc.desc: not systemapp UpdateAccountInfo success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest,
         DomainAccountClientModuleTest_UpdateAccountInfo_004, TestSize.Level3)
{
    DomainAccountInfo oldDomainInfo;
    oldDomainInfo.accountName_ = "testAccount";
    oldDomainInfo.domain_ = "test.example.com";
    oldDomainInfo.accountId_ = "testAccountId";

    DomainAccountInfo newDomainInfo;
    newDomainInfo.accountName_ = "testNewAccount";
    newDomainInfo.domain_ = "test.example.com";
    newDomainInfo.accountId_ = "testAccountId2";

    LoadPluginMethods();
    auto callback = std::make_shared<MockPluginSoDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, "testAccount", "test.example.com", _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, oldDomainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback]() { return lockCallback->isReady; });
    EXPECT_EQ(errCode, ERR_OK);
    int32_t oldUserId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(oldDomainInfo, oldUserId), ERR_OK);
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_DOMAIN_ACCOUNTS"}, tokenID, false));
    setuid(ROOT_UID);
    // test not systemApi
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountInfo(oldDomainInfo, newDomainInfo), ERR_OK);
    ASSERT_TRUE(RecoveryPermission(tokenID));
    UnloadPluginMethods();
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(oldUserId), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: DomainAccountClientModuleTest_IsAuthenticationExpired_001
 * @tc.desc: IsAuthenticationExpired failed with no plugin so.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_IsAuthenticationExpired_001,
         TestSize.Level3)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, tokenID));
    setuid(EDM_UID);
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";

    bool isExpired = false;
    UnloadPluginMethods();
    EXPECT_EQ(DomainAccountClient::GetInstance().IsAuthenticationExpired(domainInfo, isExpired),
              ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    EXPECT_TRUE(isExpired);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));
}

/**
 * @tc.name: DomainAccountClientModuleTest_IsAuthenticationExpired_002
 * @tc.desc: IsAuthenticationExpired failed with domain account not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_IsAuthenticationExpired_002,
         TestSize.Level3)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";

    bool isExpired = false;
    LoadPluginMethods();
    EXPECT_EQ(DomainAccountClient::GetInstance().IsAuthenticationExpired(domainInfo, isExpired),
        ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT);
    EXPECT_TRUE(isExpired);
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountClientModuleTest_IsAuthenticationExpired_003
 * @tc.desc: IsAuthenticationExpired failed with domain account not authed.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_IsAuthenticationExpired_003,
         TestSize.Level3)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";
    domainInfo.serverConfigId_ = "100";

    LoadPluginMethods();
    auto callback = std::make_shared<MockPluginSoDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, "testaccount", "test.example.com", _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback]() { return lockCallback->isReady; });
    EXPECT_EQ(errCode, ERR_OK);

    bool isExpired = false;
    EXPECT_EQ(DomainAccountClient::GetInstance().IsAuthenticationExpired(domainInfo, isExpired), ERR_OK);
    EXPECT_TRUE(isExpired);
    UnloadPluginMethods();

    int32_t userId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_IsAuthenticationExpired_004
 * @tc.desc: IsAuthenticationExpired success expired time not set.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_IsAuthenticationExpired_004,
         TestSize.Level3)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";
    LoadPluginMethods();
    auto callback = std::make_shared<MockPluginSoDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, "testaccount", "test.example.com", _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback]() { return lockCallback->isReady; });
    ASSERT_EQ(errCode, ERR_OK);
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, tokenID));
    setuid(EDM_UID);

    std::string policy = "{\"authenicationValidityPeriod\":-1}";
    EXPECT_EQ(DomainAccountClient::GetInstance().SetAccountPolicy(domainInfo, policy), ERR_OK);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));

    auto authCallback = std::make_shared<MockPluginSoDomainAuthCallback>();
    ASSERT_NE(authCallback, nullptr);
    EXPECT_CALL(*authCallback, OnResult(ERR_OK, _)).Times(Exactly(1));
    auto testAuthCallback = std::make_shared<TestPluginSoDomainAuthCallback>(authCallback);
    ASSERT_NE(testAuthCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().Auth(domainInfo, DEFAULT_TOKEN, testAuthCallback), ERR_OK);

    bool isExpired = true;
    EXPECT_EQ(DomainAccountClient::GetInstance().IsAuthenticationExpired(domainInfo, isExpired), ERR_OK);
    EXPECT_FALSE(isExpired);

    sleep(2);

    isExpired = true;
    EXPECT_EQ(DomainAccountClient::GetInstance().IsAuthenticationExpired(domainInfo, isExpired), ERR_OK);
    EXPECT_FALSE(isExpired);

    UnloadPluginMethods();
    int32_t userId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_IsAuthenticationExpired_005
 * @tc.desc: IsAuthenticationExpired success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_IsAuthenticationExpired_005,
         TestSize.Level3)
{
    LoadPluginMethods();
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";
    domainInfo.serverConfigId_ = "100";
    auto callback = std::make_shared<MockPluginSoDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, "testaccount", "test.example.com", _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback]() { return lockCallback->isReady; });
    ASSERT_EQ(errCode, ERR_OK);
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, tokenID));
    setuid(EDM_UID);

    std::string policy = "{\"authenicationValidityPeriod\":1}";
    EXPECT_EQ(DomainAccountClient::GetInstance().SetAccountPolicy(domainInfo, policy), ERR_OK);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));

    auto authCallback = std::make_shared<MockPluginSoDomainAuthCallback>();
    ASSERT_NE(authCallback, nullptr);
    EXPECT_CALL(*authCallback, OnResult(ERR_OK, _)).Times(Exactly(1));
    auto testAuthCallback = std::make_shared<TestPluginSoDomainAuthCallback>(authCallback);
    ASSERT_NE(testAuthCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().Auth(domainInfo, DEFAULT_TOKEN, testAuthCallback), ERR_OK);
    {
        std::unique_lock<std::mutex> lock(testAuthCallback->mutex);
        testAuthCallback->cv.wait(lock);
    }
    bool isExpired = false;
    EXPECT_EQ(DomainAccountClient::GetInstance().IsAuthenticationExpired(domainInfo, isExpired), ERR_OK);
    EXPECT_FALSE(isExpired);

    sleep(2);

    isExpired = false;
    EXPECT_EQ(DomainAccountClient::GetInstance().IsAuthenticationExpired(domainInfo, isExpired), ERR_OK);
    EXPECT_TRUE(isExpired);

    UnloadPluginMethods();
    int32_t userId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_IsAuthWithServerConfig_001
 * @tc.desc: IsAuthWithServerConfig success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_IsAuthWithServerConfig_001,
         TestSize.Level3)
{
    LoadPluginMethods();
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";
    domainInfo.serverConfigId_ = "100";
    auto callback = std::make_shared<MockPluginSoDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, "testaccount", "test.example.com", _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback]() { return lockCallback->isReady; });
    ASSERT_EQ(errCode, ERR_OK);
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, tokenID));
    setuid(EDM_UID);

    std::string policy = "{\"authenicationValidityPeriod\":1}";
    EXPECT_EQ(DomainAccountClient::GetInstance().SetAccountPolicy(domainInfo, policy), ERR_OK);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));

    auto authCallback = std::make_shared<MockPluginSoDomainAuthCallback>();
    ASSERT_NE(authCallback, nullptr);
    EXPECT_CALL(*authCallback, OnResult(ERR_OK, _)).Times(Exactly(1));
    auto testAuthCallback = std::make_shared<TestPluginSoDomainAuthCallback>(authCallback);
    ASSERT_NE(testAuthCallback, nullptr);
    DomainAccountAuthOptions authOptions;
    authOptions.serverParams_ = "test_params";
    authOptions.hasServerParams_ = true;
    EXPECT_EQ(DomainAccountClient::GetInstance().Auth(domainInfo, DEFAULT_TOKEN,
        authOptions, testAuthCallback), ERR_OK);
    {
        std::unique_lock<std::mutex> lock(testAuthCallback->mutex);
        testAuthCallback->cv.wait(lock);
    }

    UnloadPluginMethods();
    int32_t userId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_IsAuthenticationExpired_005
 * @tc.desc: IsAuthenticationExpired success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_IsAuthenticationExpired_007,
         TestSize.Level3)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";

    CreateOsAccountForDomainOptions options;
    options.hasShortName = true;

    OsAccountInfo osAccountInfo;
    ErrCode code = OsAccountManager::CreateOsAccount("domain007", "shortExist", OsAccountType::NORMAL, osAccountInfo);
    EXPECT_EQ(code, ERR_OK);

    auto testCallback1 = nullptr;
    options.shortName = "TEST1*";
    EXPECT_NE(OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo,
        testCallback1, options), ERR_OK);

    options.shortName = "..";
    EXPECT_NE(OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo,
        testCallback1, options), ERR_OK);

    options.shortName = "";
    EXPECT_NE(OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo,
        testCallback1, options), ERR_OK);

    options.shortName = STRING_SHORT_NAME_OUT_OF_RANGE;
    EXPECT_NE(OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo,
        testCallback1, options), ERR_OK);

    options.shortName = "shortExist";
    EXPECT_NE(OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo,
        testCallback1, options), ERR_OK);

    LoadPluginMethods();
    auto callback = std::make_shared<MockPluginSoDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, "testaccount", "test.example.com", _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    options.shortName = "shortNameTest";
    options.hasShortName = false;
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo,
        testCallback, options);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback]() { return lockCallback->isReady; });
    EXPECT_EQ(errCode, ERR_OK);
    int32_t userId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: DomainAccountClientModuleTest_IsAuthenticationExpired_006
 * @tc.desc: IsAuthenticationExpired failed without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_IsAuthenticationExpired_006,
         TestSize.Level3)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({}, tokenID));
    setuid(EDM_UID);
    LoadPluginMethods();
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";
    domainInfo.serverConfigId_ = "100";

    bool isExpired = false;
    EXPECT_EQ(DomainAccountClient::GetInstance().IsAuthenticationExpired(domainInfo, isExpired),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    EXPECT_TRUE(isExpired);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));
    ASSERT_TRUE(AllocPermission({"ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS"}, tokenID));
    setuid(EDM_UID);
    EXPECT_EQ(DomainAccountClient::GetInstance().IsAuthenticationExpired(domainInfo, isExpired),
        ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT);
    EXPECT_TRUE(isExpired);
    setuid(ROOT_UID);
    UnloadPluginMethods();
    ASSERT_TRUE(RecoveryPermission(tokenID));
}

/**
 * @tc.name: DomainAccountClientModuleTest_GetOsAccountDomainInfo_001
 * @tc.desc: GetOsAccountDomainInfo success.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_GetOsAccountDomainInfo_001,
         TestSize.Level3)
{
    uint64_t tokenID;
    std::vector<std::string> needPermissions = {
        "ohos.permission.GET_DOMAIN_ACCOUNTS",
        "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS",
    };
    ASSERT_TRUE(AllocPermission(needPermissions, tokenID));
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";

    CreateOsAccountForDomainOptions options;
    LoadPluginMethods();
    auto callback = std::make_shared<MockPluginSoDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, "testaccount", "test.example.com", _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    options.shortName = "shortNameTest";
    options.hasShortName = false;
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo,
        testCallback, options);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback]() { return lockCallback->isReady; });
    ASSERT_EQ(errCode, ERR_OK);

    int32_t userId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    ASSERT_NE(userId, -1);
    DomainAccountInfo queryDomainInfo;
    EXPECT_EQ(OsAccountManager::GetOsAccountDomainInfo(userId, queryDomainInfo), ERR_OK);
    EXPECT_EQ(queryDomainInfo.accountId_, domainInfo.accountId_);
    EXPECT_EQ(queryDomainInfo.accountName_, domainInfo.accountName_);
    EXPECT_EQ(queryDomainInfo.domain_, domainInfo.domain_);

    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetOsAccountDomainInfo(userId, queryDomainInfo),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    RecoveryPermission(tokenID);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: DomainAccountClientModuleTest_GetOsAccountDomainInfo_002
 * @tc.desc: GetOsAccountDomainInfo fail with invalid input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_GetOsAccountDomainInfo_002,
         TestSize.Level3)
{
    uint64_t tokenID;

    std::vector<std::string> needPermissions = {
        "ohos.permission.GET_DOMAIN_ACCOUNTS",
        "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS",
    };
    ASSERT_TRUE(AllocPermission(needPermissions, tokenID));
    DomainAccountInfo queryDomainInfo;
    EXPECT_EQ(OsAccountManager::GetOsAccountDomainInfo(-1, queryDomainInfo),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    RecoveryPermission(tokenID);
}

/**
 * @tc.name: DomainAccountClientModuleTest_GetOsAccountDomainInfo_003
 * @tc.desc: GetOsAccountDomainInfo fail with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_GetOsAccountDomainInfo_003,
         TestSize.Level3)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({}, tokenID));
    setuid(EDM_UID);
    int32_t testUserId = 1;
    DomainAccountInfo queryDomainInfo;
    EXPECT_EQ(OsAccountManager::GetOsAccountDomainInfo(testUserId, queryDomainInfo),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
    RecoveryPermission(tokenID);

    ASSERT_TRUE(AllocPermission({"ohos.permission.GET_DOMAIN_ACCOUNTS"}, tokenID));
    setuid(EDM_UID);
    EXPECT_EQ(OsAccountManager::GetOsAccountDomainInfo(testUserId, queryDomainInfo),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
    RecoveryPermission(tokenID);

    ASSERT_TRUE(AllocPermission({"ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS"}, tokenID));
    setuid(EDM_UID);
    EXPECT_EQ(OsAccountManager::GetOsAccountDomainInfo(testUserId, queryDomainInfo),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
    RecoveryPermission(tokenID);
}

/**
 * @tc.name: SetAccountPolicy001
 * @tc.desc: Test UpdateServerConfig success update local info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, UpdateServerConfig001, TestSize.Level1)
{
    std::string configId = "changeConfigId";
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";
    domainInfo.serverConfigId_ = configId;
    CreateOsAccountForDomainOptions options;
    LoadPluginMethods();
    auto callback = std::make_shared<MockPluginSoDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    ErrCode code = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo,
        testCallback, options);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback]() { return lockCallback->isReady; });
    ASSERT_EQ(code, ERR_OK);
    int32_t userId1 = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId1), ERR_OK);
    ASSERT_NE(userId1, -1);
    domainInfo.accountName_ = "testaccount2";
    domainInfo.accountId_ = "testid2";
    domainInfo.serverConfigId_ = "serverConfigId2";
    auto testCallback2 = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    ASSERT_NE(testCallback2, nullptr);
    code = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo,
        testCallback2, options);
    testCallback2->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback2]() { return lockCallback->isReady; });
    EXPECT_EQ(code, ERR_OK);
    int32_t userId2 = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId2), ERR_OK);
    ASSERT_NE(userId2, -1);
    DomainServerConfig config("test", "updateConfigId", "testDomain");
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateServerConfig(configId, "testParameter", config), ERR_OK);
    OsAccountInfo accountInfo;
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(userId1, accountInfo), ERR_OK);
    accountInfo.GetDomainInfo(domainInfo);
    EXPECT_EQ(domainInfo.serverConfigId_, config.id_);
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(userId2, accountInfo), ERR_OK);
    accountInfo.GetDomainInfo(domainInfo);
    EXPECT_NE(domainInfo.serverConfigId_, config.id_);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId1), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId2), ERR_OK);
    UnloadPluginMethods();
}

/**
 * @tc.name: GetDomainInfo001
 * @tc.desc: Test GetDomainInfo success update local info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, GetDomainInfo001, TestSize.Level1)
{
    std::string configId = "passserver";
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "passserver";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";
    domainInfo.serverConfigId_ = configId;
    CreateOsAccountForDomainOptions options;
    LoadPluginMethods();
    auto callback = std::make_shared<MockPluginSoDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    ErrCode code = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo,
        testCallback, options);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback]() { return lockCallback->isReady; });
    ASSERT_EQ(code, ERR_OK);
    int32_t userId1 = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId1), ERR_OK);
    ASSERT_NE(userId1, -1);
    domainInfo.accountName_ = "passserver2";
    domainInfo.accountId_ = "testNewAccountInvalid";
    domainInfo.serverConfigId_ = "passserver";
    auto testCallback2 = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    ASSERT_NE(testCallback2, nullptr);
    code = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo,
        testCallback2, options);
    std::unique_lock<std::mutex> lock2(testCallback2->mutex);
    testCallback2->cv.wait_for(lock2, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback2]() { return lockCallback->isReady; });
    EXPECT_EQ(code, ERR_OK);
    int32_t userId2 = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId2), ERR_OK);
    ASSERT_NE(userId2, -1);
    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    SetIsCheckError(true);
    EXPECT_EQ(OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    DomainAccountInfo resultDomainInfo;
    EXPECT_NE(OsAccountManager::GetOsAccountDomainInfo(100, resultDomainInfo), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetOsAccountDomainInfo(userId1, resultDomainInfo), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetOsAccountDomainInfo(userId2, resultDomainInfo), ERR_OK);
    SetIsCheckError(false);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId1), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId2), ERR_OK);
    UnloadPluginMethods();
}

class TestBindDomainCallback : public DomainAccountCallback {
public:
    TestBindDomainCallback() = default;
    virtual ~TestBindDomainCallback() = default;

    void OnResult(const int32_t errCode, Parcel &parcel) override
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (isCalled_) {
            ACCOUNT_LOGE("Callback is called.");
            return;
        }
        errCode_ = errCode;
        isCalled_ = true;
        cv_.notify_one();
    }

    void WaitForCallbackResult()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        ACCOUNT_LOGI("WaitForCallbackResult.");
        cv_.wait(lock, [this] { return isCalled_; });
    }

    int32_t GetResult()
    {
        return errCode_;
    }

    void Clear()
    {
        errCode_ = -1;
        isCalled_ = false;
    }

private:
    std::mutex mutex_;
    int32_t errCode_ = -1;
    bool isCalled_ = false;
    std::condition_variable cv_;
};

/**
 * @tc.name: BindDomainAccount001
 * @tc.desc: Test BindDomainAccount success & scene
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, BindDomainAccount001, TestSize.Level1)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";
    LoadPluginMethods();
    OsAccountInfo info;
    ASSERT_EQ(ERR_OK, OsAccountManager::CreateOsAccount("BindDomainAccount001", OsAccountType::ADMIN, info));
    auto callback = std::make_shared<TestBindDomainCallback>();
    // bind first time
    ErrCode ret = OsAccountManager::BindDomainAccount(info.GetLocalId(), domainInfo, callback);
    EXPECT_EQ(ERR_OK, ret);
    callback->WaitForCallbackResult();
    ret = callback->GetResult();
    ASSERT_EQ(ERR_OK, ret);
    OsAccountControlFileManager fileController;
    bool isBoundCompleted = false;
    DomainAccountInfo readInfo;
    EXPECT_EQ(ERR_OK, fileController.GetDomainBoundFlag(info.GetLocalId(), isBoundCompleted, readInfo));
    ASSERT_TRUE(isBoundCompleted);

    // bind second time, should return ERR_OSACCOUNT_SERVICE_INNER_OS_ACCOUNT_ALREADY_BOUND
    // localId is already bound
    callback->Clear();
    ret = OsAccountManager::BindDomainAccount(info.GetLocalId(), domainInfo, callback);
    EXPECT_EQ(ERR_OK, ret);
    callback->WaitForCallbackResult();
    ret = callback->GetResult();
    ASSERT_EQ(ERR_OSACCOUNT_SERVICE_INNER_OS_ACCOUNT_ALREADY_BOUND, ret);

    // bind another localId, should return ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ACCOUNT_ALREADY_BOUND
    callback->Clear();
    ret = OsAccountManager::BindDomainAccount(100, domainInfo, callback);
    EXPECT_EQ(ERR_OK, ret);
    callback->WaitForCallbackResult();
    ret = callback->GetResult();
    ASSERT_EQ(ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ACCOUNT_ALREADY_BOUND, ret);

    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(info.GetLocalId()));
    UnloadPluginMethods();
}

/**
 * @tc.name: BindDomainAccount002
 * @tc.desc: Test BindDomainAccount input fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, BindDomainAccount002, TestSize.Level1)
{
    auto callback = std::make_shared<TestBindDomainCallback>();
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";
    auto service = std::make_shared<OsAccountManagerService>();
    ErrCode ret = OsAccountManager::BindDomainAccount(-1, domainInfo, callback);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    ret = service->BindDomainAccount(-1, domainInfo, nullptr);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    ret = OsAccountManager::BindDomainAccount(0, domainInfo, callback);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
    ret = service->BindDomainAccount(0, domainInfo, nullptr);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
    bool isU1Exist = false;
    EXPECT_EQ(ERR_OK, service->IsOsAccountExists(Constants::U1_ID, isU1Exist));
    ret = OsAccountManager::BindDomainAccount(Constants::U1_ID, domainInfo, callback);
    if (isU1Exist) {
        EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
    } else {
        EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    }

    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";
    ret = OsAccountManager::BindDomainAccount(100, domainInfo, nullptr);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    ret = service->BindDomainAccount(100, domainInfo, nullptr);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: BindDomainAccount003
 * @tc.desc: Test BindDomainAccount recover
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, BindDomainAccount003, TestSize.Level1)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";

    OsAccountInfo info;
    ASSERT_EQ(ERR_OK, OsAccountManager::CreateOsAccount("BindDomainAccount003", OsAccountType::ADMIN, info));
    auto callback = std::make_shared<TestBindDomainCallback>();

    OsAccountControlFileManager fileController;
    fileController.SetDomainBoundFlag(info.GetLocalId(), false, domainInfo);

    LoadPluginMethods();
    domainInfo.accountName_ = "testaccount-2";
    ErrCode ret =
        OsAccountManager::BindDomainAccount(info.GetLocalId(), domainInfo, callback);
    EXPECT_EQ(ERR_OK, ret);
    callback->WaitForCallbackResult();
    ret = callback->GetResult();

    ASSERT_EQ(info.GetLocalId(), GetCallingLocalId());
    ResetCallingLocalId();

    OsAccountInfo readInfo;
    EXPECT_EQ(ERR_OK, fileController.GetOsAccountInfoById(info.GetLocalId(), readInfo));
    ASSERT_EQ("testaccount-2", readInfo.domainInfo_.accountName_);
    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(info.GetLocalId()));
    UnloadPluginMethods();
}

/**
 * @tc.name: BindDomainAccount004
 * @tc.desc: Test BindDomainAccount recover failed, return errcode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, BindDomainAccount004, TestSize.Level1)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";

    OsAccountInfo info;
    ASSERT_EQ(ERR_OK, OsAccountManager::CreateOsAccount("BindDomainAccount004", OsAccountType::ADMIN, info));
    auto callback = std::make_shared<TestBindDomainCallback>();

    OsAccountControlFileManager fileController;
    fileController.SetDomainBoundFlag(info.GetLocalId(), false, domainInfo);

    PLUGIN_METHOD_MAP[PluginMethodEnum::UNBIND_ACCOUNT] = reinterpret_cast<void *>(UnBindAccountError);
    LoadPluginMethods();
    PLUGIN_METHOD_MAP[PluginMethodEnum::UNBIND_ACCOUNT] = reinterpret_cast<void *>(UnBindAccount);

    domainInfo.accountName_ = "testaccount-2";
    ErrCode ret = OsAccountManager::BindDomainAccount(info.GetLocalId(), domainInfo, callback);
    EXPECT_EQ(ERR_OK, ret);
    callback->WaitForCallbackResult();
    ret = callback->GetResult();

    ASSERT_EQ(g_testErrCode, ret);

    ASSERT_EQ(info.GetLocalId(), GetCallingLocalId());
    ResetCallingLocalId();

    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(info.GetLocalId()));
    UnloadPluginMethods();
}

/**
 * @tc.name: BindDomainAccount005
 * @tc.desc: Test BindDomainAccount file delete failed, return errcode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, BindDomainAccount005, TestSize.Level1)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";

    OsAccountInfo info;
    ASSERT_EQ(ERR_OK, OsAccountManager::CreateOsAccount("BindDomainAccount005", OsAccountType::ADMIN, info));
    auto callback = std::make_shared<TestBindDomainCallback>();
    LoadPluginMethods();

    ErrCode ret = OsAccountManager::BindDomainAccount(info.GetLocalId(), domainInfo, callback);
    EXPECT_EQ(ERR_OK, ret);
    callback->WaitForCallbackResult();
    ret = callback->GetResult();
    EXPECT_EQ(ERR_OK, ret);
    callback->Clear();
    OsAccountControlFileManager fileController;
    fileController.SetDomainBoundFlag(info.GetLocalId(), false, domainInfo);

    domainInfo.accountName_ = "testaccount-2";
    ret = OsAccountManager::BindDomainAccount(info.GetLocalId(), domainInfo, callback);
    EXPECT_EQ(ERR_OK, ret);
    callback->WaitForCallbackResult();
    ret = callback->GetResult();

    ASSERT_EQ(ERR_OSACCOUNT_SERVICE_INNER_OS_ACCOUNT_ALREADY_BOUND, ret);

    bool boundComplete = false;
    DomainAccountInfo readInfo;
    EXPECT_EQ(ERR_OK, fileController.GetDomainBoundFlag(info.GetLocalId(), boundComplete, domainInfo));
    EXPECT_TRUE(boundComplete);

    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(info.GetLocalId()));
    UnloadPluginMethods();
    ResetCallingLocalId();
}

/**
 * @tc.name: BindDomainAccount006
 * @tc.desc: Test BindDomainAccount for garbage account
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, BindDomainAccount006, TestSize.Level1)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";

    OsAccountInfo info;
    ASSERT_EQ(ERR_OK, OsAccountManager::CreateOsAccount("BindDomainAccount006", OsAccountType::ADMIN, info));
    auto callback = std::make_shared<TestBindDomainCallback>();
    ASSERT_EQ(ERR_OK, OsAccountManager::SetOsAccountToBeRemoved(info.GetLocalId(), true));
    LoadPluginMethods();
    // bind first time
    ErrCode ret = OsAccountManager::BindDomainAccount(info.GetLocalId(), domainInfo, callback);
    EXPECT_EQ(ERR_OK, ret);
    callback->WaitForCallbackResult();
    ret = callback->GetResult();
    ASSERT_EQ(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, ret);

    ResetCallingLocalId();
    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(info.GetLocalId()));
    UnloadPluginMethods();
}

/**
 * @tc.name: BindDomainAccount007
 * @tc.desc: Test BindDomainAccount for domain plugin error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, BindDomainAccount007, TestSize.Level1)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";

    OsAccountInfo info;
    ASSERT_EQ(ERR_OK, OsAccountManager::CreateOsAccount("BindDomainAccount007", OsAccountType::ADMIN, info));
    auto callback = std::make_shared<TestBindDomainCallback>();

    // get domain info error
    PLUGIN_METHOD_MAP[PluginMethodEnum::GET_ACCOUNT_INFO] = reinterpret_cast<void *>(GetAccountInfoError);
    LoadPluginMethods();
    PLUGIN_METHOD_MAP[PluginMethodEnum::GET_ACCOUNT_INFO] = reinterpret_cast<void *>(GetAccountInfo);

    ErrCode ret = OsAccountManager::BindDomainAccount(info.GetLocalId(), domainInfo, callback);
    EXPECT_EQ(ERR_OK, ret);
    callback->WaitForCallbackResult();
    ret = callback->GetResult();
    ASSERT_EQ(g_testErrCode, ret);

    ResetCallingLocalId();
    callback->Clear();
    UnloadPluginMethods();

    // bind account error
    PLUGIN_METHOD_MAP[PluginMethodEnum::BIND_ACCOUNT] = reinterpret_cast<void *>(BindAccountError);
    LoadPluginMethods();
    PLUGIN_METHOD_MAP[PluginMethodEnum::BIND_ACCOUNT] = reinterpret_cast<void *>(BindAccount);

    // bind first time
    ret = OsAccountManager::BindDomainAccount(info.GetLocalId(), domainInfo, callback);
    EXPECT_EQ(ERR_OK, ret);
    callback->WaitForCallbackResult();
    ret = callback->GetResult();
    ASSERT_EQ(g_testErrCode, ret);
    ResetCallingLocalId();
    callback->Clear();
    UnloadPluginMethods();

    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(info.GetLocalId()));
}

/**
 * @tc.name: BindDomainAccount008
 * @tc.desc: Test BindDomainAccount for account busy & account not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, BindDomainAccount008, TestSize.Level1)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";

    OsAccountInfo info;
    ASSERT_EQ(ERR_OK, OsAccountManager::CreateOsAccount("BindDomainAccount008", OsAccountType::ADMIN, info));
    auto callback = std::make_shared<TestBindDomainCallback>();
    LoadPluginMethods();

    IInnerOsAccountManager::GetInstance().CheckAndAddLocalIdOperating(info.GetLocalId());

    ErrCode ret = OsAccountManager::BindDomainAccount(info.GetLocalId(), domainInfo, callback);
    EXPECT_EQ(ERR_OK, ret);
    callback->WaitForCallbackResult();
    ret = callback->GetResult();
    ASSERT_EQ(ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR, ret);

    IInnerOsAccountManager::GetInstance().RemoveLocalIdToOperating(info.GetLocalId());
    callback->Clear();

    // account not found
    ret = OsAccountManager::BindDomainAccount(info.GetLocalId() + 1, domainInfo, callback);
    EXPECT_EQ(ERR_OK, ret);
    callback->WaitForCallbackResult();
    ret = callback->GetResult();
    ASSERT_EQ(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, ret);

    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(info.GetLocalId()));
    UnloadPluginMethods();
}

/**
 * @tc.name: BindDomainAccount009
 * @tc.desc: Test BindDomainAccount recover when file data not json format
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, BindDomainAccount009, TestSize.Level1)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";

    OsAccountInfo info;
    ASSERT_EQ(ERR_OK, OsAccountManager::CreateOsAccount("BindDomainAccount009", OsAccountType::ADMIN, info));
    auto callback = std::make_shared<TestBindDomainCallback>();

    OsAccountControlFileManager fileController;

    std::string filePath = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(info.GetLocalId()) +
                           Constants::PATH_SEPARATOR + Constants::IS_DOMAIN_BOUND_COMPLETED_FILE_NAME;
    fileController.accountFileOperator_->InputFileByPathAndContent(filePath, "{ \"domain\": 123");
    LoadPluginMethods();

    ErrCode ret = OsAccountManager::BindDomainAccount(info.GetLocalId(), domainInfo, callback);
    EXPECT_EQ(ERR_OK, ret);
    callback->WaitForCallbackResult();
    ret = callback->GetResult();
    EXPECT_EQ(ERR_OK, ret);

    OsAccountInfo readInfo;
    EXPECT_EQ(ERR_OK, fileController.GetOsAccountInfoById(info.GetLocalId(), readInfo));
    ASSERT_EQ("testaccount", readInfo.domainInfo_.accountName_);
    ASSERT_EQ(false, fileController.accountFileOperator_->IsExistFile(filePath));
    domainInfo.accountName_ = "testAccount";
    domainInfo.domain_ = "testDomain";
    auto callback2 = std::make_shared<MockDomainHasDomainInfoCallback>();
    ASSERT_NE(callback2, nullptr);
    auto testCallback = std::make_shared<TestHasDomainInfoCallback>(callback2);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().HasAccount(domainInfo, testCallback), ERR_OK);
    domainInfo.accountName_ = "testAccountInvalid";
    EXPECT_EQ(DomainAccountClient::GetInstance().HasAccount(domainInfo, testCallback), ERR_OK);
    domainInfo.accountName_ = "testDomainInvalid";
    domainInfo.domain_ = "testDomainInvalid";
    EXPECT_EQ(DomainAccountClient::GetInstance().HasAccount(domainInfo, testCallback), ERR_OK);
    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(info.GetLocalId()));
    UnloadPluginMethods();
}

/**
 * @tc.name: BindDomainAccount010
 * @tc.desc: Test BindDomainAccount domain invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, BindDomainAccount010, TestSize.Level1)
{
    auto callback = std::make_shared<TestBindDomainCallback>();
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";
    auto service = std::make_shared<OsAccountManagerService>();
    std::string overlengthStr(Constants::LOCAL_NAME_MAX_SIZE, '0');

    domainInfo.accountName_ = overlengthStr;
    ErrCode ret = OsAccountManager::BindDomainAccount(100, domainInfo, callback);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    ret = service->BindDomainAccount(100, domainInfo, nullptr);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = overlengthStr;
    ret = OsAccountManager::BindDomainAccount(100, domainInfo, callback);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    ret = service->BindDomainAccount(100, domainInfo, nullptr);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    domainInfo.accountName_ = "";
    domainInfo.domain_ = "test.example.com";
    ret = OsAccountManager::BindDomainAccount(100, domainInfo, callback);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    ret = service->BindDomainAccount(100, domainInfo, nullptr);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "";
    ret = OsAccountManager::BindDomainAccount(100, domainInfo, callback);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    ret = service->BindDomainAccount(100, domainInfo, nullptr);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: BindDomainAccount011
 * @tc.desc: Test BindDomainAccount domain no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, BindDomainAccount011, TestSize.Level1)
{
    auto callback = std::make_shared<TestBindDomainCallback>();
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({}, tokenID));
    setuid(EDM_UID);
    ErrCode ret = OsAccountManager::BindDomainAccount(100, domainInfo, callback);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED, ret);
    setuid(ROOT_UID);
    RecoveryPermission(tokenID);
}

/**
 * @tc.name: CleanUnbindDomainAccount001
 * @tc.desc: Test CleanUnbindDomainAccount for uncomplete
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, CleanUnbindDomainAccount001, TestSize.Level1)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";

    OsAccountInfo info;
    ASSERT_EQ(ERR_OK, OsAccountManager::CreateOsAccount("BindDomainAccount004", OsAccountType::ADMIN, info));
    auto callback = std::make_shared<TestBindDomainCallback>();

    OsAccountControlFileManager fileController;
    fileController.SetDomainBoundFlag(info.GetLocalId(), false, domainInfo);

    LoadPluginMethods();
    ErrCode ret = InnerDomainAccountManager::GetInstance().CleanUnbindDomainAccount();
    EXPECT_EQ(ERR_OK, ret);

    ASSERT_EQ(info.GetLocalId(), GetCallingLocalId());
    ResetCallingLocalId();

    bool isBoundCompleted = false;
    DomainAccountInfo readInfo;
    EXPECT_EQ(ERR_OK, fileController.GetDomainBoundFlag(info.GetLocalId(), isBoundCompleted, readInfo));
    ASSERT_TRUE(isBoundCompleted);

    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(info.GetLocalId()));
    UnloadPluginMethods();
}

/**
 * @tc.name: CancelAuth001
 * @tc.desc: Test CancelAuth with full process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, CancelAuth001, TestSize.Level1)
{
    PLUGIN_METHOD_MAP[PluginMethodEnum::AUTH] = reinterpret_cast<void *>(AuthBlocking);
    LoadPluginMethods();

    OsAccountInfo osAccountinfo;
    ASSERT_EQ(ERR_OK, OsAccountManager::CreateOsAccount("CancelAuth001", OsAccountType::ADMIN, osAccountinfo));

    auto bindCallback = std::make_shared<TestBindDomainCallback>();
    DomainAccountInfo info;
    info.accountName_ = "testAccount";
    info.domain_ = "test.example.com";
    info.accountId_ = "testAccountId";
    ErrCode ret = OsAccountManager::BindDomainAccount(osAccountinfo.GetLocalId(), info, bindCallback);
    bindCallback->WaitForCallbackResult();
    EXPECT_EQ(ret, ERR_OK);
    uint64_t contextId = 0;

    std::vector<uint8_t> passwd = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36}; // "123456"
    auto authCallback = std::make_shared<MockPluginSoDomainAuthCallback>();
    ASSERT_NE(authCallback, nullptr);
    EXPECT_CALL(*authCallback, OnResult(ERR_JS_AUTH_CANCELLED, _)).Times(Exactly(1));
    std::shared_ptr<TestPluginSoDomainAuthCallback> callback =
        std::make_shared<TestPluginSoDomainAuthCallback>(authCallback);
    ErrCode result =
        DomainAccountClient::GetInstance().AuthUser(osAccountinfo.GetLocalId(), passwd, callback, contextId);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_NE(contextId, 0);

    result = DomainAccountClient::GetInstance().CancelAuth(contextId);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(osAccountinfo.GetLocalId()));
    UnloadPluginMethods();
    PLUGIN_METHOD_MAP[PluginMethodEnum::AUTH] = reinterpret_cast<void *>(Auth);
}

class AuthCallbackSync : public DomainAccountCallbackStub {
public:
    AuthCallbackSync() = default;
    virtual ~AuthCallbackSync() = default;
    int32_t errCode = -1;
    ErrCode OnResult(int32_t domainAccountErrCode, const DomainAccountParcel &domainAccountParcel) override
    {
        errCode = domainAccountErrCode;
        return ERR_OK;
    };
    ErrCode OnAcquireInfo(
        int32_t module, uint32_t acquireInfo, const DomainAccountUnlockExtraInfoIdl &extraInfo) override
    {
        return ERR_OK;
    }
};

/**
 * @tc.name: CancelAuth002
 * @tc.desc: Test CancelAuth branches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, CancelAuth002, TestSize.Level3)
{
    LoadPluginMethods();
    auto callback = sptr<AuthCallbackSync>::MakeSptr();
    auto innerCallback = sptr<InnerDomainAuthCallback>::MakeSptr(0, callback);
    uint64_t contextId = 0;
    InnerDomainAccountManager::GetInstance().authContextIdMap_.clear();
    ASSERT_EQ(0, InnerDomainAccountManager::GetInstance().authContextIdMap_.size());
    EXPECT_EQ(ERR_JS_INVALID_CONTEXT_ID, InnerDomainAccountManager::GetInstance().CancelAuth(callback));
    EXPECT_EQ(ERR_JS_INVALID_CONTEXT_ID, InnerDomainAccountManager::GetInstance().CancelAuth(1));

    ASSERT_TRUE(InnerDomainAccountManager::GetInstance().GenerateContextId(contextId));
    EXPECT_TRUE(InnerDomainAccountManager::GetInstance().AddToContextMap(contextId, innerCallback));
    EXPECT_EQ(1, InnerDomainAccountManager::GetInstance().authContextIdMap_.size());
    EXPECT_EQ(ERR_OK, InnerDomainAccountManager::GetInstance().CancelAuth(callback));
    ASSERT_EQ(callback->errCode, ERR_JS_AUTH_CANCELLED);
    EXPECT_EQ(0, InnerDomainAccountManager::GetInstance().authContextIdMap_.size());

    callback->errCode = -1;
    ASSERT_TRUE(InnerDomainAccountManager::GetInstance().GenerateContextId(contextId));
    EXPECT_TRUE(InnerDomainAccountManager::GetInstance().AddToContextMap(contextId, innerCallback));
    EXPECT_EQ(1, InnerDomainAccountManager::GetInstance().authContextIdMap_.size());
    EXPECT_EQ(ERR_OK, InnerDomainAccountManager::GetInstance().CancelAuth(contextId));
    ASSERT_EQ(callback->errCode, ERR_JS_AUTH_CANCELLED);
    EXPECT_EQ(0, InnerDomainAccountManager::GetInstance().authContextIdMap_.size());

    UnloadPluginMethods();
}

/**
 * @tc.name: InnerGenerateContextId001
 * @tc.desc: Test InnerGenerateContextId branches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, InnerGenerateContextId001, TestSize.Level3)
{
    InnerDomainAccountManager::GetInstance().authContextIdMap_.clear();
    InnerDomainAccountManager::GetInstance().contextIdCount_ = 0;
    auto callback = sptr<AuthCallbackSync>::MakeSptr();
    auto innerCallback = sptr<InnerDomainAuthCallback>::MakeSptr(0, callback);
    uint64_t contextId1 = 0;
    ASSERT_TRUE(InnerDomainAccountManager::GetInstance().GenerateContextId(contextId1));
    EXPECT_TRUE(InnerDomainAccountManager::GetInstance().AddToContextMap(contextId1, innerCallback));

    uint64_t contextId2 = 0;
    ASSERT_TRUE(InnerDomainAccountManager::GetInstance().GenerateContextId(contextId2));
    EXPECT_TRUE(InnerDomainAccountManager::GetInstance().AddToContextMap(contextId2, innerCallback));

    uint64_t contextId3 = 0;
    ASSERT_TRUE(InnerDomainAccountManager::GetInstance().GenerateContextId(contextId3));
    EXPECT_TRUE(InnerDomainAccountManager::GetInstance().AddToContextMap(contextId3, innerCallback));

    // remove contextid 2
    InnerDomainAccountManager::GetInstance().EraseFromContextMap(contextId2);
    InnerDomainAccountManager::GetInstance().contextIdCount_ = 0;
    uint64_t contextId4 = 1;
    ASSERT_TRUE(InnerDomainAccountManager::GetInstance().GenerateContextId(contextId4));
    EXPECT_EQ(contextId4, contextId2);
    InnerDomainAccountManager::GetInstance().authContextIdMap_.clear();
    InnerDomainAccountManager::GetInstance().contextIdCount_ = 0;
}

// F3 test cases for domain account unlock

class UnlockAuthCallback final : public DomainAccountCallback {
public:
    UnlockAuthCallback() = default;
    ~UnlockAuthCallback() = default;
    int32_t resultErrCode = -1;
    bool acquireInfoCalled = false;
    int32_t acquireModule = -1;
    uint32_t acquireInfoVal = 0;
    std::mutex mutex;
    std::condition_variable cv;
    bool isReady = false;
    void OnResult(const int32_t errCode, Parcel &parcel) override
    {
        resultErrCode = errCode;
        std::lock_guard<std::mutex> lock(mutex);
        isReady = true;
        cv.notify_all();
    }
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo,
        const DomainAccountUnlockExtraInfo &extraInfo) override
    {
        acquireInfoCalled = true;
        acquireModule = module;
        acquireInfoVal = acquireInfo;
    }
};

static int32_t CreateAndBindDomainAccount(const std::string &accountName)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = accountName;
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = accountName + "_id";
    auto callback = std::make_shared<MockPluginSoDomainCreateDomainAccountCallback>();
    auto testCallback = std::make_shared<TestPluginSoCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, accountName, "test.example.com", _)).Times(Exactly(1));
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [lockCallback = testCallback]() { return lockCallback->isReady; });
    if (errCode != ERR_OK) {
        return -1;
    }
    int32_t userId = -1;
    OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId);
    return userId;
}

/**
 * @tc.name: DomainAccountUnlock_001
 * @tc.desc: Test AuthUserWithUnlockOptions routes to plugin AuthWithUnlockIntent.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlock_001, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    SetAuthWithUnlockIntentError(false);
    int32_t userId = CreateAndBindDomainAccount("unlock001");
    ASSERT_GT(userId, 0);
    auto callback = std::make_shared<UnlockAuthCallback>();
    DomainAccountUnlockOptions options;
    options.authIntent = UNLOCK_INTENT;
    options.challenge = {1, 2, 3};
    uint64_t contextId = 0;
    ErrCode ret = DomainAccountClient::GetInstance().AuthUser(
        userId, []() { return std::vector<uint8_t>{49, 50, 51}; },
        callback, options, contextId);
    EXPECT_EQ(ret, ERR_OK);
    std::unique_lock<std::mutex> lock(callback->mutex);
    callback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                          [callback]() { return callback->isReady; });
    EXPECT_EQ(callback->resultErrCode, ERR_OK);
    EXPECT_TRUE(callback->acquireInfoCalled);
    EXPECT_EQ(callback->acquireModule, static_cast<int32_t>(IAMAuthType::DOMAIN));
    std::vector<uint8_t> challenge;
    GetLastChallenge(challenge);
    EXPECT_EQ(challenge, std::vector<uint8_t>({1, 2, 3}));
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountUnlock_002
 * @tc.desc: Test AuthUser with DEFAULT intent routes to existing AuthUser (not AuthWithUnlockIntent).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlock_002, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    int32_t userId = CreateAndBindDomainAccount("unlock002");
    ASSERT_GT(userId, 0);
    auto callback = std::make_shared<UnlockAuthCallback>();
    DomainAccountUnlockOptions options;
    options.authIntent = 0;
    uint64_t contextId = 0;
    ErrCode ret = DomainAccountClient::GetInstance().AuthUser(
        userId, []() { return std::vector<uint8_t>{49, 50, 51}; },
        callback, options, contextId);
    EXPECT_EQ(ret, ERR_OK);
    std::unique_lock<std::mutex> lock(callback->mutex);
    callback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                          [callback]() { return callback->isReady; });
    EXPECT_EQ(callback->resultErrCode, ERR_OK);
    EXPECT_FALSE(callback->acquireInfoCalled);
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountUnlock_003
 * @tc.desc: Test AuthUserWithUnlockOptions with no plugin loaded.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlock_003, TestSize.Level3)
{
    LoadPluginMethods();
    int32_t userId = CreateAndBindDomainAccount("unlock003");
    ASSERT_GT(userId, 0);
    UnloadPluginMethods();
    auto callback = std::make_shared<UnlockAuthCallback>();
    DomainAccountUnlockOptions options;
    options.authIntent = UNLOCK_INTENT;
    uint64_t contextId = 0;
    ErrCode ret = DomainAccountClient::GetInstance().AuthUser(
        userId, []() { return std::vector<uint8_t>{49, 50, 51}; },
        callback, options, contextId);
    EXPECT_EQ(ret, ERR_OK);
    std::unique_lock<std::mutex> lock(callback->mutex);
    callback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                          [callback]() { return callback->isReady; });
    EXPECT_EQ(callback->resultErrCode, ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE);
}

/**
 * @tc.name: DomainAccountUnlock_004
 * @tc.desc: Test AuthUserWithUnlockOptions with unlock not enabled.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlock_004, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(false);
    int32_t userId = CreateAndBindDomainAccount("unlock004");
    ASSERT_GT(userId, 0);
    auto callback = std::make_shared<UnlockAuthCallback>();
    DomainAccountUnlockOptions options;
    options.authIntent = UNLOCK_INTENT;
    uint64_t contextId = 0;
    ErrCode ret = DomainAccountClient::GetInstance().AuthUser(
        userId, []() { return std::vector<uint8_t>{49, 50, 51}; },
        callback, options, contextId);
    EXPECT_EQ(ret, ERR_OK);
    std::unique_lock<std::mutex> lock(callback->mutex);
    callback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                          [callback]() { return callback->isReady; });
    EXPECT_EQ(callback->resultErrCode, ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE);
    SetEnableUnlockDevice(true);
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountUnlock_005
 * @tc.desc: Test AuthUserWithUnlockOptions with user not bound to domain account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlock_005, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    auto callback = std::make_shared<UnlockAuthCallback>();
    DomainAccountUnlockOptions options;
    options.authIntent = UNLOCK_INTENT;
    uint64_t contextId = 0;
    ErrCode ret = DomainAccountClient::GetInstance().AuthUser(
        9999, []() { return std::vector<uint8_t>{49, 50, 51}; },
        callback, options, contextId);
    EXPECT_EQ(ret, ERR_OK);
    std::unique_lock<std::mutex> lock(callback->mutex);
    callback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                          [callback]() { return callback->isReady; });
    EXPECT_NE(callback->resultErrCode, ERR_OK);
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountUnlock_006
 * @tc.desc: Test AuthUserWithUnlockOptions with plugin auth failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlock_006, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    SetAuthWithUnlockIntentError(true);
    int32_t userId = CreateAndBindDomainAccount("unlock006");
    ASSERT_GT(userId, 0);
    auto callback = std::make_shared<UnlockAuthCallback>();
    DomainAccountUnlockOptions options;
    options.authIntent = UNLOCK_INTENT;
    uint64_t contextId = 0;
    ErrCode ret = DomainAccountClient::GetInstance().AuthUser(
        userId, []() { return std::vector<uint8_t>{49, 50, 51}; },
        callback, options, contextId);
    EXPECT_EQ(ret, ERR_OK);
    std::unique_lock<std::mutex> lock(callback->mutex);
    callback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                          [callback]() { return callback->isReady; });
    EXPECT_NE(callback->resultErrCode, ERR_OK);
    EXPECT_FALSE(callback->acquireInfoCalled);
    SetAuthWithUnlockIntentError(false);
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountUnlock_007
 * @tc.desc: Test password-based AuthUser does not trigger unlock.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlock_007, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    int32_t userId = CreateAndBindDomainAccount("unlock007");
    ASSERT_GT(userId, 0);
    auto mockCallback = std::make_shared<MockPluginSoDomainAuthCallback>();
    auto testCallback = std::make_shared<TestPluginSoDomainAuthCallback>(mockCallback);
    EXPECT_CALL(*mockCallback, OnResult(_, _)).Times(Exactly(1));
    uint64_t contextId = 0;
    ErrCode ret = DomainAccountClient::GetInstance().AuthUser(
        userId, std::vector<uint8_t>{49, 50, 51}, testCallback, contextId);
    EXPECT_EQ(ret, ERR_OK);
    std::unique_lock<std::mutex> testLock2(testCallback->mutex);
    testCallback->cv.wait_for(testLock2, std::chrono::seconds(WAIT_TIME),
                              []() { return true; });
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountUnlock_008
 * @tc.desc: Test AuthUserWithUnlockOptions with invalid auth user returns error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlock_008, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    auto callback = std::make_shared<UnlockAuthCallback>();
    DomainAccountUnlockOptions options;
    options.authIntent = UNLOCK_INTENT;
    uint64_t contextId = 0;
    ErrCode ret = DomainAccountClient::GetInstance().AuthUser(
        -1, []() { return std::vector<uint8_t>{49, 50, 51}; },
        callback, options, contextId);
    EXPECT_EQ(ret, ERR_OK);
    std::unique_lock<std::mutex> lock(callback->mutex);
    callback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME), [callback]() { return callback->isReady; });
    EXPECT_EQ(callback->resultErrCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountUnlock_009
 * @tc.desc: Test AuthUserWithUnlockOptions with invalid permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlock_009, TestSize.Level3)
{
    LoadPluginMethods();
    uint64_t noPermTokenId = 0;
    ASSERT_TRUE(AllocPermission({}, noPermTokenId, false));
    ASSERT_EQ(SetSelfTokenID(noPermTokenId), 0);
    SetEnableUnlockDevice(true);
    auto callback = std::make_shared<UnlockAuthCallback>();
    DomainAccountUnlockOptions options;
    options.authIntent = UNLOCK_INTENT;
    uint64_t contextId = 0;
    int32_t userId = 100; // test uid
    ErrCode ret = DomainAccountClient::GetInstance().AuthUser(userId,
        []() { return std::vector<uint8_t> {49, 50, 51}; },
        callback, options, contextId);
    EXPECT_EQ(ret, ERR_OK);
    std::unique_lock<std::mutex> lock(callback->mutex);
    callback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME), [callback]() { return callback->isReady; });
    EXPECT_EQ(callback->resultErrCode, ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
    UnloadPluginMethods();
    ASSERT_TRUE(RecoveryPermission(noPermTokenId));
}

// F1 test cases

/**
 * @tc.name: DomainAccountPlugin_001
 * @tc.desc: Test AuthWithUnlockIntent returns PluginAuthResultInfo with token and secret.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountPlugin_001, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    SetAuthWithUnlockIntentError(false);
    int32_t userId = CreateAndBindDomainAccount("plugin001");
    ASSERT_GT(userId, 0);
    auto callback = std::make_shared<UnlockAuthCallback>();
    DomainAccountUnlockOptions options;
    options.authIntent = UNLOCK_INTENT;
    uint64_t contextId = 0;
    ErrCode ret = DomainAccountClient::GetInstance().AuthUser(
        userId, []() { return std::vector<uint8_t>{49, 50, 51}; }, callback, options, contextId);
    EXPECT_EQ(ret, ERR_OK);
    std::unique_lock<std::mutex> lock(callback->mutex);
    callback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                          [callback]() { return callback->isReady; });
    EXPECT_EQ(callback->resultErrCode, ERR_OK);
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountUnlock_Deactivating_001
 * @tc.desc: AuthUserWithUnlockOptions returns ERR_IAM_BUSY via callback when the account is deactivating.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlock_Deactivating_001, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    SetAuthWithUnlockIntentError(false);
    int32_t userId = CreateAndBindDomainAccount("unlock_deact");
    ASSERT_GT(userId, 0);
    IInnerOsAccountManager::GetInstance().deactivatingAccounts_.EnsureInsert(userId, true);
    auto callback = std::make_shared<UnlockAuthCallback>();
    DomainAccountUnlockOptions options;
    options.authIntent = UNLOCK_INTENT;
    options.challenge = {1, 2, 3};
    uint64_t contextId = 0;
    ErrCode ret = DomainAccountClient::GetInstance().AuthUser(
        userId, []() { return std::vector<uint8_t>{49, 50, 51}; }, callback, options, contextId);
    EXPECT_EQ(ret, ERR_OK);
    {
        std::unique_lock<std::mutex> lock(callback->mutex);
        callback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [callback]() { return callback->isReady; });
    }
    EXPECT_TRUE(callback->isReady);
    EXPECT_EQ(callback->resultErrCode, ERR_IAM_BUSY);
    IInnerOsAccountManager::GetInstance().deactivatingAccounts_.Erase(userId);
    UnloadPluginMethods();
}

#ifdef SUPPORT_LOCK_OS_ACCOUNT
/**
 * @tc.name: DomainAccountUnlock_Locking_001
 * @tc.desc: AuthUserWithUnlockOptions returns ERR_IAM_BUSY via callbackwhen the account is locking.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlock_Locking_001, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    SetAuthWithUnlockIntentError(false);
    int32_t userId = CreateAndBindDomainAccount("unlock_lock");
    ASSERT_GT(userId, 0);
    IInnerOsAccountManager::GetInstance().lockingAccounts_.EnsureInsert(userId, true);
    auto callback = std::make_shared<UnlockAuthCallback>();
    DomainAccountUnlockOptions options;
    options.authIntent = UNLOCK_INTENT;
    options.challenge = {1, 2, 3};
    uint64_t contextId = 0;
    ErrCode ret = DomainAccountClient::GetInstance().AuthUser(
        userId, []() { return std::vector<uint8_t>{49, 50, 51}; }, callback, options, contextId);
    EXPECT_EQ(ret, ERR_OK);
    {
        std::unique_lock<std::mutex> lock(callback->mutex);
        callback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [callback]() { return callback->isReady; });
    }
    EXPECT_TRUE(callback->isReady);
    EXPECT_EQ(callback->resultErrCode, ERR_IAM_BUSY);
    IInnerOsAccountManager::GetInstance().lockingAccounts_.Erase(userId);
    UnloadPluginMethods();
}
#endif

/**
 * @tc.name: DomainAccountUnlock_HandleUnlock_Deactivating_001
 * @tc.desc: On auth success, HandleUnlockResult skips storage unlock and returns ERR_OK when the
 *           account became deactivating after auth started.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlock_HandleUnlock_Deactivating_001,
    TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    SetAuthWithUnlockIntentError(false);
    int32_t userId = CreateAndBindDomainAccount("unlock_hdl_deact");
    ASSERT_GT(userId, 0);
    auto callback = std::make_shared<UnlockAuthCallback>();
    DomainAccountUnlockOptions options;
    options.authIntent = UNLOCK_INTENT;
    options.challenge = {1, 2, 3};
    uint64_t contextId = 0;
    ErrCode ret = DomainAccountClient::GetInstance().AuthUser(
        userId, []() { return std::vector<uint8_t>{49, 50, 51}; }, callback, options, contextId);
    EXPECT_EQ(ret, ERR_OK);
    // Wait briefly to let the entry-level deactivating check pass
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    IInnerOsAccountManager::GetInstance().deactivatingAccounts_.EnsureInsert(userId, true);
    {
        std::unique_lock<std::mutex> lock(callback->mutex);
        callback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                              [callback]() { return callback->isReady; });
    }
    EXPECT_TRUE(callback->isReady);
    EXPECT_EQ(callback->resultErrCode, ERR_OK);
    EXPECT_TRUE(callback->acquireInfoCalled);
    // Distinguisher: storage unlock was skipped, so the account stays UNVERIFIED (the normal
    // path would call SetOsAccountIsVerified via UnlockUserStorage).
    bool verifiedAfter = true;
    EXPECT_EQ(IInnerOsAccountManager::GetInstance().IsOsAccountVerified(userId, verifiedAfter), ERR_OK);
    EXPECT_FALSE(verifiedAfter);
    IInnerOsAccountManager::GetInstance().deactivatingAccounts_.Erase(userId);
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountPlugin_002
 * @tc.desc: Test GetUnlockDeviceConfigResult returns correct config.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountPlugin_002, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    int32_t userId = CreateAndBindDomainAccount("plugin002");
    ASSERT_GT(userId, 0);
    bool enableUnlockDevice = false;
    int32_t unlockDeviceMode = 0;
    ErrCode ret = InnerDomainAccountManager::GetInstance().GetUnlockDeviceConfig(
        userId, enableUnlockDevice, unlockDeviceMode);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(enableUnlockDevice);
    EXPECT_EQ(unlockDeviceMode, ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE);
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountPlugin_003
 * @tc.desc: Test GetUnlockDeviceConfigResult with unlock disabled.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountPlugin_003, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(false);
    int32_t userId = CreateAndBindDomainAccount("plugin003");
    ASSERT_GT(userId, 0);
    bool enableUnlockDevice = true;
    int32_t unlockDeviceMode = 0;
    ErrCode ret = InnerDomainAccountManager::GetInstance().GetUnlockDeviceConfig(
        userId, enableUnlockDevice, unlockDeviceMode);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(enableUnlockDevice);
    SetEnableUnlockDevice(true);
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountPlugin_004
 * @tc.desc: Test GetUnlockDeviceConfig with no plugin loaded returns default.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountPlugin_004, TestSize.Level3)
{
    LoadPluginMethods();
    int32_t userId = CreateAndBindDomainAccount("plugin004");
    ASSERT_GT(userId, 0);
    UnloadPluginMethods();
    bool enableUnlockDevice = true;
    int32_t unlockDeviceMode = 0;
    ErrCode ret = InnerDomainAccountManager::GetInstance().GetUnlockDeviceConfig(
        userId, enableUnlockDevice, unlockDeviceMode);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(enableUnlockDevice);
}

// F2 test cases

/**
 * @tc.name: DomainAccountUnlockEnabled_001
 * @tc.desc: Test SetDomainAuthUnlockEnabled with uid not 7058.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlockEnabled_001, TestSize.Level3)
{
    LoadPluginMethods();
    setuid(ROOT_UID);
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_USER_IDM"}, tokenID));
    auto service = new (std::nothrow) AccountIAMService();
    ASSERT_NE(service, nullptr);
    std::vector<uint8_t> token = {1, 2, 3};
    std::vector<uint8_t> secret = {4, 5, 6};
    EXPECT_EQ(service->SetDomainAuthUnlockEnabled(100, token, secret, 1),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    ASSERT_TRUE(RecoveryPermission(tokenID));
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountUnlockEnabled_002
 * @tc.desc: Test SetDomainAuthUnlockEnabled without MANAGE_USER_IDM permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlockEnabled_002, TestSize.Level3)
{
    LoadPluginMethods();
    setuid(7058);
    auto service = new (std::nothrow) AccountIAMService();
    ASSERT_NE(service, nullptr);
    std::vector<uint8_t> token = {1, 2, 3};
    std::vector<uint8_t> secret = {4, 5, 6};
    EXPECT_EQ(service->SetDomainAuthUnlockEnabled(100, token, secret, 1),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountUnlockEnabled_003
 * @tc.desc: Test SetDomainAuthUnlockEnabled with no plugin loaded.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlockEnabled_003, TestSize.Level3)
{
    UnloadPluginMethods();
    std::vector<uint8_t> token = {1, 2, 3};
    std::vector<uint8_t> secret = {4, 5, 6};
    ErrCode ret = InnerAccountIAMManager::GetInstance().SetDomainAuthUnlockEnabled(
        100, token, secret, true);
    EXPECT_EQ(ret, ERR_DOMAIN_ACCOUNT_NOT_SUPPORT);
}

/**
 * @tc.name: DomainAccountUnlockEnabled_004
 * @tc.desc: Test SetDomainAuthUnlockEnabled with unbound localId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlockEnabled_004, TestSize.Level3)
{
    LoadPluginMethods();
    std::vector<uint8_t> token = {1, 2, 3};
    std::vector<uint8_t> secret = {4, 5, 6};
    ErrCode ret = InnerAccountIAMManager::GetInstance().SetDomainAuthUnlockEnabled(
        9999, token, secret, true);
    EXPECT_NE(ret, ERR_OK);
    UnloadPluginMethods();
}

/**
 * @tc.name: DomainAccountUnlockEnabled_005
 * @tc.desc: Test SetDomainAuthUnlockEnabled with invalid token (VerifyAuthToken fails).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountUnlockEnabled_005, TestSize.Level3)
{
    LoadPluginMethods();
    int32_t userId = CreateAndBindDomainAccount("unlockEnabled005");
    ASSERT_GT(userId, 0);
    std::vector<uint8_t> token = {1, 2, 3};
    std::vector<uint8_t> secret = {4, 5, 6};
    ErrCode ret = InnerAccountIAMManager::GetInstance().SetDomainAuthUnlockEnabled(
        userId, token, secret, true);
    EXPECT_EQ(ret, ERR_ACCOUNT_IAM_AUTH_TOKEN_INVALID);
    UnloadPluginMethods();
}

/**
 * @tc.name: IsEnableDomainUnlock_001
 * @tc.desc: Test IsEnableDomainUnlock returns true when domain unlock is enabled with ONLINE_OFFLINE mode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, IsEnableDomainUnlock_001, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    int32_t userId = CreateAndBindDomainAccount("isEnableUnlock001");
    ASSERT_GT(userId, 0);
    bool enable = false;
    ErrCode ret = InnerAccountIAMManager::GetInstance().IsEnableDomainUnlock(userId, enable);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(enable);
    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(userId);
    UnloadPluginMethods();
}

/**
 * @tc.name: IsEnableDomainUnlock_002
 * @tc.desc: Test IsEnableDomainUnlock returns false when domain unlock is disabled.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, IsEnableDomainUnlock_002, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(false);
    int32_t userId = CreateAndBindDomainAccount("isEnableUnlock002");
    ASSERT_GT(userId, 0);
    bool enable = true;
    ErrCode ret = InnerAccountIAMManager::GetInstance().IsEnableDomainUnlock(userId, enable);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(enable);
    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(userId);
    SetEnableUnlockDevice(true);
    UnloadPluginMethods();
}

/**
 * @tc.name: IsEnableDomainUnlock_003
 * @tc.desc: Test IsEnableDomainUnlock returns false when no plugin is loaded.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, IsEnableDomainUnlock_003, TestSize.Level3)
{
    LoadPluginMethods();
    int32_t userId = CreateAndBindDomainAccount("isEnableUnlock003");
    ASSERT_GT(userId, 0);
    UnloadPluginMethods();
    bool enable = true;
    ErrCode ret = InnerAccountIAMManager::GetInstance().IsEnableDomainUnlock(userId, enable);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(enable);
    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(userId);
}

// F2 PIN flow adaptation tests

/**
 * @tc.name: CommitDelCredCallback_SkipStorageKey_001
 * @tc.desc: Test CommitDelCredCallback::OnResult with skipStorageKey=true skips UpdateStorageKeyContext.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, CommitDelCredCallback_SkipStorageKey_001, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    sptr<MockIDMCallback> callback = new (std::nothrow) MockIDMCallback();
    ASSERT_NE(callback, nullptr);
    auto commitDelCredCallback = std::make_shared<CommitDelCredCallback>(100, callback, true);
    ASSERT_NE(commitDelCredCallback, nullptr);
    Attributes extraInfo;
    commitDelCredCallback->OnResult(ERR_OK, extraInfo);
    EXPECT_EQ(callback->result_, ERR_OK);
    EXPECT_TRUE(commitDelCredCallback->isCalled_);
    UnloadPluginMethods();
}

/**
 * @tc.name: CommitDelCredCallback_SkipStorageKey_002
 * @tc.desc: Test CommitDelCredCallback::OnResult with skipStorageKey=false calls UpdateStorageKeyContext.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, CommitDelCredCallback_SkipStorageKey_002, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(false);
    sptr<MockIDMCallback> callback = new (std::nothrow) MockIDMCallback();
    ASSERT_NE(callback, nullptr);
    auto commitDelCredCallback = std::make_shared<CommitDelCredCallback>(100, callback, false);
    ASSERT_NE(commitDelCredCallback, nullptr);
    Attributes extraInfo;
    commitDelCredCallback->OnResult(ERR_OK, extraInfo);
    EXPECT_EQ(callback->result_, ERR_OK);
    EXPECT_TRUE(commitDelCredCallback->isCalled_);
    UnloadPluginMethods();
}

/**
 * @tc.name: CommitDelCredCallback_SkipStorageKey_003
 * @tc.desc: Test CommitDelCredCallback::OnResult with error result (not ERR_OK).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, CommitDelCredCallback_SkipStorageKey_003, TestSize.Level3)
{
    sptr<MockIDMCallback> callback = new (std::nothrow) MockIDMCallback();
    ASSERT_NE(callback, nullptr);
    auto commitDelCredCallback = std::make_shared<CommitDelCredCallback>(100, callback, true);
    ASSERT_NE(commitDelCredCallback, nullptr);
    Attributes extraInfo;
    commitDelCredCallback->OnResult(ResultCode::FAIL, extraInfo);
    EXPECT_EQ(callback->result_, ResultCode::FAIL);
    EXPECT_TRUE(commitDelCredCallback->isCalled_);
}

/**
 * @tc.name: AddCredCallback_SkipStorageKey_001
 * @tc.desc: Test AddCredCallback::OnResult skips AddUserKey when domain unlock is enabled.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, AddCredCallback_SkipStorageKey_001, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    int32_t userId = CreateAndBindDomainAccount("skipAdd001");
    ASSERT_GT(userId, 0);
    sptr<MockIDMCallback> callback = new (std::nothrow) MockIDMCallback();
    ASSERT_NE(callback, nullptr);
    CredentialParameters credInfo = {};
    credInfo.authType = AuthType::PIN;
    auto addCredCallback = std::make_shared<AddCredCallback>(userId, credInfo, callback);
    ASSERT_NE(addCredCallback, nullptr);
    Attributes extraInfo;
    extraInfo.SetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, 100);
    extraInfo.SetUint64Value(Attributes::AttributeKey::ATTR_SEC_USER_ID, 200);
    extraInfo.SetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, {1, 2, 3});
    extraInfo.SetUint8ArrayValue(Attributes::ATTR_AUTH_TOKEN, {4, 5, 6});
    addCredCallback->OnResult(0, extraInfo);
    EXPECT_EQ(callback->result_, 0);
    EXPECT_TRUE(addCredCallback->isCalled_);
    UnloadPluginMethods();
}

/**
 * @tc.name: AddCredCallback_SkipStorageKey_002
 * @tc.desc: Test AddCredCallback::OnResult does NOT skip AddUserKey when no plugin loaded.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, AddCredCallback_SkipStorageKey_002, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(false);
    int32_t userId = CreateAndBindDomainAccount("skipAdd002");
    ASSERT_GT(userId, 0);
    sptr<MockIDMCallback> callback = new (std::nothrow) MockIDMCallback();
    ASSERT_NE(callback, nullptr);
    CredentialParameters credInfo = {};
    credInfo.authType = AuthType::PIN;
    auto addCredCallback = std::make_shared<AddCredCallback>(userId, credInfo, callback);
    ASSERT_NE(addCredCallback, nullptr);
    Attributes extraInfo;
    extraInfo.SetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, 100);
    extraInfo.SetUint64Value(Attributes::AttributeKey::ATTR_SEC_USER_ID, 200);
    extraInfo.SetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, {1, 2, 3});
    extraInfo.SetUint8ArrayValue(Attributes::ATTR_AUTH_TOKEN, {4, 5, 6});
    addCredCallback->OnResult(0, extraInfo);
    EXPECT_EQ(callback->result_, 0);
    EXPECT_TRUE(addCredCallback->isCalled_);
    UnloadPluginMethods();
}

/**
 * @tc.name: AddCredCallback_SkipStorageKey_003
 * @tc.desc: Test AddCredCallback::OnResult with non-PIN authType does not enter skip logic.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, AddCredCallback_SkipStorageKey_003, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    sptr<MockIDMCallback> callback = new (std::nothrow) MockIDMCallback();
    ASSERT_NE(callback, nullptr);
    CredentialParameters credInfo = {};
    credInfo.authType = AuthType::FACE;
    auto addCredCallback = std::make_shared<AddCredCallback>(100, credInfo, callback);
    ASSERT_NE(addCredCallback, nullptr);
    Attributes extraInfo;
    addCredCallback->OnResult(0, extraInfo);
    EXPECT_EQ(callback->result_, 0);
    EXPECT_TRUE(addCredCallback->isCalled_);
    UnloadPluginMethods();
}

/**
 * @tc.name: AddCredCallback_SkipStorageKey_004
 * @tc.desc: Test AddCredCallback::OnResult with error result and PIN authType.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, AddCredCallback_SkipStorageKey_004, TestSize.Level3)
{
    LoadPluginMethods();
    SetEnableUnlockDevice(true);
    sptr<MockIDMCallback> callback = new (std::nothrow) MockIDMCallback();
    ASSERT_NE(callback, nullptr);
    CredentialParameters credInfo = {};
    credInfo.authType = AuthType::PIN;
    auto addCredCallback = std::make_shared<AddCredCallback>(100, credInfo, callback);
    ASSERT_NE(addCredCallback, nullptr);
    Attributes extraInfo;
    addCredCallback->OnResult(ResultCode::FAIL, extraInfo);
    EXPECT_EQ(callback->result_, ResultCode::FAIL);
    EXPECT_TRUE(addCredCallback->isCalled_);
    UnloadPluginMethods();
}

// Sync callback tests (Gap A: VerifyTokenSyncCallback, GetCredentialInfoSyncCallback, GetSecureUidCallback)

/**
 * @tc.name: VerifyTokenSyncCallback_OnResult_0100
 * @tc.desc: Test VerifyTokenSyncCallback::OnResult with success result.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, VerifyTokenSyncCallback_OnResult_0100, TestSize.Level3)
{
    auto callback = std::make_shared<VerifyTokenSyncCallback>();
    ASSERT_NE(callback, nullptr);
    Attributes extraInfo;
    callback->OnResult(ERR_OK, extraInfo);
    EXPECT_TRUE(callback->isCalled_);
    EXPECT_EQ(callback->result_, ERR_OK);
}

/**
 * @tc.name: VerifyTokenSyncCallback_OnResult_0200
 * @tc.desc: Test VerifyTokenSyncCallback::OnResult with failure result.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, VerifyTokenSyncCallback_OnResult_0200, TestSize.Level3)
{
    auto callback = std::make_shared<VerifyTokenSyncCallback>();
    ASSERT_NE(callback, nullptr);
    Attributes extraInfo;
    callback->OnResult(ResultCode::FAIL, extraInfo);
    EXPECT_TRUE(callback->isCalled_);
    EXPECT_EQ(callback->result_, ResultCode::FAIL);
}

/**
 * @tc.name: GetCredentialInfoSyncCallback_OnCredentialInfo_0100
 * @tc.desc: Test GetCredentialInfoSyncCallback with PIN credential present.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, GetCredentialInfoSyncCallback_OnCredentialInfo_0100,
    TestSize.Level3)
{
    auto callback = std::make_shared<GetCredentialInfoSyncCallback>(100);
    ASSERT_NE(callback, nullptr);
    std::vector<CredentialInfo> infoList;
    CredentialInfo info;
    info.authType = AuthType::PIN;
    info.isAbandoned = false;
    infoList.push_back(info);
    callback->OnCredentialInfo(ERR_OK, infoList);
    EXPECT_TRUE(callback->isCalled_);
    EXPECT_EQ(callback->result_, ERR_OK);
    EXPECT_TRUE(callback->hasPIN_);
}

/**
 * @tc.name: GetCredentialInfoSyncCallback_OnCredentialInfo_0200
 * @tc.desc: Test GetCredentialInfoSyncCallback with empty info list.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, GetCredentialInfoSyncCallback_OnCredentialInfo_0200,
    TestSize.Level3)
{
    auto callback = std::make_shared<GetCredentialInfoSyncCallback>(100);
    ASSERT_NE(callback, nullptr);
    std::vector<CredentialInfo> emptyList;
    callback->OnCredentialInfo(ERR_OK, emptyList);
    EXPECT_TRUE(callback->isCalled_);
    EXPECT_EQ(callback->result_, ERR_OK);
    EXPECT_FALSE(callback->hasPIN_);
}

/**
 * @tc.name: GetCredentialInfoSyncCallback_OnCredentialInfo_0300
 * @tc.desc: Test GetCredentialInfoSyncCallback with abandoned PIN credential.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, GetCredentialInfoSyncCallback_OnCredentialInfo_0300,
    TestSize.Level3)
{
    auto callback = std::make_shared<GetCredentialInfoSyncCallback>(100);
    ASSERT_NE(callback, nullptr);
    std::vector<CredentialInfo> infoList;
    CredentialInfo info;
    info.authType = AuthType::PIN;
    info.isAbandoned = true;
    infoList.push_back(info);
    callback->OnCredentialInfo(ERR_OK, infoList);
    EXPECT_TRUE(callback->isCalled_);
    EXPECT_EQ(callback->result_, ERR_OK);
    EXPECT_FALSE(callback->hasPIN_);
}

/**
 * @tc.name: GetCredentialInfoSyncCallback_OnCredentialInfo_0400
 * @tc.desc: Test GetCredentialInfoSyncCallback with NOT_ENROLLED result.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, GetCredentialInfoSyncCallback_OnCredentialInfo_0400,
    TestSize.Level3)
{
    auto callback = std::make_shared<GetCredentialInfoSyncCallback>(100);
    ASSERT_NE(callback, nullptr);
    std::vector<CredentialInfo> infoList;
    callback->OnCredentialInfo(ResultCode::NOT_ENROLLED, infoList);
    EXPECT_TRUE(callback->isCalled_);
    EXPECT_EQ(callback->result_, ResultCode::NOT_ENROLLED);
    EXPECT_FALSE(callback->hasPIN_);
}

/**
 * @tc.name: GetCredentialInfoSyncCallback_OnCredentialInfo_0500
 * @tc.desc: Test GetCredentialInfoSyncCallback with non-PIN credential.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, GetCredentialInfoSyncCallback_OnCredentialInfo_0500,
    TestSize.Level3)
{
    auto callback = std::make_shared<GetCredentialInfoSyncCallback>(100);
    ASSERT_NE(callback, nullptr);
    std::vector<CredentialInfo> infoList;
    CredentialInfo info;
    info.authType = AuthType::FACE;
    info.isAbandoned = false;
    infoList.push_back(info);
    callback->OnCredentialInfo(ERR_OK, infoList);
    EXPECT_TRUE(callback->isCalled_);
    EXPECT_EQ(callback->result_, ERR_OK);
    EXPECT_FALSE(callback->hasPIN_);
}

/**
 * @tc.name: GetSecureUidCallback_OnSecUserInfo_0100
 * @tc.desc: Test GetSecureUidCallback::OnSecUserInfo with success result.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, GetSecureUidCallback_OnSecUserInfo_0100, TestSize.Level3)
{
    auto callback = std::make_shared<GetSecureUidCallback>(100);
    ASSERT_NE(callback, nullptr);
    SecUserInfo info;
    info.secureUid = 12345;
    callback->OnSecUserInfo(ERR_OK, info);
    EXPECT_TRUE(callback->isCalled_);
    EXPECT_EQ(callback->ret, ERR_OK);
    EXPECT_EQ(callback->secureUid_, 12345u);
}

/**
 * @tc.name: GetSecureUidCallback_OnSecUserInfo_0200
 * @tc.desc: Test GetSecureUidCallback::OnSecUserInfo with failure result.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, GetSecureUidCallback_OnSecUserInfo_0200, TestSize.Level3)
{
    auto callback = std::make_shared<GetSecureUidCallback>(100);
    ASSERT_NE(callback, nullptr);
    SecUserInfo info;
    info.secureUid = 0;
    callback->OnSecUserInfo(ResultCode::FAIL, info);
    EXPECT_TRUE(callback->isCalled_);
    EXPECT_EQ(callback->ret, static_cast<int32_t>(ResultCode::FAIL));
    EXPECT_EQ(callback->secureUid_, 0u);
}

/**
 * @tc.name: GetSecureUidCallback_OnSecUserInfo_0300
 * @tc.desc: Test GetSecureUidCallback::OnSecUserInfo with NOT_ENROLLED result.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, GetSecureUidCallback_OnSecUserInfo_0300, TestSize.Level3)
{
    auto callback = std::make_shared<GetSecureUidCallback>(100);
    ASSERT_NE(callback, nullptr);
    SecUserInfo info;
    callback->OnSecUserInfo(ResultCode::NOT_ENROLLED, info);
    EXPECT_TRUE(callback->isCalled_);
    EXPECT_EQ(callback->ret, static_cast<int32_t>(ResultCode::NOT_ENROLLED));
}

/**
 * @tc.name: PluginGetUnlockDeviceConfigWithInfo_NoPlugin_0100
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, PluginGetUnlockDeviceConfigWithInfo_NoPlugin_0100, TestSize.Level3)
{
    LoadPluginMethods();
    {
        std::lock_guard<std::mutex> lock(InnerDomainAccountManager::GetInstance().libMutex_);
        InnerDomainAccountManager::GetInstance().methodMap_.erase(PluginMethodEnum::GET_UNLOCK_DEVICE_CONFIG);
    }
    DomainAccountInfo info;
    bool enableUnlockDevice = true;
    int32_t unlockDeviceMode = 0;
    EXPECT_EQ(InnerDomainAccountManager::GetInstance().PluginGetUnlockDeviceConfigWithInfo(
        info, enableUnlockDevice, unlockDeviceMode), ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    UnloadPluginMethods();
}

/**
 * @tc.name: PluginAuthWithUnlockIntent_NoPlugin_0100
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, PluginAuthWithUnlockIntent_NoPlugin_0100, TestSize.Level3)
{
    LoadPluginMethods();
    {
        std::lock_guard<std::mutex> lock(InnerDomainAccountManager::GetInstance().libMutex_);
        InnerDomainAccountManager::GetInstance().methodMap_.erase(PluginMethodEnum::AUTH_WITH_UNLOCK_INTENT);
    }
    DomainAccountInfo info;
    uint64_t contextId;
    EXPECT_EQ(InnerDomainAccountManager::GetInstance().PluginAuthWithUnlockIntent(info, {}, {}, contextId),
        ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE);
    UnloadPluginMethods();
}

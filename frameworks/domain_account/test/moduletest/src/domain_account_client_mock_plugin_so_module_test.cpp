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
#include <gtest/hwext/gtest-multithread.h>
#include <thread>
#include <unistd.h>
#include "accesstoken_kit.h"
#include "account_error_no.h"
#include "account_file_operator.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "domain_account_callback_service.h"
#ifdef BUNDLE_ADAPTER_MOCK
#include "domain_account_manager_service.h"
#include "domain_account_proxy.h"
#endif
#define private public
#include "domain_account_client.h"
#include "inner_domain_account_manager.h"
#include "iinner_os_account_manager.h"
#include "os_account.h"
#undef private
#include "ipc_skeleton.h"
#include "mock_domain_auth_callback.h"
#include "mock_domain_auth_callback_for_listener.h"
#include "mock_domain_create_domain_account_callback.h"
#include "mock_domain_has_domain_info_callback.h"
#include "mock_domain_get_access_token_callback.h"
#include "mock_domain_plugin.h"
#include "mock_domain_so_plugin.h"
#include "os_account_manager.h"
#ifdef BUNDLE_ADAPTER_MOCK
#include "os_account_manager_service.h"
#include "os_account_proxy.h"
#endif
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace testing::mt;
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
static constexpr int32_t DEFAULT_API_VERSION = 8;
const std::vector<uint8_t> DEFAULT_TOKEN = {49, 50, 51, 52, 53};
static uint64_t g_selfTokenID;
const std::string STRING_TEST_NAME = "name";
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
const int32_t WAIT_TIME = 2;
const std::string STRING_SHORT_NAME_OUT_OF_RANGE(256, '1');
#endif
const std::map<PluginMethodEnum, void *> PLUGIN_METHOD_MAP = {
    {PluginMethodEnum::AUTH, reinterpret_cast<void *>(Auth)},
    {PluginMethodEnum::GET_ACCOUNT_INFO, reinterpret_cast<void *>(GetAccountInfo)},
    {PluginMethodEnum::BIND_ACCOUNT, reinterpret_cast<void *>(BindAccount)},
    {PluginMethodEnum::IS_AUTHENTICATION_EXPIRED, reinterpret_cast<void *>(IsAuthenticationExpired)},
    {PluginMethodEnum::SET_ACCOUNT_POLICY, reinterpret_cast<void *>(SetAccountPolicy)},
    {PluginMethodEnum::GET_ACCOUNT_POLICY, reinterpret_cast<void *>(GetAccountPolicy)},
    {PluginMethodEnum::UPDATE_ACCOUNT_INFO, reinterpret_cast<void *>(UpdateAccountInfo)},
};
}

static bool AllocPermission(std::vector<std::string> permissions, AccessTokenID &tokenID, bool isSystemApp = true)
{
    std::vector<PermissionStateFull> permissionStates;
    for (const auto& permission : permissions) {
        PermissionStateFull permissionState = {
            .permissionName = permission,
            .isGeneral = true,
            .resDeviceID = {"local"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {PERMISSION_SYSTEM_FIXED}
        };
        permissionStates.emplace_back(permissionState);
    }
    HapPolicyParams hapPolicyParams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = permissionStates
    };

    HapInfoParams hapInfoParams = {
        .userID = 100,
        .bundleName = "account_test",
        .instIndex = 0,
        .appIDDesc = "account_test",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = isSystemApp
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(hapInfoParams, hapPolicyParams);
    tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    return (INVALID_TOKENID != tokenIdEx.tokenIDEx) && (0 == SetSelfTokenID(tokenIdEx.tokenIDEx));
}

bool RecoveryPermission(AccessTokenID tokenID)
{
    return (ERR_OK == AccessTokenKit::DeleteToken(tokenID)) && (ERR_OK == SetSelfTokenID(g_selfTokenID));
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
    if (callback_ == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    std::shared_ptr<DomainAuthResult> authResult(DomainAuthResult::Unmarshalling(parcel));
    callback_->OnResult(errCode, (*authResult));
}

void TestPluginSoDomainAuthCallback::SetOsAccountInfo(const OsAccountInfo &accountInfo)
{
    accountInfo_ = accountInfo;
}

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
    OsAccount::GetInstance().proxy_ = new (std::nothrow) OsAccountProxy(osAccountService->AsObject());
    ASSERT_NE(OsAccount::GetInstance().proxy_, nullptr);
    g_selfTokenID = IPCSkeleton::GetSelfTokenID();
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
         TestSize.Level0)
{
    AccessTokenID tokenID;
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
         TestSize.Level0)
{
    DomainAccountInfo info;
    LoadPluginMethods();
    AccessTokenID tokenID;
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
         TestSize.Level0)
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
         TestSize.Level0)
{
    AccessTokenID tokenID;
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
         TestSize.Level0)
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
    AccessTokenID tokenID;
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
         TestSize.Level0)
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
    setuid(EDM_UID);
    ASSERT_EQ(DomainAccountClient::GetInstance().UpdateAccountInfo(oldDomainInfo, newDomainInfo),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
    AccessTokenID tokenID;
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
         TestSize.Level0)
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
    AccessTokenID tokenID;
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
         TestSize.Level0)
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
    AccessTokenID tokenID;
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
         DomainAccountClientModuleTest_UpdateAccountInfo_004, TestSize.Level0)
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
    AccessTokenID tokenID;
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
         TestSize.Level0)
{
    AccessTokenID tokenID;
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
         TestSize.Level0)
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
         TestSize.Level0)
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
         TestSize.Level0)
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
    AccessTokenID tokenID;
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
         TestSize.Level0)
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
    AccessTokenID tokenID;
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
 * @tc.name: DomainAccountClientModuleTest_IsAuthenticationExpired_005
 * @tc.desc: IsAuthenticationExpired success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest, DomainAccountClientModuleTest_IsAuthenticationExpired_007,
         TestSize.Level0)
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
         TestSize.Level0)
{
    AccessTokenID tokenID;
    ASSERT_TRUE(AllocPermission({}, tokenID));
    setuid(EDM_UID);
    LoadPluginMethods();
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";

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
         TestSize.Level0)
{
    AccessTokenID tokenID;
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
         TestSize.Level0)
{
    AccessTokenID tokenID;

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
         TestSize.Level0)
{
    AccessTokenID tokenID;
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

/*** multithread */

/**
 * @tc.name: DomainAccountClientModuleTest_IsAuthenticationExpired_MultiThread_001
 * @tc.desc:  MultiThread IsAuthenticationExpired success expired time not set..
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(DomainAccountClientMockPluginSoModuleTest,
         DomainAccountClientModuleTest_IsAuthenticationExpired_MultiThread_001, TestSize.Level0)
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

    auto func = [] {
        DomainAccountInfo domainInfo;
        domainInfo.accountName_ = "testaccount";
        domainInfo.domain_ = "test.example.com";
        domainInfo.accountId_ = "testid";
        bool isExpired = false;
        EXPECT_EQ(DomainAccountClient::GetInstance().IsAuthenticationExpired(domainInfo, isExpired), ERR_OK);
        EXPECT_TRUE(isExpired);
    };

    GTEST_RUN_TASK(func);

    UnloadPluginMethods();

    int32_t userId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_SetAuthenticationExpiryThreshold_MultiThread_001
 * @tc.desc: MultiThread SetAccountPolicy success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientMockPluginSoModuleTest,
         DomainAccountClientModuleTest_SetAuthenticationExpiryThreshold_MultiThread_001, TestSize.Level0)
{
    LoadPluginMethods();
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "testaccount";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";
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
    AccessTokenID tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, tokenID));
    setuid(EDM_UID);
    GTEST_RUN_TASK([]() {
        DomainAccountInfo domainInfo;
        domainInfo.accountName_ = "testaccount";
        domainInfo.domain_ = "test.example.com";
        domainInfo.accountId_ = "testid";
        std::string policy = "{\"authenicationValidityPeriod\":10}";
        std::string policyFromGet;
        EXPECT_EQ(DomainAccountClient::GetInstance().SetAccountPolicy(domainInfo, policy), ERR_OK);
        EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountPolicy(domainInfo, policyFromGet), ERR_OK);
    });
    UnloadPluginMethods();
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));
    int32_t userId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

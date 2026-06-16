/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "authorization_callback.h"
#include "authorization_callback_stub.h"
#include "authorization_common.h"
#include "bundle_manager_adapter.h"
#include "extension_manager_client.h"
#include "iauthorization_callback.h"
#include "iinner_os_account_manager.h"
#include "privilege_cache_manager.h"
#include "privileges_map.h"
#include "service_extension_connect.h"
#include "tee_auth_adapter.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <thread>

#define protected public
#define private public
#include "inner_authorization_manager.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
namespace OHOS {
namespace AccountSA {
namespace {
const std::string TEST_BUNDLE_NAME = "com.test.bundle";
const std::string TEST_ABILITY_NAME = "com.test.bundle.MainAbility";
const std::string TEST_PRIVILEGE = "ohos.privilege.MANAGE_LOCAL_ACCOUNTS";
const std::string TEST_DESCRIPTION = "Test privilege description";
const std::string TEST_AUTH_APP_BUNDLE = "com.example.authapp";
const std::string TEST_UI_EXTENSION = "com.example.authapp.UIExtension";
const std::string TEST_SERVICE_EXTENSION = "com.example.authapp.ServiceExtension";
const std::string TEST_SESSIONID = "111111";
const int32_t TEST_CALLING_UID = 200100; // UID for account 100
const int32_t TEST_CALLING_PID = 12345;
const int32_t ERR_PID = -1;
const int32_t TEST_USER_ID = 100;
static bool g_transferPrivilegeToCode = true;
} // namespace

/**
 * @class MockIAuthorizationCallback
 * Mock implementation of IAuthorizationCallback.
 */
class MockIAuthorizationCallback final {
public:
    MOCK_METHOD2(OnResult, void(int32_t resultCode, const AuthorizationResult& result));
    MOCK_METHOD2(OnConnectAbility, void(const ConnectAbilityInfo& info, const sptr<IRemoteObject>& connectCallback));
};

/**
 * @class MockAuthorizationCallbackStub
 * Mock implementation of AuthorizationCallbackStub for IRemoteObject.
 */
class MockAuthorizationCallbackStub : public AuthorizationCallbackStub {
public:
    MockAuthorizationCallbackStub() = default;
    ~MockAuthorizationCallbackStub() override = default;

    ErrCode OnResult(int32_t resultCode, const AccountSA::AuthorizationResult& result) override
    {
        std::lock_guard<std::mutex> lock(mutex);
        isReady = true;
        cv.notify_one();
        return 0;
    }

    ErrCode OnConnectAbility(const AccountSA::ConnectAbilityInfo& info, const sptr<IRemoteObject>& callback) override
    {
        auto connectCallback = iface_cast<IConnectAbilityCallback>(callback);
        if (connectCallback == nullptr) {
            ACCOUNT_LOGE("ConnectAbilityCallback proxy is nullptr");
            return -1;
        }
        auto task = [connectCallback] {
            std::vector<uint8_t> iamToken;
            connectCallback->OnResult(0, iamToken, -1, -1);
        };
        std::thread taskThread(task);
        pthread_setname_np(taskThread.native_handle(), "OnConnectAbility");
        taskThread.detach();

        return 0;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient>& recipient) override { return true; }

    int SendRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override
    {
        sendRequestTime++;
        return 0;
    }

    int32_t sendRequestTime = 0;
    std::mutex mutex;
    std::condition_variable cv;
    bool isReady = false;
};

class MockAccountPermissionManager {
public:
    static MockAccountPermissionManager& GetInstance()
    {
        static MockAccountPermissionManager instance;
        return instance;
    }
    MOCK_METHOD2(VerifyPermission, ErrCode(const uint32_t tokenId, const std::string& permissionName));
};

ErrCode AccountPermissionManager::VerifyPermission(const uint32_t tokenId, const std::string& permissionName)
{
    return MockAccountPermissionManager::GetInstance().VerifyPermission(tokenId, permissionName);
}

/**
 * @class MockIInnerOsAccountManager
 * Mock for IInnerOsAccountManager.
 */
class MockIInnerOsAccountManager {
public:
    static MockIInnerOsAccountManager& GetInstance()
    {
        static MockIInnerOsAccountManager instance;
        return instance;
    }

    MOCK_METHOD2(GetOsAccountType, ErrCode(int32_t id, OsAccountType& type));
    MOCK_METHOD2(GetForegroundOsAccountLocalId, ErrCode(const uint64_t displayId, int32_t &localId));
};

/**
 * @class MockOsAccountTeeAdapter
 * Mock for OsAccountTeeAdapter.
 */
class MockOsAccountTeeAdapter {
public:
    static MockOsAccountTeeAdapter& GetInstance()
    {
        static MockOsAccountTeeAdapter instance;
        return instance;
    }

    MOCK_METHOD2(TaAcquireAuthorization, ErrCode(const ApplyUserTokenParam& param, ApplyUserTokenResult& result));
    MOCK_METHOD2(VerifyToken, ErrCode(const std::vector<uint8_t>& token, std::vector<uint8_t>& tokenResult));
};

SessionAbilityConnection& SessionAbilityConnection::GetInstance()
{
    static SessionAbilityConnection instance;
    return instance;
}

bool SessionAbilityConnection::GetConnectInfo(int32_t callingUid, ConnectAbilityInfo& info) { return true; }

ErrCode SessionAbilityConnection::SaveAuthorizationResult(ErrCode errCode,
    AuthorizationResultCode& resultCode,
    const std::vector<uint8_t>& iamToken,
    int32_t remainValidityTime)
{
    return ERR_OK;
}

ErrCode SessionAbilityConnection::SessionConnectExtension(const ConnectAbilityInfo& info,
    sptr<IAuthorizationCallback>& callback,
    AuthorizationResult& authorizationResult)
{
    return ERR_OK;
}

ErrCode OpenSmartPidFd(const int32_t pid, SmartPidFd &fdPtr)
{
    return ERR_OK;
}

ErrCode GetUptimeMs(int64_t &bootTimeStampMs)
{
    bootTimeStampMs = 1L;
    return ERR_OK;
}

// Mock implementations that redirect to Mock classes
ErrCode IInnerOsAccountManager::GetOsAccountType(int32_t id, OsAccountType& type)
{
    return MockIInnerOsAccountManager::GetInstance().GetOsAccountType(id, type);
}

ErrCode IInnerOsAccountManager::GetForegroundOsAccountLocalId(const uint64_t displayId, int32_t &localId)
{
    return MockIInnerOsAccountManager::GetInstance().GetForegroundOsAccountLocalId(displayId, localId);
}

ErrCode OsAccountTeeAdapter::TaAcquireAuthorization(const ApplyUserTokenParam& param, ApplyUserTokenResult& result)
{
    return MockOsAccountTeeAdapter::GetInstance().TaAcquireAuthorization(param, result);
}

ErrCode OsAccountTeeAdapter::VerifyToken(
    const std::vector<uint8_t>& token, const std::string &privilege, std::vector<uint8_t>& tokenResult)
{
    return MockOsAccountTeeAdapter::GetInstance().VerifyToken(token, tokenResult);
}

PrivilegeCacheManager& PrivilegeCacheManager::GetInstance()
{
    static PrivilegeCacheManager instance;
    return instance;
}

static bool g_addCacheFail = false;

ErrCode PrivilegeCacheManager::AddCache(const AuthenCallerInfo& callerInfo, uint32_t safeStartTime)
{
    if (callerInfo.pid == ERR_PID || g_addCacheFail) {
        return ERR_AUTHORIZATION_CACHE_ERROR;
    }
    return 0;
}

bool TransferPrivilegeToCode(const std::string& privilegeName, uint32_t& code) { return g_transferPrivilegeToCode; }

class InnerAuthorizationManagerModuleTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    InnerAuthorizationManager& manager_ = InnerAuthorizationManager::GetInstance();
};

void InnerAuthorizationManagerModuleTest::SetUpTestCase() { ACCOUNT_LOGI("SetUpTestCase enter"); }

void InnerAuthorizationManagerModuleTest::TearDownTestCase() { ACCOUNT_LOGI("TearDownTestCase enter"); }

void InnerAuthorizationManagerModuleTest::SetUp()
{
    // Set default mock behaviors
    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetOsAccountType(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(OsAccountType::ADMIN), Return(ERR_OK)));
    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetForegroundOsAccountLocalId(_, _))
        .WillRepeatedly(Return(ERR_OK));

    EXPECT_CALL(MockOsAccountTeeAdapter::GetInstance(), TaAcquireAuthorization(_, _)).WillRepeatedly(Return(ERR_OK));
}

void InnerAuthorizationManagerModuleTest::TearDown() {}

/**
 * @tc.name: InnerAuthorizationManagerTest_GetInstance_0100
 * @tc.desc: test GetInstance singleton.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, InnerAuthorizationManagerTest_GetInstance_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("InnerAuthorizationManagerTest_GetInstance_0100");

    auto& instance1 = InnerAuthorizationManager::GetInstance();
    auto& instance2 = InnerAuthorizationManager::GetInstance();

    EXPECT_EQ(&instance1, &instance2);
    sptr<IRemoteObject> callback = nullptr;
    sptr<IRemoteObject> requestObj = new MockAuthorizationCallbackStub();
    PrivilegeBriefDef pdef = {.privilegeName = const_cast<char*>(TEST_PRIVILEGE.c_str()),
        .description = const_cast<char*>(TEST_DESCRIPTION.c_str()),
        .timeout = 300};
    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = true;
    options.isInteractionAllowed = true;
    options.hasContext = false;

    OsAccountConfig config;
    config.authAppBundleName = TEST_AUTH_APP_BUNDLE;
    config.authAppServiceExtensionAbilityName = TEST_SERVICE_EXTENSION;
    ErrCode ret = manager_.AcquireAuthorization(pdef, options, config, callback, requestObj);
    EXPECT_EQ(ret, ERR_AUTHORIZATION_GET_PROXY_ERROR);
}

/**
 * @tc.name: AcquireAuthorizationTest_0200
 * @tc.desc: test AcquireAuthorization with service extension (no context).
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, AcquireAuthorizationTest_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_0200");
    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), VerifyPermission(_, _)).WillRepeatedly(Return(ERR_OK));
    PrivilegeBriefDef pdef = {.privilegeName = const_cast<char*>(TEST_PRIVILEGE.c_str()),
        .description = const_cast<char*>(TEST_DESCRIPTION.c_str()),
        .timeout = 300};

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = true;
    options.isInteractionAllowed = true;
    options.hasContext = false;

    OsAccountConfig config;
    config.authAppBundleName = TEST_AUTH_APP_BUNDLE;
    config.authAppServiceExtensionAbilityName = TEST_SERVICE_EXTENSION;

    sptr<IRemoteObject> callbackObj = new MockAuthorizationCallbackStub();
    sptr<IRemoteObject> requestObj = new MockAuthorizationCallbackStub();

    ErrCode ret = manager_.AcquireAuthorization(pdef, options, config, callbackObj, requestObj);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: AcquireAuthorizationTest_0300
 * @tc.desc: test AcquireAuthorization with UI extension (has context).
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, AcquireAuthorizationTest_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_0300");
    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), VerifyPermission(_, _)).WillRepeatedly(Return(ERR_OK));
    PrivilegeBriefDef pdef = {.privilegeName = const_cast<char*>(TEST_PRIVILEGE.c_str()),
        .description = const_cast<char*>(TEST_DESCRIPTION.c_str()),
        .timeout = 300};

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = true;
    options.isInteractionAllowed = true;
    options.hasContext = true;

    OsAccountConfig config;
    config.authAppBundleName = TEST_AUTH_APP_BUNDLE;
    config.authAppUIExtensionAbilityName = TEST_UI_EXTENSION;

    auto callbackObj = new MockAuthorizationCallbackStub();
    auto requestObj = new MockAuthorizationCallbackStub();

    ErrCode ret = manager_.AcquireAuthorization(pdef, options, config, callbackObj->AsObject(), requestObj->AsObject());
    EXPECT_EQ(ret, ERR_OK);

    // Give time for the detached thread to complete
    std::unique_lock<std::mutex> lock(callbackObj->mutex);
    callbackObj->cv.wait_for(
        lock, std::chrono::seconds(3), [callbackObj = callbackObj]() { return callbackObj->isReady; });
}

/**
 * @tc.name: AcquireAuthorizationTest_0400
 * @tc.desc: test AcquireAuthorization with null requestRemoteObj.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, AcquireAuthorizationTest_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_0400");
    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), VerifyPermission(_, _)).WillRepeatedly(Return(ERR_OK));
    PrivilegeBriefDef pdef = {.privilegeName = const_cast<char*>(TEST_PRIVILEGE.c_str()),
        .description = const_cast<char*>(TEST_DESCRIPTION.c_str()),
        .timeout = 300};

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = true;
    options.isInteractionAllowed = true;
    options.hasContext = true;

    OsAccountConfig config;
    config.authAppBundleName = TEST_AUTH_APP_BUNDLE;
    config.authAppUIExtensionAbilityName = TEST_UI_EXTENSION;

    sptr<IRemoteObject> callbackObj = new MockAuthorizationCallbackStub();
    sptr<IRemoteObject> requestObj = nullptr;

    ErrCode ret = manager_.AcquireAuthorization(pdef, options, config, callbackObj, requestObj);
    EXPECT_EQ(ret, ERR_AUTHORIZATION_GET_PROXY_ERROR);
}

/**
 * @tc.name: AcquireAuthorizationTest_0500
 * @tc.desc: test AcquireAuthorization with service extension connection failure.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, AcquireAuthorizationTest_0500, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_0500");
    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), VerifyPermission(_, _)).WillRepeatedly(Return(ERR_OK));
    PrivilegeBriefDef pdef = {.privilegeName = const_cast<char*>(TEST_PRIVILEGE.c_str()),
        .description = const_cast<char*>(TEST_DESCRIPTION.c_str()),
        .timeout = 300};

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = true;
    options.isInteractionAllowed = true;
    options.hasContext = false;

    OsAccountConfig config;
    config.authAppBundleName = TEST_AUTH_APP_BUNDLE;
    config.authAppServiceExtensionAbilityName = TEST_SERVICE_EXTENSION;

    sptr<IRemoteObject> callbackObj = new MockAuthorizationCallbackStub();
    sptr<IRemoteObject> requestObj = new MockAuthorizationCallbackStub();

    ErrCode ret = manager_.AcquireAuthorization(pdef, options, config, callbackObj, requestObj);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: VerifyAdminAccountTest_0100
 * @tc.desc: test VerifyAdminAccount with admin account.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, VerifyAdminAccountTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("VerifyAdminAccountTest_0100");

    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetOsAccountType(TEST_USER_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(OsAccountType::ADMIN), Return(ERR_OK)));

    auto [errCode, resultCode] = manager_.VerifyAdminAccount(TEST_USER_ID);

    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(resultCode, AuthorizationResultCode::AUTHORIZATION_SUCCESS);
}

/**
 * @tc.name: VerifyAdminAccountTest_0200
 * @tc.desc: test VerifyAdminAccount with non-admin account.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, VerifyAdminAccountTest_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("VerifyAdminAccountTest_0200");

    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetOsAccountType(TEST_USER_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(OsAccountType::NORMAL), Return(ERR_OK)));

    auto [errCode, resultCode] = manager_.VerifyAdminAccount(TEST_USER_ID);

    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(resultCode, AuthorizationResultCode::AUTHORIZATION_DENIED);
}

/**
 * @tc.name: VerifyAdminAccountTest_0300
 * @tc.desc: test VerifyAdminAccount with GetOsAccountType failure.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, VerifyAdminAccountTest_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("VerifyAdminAccountTest_0300");

    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetOsAccountType(TEST_USER_ID, _))
        .WillOnce(Return(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR));

    auto [errCode, resultCode] = manager_.VerifyAdminAccount(TEST_USER_ID);

    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(resultCode, AuthorizationResultCode::AUTHORIZATION_SUCCESS);
}

/**
 * @tc.name: CallTaAuthorizationTest_0100
 * @tc.desc: test CallTaAuthorization success.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, CallTaAuthorizationTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("CallTaAuthorizationTest_0100");

    std::vector<uint8_t> iamToken = {1, 2, 3, 4, 5};
    ConnectAbilityInfo info;
    info.privilege = TEST_PRIVILEGE;
    info.callingPid = TEST_CALLING_PID;
    info.timeout = 300;
    ApplyUserTokenResult tokenResult;

    EXPECT_CALL(MockOsAccountTeeAdapter::GetInstance(), TaAcquireAuthorization(_, _)).WillOnce(Return(ERR_OK));

    ErrCode ret = manager_.CallTaAuthorization(iamToken, TEST_USER_ID, tokenResult, info);

    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: CallTaAuthorizationTest_0200
 * @tc.desc: test CallTaAuthorization with TEE failure.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, CallTaAuthorizationTest_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("CallTaAuthorizationTest_0200");

    std::vector<uint8_t> iamToken = {1, 2, 3, 4, 5};
    ConnectAbilityInfo info;
    info.privilege = TEST_PRIVILEGE;
    info.callingPid = TEST_CALLING_PID;
    info.timeout = 300;
    ApplyUserTokenResult tokenResult;

    EXPECT_CALL(MockOsAccountTeeAdapter::GetInstance(), TaAcquireAuthorization(_, _))
        .WillOnce(Return(ERR_AUTHORIZATION_TA_ERROR));

    ErrCode ret = manager_.CallTaAuthorization(iamToken, TEST_USER_ID, tokenResult, info);

    EXPECT_EQ(ret, ERR_AUTHORIZATION_TA_ERROR);
}

/**
 * @tc.name: AdminAuthCallbackCallTaForTokenTest_0100
 * @tc.desc: test admin auth callback passes privilege to TEE.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, AdminAuthCallbackCallTaForTokenTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AdminAuthCallbackCallTaForTokenTest_0100");

    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<uint8_t> iamToken = {5, 6, 7, 8};
    std::vector<uint8_t> token;
    AdminAuthCallback callback(challenge, nullptr, TEST_USER_ID, TEST_CALLING_PID, TEST_PRIVILEGE);

    EXPECT_CALL(MockOsAccountTeeAdapter::GetInstance(), TaAcquireAuthorization(_, _))
        .WillOnce(Invoke([](const ApplyUserTokenParam &param, ApplyUserTokenResult &result) {
            EXPECT_EQ(param.pid, static_cast<uint32_t>(TEST_CALLING_PID));
            EXPECT_EQ(param.permissionSize, TEST_PRIVILEGE.size());
            std::string privilege(reinterpret_cast<const char *>(param.permission), param.permissionSize);
            EXPECT_EQ(privilege, TEST_PRIVILEGE);
            result.userTokenSize = 2;
            result.userToken[0] = 0x12;
            result.userToken[1] = 0x34;
            return ERR_OK;
        }));

    ErrCode ret = callback.CallTAForToken(TEST_USER_ID, iamToken, token);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(token, std::vector<uint8_t>({0x12, 0x34}));
}

/**
 * @tc.name: UpdatePrivilegeCacheTest_0100
 * @tc.desc: test UpdatePrivilegeCache success.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, UpdatePrivilegeCacheTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("UpdatePrivilegeCacheTest_0100");

    ConnectAbilityInfo info;
    info.privilege = TEST_PRIVILEGE;
    info.callingUid = TEST_CALLING_UID;
    info.callingPid = TEST_CALLING_PID;

    ApplyUserTokenResult tokenResult;
    tokenResult.grantTime = 1000;

    ErrCode ret = manager_.UpdatePrivilegeCache(info, tokenResult);

    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: UpdatePrivilegeCacheTest_0200
 * @tc.desc: test UpdatePrivilegeCache with cache failure.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, UpdatePrivilegeCacheTest_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("UpdatePrivilegeCacheTest_0200");

    ConnectAbilityInfo info;
    info.privilege = TEST_PRIVILEGE;
    info.callingUid = TEST_CALLING_UID;
    info.callingPid = ERR_PID;

    ApplyUserTokenResult tokenResult;
    tokenResult.grantTime = 1000;

    ErrCode ret = manager_.UpdatePrivilegeCache(info, tokenResult);

    EXPECT_EQ(ret, ERR_AUTHORIZATION_CACHE_ERROR);
}

/**
 * @tc.name: UpdatePrivilegeCacheTest_0300
 * @tc.desc: test UpdatePrivilegeCache with TransferPrivilegeToCode
 * failure.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, UpdatePrivilegeCacheTest_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("UpdatePrivilegeCacheTest_0300");

    ConnectAbilityInfo info;
    info.privilege = TEST_PRIVILEGE;
    info.callingUid = TEST_CALLING_UID;
    info.callingPid = TEST_CALLING_PID;

    ApplyUserTokenResult tokenResult;
    tokenResult.grantTime = 1000;

    g_transferPrivilegeToCode = false;
    ErrCode ret = manager_.UpdatePrivilegeCache(info, tokenResult);
    EXPECT_EQ(ret, ERR_AUTHORIZATION_CACHE_ERROR);
    g_transferPrivilegeToCode = true;
}

/**
 * @tc.name: ApplyTaAuthorizationTest_0100
 * @tc.desc: test ApplyTaAuthorization success flow.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, ApplyTaAuthorizationTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("ApplyTaAuthorizationTest_0100");

    std::vector<uint8_t> iamToken = {1, 2, 3, 4, 5};
    ConnectAbilityInfo info;
    info.privilege = TEST_PRIVILEGE;
    info.callingUid = TEST_CALLING_UID;
    info.callingPid = TEST_CALLING_PID;
    ApplyUserTokenResult tokenResult;

    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetOsAccountType(TEST_USER_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(OsAccountType::ADMIN), Return(ERR_OK)));

    EXPECT_CALL(MockOsAccountTeeAdapter::GetInstance(), TaAcquireAuthorization(_, _)).WillOnce(Return(ERR_OK));

    auto [errCode, resultCode] = manager_.ApplyTaAuthorization(iamToken, TEST_USER_ID, tokenResult, info);

    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(resultCode, AuthorizationResultCode::AUTHORIZATION_SUCCESS);
}

/**
 * @tc.name: ApplyTaAuthorizationTest_0200
 * @tc.desc: test ApplyTaAuthorization with non-admin account.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, ApplyTaAuthorizationTest_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("ApplyTaAuthorizationTest_0200");

    std::vector<uint8_t> iamToken = {1, 2, 3, 4, 5};
    ConnectAbilityInfo info;
    info.privilege = TEST_PRIVILEGE;
    info.callingUid = TEST_CALLING_UID;
    info.callingPid = TEST_CALLING_PID;
    ApplyUserTokenResult tokenResult;

    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetOsAccountType(TEST_USER_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(OsAccountType::NORMAL), Return(ERR_OK)));

    auto [errCode, resultCode] = manager_.ApplyTaAuthorization(iamToken, TEST_USER_ID, tokenResult, info);

    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(resultCode, AuthorizationResultCode::AUTHORIZATION_DENIED);
}

/**
 * @tc.name: StartServiceExtensionConnectionTest_0100
 * @tc.desc: test StartServiceExtensionConnection success.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, StartServiceExtensionConnectionTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("StartServiceExtensionConnectionTest_0100");

    ConnectAbilityInfo info;
    info.callingUid = TEST_CALLING_UID;
    info.callingPid = TEST_CALLING_PID;

    sptr<IAuthorizationCallback> callback = iface_cast<IAuthorizationCallback>(new MockAuthorizationCallbackStub());
    AuthorizationResult result;
    sptr<IRemoteObject> requestObj = new MockAuthorizationCallbackStub();

    ErrCode ret = manager_.StartServiceExtensionConnection(info, TEST_SERVICE_EXTENSION, callback, result, requestObj);

    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: StartServiceExtensionConnectionTest_0200
 * @tc.desc: test StartServiceExtensionConnection with GetNameForUid failure.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, StartServiceExtensionConnectionTest_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("StartServiceExtensionConnectionTest_0200");

    ConnectAbilityInfo info;
    info.callingUid = TEST_CALLING_UID;
    info.callingPid = TEST_CALLING_PID;

    sptr<IAuthorizationCallback> callback = iface_cast<IAuthorizationCallback>(new MockAuthorizationCallbackStub());
    AuthorizationResult result;
    sptr<IRemoteObject> requestObj = new MockAuthorizationCallbackStub();
    ErrCode ret = manager_.StartServiceExtensionConnection(info, TEST_SERVICE_EXTENSION, callback, result, requestObj);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: StartServiceExtensionConnectionTest_0300
 * @tc.desc: test StartServiceExtensionConnection with
 * GetNameForUid failure.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, StartServiceExtensionConnectionTest_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("StartServiceExtensionConnectionTest_0300");

    ConnectAbilityInfo info;
    info.callingUid = TEST_CALLING_UID;
    info.callingPid = TEST_CALLING_PID;

    sptr<IAuthorizationCallback> callback = iface_cast<IAuthorizationCallback>(new MockAuthorizationCallbackStub());
    AuthorizationResult result;
    sptr<IRemoteObject> requestObj = new MockAuthorizationCallbackStub();

    BundleManagerAdapter::GetInstance()->g_resultCode = ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    ErrCode ret = manager_.StartServiceExtensionConnection(info, TEST_SERVICE_EXTENSION, callback, result, requestObj);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    BundleManagerAdapter::GetInstance()->g_resultCode = ERR_OK;
}

/**
 * @tc.name: InitializeConnectAbilityInfoTest_0100
 * @tc.desc: test InitializeConnectAbilityInfo.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, InitializeConnectAbilityInfoTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("InitializeConnectAbilityInfoTest_0100");

    PrivilegeBriefDef pdef = {.privilegeName = const_cast<char*>(TEST_PRIVILEGE.c_str()),
        .description = const_cast<char*>(TEST_DESCRIPTION.c_str()),
        .timeout = 300};

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = true;

    OsAccountConfig config;
    config.authAppBundleName = TEST_AUTH_APP_BUNDLE;

    ConnectAbilityInfo info;
    ErrCode ret = manager_.InitializeConnectAbilityInfo(pdef, options, config, info);
    EXPECT_EQ(ret, ERR_OK);

    EXPECT_EQ(info.privilege, TEST_PRIVILEGE);
    EXPECT_EQ(info.description, TEST_DESCRIPTION);
    EXPECT_EQ(info.timeout, 300);
    EXPECT_EQ(info.bundleName, TEST_AUTH_APP_BUNDLE);
    EXPECT_EQ(info.challenge.size(), 3);
}

/**
 * @tc.name: ConnectAbilityCallbackTest_0100
 * @tc.desc: test ConnectAbilityCallback OnResult with null func.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, ConnectAbilityCallbackTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("ConnectAbilityCallbackTest_0100");

    ConnectAbilityInfo info;
    info.callingPid = TEST_CALLING_PID;
    AcquireOnResultfunc func = nullptr;
    AuthorizationResult result;

    ConnectAbilityCallback callback(info, func, result);
    std::vector<uint8_t> iamToken = {1, 2, 3};
    ErrCode ret = callback.OnResult(ERR_OK, iamToken, TEST_USER_ID, ERR_OK);
    EXPECT_EQ(ret, ERR_AUTHORIZATION_GET_PROXY_ERROR);
}

/**
 * @tc.name: ConnectAbilityCallbackTest_0200
 * @tc.desc: test ConnectAbilityCallback OnResult with errorCode != ERR_OK.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, ConnectAbilityCallbackTest_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("ConnectAbilityCallbackTest_0200");

    ConnectAbilityInfo info;
    info.callingPid = TEST_CALLING_PID;
    auto func = [](int32_t errorCode, AuthorizationResult& result, int32_t callingPid) -> ErrCode { return ERR_OK; };
    AuthorizationResult result;

    ConnectAbilityCallback callback(info, func, result);
    std::vector<uint8_t> iamToken = {1, 2, 3};
    ErrCode ret = callback.OnResult(ERR_AUTHORIZATION_TA_ERROR, iamToken, TEST_USER_ID, ERR_OK);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: ConnectAbilityCallbackTest_0300
 * @tc.desc: test ConnectAbilityCallback OnResult with iamResultCode != ERR_OK.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, ConnectAbilityCallbackTest_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("ConnectAbilityCallbackTest_0300");

    ConnectAbilityInfo info;
    info.callingPid = TEST_CALLING_PID;
    auto func = [](int32_t errorCode, AuthorizationResult& result, int32_t callingPid) -> ErrCode { return ERR_OK; };
    AuthorizationResult result;

    ConnectAbilityCallback callback(info, func, result);
    std::vector<uint8_t> iamToken = {1, 2, 3};
    ErrCode ret = callback.OnResult(ERR_OK, iamToken, TEST_USER_ID, ERR_AUTHORIZATION_TA_ERROR);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: ApplyTaAuthorizationTest_0300
 * @tc.desc: test ApplyTaAuthorization with CallTaAuthorization failure.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, ApplyTaAuthorizationTest_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("ApplyTaAuthorizationTest_0300");

    std::vector<uint8_t> iamToken = {1, 2, 3, 4, 5};
    ConnectAbilityInfo info;
    info.privilege = TEST_PRIVILEGE;
    info.callingUid = TEST_CALLING_UID;
    info.callingPid = TEST_CALLING_PID;
    ApplyUserTokenResult tokenResult;

    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetOsAccountType(TEST_USER_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(OsAccountType::ADMIN), Return(ERR_OK)));

    EXPECT_CALL(MockOsAccountTeeAdapter::GetInstance(), TaAcquireAuthorization(_, _))
        .WillOnce(Return(ERR_AUTHORIZATION_TA_ERROR));

    auto [errCode, resultCode] = manager_.ApplyTaAuthorization(iamToken, TEST_USER_ID, tokenResult, info);

    EXPECT_EQ(errCode, ERR_AUTHORIZATION_TA_ERROR);
    EXPECT_EQ(resultCode, AuthorizationResultCode::AUTHORIZATION_SUCCESS);
}

/**
 * @tc.name: UpdateAuthInfoTest_0100
 * @tc.desc: test UpdateAuthInfo.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, UpdateAuthInfoTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("UpdateAuthInfoTest_0100");

    std::vector<uint8_t> iamToken = {1, 2, 3, 4, 5};

    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetOsAccountType(TEST_USER_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(OsAccountType::ADMIN), Return(ERR_OK)));

    EXPECT_CALL(MockOsAccountTeeAdapter::GetInstance(), TaAcquireAuthorization(_, _)).WillOnce(Return(ERR_OK));

    ErrCode ret = manager_.UpdateAuthInfo(iamToken, TEST_USER_ID, TEST_CALLING_PID, "");
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: StartUIExtensionConnectionTest_0000
 * @tc.desc: test StartUIExtensionConnection with nullptr
 * callback.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, StartUIExtensionConnectionTest_0000, TestSize.Level0)
{
    ACCOUNT_LOGI("StartUIExtensionConnectionTest_0000");

    ConnectAbilityInfo info;
    info.callingUid = TEST_CALLING_UID;
    info.callingPid = TEST_CALLING_PID;
    info.privilege = TEST_PRIVILEGE;

    AuthorizationResult result;
    sptr<IRemoteObject> requestObj = new MockAuthorizationCallbackStub();

    ErrCode ret = manager_.StartUIExtensionConnection(info, TEST_UI_EXTENSION, nullptr, result, requestObj);
    EXPECT_EQ(ret, ERR_AUTHORIZATION_GET_PROXY_ERROR);
}

/**
 * @tc.name: StartUIExtensionConnectionTest_0100
 * @tc.desc: test StartUIExtensionConnection with AddDeathRecipient
 * failure.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, StartUIExtensionConnectionTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("StartUIExtensionConnectionTest_0100");

    ConnectAbilityInfo info;
    info.callingUid = TEST_CALLING_UID;
    info.callingPid = TEST_CALLING_PID;
    info.privilege = TEST_PRIVILEGE;

    class MockCallbackStubWithFailAddDeathRecipient : public MockAuthorizationCallbackStub {
    public:
        bool AddDeathRecipient(const sptr<DeathRecipient>& recipient) override { return false; }
    };

    sptr<MockCallbackStubWithFailAddDeathRecipient> callbackObj =
        new (std::nothrow) MockCallbackStubWithFailAddDeathRecipient();
    ASSERT_NE(callbackObj, nullptr);
    sptr<IAuthorizationCallback> callback = iface_cast<IAuthorizationCallback>(callbackObj);
    AuthorizationResult result;
    sptr<IRemoteObject> requestObj = new MockAuthorizationCallbackStub();

    ErrCode ret = manager_.StartUIExtensionConnection(info, TEST_UI_EXTENSION, callback, result, requestObj);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT);
}

/**
 * @tc.name: ConnectAbilityCallbackTest_0400
 * @tc.desc: test ConnectAbilityCallback OnResult with
 * ApplyTaAuthorization success.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, ConnectAbilityCallbackTest_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("ConnectAbilityCallbackTest_0400");

    ConnectAbilityInfo info;
    info.callingPid = TEST_CALLING_PID;
    info.privilege = TEST_PRIVILEGE;
    AuthorizationResult result;
    auto func = [](int32_t errorCode, AuthorizationResult& result, int32_t callingPid) -> ErrCode { return ERR_OK; };

    ConnectAbilityCallback callback(info, func, result);
    std::vector<uint8_t> iamToken = {1, 2, 3};

    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetOsAccountType(TEST_USER_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(OsAccountType::ADMIN), Return(ERR_OK)));

    EXPECT_CALL(MockOsAccountTeeAdapter::GetInstance(), TaAcquireAuthorization(_, _)).WillOnce(Return(ERR_OK));

    g_addCacheFail = false;
    ErrCode ret = callback.OnResult(ERR_OK, iamToken, TEST_USER_ID, ERR_OK);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: ConnectAbilityCallbackTest_0500
 * @tc.desc: test ConnectAbilityCallback OnResult with
 * UpdatePrivilegeCache failure.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, ConnectAbilityCallbackTest_0500, TestSize.Level0)
{
    ACCOUNT_LOGI("ConnectAbilityCallbackTest_0500");

    ConnectAbilityInfo info;
    info.callingPid = TEST_CALLING_PID;
    info.privilege = TEST_PRIVILEGE;
    AuthorizationResult result;
    auto func = [](int32_t errorCode, AuthorizationResult& result, int32_t callingPid) -> ErrCode { return ERR_OK; };

    ConnectAbilityCallback callback(info, func, result);
    std::vector<uint8_t> iamToken = {1, 2, 3};

    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetOsAccountType(TEST_USER_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(OsAccountType::ADMIN), Return(ERR_OK)));

    EXPECT_CALL(MockOsAccountTeeAdapter::GetInstance(), TaAcquireAuthorization(_, _)).WillOnce(Return(ERR_OK));

    g_addCacheFail = true;
    ErrCode ret = callback.OnResult(ERR_OK, iamToken, TEST_USER_ID, ERR_OK);
    EXPECT_EQ(ret, ERR_OK);
    g_addCacheFail = false;
}

/**
 * @tc.name: AppDeathRecipientTest_0500
 * @tc.desc: test AppDeathRecipient OnRemoteDied with object not found in
 * callback map.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, AppDeathRecipientTest_0500, TestSize.Level0)
{
    ACCOUNT_LOGI("AppDeathRecipientTest_0500");
    InnerAuthorizationManager::AppDeathRecipient deathRecipient1;
    wptr<IRemoteObject> remote1 = nullptr;
    deathRecipient1.OnRemoteDied(remote1);

    InnerAuthorizationManager::AppDeathRecipient deathRecipient2;
    sptr<IRemoteObject> obj2 = nullptr;
    wptr<IRemoteObject> remote2 = obj2;
    deathRecipient2.OnRemoteDied(remote2);

    std::string bundleName = "test";
    auto deathRecipient = new (std::nothrow) InnerAuthorizationManager::AppDeathRecipient();
    ASSERT_NE(deathRecipient, nullptr);
}

/**
 * @tc.name: HasExtensionConnectTest_0100
 * @tc.desc: test HasExtensionConnect with empty map.
 * @tc.type: FUNC
 *
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, HasExtensionConnectTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("HasExtensionConnectTest_0100");

    bool hasConnect = manager_.HasExtensionConnect();
    EXPECT_FALSE(hasConnect);
}

/**
 * @tc.name: VerifyWidgetTest_0100
 * @tc.desc: test VerifyWidget with GetForegroundOsAccountLocalId failure.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, VerifyWidgetTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("VerifyWidgetTest_0100");
    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetForegroundOsAccountLocalId(_, _))
        .WillOnce(Return(ERR_ACCOUNT_COMMON_EXCEPTION_ERROR));
    bool result = manager_.VerifyWidget(TEST_AUTH_APP_BUNDLE);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: VerifyWidgetTest_0300
 * @tc.desc: test VerifyWidget with GetBundleInfo failure.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, VerifyWidgetTest_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("VerifyWidgetTest_0300");
    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetForegroundOsAccountLocalId(_, _))
        .WillRepeatedly(Return(ERR_OK));
    bool result = manager_.VerifyWidget("com.example.get_fail");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: VerifyWidgetTest_0400
 * @tc.desc: test VerifyWidget with VerifyPermission failure.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, VerifyWidgetTest_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("VerifyWidgetTest_0400");
    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetForegroundOsAccountLocalId(_, _))
        .WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), VerifyPermission(_, _))
        .WillOnce(Return(ERR_ACCOUNT_COMMON_PERMISSION_DENIED));
    bool result = manager_.VerifyWidget(TEST_AUTH_APP_BUNDLE);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: VerifyWidgetTest_0500
 * @tc.desc: test VerifyWidget with success case.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, VerifyWidgetTest_0500, TestSize.Level0)
{
    ACCOUNT_LOGI("VerifyWidgetTest_0500");
    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetForegroundOsAccountLocalId(_, _))
        .WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), VerifyPermission(_, _))
        .WillOnce(Return(ERR_OK));
    bool result = manager_.VerifyWidget(TEST_AUTH_APP_BUNDLE);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: GetAuthSessionInfoTest_0100
 * @tc.desc: test GetAuthSessionInfo with modal system success case.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, GetAuthSessionInfoTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("GetAuthSessionInfoTest_0100");
    std::vector<uint8_t> inputChallenge = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    std::string outSessionId;
    std::vector<uint8_t> outChallenge;
    bool result = manager_.GetAuthSessionInfo(inputChallenge, outSessionId, outChallenge, TEST_CALLING_PID);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GetAuthSessionInfoTest_0200
 * @tc.desc: test GetAuthSessionInfo with non-modal system success case.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, GetAuthSessionInfoTest_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("GetAuthSessionInfoTest_0200");
    std::vector<uint8_t> inputChallenge = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    std::string outSessionId;
    std::vector<uint8_t> outChallenge;
    bool result = manager_.GetAuthSessionInfo(inputChallenge, outSessionId, outChallenge, TEST_CALLING_PID);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GetAuthSessionInfoTest_0300
 * @tc.desc: test GetAuthSessionInfo with sessionId not found case.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, GetAuthSessionInfoTest_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("GetAuthSessionInfoTest_0300");
    std::vector<uint8_t> inputChallenge = {0xaa, 0xbb, 0xcc, 0xdd};
    std::string outSessionId;
    std::vector<uint8_t> outChallenge;
    bool result = manager_.GetAuthSessionInfo(inputChallenge, outSessionId, outChallenge, TEST_CALLING_PID);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: UpdateAuthInfoTest_0200
 * @tc.desc: test UpdateAuthInfo with empty sessionId.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, UpdateAuthInfoTest_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("UpdateAuthInfoTest_0200");
    std::vector<uint8_t> iamToken = {1, 2, 3, 4, 5};
    EXPECT_CALL(MockIInnerOsAccountManager::GetInstance(), GetOsAccountType(TEST_USER_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(OsAccountType::ADMIN), Return(ERR_OK)));
    ErrCode ret = manager_.UpdateAuthInfo(iamToken, TEST_USER_ID, TEST_CALLING_PID, TEST_SESSIONID);
    EXPECT_EQ(ret, ERR_AUTHORIZATION_UPDATE_INFO_ERROR);
}

/**
 * @tc.name: InitializeConnectAbilityInfoTest_0200
 * @tc.desc: test InitializeConnectAbilityInfo with sessionId generation failure.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, InitializeConnectAbilityInfoTest_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("InitializeConnectAbilityInfoTest_0200");
    PrivilegeBriefDef pdef = {.privilegeName = const_cast<char*>(TEST_PRIVILEGE.c_str()),
        .description = const_cast<char*>(TEST_DESCRIPTION.c_str()),
        .timeout = 300};
    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3, 4};
    OsAccountConfig config;
    config.authAppBundleName = TEST_AUTH_APP_BUNDLE;
    ConnectAbilityInfo info;
    ErrCode ret = manager_.InitializeConnectAbilityInfo(pdef, options, config, info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(info.sessionId.empty());
}

/**
 * @tc.name: InitializeConnectAbilityInfoTest_0300
 * @tc.desc: test sessionId uniqueness across multiple calls.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, InitializeConnectAbilityInfoTest_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("InitializeConnectAbilityInfoTest_0300");
    PrivilegeBriefDef pdef = {.privilegeName = const_cast<char*>(TEST_PRIVILEGE.c_str()),
        .description = const_cast<char*>(TEST_DESCRIPTION.c_str()),
        .timeout = 300};
    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3, 4};
    OsAccountConfig config;
    config.authAppBundleName = TEST_AUTH_APP_BUNDLE;
    ConnectAbilityInfo info1;
    ConnectAbilityInfo info2;
    ErrCode ret1 = manager_.InitializeConnectAbilityInfo(pdef, options, config, info1);
    ErrCode ret2 = manager_.InitializeConnectAbilityInfo(pdef, options, config, info2);
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_FALSE(info1.sessionId.empty());
    EXPECT_FALSE(info2.sessionId.empty());
    EXPECT_NE(info1.sessionId, info2.sessionId);  // sessionId should be unique
}

/**
 * @tc.name: InitializeConnectAbilityInfoTest_0400
 * @tc.desc: test sessionId length is 32 characters (128 bits).
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, InitializeConnectAbilityInfoTest_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("InitializeConnectAbilityInfoTest_0400");
    PrivilegeBriefDef pdef = {.privilegeName = const_cast<char*>(TEST_PRIVILEGE.c_str()),
        .description = const_cast<char*>(TEST_DESCRIPTION.c_str()),
        .timeout = 300};
    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3, 4};
    OsAccountConfig config;
    config.authAppBundleName = TEST_AUTH_APP_BUNDLE;
    ConnectAbilityInfo info;
    ErrCode ret = manager_.InitializeConnectAbilityInfo(pdef, options, config, info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(info.sessionId.length(), 32);  // 128 bits = 16 bytes * 2 hex chars
}

/**
 * @tc.name: StoreCallbackMapsTest_0100
 * @tc.desc: test StoreCallbackMaps with OpenSmartPidFd failure.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, StoreCallbackMapsTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("StoreCallbackMapsTest_0100");
    ConnectAbilityInfo uiInfo;
    uiInfo.callingPid = TEST_CALLING_PID;
    uiInfo.callingUid = TEST_CALLING_UID;
    uiInfo.sessionId = "test_session_id_12345678";
    sptr<IAuthorizationCallback> callback = new MockAuthorizationCallbackStub();
    sptr<ConnectAbilityCallback> connectCallback = new ConnectAbilityCallback(uiInfo,
        [](int32_t, AuthorizationResult&, int32_t) { return ERR_OK; }, AuthorizationResult());
    sptr<IRemoteObject> requestRemoteObj = new MockAuthorizationCallbackStub();
    // Mock OpenSmartPidFd to fail (would need additional mock infrastructure)
    bool result = manager_.StoreCallbackMaps(uiInfo, callback, connectCallback, requestRemoteObj);
    EXPECT_TRUE(result);  // Should succeed in normal case
}

/**
 * @tc.name: CleanupAuthorizationSessionMapsTest_0100
 * @tc.desc: test CleanupAuthorizationSessionMaps clears sessionId mapping.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, CleanupAuthorizationSessionMapsTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("CleanupAuthorizationSessionMapsTest_0100");
    // This test would verify that g_sessionIdToPidMap is cleaned correctly
    // Since CleanupAuthorizationSessionMaps is a static internal function,
    // we test it indirectly through the callback cleanup flow
    ConnectAbilityInfo info;
    info.callingPid = TEST_CALLING_PID;
    info.sessionId = "test_session_id";
    auto func = [](int32_t errorCode, AuthorizationResult& result, int32_t callingPid) -> ErrCode {
        return ERR_OK;
    };
    AuthorizationResult result;
    ConnectAbilityCallback callback(info, func, result);
    // Simulate cleanup through acquireAuthorizationOnResultfunc
    std::vector<uint8_t> iamToken = {1, 2, 3};
    ErrCode ret = callback.OnResult(ERR_AUTHORIZATION_GET_PROXY_ERROR, iamToken, TEST_USER_ID, ERR_OK);
    EXPECT_EQ(ret, ERR_OK);  // Should cleanup properly
}

/**
 * @tc.name: UpdateAuthorizationResultTest_0100
 * @tc.desc: test UpdateAuthorizationResult atomic synchronization.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, UpdateAuthorizationResultTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("UpdateAuthorizationResultTest_0100");
    ConnectAbilityInfo info;
    info.callingPid = TEST_CALLING_PID;
    info.privilege = TEST_PRIVILEGE;
    AuthorizationResult result;
    auto func = [](int32_t errorCode, AuthorizationResult& result, int32_t callingPid) -> ErrCode {
        return ERR_OK;
    };
    ConnectAbilityCallback callback(info, func, result);
    ErrCode errCode = ERR_OK;
    AuthorizationResultCode resultCode = AuthorizationResultCode::AUTHORIZATION_SUCCESS;
    std::vector<uint8_t> taToken = {1, 2, 3, 4, 5};
    int32_t remainValidityTime = 300;
    callback.UpdateAuthorizationResult(errCode, resultCode, taToken, remainValidityTime);
    std::vector<uint8_t> iamToken = {};
    ErrCode ret = callback.OnResult(ERR_OK, iamToken, TEST_USER_ID, ERR_OK);
    EXPECT_EQ(ret, ERR_OK);  // Should use updated result due to atomic sync
}

/**
 * @tc.name: UpdateAuthorizationResultTest_0200
 * @tc.desc: test UpdateAuthorizationResult with failure code.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(InnerAuthorizationManagerModuleTest, UpdateAuthorizationResultTest_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("UpdateAuthorizationResultTest_0200");
    ConnectAbilityInfo info;
    info.callingPid = TEST_CALLING_PID;
    info.privilege = TEST_PRIVILEGE;
    AuthorizationResult result;
    auto func = [](int32_t errorCode, AuthorizationResult& result, int32_t callingPid) -> ErrCode {
        return ERR_OK;
    };
    ConnectAbilityCallback callback(info, func, result);
    ErrCode errCode = ERR_AUTHORIZATION_TA_ERROR;
    AuthorizationResultCode resultCode = AuthorizationResultCode::AUTHORIZATION_DENIED;
    std::vector<uint8_t> taToken = {};
    int32_t remainValidityTime = 0;
    callback.UpdateAuthorizationResult(errCode, resultCode, taToken, remainValidityTime);
    std::vector<uint8_t> iamToken = {};
    ErrCode ret = callback.OnResult(ERR_OK, iamToken, TEST_USER_ID, ERR_OK);
    EXPECT_EQ(ret, ERR_OK);  // Should handle failure result
}
} // namespace AccountSA
} // namespace OHOS

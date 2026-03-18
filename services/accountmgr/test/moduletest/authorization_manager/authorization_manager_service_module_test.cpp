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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

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
#include "inner_authorization_manager.h"
#include "os_account_control_file_manager.h"
#include "privilege_cache_manager.h"
#include "privileges_map.h"
#include "service_extension_connect.h"
#include "tee_auth_adapter.h"

#define protected public
#define private public
#include "authorization_manager_service.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
namespace OHOS {
namespace AccountSA {
namespace {
const std::string TEST_BUNDLE_NAME = "com.test.bundle";
const std::string TEST_PRIVILEGE = "ohos.privilege.MANAGE_LOCAL_ACCOUNTS";
const std::string TEST_AUTH_APP_BUNDLE = "com.example.authapp";
const std::string TEST_UI_EXTENSION = "com.example.authapp.UIExtension";
const std::string TEST_SERVICE_EXTENSION = "com.example.authapp.ServiceExtension";
// const int32_t TEST_CALLING_UID = 200100;  // UID for account 100
static bool g_hasConnect = false;
static int32_t g_callbackOnResult = ERR_OK;
static bool g_getPrivilegeBriefDef = false;
static bool g_transferPrivilegeToCode = false;
static bool g_hasExtensionConnect = true;
static ErrCode g_checkPrivilegeResult = ERR_OK;
const ErrCode FAIL_CODE = -1;
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

OsAccountStateParcel* OsAccountStateParcel::Unmarshalling(Parcel& parcel)
{
    OsAccountStateParcel* stateParcel = new (std::nothrow) OsAccountStateParcel();
    return stateParcel;
}

/**
 * @class MockAuthorizationCallbackStub
 * Mock implementation of AuthorizationCallbackStub for IRemoteObject.
 */
class MockAuthorizationCallbackStub final : public AuthorizationCallbackStub {
public:
    MockAuthorizationCallbackStub() = default;
    ~MockAuthorizationCallbackStub() override = default;

    ErrCode OnResult(int32_t resultCode, const AccountSA::AuthorizationResult& result) override
    {
        std::lock_guard<std::mutex> lock(mutex);
        isReady = true;
        result_ = result;
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
        std::vector<uint8_t> iamToken;
        connectCallback->OnResult(0, iamToken, -1, -1);
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
    AccountSA::AuthorizationResult result_;
};

/**
 * @class MockAccountPermissionManager
 * Mock for AccountPermissionManager.
 */
class MockAccountPermissionManager {
public:
    static MockAccountPermissionManager& GetInstance()
    {
        static MockAccountPermissionManager instance;
        return instance;
    }

    MOCK_METHOD1(VerifyPermission, ErrCode(const std::string& permissionName));
    MOCK_METHOD1(CheckSystemApp, ErrCode(bool isCallStub));
};

SessionAbilityConnection& SessionAbilityConnection::GetInstance()
{
    static SessionAbilityConnection instance;
    return instance;
}

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

// Mock implementations
ErrCode AccountPermissionManager::VerifyPermission(const std::string& permissionName)
{
    return MockAccountPermissionManager::GetInstance().VerifyPermission(permissionName);
}

ErrCode AccountPermissionManager::CheckSystemApp(bool isCallStub)
{
    return MockAccountPermissionManager::GetInstance().CheckSystemApp(isCallStub);
}

bool SessionAbilityConnection::HasServiceConnect() { return g_hasConnect; }

ErrCode SessionAbilityConnection::RegisterAuthAppRemoteObject(int32_t callingUid,
    const sptr<IRemoteObject>& authAppRemoteObj)
{
    if (authAppRemoteObj == nullptr) {
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return ERR_OK;
}

ErrCode SessionAbilityConnection::CallbackOnResult(ErrCode errCode, AuthorizationResultCode resultCode)
{
    return g_callbackOnResult;
}

ErrCode SessionAbilityConnection::UnRegisterAuthAppRemoteObject(int32_t callingUid) { return ERR_OK; }

InnerAuthorizationManager::InnerAuthorizationManager() {}

InnerAuthorizationManager::~InnerAuthorizationManager() {}

InnerAuthorizationManager& InnerAuthorizationManager::GetInstance()
{
    static InnerAuthorizationManager instance;
    return instance;
}

bool GetPrivilegeBriefDef(const std::string& privilege, PrivilegeBriefDef& privilegeBriefDef)
{
    return g_getPrivilegeBriefDef;
}

bool TransferPrivilegeToCode(const std::string& privilegeName, uint32_t& code) { return g_transferPrivilegeToCode; }

ErrCode InnerAuthorizationManager::AcquireAuthorization(const PrivilegeBriefDef& pdef,
    const AcquireAuthorizationOptions& options,
    const OsAccountConfig& config,
    const sptr<IRemoteObject>& authorizationResultCallback,
    const sptr<IRemoteObject>& requestRemoteObj)
{
    return ERR_OK;
}

std::pair<ErrCode, AuthorizationResultCode> InnerAuthorizationManager::VerifyAdminAccount(int32_t accountId)
{
    return {ERR_OK, AuthorizationResultCode::AUTHORIZATION_SUCCESS};
}

ErrCode InnerAuthorizationManager::AcquireAdminAuthorization(int32_t accountId,
    const std::vector<uint8_t> &challenge, const sptr<IAdminAuthorizationCallback> &callback)
{
    return ERR_OK;
}

bool InnerAuthorizationManager::HasExtensionConnect() { return g_hasExtensionConnect; }

ErrCode InnerAuthorizationManager::CheckAuthorization(const uint32_t privilegeId, const int32_t pid, bool& isAuthorized)
{
    return ERR_OK;
}

ErrCode InnerAuthorizationManager::VerifyToken(const std::vector<uint8_t>& token,
    const std::string& privilege,
    const uint32_t pid,
    std::vector<uint8_t>& challenge,
    std::vector<uint8_t>& iamToken)
{
    return ERR_OK;
}

PrivilegeCacheManager& PrivilegeCacheManager::GetInstance()
{
    static PrivilegeCacheManager instance;
    return instance;
}

ErrCode PrivilegeCacheManager::CheckPrivilege(const AuthenCallerInfo& callerInfo, int32_t& remainTime)
{
    return g_checkPrivilegeResult;
}

ErrCode PrivilegeCacheManager::RemoveSingle(const AuthenCallerInfo& callerInfo) { return ERR_OK; }

class AuthorizationManagerServiceModuleTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    std::unique_ptr<AuthorizationManagerService> service_ = std::make_unique<AuthorizationManagerService>();
};

void AuthorizationManagerServiceModuleTest::SetUpTestCase() { ACCOUNT_LOGI("SetUpTestCase enter"); }

void AuthorizationManagerServiceModuleTest::TearDownTestCase() { ACCOUNT_LOGI("TearDownTestCase enter"); }

void AuthorizationManagerServiceModuleTest::SetUp()
{
    // Set default mock behaviors
    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), VerifyPermission(_)).WillRepeatedly(Return(ERR_OK));

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillRepeatedly(Return(ERR_OK));
}

void AuthorizationManagerServiceModuleTest::TearDown() {}

/**
 * @tc.name: AuthorizationManagerServiceTest_Constructor_0100
 * @tc.desc: test AuthorizationManagerService constructor.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AuthorizationManagerServiceTest_Constructor_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AuthorizationManagerServiceTest_Constructor_0100");

    ASSERT_NE(service_, nullptr);
}

/**
 * @tc.name: RegisterAuthAppRemoteObjectTest_0100
 * @tc.desc: test RegisterAuthAppRemoteObject when no service connect.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, RegisterAuthAppRemoteObjectTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("RegisterAuthAppRemoteObjectTest_0100");

    g_hasConnect = false;
    auto authAppRemoteObj = new MockAuthorizationCallbackStub();

    ErrCode ret = service_->RegisterAuthAppRemoteObject(authAppRemoteObj->AsObject());

    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: RegisterAuthAppRemoteObjectTest_0200
 * @tc.desc: test RegisterAuthAppRemoteObject with null remote object.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, RegisterAuthAppRemoteObjectTest_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("RegisterAuthAppRemoteObjectTest_0200");

    g_hasConnect = true;
    g_callbackOnResult = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;

    ErrCode ret = service_->RegisterAuthAppRemoteObject(nullptr);

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: RegisterAuthAppRemoteObjectTest_0300
 * @tc.desc: test RegisterAuthAppRemoteObject when not system app.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, RegisterAuthAppRemoteObjectTest_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("RegisterAuthAppRemoteObjectTest_0300");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_))
        .Times(2)
        .WillOnce(Return(ERR_ACCOUNT_COMMON_PERMISSION_DENIED))
        .WillOnce(Return(ERR_ACCOUNT_COMMON_PERMISSION_DENIED));

    g_hasConnect = true;
    auto authAppRemoteObj = new MockAuthorizationCallbackStub();

    ErrCode ret = service_->RegisterAuthAppRemoteObject(authAppRemoteObj->AsObject());

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    ret = service_->UnRegisterAuthAppRemoteObject();
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: RegisterAuthAppRemoteObjectTest_0400
 * @tc.desc: test RegisterAuthAppRemoteObject without START_DIALOG permission.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, RegisterAuthAppRemoteObjectTest_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("RegisterAuthAppRemoteObjectTest_0400");

    g_hasConnect = true;
    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_))
        .Times(2)
        .WillOnce(Return(ERR_OK))
        .WillOnce(Return(ERR_OK));

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(),
        VerifyPermission(std::string("ohos.permission.START_SYSTEM_DIALOG")))
        .Times(2)
        .WillOnce(Return(ERR_ACCOUNT_COMMON_PERMISSION_DENIED))
        .WillOnce(Return(ERR_ACCOUNT_COMMON_PERMISSION_DENIED));

    auto authAppRemoteObj = new MockAuthorizationCallbackStub();

    ErrCode ret = service_->RegisterAuthAppRemoteObject(authAppRemoteObj->AsObject());

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    ret = service_->UnRegisterAuthAppRemoteObject();
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: RegisterAuthAppRemoteObjectTest_0500
 * @tc.desc: test RegisterAuthAppRemoteObject without ACCESS_USER_AUTH permission.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, RegisterAuthAppRemoteObjectTest_0500, TestSize.Level0)
{
    ACCOUNT_LOGI("RegisterAuthAppRemoteObjectTest_0500");

    g_hasConnect = true;
    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillOnce(Return(ERR_OK));

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(),
        VerifyPermission(std::string("ohos.permission.START_SYSTEM_DIALOG")))
        .WillOnce(Return(ERR_OK));

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(),
        VerifyPermission(std::string("ohos.permission.ACCESS_USER_AUTH_INTERNAL")))
        .WillOnce(Return(ERR_ACCOUNT_COMMON_PERMISSION_DENIED));

    auto authAppRemoteObj = new MockAuthorizationCallbackStub();

    ErrCode ret = service_->RegisterAuthAppRemoteObject(authAppRemoteObj->AsObject());
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: RegisterAuthAppRemoteObjectTest_0600
 * @tc.desc: test RegisterAuthAppRemoteObject success.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, RegisterAuthAppRemoteObjectTest_0600, TestSize.Level0)
{
    ACCOUNT_LOGI("RegisterAuthAppRemoteObjectTest_0600");

    g_hasConnect = true;

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillOnce(Return(ERR_OK));

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), VerifyPermission(_)).WillRepeatedly(Return(ERR_OK));

    auto authAppRemoteObj = new MockAuthorizationCallbackStub();

    ErrCode ret = service_->RegisterAuthAppRemoteObject(authAppRemoteObj->AsObject());

    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: RegisterAuthAppRemoteObjectTest_0600
 * @tc.desc: test RegisterAuthAppRemoteObject not success.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, RegisterAuthAppRemoteObjectTest_0700, TestSize.Level0)
{
    ACCOUNT_LOGI("RegisterAuthAppRemoteObjectTest_0600");

    g_hasConnect = true;

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillOnce(Return(ERR_OK));

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), VerifyPermission(_)).WillRepeatedly(Return(ERR_OK));

    auto authAppRemoteObj = new MockAuthorizationCallbackStub();
    BundleManagerAdapter::GetInstance()->g_resultCode = FAIL_CODE;
    ErrCode ret =
        service_->RegisterAuthAppRemoteObject(authAppRemoteObj->AsObject());
    EXPECT_EQ(ret, FAIL_CODE);
    BundleManagerAdapter::GetInstance()->g_resultCode = ERR_OK;
}
/**
 * @tc.name: UnRegisterAuthAppRemoteObjectTest_0100
 * @tc.desc: test UnRegisterAuthAppRemoteObject.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, UnRegisterAuthAppRemoteObjectTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("UnRegisterAuthAppRemoteObjectTest_0100");

    ErrCode ret = service_->UnRegisterAuthAppRemoteObject();

    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: AcquireAuthorizationTest_0100
 * @tc.desc: test AcquireAuthorization when not system app.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AcquireAuthorizationTest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_0100");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_))
        .WillOnce(Return(ERR_ACCOUNT_COMMON_PERMISSION_DENIED));

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = true;

    auto callbackObj = new MockAuthorizationCallbackStub();
    auto requestObj = new MockAuthorizationCallbackStub();
    ErrCode ret =
        service_->AcquireAuthorization(TEST_PRIVILEGE, options, callbackObj->AsObject(), requestObj->AsObject());

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: AcquireAuthorizationTest_0200
 * @tc.desc: test AcquireAuthorization without ACQUIRE_AUTHORIZATION permission.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AcquireAuthorizationTest_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_0200");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillOnce(Return(ERR_OK));

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(),
        VerifyPermission(std::string("ohos.permission.ACQUIRE_LOCAL_ACCOUNT_AUTHORIZATION")))
        .WillOnce(Return(ERR_ACCOUNT_COMMON_PERMISSION_DENIED));

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = true;

    auto callbackObj = new MockAuthorizationCallbackStub();
    auto requestObj = new MockAuthorizationCallbackStub();

    ErrCode ret =
        service_->AcquireAuthorization(TEST_PRIVILEGE, options, callbackObj->AsObject(), requestObj->AsObject());

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: AcquireAuthorizationTest_0300
 * @tc.desc: test AcquireAuthorization with null callback.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AcquireAuthorizationTest_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_0300");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillRepeatedly(Return(ERR_OK));

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = true;
    ErrCode ret = service_->AcquireAuthorization(TEST_PRIVILEGE, options, nullptr, nullptr);

    EXPECT_EQ(ret, ERR_AUTHORIZATION_GET_PROXY_ERROR);
}

/**
 * @tc.name: AcquireAuthorizationTest_0400
 * @tc.desc: test AcquireAuthorization when system is busy.
 * @tc.type:
 * FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AcquireAuthorizationTest_0400, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_0400");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillRepeatedly(Return(ERR_OK));

    g_hasConnect = true;

    auto callbackObj = new MockAuthorizationCallbackStub();

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = false;
    options.isInteractionAllowed = true;
    options.hasContext = false;
    auto callback = iface_cast<IAuthorizationCallback>(callbackObj);
    ErrCode ret = service_->AcquireAuthorization(TEST_PRIVILEGE, options, callback->AsObject(), nullptr);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(callbackObj->result_.resultCode, AuthorizationResultCode::AUTHORIZATION_SERVICE_BUSY);
}

/**
 * @tc.name: AcquireAuthorizationTest_0500
 * @tc.desc: test AcquireAuthorization with invalid privilege.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AcquireAuthorizationTest_0500, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_0500");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillRepeatedly(Return(ERR_OK));
    g_hasConnect = false;

    // Test with invalid privilege name
    std::string invalidPrivilege = "ohos.privilege.INVALID_PRIVILEGE";

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = false;
    options.isInteractionAllowed = true;

    auto callbackObj = new MockAuthorizationCallbackStub();
    auto requestObj = new MockAuthorizationCallbackStub();
    ErrCode ret =
        service_->AcquireAuthorization(invalidPrivilege, options, callbackObj->AsObject(), requestObj->AsObject());

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AcquireAuthorizationTest_0600
 * @tc.desc: test AcquireAuthorization with invalid options.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AcquireAuthorizationTest_0600, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_0600");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillRepeatedly(Return(ERR_OK));

    g_hasConnect = false;
    g_getPrivilegeBriefDef = true;
    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = false;
    options.isInteractionAllowed = false;
    options.hasContext = false;

    auto callbackObj = new MockAuthorizationCallbackStub();
    auto requestObj = new MockAuthorizationCallbackStub();

    auto callback = iface_cast<IAuthorizationCallback>(callbackObj);
    ErrCode ret = service_->AcquireAuthorization(TEST_PRIVILEGE, options, callback->AsObject(), requestObj->AsObject());

    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: AcquireAuthorizationTest_0700
 * @tc.desc: test AcquireAuthorization with reuse needed and cache check
 * success.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AcquireAuthorizationTest_0700, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_0700");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillRepeatedly(Return(ERR_OK));

    g_hasConnect = false;
    g_getPrivilegeBriefDef = false;
    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = true;
    options.isInteractionAllowed = true;
    options.hasContext = false;

    sptr<AuthorizationCallbackStub> callbackObj = new (std::nothrow) MockAuthorizationCallbackStub();
    sptr<AuthorizationCallbackStub> requestObj = new (std::nothrow) MockAuthorizationCallbackStub();

    ErrCode ret =
        service_->AcquireAuthorization(TEST_PRIVILEGE, options, callbackObj->AsObject(), requestObj->AsObject());

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_getPrivilegeBriefDef = true;
    g_transferPrivilegeToCode = false;
    ret = service_->AcquireAuthorization(TEST_PRIVILEGE, options, callbackObj->AsObject(), requestObj->AsObject());
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_transferPrivilegeToCode = true;
    ret = service_->AcquireAuthorization(TEST_PRIVILEGE, options, callbackObj->AsObject(), requestObj->AsObject());
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: AcquireAuthorizationTest_0800
 * @tc.desc: test AcquireAuthorization with new authorization flow.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AcquireAuthorizationTest_0800, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_0800");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillRepeatedly(Return(ERR_OK));

    g_hasConnect = false;

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = false;
    options.isInteractionAllowed = true;
    options.hasContext = false;
    g_getPrivilegeBriefDef = true;
    auto callbackObj = new MockAuthorizationCallbackStub();
    auto requestObj = new MockAuthorizationCallbackStub();
    ErrCode ret =
        service_->AcquireAuthorization(TEST_PRIVILEGE, options, callbackObj->AsObject(), requestObj->AsObject());

    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: AcquireAuthorizationTest_0900
 * @tc.desc: test AcquireAuthorization with hasContext=true and
 * HasExtensionConnect=false.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AcquireAuthorizationTest_0900, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_0900");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillRepeatedly(Return(ERR_OK));

    g_hasConnect = false;
    g_hasExtensionConnect = false;
    g_getPrivilegeBriefDef = true;

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = false;
    options.isInteractionAllowed = true;
    options.hasContext = true;

    auto callbackObj = new MockAuthorizationCallbackStub();
    auto requestObj = new MockAuthorizationCallbackStub();

    ErrCode ret =
        service_->AcquireAuthorization(TEST_PRIVILEGE, options, callbackObj->AsObject(), requestObj->AsObject());

    EXPECT_NE(ret, ERR_OK);
    g_hasExtensionConnect = true;
}

/**
 * @tc.name: AcquireAuthorizationTest_1000
 * @tc.desc: test AcquireAuthorization with hasContext=false and
 * HasExtensionConnect=true.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AcquireAuthorizationTest_1000, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_1000");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillRepeatedly(Return(ERR_OK));

    g_hasConnect = false;
    g_hasExtensionConnect = true;
    g_getPrivilegeBriefDef = true;

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = false;
    options.isInteractionAllowed = true;
    options.hasContext = false;

    auto callbackObj = new MockAuthorizationCallbackStub();
    auto requestObj = new MockAuthorizationCallbackStub();

    ErrCode ret =
        service_->AcquireAuthorization(TEST_PRIVILEGE, options, callbackObj->AsObject(), requestObj->AsObject());

    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: AcquireAuthorizationTest_1100
 * @tc.desc: test AcquireAuthorization with hasContext=false and
 * HasExtensionConnect=false.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AcquireAuthorizationTest_1100, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_1100");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillRepeatedly(Return(ERR_OK));

    g_hasConnect = false;
    g_hasExtensionConnect = false;
    g_getPrivilegeBriefDef = true;

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = false;
    options.isInteractionAllowed = true;
    options.hasContext = false;

    auto callbackObj = new MockAuthorizationCallbackStub();
    auto requestObj = new MockAuthorizationCallbackStub();

    ErrCode ret =
        service_->AcquireAuthorization(TEST_PRIVILEGE, options, callbackObj->AsObject(), requestObj->AsObject());

    EXPECT_EQ(ret, ERR_OK);
    g_hasExtensionConnect = true;
}

/**
 * @tc.name: AcquireAuthorizationTest_1200
 * @tc.desc: test AcquireAuthorization with challenge size > 32.
 *
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AcquireAuthorizationTest_1200, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_1200");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillRepeatedly(Return(ERR_OK));

    g_hasConnect = false;
    g_hasExtensionConnect = false;
    g_getPrivilegeBriefDef = true;

    AcquireAuthorizationOptions options;
    options.challenge = std::vector<uint8_t>(33, 1);
    options.isReuseNeeded = false;
    options.isInteractionAllowed = true;
    options.hasContext = false;

    auto callbackObj = new MockAuthorizationCallbackStub();
    auto requestObj = new MockAuthorizationCallbackStub();

    ErrCode ret =
        service_->AcquireAuthorization(TEST_PRIVILEGE, options, callbackObj->AsObject(), requestObj->AsObject());

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_hasExtensionConnect = true;
}

/**
 * @tc.name: AcquireAuthorizationTest_1300
 * @tc.desc: test AcquireAuthorization with hasContext=true and
 * isContextValid=false.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AcquireAuthorizationTest_1300, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_1300");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillRepeatedly(Return(ERR_OK));

    g_hasConnect = false;
    g_hasExtensionConnect = false;
    g_getPrivilegeBriefDef = true;

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = false;
    options.isInteractionAllowed = true;
    options.hasContext = true;
    options.isContextValid = false;

    auto callbackObj = new MockAuthorizationCallbackStub();
    auto requestObj = new MockAuthorizationCallbackStub();

    ErrCode ret =
        service_->AcquireAuthorization(TEST_PRIVILEGE, options, callbackObj->AsObject(), requestObj->AsObject());

    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    g_hasExtensionConnect = true;
}

/**
 * @tc.name: AcquireAuthorizationTest_1400
 * @tc.desc: test AcquireAuthorization with isReuseNeeded=true,
 * CheckPrivilege failed, isInteractionAllowed=false.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AcquireAuthorizationTest_1400, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_1400");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillRepeatedly(Return(ERR_OK));

    g_hasConnect = false;
    g_hasExtensionConnect = false;
    g_getPrivilegeBriefDef = true;
    g_transferPrivilegeToCode = true;
    g_checkPrivilegeResult = ERR_ACCOUNT_COMMON_PERMISSION_DENIED;

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = true;
    options.isInteractionAllowed = false;
    options.hasContext = false;

    auto callbackObj = new MockAuthorizationCallbackStub();
    auto requestObj = new MockAuthorizationCallbackStub();

    ErrCode ret =
        service_->AcquireAuthorization(TEST_PRIVILEGE, options, callbackObj->AsObject(), requestObj->AsObject());

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(callbackObj->result_.resultCode, AuthorizationResultCode::AUTHORIZATION_INTERACTION_NOT_ALLOWED);

    g_hasExtensionConnect = true;
    g_checkPrivilegeResult = ERR_OK;
}

/**
 * @tc.name: AcquireAuthorizationTest_1500
 * @tc.desc: test AcquireAuthorization with isReuseNeeded=true,
 * CheckPrivilege failed, isInteractionAllowed=true.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(AuthorizationManagerServiceModuleTest, AcquireAuthorizationTest_1500, TestSize.Level0)
{
    ACCOUNT_LOGI("AcquireAuthorizationTest_1500");

    EXPECT_CALL(MockAccountPermissionManager::GetInstance(), CheckSystemApp(_)).WillRepeatedly(Return(ERR_OK));

    g_hasConnect = false;
    g_hasExtensionConnect = false;
    g_getPrivilegeBriefDef = true;
    g_transferPrivilegeToCode = true;
    g_checkPrivilegeResult = ERR_ACCOUNT_COMMON_PERMISSION_DENIED;

    AcquireAuthorizationOptions options;
    options.challenge = {1, 2, 3};
    options.isReuseNeeded = true;
    options.isInteractionAllowed = true;
    options.hasContext = false;

    auto callbackObj = new MockAuthorizationCallbackStub();
    auto requestObj = new MockAuthorizationCallbackStub();

    ErrCode ret =
        service_->AcquireAuthorization(TEST_PRIVILEGE, options, callbackObj->AsObject(), requestObj->AsObject());

    EXPECT_EQ(ret, ERR_OK);

    g_hasExtensionConnect = true;
    g_checkPrivilegeResult = ERR_OK;
}

} // namespace AccountSA
} // namespace OHOS

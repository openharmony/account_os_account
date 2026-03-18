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
#include <functional>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "authorization_callback.h"
#include "authorization_callback_stub.h"
#include "authorization_common.h"
#include "cJSON.h"
#include "extension_manager_client.h"
#include "iauthorization_callback.h"

#define protected public
#define private public
#include "service_extension_connect.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
namespace OHOS {
namespace AccountSA {
namespace {
const std::string TEST_BUNDLE_NAME = "com.test.bundle";
const std::string TEST_ABILITY_NAME = "com.test.bundle.MainAbility";
const std::string TEST_PRIVILEGE = "test.privilege";
const std::string TEST_DESCRIPTION = "Test privilege description";
const int32_t TEST_CALLING_PID = 200100; // UID for account 100
static bool g_addStringToJson = true;
static bool g_addIntToJson = true;
static int g_addStringToJsonCallCount = 0;
static int g_addIntToJsonCallCount = 0;
static int g_addStringToJsonFailAt = -1;
static int g_addIntToJsonFailAt = -1;
typedef cJSON CJson;
typedef std::unique_ptr<CJson, std::function<void(CJson *ptr)>> CJsonUnique;
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
class MockAuthorizationCallbackStub final : public AuthorizationCallbackStub {
public:
    MockAuthorizationCallbackStub() = default;
    ~MockAuthorizationCallbackStub() = default;
    ErrCode OnResult(int32_t resultCode, const AccountSA::AuthorizationResult& result) override { return 0; }
    ErrCode OnConnectAbility(const AccountSA::ConnectAbilityInfo& info, const sptr<IRemoteObject>& callback) override
    {
        return 0;
    }
    bool AddDeathRecipient(const sptr<DeathRecipient>& recipient) override { return addDeathRecipientResult_; }
    int SendRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
    {
        sendRequestTime++;
        return sendRequestResult_;
    }

public:
    int32_t sendRequestTime = 0;
    int32_t sendRequestResult_ = 0;
    bool addDeathRecipientResult_ = true;

private:
};

class MockAuthAppDeathRecipient : public SessionAbilityConnection::AuthAppDeathRecipient {
public:
    MockAuthAppDeathRecipient() = default;
};
class ServiceExtensionConnectModuleTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    SessionAbilityConnection& connection_ = SessionAbilityConnection::GetInstance();
};

bool AddStringToJson(CJsonUnique& jsonObj, const std::string& key, const std::string& value)
{
    g_addStringToJsonCallCount++;
    if (g_addStringToJsonCallCount == g_addStringToJsonFailAt) {
        return false;
    }
    return g_addStringToJson;
}

bool AddIntToJson(CJsonUnique& jsonObj, const std::string& key, int32_t value)
{
    g_addIntToJsonCallCount++;
    if (g_addIntToJsonCallCount == g_addIntToJsonFailAt) {
        return false;
    }
    return g_addIntToJson;
}

void ServiceExtensionConnectModuleTest::SetUpTestCase() { ACCOUNT_LOGI("SetUpTestCase enter"); }

void ServiceExtensionConnectModuleTest::TearDownTestCase() { ACCOUNT_LOGI("TearDownTestCase enter"); }

void ServiceExtensionConnectModuleTest::SetUp()
{
    // Clean up any active connections
    if (connection_.HasServiceConnect()) {
        connection_.SessionDisconnectExtension();
    }
}

void ServiceExtensionConnectModuleTest::TearDown()
{
    // Clean up any active connections
    if (connection_.HasServiceConnect()) {
        connection_.SessionDisconnectExtension();
    }
}

/**
 * @tc.name: ServiceExtensionConnectTest_GetInstance_0100
 * @tc.desc: test GetInstance singleton.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest, ServiceExtensionConnectTest_GetInstance_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("ServiceExtensionConnectTest_GetInstance_0100");

    auto& instance1 = SessionAbilityConnection::GetInstance();
    auto& instance2 = SessionAbilityConnection::GetInstance();

    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: ServiceExtensionConnectTest_HasServiceConnect_0100
 * @tc.desc: test HasServiceConnect with no connection.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest, ServiceExtensionConnectTest_HasServiceConnect_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("ServiceExtensionConnectTest_HasServiceConnect_0100");

    bool hasConnect = connection_.HasServiceConnect();
    EXPECT_FALSE(hasConnect);
    EXPECT_EQ(ERR_AUTHORIZATION_GET_STUB_ERROR, connection_.RegisterAuthAppRemoteObject(TEST_CALLING_PID, nullptr));
    AuthorizationResultCode resultCode;
    std::vector<uint8_t> iamToken;
    int32_t remainValidityTime = 0;
    EXPECT_EQ(ERR_AUTHORIZATION_GET_STUB_ERROR,
        connection_.SaveAuthorizationResult(0, resultCode, iamToken, remainValidityTime));
    EXPECT_EQ(ERR_AUTHORIZATION_GET_STUB_ERROR, connection_.CallbackOnResult(0, resultCode));
}

/**
 * @tc.name: ServiceExtensionConnectTest_SessionConnectExtension_0100
 * @tc.desc: test SessionConnectExtension success.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest, ServiceExtensionConnectTest_SessionConnectExtension_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("ServiceExtensionConnectTest_SessionConnectExtension_0100");

    ConnectAbilityInfo info;
    info.bundleName = TEST_BUNDLE_NAME;
    info.abilityName = TEST_ABILITY_NAME;
    info.callingUid = TEST_CALLING_PID;
    info.privilege = TEST_PRIVILEGE;
    info.description = TEST_DESCRIPTION;

    sptr<MockAuthorizationCallbackStub> mockCallback = new (std::nothrow) MockAuthorizationCallbackStub();
    ASSERT_NE(mockCallback, nullptr);
    sptr<IAuthorizationCallback> callback = iface_cast<IAuthorizationCallback>(mockCallback);
    AuthorizationResult result;

    ErrCode ret = connection_.SessionConnectExtension(info, callback, result);
    EXPECT_EQ(ret, ERR_OK);

    // Verify connection state
    EXPECT_TRUE(connection_.HasServiceConnect());
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, connection_.RegisterAuthAppRemoteObject(TEST_CALLING_PID, nullptr));
    sptr<MockAuthorizationCallbackStub> temp = new (std::nothrow) MockAuthorizationCallbackStub();
    ASSERT_NE(temp, nullptr);
    sptr<IAuthorizationCallback> callbackTemp = iface_cast<IAuthorizationCallback>(temp);

    EXPECT_EQ(ERR_OK, connection_.RegisterAuthAppRemoteObject(TEST_CALLING_PID, callbackTemp->AsObject()));
    ConnectAbilityInfo info2;
    bool ret1 = connection_.GetConnectInfo(TEST_CALLING_PID + 1, info2);
    EXPECT_FALSE(ret1);
    bool ret2 = connection_.GetConnectInfo(TEST_CALLING_PID, info2);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(info2.bundleName == info.bundleName);
    AuthorizationResultCode resultCode;
    std::vector<uint8_t> iamToken;
    int32_t remainValidityTime = 0;
    EXPECT_EQ(ERR_OK, connection_.SaveAuthorizationResult(0, resultCode, iamToken, remainValidityTime));
    EXPECT_EQ(ERR_AUTHORIZATION_NOT_SUPPORT, connection_.UnRegisterAuthAppRemoteObject(TEST_CALLING_PID + 1));
    EXPECT_EQ(ERR_OK, connection_.UnRegisterAuthAppRemoteObject(TEST_CALLING_PID));
    // Clean up
    connection_.SessionDisconnectExtension();
}

/**
 * @tc.name: ServiceExtensionConnectTest_SessionConnectExtension_0200
 * @tc.desc: test SessionConnectExtension with valid callback.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest, ServiceExtensionConnectTest_SessionConnectExtension_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("ServiceExtensionConnectTest_SessionConnectExtension_0200");

    ConnectAbilityInfo info;
    info.bundleName = TEST_BUNDLE_NAME;
    info.abilityName = TEST_ABILITY_NAME;
    info.callingUid = TEST_CALLING_PID;
    info.privilege = TEST_PRIVILEGE;
    info.description = TEST_DESCRIPTION;

    sptr<MockAuthorizationCallbackStub> mockCallback = new (std::nothrow) MockAuthorizationCallbackStub();
    ASSERT_NE(mockCallback, nullptr);
    sptr<IAuthorizationCallback> callback = iface_cast<IAuthorizationCallback>(mockCallback);
    AuthorizationResult result;

    ErrCode ret = connection_.SessionConnectExtension(info, callback, result);
    EXPECT_EQ(ret, ERR_OK);
    sptr<MockAuthorizationCallbackStub> connectCallback = new (std::nothrow) MockAuthorizationCallbackStub();
    ASSERT_NE(connectCallback, nullptr);
    sptr<IAuthorizationCallback> callback2 = iface_cast<IAuthorizationCallback>(connectCallback);
    AppExecFwk::ElementName element;

    connection_.abilityConnectionStub_->OnAbilityConnectDone(element, callback2->AsObject(), 0);
    EXPECT_EQ(connectCallback->sendRequestTime, 1);
    connection_.abilityConnectionStub_->OnAbilityDisconnectDone(element, 0);
    // Clean up
    connection_.SessionDisconnectExtension();
}

/**
 * @tc.name: ServiceExtensionConnectTest_SessionConnectExtension_0300
 * @tc.desc: test SessionConnectExtension when already connected.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest, ServiceExtensionConnectTest_SessionConnectExtension_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("ServiceExtensionConnectTest_SessionConnectExtension_0300");

    ConnectAbilityInfo info;
    info.bundleName = TEST_BUNDLE_NAME;
    info.abilityName = TEST_ABILITY_NAME;
    info.callingUid = TEST_CALLING_PID;
    info.privilege = TEST_PRIVILEGE;
    info.description = TEST_DESCRIPTION;

    sptr<MockAuthorizationCallbackStub> mockCallback = new (std::nothrow) MockAuthorizationCallbackStub();
    ASSERT_NE(mockCallback, nullptr);
    sptr<IAuthorizationCallback> callback = iface_cast<IAuthorizationCallback>(mockCallback);
    AuthorizationResult result;

    ErrCode ret = connection_.SessionConnectExtension(info, callback, result);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(connection_.HasServiceConnect());

    ConnectAbilityInfo info2;
    info2.bundleName = TEST_BUNDLE_NAME + "_2";
    info2.abilityName = TEST_ABILITY_NAME + "_2";
    info2.callingUid = TEST_CALLING_PID;
    info2.privilege = TEST_PRIVILEGE;
    info2.description = TEST_DESCRIPTION;

    AuthorizationResult result2;
    connection_.SessionConnectExtension(info2, callback, result2);
    EXPECT_EQ(result2.resultCode, AuthorizationResultCode::AUTHORIZATION_SERVICE_BUSY);

    connection_.SessionDisconnectExtension();
}

/**
 * @tc.name: ServiceExtensionConnectTest_ValidateConnectionResult_0100
 * @tc.desc: test ValidateConnectionResult with error result code.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest, ServiceExtensionConnectTest_ValidateConnectionResult_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("ServiceExtensionConnectTest_ValidateConnectionResult_0100");

    ConnectAbilityInfo info;
    info.bundleName = TEST_BUNDLE_NAME;
    info.abilityName = TEST_ABILITY_NAME;
    info.callingUid = TEST_CALLING_PID;
    info.privilege = TEST_PRIVILEGE;
    info.description = TEST_DESCRIPTION;

    sptr<MockAuthorizationCallbackStub> mockCallback = new (std::nothrow) MockAuthorizationCallbackStub();
    ASSERT_NE(mockCallback, nullptr);
    sptr<IAuthorizationCallback> callback = iface_cast<IAuthorizationCallback>(mockCallback);
    AuthorizationResult result;

    ErrCode ret = connection_.SessionConnectExtension(info, callback, result);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(connection_.HasServiceConnect());

    AppExecFwk::ElementName element;
    connection_.abilityConnectionStub_->OnAbilityConnectDone(element, nullptr, ERR_INVALID_VALUE);
    connection_.SessionDisconnectExtension();
}

/**
 * @tc.name: ServiceExtensionConnectTest_SendConnectionRequest_0100
 * @tc.desc: test SendConnectionRequest with remoteObject is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest, ServiceExtensionConnectTest_SendConnectionRequest_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("ServiceExtensionConnectTest_SendConnectionRequest_0100");

    ConnectAbilityInfo info;
    info.bundleName = TEST_BUNDLE_NAME;
    info.abilityName = TEST_ABILITY_NAME;
    info.callingUid = TEST_CALLING_PID;
    info.privilege = TEST_PRIVILEGE;
    info.description = TEST_DESCRIPTION;

    sptr<MockAuthorizationCallbackStub> mockCallback = new (std::nothrow) MockAuthorizationCallbackStub();
    ASSERT_NE(mockCallback, nullptr);
    sptr<IAuthorizationCallback> callback = iface_cast<IAuthorizationCallback>(mockCallback);
    AuthorizationResult result;

    ErrCode ret = connection_.SessionConnectExtension(info, callback, result);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(connection_.HasServiceConnect());

    AppExecFwk::ElementName element;
    sptr<MockAuthorizationCallbackStub> connectCallback = new (std::nothrow) MockAuthorizationCallbackStub();
    ASSERT_NE(connectCallback, nullptr);
    connectCallback->sendRequestResult_ = ERR_INVALID_VALUE;
    sptr<IAuthorizationCallback> callback2 = iface_cast<IAuthorizationCallback>(connectCallback);

    connection_.abilityConnectionStub_->OnAbilityConnectDone(element, callback2->AsObject(), ERR_OK);
    connection_.SessionDisconnectExtension();
}

/**
 * @tc.name: ServiceExtensionConnectTest_CallbackOnResult_0100
 * @tc.desc: test CallbackOnResult when callback_ is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest, ServiceExtensionConnectTest_CallbackOnResult_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("ServiceExtensionConnectTest_CallbackOnResult_0100");

    connection_.callback_ = nullptr;
    AuthorizationResultCode resultCode = AuthorizationResultCode::AUTHORIZATION_SUCCESS;
    ErrCode ret = connection_.CallbackOnResult(ERR_OK, resultCode);
    EXPECT_EQ(ret, ERR_AUTHORIZATION_GET_STUB_ERROR);
}

/**
 * @tc.name: ServiceExtensionConnectTest_SaveAuthorizationResult_0100
 * @tc.desc: test SaveAuthorizationResult when abilityConnectionStub_ is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest, ServiceExtensionConnectTest_SaveAuthorizationResult_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("ServiceExtensionConnectTest_SaveAuthorizationResult_0100");

    connection_.abilityConnectionStub_ = nullptr;
    AuthorizationResultCode resultCode = AuthorizationResultCode::AUTHORIZATION_SUCCESS;
    std::vector<uint8_t> iamToken = {1, 2, 3};
    int32_t remainValidityTime = 100;
    ErrCode ret = connection_.SaveAuthorizationResult(ERR_OK, resultCode, iamToken, remainValidityTime);
    EXPECT_EQ(ret, ERR_AUTHORIZATION_GET_STUB_ERROR);
}

/**
 * @tc.name: ServiceExtensionConnectTest_RegisterAuthAppRemoteObject_0100
 * @tc.desc: test RegisterAuthAppRemoteObject when deathRecipient creation fails.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest,
    ServiceExtensionConnectTest_RegisterAuthAppRemoteObject_0100,
    TestSize.Level0)
{
    ACCOUNT_LOGI("ServiceExtensionConnectTest_RegisterAuthAppRemoteObject_0100");

    ConnectAbilityInfo info;
    info.bundleName = TEST_BUNDLE_NAME;
    info.abilityName = TEST_ABILITY_NAME;
    info.callingUid = TEST_CALLING_PID;
    info.privilege = TEST_PRIVILEGE;
    info.description = TEST_DESCRIPTION;

    sptr<MockAuthorizationCallbackStub> mockCallback = new (std::nothrow) MockAuthorizationCallbackStub();
    ASSERT_NE(mockCallback, nullptr);
    sptr<IAuthorizationCallback> callback = iface_cast<IAuthorizationCallback>(mockCallback);
    AuthorizationResult result;

    ErrCode ret = connection_.SessionConnectExtension(info, callback, result);
    EXPECT_EQ(ret, ERR_OK);

    sptr<MockAuthorizationCallbackStub> temp = new (std::nothrow) MockAuthorizationCallbackStub();
    ASSERT_NE(temp, nullptr);
    sptr<IAuthorizationCallback> callbackTemp = iface_cast<IAuthorizationCallback>(temp);

    connection_.RegisterAuthAppRemoteObject(TEST_CALLING_PID, callbackTemp->AsObject());

    connection_.SessionDisconnectExtension();
}

/**
 * @tc.name: ServiceExtensionConnectTest_UnRegisterAuthAppRemoteObject_0100
 * @tc.desc: test UnRegisterAuthAppRemoteObject when callingUid not equal.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest,
    ServiceExtensionConnectTest_UnRegisterAuthAppRemoteObject_0100,
    TestSize.Level0)
{
    ACCOUNT_LOGI("ServiceExtensionConnectTest_UnRegisterAuthAppRemoteObject_0100");

    ConnectAbilityInfo info;
    info.bundleName = TEST_BUNDLE_NAME;
    info.abilityName = TEST_ABILITY_NAME;
    info.callingUid = TEST_CALLING_PID;
    info.privilege = TEST_PRIVILEGE;
    info.description = TEST_DESCRIPTION;

    sptr<MockAuthorizationCallbackStub> mockCallback = new (std::nothrow) MockAuthorizationCallbackStub();
    ASSERT_NE(mockCallback, nullptr);
    sptr<IAuthorizationCallback> callback = iface_cast<IAuthorizationCallback>(mockCallback);
    AuthorizationResult result;

    ErrCode ret = connection_.SessionConnectExtension(info, callback, result);
    EXPECT_EQ(ret, ERR_OK);

    sptr<MockAuthorizationCallbackStub> temp = new (std::nothrow) MockAuthorizationCallbackStub();
    ASSERT_NE(temp, nullptr);
    sptr<IAuthorizationCallback> callbackTemp = iface_cast<IAuthorizationCallback>(temp);

    EXPECT_EQ(ERR_OK, connection_.RegisterAuthAppRemoteObject(TEST_CALLING_PID, callbackTemp->AsObject()));
    EXPECT_EQ(ERR_AUTHORIZATION_NOT_SUPPORT, connection_.UnRegisterAuthAppRemoteObject(TEST_CALLING_PID + 999));
    EXPECT_EQ(ERR_OK, connection_.UnRegisterAuthAppRemoteObject(TEST_CALLING_PID));

    connection_.SessionDisconnectExtension();
}

/**
 * @tc.name: ServiceExtensionConnectTest_SessionDisconnectExtension_0100
 * @tc.desc: test SessionDisconnectExtension when abilityConnectionStub_ is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest,
    ServiceExtensionConnectTest_SessionDisconnectExtension_0100,
    TestSize.Level0)
{
    ACCOUNT_LOGI("ServiceExtensionConnectTest_SessionDisconnectExtension_0100");

    connection_.abilityConnectionStub_ = nullptr;
    connection_.SessionDisconnectExtension();
    EXPECT_FALSE(connection_.HasServiceConnect());
}

/**
 * @tc.name: ServiceExtensionConnectTest_CreateCallbackDeathRecipient_0100
 * @tc.desc: test CreateCallbackDeathRecipient when AddDeathRecipient fails.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest,
    ServiceExtensionConnectTest_CreateCallbackDeathRecipient_0100,
    TestSize.Level0)
{
    ACCOUNT_LOGI("ServiceExtensionConnectTest_CreateCallbackDeathRecipient_0100");

    ConnectAbilityInfo info;
    info.bundleName = TEST_BUNDLE_NAME;
    info.abilityName = TEST_ABILITY_NAME;
    info.callingUid = TEST_CALLING_PID;
    info.privilege = TEST_PRIVILEGE;
    info.description = TEST_DESCRIPTION;

    sptr<MockAuthorizationCallbackStub> mockCallback = new (std::nothrow) MockAuthorizationCallbackStub();
    ASSERT_NE(mockCallback, nullptr);
    mockCallback->addDeathRecipientResult_ = false;
    sptr<IAuthorizationCallback> callback = iface_cast<IAuthorizationCallback>(mockCallback);
    AuthorizationResult result;

    ErrCode ret = connection_.SessionConnectExtension(info, callback, result);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT);
}

/**
 * @tc.name: GenerateParametersTest_0300
 * @tc.desc: test GenerateParameters when AddStringToJson for privilege
 * fails.
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest, GenerateParametersTest_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("GenerateParametersTest_0300");

    ConnectAbilityInfo info;
    info.bundleName = TEST_BUNDLE_NAME;
    info.abilityName = TEST_ABILITY_NAME;
    info.callingUid = TEST_CALLING_PID;
    info.privilege = TEST_PRIVILEGE;
    info.description = TEST_DESCRIPTION;
    info.callingBundleName = TEST_BUNDLE_NAME;
    info.challenge = {1, 2, 3};

    SessionAbilityConnection::SessionAbilityConnectionStub stub(info);
    g_addStringToJsonCallCount = 0;
    g_addIntToJsonCallCount = 0;
    g_addStringToJsonFailAt = 2;
    std::string parameters;
    bool ret = stub.GenerateParameters(parameters);
    EXPECT_FALSE(ret);
    EXPECT_EQ(g_addStringToJsonCallCount, 2);
    EXPECT_EQ(g_addIntToJsonCallCount, 1);
    g_addStringToJsonFailAt = -1;
}

/**
 * @tc.name: AuthAppDeathRecipientTest_0200
 * @tc.desc: test AuthAppDeathRecipient OnRemoteDied with valid remote.

 * * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest, AuthAppDeathRecipientTest_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AuthAppDeathRecipientTest_0200");

    MockAuthAppDeathRecipient deathRecipient1;
    wptr<IRemoteObject> remote1 = nullptr;
    deathRecipient1.OnRemoteDied(remote1);

    MockAuthAppDeathRecipient deathRecipient2;
    sptr<MockAuthorizationCallbackStub> obj2 = new (std::nothrow) MockAuthorizationCallbackStub();
    ASSERT_NE(obj2, nullptr);
    wptr<IRemoteObject> remote2 = obj2;
    deathRecipient2.OnRemoteDied(remote2);
    ASSERT_NE(obj2, nullptr);
}

/**
 * @tc.name: AppDeathRecipientTest_0200
 * @tc.desc: test AppDeathRecipient OnRemoteDied with nullptr remote.
 *
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest, AppDeathRecipientTest_0200, TestSize.Level0)
{
    ACCOUNT_LOGI("AppDeathRecipientTest_0200");

    std::string bundleName = "test";
    auto deathRecipient = new (std::nothrow) SessionAbilityConnection::AppDeathRecipient(bundleName);
    ASSERT_NE(deathRecipient, nullptr);
    wptr<IRemoteObject> remote = nullptr;
    deathRecipient->OnRemoteDied(remote);
    ASSERT_NE(deathRecipient, nullptr);
}

/**
 * @tc.name: AppDeathRecipientTest_0300
 * @tc.desc: test AppDeathRecipient OnRemoteDied with valid remote.
 *
 * @tc.type: FUNC
 * @tc.require: issueIXXXXX
 */
HWTEST_F(ServiceExtensionConnectModuleTest, AppDeathRecipientTest_0300, TestSize.Level0)
{
    ACCOUNT_LOGI("AppDeathRecipientTest_0300");

    std::string bundleName = "test";
    auto deathRecipient = new (std::nothrow) SessionAbilityConnection::AppDeathRecipient(bundleName);
    ASSERT_NE(deathRecipient, nullptr);
    sptr<MockAuthorizationCallbackStub> obj = new (std::nothrow) MockAuthorizationCallbackStub();
    ASSERT_NE(obj, nullptr);
    wptr<IRemoteObject> remote = obj;
    deathRecipient->OnRemoteDied(remote);
    ASSERT_NE(obj, nullptr);
}

} // namespace AccountSA
} // namespace OHOS

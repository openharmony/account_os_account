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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <thread>

#include "account_log_wrapper.h"
#include "app_account_common.h"
#define private public
#include "app_account_authenticator_callback.h"
#include "app_account_authenticator_manager.h"
#include "app_account_authenticator_proxy.h"
#include "app_account_authenticator_stub.h"
#include "app_account_constants.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IAppAccountAuthenticator");
namespace {
const std::string STRING_NAME = "name";
const std::string STRING_AUTH_TYPE = "test.authType";
const std::string STRING_ABILITY_NAME = "test.mainAbility";
const std::string CALLER_BUNDLE_NAME = "test.callerbundlename";
const uint32_t SET_PROPERTIES = 4;
}  // namespace

class MockAuthenticatorCallback final : public AppAccountAuthenticatorCallbackStub {
public:
    MOCK_METHOD2(OnResult, void(int32_t resultCode, const AAFwk::Want &result));
    MOCK_METHOD1(OnRequestRedirected, void(AAFwk::Want &request));
    MOCK_METHOD0(OnRequestContinued, void());
};

class MockAppAccountAuthenticator : public AppAccountAuthenticatorStub {
public:
    ErrCode AddAccountImplicitly(const std::string &authType, const std::string &callerBundleName,
        const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback);
    ErrCode Authenticate(
        const std::string &name, const std::string &authType, const std::string &callerBundleName,
        const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback);
    ErrCode VerifyCredential(
        const std::string &name, const VerifyCredentialOptions &options, const sptr<IRemoteObject> &callback);
    ErrCode CheckAccountLabels(
        const std::string &name, const std::vector<std::string> &labels, const sptr<IRemoteObject> &callback);
    ErrCode SetProperties(const SetPropertiesOptions &options, const sptr<IRemoteObject> &callback);
    ErrCode IsAccountRemovable(const std::string &name, const sptr<IRemoteObject> &callback);
    ErrCode CreateAccountImplicitly(
        const CreateAccountImplicitlyOptions &options, const sptr<IRemoteObject> &callback);
    ErrCode Auth(const std::string &name, const std::string &authType,
        const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback);
};

ErrCode MockAppAccountAuthenticator::AddAccountImplicitly(
    const std::string &authType, const std::string &callerBundleName,
    const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode MockAppAccountAuthenticator::Authenticate(
    const std::string &name, const std::string &authType, const std::string &callerBundleName,
    const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode MockAppAccountAuthenticator::VerifyCredential(
    const std::string &name, const VerifyCredentialOptions &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode MockAppAccountAuthenticator::CheckAccountLabels(
    const std::string &name, const std::vector<std::string> &labels, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode MockAppAccountAuthenticator::SetProperties(
    const SetPropertiesOptions &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode MockAppAccountAuthenticator::IsAccountRemovable(const std::string &name, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode MockAppAccountAuthenticator::CreateAccountImplicitly(
    const CreateAccountImplicitlyOptions &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode MockAppAccountAuthenticator::Auth(const std::string &name, const std::string &authType,
    const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

class AppAccountAuthenticateModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    sptr<AppAccountAuthenticatorProxy> authenticateProxyPtr_ = nullptr;
    sptr<MockAppAccountAuthenticator> mockServicePtr_ = nullptr;
    sptr<IRemoteObject> authenticorService_ = nullptr;
};

void AppAccountAuthenticateModuleTest::SetUpTestCase(void)
{}

void AppAccountAuthenticateModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase enter";
}

void AppAccountAuthenticateModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    mockServicePtr_ =  new (std::nothrow) MockAppAccountAuthenticator();
    ASSERT_NE(mockServicePtr_, nullptr);

    authenticorService_ = mockServicePtr_->AsObject();
    authenticateProxyPtr_ = new (std::nothrow) AppAccountAuthenticatorProxy(authenticorService_);
}

void AppAccountAuthenticateModuleTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountAuthenticateTest_CreateAccountImplicitly_0100
 * @tc.desc: test authenticate proxy func CreateAccountImplicitly.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticateTest_CreateAccountImplicitly_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountAuthenticateTest_CreateAccountImplicitly_0100");

    CreateAccountImplicitlyOptions options;
    sptr<IRemoteObject> callback = nullptr;
    options.parameters.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    ErrCode result = authenticateProxyPtr_->CreateAccountImplicitly(options, callback);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticateTest_Auth_0100
 * @tc.desc: test authenticate proxy func Auth.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticateTest_Auth_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountAuthenticateTest_Auth_0100");

    AAFwk::Want want;
    want.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    sptr<IRemoteObject> callback = nullptr;
    ErrCode result = authenticateProxyPtr_->Auth(STRING_NAME, STRING_AUTH_TYPE, want.GetParams(), callback);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticateTest_CreateAccountImplicitly_0200
 * @tc.desc: test authenticate proxy func CreateAccountImplicitly.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticateTest_CreateAccountImplicitly_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountAuthenticateTest_CreateAccountImplicitly_0200");

    CreateAccountImplicitlyOptions options;
    options.parameters.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    sptr<IAppAccountAuthenticatorCallback> oauthCallbackPtr = new (std::nothrow) MockAuthenticatorCallback();
    sptr<IRemoteObject> callback = oauthCallbackPtr->AsObject();
    EXPECT_NE(callback, nullptr);
    ErrCode result = authenticateProxyPtr_->CreateAccountImplicitly(options, callback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticateTest_Auth_0200
 * @tc.desc: test authenticate proxy func Auth.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticateTest_Auth_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountAuthenticateTest_Auth_0200");

    AAFwk::Want want;
    sptr<IAppAccountAuthenticatorCallback> oauthCallbackPtr = new (std::nothrow) MockAuthenticatorCallback();
    sptr<IRemoteObject> callback = oauthCallbackPtr->AsObject();
    EXPECT_NE(callback, nullptr);
    ErrCode result = authenticateProxyPtr_->Auth(STRING_NAME, STRING_AUTH_TYPE, want.GetParams(), callback);
    EXPECT_EQ(result, ERR_OK);
}


/**
 * @tc.name: AppAccountAuthenticateTest_AddAccountImplicitly_0100
 * @tc.desc: test authenticate proxy func AddAccountImplicitly.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticateTest_AddAccountImplicitly_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountAuthenticateTest_AddAccountImplicitly_0100");
    AAFwk::Want want;
    sptr<IRemoteObject> callback = nullptr;
    ErrCode result =
        authenticateProxyPtr_->AddAccountImplicitly(STRING_AUTH_TYPE, CALLER_BUNDLE_NAME, want.GetParams(), callback);
    EXPECT_NE(result, ERR_OK);

    want.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    result =
        authenticateProxyPtr_->AddAccountImplicitly(STRING_AUTH_TYPE, CALLER_BUNDLE_NAME, want.GetParams(), callback);
    EXPECT_NE(result, ERR_OK);

    sptr<IAppAccountAuthenticatorCallback> oauthCallbackPtr = new (std::nothrow) MockAuthenticatorCallback();
    ASSERT_NE(oauthCallbackPtr, nullptr);
    callback = oauthCallbackPtr->AsObject();
    ASSERT_NE(callback, nullptr);
    result =
        authenticateProxyPtr_->AddAccountImplicitly(STRING_AUTH_TYPE, CALLER_BUNDLE_NAME, want.GetParams(), callback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticateTest_Authenticate_0100
 * @tc.desc: test authenticate proxy func Authenticate.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticateTest_Authenticate_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountAuthenticateTest_Authenticate_0100");
    AAFwk::Want want;
    sptr<IRemoteObject> callback = nullptr;
    ErrCode result = authenticateProxyPtr_->Authenticate(
        STRING_NAME, STRING_AUTH_TYPE, CALLER_BUNDLE_NAME, want.GetParams(), callback);
    EXPECT_NE(result, ERR_OK);

    want.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    result = authenticateProxyPtr_->Authenticate(
        STRING_NAME, STRING_AUTH_TYPE, CALLER_BUNDLE_NAME, want.GetParams(), callback);
    EXPECT_NE(result, ERR_OK);

    sptr<IAppAccountAuthenticatorCallback> oauthCallbackPtr = new (std::nothrow) MockAuthenticatorCallback();
    ASSERT_NE(oauthCallbackPtr, nullptr);
    callback = oauthCallbackPtr->AsObject();
    ASSERT_NE(callback, nullptr);
    result = authenticateProxyPtr_->Authenticate(
        STRING_NAME, STRING_AUTH_TYPE, CALLER_BUNDLE_NAME, want.GetParams(), callback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticateTest_VerifyCredential_0100
 * @tc.desc: test authenticate proxy func VerifyCredential.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticateTest_VerifyCredential_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountAuthenticateTest_VerifyCredential_0100");
    VerifyCredentialOptions options;
    sptr<IRemoteObject> callback = nullptr;
    ErrCode result = authenticateProxyPtr_->VerifyCredential(STRING_NAME, options, callback);
    EXPECT_NE(result, ERR_OK);

    sptr<IAppAccountAuthenticatorCallback> oauthCallbackPtr = new (std::nothrow) MockAuthenticatorCallback();
    ASSERT_NE(oauthCallbackPtr, nullptr);
    callback = oauthCallbackPtr->AsObject();
    ASSERT_NE(callback, nullptr);
    result = authenticateProxyPtr_->VerifyCredential(STRING_NAME, options, callback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticateTest_CheckAccountLabels_0100
 * @tc.desc: test authenticate proxy func VerifyCredential.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticateTest_CheckAccountLabels_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountAuthenticateTest_CheckAccountLabels_0100");
    std::vector<std::string> labels;
    sptr<IRemoteObject> callback = nullptr;
    ErrCode result = authenticateProxyPtr_->CheckAccountLabels(STRING_NAME, labels, callback);
    EXPECT_NE(result, ERR_OK);

    sptr<IAppAccountAuthenticatorCallback> oauthCallbackPtr = new (std::nothrow) MockAuthenticatorCallback();
    ASSERT_NE(oauthCallbackPtr, nullptr);
    callback = oauthCallbackPtr->AsObject();
    ASSERT_NE(callback, nullptr);
    result = authenticateProxyPtr_->CheckAccountLabels(STRING_NAME, labels, callback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticateTest_SetProperties_0100
 * @tc.desc: test authenticate proxy func VerifyCredential.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticateTest_SetProperties_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountAuthenticateTest_SetProperties_0100");
    SetPropertiesOptions options;
    sptr<IRemoteObject> callback = nullptr;
    ErrCode result = authenticateProxyPtr_->SetProperties(options, callback);
    EXPECT_NE(result, ERR_OK);

    sptr<IAppAccountAuthenticatorCallback> oauthCallbackPtr = new (std::nothrow) MockAuthenticatorCallback();
    ASSERT_NE(oauthCallbackPtr, nullptr);
    callback = oauthCallbackPtr->AsObject();
    ASSERT_NE(callback, nullptr);
    result = authenticateProxyPtr_->SetProperties(options, callback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticateTest_IsAccountRemovable_0100
 * @tc.desc: test authenticate proxy func VerifyCredential.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticateTest_IsAccountRemovable_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountAuthenticateTest_IsAccountRemovable_0100");
    sptr<IRemoteObject> callback = nullptr;
    ErrCode result = authenticateProxyPtr_->IsAccountRemovable(STRING_NAME, callback);
    EXPECT_NE(result, ERR_OK);

    sptr<IAppAccountAuthenticatorCallback> oauthCallbackPtr = new (std::nothrow) MockAuthenticatorCallback();
    ASSERT_NE(oauthCallbackPtr, nullptr);
    callback = oauthCallbackPtr->AsObject();
    ASSERT_NE(callback, nullptr);
    result = authenticateProxyPtr_->IsAccountRemovable(STRING_NAME, callback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_GetAuthenticatorInfo_0100
 * @tc.desc: test GetAuthenticatorInfo with not init.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_GetAuthenticatorInfo_0100,
    TestSize.Level1)
{
    std::string owner = "owner";
    int32_t userId = 1;
    AuthenticatorInfo info;
    ErrCode result = AppAccountAuthenticatorManager::GetAuthenticatorInfo(owner, userId, info);
    ASSERT_NE(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0100
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0100,
    TestSize.Level1)
{
    EXPECT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(-1, data, reply, option), ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0200
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0200,
    TestSize.Level1)
{
    EXPECT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_NE(mockServicePtr_->OnRemoteRequest(-1, data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0300
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0300,
    TestSize.Level1)
{
    EXPECT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(ADD_ACCOUNT_IMPLICITLY, data, reply, option), ERR_NONE);
    int result = 0;
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0400
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0400,
    TestSize.Level1)
{
    EXPECT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(AUTHENTICATE, data, reply, option), ERR_NONE);
    int result = 0;
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0500
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0500,
    TestSize.Level1)
{
    ASSERT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = 0;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(VERIFY_CREDENTIAL, data, reply, option), ERR_NONE);
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0600
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0600,
    TestSize.Level1)
{
    ASSERT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = 0;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(CHECK_ACCOUNT_LABELS, data, reply, option), ERR_NONE);
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0700
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0700,
    TestSize.Level1)
{
    ASSERT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = 0;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(SET_PROPERTIES, data, reply, option),
        ERR_NONE);
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0800
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0800,
    TestSize.Level1)
{
    ASSERT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = 0;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(IS_ACCOUNT_REMOVABLE, data, reply, option), ERR_NONE);
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0900
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0900,
    TestSize.Level1)
{
    ASSERT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = 0;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(CREATE_ACCOUNT_IMPLICITLY, data, reply, option), ERR_NONE);
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_100
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_100,
    TestSize.Level1)
{
    ASSERT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = 0;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(AUTH, data, reply, option), ERR_NONE);
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0300
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_1100,
    TestSize.Level1)
{
    EXPECT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    AAFwk::WantParams options;
    std::string authType;
    std::string callerBundleName;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(data.WriteString(authType), true);
    EXPECT_EQ(data.WriteString(callerBundleName), true);
    EXPECT_EQ(data.WriteParcelable(&options), true);
    EXPECT_EQ(data.WriteRemoteObject(authenticorService_), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(ADD_ACCOUNT_IMPLICITLY, data, reply, option), ERR_NONE);
    int result = 0;
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0400
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_1200,
    TestSize.Level1)
{
    EXPECT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    AAFwk::WantParams options;
    std::string name;
    std::string authType;
    std::string callerBundleName;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(data.WriteString(name), true);
    EXPECT_EQ(data.WriteString(authType), true);
    EXPECT_EQ(data.WriteString(callerBundleName), true);
    EXPECT_EQ(data.WriteParcelable(&options), true);
    EXPECT_EQ(data.WriteRemoteObject(authenticorService_), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(AUTHENTICATE, data, reply, option), ERR_NONE);
    int result = 0;
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0500
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_1300,
    TestSize.Level1)
{
    ASSERT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = 0;
    VerifyCredentialOptions options;
    std::string name;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(data.WriteString(name), true);
    EXPECT_EQ(data.WriteParcelable(&options), true);
    EXPECT_EQ(data.WriteRemoteObject(authenticorService_), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(VERIFY_CREDENTIAL, data, reply, option), ERR_NONE);
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0600
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_1400,
    TestSize.Level1)
{
    ASSERT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::vector<std::string> labels;
    std::string name;
    int result = 0;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(data.WriteString(name), true);
    EXPECT_EQ(data.WriteStringVector(labels), true);
    EXPECT_EQ(data.WriteRemoteObject(authenticorService_), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(CHECK_ACCOUNT_LABELS, data, reply, option), ERR_NONE);
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0700
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_1500,
    TestSize.Level1)
{
    ASSERT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    SetPropertiesOptions options;
    int result = 0;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(data.WriteParcelable(&options), true);
    EXPECT_EQ(data.WriteRemoteObject(authenticorService_), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(SET_PROPERTIES, data, reply, option),
        ERR_NONE);
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0800
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_1600,
    TestSize.Level1)
{
    ASSERT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::string name;
    int result = 0;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(data.WriteString(name), true);
    EXPECT_EQ(data.WriteRemoteObject(authenticorService_), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(IS_ACCOUNT_REMOVABLE, data, reply, option), ERR_NONE);
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_0900
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_1700,
    TestSize.Level1)
{
    ASSERT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    CreateAccountImplicitlyOptions options;
    int result = 0;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(data.WriteParcelable(&options), true);
    EXPECT_EQ(data.WriteRemoteObject(authenticorService_), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(CREATE_ACCOUNT_IMPLICITLY, data, reply, option), ERR_NONE);
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_100
 * @tc.desc: test AppAccountAuthenticatorStub.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticatorManagerTest_AppAccountAuthenticatorStub_1800,
    TestSize.Level1)
{
    ASSERT_NE(mockServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::string name;
    std::string authType;
    AAFwk::WantParams options;
    int result = 0;
    EXPECT_EQ(data.WriteInterfaceToken(GetDescriptor()), true);
    EXPECT_EQ(data.WriteString(name), true);
    EXPECT_EQ(data.WriteString(authType), true);
    EXPECT_EQ(data.WriteParcelable(&options), true);
    EXPECT_EQ(data.WriteRemoteObject(authenticorService_), true);
    EXPECT_EQ(mockServicePtr_->OnRemoteRequest(AUTH, data, reply, option), ERR_NONE);
    reply.ReadInt32(result);
    EXPECT_EQ(result, ERR_OK);
}
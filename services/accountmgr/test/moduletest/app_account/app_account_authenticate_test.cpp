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
#define private public
#include "app_account_authenticator_callback.h"
#include "app_account_authenticator_proxy.h"
#include "app_account_authenticator_stub.h"
#include "app_account_constants.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_AUTH_TYPE = "test.authType";
const std::string STRING_ABILITY_NAME = "test.mainAbility";
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
    sptr<IAppAccountAuthenticator> authenticateProxyPtr_;
};

void AppAccountAuthenticateModuleTest::SetUpTestCase(void)
{}

void AppAccountAuthenticateModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase enter";
}

void AppAccountAuthenticateModuleTest::SetUp(void)
{
    sptr<MockAppAccountAuthenticator> mockServicePtr_ =  new (std::nothrow) MockAppAccountAuthenticator();

    sptr<IRemoteObject> authenticorService_ = mockServicePtr_->AsObject();
    authenticateProxyPtr_ = iface_cast<IAppAccountAuthenticator>(authenticorService_);
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
    EXPECT_EQ(result, ERR_OK);
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
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticateTest_CreateAccountImplicitly_0200
 * @tc.desc: test authenticate proxy func CreateAccountImplicitly.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountAuthenticateModuleTest, AppAccountAuthenticateTest_CreateAccountImplicitly_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountAuthenticateTest_CreateAccountImplicitly_0100");

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
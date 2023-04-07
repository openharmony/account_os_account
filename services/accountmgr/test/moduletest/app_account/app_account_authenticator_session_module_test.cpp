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

#include "account_log_wrapper.h"
#include "app_mgr_constants.h"
#define protected public
#define private public
#include "app_account_authenticator_session_manager.h"
#include "app_account_authenticator_session.h"
#include "app_account_constants.h"
#include "app_account_authenticator_callback.h"
#undef private
#undef protected
#include "app_account_common.h"
#include "iservice_registry.h"
#include "mock_app_account_authenticator_stub.h"
#include "system_ability_definition.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string SESSION_ID = "256";
const std::string PARAM_VALUE = "VALUE";
const std::string REQUEST_NAME = "NAME";
const std::string STRING_OWNER = "OWNER";
const std::string STRING_EMPTY = "";
const std::int32_t INVALID_ACTION = -1;
}

class MockAuthenticatorCallback final : public AppAccountAuthenticatorCallbackStub {
public:
    MOCK_METHOD2(OnResult, void(int32_t resultCode, const AAFwk::Want &result));
    MOCK_METHOD1(OnRequestRedirected, void(AAFwk::Want &request));
    MOCK_METHOD0(OnRequestContinued, void());
};

class AppAccountSessionModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    std::shared_ptr<AppAccountAuthenticatorSession> appAccountAuthenticatorSessionPtr_;
};

void AppAccountSessionModuleTest::SetUpTestCase(void)
{}

void AppAccountSessionModuleTest::TearDownTestCase(void)
{}

void AppAccountSessionModuleTest::SetUp(void)
{
    AuthenticatorAction action = VERIFY_CREDENTIAL;
    AuthenticatorSessionRequest request;
    appAccountAuthenticatorSessionPtr_ = std::make_shared<AppAccountAuthenticatorSession>(action, request);
}

void AppAccountSessionModuleTest::TearDown(void)
{
    DelayedSingleton<AppAccountControlManager>::DestroyInstance();
    DelayedSingleton<AppAccountAuthenticatorSession>::DestroyInstance();
    GTEST_LOG_(INFO) << "TearDownTestCase exit";
}

/**
 * @tc.name: AppAccountAuthenticateTest_Open_0100
 * @tc.desc: test session func init and open abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionModuleTest, AppAccountSessionModuleTest_Open_0100, TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionPtr_, nullptr);

    appAccountAuthenticatorSessionPtr_->Init();
    ASSERT_EQ(appAccountAuthenticatorSessionPtr_->isInitialized_, true);

    appAccountAuthenticatorSessionPtr_->isOpened_ = true;
    ErrCode result = appAccountAuthenticatorSessionPtr_->Open();
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION);

    appAccountAuthenticatorSessionPtr_->isOpened_ = false;
    appAccountAuthenticatorSessionPtr_->isInitialized_ = false;
    result = appAccountAuthenticatorSessionPtr_->Open();
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION);
}

/**
 * @tc.name: AppAccountAuthenticateTest_Close_0100
 * @tc.desc: test session func Close proxy not is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionModuleTest, AppAccountSessionModuleTest_Close_0100, TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionPtr_, nullptr);

    appAccountAuthenticatorSessionPtr_->authenticatorProxy_ =
        new (std::nothrow) AccountSA::MockAppAccountAuthenticator();
    ASSERT_NE(nullptr, appAccountAuthenticatorSessionPtr_->authenticatorProxy_);
    ASSERT_NE(nullptr, appAccountAuthenticatorSessionPtr_->authenticatorProxy_->AsObject());
    appAccountAuthenticatorSessionPtr_->serverDeathRecipient_ =
        new (std::nothrow) SessionServerDeathRecipient(SESSION_ID);
    ASSERT_NE(nullptr, appAccountAuthenticatorSessionPtr_->serverDeathRecipient_);
    appAccountAuthenticatorSessionPtr_->isOpened_ = true;
    appAccountAuthenticatorSessionPtr_->Close();
    ASSERT_EQ(appAccountAuthenticatorSessionPtr_->isOpened_, false);
}

/**
 * @tc.name: AppAccountAuthenticateTest_Close_0200
 * @tc.desc: test session func Close callback not is nullptr branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionModuleTest, AppAccountSessionModuleTest_Close_0200, TestSize.Level1)
{
    AuthenticatorAction action = SET_AUTHENTICATOR_PROPERTIES;
    AuthenticatorSessionRequest request;
    request.callback = new (std::nothrow) MockAuthenticatorCallback();
    ASSERT_NE(request.callback, nullptr);
    ASSERT_NE(request.callback->AsObject(), nullptr);
    auto testSessionPtr_ = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(testSessionPtr_, nullptr);
    testSessionPtr_->isOpened_ = true;
    testSessionPtr_->Close();
    ASSERT_EQ(testSessionPtr_->isOpened_, false);
}

/**
 * @tc.name: AppAccountAuthenticateTest_Close_0300
 * @tc.desc: test session func Close isConnected is true branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionModuleTest, AppAccountSessionModuleTest_Close_0300, TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionPtr_, nullptr);
    appAccountAuthenticatorSessionPtr_->isConnected_ = true;
    appAccountAuthenticatorSessionPtr_->conn_ = new (std::nothrow) SessionConnection(SESSION_ID);
    ASSERT_NE(appAccountAuthenticatorSessionPtr_->conn_, nullptr);
    appAccountAuthenticatorSessionPtr_->isOpened_ = true;
    appAccountAuthenticatorSessionPtr_->Close();
    ASSERT_EQ(appAccountAuthenticatorSessionPtr_->isOpened_, false);
}

/**
 * @tc.name: AppAccountAuthenticateTest_AddClientDeathRecipient_0100
 * @tc.desc: test session func AddClientDeathRecipient is opened and callback is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionModuleTest, AppAccountSessionModuleTest_AddClientDeathRecipient_0100, TestSize.Level1)
{
    AuthenticatorAction action = SET_AUTHENTICATOR_PROPERTIES;
    AuthenticatorSessionRequest request;
    request.callback = new (std::nothrow) MockAuthenticatorCallback();
    ASSERT_NE(request.callback, nullptr);
    ASSERT_NE(request.callback->AsObject(), nullptr);
    auto testSessionPtr_ = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(testSessionPtr_, nullptr);
    ErrCode result = testSessionPtr_->AddClientDeathRecipient();
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION);

    result = testSessionPtr_->Open();
    ASSERT_EQ(result, ERR_OK);
    result = testSessionPtr_->AddClientDeathRecipient();
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION);

    result = appAccountAuthenticatorSessionPtr_->Open();
    ASSERT_EQ(result, ERR_OK);
    result = appAccountAuthenticatorSessionPtr_->AddClientDeathRecipient();
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OnAbilityConnectDone_0100
 * @tc.desc: test OnAbilityConnectDone with not same action and OnResult resultcode is ADD_ACCOUNT_IMPLICITLY branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionModuleTest, AppAccountSessionModuleTest_OnAbilityConnectDone_0100, TestSize.Level1)
{
    AuthenticatorAction action = ADD_ACCOUNT_IMPLICITLY;
    AuthenticatorSessionRequest request;
    auto appAccountAuthenticatorSessionPtr = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(appAccountAuthenticatorSessionPtr, nullptr);

    sptr<MockAppAccountAuthenticator> authenticatorProxy = new (std::nothrow) AccountSA::MockAppAccountAuthenticator();
    ASSERT_NE(authenticatorProxy, nullptr);
    ASSERT_NE(authenticatorProxy->AsObject(), nullptr);
    AppExecFwk::ElementName element;
    int resultCode = ERR_OK;
    authenticatorProxy->status = true;
    appAccountAuthenticatorSessionPtr->OnAbilityConnectDone(element, authenticatorProxy, resultCode);
    ASSERT_EQ(authenticatorProxy->status, false);
    AAFwk::Want result;
    resultCode = appAccountAuthenticatorSessionPtr->OnResult(ERR_JS_SUCCESS, result);
    ASSERT_EQ(ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION, resultCode);
    result.SetParam(Constants::KEY_NAME, PARAM_VALUE);
    resultCode = appAccountAuthenticatorSessionPtr->OnResult(ERR_JS_SUCCESS, result);
    ASSERT_EQ(ERR_JS_SUCCESS, resultCode);

    action = AUTHENTICATE;
    AuthenticatorSessionRequest request1;
    request1.name = REQUEST_NAME;
    appAccountAuthenticatorSessionPtr = std::make_shared<AppAccountAuthenticatorSession>(action, request1);
    ASSERT_NE(appAccountAuthenticatorSessionPtr, nullptr);
    authenticatorProxy->status = true;
    appAccountAuthenticatorSessionPtr->OnAbilityConnectDone(element, authenticatorProxy, resultCode);
    ASSERT_EQ(authenticatorProxy->status, false);
    resultCode = appAccountAuthenticatorSessionPtr->OnResult(ERR_JS_SUCCESS, result);
    ASSERT_EQ(ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION, resultCode);

    action = CREATE_ACCOUNT_IMPLICITLY;
    appAccountAuthenticatorSessionPtr = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(appAccountAuthenticatorSessionPtr, nullptr);
    authenticatorProxy->status = true;
    appAccountAuthenticatorSessionPtr->OnAbilityConnectDone(element, authenticatorProxy, resultCode);
    ASSERT_EQ(authenticatorProxy->status, false);

    action = AUTH;
    appAccountAuthenticatorSessionPtr = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(appAccountAuthenticatorSessionPtr, nullptr);
    authenticatorProxy->status = true;
    appAccountAuthenticatorSessionPtr->OnAbilityConnectDone(element, authenticatorProxy, resultCode);
    ASSERT_EQ(authenticatorProxy->status, false);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OnAbilityConnectDone_0200
 * @tc.desc: test session func OnAbilityConnectDone different action.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionModuleTest, AppAccountSessionModuleTest_OnAbilityConnectDone_0200, TestSize.Level1)
{
    AuthenticatorAction action = ADD_ACCOUNT_IMPLICITLY;
    AuthenticatorSessionRequest request;

    sptr<MockAppAccountAuthenticator> authenticatorProxy = new (std::nothrow) AccountSA::MockAppAccountAuthenticator();
    ASSERT_NE(authenticatorProxy, nullptr);
    ASSERT_NE(authenticatorProxy->AsObject(), nullptr);
    AppExecFwk::ElementName element;
    action = VERIFY_CREDENTIAL;
    int32_t resultCode = ERR_OK;
    auto appAccountAuthenticatorSessionPtr = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(appAccountAuthenticatorSessionPtr, nullptr);
    authenticatorProxy->status = true;
    appAccountAuthenticatorSessionPtr->OnAbilityConnectDone(element, authenticatorProxy, resultCode);
    ASSERT_EQ(authenticatorProxy->status, false);

    action = CHECK_ACCOUNT_LABELS;
    appAccountAuthenticatorSessionPtr = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(appAccountAuthenticatorSessionPtr, nullptr);
    authenticatorProxy->status = true;
    appAccountAuthenticatorSessionPtr->OnAbilityConnectDone(element, authenticatorProxy, resultCode);
    ASSERT_EQ(authenticatorProxy->status, false);

    action = SET_AUTHENTICATOR_PROPERTIES;
    appAccountAuthenticatorSessionPtr = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(appAccountAuthenticatorSessionPtr, nullptr);
    authenticatorProxy->status = true;
    appAccountAuthenticatorSessionPtr->OnAbilityConnectDone(element, authenticatorProxy, resultCode);
    ASSERT_EQ(authenticatorProxy->status, false);

    action = IS_ACCOUNT_REMOVABLE;
    appAccountAuthenticatorSessionPtr = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(appAccountAuthenticatorSessionPtr, nullptr);
    authenticatorProxy->status = true;
    appAccountAuthenticatorSessionPtr->OnAbilityConnectDone(element, authenticatorProxy, resultCode);
    ASSERT_EQ(authenticatorProxy->status, false);

    action = static_cast<AuthenticatorAction>(INVALID_ACTION);
    auto testCallBack = new (std::nothrow) MockAuthenticatorCallback();
    ASSERT_NE(testCallBack, nullptr);
    request.callback = testCallBack;
    ASSERT_NE(request.callback, nullptr);
    appAccountAuthenticatorSessionPtr = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(appAccountAuthenticatorSessionPtr, nullptr);

    EXPECT_CALL(*testCallBack, OnResult(_, _)).Times(Exactly(1));
    appAccountAuthenticatorSessionPtr->OnAbilityConnectDone(element, authenticatorProxy, resultCode);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OnResult_0100
 * @tc.desc: test session func OnResult action is AUTHENTICATE branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionModuleTest, AppAccountSessionModuleTest_OnResult_0100, TestSize.Level1)
{
    AuthenticatorAction action = AUTHENTICATE;
    AuthenticatorSessionRequest request;
    request.name = PARAM_VALUE;
    AAFwk::Want result;
    result.SetParam(Constants::KEY_NAME, PARAM_VALUE);
    auto appAccountAuthenticatorSessionPtr = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(appAccountAuthenticatorSessionPtr, nullptr);
    int32_t resultCode = appAccountAuthenticatorSessionPtr->OnResult(ERR_JS_SUCCESS, result);
    ASSERT_EQ(resultCode, ERR_JS_SUCCESS);
}

/**
 * @tc.name: AppAccountAuthenticateTest_GetAuthenticatorCallback_0100
 * @tc.desc: test func GetAuthenticatorCallback callerUid not equal ownerUid and callerBundleName not equal owner.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionModuleTest, AppAccountSessionModuleTest_GetAuthenticatorCallback_0100, TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionPtr_, nullptr);
    AuthenticatorSessionRequest request;
    pid_t ownerUid = 1;
    request.callerUid = ownerUid;
    sptr<IRemoteObject> callback = nullptr;
    ErrCode result = appAccountAuthenticatorSessionPtr_->GetAuthenticatorCallback(request, callback);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED);

    appAccountAuthenticatorSessionPtr_->ownerUid_ = ownerUid;
    request.callerBundleName = "test";
    result = appAccountAuthenticatorSessionPtr_->GetAuthenticatorCallback(request, callback);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED);
}

/**
 * @tc.name: AppAccountAuthenticateTest_GetAuthenticatorCallback_0200
 * @tc.desc: test session func GetAuthenticatorCallback normal and authenticatorCb is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionModuleTest, AppAccountSessionModuleTest_GetAuthenticatorCallback_0200, TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionPtr_, nullptr);
    AuthenticatorSessionRequest request;
    pid_t ownerUid = 1;
    sptr<IRemoteObject> callback = nullptr;

    AuthenticatorSessionRequest request1;
    AuthenticatorAction action = SET_AUTHENTICATOR_PROPERTIES;
    request1.owner = STRING_OWNER;
    auto appAccountAuthenticatorSessionPtr = std::make_shared<AppAccountAuthenticatorSession>(action, request1);
    ASSERT_NE(appAccountAuthenticatorSessionPtr, nullptr);
    appAccountAuthenticatorSessionPtr->ownerUid_ = ownerUid;
    request.callerBundleName = STRING_OWNER;
    request.callerUid = ownerUid;
    appAccountAuthenticatorSessionPtr->authenticatorCb_ = nullptr;
    ErrCode result = appAccountAuthenticatorSessionPtr->GetAuthenticatorCallback(request, callback);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_CALLBACK_NOT_EXIST);

    appAccountAuthenticatorSessionPtr->authenticatorCb_ = new (std::nothrow) MockAuthenticatorCallback();
    ASSERT_NE(appAccountAuthenticatorSessionPtr->authenticatorCb_, nullptr);
    result = appAccountAuthenticatorSessionPtr->GetAuthenticatorCallback(request, callback);
    ASSERT_EQ(result, ERR_OK);
    ASSERT_EQ(callback, appAccountAuthenticatorSessionPtr->authenticatorCb_->AsObject());
}

/**
 * @tc.name: AppAccountSessionModuleTest_GOnRemoteDied_0100
 * @tc.desc: test session func OnRemoteDied.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionModuleTest, AppAccountSessionModuleTest_OnRemoteDied_0100, TestSize.Level1)
{
    std::string sessionId = "sessionId";
    SessionServerDeathRecipient testSessionServerDeathRecipient(sessionId);
    testSessionServerDeathRecipient.OnRemoteDied(nullptr);
    ASSERT_EQ(testSessionServerDeathRecipient.sessionId_, sessionId);
}
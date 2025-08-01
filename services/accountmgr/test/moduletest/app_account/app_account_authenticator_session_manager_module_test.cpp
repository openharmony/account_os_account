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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "account_log_wrapper.h"
#include "app_mgr_constants.h"
#define private public
#include "app_account_authenticator_session_manager.h"
#include "app_account_authenticator_session.h"
#include "app_account_authenticator_callback.h"
#include "app_account_constants.h"
#undef private
#include "iservice_registry.h"
#include "mock_app_account_authenticator_stub.h"
#include "system_ability_definition.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string BUNDLE_NAME = "bundlename";
const std::string STRING_OWNER = "com.example.name";
const std::string ABILITY_NAME = "abilityName";
const std::string VALUE = "VALUE";
const std::string SESSION_ID = "sessionId";
const std::string SESSION_ID_OTHER = "sessionId1";
const int32_t SESSION_MAX_NUM = 256;
}  // namespace

bool g_status = false;
class MockAuthenticatorCallback final : public AppAccountAuthenticatorCallbackStub {
public:
    MOCK_METHOD2(OnResult, ErrCode(int32_t resultCode, const AAFwk::Want &result));
    MOCK_METHOD1(OnRequestRedirected, ErrCode(const AAFwk::Want &request));
    MOCK_METHOD0(OnRequestContinued, ErrCode());
    MOCK_METHOD1(CallbackEnter, ErrCode(uint32_t code));
    MOCK_METHOD2(CallbackExit, ErrCode(uint32_t code, int32_t result));
};

class MockSpecicalAuthenticatorCallback final : public AppAccountAuthenticatorCallbackStub {
public:
    ErrCode OnResult(int32_t resultCode, const AAFwk::Want &result)
    {
        g_status = true;
        return ERR_OK;
    }
    ErrCode OnRequestRedirected(const AAFwk::Want &request)
    {
        g_status = true;
        return ERR_OK;
    }
    ErrCode OnRequestContinued()
    {
        g_status = true;
        return ERR_OK;
    }
    ErrCode CallbackEnter([[maybe_unused]] uint32_t code)
    {
        g_status = true;
        return ERR_OK;
    }
    ErrCode CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
    {
        g_status = true;
        return ERR_OK;
    }
};

class AppAccountSessionManagerModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    AppAccountAuthenticatorSessionManager *appAccountAuthenticatorSessionManagerPtr_;
};

void AppAccountSessionManagerModuleTest::SetUpTestCase(void)
{}

void AppAccountSessionManagerModuleTest::TearDownTestCase(void)
{}

void AppAccountSessionManagerModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    appAccountAuthenticatorSessionManagerPtr_ = &AppAccountAuthenticatorSessionManager::GetInstance();
}

void AppAccountSessionManagerModuleTest::TearDown(void)
{
    std::lock_guard<std::mutex> lock(appAccountAuthenticatorSessionManagerPtr_->mutex_);
    appAccountAuthenticatorSessionManagerPtr_->sessionMap_.clear();
    appAccountAuthenticatorSessionManagerPtr_->abilitySessions_.clear();
}

/**
 * @tc.name: AppAccountAuthenticateTest_IsAccountRemovable_0100
 * @tc.desc: test session manager func IsAccountRemovable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(
    AppAccountSessionManagerModuleTest, AppAccountSessionManagerModuleTest_IsAccountRemovable_0100, TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionManagerPtr_, nullptr);

    AuthenticatorSessionRequest request;
    ErrCode result = appAccountAuthenticatorSessionManagerPtr_->IsAccountRemovable(request);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticateTest_SelectAccountsByOptions_0100
 * @tc.desc: test session manager func SelectAccountsByOptions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionManagerModuleTest, AppAccountSessionManagerModuleTest_OnAbilityConnectDone_0100,
    TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionManagerPtr_, nullptr);

    AuthenticatorSessionRequest request;
    std::vector<AppAccountInfo> accounts;
    ErrCode result = appAccountAuthenticatorSessionManagerPtr_->SelectAccountsByOptions(accounts, request);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticateTest_SelectAccountsByOptions_0100
 * @tc.desc: according IsAccountRemovable test func OnAbilityConnectDone remoteObject is not nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionManagerModuleTest, AppAccountSessionManagerModuleTest_SelectAccountsByOptions_0100,
    TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionManagerPtr_, nullptr);

    AuthenticatorSessionRequest request;
    request.owner = STRING_OWNER;
    ErrCode result = appAccountAuthenticatorSessionManagerPtr_->IsAccountRemovable(request);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OpenSession_0100
 * @tc.desc: test session manager func OpenSession.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionManagerModuleTest, AppAccountSessionManagerModuleTest_OpenSession_0100, TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionManagerPtr_, nullptr);

    std::shared_ptr<AppAccountAuthenticatorSession> session = nullptr;
    ErrCode result = appAccountAuthenticatorSessionManagerPtr_->OpenSession(session);
    ASSERT_EQ(ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION, result);

    for (int i = 0; i < SESSION_MAX_NUM; i++) {
        std::string key = std::to_string(i);
        AuthenticatorAction action;
        AuthenticatorSessionRequest request;
        auto sessionPtr = std::make_shared<AppAccountAuthenticatorSession>(action, request);
        ASSERT_NE(sessionPtr, nullptr);
        appAccountAuthenticatorSessionManagerPtr_->sessionMap_[key] = sessionPtr;
    }
    ASSERT_EQ(appAccountAuthenticatorSessionManagerPtr_->sessionMap_.size(), SESSION_MAX_NUM);
    AuthenticatorAction action;
    AuthenticatorSessionRequest request;
    session = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(session, nullptr);
    result = appAccountAuthenticatorSessionManagerPtr_->OpenSession(session);
    ASSERT_EQ(ERR_APPACCOUNT_SERVICE_OAUTH_BUSY, result);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OpenSession_0200
 * @tc.desc: test session manager func OpenSession abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionManagerModuleTest, AppAccountSessionManagerModuleTest_OpenSession_0200, TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionManagerPtr_, nullptr);

    std::string key = std::to_string(SESSION_MAX_NUM);
    AuthenticatorAction action;
    AuthenticatorSessionRequest request;
    auto session = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(session, nullptr);
    appAccountAuthenticatorSessionManagerPtr_->sessionMap_.clear();
    appAccountAuthenticatorSessionManagerPtr_->sessionMap_[key] = session;

    ErrCode result = appAccountAuthenticatorSessionManagerPtr_->OpenSession(session);
    ASSERT_EQ(ERR_OK, result);
    appAccountAuthenticatorSessionManagerPtr_->CloseSession(key);
    auto size = appAccountAuthenticatorSessionManagerPtr_->sessionMap_.size();
    appAccountAuthenticatorSessionManagerPtr_->CloseSession(key);
    ASSERT_EQ(size, appAccountAuthenticatorSessionManagerPtr_->sessionMap_.size());
}

/**
 * @tc.name: AppAccountAuthenticateTest_GetSession_0100
 * @tc.desc: test session manager func GetSession normal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionManagerModuleTest, AppAccountSessionManagerModuleTest_GetSession_0100, TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionManagerPtr_, nullptr);

    std::string sessionId = SESSION_ID;
    auto sessionPtr = appAccountAuthenticatorSessionManagerPtr_->GetSession(sessionId);
    ASSERT_EQ(sessionPtr, nullptr);

    AuthenticatorAction action;
    AuthenticatorSessionRequest request;
    auto session = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(session, nullptr);
    appAccountAuthenticatorSessionManagerPtr_->sessionMap_[sessionId] = session;
    sessionPtr = appAccountAuthenticatorSessionManagerPtr_->GetSession(sessionId);
    ASSERT_NE(sessionPtr, nullptr);
}

/**
 * @tc.name: AppAccountAuthenticateTest_GetAuthenticatorCallback_0100
 * @tc.desc: test session manager func GetAuthenticatorCallback abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionManagerModuleTest, AppAccountSessionManagerModuleTest_GetAuthenticatorCallback_0200,
    TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionManagerPtr_, nullptr);

    AuthenticatorSessionRequest request;
    request.sessionId = SESSION_ID;
    sptr<IRemoteObject> callback = nullptr;
    ErrCode sessionPtr = appAccountAuthenticatorSessionManagerPtr_->GetAuthenticatorCallback(request, callback);
    ASSERT_EQ(sessionPtr, ERR_APPACCOUNT_SERVICE_OAUTH_SESSION_NOT_EXIST);

    appAccountAuthenticatorSessionManagerPtr_->sessionMap_[SESSION_ID] = nullptr;
    sessionPtr = appAccountAuthenticatorSessionManagerPtr_->GetAuthenticatorCallback(request, callback);
    ASSERT_EQ(sessionPtr, ERR_APPACCOUNT_SERVICE_OAUTH_SESSION_NOT_EXIST);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OnSessionServerDied_0100
 * @tc.desc: test session manager func OnSessionServerDied.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(
    AppAccountSessionManagerModuleTest, AppAccountSessionManagerModuleTest_OnSessionServerDied_0100, TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionManagerPtr_, nullptr);

    std::string sessionId = SESSION_ID;
    AuthenticatorAction action;
    AuthenticatorSessionRequest request;
    auto testCallBack = new (std::nothrow) MockAuthenticatorCallback();
    ASSERT_NE(testCallBack, nullptr);
    request.callback = testCallBack;
    ASSERT_NE(request.callback, nullptr);
    auto session = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(session, nullptr);

    auto sessionPtr = appAccountAuthenticatorSessionManagerPtr_->GetSession(sessionId);
    ASSERT_EQ(sessionPtr, nullptr);
    EXPECT_CALL(*testCallBack, OnResult(_, _)).Times(Exactly(0));
    appAccountAuthenticatorSessionManagerPtr_->OnSessionServerDied(sessionId);

    appAccountAuthenticatorSessionManagerPtr_->sessionMap_[sessionId] = session;
    sessionPtr = appAccountAuthenticatorSessionManagerPtr_->GetSession(sessionId);
    ASSERT_EQ(sessionPtr, session);
    EXPECT_CALL(*testCallBack, OnResult(_, _)).Times(Exactly(1));
    appAccountAuthenticatorSessionManagerPtr_->OnSessionServerDied(sessionId);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OnSessionAbilityConnectDone_0100
 * @tc.desc: test session manager func OnSessionAbilityConnectDone.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionManagerModuleTest, AppAccountSessionManagerModuleTest_OnSessionAbilityConnectDone_0100,
    TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionManagerPtr_, nullptr);

    std::string sessionId = SESSION_ID;
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int32_t resultCode = -1;
    AuthenticatorAction action;
    AuthenticatorSessionRequest request;
    auto testCallBack = new (std::nothrow) MockAuthenticatorCallback();
    ASSERT_NE(testCallBack, nullptr);
    request.callback = testCallBack;
    ASSERT_NE(request.callback, nullptr);
    auto session = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(session, nullptr);

    auto sessionPtr = appAccountAuthenticatorSessionManagerPtr_->GetSession(sessionId);
    ASSERT_EQ(sessionPtr, nullptr);
    EXPECT_CALL(*testCallBack, OnResult(_, _)).Times(Exactly(0));
    appAccountAuthenticatorSessionManagerPtr_->OnSessionAbilityConnectDone(
        sessionId, element, remoteObject, resultCode);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OnSessionAbilityDisconnectDone_0100
 * @tc.desc: test session manager func OnSessionAbilityDisconnectDone.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionManagerModuleTest, AppAccountSessionManagerModuleTest_OnSessionAbilityDisconnectDone_0100,
    TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionManagerPtr_, nullptr);

    std::string sessionId = SESSION_ID;
    AppExecFwk::ElementName element;
    int32_t resultCode = -1;
    AuthenticatorAction action;
    AuthenticatorSessionRequest request;
    auto session = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(session, nullptr);
    session->isConnected_ = true;

    auto sessionPtr = appAccountAuthenticatorSessionManagerPtr_->GetSession(sessionId);
    ASSERT_EQ(sessionPtr, nullptr);
    appAccountAuthenticatorSessionManagerPtr_->OnSessionAbilityDisconnectDone(sessionId, element, resultCode);
    ASSERT_EQ(session->isConnected_, true);

    appAccountAuthenticatorSessionManagerPtr_->sessionMap_[sessionId] = session;
    sessionPtr = appAccountAuthenticatorSessionManagerPtr_->GetSession(sessionId);
    ASSERT_EQ(sessionPtr, session);
    appAccountAuthenticatorSessionManagerPtr_->OnSessionAbilityDisconnectDone(sessionId, element, resultCode);
    ASSERT_EQ(session->isConnected_, false);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OnSessionRequestRedirected_0100
 * @tc.desc: test session manager func OnSessionRequestRedirected OnSessionResult OnSessionRequestContinued.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionManagerModuleTest, AppAccountSessionManagerModuleTest_OnSessionRequestRedirected_0100,
    TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionManagerPtr_, nullptr);

    std::string sessionId = SESSION_ID;
    AAFwk::Want result;
    int32_t resultCode = -1;
    AuthenticatorAction action;
    AuthenticatorSessionRequest request;
    request.owner = BUNDLE_NAME;
    auto testCallBack = new (std::nothrow) MockAuthenticatorCallback();
    ASSERT_NE(testCallBack, nullptr);
    request.callback = testCallBack;
    ASSERT_NE(request.callback, nullptr);
    auto session = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(session, nullptr);

    EXPECT_CALL(*testCallBack, OnResult(_, _)).Times(Exactly(0));
    appAccountAuthenticatorSessionManagerPtr_->OnSessionResult(sessionId, resultCode, result);

    EXPECT_CALL(*testCallBack, OnRequestContinued()).Times(Exactly(0));
    appAccountAuthenticatorSessionManagerPtr_->OnSessionRequestContinued(sessionId);

    appAccountAuthenticatorSessionManagerPtr_->sessionMap_[sessionId] = session;
    auto sessionPtr = appAccountAuthenticatorSessionManagerPtr_->GetSession(sessionId);
    ASSERT_EQ(sessionPtr, session);

    EXPECT_CALL(*testCallBack, OnRequestContinued()).Times(Exactly(1));
    appAccountAuthenticatorSessionManagerPtr_->OnSessionRequestContinued(sessionId);

    EXPECT_CALL(*testCallBack, OnResult(_, _)).Times(Exactly(1));
    appAccountAuthenticatorSessionManagerPtr_->OnSessionResult(sessionId, resultCode, result);

    EXPECT_CALL(*testCallBack, OnResult(_, _)).Times(Exactly(1));
    appAccountAuthenticatorSessionManagerPtr_->OnSessionRequestRedirected(sessionId, result);

    AppExecFwk::ElementName element = result.GetElement();
    element.SetBundleName(BUNDLE_NAME);
    ASSERT_EQ(element.GetBundleName(), request.owner);
    result.SetElement(element);
    EXPECT_CALL(*testCallBack, OnRequestRedirected(_)).Times(Exactly(1));
    appAccountAuthenticatorSessionManagerPtr_->OnSessionRequestRedirected(sessionId, result);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OnSessionRequestRedirected_0200
 * @tc.desc: test session manager func OnSessionRequestRedirected callback is nullptr branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionManagerModuleTest, AppAccountSessionManagerModuleTest_OnSessionRequestRedirected_0200,
    TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionManagerPtr_, nullptr);

    std::string sessionId = SESSION_ID;
    AAFwk::Want result;
    AuthenticatorAction action;
    AuthenticatorSessionRequest request;
    request.owner = BUNDLE_NAME;
    auto testCallBack = new (std::nothrow) MockSpecicalAuthenticatorCallback();
    ASSERT_NE(testCallBack, nullptr);
    auto session = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    ASSERT_NE(session, nullptr);

    AppExecFwk::ElementName element = result.GetElement();
    element.SetBundleName(BUNDLE_NAME);
    ASSERT_EQ(element.GetBundleName(), request.owner);
    result.SetElement(element);
    session->isConnected_ = true;
    appAccountAuthenticatorSessionManagerPtr_->sessionMap_[sessionId] = session;
    auto sessionPtr = appAccountAuthenticatorSessionManagerPtr_->GetSession(sessionId);
    ASSERT_EQ(sessionPtr, session);
    appAccountAuthenticatorSessionManagerPtr_->OnSessionRequestRedirected(sessionId, result);
    ASSERT_EQ(g_status, false);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OnSessionRequestRedirected_0300
 * @tc.desc: test session manager func OnSessionRequestRedirected action is AUTHENTICATE or ADD_ACCOUNT_IMPLICITLY.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionManagerModuleTest, AppAccountSessionManagerModuleTest_OnSessionRequestRedirected_0300,
    TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionManagerPtr_, nullptr);

    std::string sessionId = SESSION_ID;
    AAFwk::Want result;
    AuthenticatorSessionRequest request;
    request.owner = BUNDLE_NAME;
    auto testCallBack = new (std::nothrow) MockAuthenticatorCallback();
    ASSERT_NE(testCallBack, nullptr);
    request.callback = testCallBack;
    ASSERT_NE(request.callback, nullptr);
    auto session = std::make_shared<AppAccountAuthenticatorSession>(AUTHENTICATE, request);
    ASSERT_NE(session, nullptr);

    appAccountAuthenticatorSessionManagerPtr_->sessionMap_[sessionId] = session;
    auto sessionPtr = appAccountAuthenticatorSessionManagerPtr_->GetSession(sessionId);
    ASSERT_EQ(sessionPtr, session);
    AppExecFwk::ElementName element = result.GetElement();
    element.SetBundleName(BUNDLE_NAME);
    ASSERT_EQ(element.GetBundleName(), request.owner);
    result.SetElement(element);
    EXPECT_CALL(*testCallBack, OnRequestRedirected(_)).Times(Exactly(1));
    appAccountAuthenticatorSessionManagerPtr_->OnSessionRequestRedirected(sessionId, result);

    AuthenticatorSessionRequest request1;
    request1.owner = BUNDLE_NAME;
    auto session1 = std::make_shared<AppAccountAuthenticatorSession>(ADD_ACCOUNT_IMPLICITLY, request1);
    ASSERT_NE(session, nullptr);

    appAccountAuthenticatorSessionManagerPtr_->sessionMap_[SESSION_ID_OTHER] = session1;
    auto sessionPtr1 = appAccountAuthenticatorSessionManagerPtr_->GetSession(SESSION_ID_OTHER);
    ASSERT_EQ(sessionPtr1, session1);
    AppExecFwk::ElementName element1 = result.GetElement();
    element1.SetBundleName(BUNDLE_NAME);
    ASSERT_EQ(element1.GetBundleName(), request1.owner);
    result.SetElement(element1);
    request1.callback = testCallBack;
    ASSERT_NE(request1.callback, nullptr);
    EXPECT_CALL(*testCallBack, OnRequestRedirected(_)).Times(Exactly(1));
    appAccountAuthenticatorSessionManagerPtr_->OnSessionRequestRedirected(sessionId, result);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OnSessionRequestRedirected_0400
 * @tc.desc: test session manager func OnSessionRequestRedirected sessionid is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionManagerModuleTest, AppAccountSessionManagerModuleTest_OnSessionRequestRedirected_0400,
    TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionManagerPtr_, nullptr);
    AAFwk::Want result;
    appAccountAuthenticatorSessionManagerPtr_->OnSessionRequestRedirected(SESSION_ID, result);
    auto session = appAccountAuthenticatorSessionManagerPtr_->GetSession(SESSION_ID);
    ASSERT_EQ(session, nullptr);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OnSessionRequestContinued_0200
 * @tc.desc: test session manager func OnSessionRequestContinued callback is nullptr isconnected is true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountSessionManagerModuleTest, AppAccountSessionManagerModuleTest_OnSessionRequestContinued_0200,
    TestSize.Level1)
{
    ASSERT_NE(appAccountAuthenticatorSessionManagerPtr_, nullptr);

    std::string sessionId = SESSION_ID;
    AAFwk::Want result;
    AuthenticatorAction action;
    AuthenticatorSessionRequest request;
    auto testCallBack = new (std::nothrow) MockSpecicalAuthenticatorCallback();
    ASSERT_NE(testCallBack, nullptr);

    auto session = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    session->isConnected_ = true;
    ASSERT_NE(session, nullptr);
    appAccountAuthenticatorSessionManagerPtr_->sessionMap_[sessionId] = session;
    auto sessionPtr = appAccountAuthenticatorSessionManagerPtr_->GetSession(sessionId);
    ASSERT_EQ(sessionPtr, session);
    appAccountAuthenticatorSessionManagerPtr_->OnSessionRequestContinued(sessionId);
    ASSERT_EQ(g_status, false);
}
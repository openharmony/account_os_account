/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define private public
#include "app_account_authorization_extension_callback.h"
#include "app_account_authorization_extension_callback_service.h"
#include "app_account_authorization_extension_proxy.h"
#include "app_account_authorization_extension_service.h"
#include "app_account_authorization_extension_stub.h"
#undef private
#include "app_account_common.h"
#include "authorization_extension.h"
#include "napi_app_account_authorization_extension.h"
#include "js_runtime.h"
#include "want.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS;
using namespace OHOS::AccountSA;

class MockAppAccountAuthorizationExtensionCallback {
public:
    MOCK_METHOD2(OnResult, void(const int32_t errCode, const AAFwk::WantParams &parameters));
};

class TestAppAccountAuthorizationExtensionCallback : public AppAccountAuthorizationExtensionCallback {
public:
    explicit TestAppAccountAuthorizationExtensionCallback(
        const std::shared_ptr<MockAppAccountAuthorizationExtensionCallback> &callback)
        : callback_(callback)
    {}
    virtual ~TestAppAccountAuthorizationExtensionCallback();
    void OnResult(const AsyncCallbackError &businessError, const AAFwk::WantParams &parameters) override;

private:
    std::shared_ptr<MockAppAccountAuthorizationExtensionCallback> callback_;
};

TestAppAccountAuthorizationExtensionCallback::~TestAppAccountAuthorizationExtensionCallback()
{}

void TestAppAccountAuthorizationExtensionCallback::OnResult(
    const AsyncCallbackError &businessError, const AAFwk::WantParams &parameters)
{
    callback_->OnResult(businessError.code, parameters);
}

class MockJsAuthorizationExtension final : public OHOS::AbilityRuntime::AuthorizationExtension {
public:
    void StartAuthorization(
        const std::shared_ptr<AccountSA::AppAccountAuthorizationExtensionCallbackClient> &callbackPtr)
    {
        AAFwk::WantParams parameters;
        EXPECT_NE(callbackPtr, nullptr);
        AsyncCallbackError businessError;
        callbackPtr->OnResult(businessError, parameters);
        return;
    }
};

class MockAppAccountAuthorizationExtensionService final : public AppAccountAuthorizationExtensionStub {
public:
    explicit MockAppAccountAuthorizationExtensionService(
        const std::shared_ptr<MockJsAuthorizationExtension> &extension)
        : innerExtension_(extension)
    {}
    ErrCode StartAuthorization(const AuthorizationRequest &request)
    {
        AppAccountAuthorizationExtensionCallbackClient *callbackClient =
            new (std::nothrow) AppAccountAuthorizationExtensionCallbackClient(request.callback);
        EXPECT_NE(callbackClient, nullptr);
        std::shared_ptr<AppAccountAuthorizationExtensionCallbackClient> callbackPtr(callbackClient);
        innerExtension_->StartAuthorization(callbackPtr);
        return ERR_OK;
    }

private:
    std::shared_ptr<MockJsAuthorizationExtension> innerExtension_ = nullptr;
};

static void InitRequestCallback(
    const std::shared_ptr<TestAppAccountAuthorizationExtensionCallback> &callback, AuthorizationRequest &request)
{
    request.callback = new (std::nothrow) AppAccountAuthorizationExtensionCallbackService(callback);
    EXPECT_NE(request.callback, nullptr);
}

class AppAccountExtensionModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    sptr<AppAccountAuthorizationExtensionCallbackProxy> callbackProxyPtr_ = nullptr;
    sptr<AppAccountAuthorizationExtensionCallbackService> callbackServicePtr_ = nullptr;
    sptr<IRemoteObject> MockService_ = nullptr;
};

void AppAccountExtensionModuleTest::SetUpTestCase(void)
{}

void AppAccountExtensionModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase enter";
}

void AppAccountExtensionModuleTest::SetUp(void)
{
    callbackServicePtr_ = new (std::nothrow) AppAccountAuthorizationExtensionCallbackService(nullptr);
    ASSERT_NE(callbackServicePtr_, nullptr);
    MockService_ = callbackServicePtr_->AsObject();
    callbackProxyPtr_ = new (std::nothrow) AppAccountAuthorizationExtensionCallbackProxy(MockService_);
}

void AppAccountExtensionModuleTest::TearDown(void)
{}

/**
 * @tc.name: StartAuthorization_0100
 * @tc.desc: test AppAccountAuthorizationExtensionProxy func StartAuthorization.
 * @tc.type: FUNC
 * @tc.require: issuesI7AVZ5
 */
HWTEST_F(AppAccountExtensionModuleTest, StartAuthorization_0100, TestSize.Level1)
{
    std::shared_ptr<MockJsAuthorizationExtension> innerExtension = std::make_shared<MockJsAuthorizationExtension>();
    EXPECT_NE(innerExtension, nullptr);
    sptr<MockAppAccountAuthorizationExtensionService> authorizationService =
        new (std::nothrow) MockAppAccountAuthorizationExtensionService(innerExtension);
    EXPECT_NE(authorizationService, nullptr);
    sptr<AppAccountAuthorizationExtensionProxy> authorizationProxy =
        new (std::nothrow) AppAccountAuthorizationExtensionProxy(authorizationService->AsObject());
    auto callback = std::make_shared<MockAppAccountAuthorizationExtensionCallback>();
    auto testCallbackCreate = std::make_shared<TestAppAccountAuthorizationExtensionCallback>(callback);
    EXPECT_CALL(*callback, OnResult(0, _)).Times(Exactly(1));
    AuthorizationRequest request;
    InitRequestCallback(testCallbackCreate, request);
    EXPECT_NE(authorizationProxy, nullptr);
    EXPECT_EQ(authorizationProxy->StartAuthorization(request), ERR_OK);
}

/**
 * @tc.name: StartAuthorization_0200
 * @tc.desc: test AppAccountAuthorizationExtensionService func StartAuthorization.
 * @tc.type: FUNC
 * @tc.require: issuesI7AVZ5
 */
HWTEST_F(AppAccountExtensionModuleTest, StartAuthorization_0200, TestSize.Level1)
{
    OHOS::AbilityRuntime::JsRuntime jsRuntime;
    std::shared_ptr<AccountJsKit::JsAuthorizationExtension> innerExtension =
        std::make_shared<OHOS::AccountJsKit::JsAuthorizationExtension>(jsRuntime);
    EXPECT_NE(innerExtension, nullptr);
    sptr<AppAccountAuthorizationExtensionService> authorizationService =
        new (std::nothrow) AppAccountAuthorizationExtensionService(innerExtension);
    EXPECT_NE(authorizationService, nullptr);
    AuthorizationRequest request;
    EXPECT_EQ(authorizationService->StartAuthorization(request), ERR_OK);
}

/**
 * @tc.name: StartAuthorization_0300
 * @tc.desc: test AppAccountAuthorizationExtensionService func StartAuthorization with extension is nullptr.
 * @tc.type: FUNC
 * @tc.require: issuesI7AVZ5
 */
HWTEST_F(AppAccountExtensionModuleTest, StartAuthorization_0300, TestSize.Level1)
{
    std::shared_ptr<AccountJsKit::JsAuthorizationExtension> innerExtension = nullptr;
    sptr<AppAccountAuthorizationExtensionService> authorizationService =
        new (std::nothrow) AppAccountAuthorizationExtensionService(innerExtension);
    EXPECT_NE(authorizationService, nullptr);
    AuthorizationRequest request;
    EXPECT_EQ(authorizationService->StartAuthorization(request), ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: StartAuthorization_0400
 * @tc.desc: test AppAccountAuthorizationExtensionProxy func StartAuthorization with callback is nullptr.
 * @tc.type: FUNC
 * @tc.require: issuesI7AVZ5
 */
HWTEST_F(AppAccountExtensionModuleTest, StartAuthorization_0400, TestSize.Level1)
{
    std::shared_ptr<MockJsAuthorizationExtension> innerExtension = std::make_shared<MockJsAuthorizationExtension>();
    EXPECT_NE(innerExtension, nullptr);
    sptr<MockAppAccountAuthorizationExtensionService> authorizationService =
        new (std::nothrow) MockAppAccountAuthorizationExtensionService(innerExtension);
    EXPECT_NE(authorizationService, nullptr);
    auto callback = std::make_shared<MockAppAccountAuthorizationExtensionCallback>();
    auto testCallbackCreate = std::make_shared<TestAppAccountAuthorizationExtensionCallback>(callback);
    sptr<AppAccountAuthorizationExtensionProxy> authorizationProxy =
        new (std::nothrow) AppAccountAuthorizationExtensionProxy(authorizationService->AsObject());
    EXPECT_NE(authorizationProxy, nullptr);
    AuthorizationRequest request;
    EXPECT_EQ(authorizationProxy->StartAuthorization(request), ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
}

/**
 * @tc.name: AppAccountAuthorizationExtensionCallbackProxy_001
 * @tc.desc: test AppAccountAuthorizationExtensionCallbackProxy OnResult.
 * @tc.type: FUNC
 * @tc.require: issuesI7AVZ5
 */
HWTEST_F(AppAccountExtensionModuleTest, AppAccountAuthorizationExtensionCallbackProxy_001, TestSize.Level1)
{
    AAFwk::WantParams parameters;
    AsyncCallbackError businessError;
    ASSERT_NE(callbackProxyPtr_, nullptr);
    callbackProxyPtr_->OnResult(businessError, parameters);
    EXPECT_EQ(businessError.code, 0);
}

/**
 * @tc.name: AppAccountAuthorizationExtensionCallbackStub_001
 * @tc.desc: test AppAccountAuthorizationExtensionCallbackStub OnRemoteRequest abnormal branch.
 * @tc.type: FUNC
 * @tc.require: issuesI7AVZ5
 */
HWTEST_F(AppAccountExtensionModuleTest, AppAccountAuthorizationExtensionCallbackStub_001, TestSize.Level1)
{
    AAFwk::WantParams parameters;
    EXPECT_NE(callbackServicePtr_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(callbackServicePtr_->OnRemoteRequest(0, data, reply, option), ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR);
}
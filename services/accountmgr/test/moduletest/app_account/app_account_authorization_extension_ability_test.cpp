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
#include "app_account_authentication_extension_callback.h"
#include "app_account_authentication_extension_callback_service.h"
#include "app_account_authentication_extension_proxy.h"
#include "app_account_authentication_extension_service.h"
#include "app_account_authentication_extension_stub.h"
#include "app_account_common.h"
#include "authentication_extension.h"
#include "napi_app_account_authentication_extension.h"
#include "js_runtime.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS;
using namespace OHOS::AccountSA;

class MockAppAccountAuthenticationExtensionCallback {
public:
    MOCK_METHOD2(OnResult, void(const int32_t errCode, const AAFwk::WantParams &parameters));
};

class TestAppAccountAuthenticationExtensionCallback : public AppAccountAuthenticationExtensionCallback {
public:
    explicit TestAppAccountAuthenticationExtensionCallback(
        const std::shared_ptr<MockAppAccountAuthenticationExtensionCallback> &callback)
    {
        callback_ = callback;
    }
    virtual ~TestAppAccountAuthenticationExtensionCallback();
    void OnResult(const int32_t errCode, const AAFwk::WantParams &parameters) override;

private:
    std::shared_ptr<MockAppAccountAuthenticationExtensionCallback> callback_;
};

TestAppAccountAuthenticationExtensionCallback::~TestAppAccountAuthenticationExtensionCallback()
{}

void TestAppAccountAuthenticationExtensionCallback::OnResult(const int32_t errCode, const AAFwk::WantParams &parameters)
{
    callback_->OnResult(errCode, parameters);
}

class MockJsAuthenticationExtension final : public OHOS::AbilityRuntime::AuthenticationExtension {
public:
    void StartAuthentication(
        const std::shared_ptr<AccountSA::AppAccountAuthenticationExtensionCallbackClient> &callbackPtr)
    {
        AAFwk::WantParams parameters;
        EXPECT_NE(callbackPtr, nullptr);
        callbackPtr->OnResult(0, parameters);
        return;
    }
};

class MockAppAccountAuthenticationExtensionService final : public AppAccountAuthenticationExtensionStub {
public:
    explicit MockAppAccountAuthenticationExtensionService(
        const std::shared_ptr<MockJsAuthenticationExtension> &extension)
        : innerExtension_(extension)
    {}
    ErrCode StartAuthentication(const AuthenticationRequest &request)
    {
        AppAccountAuthenticationExtensionCallbackClient *callbackClient =
            new (std::nothrow) AppAccountAuthenticationExtensionCallbackClient(request.callback);
        EXPECT_NE(callbackClient, nullptr);
        std::shared_ptr<AppAccountAuthenticationExtensionCallbackClient> callbackPtr(callbackClient);
        innerExtension_->StartAuthentication(callbackPtr);
        return ERR_OK;
    }

private:
    std::shared_ptr<MockJsAuthenticationExtension> innerExtension_ = nullptr;
};

void InitRequestCallback(
    const std::shared_ptr<TestAppAccountAuthenticationExtensionCallback> &callback, AuthenticationRequest &request)
{
    request.callback = new (std::nothrow) AppAccountAuthenticationExtensionCallbackService(callback);
    EXPECT_NE(request.callback, nullptr);
}

class AppAccountExtensionModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountExtensionModuleTest::SetUpTestCase(void)
{}

void AppAccountExtensionModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase enter";
}

void AppAccountExtensionModuleTest::SetUp(void)
{}

void AppAccountExtensionModuleTest::TearDown(void)
{}

/**
 * @tc.name: StartAuthentication_0100
 * @tc.desc: test AppAccountAuthenticationExtensionProxy func StartAuthentication.
 * @tc.type: FUNC
 * @tc.require: issuesI7AVZ5
 */
HWTEST_F(AppAccountExtensionModuleTest, StartAuthentication_0100, TestSize.Level1)
{
    std::shared_ptr<MockJsAuthenticationExtension> innerExtension = std::make_shared<MockJsAuthenticationExtension>();
    EXPECT_NE(innerExtension, nullptr);
    sptr<MockAppAccountAuthenticationExtensionService> authenticationService =
        new (std::nothrow) MockAppAccountAuthenticationExtensionService(innerExtension);
    EXPECT_NE(authenticationService, nullptr);
    sptr<AppAccountAuthenticationExtensionProxy> authenticationProxy =
        new (std::nothrow) AppAccountAuthenticationExtensionProxy(authenticationService->AsObject());
    auto callback = std::make_shared<MockAppAccountAuthenticationExtensionCallback>();
    auto testCallbackCreate = std::make_shared<TestAppAccountAuthenticationExtensionCallback>(callback);
    EXPECT_CALL(*callback, OnResult(0, _)).Times(Exactly(1));
    AuthenticationRequest request;
    InitRequestCallback(testCallbackCreate, request);
    EXPECT_NE(authenticationProxy, nullptr);
    EXPECT_EQ(authenticationProxy->StartAuthentication(request), ERR_OK);
}

/**
 * @tc.name: StartAuthentication_0200
 * @tc.desc: test AppAccountAuthenticationExtensionService func StartAuthentication.
 * @tc.type: FUNC
 * @tc.require: issuesI7AVZ5
 */
HWTEST_F(AppAccountExtensionModuleTest, StartAuthentication_0200, TestSize.Level1)
{
    OHOS::AbilityRuntime::JsRuntime jsRuntime;
    std::shared_ptr<AccountJsKit::JsAuthenticationExtension> innerExtension =
        std::make_shared<OHOS::AccountJsKit::JsAuthenticationExtension>(jsRuntime);
    EXPECT_NE(innerExtension, nullptr);
    sptr<AppAccountAuthenticationExtensionService> authenticationService =
        new (std::nothrow) AppAccountAuthenticationExtensionService(innerExtension);
    EXPECT_NE(authenticationService, nullptr);
    AuthenticationRequest request;
    EXPECT_EQ(authenticationService->StartAuthentication(request), ERR_OK);
}

/**
 * @tc.name: StartAuthentication_0300
 * @tc.desc: test AppAccountAuthenticationExtensionService func StartAuthentication with extension is nullptr.
 * @tc.type: FUNC
 * @tc.require: issuesI7AVZ5
 */
HWTEST_F(AppAccountExtensionModuleTest, StartAuthentication_0300, TestSize.Level1)
{
    std::shared_ptr<AccountJsKit::JsAuthenticationExtension> innerExtension = nullptr;
    sptr<AppAccountAuthenticationExtensionService> authenticationService =
        new (std::nothrow) AppAccountAuthenticationExtensionService(innerExtension);
    EXPECT_NE(authenticationService, nullptr);
    AuthenticationRequest request;
    EXPECT_EQ(authenticationService->StartAuthentication(request), ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: StartAuthentication_0400
 * @tc.desc: test AppAccountAuthenticationExtensionProxy func StartAuthentication with callback is nullptr.
 * @tc.type: FUNC
 * @tc.require: issuesI7AVZ5
 */
HWTEST_F(AppAccountExtensionModuleTest, StartAuthentication_0400, TestSize.Level1)
{
    std::shared_ptr<MockJsAuthenticationExtension> innerExtension = std::make_shared<MockJsAuthenticationExtension>();
    EXPECT_NE(innerExtension, nullptr);
    sptr<MockAppAccountAuthenticationExtensionService> authenticationService =
        new (std::nothrow) MockAppAccountAuthenticationExtensionService(innerExtension);
    EXPECT_NE(authenticationService, nullptr);
    auto callback = std::make_shared<MockAppAccountAuthenticationExtensionCallback>();
    auto testCallbackCreate = std::make_shared<TestAppAccountAuthenticationExtensionCallback>(callback);
    sptr<AppAccountAuthenticationExtensionProxy> authenticationProxy =
        new (std::nothrow) AppAccountAuthenticationExtensionProxy(authenticationService->AsObject());
    EXPECT_NE(authenticationProxy, nullptr);
    AuthenticationRequest request;
    EXPECT_EQ(authenticationProxy->StartAuthentication(request), ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
}

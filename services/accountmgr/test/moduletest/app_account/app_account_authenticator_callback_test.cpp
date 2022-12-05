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

#include "account_log_wrapper.h"
#include "app_account_common.h"
#define private public
#include "app_account_authenticator_callback.h"
#include "app_account_authenticator_callback_stub.h"
#include "app_account_authenticator_callback_proxy.h"
#include "iapp_account_authenticator_callback.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

bool g_status = false;

class MockAppAccountAuthenticatorCallbackStub : public AppAccountAuthenticatorCallbackStub {
public:
    void OnResult(int32_t resultCode, const AAFwk::Want &result)
    {
        g_status = true;
    }
    virtual void OnRequestRedirected(AAFwk::Want &request)
    {
        g_status = true;
    }
    virtual void OnRequestContinued()
    {
        g_status = true;
    }
};

class AppAccountAuthenticatorCallbackModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountAuthenticatorCallbackModuleTest::SetUpTestCase(void)
{}

void AppAccountAuthenticatorCallbackModuleTest::TearDownTestCase(void)
{}

void AppAccountAuthenticatorCallbackModuleTest::SetUp(void)
{}

void AppAccountAuthenticatorCallbackModuleTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountAuthenticatorCallbackTest_OnResult_0100
 * @tc.desc: test authenticatecallback func OnResult.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountAuthenticatorCallbackModuleTest, AppAccountAuthenticatorCallbackTest_OnResult_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountAuthenticatorCallbackTest_OnResult_0100");

    AAFwk::Want result;
    int32_t testResultCode = 1;
    sptr<IAppAccountAuthenticatorCallback> oauthCallbackPtr =
        new (std::nothrow) MockAppAccountAuthenticatorCallbackStub();
    ASSERT_NE(oauthCallbackPtr, nullptr);
    sptr<IRemoteObject> callback = oauthCallbackPtr->AsObject();
    AppAccountAuthenticatorCallbackProxy testCallbackProxy(callback);
    testCallbackProxy.OnResult(testResultCode, result);
    EXPECT_EQ(g_status, true);
    g_status = false;

    AAFwk::Want request;
    testCallbackProxy.OnRequestRedirected(request);
    EXPECT_EQ(g_status, true);
    g_status = false;

    testCallbackProxy.OnRequestContinued();
    EXPECT_EQ(g_status, true);
    g_status = false;
}

/**
 * @tc.name: AppAccountAuthenticatorCallbackTest_func_0200
 * @tc.desc: test authenticatecallback func OnRequestRedirected and OnRequestContinued.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountAuthenticatorCallbackModuleTest, AppAccountAuthenticatorCallbackTest_func_0200, TestSize.Level1)
{
    const std::string sessionId = "testsessionid";
    auto AppAccountAuthenticatorCallbackPtr = std::make_shared<AppAccountAuthenticatorCallback>(sessionId);
    ASSERT_NE(nullptr, AppAccountAuthenticatorCallbackPtr);
    AAFwk::Want reques;
    AppAccountAuthenticatorCallbackPtr->OnRequestRedirected(reques);
    ASSERT_EQ(AppAccountAuthenticatorCallbackPtr->sessionId_, sessionId);
    AppAccountAuthenticatorCallbackPtr->OnRequestContinued();
    ASSERT_EQ(AppAccountAuthenticatorCallbackPtr->sessionId_, sessionId);
}
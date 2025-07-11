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
namespace {
const uint32_t TEST_CODE = 1;
const int32_t TEST_INT32 = 1;
const int32_t TEST_ERR_INVALID_DATA = 5;
}

class MockAppAccountAuthenticatorCallbackStub : public AppAccountAuthenticatorCallbackStub {
public:
    ErrCode OnResult(int32_t resultCode, const AAFwk::Want &result)
    {
        g_status = true;
        return ERR_OK;
    }
    virtual ErrCode OnRequestRedirected(const AAFwk::Want &request)
    {
        g_status = true;
        return ERR_OK;
    }
    virtual ErrCode OnRequestContinued()
    {
        g_status = true;
        return ERR_OK;
    }
    virtual ErrCode CallbackEnter([[maybe_unused]] uint32_t code)
    {
        g_status = true;
        return ERR_OK;
    }
    virtual ErrCode CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
    {
        g_status = true;
        return ERR_OK;
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

void AppAccountAuthenticatorCallbackModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

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

/**
 * @tc.name: AppAccountAuthenticatorCallbackTest_func_0300
 * @tc.desc: test CallbackEnter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountAuthenticatorCallbackModuleTest, AppAccountAuthenticatorCallbackTest_func_0300, TestSize.Level3)
{
    const std::string sessionId = "testsessionid";
    auto AppAccountAuthenticatorCallbackPtr = std::make_shared<AppAccountAuthenticatorCallback>(sessionId);
    EXPECT_EQ(AppAccountAuthenticatorCallbackPtr->CallbackEnter(TEST_CODE), ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticatorCallbackTest_func_0400
 * @tc.desc: test CallbackExit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountAuthenticatorCallbackModuleTest, AppAccountAuthenticatorCallbackTest_func_0400, TestSize.Level3)
{
    const std::string sessionId = "testsessionid";
    auto AppAccountAuthenticatorCallbackPtr = std::make_shared<AppAccountAuthenticatorCallback>(sessionId);
    EXPECT_EQ(AppAccountAuthenticatorCallbackPtr->CallbackExit(
        static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_RESULT), TEST_ERR_INVALID_DATA),
        ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE);
}

/**
 * @tc.name: AppAccountAuthenticatorCallbackTest_func_0500
 * @tc.desc: test CallbackExit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountAuthenticatorCallbackModuleTest, AppAccountAuthenticatorCallbackTest_func_0500, TestSize.Level3)
{
    const std::string sessionId = "testsessionid";
    auto AppAccountAuthenticatorCallbackPtr = std::make_shared<AppAccountAuthenticatorCallback>(sessionId);
    EXPECT_EQ(AppAccountAuthenticatorCallbackPtr->CallbackExit(
        static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_REQUEST_REDIRECTED),
        TEST_ERR_INVALID_DATA), ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE);
}

/**
 * @tc.name: AppAccountAuthenticatorCallbackTest_func_0600
 * @tc.desc: test CallbackExit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountAuthenticatorCallbackModuleTest, AppAccountAuthenticatorCallbackTest_func_0600, TestSize.Level3)
{
    const std::string sessionId = "testsessionid";
    auto AppAccountAuthenticatorCallbackPtr = std::make_shared<AppAccountAuthenticatorCallback>(sessionId);
    EXPECT_EQ(AppAccountAuthenticatorCallbackPtr->CallbackExit(
        static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_REQUEST_REDIRECTED), TEST_INT32),
        ERR_NONE);
}

/**
 * @tc.name: AppAccountAuthenticatorCallbackTest_func_0700
 * @tc.desc: test CallbackExit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountAuthenticatorCallbackModuleTest, AppAccountAuthenticatorCallbackTest_func_0700, TestSize.Level3)
{
    const std::string sessionId = "testsessionid";
    auto AppAccountAuthenticatorCallbackPtr = std::make_shared<AppAccountAuthenticatorCallback>(sessionId);
    EXPECT_EQ(AppAccountAuthenticatorCallbackPtr->CallbackExit(
        static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_REQUEST_REDIRECTED), TEST_INT32),
        ERR_NONE);
}
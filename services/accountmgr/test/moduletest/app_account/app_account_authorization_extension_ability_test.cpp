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
#include "app_account_authorization_extension_callback_client.h"
#include "app_account_authorization_extension_callback_service.h"
#include "app_account_authorization_extension_proxy.h"
#include "app_account_authorization_extension_service.h"
#include "app_account_authorization_extension_stub.h"
#undef private
#include "app_account_common.h"
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
    void OnRequestRedirected(const AAFwk::Want &request) override;

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

void TestAppAccountAuthorizationExtensionCallback::OnRequestRedirected(const AAFwk::Want &request)
{}

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

void AppAccountExtensionModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    AuthorizationExtensionOnResultCallbackFunc onResultFunc;
    AuthorizationExtensionOnRequestRedirectedCallbackFunc onRequestRedirectedFunc;
    callbackServicePtr_ =
        new (std::nothrow) AppAccountAuthorizationExtensionCallbackService(onResultFunc, onRequestRedirectedFunc);
    ASSERT_NE(callbackServicePtr_, nullptr);
    MockService_ = callbackServicePtr_->AsObject();
    callbackProxyPtr_ = new (std::nothrow) AppAccountAuthorizationExtensionCallbackProxy(MockService_);
}

void AppAccountExtensionModuleTest::TearDown(void)
{}

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

/**
 * @tc.name: OnRequestRedirected_001
 * @tc.desc: test OnRequestRedirected callback client cov
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountExtensionModuleTest, OnRequestRedirected_001, TestSize.Level1)
{
    auto callbackClient = new (std::nothrow) AppAccountAuthorizationExtensionCallbackClient(callbackProxyPtr_);
    ASSERT_NE(callbackClient, nullptr);
    AAFwk::Want request;
    callbackClient->OnRequestRedirected(request);
    EXPECT_NE(callbackClient->proxy_, nullptr);
}

/**
 * @tc.name: OnRequestRedirected_002
 * @tc.desc: test OnRequestRedirected callback stub cov
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountExtensionModuleTest, OnRequestRedirected_002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(callbackServicePtr_->OnRemoteRequest(1, data, reply, option), ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR);
}

/**
 * @tc.name: OnRequestRedirected_003
 * @tc.desc: test OnRequestRedirected callback stub cov
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountExtensionModuleTest, OnRequestRedirected_003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    AAFwk::Want request;
    EXPECT_EQ(data.WriteParcelable(&request), true);
    EXPECT_EQ(callbackServicePtr_->ProcOnRequestRedirected(data, reply), ERR_NONE);
}

/**
 * @tc.name: OnRequestRedirected_004
 * @tc.desc: test OnRequestRedirected callback stub cov
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountExtensionModuleTest, OnRequestRedirected_004, TestSize.Level1)
{
    auto callbackClient = new (std::nothrow) AppAccountAuthorizationExtensionCallbackClient(nullptr);
    ASSERT_NE(callbackClient, nullptr);
    AAFwk::Want request;
    callbackClient->OnRequestRedirected(request);
    EXPECT_EQ(callbackClient->proxy_, nullptr);
}
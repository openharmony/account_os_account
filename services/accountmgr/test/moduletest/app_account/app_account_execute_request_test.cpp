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

#define private public
#include "app_account_authorization_extension_callback_stub.h"
#include "app_account_common.h"
#include "app_account_constants.h"
#include "app_account_manager_service.h"
#include "string_wrapper.h"
#undef private
#include "account_log_wrapper.h"
#include "datetime_ex.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AppExecFwk;
#ifdef HAS_CES_PART
using namespace OHOS::EventFwk;
#endif // HAS_CES_PART
namespace {
const std::string STRING_OWNER = "com.example.owner";
const std::string STRING_BUNDLE_NAME_NOT_INSTALLED = "com.example.not_installed";
const std::string STRING_NORMAL_BUNDLENAME = "com.example.normal.bundle";
const std::string STRING_BUNDLEINFO_WITH_NO_VALID_EXTENSION = "com.bundleInfo.noExtension";
const std::string STRING_BUNDLEINFO_WITH_NO_VALID_TYPE_EXTENSION = "com.bundleInfo.noValidTypeExtension";
const std::string STRING_BUNDLEINFO_WITH_MULTIPLE_VALID_EXTENSION = "com.bundleInfo.noExtension";
const std::string STRING_ABILITY_NAME = "com.example.owner.MainAbility";
const std::string STRING_ABILITY_INVALID_NAME = "com.example.invalid.MainAbility";
const std::string STRING_ABILITY_NAME_WITH_NO_INFO = "com.example.owner.MainAbilityWithNoInfo";
const std::string STRING_ABILITY_NAME_WITH_CONNECT_FAILED = "com.example.MainAbilityWithConnectFailed";
const std::string STRING_ABILITY_NAME_WITH_NO_PROXY = "com.example.MainAbilityWithNoProxy";
std::shared_ptr<AppAccountManagerService> g_accountManagerService = std::make_shared<AppAccountManagerService>();
}  // namespace

class MockAppAccountAuthorizationExtensionCallback {
public:
    MOCK_METHOD2(OnResult, void(const int32_t errCode, const AAFwk::WantParams &parameters));
};

class MockAppAccountAuthorizationExtensionCallbackStub final : public AppAccountAuthorizationExtensionCallbackStub {
public:
    explicit MockAppAccountAuthorizationExtensionCallbackStub(
        const std::shared_ptr<MockAppAccountAuthorizationExtensionCallback> &callback)
        : callback_(callback)
    {}
    virtual ~MockAppAccountAuthorizationExtensionCallbackStub();
    void OnResult(const AsyncCallbackError &businessError, const AAFwk::WantParams &parameters) override;
    void OnRequestRedirected(const AAFwk::Want &request) override;

private:
    std::shared_ptr<MockAppAccountAuthorizationExtensionCallback> callback_;
};

MockAppAccountAuthorizationExtensionCallbackStub::~MockAppAccountAuthorizationExtensionCallbackStub()
{}

void MockAppAccountAuthorizationExtensionCallbackStub::OnResult(
    const AsyncCallbackError &businessError, const AAFwk::WantParams &parameters)
{
    ACCOUNT_LOGI("mock AppAccountAuthorizationExtensionCallbackStub OnResult enter");
    callback_->OnResult(businessError.code, parameters);
    return;
}

void MockAppAccountAuthorizationExtensionCallbackStub::OnRequestRedirected(const AAFwk::Want &request)
{}

class AppAccountManagerServiceModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    void ClearDataStorage();
};

void AppAccountManagerServiceModuleTest::SetUpTestCase(void)
{}

void AppAccountManagerServiceModuleTest::TearDownTestCase(void)
{}

void AppAccountManagerServiceModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AppAccountManagerServiceModuleTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountManagerService_ExecuteRequest_0100
 * @tc.desc: test ExecuteRequest normal case
 * @tc.type: FUNC
 * @tc.require: issueI7AVZ5
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_ExecuteRequest_0100, TestSize.Level1)
{
    auto testCallback = std::make_shared<MockAppAccountAuthorizationExtensionCallback>();
    sptr<IAppAccountAuthorizationExtensionCallback> callback =
        new (std::nothrow)MockAppAccountAuthorizationExtensionCallbackStub(testCallback);
    ASSERT_NE(callback, nullptr);
    AccountCapabilityRequest request;
    request.bundleName = STRING_NORMAL_BUNDLENAME;
    request.abilityName = STRING_ABILITY_NAME;
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(testing::Exactly(1));
    ErrCode result = g_accountManagerService->ExecuteRequest(request, callback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_ExecuteRequest_0200
 * @tc.desc: test ExecuteRequest normal case with only bundleName
 * @tc.type: FUNC
 * @tc.require: issueI7AVZ5
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_ExecuteRequest_0200, TestSize.Level1)
{
    auto testCallback = std::make_shared<MockAppAccountAuthorizationExtensionCallback>();
    sptr<IAppAccountAuthorizationExtensionCallback> callback =
        new (std::nothrow)MockAppAccountAuthorizationExtensionCallbackStub(testCallback);
    ASSERT_NE(callback, nullptr);
    AccountCapabilityRequest request;
    request.bundleName = STRING_NORMAL_BUNDLENAME;
    request.abilityName = "";
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(testing::Exactly(1));
    ErrCode result = g_accountManagerService->ExecuteRequest(request, callback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_ExecuteRequest_0300
 * @tc.desc: test ExecuteRequest error case with ability is invalid
 * @tc.type: FUNC
 * @tc.require: issueI7AVZ5
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_ExecuteRequest_0300, TestSize.Level1)
{
    auto testCallback = std::make_shared<MockAppAccountAuthorizationExtensionCallback>();
    sptr<IAppAccountAuthorizationExtensionCallback> callback =
        new (std::nothrow)MockAppAccountAuthorizationExtensionCallbackStub(testCallback);
    ASSERT_NE(callback, nullptr);
    AccountCapabilityRequest request;
    request.bundleName = STRING_OWNER;
    request.abilityName = STRING_ABILITY_INVALID_NAME;
    ErrCode result = g_accountManagerService->ExecuteRequest(request, callback);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManagerService_ExecuteRequest_0400
 * @tc.desc: test ExecuteRequest error case with abilityInfo is empty
 * @tc.type: FUNC
 * @tc.require: issueI7AVZ5
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_ExecuteRequest_0400, TestSize.Level1)
{
    auto testCallback = std::make_shared<MockAppAccountAuthorizationExtensionCallback>();
    sptr<IAppAccountAuthorizationExtensionCallback> callback =
        new (std::nothrow)MockAppAccountAuthorizationExtensionCallbackStub(testCallback);
    ASSERT_NE(callback, nullptr);
    AccountCapabilityRequest request;
    request.bundleName = STRING_OWNER;
    request.abilityName = STRING_ABILITY_NAME_WITH_NO_INFO;
    ErrCode result = g_accountManagerService->ExecuteRequest(request, callback);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManagerService_ExecuteRequest_0500
 * @tc.desc: test ExecuteRequest error case with bundleName is invalid
 * @tc.type: FUNC
 * @tc.require: issueI7AVZ5
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_ExecuteRequest_0500, TestSize.Level1)
{
    auto testCallback = std::make_shared<MockAppAccountAuthorizationExtensionCallback>();
    sptr<IAppAccountAuthorizationExtensionCallback> callback =
        new (std::nothrow)MockAppAccountAuthorizationExtensionCallbackStub(testCallback);
    ASSERT_NE(callback, nullptr);
    AccountCapabilityRequest request;
    request.bundleName = STRING_BUNDLE_NAME_NOT_INSTALLED;
    request.abilityName = "";
    ErrCode result = g_accountManagerService->ExecuteRequest(request, callback);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManagerService_ExecuteRequest_0600
 * @tc.desc: test ExecuteRequest error case with bundleInfo is empty
 * @tc.type: FUNC
 * @tc.require: issueI7AVZ5
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_ExecuteRequest_0600, TestSize.Level1)
{
    auto testCallback = std::make_shared<MockAppAccountAuthorizationExtensionCallback>();
    sptr<IAppAccountAuthorizationExtensionCallback> callback =
        new (std::nothrow)MockAppAccountAuthorizationExtensionCallbackStub(testCallback);
    ASSERT_NE(callback, nullptr);
    AccountCapabilityRequest request;
    request.bundleName = STRING_BUNDLEINFO_WITH_NO_VALID_EXTENSION;
    request.abilityName = "";
    ErrCode result = g_accountManagerService->ExecuteRequest(request, callback);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManagerService_ExecuteRequest_0700
 * @tc.desc: test ExecuteRequest error case with abilityInfo's type is invalid
 * @tc.type: FUNC
 * @tc.require: issueI7AVZ5
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_ExecuteRequest_0700, TestSize.Level1)
{
    auto testCallback = std::make_shared<MockAppAccountAuthorizationExtensionCallback>();
    sptr<IAppAccountAuthorizationExtensionCallback> callback =
        new (std::nothrow)MockAppAccountAuthorizationExtensionCallbackStub(testCallback);
    ASSERT_NE(callback, nullptr);
    AccountCapabilityRequest request;
    request.bundleName = STRING_BUNDLEINFO_WITH_NO_VALID_TYPE_EXTENSION;
    request.abilityName = "";
    ErrCode result = g_accountManagerService->ExecuteRequest(request, callback);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManagerService_ExecuteRequest_0800
 * @tc.desc: test ExecuteRequest error case with bundle has multiple valid abilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI7AVZ5
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_ExecuteRequest_0800, TestSize.Level1)
{
    auto testCallback = std::make_shared<MockAppAccountAuthorizationExtensionCallback>();
    sptr<IAppAccountAuthorizationExtensionCallback> callback =
        new (std::nothrow)MockAppAccountAuthorizationExtensionCallbackStub(testCallback);
    ASSERT_NE(callback, nullptr);
    AccountCapabilityRequest request;
    request.bundleName = STRING_BUNDLEINFO_WITH_MULTIPLE_VALID_EXTENSION;
    request.abilityName = "";
    ErrCode result = g_accountManagerService->ExecuteRequest(request, callback);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManagerService_ExecuteRequest_0900
 * @tc.desc: test ExecuteRequest error case with ConnectAbility failed
 * @tc.type: FUNC
 * @tc.require: issueI7AVZ5
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_ExecuteRequest_0900, TestSize.Level1)
{
    auto testCallback = std::make_shared<MockAppAccountAuthorizationExtensionCallback>();
    sptr<IAppAccountAuthorizationExtensionCallback> callback =
        new (std::nothrow)MockAppAccountAuthorizationExtensionCallbackStub(testCallback);
    ASSERT_NE(callback, nullptr);
    AccountCapabilityRequest request;
    request.bundleName = STRING_NORMAL_BUNDLENAME;
    request.abilityName = STRING_ABILITY_NAME_WITH_CONNECT_FAILED;
    ErrCode result = g_accountManagerService->ExecuteRequest(request, callback);
    EXPECT_EQ(result, ERR_JS_SYSTEM_SERVICE_EXCEPTION);
}

/**
 * @tc.name: AppAccountManagerService_ExecuteRequest_1000
 * @tc.desc: test ExecuteRequest error case with return proxy is nullptr
 * @tc.type: FUNC
 * @tc.require: issueI7AVZ5
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_ExecuteRequest_1000, TestSize.Level1)
{
    auto testCallback = std::make_shared<MockAppAccountAuthorizationExtensionCallback>();
    sptr<IAppAccountAuthorizationExtensionCallback> callback =
        new (std::nothrow)MockAppAccountAuthorizationExtensionCallbackStub(testCallback);
    ASSERT_NE(callback, nullptr);
    AccountCapabilityRequest request;
    request.bundleName = STRING_NORMAL_BUNDLENAME;
    request.abilityName = STRING_ABILITY_NAME_WITH_NO_PROXY;
    EXPECT_CALL(*testCallback, OnResult(ERR_JS_SYSTEM_SERVICE_EXCEPTION, _)).Times(testing::Exactly(1));
    ErrCode result = g_accountManagerService->ExecuteRequest(request, callback);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_ExecuteRequest_1100
 * @tc.desc: test ExecuteRequest error case with startAuth failed
 * @tc.type: FUNC
 * @tc.require: issueI7AVZ5
 */
HWTEST_F(AppAccountManagerServiceModuleTest, AppAccountManagerService_ExecuteRequest_1100, TestSize.Level1)
{
    auto testCallback = std::make_shared<MockAppAccountAuthorizationExtensionCallback>();
    sptr<IAppAccountAuthorizationExtensionCallback> callback =
        new (std::nothrow)MockAppAccountAuthorizationExtensionCallbackStub(testCallback);
    ASSERT_NE(callback, nullptr);
    AccountCapabilityRequest request;
    request.bundleName = STRING_NORMAL_BUNDLENAME;
    request.abilityName = STRING_ABILITY_NAME;
    AAFwk::WantParams testParameters;
    std::string testValue = "testValue";
    testParameters.SetParam("keyStr", OHOS::AAFwk::String::Box(testValue));
    request.parameters = testParameters;
    EXPECT_CALL(*testCallback, OnResult(ERR_JS_SYSTEM_SERVICE_EXCEPTION, _)).Times(testing::Exactly(1));
    ErrCode result = g_accountManagerService->ExecuteRequest(request, callback);
    EXPECT_EQ(result, ERR_OK);
}

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
#include "app_mgr_constants.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"
#define protected public
#define private public
#include "app_account_authenticator_session.h"
#include "app_account_check_labels_callback.h"
#include "app_account_check_labels_session.h"
#include "app_account_info.h"
#include "app_account_constants.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string NAME = "NAME";
const std::string SESSION_ID = "256";
const std::string OWNER = "owner";
const std::int32_t NUMBER_SIZE = 1;
const std::int32_t NUMBER_ZERO = 0;
}

class AppAccountCheckLabelsModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    std::shared_ptr<AppAccountCheckLabelsSession> appAccountCheckLabelsSessionPtr;
    std::shared_ptr<AppAccountCheckLabelsCallback> appAccountCheckLabelsCallbackPtr;
};

void AppAccountCheckLabelsModuleTest::SetUpTestCase(void)
{}

void AppAccountCheckLabelsModuleTest::TearDownTestCase(void)
{}

void AppAccountCheckLabelsModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    AppAccountInfo testAppAccountInfo(NAME, OWNER);
    std::vector<AppAccountInfo> accounts;
    accounts.emplace_back(testAppAccountInfo);
    AuthenticatorSessionRequest request;
    std::uint64_t id = 0;
    request.name = NAME;
    appAccountCheckLabelsSessionPtr = std::make_shared<AppAccountCheckLabelsSession>(accounts, request, id);
    appAccountCheckLabelsCallbackPtr = std::make_shared<AppAccountCheckLabelsCallback>(accounts, request, SESSION_ID);
}

void AppAccountCheckLabelsModuleTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountAuthenticateTest_Open_0100
 * @tc.desc: test AppAccountCheckLabelsSession func failed with open twice.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountCheckLabelsModuleTest_Open_0100, TestSize.Level1)
{
    ASSERT_NE(appAccountCheckLabelsSessionPtr, nullptr);

    ErrCode result = appAccountCheckLabelsSessionPtr->Open();
    ASSERT_EQ(result, ERR_OK);
    result = appAccountCheckLabelsSessionPtr->Open();
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION);
}

/**
 * @tc.name: AppAccountAuthenticateTest_CheckLabels_0100
 * @tc.desc: test AppAccountCheckLabelsSession func CheckLabels success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountCheckLabelsModuleTest_CheckLabels_0100, TestSize.Level1)
{
    ASSERT_NE(appAccountCheckLabelsSessionPtr, nullptr);

    std::vector<AppAccountInfo> accounts;
    AuthenticatorSessionRequest request;
    std::string sessionId = SESSION_ID;
    AppAccountInfo testAppAccountInfo(NAME, OWNER);
    accounts.emplace_back(testAppAccountInfo);
    appAccountCheckLabelsSessionPtr->checkCallback_ =
        new (std::nothrow) AppAccountCheckLabelsCallback(accounts, request, sessionId);
    ASSERT_NE(appAccountCheckLabelsSessionPtr->checkCallback_, nullptr);
    ErrCode result = appAccountCheckLabelsSessionPtr->CheckLabels();
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticateTest_GetRequest_0100
 * @tc.desc: test AppAccountCheckLabelsSession func GetRequest success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountCheckLabelsModuleTest_GetRequest_0100, TestSize.Level1)
{
    ASSERT_NE(appAccountCheckLabelsSessionPtr, nullptr);

    AuthenticatorSessionRequest resultRequest;
    appAccountCheckLabelsSessionPtr->GetRequest(resultRequest);
    ASSERT_EQ(resultRequest.name, NAME);
}

/**
 * @tc.name: AppAccountAuthenticateTest_GetRequest_0100
 * @tc.desc: test AppAccountCheckLabelsCallback func OnResult success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountCheckLabelsModuleTest_OnResult_0100, TestSize.Level1)
{
    ASSERT_NE(appAccountCheckLabelsCallbackPtr, nullptr);

    int32_t resultCode = -1;
    AAFwk::Want result;
    result.SetParam(Constants::KEY_BOOLEAN_RESULT, true);
    ASSERT_EQ(appAccountCheckLabelsCallbackPtr->accountsWithLabels_.size(), NUMBER_ZERO);
    ASSERT_EQ(appAccountCheckLabelsCallbackPtr->index_, NUMBER_ZERO);
    appAccountCheckLabelsCallbackPtr->isRequesting_ = true;
    appAccountCheckLabelsCallbackPtr->OnResult(resultCode, result);
    ASSERT_EQ(appAccountCheckLabelsCallbackPtr->index_, NUMBER_SIZE);
    ASSERT_EQ(appAccountCheckLabelsCallbackPtr->accountsWithLabels_.size(), NUMBER_SIZE);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OnRequestRedirected_0100
 * @tc.desc: test AppAccountCheckLabelsCallback func OnRequestRedirected success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountCheckLabelsModuleTest_OnRequestRedirected_0100, TestSize.Level1)
{
    ASSERT_NE(appAccountCheckLabelsCallbackPtr, nullptr);

    AAFwk::Want request;
    ASSERT_EQ(appAccountCheckLabelsCallbackPtr->index_, NUMBER_ZERO);
    appAccountCheckLabelsCallbackPtr->isRequesting_ = true;
    appAccountCheckLabelsCallbackPtr->OnRequestRedirected(request);
    ASSERT_EQ(appAccountCheckLabelsCallbackPtr->index_, NUMBER_SIZE);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OnRequestContinued_0100
 * @tc.desc: test AppAccountCheckLabelsCallback func OnRequestContinued success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountCheckLabelsModuleTest_OnRequestContinued_0100, TestSize.Level1)
{
    ASSERT_NE(appAccountCheckLabelsCallbackPtr, nullptr);

    ASSERT_EQ(appAccountCheckLabelsCallbackPtr->index_, NUMBER_ZERO);
    appAccountCheckLabelsCallbackPtr->isRequesting_ = true;
    appAccountCheckLabelsCallbackPtr->OnRequestContinued();
    ASSERT_EQ(appAccountCheckLabelsCallbackPtr->index_, NUMBER_SIZE);
}

/**
 * @tc.name: AppAccountAuthenticateTest_CallbackEnter_0100
 * @tc.desc: test AppAccountCheckLabelsCallback func CallbackEnter success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountAuthenticateTest_CallbackEnter_0100, TestSize.Level3)
{
    ASSERT_NE(appAccountCheckLabelsCallbackPtr, nullptr);
    EXPECT_EQ(appAccountCheckLabelsCallbackPtr->CallbackEnter(
        static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_RESULT)), ERR_OK);
}

/**
 * @tc.name: AppAccountAuthenticateTest_CallbackExit_0100
 * @tc.desc: test AppAccountCheckLabelsCallback func CallbackExit success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountAuthenticateTest_CallbackExit_0100, TestSize.Level3)
{
    ASSERT_NE(appAccountCheckLabelsCallbackPtr, nullptr);
    EXPECT_EQ(appAccountCheckLabelsCallbackPtr->CallbackExit(
        static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_RESULT), ERR_NONE), ERR_NONE);
}

/**
 * @tc.name: AppAccountAuthenticateTest_CallbackExit_0200
 * @tc.desc: test AppAccountCheckLabelsCallback func CallbackExit success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountAuthenticateTest_CallbackExit_0200, TestSize.Level3)
{
    ASSERT_NE(appAccountCheckLabelsCallbackPtr, nullptr);
    EXPECT_EQ(appAccountCheckLabelsCallbackPtr->CallbackExit(
        static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_REQUEST_REDIRECTED), ERR_NONE),
        ERR_NONE);
}

/**
 * @tc.name: AppAccountAuthenticateTest_CallbackExit_0300
 * @tc.desc: test AppAccountCheckLabelsCallback func CallbackExit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountAuthenticateTest_CallbackExit_0300, TestSize.Level3)
{
    ASSERT_NE(appAccountCheckLabelsCallbackPtr, nullptr);
    EXPECT_EQ(appAccountCheckLabelsCallbackPtr->CallbackExit(
        static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_RESULT), ERR_INVALID_DATA),
        ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE);
}

/**
 * @tc.name: AppAccountAuthenticateTest_CallbackExit_0400
 * @tc.desc: test AppAccountCheckLabelsCallback func CallbackExit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountAuthenticateTest_CallbackExit_0400, TestSize.Level3)
{
    ASSERT_NE(appAccountCheckLabelsCallbackPtr, nullptr);
    EXPECT_EQ(appAccountCheckLabelsCallbackPtr->CallbackExit(static_cast<uint32_t>(
        IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_REQUEST_REDIRECTED), ERR_INVALID_DATA),
        ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE);
}

/**
 * @tc.name: AppAccountAuthenticateTest_CallbackExit_0500
 * @tc.desc: test AppAccountCheckLabelsCallback func CallbackExit success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountAuthenticateTest_CallbackExit_0500, TestSize.Level3)
{
    ASSERT_NE(appAccountCheckLabelsCallbackPtr, nullptr);
    EXPECT_EQ(appAccountCheckLabelsCallbackPtr->CallbackExit(static_cast<uint32_t>(
        IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_REQUEST_CONTINUED), ERR_NONE), ERR_NONE);
}

class NativeAppAuthResultTestHelper {
public:
    NativeAppAuthResultTestHelper(bool hasAuthResult, std::optional<AppAccountInfo> account)
        : hasAuthResult(hasAuthResult), account(account)
    {}

    AAFwk::Want ToWant();
    bool hasAuthResult = false;
    std::optional<AppAccountInfo> account = std::nullopt;
};

AAFwk::Want NativeAppAuthResultTestHelper::ToWant()
{
    AAFwk::Want want;
    AAFwk::WantParams accountParam;
    if (!hasAuthResult) {
        return want;
    }
    AAFwk::WantParams accountInfo;
    if (account.has_value()) {
        accountInfo.SetParam("name", AAFwk::String::Box(account->GetName()));
        accountInfo.SetParam("owner", AAFwk::String::Box(account->GetOwner()));
    }
    accountParam.SetParam("account", AAFwk::WantParamWrapper::Box(accountInfo));
    want.SetParams(accountParam);
    return want;
}

/**
 * @tc.name: AppAccountAuthenticateTest_NativeAppAuthResult_0100
 * @tc.desc: test NativeAppAuthResult data conversion.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountAuthenticateTest_NativeAppAuthResult_0100, TestSize.Level3)
{
    // empty want
    AAFwk::Want emptyWant;
    NativeAppAuthResult nativeAppAuthResultEmpty(emptyWant);
    ASSERT_EQ(nativeAppAuthResultEmpty.hasAuthResult, false);

    // empty account
    NativeAppAuthResultTestHelper emptyAccountHelper(true, std::nullopt);
    auto emptyAccountWantResult = emptyAccountHelper.ToWant();
    NativeAppAuthResult nativeAppAuthResultNoAccount(emptyAccountWantResult);
    ASSERT_EQ(nativeAppAuthResultNoAccount.hasAuthResult, true);
    ASSERT_EQ(nativeAppAuthResultNoAccount.account.has_value(), false);

    // full want with account
    AppAccountInfo accountInfo(NAME, OWNER);
    NativeAppAuthResultTestHelper fullAccountHelper(true, accountInfo);
    auto fullWantResult = fullAccountHelper.ToWant();
    NativeAppAuthResult nativeAppAuthResultWithAccount(fullWantResult);
    ASSERT_EQ(nativeAppAuthResultWithAccount.hasAuthResult, true);
    ASSERT_EQ(nativeAppAuthResultWithAccount.account.has_value(), true);
    ASSERT_EQ(nativeAppAuthResultWithAccount.account->GetName(), NAME);
    ASSERT_EQ(nativeAppAuthResultWithAccount.account->GetOwner(), OWNER);
}

/**
 * @tc.name: AppAccountAuthenticateTest_OnResultAPI9_0100
 * @tc.desc: test AppAccountCheckLabelsCallback func OnResultAPI9 success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountAuthenticateTest_OnResultAPI9_0100, TestSize.Level1)
{
    AppAccountInfo info(NAME, OWNER);
    std::vector<AppAccountInfo> accounts;
    accounts.emplace_back(info);
    AuthenticatorSessionRequest request;
    request.name = NAME;
    auto cbkPtr = std::make_shared<AppAccountCheckLabelsCallback>(accounts, request, SESSION_ID);
    // test OnResult with API9
    AAFwk::Want emptyWant;
    cbkPtr->isRequesting_ = true;
    ASSERT_EQ(cbkPtr->OnResult(-1, emptyWant), ERR_OK);
    cbkPtr->isRequesting_ = true;
    ASSERT_EQ(cbkPtr->OnResult(ERR_JS_ACCOUNT_NOT_FOUND, emptyWant), ERR_OK);
    cbkPtr->index_ = 2; // set index_ out of range
    cbkPtr->isRequesting_ = true;
    ASSERT_EQ(cbkPtr->OnResult(ERR_OK, emptyWant), ERR_OK);
    ASSERT_EQ(cbkPtr->accountsWithLabels_.size(), NUMBER_ZERO);
    cbkPtr->index_ = 0;
    cbkPtr->isRequesting_ = true;
    ASSERT_EQ(cbkPtr->OnResult(ERR_OK, emptyWant), ERR_OK);
    ASSERT_EQ(cbkPtr->accountsWithLabels_.size(), NUMBER_ZERO);
    // empty account
    NativeAppAuthResultTestHelper emptyAccountHelper(false, std::nullopt);
    auto emptyAuthResult = emptyAccountHelper.ToWant();
    cbkPtr->isRequesting_ = true;
    ASSERT_EQ(cbkPtr->OnResult(ERR_OK, emptyAuthResult), ERR_OK);
    ASSERT_EQ(cbkPtr->accountsWithLabels_.size(), NUMBER_ZERO);
    // full info
    cbkPtr->index_ = 0;
    NativeAppAuthResultTestHelper fullAccountHelper(true, info);
    auto fullWantResult = fullAccountHelper.ToWant();
    cbkPtr->isRequesting_ = true;
    ASSERT_EQ(cbkPtr->OnResult(ERR_OK, fullWantResult), ERR_OK);
    ASSERT_EQ(cbkPtr->accountsWithLabels_.size(), NUMBER_SIZE);
    cbkPtr->index_ = 0;
    AppAccountInfo diffAccountInfo("nameA", "ownerA");
    NativeAppAuthResultTestHelper diffAccountHelper(true, diffAccountInfo);
    auto diffWantResult = diffAccountHelper.ToWant();
    cbkPtr->isRequesting_ = true;
    ASSERT_EQ(cbkPtr->OnResult(ERR_OK, diffWantResult), ERR_OK);
    ASSERT_EQ(cbkPtr->accountsWithLabels_.size(), NUMBER_SIZE);
}

class AuthenticatorCallbackTest : public AppAccountAuthenticatorCallbackStub {
public:
    AuthenticatorCallbackTest() = default;
    ~AuthenticatorCallbackTest() override = default;

    ErrCode OnResult(int32_t resultCode, const AAFwk::Want &result) override
    {
        isOnresultCalled = true;
        resultWant = result;
        errCode = resultCode;
        return ERR_OK;
    }

    ErrCode OnRequestRedirected(const AAFwk::Want &request) override
    {
        isOnRequestRedirectedCalled = true;
        resultWant = request;
        return ERR_OK;
    }

    ErrCode OnRequestContinued() override
    {
        isOnRequestContinuedCalled = true;
        return ERR_OK;
    }

    ErrCode CallbackEnter([[maybe_unused]] uint32_t code) override
    {
        return ERR_OK;
    }
    ErrCode CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override
    {
        return ERR_OK;
    }

    void Clear()
    {
        isOnresultCalled = false;
        isOnRequestRedirectedCalled = false;
        isOnRequestContinuedCalled = false;
        resultWant = AAFwk::Want();
        errCode = ERR_OK;
    }

    bool isOnresultCalled = false;
    bool isOnRequestRedirectedCalled = false;
    bool isOnRequestContinuedCalled = false;
    AAFwk::Want resultWant;
    ErrCode errCode;
};

/**
 * @tc.name: AppAccountAuthenticateTest_CheckLabelsCallbackHelper_0100
 * @tc.desc: test ipc enter&exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountAuthenticateTest_CheckLabelsCallbackHelper_0100, TestSize.Level3)
{
    auto testCallback = sptr<AuthenticatorCallbackTest>::MakeSptr();
    auto cbkPtr = std::make_shared<CheckLabelsCallbackHelper>(NAME, OWNER, testCallback);
    ASSERT_EQ(cbkPtr->CallbackEnter(
        static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_RESULT)), ERR_NONE);

    ASSERT_EQ(cbkPtr->CallbackExit(
                  static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_RESULT), ERR_NONE),
        ERR_NONE);
    ASSERT_EQ(
        cbkPtr->CallbackExit(
            static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_REQUEST_REDIRECTED), ERR_NONE),
        ERR_NONE);
    ASSERT_EQ(cbkPtr->CallbackExit(
                  static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_RESULT), ERR_INVALID_DATA),
        ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE);
    ASSERT_EQ(cbkPtr->CallbackExit(
                  static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_REQUEST_REDIRECTED),
                  ERR_INVALID_DATA),
        ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE);
    ASSERT_EQ(
        cbkPtr->CallbackExit(
            static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_REQUEST_CONTINUED), ERR_NONE),
        ERR_NONE);
}

/**
 * @tc.name: AppAccountAuthenticateTest_CheckLabelsCallbackHelper_0200
 * @tc.desc: test OnRequestRedirected & OnRequestContinued
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountAuthenticateTest_CheckLabelsCallbackHelper_0200, TestSize.Level1)
{
    auto testCallback = sptr<AuthenticatorCallbackTest>::MakeSptr();
    auto cbkPtr = std::make_shared<CheckLabelsCallbackHelper>(NAME, OWNER, testCallback);
    AAFwk::Want request;
    request.SetParam(Constants::KEY_BOOLEAN_RESULT, true);
    ASSERT_EQ(cbkPtr->OnRequestRedirected(request), ERR_OK);
    ASSERT_EQ(testCallback->isOnRequestRedirectedCalled, true);
    ASSERT_TRUE(testCallback->resultWant.GetBoolParam(Constants::KEY_BOOLEAN_RESULT, false));

    ASSERT_EQ(cbkPtr->OnRequestContinued(), ERR_OK);
    ASSERT_EQ(testCallback->isOnRequestContinuedCalled, true);
}

/**
 * @tc.name: AppAccountAuthenticateTest_CheckLabelsCallbackHelper_0300
 * @tc.desc: test OnResult when below api 9
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountAuthenticateTest_CheckLabelsCallbackHelper_0300, TestSize.Level1)
{
    auto testCallback = sptr<AuthenticatorCallbackTest>::MakeSptr();
    auto cbkPtr = std::make_shared<CheckLabelsCallbackHelper>(NAME, OWNER, testCallback);
    AAFwk::Want result;
    result.SetParam(Constants::KEY_BOOLEAN_RESULT, false);
    ASSERT_EQ(cbkPtr->OnResult(-1, result), ERR_OK);
    ASSERT_EQ(testCallback->isOnresultCalled, true);
    ASSERT_EQ(testCallback->errCode, -1);
    ASSERT_EQ(testCallback->resultWant.ToString(), result.ToString());
}

/**
 * @tc.name: AppAccountAuthenticateTest_CheckLabelsCallbackHelper_0400
 * @tc.desc: test OnResult when above api 9
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountCheckLabelsModuleTest, AppAccountAuthenticateTest_CheckLabelsCallbackHelper_0400, TestSize.Level1)
{
    auto testCallback = sptr<AuthenticatorCallbackTest>::MakeSptr();
    auto cbkPtr = std::make_shared<CheckLabelsCallbackHelper>(NAME, OWNER, testCallback);
    NativeAppAuthResultTestHelper emptyAccountHelper(true, std::nullopt);
    auto emptyAccountWantResult = emptyAccountHelper.ToWant();
    ASSERT_EQ(cbkPtr->OnResult(ERR_JS_ACCOUNT_NOT_FOUND, emptyAccountWantResult), ERR_OK);
    ASSERT_EQ(testCallback->isOnresultCalled, true);
    ASSERT_EQ(testCallback->errCode, ERR_JS_ACCOUNT_NOT_FOUND);
    testCallback->Clear();
    ASSERT_EQ(cbkPtr->OnResult(1, emptyAccountWantResult), ERR_OK);
    ASSERT_EQ(testCallback->isOnresultCalled, true);
    ASSERT_EQ(testCallback->errCode, ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION);
    testCallback->Clear();

    ASSERT_EQ(cbkPtr->OnResult(ERR_OK, emptyAccountWantResult), ERR_OK);
    ASSERT_EQ(testCallback->isOnresultCalled, true);
    ASSERT_EQ(testCallback->errCode, ERR_OK);
    ASSERT_EQ(testCallback->resultWant.GetBoolParam(Constants::KEY_BOOLEAN_RESULT, true), false);
    testCallback->Clear();

    NativeAppAuthResultTestHelper emptyAuthResultHelper(false, std::nullopt);
    auto emptyAuthResult = emptyAuthResultHelper.ToWant();
    ASSERT_EQ(cbkPtr->OnResult(ERR_OK, emptyAuthResult), ERR_OK);
    ASSERT_EQ(testCallback->isOnresultCalled, true);
    ASSERT_EQ(testCallback->errCode, ERR_OK);
    ASSERT_EQ(testCallback->resultWant.GetBoolParam(Constants::KEY_BOOLEAN_RESULT, true), false);
    testCallback->Clear();

    AppAccountInfo info(NAME, OWNER);
    NativeAppAuthResultTestHelper fullAccountHelper(true, info);
    auto fullWantResult = fullAccountHelper.ToWant();
    ASSERT_EQ(cbkPtr->OnResult(ERR_OK, fullWantResult), ERR_OK);
    ASSERT_EQ(testCallback->isOnresultCalled, true);
    ASSERT_EQ(testCallback->errCode, ERR_OK);
    ASSERT_EQ(testCallback->resultWant.GetBoolParam(Constants::KEY_BOOLEAN_RESULT, false), true);
    testCallback->Clear();

    AppAccountInfo diffInfo("nameA", "ownerA");
    NativeAppAuthResultTestHelper diffAccountHelper(true, diffInfo);
    auto diffWantResult = diffAccountHelper.ToWant();
    ASSERT_EQ(cbkPtr->OnResult(ERR_OK, diffWantResult), ERR_OK);
    ASSERT_EQ(testCallback->isOnresultCalled, true);
    ASSERT_EQ(testCallback->errCode, ERR_OK);
    ASSERT_EQ(testCallback->resultWant.GetBoolParam(Constants::KEY_BOOLEAN_RESULT, true), false);
    testCallback->Clear();
}
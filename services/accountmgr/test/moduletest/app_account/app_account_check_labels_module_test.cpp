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

void AppAccountCheckLabelsModuleTest::SetUp(void)
{
    AppAccountInfo testAppAccountInfo(NAME, OWNER);
    std::vector<AppAccountInfo> accounts;
    accounts.emplace_back(testAppAccountInfo);
    AuthenticatorSessionRequest request;
    request.name = NAME;
    appAccountCheckLabelsSessionPtr = std::make_shared<AppAccountCheckLabelsSession>(accounts, request);
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
    appAccountCheckLabelsCallbackPtr->OnRequestContinued();
    ASSERT_EQ(appAccountCheckLabelsCallbackPtr->index_, NUMBER_SIZE);
}
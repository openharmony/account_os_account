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
#include "account_error_no.h"
#include "app_account_common.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

constexpr int32_t MAX_VEC_SIZE = 1030;
constexpr int32_t MAX_CUSTOM_DATA_SIZE = 1024;
constexpr int32_t INVALID_ERR_CODE = -1;

class AppAccountCommonTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountCommonTest::SetUpTestCase(void)
{}

void AppAccountCommonTest::TearDownTestCase(void)
{}

void AppAccountCommonTest::SetUp(void)
{}

void AppAccountCommonTest::TearDown(void)
{}
/**
 * @tc.name: SelectAccountsOptions Marshalling test
 * @tc.desc: Func Marshalling.
 * @tc.type: FUNC
 * @tc.require issueI5RWXN
 */
HWTEST_F(AppAccountCommonTest, Marshalling001, TestSize.Level0)
{
    ACCOUNT_LOGI("Marshalling001");
    Parcel Parcel;
    SelectAccountsOptions option1;
    option1.hasAccounts = true;
    option1.hasOwners = true;
    option1.hasLabels = true;
    option1.allowedOwners.emplace_back("test1");
    option1.requiredLabels.emplace_back("test2");

    EXPECT_EQ(option1.Marshalling(Parcel), true);
    SelectAccountsOptions *option2 = option1.Unmarshalling(Parcel);
    EXPECT_NE(option2, nullptr);

    EXPECT_EQ(option2->hasAccounts, true);
    EXPECT_EQ(option2->hasOwners, true);
    EXPECT_EQ(option2->hasLabels, true);
    EXPECT_EQ(option2->allowedOwners[0], "test1");
    EXPECT_EQ(option2->requiredLabels[0], "test2");
}

/**
 * @tc.name: VerifyCredentialOptions Marshalling test
 * @tc.desc: Func Marshalling.
 * @tc.type: FUNC
 * @tc.require issueI5RWXN
 */
HWTEST_F(AppAccountCommonTest, Marshalling002, TestSize.Level0)
{
    ACCOUNT_LOGI("Marshalling002");
    Parcel Parcel;
    VerifyCredentialOptions option1;
    option1.credentialType = "test1";
    option1.credential = "test2";

    EXPECT_EQ(option1.Marshalling(Parcel), true);
    VerifyCredentialOptions *option2 = option1.Unmarshalling(Parcel);
    EXPECT_NE(option2, nullptr);

    EXPECT_EQ(option2->credentialType, "test1");
    EXPECT_EQ(option2->credential, "test2");
}

/**
 * @tc.name: CreateAccountOptions Marshalling test
 * @tc.desc: Func Marshalling.
 * @tc.type: FUNC
 * @tc.require issueI5RWXN
 */
HWTEST_F(AppAccountCommonTest, Marshalling003, TestSize.Level0)
{
    ACCOUNT_LOGI("Marshalling003");
    Parcel Parcel;
    CreateAccountOptions option1;
    option1.customData["test"] = "test2";

    EXPECT_EQ(option1.Marshalling(Parcel), true);
    CreateAccountOptions *option2 = option1.Unmarshalling(Parcel);
    EXPECT_NE(option2, nullptr);

    EXPECT_EQ(option2->customData["test"], "test2");
}

/**
 * @tc.name: CreateAccountImplicitlyOptions Marshalling test
 * @tc.desc: Func Marshalling.
 * @tc.type: FUNC
 * @tc.require issueI5RWXN
 */
HWTEST_F(AppAccountCommonTest, Marshalling004, TestSize.Level0)
{
    ACCOUNT_LOGI("Marshalling004");
    Parcel Parcel;
    CreateAccountImplicitlyOptions option1;
    option1.hasAuthType = true;
    option1.hasRequiredLabels = true;
    option1.authType = "test1";
    option1.requiredLabels.emplace_back("test2");

    EXPECT_EQ(option1.Marshalling(Parcel), true);
    CreateAccountImplicitlyOptions *option2 = option1.Unmarshalling(Parcel);
    EXPECT_NE(option2, nullptr);

    EXPECT_EQ(option2->hasAuthType, true);
    EXPECT_EQ(option2->hasRequiredLabels, true);
    EXPECT_EQ(option2->authType, "test1");
    EXPECT_EQ(option2->requiredLabels[0], "test2");
}

/**
 * @tc.name: CreateAccountOptions Marshalling test
 * @tc.desc: test ReadFromParcel of oversize customData.
 * @tc.type: FUNC
 * @tc.require issueI5RWXN
 */
HWTEST_F(AppAccountCommonTest, Marshalling005, TestSize.Level0)
{
    ACCOUNT_LOGI("Marshalling005");
    Parcel Parcel;
    CreateAccountOptions srcOptions;

    for (int i = 0; i < MAX_CUSTOM_DATA_SIZE + 1; i++) {
        std::string test_key = "test_key" + std::to_string(i);
        std::string test_value = "test_value" + std::to_string(i);
        srcOptions.customData.emplace(test_key, test_value);
    }

    EXPECT_EQ(srcOptions.Marshalling(Parcel), true);
    CreateAccountOptions *testOptions = srcOptions.Unmarshalling(Parcel);
    EXPECT_EQ(testOptions, nullptr);
}

/**
 * @tc.name: SelectAccountsOptions Marshalling test
 * @tc.desc: test ReadFromParcel.
 * @tc.type: FUNC
 * @tc.require issueI5RWXN
 */
HWTEST_F(AppAccountCommonTest, Marshalling006, TestSize.Level0)
{
    ACCOUNT_LOGI("Marshalling006");
    Parcel testParcel;
    SetPropertiesOptions options;
    bool result = options.Marshalling(testParcel);
    ASSERT_EQ(result, true);
    result = options.Unmarshalling(testParcel);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: SelectAccountsOptions Marshalling test
 * @tc.desc: Func Marshalling allowedAccounts is oversize.
 * @tc.type: FUNC
 * @tc.require issueI5RWXN
 */
HWTEST_F(AppAccountCommonTest, Marshalling007, TestSize.Level0)
{
    Parcel Parcel;
    SelectAccountsOptions option1;
    option1.hasAccounts = true;
    option1.hasOwners = true;
    option1.hasLabels = true;
    for (int i = 0; i <= MAX_VEC_SIZE; i++) {
        std::string key = std::to_string(i);
        std::string value = "test" + std::to_string(i);
        option1.allowedAccounts.emplace_back(std::pair<std::string, std::string>(key, value));
    }
    option1.requiredLabels.emplace_back("test2");

    EXPECT_EQ(option1.Marshalling(Parcel), true);
    SelectAccountsOptions *option2 = option1.Unmarshalling(Parcel);
    EXPECT_EQ(option2, nullptr);
}

/**
 * @tc.name: ConvertOtherJSErrCodeV8 test
 * @tc.desc: Func ConvertOtherJSErrCodeV8.
 * @tc.type: FUNC
 * @tc.require issueI5RWXN
 */
HWTEST_F(AppAccountCommonTest, ConvertOtherJSErrCodeV8001, TestSize.Level0)
{
    ACCOUNT_LOGI("ConvertOtherJSErrCodeV8001");
    EXPECT_EQ(ConvertToJSErrCodeV8(ERR_OK), ERR_JS_SUCCESS_V8);
    EXPECT_EQ(ConvertToJSErrCodeV8(ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST), ERR_JS_ACCOUNT_NOT_EXIST);
    EXPECT_EQ(ConvertToJSErrCodeV8(ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST),
        ERR_JS_OAUTH_AUTHENTICATOR_NOT_EXIST);
    EXPECT_EQ(ConvertToJSErrCodeV8(ERR_APPACCOUNT_SERVICE_OAUTH_BUSY), ERR_JS_OAUTH_SERVICE_BUSY);
    EXPECT_EQ(ConvertToJSErrCodeV8(ERR_APPACCOUNT_SERVICE_OAUTH_LIST_MAX_SIZE), ERR_JS_OAUTH_LIST_TOO_LARGE);
    EXPECT_EQ(ConvertToJSErrCodeV8(ERR_APPACCOUNT_SERVICE_OAUTH_SESSION_NOT_EXIST), ERR_JS_OAUTH_SESSION_NOT_EXIST);
    EXPECT_EQ(ConvertToJSErrCodeV8(ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST), ERR_JS_OAUTH_TOKEN_NOT_EXIST);
    EXPECT_EQ(ConvertToJSErrCodeV8(ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_MAX_SIZE), ERR_JS_OAUTH_TOKEN_TOO_MANY);
    EXPECT_EQ(ConvertToJSErrCodeV8(INVALID_ERR_CODE), ERR_JS_APP_ACCOUNT_SERVICE_EXCEPTION);
}

/**
 * @tc.name: ConvertToJSErrCodeV8 test
 * @tc.desc: Func ConvertOtherJSErrCodeV8.
 * @tc.type: FUNC
 * @tc.require issueI5RWXN
 */
HWTEST_F(AppAccountCommonTest, ConvertToJSErrCodeV8001, TestSize.Level0)
{
    ACCOUNT_LOGI("ConvertToJSErrCodeV8001");
    EXPECT_EQ(ConvertToJSErrCodeV8(ERR_APPACCOUNT_KIT_NAME_IS_EMPTY), ERR_JS_INVALID_REQUEST);
    EXPECT_EQ(ConvertToJSErrCodeV8(ERR_APPACCOUNT_SERVICE_NAME_IS_EMPTY), ERR_JS_INVALID_REQUEST);
    EXPECT_EQ(ConvertToJSErrCodeV8(ERR_APPACCOUNT_SERVICE_ADD_EXISTING_ACCOUNT), ERR_JS_INVALID_REQUEST);
    EXPECT_EQ(ConvertToJSErrCodeV8(ERR_APPACCOUNT_KIT_READ_PARCELABLE_APP_ACCOUNT_INFO), ERR_JS_INVALID_RESPONSE);
    EXPECT_EQ(ConvertToJSErrCodeV8(ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE), ERR_JS_INVALID_RESPONSE);
    EXPECT_EQ(
        ConvertToJSErrCodeV8(ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_CALLBACK_NOT_EXIST), ERR_JS_INVALID_RESPONSE);
    EXPECT_EQ(ConvertToJSErrCodeV8(ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED), ERR_JS_PERMISSION_DENIED_V8);
    EXPECT_EQ(ConvertToJSErrCodeV8(ERR_APPACCOUNT_SERVICE_SUBSCRIBE_PERMISSION_DENIED), ERR_JS_PERMISSION_DENIED_V8);
}
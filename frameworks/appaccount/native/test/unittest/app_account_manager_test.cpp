/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "app_account_manager.h"
#include "app_account_manager_test_callback.h"
#include "app_account_subscribe_info.h"
#define private public
#include "app_account.h"
#undef private
#include "singleton.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AccountTest;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_NAME_OUT_OF_RANGE =
    "name_12345678"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_EXTRA_INFO_OUT_OF_RANGE =
    "extra_info_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_BUNDLE_NAME = "com.example.third_party";
const std::string STRING_OWNER_OUT_OF_RANGE =
    "owner_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_EMPTY = "";
const std::string STRING_KEY = "key";
const std::string STRING_KEY_OUT_OF_RANGE =
    "key_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_VALUE = "value";
const std::string STRING_VALUE_OUT_OF_RANGE =
    "value_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_CREDENTIAL_TYPE = "password";
const std::string STRING_CREDENTIAL_TYPE_OUT_OF_RANGE =
    "credential_type_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_AUTHORIZED_APP_OUT_OF_RANGE =
    "authorized_app_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_CREDENTIAL = "1024";
const std::string STRING_CREDENTIAL_OUT_OF_RANGE =
    "credential_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_TOKEN = "1024";
const std::string STRING_TOKEN_OUT_OF_RANGE =
    "token_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_OWNER = "com.example.owner";
const std::string STRING_AUTH_TYPE = "all";
const std::string STRING_OUT_OF_RANGE =
    "auth_type_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_ABILITY_NAME = "MainAbility";
const std::string STRING_SESSION_ID = "123456";
constexpr int32_t MAX_CUSTOM_DATA_SIZE = 1024;
constexpr int32_t ALLOWED_ARRAY_MAX_SIZE = 1024;
constexpr int32_t CREDENTIAL_TYPE_MAX_SIZE = 1024;
constexpr int32_t CREDENTIAL_MAX_SIZE = 1024;
const bool SYNC_ENABLE_FALSE = false;

constexpr std::size_t SIZE_ZERO = 0;
}  // namespace

class AppAccountManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

class AppAccountSubscriberTest : public AppAccountSubscriber {
public:
    explicit AppAccountSubscriberTest(const AppAccountSubscribeInfo &subscribeInfo)
        : AppAccountSubscriber(subscribeInfo)
    {
        ACCOUNT_LOGI("enter");
    }

    ~AppAccountSubscriberTest()
    {}

    virtual void OnAccountsChanged(const std::vector<AppAccountInfo> &accounts)
    {
        ACCOUNT_LOGI("enter");
    }
};

void AppAccountManagerTest::SetUpTestCase(void)
{}

void AppAccountManagerTest::TearDownTestCase(void)
{}

void AppAccountManagerTest::SetUp(void)
{}

void AppAccountManagerTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountManager_AddAccount_0100
 * @tc.desc: Add an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQW
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_AddAccount_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManager_AddAccount_0100");

    ErrCode result = AppAccountManager::AddAccount(STRING_EMPTY);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_AddAccount_0200
 * @tc.desc: Add an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQW
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_AddAccount_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_AddAccount_0200");

    ErrCode result = AppAccountManager::AddAccount(STRING_NAME_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_AddAccount_0300
 * @tc.desc: Add an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQW
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_AddAccount_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_AddAccount_0300");

    ErrCode result = AppAccountManager::AddAccount(STRING_NAME, STRING_EXTRA_INFO_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_AddAccount_0400
 * @tc.desc: Fail to Add an app account from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQW
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_AddAccount_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_AddAccount_0300");

    ErrCode result = AppAccountManager::AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_CreateAccount_0100
 * @tc.desc: create an app account with invalid name data.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CreateAccount_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CreateAccount_0100");
    CreateAccountOptions option;
    GTEST_LOG_(INFO) << "name size = " << STRING_NAME_OUT_OF_RANGE.size();
    ErrCode result = AppAccountManager::CreateAccount(STRING_NAME_OUT_OF_RANGE, option);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_CreateAccount_0200
 * @tc.desc: create an app account with invalid name data.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CreateAccount_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CreateAccount_0200");
    CreateAccountOptions option;
    ErrCode result = AppAccountManager::CreateAccount(STRING_EMPTY, option);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_CreateAccount_0300
 * @tc.desc: create an app account with invalid option data.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CreateAccount_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CreateAccount_0300");
    CreateAccountOptions option;
    option.customData.emplace(STRING_KEY_OUT_OF_RANGE, STRING_VALUE);
    GTEST_LOG_(INFO) << "key size = " << STRING_VALUE_OUT_OF_RANGE.size();
    ErrCode result = AppAccountManager::CreateAccount(STRING_EMPTY, option);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_CreateAccount_0400
 * @tc.desc: create an app account with invalid option data.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CreateAccount_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CreateAccount_0400");
    CreateAccountOptions option;
    option.customData.emplace(STRING_KEY, STRING_VALUE_OUT_OF_RANGE);
    GTEST_LOG_(INFO) << "value size = " << STRING_VALUE_OUT_OF_RANGE.size();
    ErrCode result = AppAccountManager::CreateAccount(STRING_EMPTY, option);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_CreateAccount_0500
 * @tc.desc: create an app account with invalid option data.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CreateAccount_0500, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CreateAccount_0500");
    CreateAccountOptions option;
    for (int i = 0; i < MAX_CUSTOM_DATA_SIZE + 1; i++) {
        std::string test_key = "test_key" + std::to_string(i);
        std::string test_value = "test_value" + std::to_string(i);
        option.customData.emplace(test_key, test_value);
    }
    GTEST_LOG_(INFO) << "customData map size = " << option.customData.size();
    ErrCode result = AppAccountManager::CreateAccount(STRING_EMPTY, option);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_AddAccountImplicitly_0100
 * @tc.desc: Fail to add an app account implicitly with invalid parameters.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_AddAccountImplicitly_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_AddAccountImplicitly_0100");
    AAFwk::Want options;
    options.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    ErrCode result = AppAccountManager::AddAccountImplicitly(STRING_OWNER, STRING_AUTH_TYPE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_CALLBACK);

    result = AppAccountManager::AddAccountImplicitly(
        STRING_OWNER_OUT_OF_RANGE, STRING_AUTH_TYPE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::AddAccountImplicitly(STRING_EMPTY, STRING_AUTH_TYPE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::AddAccountImplicitly(STRING_OWNER, STRING_OUT_OF_RANGE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    options.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_EMPTY);
    result = AppAccountManager::AddAccountImplicitly(STRING_OWNER, STRING_AUTH_TYPE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    options.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_OUT_OF_RANGE);
    result = AppAccountManager::AddAccountImplicitly(STRING_OWNER, STRING_AUTH_TYPE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_AddAccountImplicitly_0200
 * @tc.desc: Fail to add an app account implicitly from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_AddAccountImplicitly_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_AddAccountImplicitly_0200");
    AAFwk::Want options;
    options.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    ErrCode result = AppAccountManager::AddAccountImplicitly(STRING_OWNER, STRING_AUTH_TYPE, options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_CreateAccountImplicitly_0100
 * @tc.desc: Fail to add an app account implicitly with invalid parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CreateAccountImplicitly_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CreateAccountImplicitly_0100");
    CreateAccountImplicitlyOptions options;
    // check owner
    ErrCode result = AppAccountManager::CreateAccountImplicitly(
        STRING_OWNER_OUT_OF_RANGE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::CreateAccountImplicitly(STRING_EMPTY, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    // check options.authType
    options.authType = STRING_OUT_OF_RANGE;
    result = AppAccountManager::CreateAccountImplicitly(STRING_OWNER, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    options.authType = "";
    options.parameters.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_EMPTY);
    result = AppAccountManager::CreateAccountImplicitly(STRING_OWNER, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    options.parameters.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_OUT_OF_RANGE);
    result = AppAccountManager::CreateAccountImplicitly(STRING_OWNER, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    // check callback nullptr
    options.parameters.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    result = AppAccountManager::CreateAccountImplicitly(STRING_OWNER, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_CALLBACK);
    // check options.requiredLabels
    for (int i = 0; i < ALLOWED_ARRAY_MAX_SIZE; i++) {
        std::string testLabel = "test_label_" + std::to_string(i);
        options.requiredLabels.emplace_back(testLabel);
    }
    result = AppAccountManager::CreateAccountImplicitly(STRING_OWNER, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_CALLBACK);
    options.requiredLabels.emplace_back("test_label_oversize");
    result = AppAccountManager::CreateAccountImplicitly(STRING_OWNER, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_CreateAccountImplicitly_0200
 * @tc.desc: Fail to add an app account implicitly from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CreateAccountImplicitly_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CreateAccountImplicitly_0200");
    CreateAccountImplicitlyOptions options;
    options.parameters.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    ErrCode result = AppAccountManager::CreateAccountImplicitly(STRING_OWNER, options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_Authenticate_0100
 * @tc.desc: Fail to authenticate an app account with invalid name.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_Authenticate_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_Authenticate_0100");
    AAFwk::Want options;
    options.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    ErrCode result = AppAccountManager::Authenticate(
        STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_CALLBACK);

    result = AppAccountManager::Authenticate(
        STRING_NAME_OUT_OF_RANGE, STRING_OWNER, STRING_AUTH_TYPE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::Authenticate(
        STRING_EMPTY, STRING_OWNER, STRING_AUTH_TYPE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::Authenticate(
        STRING_NAME, STRING_OWNER_OUT_OF_RANGE, STRING_AUTH_TYPE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::Authenticate(
        STRING_NAME, STRING_EMPTY, STRING_AUTH_TYPE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::Authenticate(
        STRING_NAME, STRING_OWNER, STRING_OUT_OF_RANGE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    options.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_OUT_OF_RANGE);
    result = AppAccountManager::Authenticate(
        STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    options.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_EMPTY);
    result = AppAccountManager::Authenticate(
        STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_Authenticate_0200
 * @tc.desc: Fail to authenticate account from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_Authenticate_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_Authenticate_0200");
    AAFwk::Want options;
    options.SetParam(Constants::KEY_CALLER_ABILITY_NAME, STRING_ABILITY_NAME);
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    ErrCode result = AppAccountManager::Authenticate(STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_SetOAuthTokenVisibility_0100
 * @tc.desc: Fail to set oauth token visibility with invalid name.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetOAuthTokenVisibility_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetOAuthTokenVisibility_0100");
    ErrCode result = AppAccountManager::SetOAuthTokenVisibility(
        STRING_EMPTY, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::SetOAuthTokenVisibility(
        STRING_NAME_OUT_OF_RANGE, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::SetOAuthTokenVisibility(
        STRING_NAME, STRING_OUT_OF_RANGE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::SetOAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_EMPTY, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::SetOAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_OWNER_OUT_OF_RANGE, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetOAuthTokenVisibility_0200
 * @tc.desc: Fail to set oauth token visibility from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetOAuthTokenVisibility_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetOAuthTokenVisibility_0200");
    ErrCode result = AppAccountManager::SetOAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_SetAuthTokenVisibility_0100
 * @tc.desc: Fail to set oauth token visibility with invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAuthTokenVisibility_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAuthTokenVisibility_0100");
    ErrCode result = AppAccountManager::SetAuthTokenVisibility(
        STRING_EMPTY, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::SetAuthTokenVisibility(
        STRING_NAME_OUT_OF_RANGE, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::SetAuthTokenVisibility(
        STRING_NAME, STRING_OUT_OF_RANGE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::SetAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_EMPTY, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::SetAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_OWNER_OUT_OF_RANGE, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAuthTokenVisibility_0200
 * @tc.desc: Fail to set oauth token visibility from shell process.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAuthTokenVisibility_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAuthTokenVisibility_0200");
    ErrCode result = AppAccountManager::SetAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_CheckOAuthTokenVisibility_0100
 * @tc.desc: Fail to check oauth token visibility with invalid name.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CheckOAuthTokenVisibility_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CheckOAuthTokenVisibility_0100");
    bool isVisible = false;
    ErrCode result = AppAccountManager::CheckOAuthTokenVisibility(
        STRING_EMPTY, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_FALSE(isVisible);
    result = AppAccountManager::CheckOAuthTokenVisibility(
        STRING_OUT_OF_RANGE, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_FALSE(isVisible);

    result = AppAccountManager::CheckOAuthTokenVisibility(
        STRING_NAME, STRING_OUT_OF_RANGE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_FALSE(isVisible);

    result = AppAccountManager::CheckOAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_EMPTY, isVisible);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_FALSE(isVisible);
    result = AppAccountManager::CheckOAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_OUT_OF_RANGE, isVisible);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_FALSE(isVisible);
}

/**
 * @tc.name: AppAccountManager_CheckOAuthTokenVisibility_0200
 * @tc.desc: Fail to check oauth token visibility from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CheckOAuthTokenVisibility_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CheckOAuthTokenVisibility_0200");
    bool isVisible = false;
    ErrCode result = AppAccountManager::CheckOAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    EXPECT_FALSE(isVisible);
}

/**
 * @tc.name: AppAccountManager_CheckAuthTokenVisibility_0100
 * @tc.desc: Fail to check oauth token visibility with invalid name.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CheckAuthTokenVisibility_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CheckAuthTokenVisibility_0100");
    bool isVisible = false;
    ErrCode result = AppAccountManager::CheckAuthTokenVisibility(
        STRING_EMPTY, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_FALSE(isVisible);
    result = AppAccountManager::CheckAuthTokenVisibility(
        STRING_OUT_OF_RANGE, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_FALSE(isVisible);

    result = AppAccountManager::CheckAuthTokenVisibility(
        STRING_NAME, STRING_OUT_OF_RANGE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_FALSE(isVisible);

    result = AppAccountManager::CheckAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_EMPTY, isVisible);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_FALSE(isVisible);
    result = AppAccountManager::CheckAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_OUT_OF_RANGE, isVisible);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_FALSE(isVisible);
}

/**
 * @tc.name: AppAccountManager_CheckAuthTokenVisibility_0200
 * @tc.desc: Fail to check oauth token visibility from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CheckAuthTokenVisibility_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CheckAuthTokenVisibility_0200");
    bool isVisible = false;
    ErrCode result = AppAccountManager::CheckAuthTokenVisibility(
        STRING_NAME, STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    EXPECT_FALSE(isVisible);
}

/**
 * @tc.name: AppAccountManager_DeleteAccount_0100
 * @tc.desc: Delete an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQW
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DeleteAccount_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManager_DeleteAccount_0100");

    ErrCode result = AppAccountManager::DeleteAccount(STRING_EMPTY);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_DeleteAccount_0200
 * @tc.desc: Delete an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQW
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DeleteAccount_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DeleteAccount_0200");

    ErrCode result = AppAccountManager::DeleteAccount(STRING_NAME_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_DeleteAccount_0300
 * @tc.desc: Failt to delete an app account from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQW
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DeleteAccount_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DeleteAccount_0300");

    ErrCode result = AppAccountManager::DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_GetAccountExtraInfo_0100
 * @tc.desc: Get extra info of an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAccountExtraInfo_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountExtraInfo_0100");

    std::string extraInfo;
    ErrCode result = AppAccountManager::GetAccountExtraInfo(STRING_EMPTY, extraInfo);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(extraInfo, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_GetAccountExtraInfo_0200
 * @tc.desc: Get extra info of an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAccountExtraInfo_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountExtraInfo_0200");

    std::string extraInfo;
    ErrCode result = AppAccountManager::GetAccountExtraInfo(STRING_NAME_OUT_OF_RANGE, extraInfo);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(extraInfo, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_GetAccountExtraInfo_0300
 * @tc.desc: Fail to get extra info of an app account from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAccountExtraInfo_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountExtraInfo_0300");
    std::string extraInfo;
    ErrCode result = AppAccountManager::GetAccountExtraInfo(STRING_NAME, extraInfo);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    EXPECT_EQ(extraInfo, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_SetAccountExtraInfo_0100
 * @tc.desc: Set extra info of an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountExtraInfo_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountExtraInfo_0100");

    ErrCode result = AppAccountManager::SetAccountExtraInfo(STRING_EMPTY, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAccountExtraInfo_0200
 * @tc.desc: Set extra info of an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountExtraInfo_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountExtraInfo_0200");

    ErrCode result = AppAccountManager::SetAccountExtraInfo(STRING_NAME_OUT_OF_RANGE, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAccountExtraInfo_0300
 * @tc.desc: Set extra info of an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountExtraInfo_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountExtraInfo_0300");

    ErrCode result = AppAccountManager::SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAccountExtraInfo_0400
 * @tc.desc: Fail to set extra info of an app account from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountExtraInfo_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountExtraInfo_0400");

    ErrCode result = AppAccountManager::SetAccountExtraInfo(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_EnableAppAccess_0100
 * @tc.desc: Enable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_EnableAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_EnableAppAccess_0100");

    ErrCode result = AppAccountManager::EnableAppAccess(STRING_EMPTY, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_EnableAppAccess_0200
 * @tc.desc: Enable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_EnableAppAccess_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_EnableAppAccess_0200");

    ErrCode result = AppAccountManager::EnableAppAccess(STRING_NAME_OUT_OF_RANGE, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_EnableAppAccess_0300
 * @tc.desc: Enable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_EnableAppAccess_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_EnableAppAccess_0300");

    ErrCode result = AppAccountManager::EnableAppAccess(STRING_NAME, STRING_EMPTY);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_EnableAppAccess_0400
 * @tc.desc: Enable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_EnableAppAccess_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_EnableAppAccess_0400");

    ErrCode result = AppAccountManager::EnableAppAccess(STRING_NAME, STRING_AUTHORIZED_APP_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_EnableAppAccess_0500
 * @tc.desc: Fail to enable app access from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_EnableAppAccess_0500, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_EnableAppAccess_0500");
    ErrCode result = AppAccountManager::EnableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_DisableAppAccess_0100
 * @tc.desc: Disable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DisableAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DisableAppAccess_0100");

    ErrCode result = AppAccountManager::DisableAppAccess(STRING_EMPTY, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_DisableAppAccess_0200
 * @tc.desc: Disable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DisableAppAccess_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DisableAppAccess_0200");

    ErrCode result = AppAccountManager::DisableAppAccess(STRING_NAME_OUT_OF_RANGE, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_DisableAppAccess_0300
 * @tc.desc: Disable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DisableAppAccess_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DisableAppAccess_0300");

    ErrCode result = AppAccountManager::DisableAppAccess(STRING_NAME, STRING_EMPTY);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_DisableAppAccess_0400
 * @tc.desc: Disable app access with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DisableAppAccess_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DisableAppAccess_0400");

    ErrCode result = AppAccountManager::DisableAppAccess(STRING_NAME, STRING_AUTHORIZED_APP_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_DisableAppAccess_0500
 * @tc.desc: Fail to disable app access from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DisableAppAccess_0500, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DisableAppAccess_0500");
    ErrCode result = AppAccountManager::DisableAppAccess(STRING_NAME, STRING_BUNDLE_NAME);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_SetAppAccess_0100
 * @tc.desc: Fail to set app access from shell process.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAppAccess_0100");
    ErrCode result = AppAccountManager::SetAppAccess(STRING_EMPTY, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::SetAppAccess(STRING_NAME_OUT_OF_RANGE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::SetAppAccess(STRING_NAME, STRING_AUTHORIZED_APP_OUT_OF_RANGE, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::SetAppAccess(STRING_NAME, STRING_EMPTY, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);

    result = AppAccountManager::SetAppAccess(STRING_NAME, STRING_BUNDLE_NAME, false);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_CheckAppAccountSyncEnable_0100
 * @tc.desc: Check account sync enable with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CheckAppAccountSyncEnable_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CheckAppAccountSyncEnable_0100");

    bool syncEnable = SYNC_ENABLE_FALSE;
    ErrCode result = AppAccountManager::CheckAppAccountSyncEnable(STRING_EMPTY, syncEnable);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_FALSE);
}

/**
 * @tc.name: AppAccountManager_CheckAppAccountSyncEnable_0200
 * @tc.desc: Check account sync enable with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CheckAppAccountSyncEnable_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CheckAppAccountSyncEnable_0200");

    bool syncEnable = SYNC_ENABLE_FALSE;
    ErrCode result = AppAccountManager::CheckAppAccountSyncEnable(STRING_NAME_OUT_OF_RANGE, syncEnable);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_FALSE);
}

/**
 * @tc.name: AppAccountManager_CheckAppAccountSyncEnable_0300
 * @tc.desc: Fail to check account sync enable from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CheckAppAccountSyncEnable_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CheckAppAccountSyncEnable_0300");
    bool syncEnable = SYNC_ENABLE_FALSE;
    ErrCode result = AppAccountManager::CheckAppAccountSyncEnable(STRING_NAME, syncEnable);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    EXPECT_EQ(syncEnable, SYNC_ENABLE_FALSE);
}

/**
 * @tc.name: AppAccountManager_SetAppAccountSyncEnable_0100
 * @tc.desc: Set account sync enable with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAppAccountSyncEnable_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAppAccountSyncEnable_0100");

    ErrCode result = AppAccountManager::SetAppAccountSyncEnable(STRING_EMPTY, SYNC_ENABLE_FALSE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAppAccountSyncEnable_0200
 * @tc.desc: Set account sync enable with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAppAccountSyncEnable_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAppAccountSyncEnable_0200");

    ErrCode result = AppAccountManager::SetAppAccountSyncEnable(STRING_NAME_OUT_OF_RANGE, SYNC_ENABLE_FALSE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAppAccountSyncEnable_0300
 * @tc.desc: Fail to set account sync enable from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAppAccountSyncEnable_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAppAccountSyncEnable_0300");
    ErrCode result = AppAccountManager::SetAppAccountSyncEnable(STRING_NAME, SYNC_ENABLE_FALSE);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_GetAssociatedData_0100
 * @tc.desc: Get associated data with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAssociatedData_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAssociatedData_0100");

    std::string value;
    ErrCode result = AppAccountManager::GetAssociatedData(STRING_EMPTY, STRING_KEY, value);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(value, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_GetAssociatedData_0200
 * @tc.desc: Get associated data with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAssociatedData_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAssociatedData_0200");

    std::string value;
    ErrCode result = AppAccountManager::GetAssociatedData(STRING_NAME_OUT_OF_RANGE, STRING_KEY, value);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(value, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_GetAssociatedData_0300
 * @tc.desc: Get associated data with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAssociatedData_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAssociatedData_0300");

    std::string value;
    ErrCode result = AppAccountManager::GetAssociatedData(STRING_NAME, STRING_EMPTY, value);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(value, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_GetAssociatedData_0400
 * @tc.desc: Get associated data with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAssociatedData_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAssociatedData_0400");

    std::string value;
    ErrCode result = AppAccountManager::GetAssociatedData(STRING_NAME, STRING_KEY_OUT_OF_RANGE, value);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(value, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_GetAssociatedData_0500
 * @tc.desc: Fail to get associated data from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAssociatedData_0500, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAssociatedData_0500");
    std::string value;
    ErrCode result = AppAccountManager::GetAssociatedData(STRING_NAME, STRING_KEY, value);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_APP_INDEX);
    EXPECT_EQ(value, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_SetAssociatedData_0100
 * @tc.desc: Set associated data with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAssociatedData_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAssociatedData_0100");

    ErrCode result = AppAccountManager::SetAssociatedData(STRING_EMPTY, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAssociatedData_0200
 * @tc.desc: Set associated data with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAssociatedData_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAssociatedData_0200");

    ErrCode result = AppAccountManager::SetAssociatedData(STRING_NAME_OUT_OF_RANGE, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAssociatedData_0300
 * @tc.desc: Set associated data with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAssociatedData_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAssociatedData_0300");

    ErrCode result = AppAccountManager::SetAssociatedData(STRING_NAME, STRING_EMPTY, STRING_VALUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAssociatedData_0400
 * @tc.desc: Set associated data with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAssociatedData_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAssociatedData_0400");

    ErrCode result = AppAccountManager::SetAssociatedData(STRING_NAME, STRING_KEY_OUT_OF_RANGE, STRING_VALUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAssociatedData_0500
 * @tc.desc: Set associated data with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAssociatedData_0500, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAssociatedData_0500");

    ErrCode result = AppAccountManager::SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAssociatedData_0600
 * @tc.desc: Fail to set associated data from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAssociatedData_0600, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAssociatedData_0600");
    ErrCode result = AppAccountManager::SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_GetAccountCredential_0100
 * @tc.desc: Get account credential with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAccountCredential_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountCredential_0100");

    std::string credential;
    ErrCode result = AppAccountManager::GetAccountCredential(STRING_EMPTY, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(credential, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_GetAccountCredential_0200
 * @tc.desc: Get account credential with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAccountCredential_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountCredential_0200");

    std::string credential;
    ErrCode result =
        AppAccountManager::GetAccountCredential(STRING_NAME_OUT_OF_RANGE, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(credential, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_GetAccountCredential_0300
 * @tc.desc: Get account credential with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAccountCredential_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountCredential_0300");

    std::string credential;
    ErrCode result = AppAccountManager::GetAccountCredential(STRING_NAME, STRING_EMPTY, credential);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(credential, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_GetAccountCredential_0400
 * @tc.desc: Get account credential with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAccountCredential_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountCredential_0400");

    std::string credential;
    ErrCode result =
        AppAccountManager::GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE_OUT_OF_RANGE, credential);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(credential, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_GetAccountCredential_0500
 * @tc.desc: Fail to get account credential from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAccountCredential_0500, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAccountCredential_0500");
    std::string credential;
    ErrCode result = AppAccountManager::GetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    EXPECT_EQ(credential, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_SetAccountCredential_0100
 * @tc.desc: Set account credential with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountCredential_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountCredential_0100");

    ErrCode result = AppAccountManager::SetAccountCredential(STRING_EMPTY, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAccountCredential_0200
 * @tc.desc: Set account credential with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountCredential_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountCredential_0200");

    ErrCode result =
        AppAccountManager::SetAccountCredential(STRING_NAME_OUT_OF_RANGE, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAccountCredential_0300
 * @tc.desc: Set account credential with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountCredential_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountCredential_0300");

    ErrCode result = AppAccountManager::SetAccountCredential(STRING_NAME, STRING_EMPTY, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAccountCredential_0400
 * @tc.desc: Set account credential with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountCredential_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountCredential_0400");

    ErrCode result =
        AppAccountManager::SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE_OUT_OF_RANGE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAccountCredential_0500
 * @tc.desc: Set account credential with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountCredential_0500, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountCredential_0500");

    ErrCode result =
        AppAccountManager::SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetAccountCredential_0600
 * @tc.desc: Fail to set account credential from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQT
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAccountCredential_0600, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAccountCredential_0600");
    ErrCode result = AppAccountManager::SetAccountCredential(STRING_NAME, STRING_CREDENTIAL_TYPE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_GetOAuthToken_0100
 * @tc.desc: Get oauth token with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetOAuthToken_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetOAuthToken_0100");
    std::string token;
    ErrCode result = AppAccountManager::GetOAuthToken(STRING_EMPTY, STRING_OWNER, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(token, STRING_EMPTY);

    result = AppAccountManager::GetOAuthToken(STRING_NAME, STRING_EMPTY, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(token, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_GetOAuthToken_0200
 * @tc.desc: Get oauth token with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetOAuthToken_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetOAuthToken_0200");
    std::string token;
    ErrCode result = AppAccountManager::GetOAuthToken(STRING_NAME_OUT_OF_RANGE, STRING_OWNER, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(token, STRING_EMPTY);

    result = AppAccountManager::GetOAuthToken(STRING_NAME, STRING_OWNER_OUT_OF_RANGE, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(token, STRING_EMPTY);

    result = AppAccountManager::GetOAuthToken(STRING_NAME, STRING_OWNER, STRING_OUT_OF_RANGE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(token, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_GetOAuthToken_0300
 * @tc.desc: Fail to get oauth token from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetOAuthToken_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetOAuthToken_0300");
    std::string token;
    ErrCode result = AppAccountManager::GetOAuthToken(STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    EXPECT_EQ(token, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_GetAuthToken_0100
 * @tc.desc: Get oauth token with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAuthToken_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAuthToken_0100");
    std::string token;
    ErrCode result = AppAccountManager::GetAuthToken(STRING_EMPTY, STRING_OWNER, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(token, STRING_EMPTY);

    result = AppAccountManager::GetAuthToken(STRING_NAME, STRING_EMPTY, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(token, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_GetAuthToken_0200
 * @tc.desc: Get oauth token with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAuthToken_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAuthToken_0200");
    std::string token;
    ErrCode result = AppAccountManager::GetAuthToken(STRING_NAME_OUT_OF_RANGE, STRING_OWNER, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(token, STRING_EMPTY);

    result = AppAccountManager::GetAuthToken(STRING_NAME, STRING_OWNER_OUT_OF_RANGE, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(token, STRING_EMPTY);

    result = AppAccountManager::GetAuthToken(STRING_NAME, STRING_OWNER, STRING_OUT_OF_RANGE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(token, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_GetAuthToken_0300
 * @tc.desc: Fail to get oauth token from shell process.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAuthToken_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAuthToken_0300");
    std::string token;
    ErrCode result = AppAccountManager::GetAuthToken(STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    EXPECT_EQ(token, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManager_SetOAuthToken_0100
 * @tc.desc: Set oauth token with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetOAuthToken_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetOAuthToken_0100");
    ErrCode result = AppAccountManager::SetOAuthToken(STRING_EMPTY, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetOAuthToken_0200
 * @tc.desc: Set oauth token with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetOAuthToken_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetOAuthToken_0200");
    ErrCode result = AppAccountManager::SetOAuthToken(STRING_NAME_OUT_OF_RANGE, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::SetOAuthToken(STRING_NAME, STRING_OUT_OF_RANGE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_SetOAuthToken_0300
 * @tc.desc: Fail to set oauth token from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetOAuthToken_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetOAuthToken_0300");
    ErrCode result = AppAccountManager::SetOAuthToken(STRING_NAME, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_DeleteOAuthToken_0100
 * @tc.desc: Delete oauth token with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DeleteOAuthToken_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DeleteOAuthToken_0100");
    ErrCode result = AppAccountManager::DeleteOAuthToken(STRING_EMPTY, STRING_OWNER, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::DeleteOAuthToken(STRING_NAME, STRING_EMPTY, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_DeleteOAuthToken_0200
 * @tc.desc: Delete oauth token with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DeleteOAuthToken_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DeleteOAuthToken_0200");
    ErrCode result = AppAccountManager::DeleteOAuthToken(
            STRING_NAME_OUT_OF_RANGE, STRING_OWNER, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::DeleteOAuthToken(
        STRING_NAME, STRING_OWNER_OUT_OF_RANGE, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::DeleteOAuthToken(
        STRING_NAME, STRING_OWNER, STRING_OUT_OF_RANGE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::DeleteOAuthToken(
        STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, STRING_TOKEN_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_DeleteOAuthToken_0300
 * @tc.desc: Delete oauth token with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DeleteOAuthToken_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DeleteOAuthToken_0300");
    ErrCode result = AppAccountManager::DeleteOAuthToken(STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_DeleteAuthToken_0100
 * @tc.desc: Delete oauth token with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DeleteAuthToken_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DeleteAuthToken_0100");
    ErrCode result = AppAccountManager::DeleteAuthToken(STRING_EMPTY, STRING_OWNER, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::DeleteAuthToken(STRING_NAME, STRING_EMPTY, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_DeleteAuthToken_0200
 * @tc.desc: Delete oauth token with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DeleteAuthToken_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DeleteAuthToken_0200");
    ErrCode result = AppAccountManager::DeleteAuthToken(
            STRING_NAME_OUT_OF_RANGE, STRING_OWNER, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::DeleteAuthToken(
        STRING_NAME, STRING_OWNER_OUT_OF_RANGE, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::DeleteAuthToken(
        STRING_NAME, STRING_OWNER, STRING_OUT_OF_RANGE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::DeleteAuthToken(
        STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, STRING_TOKEN_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_DeleteAuthToken_0300
 * @tc.desc: Delete oauth token with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DeleteAuthToken_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DeleteAuthToken_0300");
    ErrCode result = AppAccountManager::DeleteAuthToken(STRING_NAME, STRING_OWNER, STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_GetAllOAuthTokens_0100
 * @tc.desc: Get all oauth tokens with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAllOAuthTokens_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAllOAuthTokens_0100");
    std::vector<OAuthTokenInfo> tokenInfos;
    ErrCode result = AppAccountManager::GetAllOAuthTokens(STRING_EMPTY, STRING_OWNER, tokenInfos);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(tokenInfos.size(), 0);

    result = AppAccountManager::GetAllOAuthTokens(STRING_NAME, STRING_EMPTY, tokenInfos);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(tokenInfos.size(), 0);
}

/**
 * @tc.name: AppAccountManager_GetAllOAuthTokens_0200
 * @tc.desc: Get all oauth tokens with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAllOAuthTokens_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAllOAuthTokens_0200");
    std::vector<OAuthTokenInfo> tokenInfos;
    ErrCode result = AppAccountManager::GetAllOAuthTokens(STRING_NAME_OUT_OF_RANGE, STRING_OWNER, tokenInfos);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(tokenInfos.size(), 0);

    result = AppAccountManager::GetAllOAuthTokens(STRING_NAME, STRING_OWNER_OUT_OF_RANGE, tokenInfos);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(tokenInfos.size(), 0);

    result = AppAccountManager::GetAllOAuthTokens(STRING_NAME, STRING_OWNER, tokenInfos);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    EXPECT_EQ(tokenInfos.size(), 0);
}

/**
 * @tc.name: AppAccountManager_GetAllOAuthTokens_0300
 * @tc.desc: Fail to get all oauth tokens from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAllOAuthTokens_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAllOAuthTokens_0300");
    std::vector<OAuthTokenInfo> tokenInfos;
    ErrCode result = AppAccountManager::GetAllOAuthTokens(STRING_NAME, STRING_OWNER, tokenInfos);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    EXPECT_EQ(tokenInfos.size(), 0);
}

/**
 * @tc.name: AppAccountManager_GetAuthenticatorInfo_0100
 * @tc.desc: Fail to get authenticator info with invalid owner.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAuthenticatorInfo_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAuthenticatorInfo_0100");
    AuthenticatorInfo info;
    ErrCode result = AppAccountManager::GetAuthenticatorInfo(STRING_OUT_OF_RANGE, info);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::GetAuthenticatorInfo(STRING_EMPTY, info);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::GetAuthenticatorInfo(STRING_SESSION_ID, info);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_APP_INDEX);
}

/**
 * @tc.name: AppAccountManager_GetOAuthList_0100
 * @tc.desc: Get all oauth tokens with invalid owner.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetOAuthList_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetOAuthList_0100");
    std::set<std::string> oauthList;
    ErrCode result = AppAccountManager::GetOAuthList(STRING_OUT_OF_RANGE, STRING_AUTH_TYPE, oauthList);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_TRUE(oauthList.empty());
    result = AppAccountManager::GetOAuthList(STRING_EMPTY, STRING_AUTH_TYPE, oauthList);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_TRUE(oauthList.empty());
    result = AppAccountManager::GetOAuthList(STRING_OWNER, STRING_OUT_OF_RANGE, oauthList);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_TRUE(oauthList.empty());

    result = AppAccountManager::GetOAuthList(STRING_OWNER, STRING_AUTH_TYPE, oauthList);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    EXPECT_TRUE(oauthList.empty());
}

/**
 * @tc.name: AppAccountManager_GetAuthList_0100
 * @tc.desc: Get all oauth tokens with invalid owner.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAuthList_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAuthList_0100");
    std::set<std::string> oauthList;
    ErrCode result = AppAccountManager::GetAuthList(STRING_OUT_OF_RANGE, STRING_AUTH_TYPE, oauthList);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_TRUE(oauthList.empty());
    result = AppAccountManager::GetAuthList(STRING_EMPTY, STRING_AUTH_TYPE, oauthList);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_TRUE(oauthList.empty());
    result = AppAccountManager::GetAuthList(STRING_OWNER, STRING_OUT_OF_RANGE, oauthList);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_TRUE(oauthList.empty());

    result = AppAccountManager::GetAuthList(STRING_OWNER, STRING_AUTH_TYPE, oauthList);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    EXPECT_TRUE(oauthList.empty());
}

/**
 * @tc.name: AppAccountManager_GetAuthenticatorCallback_0100
 * @tc.desc: Fail to get authenticator callback with invalid session id.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAuthenticatorCallback_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAuthenticatorCallback_0100");
    sptr<IRemoteObject> callback;
    ErrCode result = AppAccountManager::GetAuthenticatorCallback(STRING_OUT_OF_RANGE, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::GetAuthenticatorCallback(STRING_EMPTY, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::GetAuthenticatorCallback(STRING_SESSION_ID, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_CheckAppAccess_0100
 * @tc.desc: Fail to check app access with invalid name and bundle name.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CheckAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CheckAppAccess_0100");
    bool isAccess = false;
    ErrCode result = AppAccountManager::CheckAppAccess(STRING_OUT_OF_RANGE, STRING_BUNDLE_NAME, isAccess);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::CheckAppAccess(STRING_EMPTY, STRING_BUNDLE_NAME, isAccess);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::CheckAppAccess(STRING_NAME, STRING_OUT_OF_RANGE, isAccess);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::CheckAppAccess(STRING_NAME, STRING_EMPTY, isAccess);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::CheckAppAccess(STRING_NAME, STRING_BUNDLE_NAME, isAccess);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_DeleteAccountCredential_0100
 * @tc.desc: Fail to check app access with invalid name and bundle name.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_DeleteAccountCredential_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_DeleteAccountCredential_0100");
    ErrCode result = AppAccountManager::DeleteAccountCredential(STRING_OUT_OF_RANGE, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::DeleteAccountCredential(STRING_EMPTY, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::DeleteAccountCredential(STRING_NAME, STRING_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::DeleteAccountCredential(STRING_NAME, STRING_EMPTY);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = AppAccountManager::DeleteAccountCredential(STRING_NAME, STRING_CREDENTIAL);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_SelectAccountsByOptions_0100
 * @tc.desc: Fail to select accounts by options with invalid parameters.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SelectAccountsByOptions_0100, TestSize.Level1)
{
    // check callback
    ACCOUNT_LOGI("AppAccountManager_SelectAccountsByOptions_0100");
    SelectAccountsOptions options;
    ErrCode result = AppAccountManager::SelectAccountsByOptions(options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    result = AppAccountManager::SelectAccountsByOptions(options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);

    // check options.allowedAccounts array size
    options.allowedAccounts.clear();
    for (int i = 0; i < ALLOWED_ARRAY_MAX_SIZE; i++) {
        std::string testAccountName = "test_name_" + std::to_string(i);
        std::string testAccountOwner = "test_owner_" + std::to_string(i);
        options.allowedAccounts.emplace_back(testAccountOwner, testAccountName);
    }
    result = AppAccountManager::SelectAccountsByOptions(options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    options.allowedAccounts.emplace_back("test_name_oversize", "test_owner_oversize");
    result = AppAccountManager::SelectAccountsByOptions(options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    // check options.allowedOwners array size
    options.allowedAccounts.clear();
    for (int i = 0; i < ALLOWED_ARRAY_MAX_SIZE; i++) {
        std::string testOwner = "test_owner_" + std::to_string(i);
        options.allowedOwners.emplace_back(testOwner);
    }
    result = AppAccountManager::SelectAccountsByOptions(options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    options.allowedOwners.emplace_back("test_owner_oversize");
    result = AppAccountManager::SelectAccountsByOptions(options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    // check SelectAccountsOptions.requiredLabels array size
    options.allowedOwners.clear();
    for (int i = 0; i < ALLOWED_ARRAY_MAX_SIZE; i++) {
        std::string testLabel= "test_label_" + std::to_string(i);
        options.requiredLabels.emplace_back(testLabel);
    }
    result = AppAccountManager::SelectAccountsByOptions(options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    options.requiredLabels.emplace_back("test_label_oversize");
    result = AppAccountManager::SelectAccountsByOptions(options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_VerifyCredential_0100
 * @tc.desc: Fail to select accounts by options with invalid parameters.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_VerifyCredential_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SelectAccountsByOptions_0100");
    VerifyCredentialOptions options;
    // check name
    ErrCode result = AppAccountManager::VerifyCredential(STRING_OUT_OF_RANGE, STRING_OWNER, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::VerifyCredential(STRING_EMPTY, STRING_OWNER, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    // check owner
    result = AppAccountManager::VerifyCredential(STRING_NAME, STRING_OUT_OF_RANGE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::VerifyCredential(STRING_NAME, STRING_EMPTY, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    // check callback
    result = AppAccountManager::VerifyCredential(STRING_NAME, STRING_OWNER, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    result = AppAccountManager::VerifyCredential(STRING_NAME, STRING_OWNER, options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    // check option.credentialType
    std::string testCredentialType = "";
    for (int i = 0; i < CREDENTIAL_TYPE_MAX_SIZE + 1; i++) {
        testCredentialType += 'c';
    }
    options.credentialType = testCredentialType;
    result = AppAccountManager::VerifyCredential(STRING_NAME, STRING_OWNER, options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    options.credentialType = "";
    result = AppAccountManager::VerifyCredential(STRING_NAME, STRING_OWNER, options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    // check option.credential
    std::string testCredential = "";
    for (int i = 0; i < CREDENTIAL_MAX_SIZE + 1; i++) {
        testCredential += 'c';
    }
    options.credential = testCredential;
    result = AppAccountManager::VerifyCredential(STRING_NAME, STRING_OWNER, options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccountManager_CheckAccountLabels_0100
 * @tc.desc: Fail to check account labels with invalid parameters.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_CheckAccountLabels_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_CheckAccountLabels_0100");
    std::vector<std::string> labels;
    labels.clear();
    ErrCode result = AppAccountManager::CheckAccountLabels(STRING_OUT_OF_RANGE, STRING_OWNER, labels, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::CheckAccountLabels(STRING_EMPTY, STRING_OWNER, labels, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::CheckAccountLabels(STRING_NAME, STRING_OUT_OF_RANGE, labels, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::CheckAccountLabels(STRING_NAME, STRING_EMPTY, labels, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::CheckAccountLabels(STRING_NAME, STRING_OWNER, labels, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    result = AppAccountManager::CheckAccountLabels(STRING_NAME, STRING_OWNER, labels, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    for (int i = 0; i < ALLOWED_ARRAY_MAX_SIZE; i++) {
        std::string testLabel = "test_label_" + std::to_string(i);
        labels.emplace_back(testLabel);
    }
    result = AppAccountManager::CheckAccountLabels(STRING_NAME, STRING_OWNER, labels, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    labels.emplace_back("test_label_oversize");
    result = AppAccountManager::CheckAccountLabels(STRING_NAME, STRING_OWNER, labels, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    labels.clear();
    labels.emplace_back("test_label");
    result = AppAccountManager::CheckAccountLabels(STRING_NAME, STRING_OWNER, labels, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_SetAuthenticatorProperties_0100
 * @tc.desc: Fail to set authenticator properties with invalid parameters.
 * @tc.type: FUNC
 * @tc.require: issueI4ITYY
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_SetAuthenticatorProperties_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_SetAuthenticatorProperties_0100");
    SetPropertiesOptions options;
    // check owner
    ErrCode result = AppAccountManager::SetAuthenticatorProperties(STRING_OUT_OF_RANGE, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    result = AppAccountManager::SetAuthenticatorProperties(STRING_EMPTY, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    // check callback
    result = AppAccountManager::SetAuthenticatorProperties(STRING_OWNER, options, nullptr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    result = AppAccountManager::SetAuthenticatorProperties(STRING_OWNER, options, callback);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountManager_GetAllAccounts_0100
 * @tc.desc: Get all accounts with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQS
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAllAccounts_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountManager_GetAllAccounts_0100");

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = AppAccountManager::GetAllAccounts(STRING_EMPTY, appAccounts);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(appAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.name: AppAccountManager_GetAllAccounts_0200
 * @tc.desc: Get all accounts with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQS
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAllAccounts_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAllAccounts_0200");

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = AppAccountManager::GetAllAccounts(STRING_OWNER_OUT_OF_RANGE, appAccounts);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
    EXPECT_EQ(appAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.name: AppAccountManager_GetAllAccounts_0300
 * @tc.desc: Fail to get all accounts from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQS
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAllAccounts_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManager_GetAllAccounts_0300");
    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = AppAccountManager::GetAllAccounts(STRING_OWNER, appAccounts);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    EXPECT_TRUE(appAccounts.empty());
}

/**
 * @tc.name: AppAccountManager_GetAllAccessibleAccounts_0100
 * @tc.desc: Fail to get all accessible accounts from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQS
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_GetAllAccessibleAccounts_0100, TestSize.Level1)
{
    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = AppAccountManager::GetAllAccessibleAccounts(appAccounts);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    EXPECT_TRUE(appAccounts.empty());
}

/**
 * @tc.name: AppAccountManager_QueryAllAccessibleAccounts_0100
 * @tc.desc: Fail to query all accessible accounts from shell process.
 * @tc.type: FUNC
 * @tc.require: issueI4MBQS
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_QueryAllAccessibleAccounts_0100, TestSize.Level1)
{
    std::vector<AppAccountInfo> appAccounts;
    std::string owner = "";
    ErrCode result = AppAccountManager::QueryAllAccessibleAccounts(owner, appAccounts);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
    EXPECT_TRUE(appAccounts.empty());
}


/**
 * @tc.name: AppAccountManager_UnsubscribeAppAccount_0100
 * @tc.desc: Test func success UnsubscribeAppAccount.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountManagerTest, AppAccountManager_UnsubscribeAppAccount_0100, TestSize.Level1)
{
    auto appAccountPtr = DelayedSingleton<AppAccount>::GetInstance();
    ASSERT_NE(appAccountPtr, nullptr);
    AppAccountSubscribeInfo subscribeInfo;
    std::shared_ptr<AppAccountSubscriberTest> appAccountSubscriberPtr =
        std::make_shared<AppAccountSubscriberTest>(subscribeInfo);
    ASSERT_NE(appAccountSubscriberPtr, nullptr);
    auto appAccountEventListenerSptr = new (std::nothrow) AppAccountEventListener(appAccountSubscriberPtr);
    ASSERT_NE(appAccountEventListenerSptr, nullptr);
    appAccountPtr->eventListeners_[appAccountSubscriberPtr] = appAccountEventListenerSptr;
    ErrCode result = appAccountPtr->UnsubscribeAppAccount(appAccountSubscriberPtr);
    ASSERT_EQ(result, ERR_OK);
}

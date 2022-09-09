/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <thread>
#include "account_log_wrapper.h"
#define private public
#include "app_account_manager_service.h"
#undef private
#include "event_handler.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_OWNER = "com.example.owner";
const std::string STRING_EMPTY = "";
const std::string STRING_KEY = "key";
const std::string STRING_KEY_TWO = "key_two";
const std::string STRING_VALUE = "value";
const std::string STRING_VALUE_TWO = "value_two";
constexpr std::size_t SIZE_ZERO = 0;
constexpr std::size_t SIZE_ONE = 1;
constexpr std::int32_t WAIT_FOR_EXIT = 1000;
constexpr std::int32_t DELAY_FOR_OPERATION = 3000;
}  // namespace

class AppAccountManagerServiceThreadModuleTest : public testing::Test {
public:
    using Callback = OHOS::AppExecFwk::InnerEvent::Callback;

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    std::shared_ptr<AppAccountManagerService>
        appAccountManagerServicePtr_ = std::make_shared<AppAccountManagerService>();
    std::shared_ptr<OHOS::AppExecFwk::EventHandler>
        handler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(OHOS::AppExecFwk::EventRunner::Create());

    void AddAccount(const std::shared_ptr<AppAccountManagerService> &servicePtr);
    void DeleteAccount(const std::shared_ptr<AppAccountManagerService> &servicePtr);
    void SetAssociatedData(const std::shared_ptr<AppAccountManagerService> &servicePtr);
    void SetAssociatedDataTwo(const std::shared_ptr<AppAccountManagerService> &servicePtr);
};

void AppAccountManagerServiceThreadModuleTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "SetUpTestCase";
}

void AppAccountManagerServiceThreadModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase enter";
    DelayedSingleton<AppAccountControlManager>::DestroyInstance();
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_EXIT));
}

void AppAccountManagerServiceThreadModuleTest::SetUp(void)
{}

void AppAccountManagerServiceThreadModuleTest::TearDown(void)
{}

void AppAccountManagerServiceThreadModuleTest::AddAccount(const std::shared_ptr<AppAccountManagerService> &servicePtr)
{
    ACCOUNT_LOGI("enter");

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    ACCOUNT_LOGI("result = %{public}d", result);

    GTEST_LOG_(INFO) << "after AddAccount, result = " << result;
}

void AppAccountManagerServiceThreadModuleTest::DeleteAccount(
    const std::shared_ptr<AppAccountManagerService> &servicePtr)
{
    ACCOUNT_LOGI("enter");

    ErrCode result = servicePtr->DeleteAccount(STRING_NAME);
    ACCOUNT_LOGI("result = %{public}d", result);

    GTEST_LOG_(INFO) << "after DeleteAccount, result = " << result;
}

void AppAccountManagerServiceThreadModuleTest::SetAssociatedData(
    const std::shared_ptr<AppAccountManagerService> &servicePtr)
{
    ACCOUNT_LOGI("enter");

    ErrCode result = servicePtr->SetAssociatedData(STRING_NAME, STRING_KEY, STRING_VALUE);
    ACCOUNT_LOGI("result = %{public}d", result);

    GTEST_LOG_(INFO) << "after SetAssociatedData, result = " << result;
}

void AppAccountManagerServiceThreadModuleTest::SetAssociatedDataTwo(
    const std::shared_ptr<AppAccountManagerService> &servicePtr)
{
    ACCOUNT_LOGI("enter");

    ErrCode result = servicePtr->SetAssociatedData(STRING_NAME, STRING_KEY_TWO, STRING_VALUE_TWO);
    ACCOUNT_LOGI("result = %{public}d", result);

    GTEST_LOG_(INFO) << "after SetAssociatedData, result = " << result;
}

/**
 * @tc.name: AppAccountManagerServiceThread_AddAccount_0100
 * @tc.desc: Add an account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountManagerServiceThreadModuleTest, AppAccountManagerServiceThread_AddAccount_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceThread_AddAccount_0100");

    Callback callbackAdd = std::bind(&AppAccountManagerServiceThreadModuleTest::AddAccount, this,
        appAccountManagerServicePtr_);
    handler_->PostTask(callbackAdd);

    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = appAccountManagerServicePtr_->GetAllAccounts(STRING_OWNER, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);

    Callback callbackDel = std::bind(&AppAccountManagerServiceThreadModuleTest::DeleteAccount, this,
        appAccountManagerServicePtr_);
    handler_->PostTask(callbackDel);

    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));

    result = appAccountManagerServicePtr_->GetAllAccounts(STRING_OWNER, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ZERO);
}

/**
 * @tc.name: AppAccountManagerServiceThread_DeleteAccount_0100
 * @tc.desc: Delete an account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountManagerServiceThreadModuleTest, AppAccountManagerServiceThread_DeleteAccount_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceThread_DeleteAccount_0100");

    ErrCode result = appAccountManagerServicePtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    Callback callback = std::bind(&AppAccountManagerServiceThreadModuleTest::DeleteAccount, this,
        appAccountManagerServicePtr_);
    handler_->PostTask(callback);

    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));

    std::string extraInfo;
    result = appAccountManagerServicePtr_->GetAccountExtraInfo(STRING_NAME, extraInfo);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
    EXPECT_EQ(extraInfo, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManagerServiceThread_SetAssociatedData_0100
 * @tc.desc: Set associated data with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(
    AppAccountManagerServiceThreadModuleTest, AppAccountManagerServiceThread_SetAssociatedData_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceThread_SetAssociatedData_0100");

    ErrCode result = appAccountManagerServicePtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    Callback callbackSetAss = std::bind(&AppAccountManagerServiceThreadModuleTest::SetAssociatedData, this,
        appAccountManagerServicePtr_);
    handler_->PostTask(callbackSetAss);

    Callback callbackSetTwo = std::bind(&AppAccountManagerServiceThreadModuleTest::SetAssociatedDataTwo, this,
        appAccountManagerServicePtr_);
    handler_->PostTask(callbackSetTwo);

    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));

    std::string value;
    result = appAccountManagerServicePtr_->GetAssociatedData(STRING_NAME, STRING_KEY, value);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE);

    result = appAccountManagerServicePtr_->GetAssociatedData(STRING_NAME, STRING_KEY_TWO, value);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE_TWO);

    Callback callbackDel = std::bind(&AppAccountManagerServiceThreadModuleTest::DeleteAccount, this,
        appAccountManagerServicePtr_);
    handler_->PostTask(callbackDel);

    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));

    std::vector<AppAccountInfo> appAccounts;
    result = appAccountManagerServicePtr_->GetAllAccounts(STRING_OWNER, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ZERO);
}

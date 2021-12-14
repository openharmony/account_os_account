/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#define private public
#include "app_account_control_manager.h"
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

constexpr std::int32_t UID = 10000;
constexpr std::size_t SIZE_ONE = 1;
const std::int32_t DELAY_FOR_OPERATION = 3000;
}  // namespace

class AppAccountManagerServiceThreadModuleTest : public testing::Test {
public:
    using EventHandler = OHOS::AppExecFwk::EventHandler;
    using EventRunner = OHOS::AppExecFwk::EventRunner;
    using Callback = OHOS::AppExecFwk::InnerEvent::Callback;

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    void DeleteKvStore(void);
    void GetEventHandler(void);
    void ResetEventHandler(void);
    void AddAccount(const std::shared_ptr<AppAccountManagerService> &servicePtr);
    void DeleteAccount(const std::shared_ptr<AppAccountManagerService> &servicePtr);
    void SetAssociatedData(const std::shared_ptr<AppAccountManagerService> &servicePtr);
    void SetAssociatedDataTwo(const std::shared_ptr<AppAccountManagerService> &servicePtr);

    std::shared_ptr<AppAccountControlManager> controlManagerPtr_ = nullptr;
    std::shared_ptr<EventHandler> handler_ = nullptr;
};

void AppAccountManagerServiceThreadModuleTest::SetUpTestCase(void)
{}

void AppAccountManagerServiceThreadModuleTest::TearDownTestCase(void)
{}

void AppAccountManagerServiceThreadModuleTest::SetUp(void)
{
    DeleteKvStore();

    GetEventHandler();
}

void AppAccountManagerServiceThreadModuleTest::TearDown(void)
{
    DeleteKvStore();

    ResetEventHandler();
}

void AppAccountManagerServiceThreadModuleTest::DeleteKvStore(void)
{
    controlManagerPtr_ = AppAccountControlManager::GetInstance();
    ASSERT_NE(controlManagerPtr_, nullptr);

    auto dataStoragePtr = controlManagerPtr_->GetDataStorage(UID);
    ASSERT_NE(dataStoragePtr, nullptr);

    ErrCode result = dataStoragePtr->DeleteKvStore();
    ASSERT_EQ(result, ERR_OK);

    dataStoragePtr = controlManagerPtr_->GetDataStorage(UID, true);
    ASSERT_NE(dataStoragePtr, nullptr);

    result = dataStoragePtr->DeleteKvStore();
    ASSERT_EQ(result, ERR_OK);
}

void AppAccountManagerServiceThreadModuleTest::GetEventHandler(void)
{
    handler_ = std::make_shared<EventHandler>(EventRunner::Create());
    ASSERT_NE(handler_, nullptr);
}

void AppAccountManagerServiceThreadModuleTest::ResetEventHandler(void)
{
    handler_.reset();
}

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
HWTEST_F(AppAccountManagerServiceThreadModuleTest, AppAccountManagerServiceThread_AddAccount_0100,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceThread_AddAccount_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    Callback callback = std::bind(&AppAccountManagerServiceThreadModuleTest::AddAccount, this, servicePtr);
    handler_->PostTask(callback);

    Callback callbackTwo = std::bind(&AppAccountManagerServiceThreadModuleTest::AddAccount, this, servicePtr);
    handler_->PostTask(callbackTwo);

    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = servicePtr->GetAllAccounts(STRING_OWNER, appAccounts);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccounts.size(), SIZE_ONE);
}

/**
 * @tc.name: AppAccountManagerServiceThread_DeleteAccount_0100
 * @tc.desc: Delete an account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountManagerServiceThreadModuleTest, AppAccountManagerServiceThread_DeleteAccount_0100,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceThread_DeleteAccount_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    Callback callback = std::bind(&AppAccountManagerServiceThreadModuleTest::DeleteAccount, this, servicePtr);
    handler_->PostTask(callback);

    Callback callbackTwo = std::bind(&AppAccountManagerServiceThreadModuleTest::DeleteAccount, this, servicePtr);
    handler_->PostTask(callbackTwo);

    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));

    std::string extraInfo;
    result = servicePtr->GetAccountExtraInfo(STRING_NAME, extraInfo);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
    EXPECT_EQ(extraInfo, STRING_EMPTY);
}

/**
 * @tc.name: AppAccountManagerServiceThread_SetAssociatedData_0100
 * @tc.desc: Set associated data with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountManagerServiceThreadModuleTest, AppAccountManagerServiceThread_SetAssociatedData_0100,
    Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountManagerServiceThread_SetAssociatedData_0100");

    auto servicePtr = std::make_shared<AppAccountManagerService>();
    ASSERT_NE(servicePtr, nullptr);

    ErrCode result = servicePtr->AddAccount(STRING_NAME, STRING_EXTRA_INFO);
    EXPECT_EQ(result, ERR_OK);

    Callback callback = std::bind(&AppAccountManagerServiceThreadModuleTest::SetAssociatedData, this, servicePtr);
    handler_->PostTask(callback);

    Callback callbackTwo =
        std::bind(&AppAccountManagerServiceThreadModuleTest::SetAssociatedDataTwo, this, servicePtr);
    handler_->PostTask(callbackTwo);

    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));

    std::string value;
    result = servicePtr->GetAssociatedData(STRING_NAME, STRING_KEY, value);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE);

    result = servicePtr->GetAssociatedData(STRING_NAME, STRING_KEY_TWO, value);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(value, STRING_VALUE_TWO);
}

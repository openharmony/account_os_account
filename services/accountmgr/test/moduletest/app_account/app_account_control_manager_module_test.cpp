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
#include "app_account_control_manager.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_OWNER = "com.example.owner";

const std::size_t ACCOUNT_MAX_SIZE = 1000;
const std::int32_t DELAY_FOR_OPERATION = 250;

constexpr std::int32_t UID = 10000;
}  // namespace

class AppAccountControlManagerModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    std::shared_ptr<AppAccountControlManager> controlManagerPtr_ = AppAccountControlManager::GetInstance();
};

void AppAccountControlManagerModuleTest::SetUpTestCase(void)
{}

void AppAccountControlManagerModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase enter";
    DelayedSingleton<AppAccountControlManager>::DestroyInstance();
}

void AppAccountControlManagerModuleTest::SetUp(void)
{}

void AppAccountControlManagerModuleTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountControlManager_AccountMaxSize_0100
 * @tc.desc: Check account max size with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_AccountMaxSize_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_AccountMaxSize_0100");

    ASSERT_NE(controlManagerPtr_, nullptr);

    EXPECT_EQ(controlManagerPtr_->ACCOUNT_MAX_SIZE, ACCOUNT_MAX_SIZE);
}

/**
 * @tc.name: AppAccountControlManager_AccountMaxSize_0200
 * @tc.desc: Check account max size with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_AccountMaxSize_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_AccountMaxSize_0200");

    ASSERT_NE(controlManagerPtr_, nullptr);

    ErrCode result;
    std::string name;
    for (std::size_t index = 0; index < ACCOUNT_MAX_SIZE; index++) {
        name = STRING_NAME + std::to_string(index);
        ACCOUNT_LOGI("before AddAccount, index = %{public}zu", index);
        GTEST_LOG_(INFO) << "before AddAccount, index = " << index;

        AppAccountInfo appAccountInfo(name, STRING_OWNER);
        result = controlManagerPtr_->AddAccount(name, STRING_EXTRA_INFO, UID, STRING_OWNER, appAccountInfo);
        ASSERT_EQ(result, ERR_OK);

        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));
    }

    AppAccountInfo appAccountInfo(STRING_NAME, STRING_OWNER);
    result = controlManagerPtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO, UID, STRING_OWNER, appAccountInfo);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_MAX_SIZE);

    for (std::size_t index = 0; index < ACCOUNT_MAX_SIZE; index++) {
        name = STRING_NAME + std::to_string(index);
        ACCOUNT_LOGI("before DeleteAccount, index = %{public}zu", index);
        GTEST_LOG_(INFO) << "before DeleteAccount, index = " << index;

        AppAccountInfo appAccountInfo(name, STRING_OWNER);
        result = controlManagerPtr_->DeleteAccount(name, UID, STRING_OWNER, appAccountInfo);
        ASSERT_EQ(result, ERR_OK);

        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));
    }
}

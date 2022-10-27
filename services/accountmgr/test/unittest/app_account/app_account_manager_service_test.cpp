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

#include "account_error_no.h"
#define private public
#include "app_account_control_manager.h"
#include "app_account_manager_service.h"
#undef private
#include "mock_inner_app_account_manager.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_OWNER = "com.example.owner";
}  // namespace

class AppAccountManagerServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    sptr<IRemoteObject> appAccountManagerService_;
    sptr<IAppAccount> appAccountProxy_;
};

void AppAccountManagerServiceTest::SetUpTestCase(void)
{}

void AppAccountManagerServiceTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase!";
    DelayedSingleton<AppAccountControlManager>::DestroyInstance();
}

void AppAccountManagerServiceTest::SetUp(void)
{
    auto servicePtr = new (std::nothrow) AppAccountManagerService();
    if (servicePtr == nullptr) {
        return;
    }
    auto mockInnerManagerPtr = std::make_shared<MockInnerAppAccountManager>();
    servicePtr->innerManager_ = mockInnerManagerPtr;

    appAccountManagerService_ = servicePtr->AsObject();
    appAccountProxy_ = iface_cast<IAppAccount>(appAccountManagerService_);
}

void AppAccountManagerServiceTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountManagerService_AddAccount_0100
 * @tc.desc: Add an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountManagerServiceTest, AppAccountManagerService_AddAccount_0100, TestSize.Level1)
{
    ErrCode result = appAccountProxy_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_DeleteAccount_0100
 * @tc.desc: Delete an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountManagerServiceTest, AppAccountManagerService_DeleteAccount_0100, TestSize.Level1)
{
    ErrCode result = appAccountProxy_->DeleteAccount(STRING_NAME);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_CreateAccount_0100
 * @tc.desc: Add an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountManagerServiceTest, AppAccountManagerService_CreateAccount_0100, TestSize.Level1)
{
    CreateAccountOptions option;
    ErrCode result = appAccountProxy_->CreateAccount(STRING_NAME, option);
    EXPECT_EQ(result, ERR_OK);
    result = appAccountProxy_->DeleteAccount(STRING_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccountManagerService_SubscribeAppAccount_0100
 * @tc.desc: Subscribe app accounts with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(
    AppAccountManagerServiceTest, AppAccountManagerService_SubscribeAppAccount_0100, TestSize.Level1)
{
    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo;
    subscribeInfo.SetOwners(owners);

    // subscribe app account
    ErrCode result = appAccountProxy_->SubscribeAppAccount(subscribeInfo, nullptr);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_EVENT_LISTENER_IS_NULLPTR);
}

/**
 * @tc.name: AppAccountManagerService_UnsubscribeAppAccount_0100
 * @tc.desc: Unsubscribe app accounts with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(
    AppAccountManagerServiceTest, AppAccountManagerService_UnsubscribeAppAccount_0100, TestSize.Level1)
{
    // unsubscribe app account
    ErrCode result = appAccountProxy_->UnsubscribeAppAccount(nullptr);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_EVENT_LISTENER_IS_NULLPTR);
}

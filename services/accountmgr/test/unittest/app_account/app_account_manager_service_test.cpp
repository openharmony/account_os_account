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

#include "account_error_no.h"
#define private public
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
{}

void AppAccountManagerServiceTest::SetUp(void)
{
    auto servicePtr = new AppAccountManagerService();
    auto mockInnerManagerPtr = std::make_shared<MockInnerAppAccountManager>();
    servicePtr->innerManager_ = mockInnerManagerPtr;

    appAccountManagerService_ = servicePtr->AsObject();
    appAccountProxy_ = iface_cast<IAppAccount>(appAccountManagerService_);
}

void AppAccountManagerServiceTest::TearDown(void)
{}

/**
 * @tc.number: AppAccountManagerService_AddAccount_0100
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with valid data.
 */
HWTEST_F(AppAccountManagerServiceTest, AppAccountManagerService_AddAccount_0100, Function | MediumTest | Level1)
{
    ErrCode result = appAccountProxy_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_DeleteAccount_0100
 * @tc.name: DeleteAccount
 * @tc.desc: Delete an app account with valid data.
 */
HWTEST_F(AppAccountManagerServiceTest, AppAccountManagerService_DeleteAccount_0100, Function | MediumTest | Level1)
{
    ErrCode result = appAccountProxy_->DeleteAccount(STRING_NAME);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_SubscribeAppAccount_0100
 * @tc.name: SubscribeAppAccount
 * @tc.desc: Subscribe app accounts with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceTest, AppAccountManagerService_SubscribeAppAccount_0100, Function | MediumTest | Level1)
{
    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subcribe info
    AppAccountSubscribeInfo subscribeInfo;
    subscribeInfo.SetOwners(owners);

    // subscribe app account
    ErrCode result = appAccountProxy_->SubscribeAppAccount(subscribeInfo, nullptr);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountManagerService_UnsubscribeAppAccount_0100
 * @tc.name: UnsubscribeAppAccount
 * @tc.desc: Unsubscribe app accounts with valid data.
 */
HWTEST_F(
    AppAccountManagerServiceTest, AppAccountManagerService_UnsubscribeAppAccount_0100, Function | MediumTest | Level1)
{
    // unsubscribe app account
    ErrCode result = appAccountProxy_->UnsubscribeAppAccount(nullptr);

    EXPECT_EQ(result, ERR_OK);
}

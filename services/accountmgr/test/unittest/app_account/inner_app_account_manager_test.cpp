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
#include "iinner_app_account.h"
#include "iapp_account_control.h"
#include "iapp_account_subscribe.h"
#define private public
#include "inner_app_account_manager.h"
#undef private
#include "mock_app_account_control_manager.h"
#include "mock_app_account_subscribe_manager.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_OWNER = "com.example.owner";
}  // namespace

class InnerAppAccountManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    void MakeMockObjects();
    void MakeEmptyMockObjects();

    std::shared_ptr<IInnerAppAccount> innerManagerPtr_;
};

void InnerAppAccountManagerTest::SetUpTestCase(void)
{}

void InnerAppAccountManagerTest::TearDownTestCase(void)
{}

void InnerAppAccountManagerTest::SetUp(void)
{}

void InnerAppAccountManagerTest::TearDown(void)
{}

void InnerAppAccountManagerTest::MakeMockObjects()
{
    auto innerManagerPtr = std::make_shared<InnerAppAccountManager>();

    // make mock control manager
    auto controlManagerPtr = std::make_shared<MockAppAccountControlManager>();
    innerManagerPtr->controlManagerPtr_ = controlManagerPtr;

    // make mock subscribe manager
    auto subscribeManagerPtr = std::make_shared<MockAppAccountSubscribeManager>();
    innerManagerPtr->subscribeManagerPtr_ = subscribeManagerPtr;

    innerManagerPtr_ = innerManagerPtr;
}

void InnerAppAccountManagerTest::MakeEmptyMockObjects()
{
    auto innerManagerPtr = std::make_shared<InnerAppAccountManager>();

    // make empty control manager
    innerManagerPtr->controlManagerPtr_ = nullptr;
    // make empty subscribe manager
    innerManagerPtr->subscribeManagerPtr_ = nullptr;

    innerManagerPtr_ = innerManagerPtr;
}

/**
 * @tc.number: AppAccount_AddAccount_001
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with valid data.
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_AddAccount_001, Function | MediumTest | Level1)
{
    MakeMockObjects();

    ErrCode result = innerManagerPtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO, STRING_OWNER);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccount_AddAccount_002
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with empty managers.
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_AddAccount_002, Function | MediumTest | Level1)
{
    MakeEmptyMockObjects();

    ErrCode result = innerManagerPtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO, STRING_OWNER);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.number: AppAccount_DeleteAccount_001
 * @tc.name: DeleteAccount
 * @tc.desc: Delete an app account with valid data.
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_DeleteAccount_001, Function | MediumTest | Level1)
{
    MakeMockObjects();

    ErrCode result = innerManagerPtr_->DeleteAccount(STRING_NAME, STRING_OWNER);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccount_DeleteAccount_002
 * @tc.name: DeleteAccount
 * @tc.desc: Delete an app account with empty managers.
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_DeleteAccount_002, Function | MediumTest | Level1)
{
    MakeEmptyMockObjects();

    ErrCode result = innerManagerPtr_->DeleteAccount(STRING_NAME, STRING_OWNER);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.number: AppAccount_SubscribeAppAccount_001
 * @tc.name: SubscribeAppAccount
 * @tc.desc: Subscribe app accounts with valid data.
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_SubscribeAppAccount_001, Function | MediumTest | Level1)
{
    MakeMockObjects();

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subcribe info
    AppAccountSubscribeInfo subscribeInfo;
    subscribeInfo.SetOwners(owners);

    // subscribe app account
    ErrCode result = innerManagerPtr_->SubscribeAppAccount(subscribeInfo, nullptr, STRING_OWNER);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccount_SubscribeAppAccount_002
 * @tc.name: SubscribeAppAccount
 * @tc.desc: Subscribe app accounts with empty managers.
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_SubscribeAppAccount_002, Function | MediumTest | Level1)
{
    MakeEmptyMockObjects();

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subcribe info
    AppAccountSubscribeInfo subscribeInfo;
    subscribeInfo.SetOwners(owners);

    // subscribe app account
    ErrCode result = innerManagerPtr_->SubscribeAppAccount(subscribeInfo, nullptr, STRING_OWNER);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR);
}

/**
 * @tc.number: AppAccount_UnsubscribeAppAccount_001
 * @tc.name: UnsubscribeAppAccount
 * @tc.desc: Unsubscribe app accounts with valid data.
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_UnsubscribeAppAccount_001, Function | MediumTest | Level1)
{
    MakeMockObjects();

    // unsubscribe app account
    ErrCode result = innerManagerPtr_->UnsubscribeAppAccount(nullptr);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccount_UnsubscribeAppAccount_002
 * @tc.name: UnsubscribeAppAccount
 * @tc.desc: Unsubscribe app accounts with empty managers.
 */
HWTEST_F(InnerAppAccountManagerTest, AppAccount_UnsubscribeAppAccount_002, Function | MediumTest | Level1)
{
    MakeEmptyMockObjects();

    // unsubscribe app account
    ErrCode result = innerManagerPtr_->UnsubscribeAppAccount(nullptr);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR);
}

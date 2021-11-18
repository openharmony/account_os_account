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
#include "app_account.h"
#undef private
#include "mock_app_account_stub.h"
#include "iremote_object.h"
#include "singleton.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_EMPTY = "";
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_NAME_OUT_OF_RANGE =
    "name_out_of_range_"
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
const std::string STRING_NAME_EMPTY = STRING_EMPTY;
const std::string STRING_EXTRA_INFO_EMPTY = STRING_EMPTY;
const std::string STRING_OWNER = "com.example.owner";

constexpr std::int32_t SUBSCRIBER_ZERO = 0;
constexpr std::int32_t SUBSCRIBER_ONE = 1;
}  // namespace

class AppAccountTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    sptr<IRemoteObject> MakeMockObjects(void) const;

    std::shared_ptr<AppAccount> appAccount_;
};

sptr<IRemoteObject> AppAccountTest::MakeMockObjects(void) const
{
    // mock a stub
    auto mockStub = sptr<IRemoteObject>(new MockAppAccountStub());

    return mockStub;
}

void AppAccountTest::SetUpTestCase(void)
{}

void AppAccountTest::TearDownTestCase(void)
{}

void AppAccountTest::SetUp(void)
{
    // get the singleton of AppAccount
    appAccount_ = DelayedSingleton<AppAccount>::GetInstance();

    // mock a proxy
    auto mockProxy = iface_cast<IAppAccount>(MakeMockObjects());

    // add the mock proxy
    appAccount_->appAccountProxy_ = mockProxy;
}

void AppAccountTest::TearDown(void)
{
    // destroy the singleton
    DelayedSingleton<AppAccount>::DestroyInstance();
}

class AppAccountSubscriberTest : public AppAccountSubscriber {
public:
    explicit AppAccountSubscriberTest(const AppAccountSubscribeInfo &subscribeInfo)
        : AppAccountSubscriber(subscribeInfo)
    {}

    ~AppAccountSubscriberTest()
    {}

    void OnAccountsChanged(const std::vector<AppAccountInfo> &accounts)
    {}
};

/**
 * @tc.number: AppAccount_AddAccount_0100
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with valid data.
 */
HWTEST_F(AppAccountTest, AppAccount_AddAccount_0100, Function | MediumTest | Level1)
{
    ErrCode result = appAccount_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccount_AddAccount_0200
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with invalid data.
 */
HWTEST_F(AppAccountTest, AppAccount_AddAccount_0200, Function | MediumTest | Level1)
{
    ErrCode result = appAccount_->AddAccount(STRING_NAME_EMPTY, STRING_EXTRA_INFO);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
}

/**
 * @tc.number: AppAccount_AddAccount_0300
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with valid data.
 */
HWTEST_F(AppAccountTest, AppAccount_AddAccount_0300, Function | MediumTest | Level1)
{
    ErrCode result = appAccount_->AddAccount(STRING_NAME, STRING_EXTRA_INFO_EMPTY);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccount_AddAccount_0400
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with invalid data.
 */
HWTEST_F(AppAccountTest, AppAccount_AddAccount_0400, Function | MediumTest | Level1)
{
    ErrCode result = appAccount_->AddAccount(STRING_NAME_OUT_OF_RANGE, STRING_EXTRA_INFO);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccount_AddAccount_0500
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with invalid data.
 */
HWTEST_F(AppAccountTest, AppAccount_AddAccount_0500, Function | MediumTest | Level1)
{
    ErrCode result = appAccount_->AddAccount(STRING_NAME, STRING_EXTRA_INFO_OUT_OF_RANGE);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_EXTRA_INFO_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccount_DeleteAccount_0100
 * @tc.name: DeleteAccount
 * @tc.desc: Delete an app account with valid data.
 */
HWTEST_F(AppAccountTest, AppAccount_DeleteAccount_0100, Function | MediumTest | Level1)
{
    ErrCode result = appAccount_->DeleteAccount(STRING_NAME);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccount_DeleteAccount_0200
 * @tc.name: DeleteAccount
 * @tc.desc: Delete an app account with invalid data.
 */
HWTEST_F(AppAccountTest, AppAccount_DeleteAccount_0200, Function | MediumTest | Level1)
{
    ErrCode result = appAccount_->DeleteAccount(STRING_NAME_EMPTY);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_IS_EMPTY);
}

/**
 * @tc.number: AppAccount_DeleteAccount_0300
 * @tc.name: DeleteAccount
 * @tc.desc: Delete an app account with invalid data.
 */
HWTEST_F(AppAccountTest, AppAccount_DeleteAccount_0300, Function | MediumTest | Level1)
{
    ErrCode result = appAccount_->DeleteAccount(STRING_NAME_OUT_OF_RANGE);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccount_SubscribeAppAccount_0100
 * @tc.name: SubscribeAppAccount
 * @tc.desc: Subscribe app accounts with valid data.
 */
HWTEST_F(AppAccountTest, AppAccount_SubscribeAppAccount_0100, Function | MediumTest | Level1)
{
    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subcribe info
    AppAccountSubscribeInfo subscribeInfo;
    subscribeInfo.SetOwners(owners);

    // make a subcriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);
    // subscribe app account
    ErrCode result = appAccount_->SubscribeAppAccount(subscriberTestPtr);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccount_SubscribeAppAccount_0200
 * @tc.name: SubscribeAppAccount
 * @tc.desc: Subscribe app accounts with invalid data.
 */
HWTEST_F(AppAccountTest, AppAccount_SubscribeAppAccount_0200, Function | MediumTest | Level1)
{
    // subscribe app account with nullptr
    ErrCode result = appAccount_->SubscribeAppAccount(nullptr);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_SUBSCRIBER_IS_NULLPTR);
}

/**
 * @tc.number: AppAccount_GetAppAccountProxy_0100
 * @tc.name: GetAppAccountProxy
 * @tc.desc: Get app account proxy.
 */
HWTEST_F(AppAccountTest, AppAccount_GetAppAccountProxy_0100, Function | MediumTest | Level1)
{
    // get app account proxy
    ErrCode result = appAccount_->GetAppAccountProxy();

    EXPECT_EQ(result, ERR_OK);
    EXPECT_NE(appAccount_->appAccountProxy_, nullptr);
}

/**
 * @tc.number: AppAccount_ResetAppAccountProxy_0100
 * @tc.name: ResetAppAccountProxy
 * @tc.desc: Reset app account proxy.
 */
HWTEST_F(AppAccountTest, AppAccount_ResetAppAccountProxy_0100, Function | MediumTest | Level1)
{
    // get app account proxy
    ErrCode result = appAccount_->GetAppAccountProxy();

    EXPECT_NE(appAccount_->appAccountProxy_, nullptr);

    // reset app account proxy
    result = appAccount_->ResetAppAccountProxy();

    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appAccount_->appAccountProxy_, nullptr);
}

/**
 * @tc.number: AppAccount_CreateAppAccountEventListener_0100
 * @tc.name: CreateAppAccountEventListener
 * @tc.desc: create app account event listener.
 */
HWTEST_F(AppAccountTest, AppAccount_CreateAppAccountEventListener_0100, Function | MediumTest | Level1)
{
    ErrCode result = -1;

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subcribe info
    AppAccountSubscribeInfo subscribeInfo;
    result = subscribeInfo.SetOwners(owners);

    EXPECT_EQ(result, ERR_OK);

    // make a subcriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);
    sptr<IRemoteObject> appAccountEventListener = nullptr;

    EXPECT_EQ(appAccount_->eventListeners_.size(), SUBSCRIBER_ZERO);

    // initial subscription
    result = appAccount_->CreateAppAccountEventListener(subscriberTestPtr, appAccountEventListener);
    EXPECT_EQ(result, AppAccount::SubscribeState::INITIAL_SUBSCRIPTION);
    EXPECT_EQ(appAccount_->eventListeners_.size(), SUBSCRIBER_ONE);

    // already subscribed
    result = appAccount_->CreateAppAccountEventListener(subscriberTestPtr, appAccountEventListener);
    EXPECT_EQ(result, AppAccount::SubscribeState::ALREADY_SUBSCRIBED);
    EXPECT_EQ(appAccount_->eventListeners_.size(), SUBSCRIBER_ONE);
}

/**
 * @tc.number: AppAccount_CreateAppAccountEventListener_0200
 * @tc.name: CreateAppAccountEventListener
 * @tc.desc: create app account event listener.
 */
HWTEST_F(AppAccountTest, AppAccount_CreateAppAccountEventListener_0200, Function | MediumTest | Level1)
{
    ErrCode result = -1;

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subcribe info
    AppAccountSubscribeInfo subscribeInfo;
    result = subscribeInfo.SetOwners(owners);

    EXPECT_EQ(result, ERR_OK);

    EXPECT_EQ(appAccount_->eventListeners_.size(), SUBSCRIBER_ZERO);

    // make max subcribers
    for (unsigned int counter = 1; counter <= appAccount_->SUBSCRIBER_MAX_SIZE + 1; counter += 1) {
        auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);
        sptr<IRemoteObject> appAccountEventListener = nullptr;

        result = appAccount_->CreateAppAccountEventListener(subscriberTestPtr, appAccountEventListener);
        if (counter <= appAccount_->SUBSCRIBER_MAX_SIZE) {
            EXPECT_EQ(result, AppAccount::SubscribeState::INITIAL_SUBSCRIPTION);
            EXPECT_EQ(appAccount_->eventListeners_.size(), counter);
        } else {
            EXPECT_EQ(result, AppAccount::SubscribeState::SUBSCRIBE_FAILD);
            EXPECT_EQ(appAccount_->eventListeners_.size(), counter - 1);
        }
    }
}

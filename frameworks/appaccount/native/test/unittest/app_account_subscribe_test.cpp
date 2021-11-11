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

#include "app_account_manager.h"
#include "app_account_subscriber.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_OWNER = "com.example.owner";
}  // namespace

class AppAccountSubscribeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountSubscribeTest::SetUpTestCase(void)
{}

void AppAccountSubscribeTest::TearDownTestCase(void)
{}

void AppAccountSubscribeTest::SetUp(void)
{}

void AppAccountSubscribeTest::TearDown(void)
{}

class AppAccountSubscriberTest : public AppAccountSubscriber {
public:
    explicit AppAccountSubscriberTest(const AppAccountSubscribeInfo &subscribeInfo)
        : AppAccountSubscriber(subscribeInfo)
    {
        ACCOUNT_LOGI("enter");
    }

    ~AppAccountSubscriberTest()
    {
        ACCOUNT_LOGI("enter");
    }

    virtual void OnAccountsChanged(const std::vector<AppAccountInfo> &accounts)
    {
        ACCOUNT_LOGI("enter");
    }
};

/**
 * @tc.number: AppAccountSubscribe_SubscribeAppAccount_0100
 * @tc.name: SubscribeAppAccount
 * @tc.desc: Subscribe app accounts with invalid data.
 */
HWTEST_F(AppAccountSubscribeTest, AppAccountSubscribe_SubscribeAppAccount_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("AppAccountSubscribe_SubscribeAppAccount_0100");

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo(owners);

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);

    // unsubscribe app account
    ErrCode result = AppAccountManager::UnsubscribeAppAccount(subscriberTestPtr);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED);
}

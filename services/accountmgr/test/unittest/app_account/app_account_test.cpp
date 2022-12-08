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
#include "account_log_wrapper.h"
#define private public
#include "app_account.h"
#include "app_account_authenticator_callback.h"
#include "app_account_authenticator_callback_stub.h"
#include "app_account_authenticator_stub.h"
#include "app_account_constants.h"
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
const std::string STRING_NAME_CONTAINS_SPECIAL_CHARACTERS = " name";
const std::string STRING_NAME_CONTAINS_SPECIAL_CHARACTERS_TWO = "n ame";
const std::string STRING_NAME_CONTAINS_SPECIAL_CHARACTERS_THREE = "name ";
const std::string STRING_NAME_OUT_OF_RANGE =
    "name_12345678"
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
const std::string STRING_NAME_EMPTY = STRING_EMPTY;
const std::string STRING_EXTRA_INFO_EMPTY = STRING_EMPTY;
const std::string STRING_OWNER = "com.example.owner";

constexpr std::size_t SUBSCRIBER_ZERO = 0;
constexpr std::size_t SUBSCRIBER_ONE = 1;
const uint32_t INVALID_IPC_CODE = 1000;
const int32_t MAX_CUSTOM_DATA_SIZE = 1300;
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
    auto mockStub = sptr<IRemoteObject>(new (std::nothrow) MockAppAccountStub());

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
 * @tc.name: AppAccountAuthenticatorCallbackStub_OnRemoteRequest_0100
 * @tc.desc: OnRemoteRequest with wrong message code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountTest, AppAccountAuthenticatorCallbackStub_OnRemoteRequest_0100, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    data.WriteInterfaceToken(AppAccountAuthenticatorCallbackStub::GetDescriptor());

    std::string sessionId = "sessionId";
    sptr<AppAccountAuthenticatorCallbackStub> stub = new (std::nothrow) AppAccountAuthenticatorCallback(sessionId);
    ASSERT_NE(nullptr, stub);
    int32_t ret = stub->OnRemoteRequest(INVALID_IPC_CODE, data, reply, option);
    EXPECT_EQ(IPC_STUB_UNKNOW_TRANS_ERR, ret);
}

/**
 * @tc.name: AppAccount_AddAccount_0100
 * @tc.desc: Add an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountTest, AppAccount_AddAccount_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccount_AddAccount_0100");

    ErrCode result = appAccount_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccount_AddAccount_0200
 * @tc.desc: Add an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountTest, AppAccount_AddAccount_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_AddAccount_0200");

    ErrCode result = appAccount_->AddAccount(STRING_NAME_EMPTY, STRING_EXTRA_INFO);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccount_AddAccount_0300
 * @tc.desc: Add an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountTest, AppAccount_AddAccount_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_AddAccount_0300");

    ErrCode result = appAccount_->AddAccount(STRING_NAME, STRING_EXTRA_INFO_EMPTY);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccount_AddAccount_0400
 * @tc.desc: Add an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountTest, AppAccount_AddAccount_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_AddAccount_0400");

    ErrCode result = appAccount_->AddAccount(STRING_NAME_OUT_OF_RANGE, STRING_EXTRA_INFO);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccount_AddAccount_0500
 * @tc.desc: Add an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountTest, AppAccount_AddAccount_0500, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_AddAccount_0500");

    ErrCode result = appAccount_->AddAccount(STRING_NAME_CONTAINS_SPECIAL_CHARACTERS, STRING_EXTRA_INFO);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccount_AddAccount_0600
 * @tc.desc: Add an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountTest, AppAccount_AddAccount_0600, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_AddAccount_0600");

    ErrCode result = appAccount_->AddAccount(STRING_NAME_CONTAINS_SPECIAL_CHARACTERS_TWO, STRING_EXTRA_INFO);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccount_AddAccount_0700
 * @tc.desc: Add an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountTest, AppAccount_AddAccount_0700, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_AddAccount_0700");

    ErrCode result = appAccount_->AddAccount(STRING_NAME_CONTAINS_SPECIAL_CHARACTERS_THREE, STRING_EXTRA_INFO);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccount_AddAccount_0800
 * @tc.desc: Add an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountTest, AppAccount_AddAccount_0800, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_AddAccount_0800");

    ErrCode result = appAccount_->AddAccount(STRING_NAME, STRING_EXTRA_INFO_OUT_OF_RANGE);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccount_DeleteAccount_0100
 * @tc.desc: Delete an app account with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountTest, AppAccount_DeleteAccount_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_DeleteAccount_0100");

    ErrCode result = appAccount_->DeleteAccount(STRING_NAME);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccount_DeleteAccount_0200
 * @tc.desc: Delete an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountTest, AppAccount_DeleteAccount_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_DeleteAccount_0200");

    ErrCode result = appAccount_->DeleteAccount(STRING_NAME_EMPTY);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccount_DeleteAccount_0300
 * @tc.desc: Delete an app account with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV11
 */
HWTEST_F(AppAccountTest, AppAccount_DeleteAccount_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_DeleteAccount_0300");

    ErrCode result = appAccount_->DeleteAccount(STRING_NAME_OUT_OF_RANGE);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccount_SubscribeAppAccount_0100
 * @tc.desc: Subscribe app accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(AppAccountTest, AppAccount_SubscribeAppAccount_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccount_SubscribeAppAccount_0100");

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo;
    subscribeInfo.SetOwners(owners);

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);
    // subscribe app account
    ErrCode result = appAccount_->SubscribeAppAccount(subscriberTestPtr);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccount_SubscribeAppAccount_0200
 * @tc.desc: Subscribe app accounts with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(AppAccountTest, AppAccount_SubscribeAppAccount_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_SubscribeAppAccount_0200");

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo;
    subscribeInfo.SetOwners(owners);

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);
    // subscribe app account
    ErrCode result = appAccount_->SubscribeAppAccount(subscriberTestPtr);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccount_SubscribeAppAccount_0300
 * @tc.desc: Subscribe app accounts with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(AppAccountTest, AppAccount_SubscribeAppAccount_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_SubscribeAppAccount_0300");

    // subscribe app account with nullptr
    ErrCode result = appAccount_->SubscribeAppAccount(nullptr);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_SUBSCRIBER_IS_NULLPTR);
}

/**
 * @tc.name: AppAccount_GetAppAccountProxy_0100
 * @tc.desc: Get app account proxy.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFQ
 */
HWTEST_F(AppAccountTest, AppAccount_GetAppAccountProxy_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_GetAppAccountProxy_0100");

    // get app account proxy
    ErrCode result = appAccount_->GetAppAccountProxy();

    EXPECT_EQ(result, ERR_OK);
    EXPECT_NE(appAccount_->appAccountProxy_, nullptr);
}

/**
 * @tc.name: AppAccount_ResetAppAccountProxy_0100
 * @tc.desc: Reset app account proxy.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFQ
 */
HWTEST_F(AppAccountTest, AppAccount_ResetAppAccountProxy_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_ResetAppAccountProxy_0100");

    // get app account proxy
    ErrCode result = appAccount_->GetAppAccountProxy();
    EXPECT_EQ(result, ERR_OK);
    EXPECT_NE(appAccount_->appAccountProxy_, nullptr);

    // reset app account proxy
    result = appAccount_->ResetAppAccountProxy();

    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appAccount_->appAccountProxy_, nullptr);
}

/**
 * @tc.name: AppAccount_CreateAppAccountEventListener_0100
 * @tc.desc: create app account event listener.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(AppAccountTest, AppAccount_CreateAppAccountEventListener_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_CreateAppAccountEventListener_0100");

    ErrCode result = -1;

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo;
    result = subscribeInfo.SetOwners(owners);

    EXPECT_EQ(result, ERR_OK);

    // make a subscriber
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
 * @tc.name: AppAccount_CreateAppAccountEventListener_0200
 * @tc.desc: create app account event listener.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(AppAccountTest, AppAccount_CreateAppAccountEventListener_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_CreateAppAccountEventListener_0200");

    ErrCode result = -1;

    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo;
    result = subscribeInfo.SetOwners(owners);

    EXPECT_EQ(result, ERR_OK);

    EXPECT_EQ(appAccount_->eventListeners_.size(), SUBSCRIBER_ZERO);

    // make max subscribers
    for (std::size_t counter = 1; counter <= Constants::APP_ACCOUNT_SUBSCRIBER_MAX_SIZE + 1; counter += 1) {
        auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);
        sptr<IRemoteObject> appAccountEventListener = nullptr;

        result = appAccount_->CreateAppAccountEventListener(subscriberTestPtr, appAccountEventListener);
        if (counter <= Constants::APP_ACCOUNT_SUBSCRIBER_MAX_SIZE) {
            EXPECT_EQ(result, AppAccount::SubscribeState::INITIAL_SUBSCRIPTION);
            EXPECT_EQ(appAccount_->eventListeners_.size(), counter);
        } else {
            EXPECT_EQ(result, AppAccount::SubscribeState::SUBSCRIBE_FAILED);
            EXPECT_EQ(appAccount_->eventListeners_.size(), counter - 1);
        }
    }
}

/**
 * @tc.name: AppAccount_CreateAccount_001
 * @tc.desc: Function CreateAccount normal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountTest, AppAccount_CreateAccount_001, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_CreateAccount_001");

    CreateAccountOptions option;
    ErrCode result = appAccount_->CreateAccount("test", option);
    EXPECT_EQ(result, ERR_OK);

    result = appAccount_->DeleteAccount("test");
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AppAccount_CreateAccount_002
 * @tc.desc: Function CreateAccount abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountTest, AppAccount_CreateAccount_002, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_CreateAccount_002");

    CreateAccountOptions option;

    ErrCode result = appAccount_->CreateAccount("", option);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);

    result = appAccount_->CreateAccount(STRING_NAME_OUT_OF_RANGE, option);

    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}

/**
 * @tc.name: AppAccount_CreateAccount_003
 * @tc.desc: Function CreateAccount customData is oversize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountTest, AppAccount_CreateAccount_003, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccount_CreateAccount_002");

    CreateAccountOptions option;
    for (int i = 0; i <= MAX_CUSTOM_DATA_SIZE; i++) {
        std::string key = std::to_string(i);
        std::string value = key;
        option.customData[key] = value;
    }
    ErrCode result = appAccount_->CreateAccount("test", option);
    EXPECT_EQ(result, ERR_APPACCOUNT_KIT_INVALID_PARAMETER);
}
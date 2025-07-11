/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "account_log_wrapper.h"
#include "app_account_common.h"
#define private public
#ifdef HAS_CES_PART
#include "common_event_manager.h"
#include "common_event_support.h"
#endif // HAS_CES_PART
#include "app_account_common_event_observer.h"
#include "app_account_event_listener.h"
#include "app_account_event_stub.h"
#include "app_account_event_proxy.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

bool g_status = false;
namespace {
uint32_t INVALID_CODE = -1;
}

class MockAppAccountEventStub : public AppAccountEventStub {
public:
    ErrCode OnAccountsChanged(const std::vector<AppAccountInfo> &accounts, const std::string &ownerName)
    {
        g_status = true;
        return ERR_OK;
    }
};

class AppAccountEventModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountEventModuleTest::SetUpTestCase(void)
{}

void AppAccountEventModuleTest::TearDownTestCase(void)
{}

void AppAccountEventModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AppAccountEventModuleTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountAuthenticateTest_CreateAccountImplicitly_0100
 * @tc.desc: test event proxy cpp file.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountEventModuleTest, AppAccountEventTest_OnAccountsChanged_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountAuthenticatorCallbackTest_OnAccountsChanged_0100");

    sptr<IAppAccountEvent> eventCallbackPtr = new (std::nothrow) MockAppAccountEventStub();
    ASSERT_NE(eventCallbackPtr, nullptr);
    sptr<IRemoteObject> callback = eventCallbackPtr->AsObject();
    AppAccountEventProxy testCallbackProxy(callback);
    std::vector<AppAccountInfo> accounts;
    testCallbackProxy.OnAccountsChanged(accounts, "");
    EXPECT_EQ(g_status, true);
    g_status = false;
}

/**
 * @tc.name: AppAccountEventTest_OnRemoteRequest_0100
 * @tc.desc: test event stub func OnRemoteRequest with invalid parcel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountEventModuleTest, AppAccountEventTest_OnRemoteRequest_0100, TestSize.Level1)
{
    auto appAccountEventStubPtr = std::make_shared<MockAppAccountEventStub>();
    ASSERT_NE(appAccountEventStubPtr, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = appAccountEventStubPtr->OnRemoteRequest(INVALID_CODE, data, reply, option);
    EXPECT_EQ(result, ERR_TRANSACTION_FAILED);
}

/**
 * @tc.name: AppAccountEventTest_OnAccountsChanged_0200
 * @tc.desc: test event stub func OnAccountsChanged with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountEventModuleTest, AppAccountEventTest_OnAccountsChanged_0200, TestSize.Level1)
{
    auto appAccountEventStubPtr = std::make_shared<MockAppAccountEventStub>();
    ASSERT_NE(appAccountEventStubPtr, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountEventStub::GetDescriptor()), true);
    EXPECT_EQ(appAccountEventStubPtr->OnRemoteRequest(INVALID_CODE, data, reply, option),
        IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: AppAccountEventTest_OnAccountsChanged_0300
 * @tc.desc: test event stub func OnAccountsChanged success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountEventModuleTest, AppAccountEventTest_OnAccountsChanged_0300, TestSize.Level1)
{
    auto appAccountEventStubPtr = std::make_shared<MockAppAccountEventStub>();
    ASSERT_NE(appAccountEventStubPtr, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountEventStub::GetDescriptor()), true);
    std::vector<AppAccountInfo> accounts;
    AppAccountInfo testAppAccountInfo;
    accounts.emplace_back(testAppAccountInfo);
    data.WriteUint32(accounts.size());
    for (const auto &parcelable : accounts) {
        bool result = data.WriteParcelable(&parcelable);
        ASSERT_EQ(result, true);
    }
    EXPECT_EQ(appAccountEventStubPtr->OnRemoteRequest(static_cast<uint32_t>(
        IAppAccountEventIpcCode::COMMAND_ON_ACCOUNTS_CHANGED), data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountEventTest_OnAccountsChanged_0300
 * @tc.desc: test event stub func OnAccountsChanged success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountEventModuleTest, AppAccountEventTest_OnAccountsChanged_0400, TestSize.Level3)
{
    AppAccountEventListener *appAccountEventListener = AppAccountEventListener::GetInstance();
    std::vector<AppAccountInfo> accounts(static_cast<int32_t>(Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT) + 1);
    EXPECT_EQ(appAccountEventListener->OnAccountsChanged(accounts, ""), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
}

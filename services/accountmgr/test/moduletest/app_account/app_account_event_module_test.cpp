/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
    void OnAccountsChanged(const std::vector<AppAccountInfo> &accounts)
    {
        g_status = true;
        return;
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

void AppAccountEventModuleTest::SetUp(void)
{}

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
    testCallbackProxy.OnAccountsChanged(accounts);
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
    ASSERT_EQ(result, ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR);
}

/**
 * @tc.name: AppAccountEventTest_ReadParcelableVector_0100
 * @tc.desc: test event stub func ReadParcelableVector with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountEventModuleTest, AppAccountEventTest_ReadParcelableVector_0100, TestSize.Level1)
{
    auto appAccountEventStubPtr = std::make_shared<MockAppAccountEventStub>();
    ASSERT_NE(appAccountEventStubPtr, nullptr);
    MessageParcel data;
    std::vector<AppAccountInfo> accounts;
    bool result = appAccountEventStubPtr->ReadParcelableVector(accounts, data);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: AppAccountEventTest_ReadParcelableVector_0200
 * @tc.desc: test event stub func ReadParcelableVector with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountEventModuleTest, AppAccountEventTest_ReadParcelableVector_0200, TestSize.Level1)
{
    auto appAccountEventStubPtr = std::make_shared<MockAppAccountEventStub>();
    ASSERT_NE(appAccountEventStubPtr, nullptr);
    MessageParcel data;
    data.WriteUint32(INVALID_CODE);
    std::vector<AppAccountInfo> accounts;
    bool result = appAccountEventStubPtr->ReadParcelableVector(accounts, data);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: AppAccountEventTest_ReadParcelableVector_0300
 * @tc.desc: test event stub func ReadParcelableVector success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountEventModuleTest, AppAccountEventTest_ReadParcelableVector_0300, TestSize.Level1)
{
    auto appAccountEventStubPtr = std::make_shared<MockAppAccountEventStub>();
    ASSERT_NE(appAccountEventStubPtr, nullptr);
    MessageParcel data;
    std::vector<AppAccountInfo> accounts;
    AppAccountInfo testAppAccountInfo;
    accounts.emplace_back(testAppAccountInfo);
    data.WriteUint32(accounts.size());
    for (const auto &parcelable : accounts) {
        bool result = data.WriteParcelable(&parcelable);
        ASSERT_EQ(result, true);
    }
    bool result = appAccountEventStubPtr->ReadParcelableVector(accounts, data);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: AppAccountEventTest_GetEventHandler_0100
 * @tc.desc: test AppAccountCommonEventObserver func GetEventHandler handler is exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountEventModuleTest, AppAccountEventTest_GetEventHandler_0100, TestSize.Level1)
{
    CommonEventCallback callback;
    auto appAccountCommonEventObserverPtr = std::make_shared<AppAccountCommonEventObserver>(callback);
    ASSERT_NE(appAccountCommonEventObserverPtr, nullptr);
    appAccountCommonEventObserverPtr->handler_ =
        std::make_shared<OHOS::AppExecFwk::EventHandler>(OHOS::AppExecFwk::EventRunner::Create());
    ASSERT_NE(appAccountCommonEventObserverPtr->handler_, nullptr);
    ErrCode result = appAccountCommonEventObserverPtr->GetEventHandler();
    ASSERT_EQ(result, ERR_OK);
}
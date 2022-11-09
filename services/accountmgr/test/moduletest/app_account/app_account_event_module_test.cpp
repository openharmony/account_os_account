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
#include "app_account_event_stub.h"
#include "app_account_event_proxy.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

bool g_status = false;

class MockAppAccountEventStubStub : public AppAccountEventStub {
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

    sptr<IAppAccountEvent> eventCallbackPtr = new (std::nothrow) MockAppAccountEventStubStub();
    ASSERT_NE(eventCallbackPtr, nullptr);
    sptr<IRemoteObject> callback = eventCallbackPtr->AsObject();
    AppAccountEventProxy testCallbackProxy(callback);
    std::vector<AppAccountInfo> accounts;
    testCallbackProxy.OnAccountsChanged(accounts);
    EXPECT_EQ(g_status, true);
    g_status = false;
}
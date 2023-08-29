/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <cerrno>
#include <gtest/gtest.h>
#include <thread>
#include "account_log_wrapper.h"
#define private public
#include "app_account_manager_service.h"
#include "app_account_stub.h"
#undef private
#include "parcel.h"
#include "want.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IAppAccount");

namespace {
const int32_t LIMIT_CODE = 43;
const int32_t CLEAR_OAUTH_TOKEN = 29;
const int32_t SUBSCRIBE_ACCOUNT = 33;
const int32_t UNSUBSCRIBE_ACCOUNT = 34;
const int32_t SLEEP_TIME = 2000;
} // namespace

class AppAccountStubModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    sptr<AppAccountManagerService> appAccountService_ = nullptr;
};

void AppAccountStubModuleTest::SetUpTestCase(void)
{}

void AppAccountStubModuleTest::TearDownTestCase(void)
{}

void AppAccountStubModuleTest::SetUp(void)
{
    appAccountService_ = new (std::nothrow) AppAccountManagerService();
    ASSERT_NE(appAccountService_, nullptr);
}

void AppAccountStubModuleTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountStubModuleTest_OnRemoteRequest_001
 * @tc.desc: OnRemoteRequest with invalid code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_OnRemoteRequest_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    EXPECT_NE(appAccountService_->OnRemoteRequest(-1, data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_OnRemoteRequest_002
 * @tc.desc: OnRemoteRequest with no interface token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_OnRemoteRequest_002, TestSize.Level0)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_NE(appAccountService_->OnRemoteRequest(-1, data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_OnRemoteRequest_003
 * @tc.desc: OnRemoteRequest success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_OnRemoteRequest_003, TestSize.Level0)
{
    for (int code = 0; code <= LIMIT_CODE; code++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
        data.WriteInterfaceToken(GetDescriptor());
        if ((code == CLEAR_OAUTH_TOKEN) || (code == SUBSCRIBE_ACCOUNT) || (code == UNSUBSCRIBE_ACCOUNT)) {
            EXPECT_NE(appAccountService_->OnRemoteRequest(
                static_cast<uint32_t>(static_cast<uint32_t>(code)), data, reply, option), ERR_NONE);
        } else {
            EXPECT_EQ(appAccountService_->OnRemoteRequest(
                static_cast<uint32_t>(static_cast<uint32_t>(code)), data, reply, option), ERR_NONE);
        }
    }
}
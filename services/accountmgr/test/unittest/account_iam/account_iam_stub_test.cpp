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
#include "accesstoken_kit.h"
#include "account_log_wrapper.h"
#define private public
#include "account_iam_mgr_stub.h"
#include "account_iam_service.h"
#undef private
#include "token_setproc.h"
#include "parcel.h"
#include "want.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IAccountIAM");
const int32_t LIMIT_CODE = 13;
} // namespace

class AccountIAMStubModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    sptr<AccountIAMService> service_ = nullptr;
};

void AccountIAMStubModuleTest::SetUpTestCase(void)
{
    OHOS::Security::AccessToken::AccessTokenID tokenId =
        OHOS::Security::AccessToken::AccessTokenKit::GetNativeTokenId("accountmgr");
    SetSelfTokenID(tokenId);
}

void AccountIAMStubModuleTest::TearDownTestCase(void)
{}

void AccountIAMStubModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    service_ = new (std::nothrow) AccountIAMService();
    ASSERT_NE(service_, nullptr);
}

void AccountIAMStubModuleTest::TearDown(void)
{}

/**
 * @tc.name: AccountIAMStubModuleTest_OnRemoteRequest_001
 * @tc.desc: OnRemoteRequest with invalid code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMStubModuleTest, AccountIAMStubModuleTest_OnRemoteRequest_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    EXPECT_NE(service_->OnRemoteRequest(-1, data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AccountIAMStubModuleTest_OnRemoteRequest_002
 * @tc.desc: OnRemoteRequest with not InterfaceToken.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMStubModuleTest, AccountIAMStubModuleTest_OnRemoteRequest_002, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_NE(service_->OnRemoteRequest(-1, data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AccountIAMStubModuleTest_OnRemoteRequest_003
 * @tc.desc: OnRemoteRequest with invalid code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMStubModuleTest, AccountIAMStubModuleTest_OnRemoteRequest_003, TestSize.Level0)
{
    for (int code = 0; code <= LIMIT_CODE; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
        data.WriteInterfaceToken(GetDescriptor());
        EXPECT_NE(service_->OnRemoteRequest(static_cast<uint32_t>(static_cast<uint32_t>(code)), data, reply, option),
            ERR_NONE);
    }
}
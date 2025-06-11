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
#include "account_log_wrapper.h"
#define private public
#include "domain_account_callback_service.h"
#include "domain_account_plugin_service.h"
#include "domain_account_plugin_stub.h"
#undef private
#include "parcel.h"
#include "want.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.AccountSA.IDomainAccountPlugin");

namespace {
} // namespace

class DomainPluginStubModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    sptr<DomainAccountPluginService> pluginServie_ = nullptr;
};

void DomainPluginStubModuleTest::SetUpTestCase(void)
{}

void DomainPluginStubModuleTest::TearDownTestCase(void)
{}

void DomainPluginStubModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    pluginServie_ = new (std::nothrow) DomainAccountPluginService(nullptr);
    ASSERT_NE(pluginServie_, nullptr);
}

void DomainPluginStubModuleTest::TearDown(void)
{}

/**
 * @tc.name: DomainPluginStubModuleTest_OnRemoteRequest_001
 * @tc.desc: OnRemoteRequest with invalid code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginStubModuleTest, DomainPluginStubModuleTest_OnRemoteRequest_001, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    EXPECT_NE(pluginServie_->OnRemoteRequest(-1, data, reply, option), ERR_NONE);
}
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

DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IDomainAccountPlugin");

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
HWTEST_F(DomainPluginStubModuleTest, DomainPluginStubModuleTest_OnRemoteRequest_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    EXPECT_NE(pluginServie_->OnRemoteRequest(-1, data, reply, option), ERR_NONE);
}

/**
 * @tc.name: DomainPluginStubModuleTest_ProcAuthCommonInterface_001
 * @tc.desc: ProcAuthCommonInterface with invalid info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginStubModuleTest, DomainPluginStubModuleTest_ProcAuthCommonInterface_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(GetDescriptor());
    EXPECT_EQ(pluginServie_->ProcAuthCommonInterface(data, reply), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
}

/**
 * @tc.name: DomainPluginStubModuleTest_ProcAuthCommonInterface_002
 * @tc.desc: ProcAuthCommonInterface with AUTH_WITH_TOKEN_MODE.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginStubModuleTest, DomainPluginStubModuleTest_ProcAuthCommonInterface_002, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    DomainAccountInfo info;
    info.accountName_ = "test";
    info.domain_ = "china";
    EXPECT_EQ(data.WriteParcelable(&info), true);
    std::vector<uint8_t> authData;
    EXPECT_EQ(data.WriteUInt8Vector(authData), true);
    std::shared_ptr<DomainAccountCallback> callback = nullptr;
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    ASSERT_NE(callbackService, nullptr);
    EXPECT_EQ(data.WriteRemoteObject(callbackService->AsObject()), true);
    EXPECT_EQ(data.WriteInt32(AUTH_WITH_TOKEN_MODE), true);
    EXPECT_EQ(pluginServie_->ProcAuthCommonInterface(data, reply), ERR_NONE);
}

/**
 * @tc.name: DomainPluginStubModuleTest_ProcGetAuthStatusInfo_001
 * @tc.desc: ProcGetAuthStatusInfo success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginStubModuleTest, DomainPluginStubModuleTest_ProcGetAuthStatusInfo_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    DomainAccountInfo info;
    info.accountName_ = "test";
    info.domain_ = "china";
    EXPECT_EQ(data.WriteParcelable(&info), true);
    std::shared_ptr<DomainAccountCallback> callback = nullptr;
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    ASSERT_NE(callbackService, nullptr);
    EXPECT_EQ(data.WriteRemoteObject(callbackService->AsObject()), true);
    EXPECT_EQ(pluginServie_->ProcGetAuthStatusInfo(data, reply), ERR_NONE);
    int32_t result = -1;
    EXPECT_EQ(reply.WriteInt32(result), true);
}

/**
 * @tc.name: DomainPluginStubModuleTest_ProcGetAuthStatusInfo_002
 * @tc.desc: ProcGetAuthStatusInfo with invalid info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginStubModuleTest, DomainPluginStubModuleTest_ProcGetAuthStatusInfo_002, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    DomainAccountInfo info;
    std::vector<uint8_t> authData;
    EXPECT_EQ(data.WriteUInt8Vector(authData), true);
    EXPECT_EQ(pluginServie_->ProcGetAuthStatusInfo(data, reply), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
}

/**
 * @tc.name: DomainPluginStubModuleTest_ProcIsAccountTokenValid_001
 * @tc.desc: ProcIsAccountTokenValid with invalid info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginStubModuleTest, DomainPluginStubModuleTest_ProcIsAccountTokenValid_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    std::vector<uint8_t> authData;
    EXPECT_EQ(data.WriteUInt8Vector(authData), true);
    EXPECT_EQ(pluginServie_->ProcIsAccountTokenValid(data, reply), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
}

/**
 * @tc.name: DomainPluginStubModuleTest_ProcIsAccountTokenValid_002
 * @tc.desc: ProcGetAccessToken with invalid info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginStubModuleTest, DomainPluginStubModuleTest_ProcGetAccessToken_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    std::vector<uint8_t> authData;
    EXPECT_EQ(data.WriteUInt8Vector(authData), true);
    EXPECT_EQ(pluginServie_->ProcGetAccessToken(data, reply), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
}

/**
 * @tc.name: DomainPluginStubModuleTest_ProcGetAccessToken_001
 * @tc.desc: ProcGetAccessToken with invalid GetAccessTokenOptions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginStubModuleTest, DomainPluginStubModuleTest_ProcGetAccessToken_002, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    DomainAccountInfo info;
    info.accountName_ = "test";
    info.domain_ = "china";
    EXPECT_EQ(data.WriteParcelable(&info), true);
    std::vector<uint8_t> authData;
    EXPECT_EQ(data.WriteUInt8Vector(authData), true);
    std::string name = "test";
    EXPECT_EQ(data.WriteString(name), true);
    EXPECT_EQ(pluginServie_->ProcIsAccountTokenValid(data, reply), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
}

/**
 * @tc.name: DomainPluginStubModuleTest_ProcOnAccountBound_001
 * @tc.desc: ProcOnAccountBound with invalid info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginStubModuleTest, DomainPluginStubModuleTest_ProcOnAccountBound_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    std::vector<uint8_t> authData;
    EXPECT_EQ(data.WriteUInt8Vector(authData), true);
    EXPECT_EQ(pluginServie_->ProcOnAccountBound(data, reply), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
}
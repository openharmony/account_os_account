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
#include "domain_account_plugin_proxy.h"
#include "domain_account_plugin_service.h"
#include "domain_account_callback_service.h"
#include "domain_has_domain_info_callback.h"
#undef private
#include "parcel.h"
#include "want.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
} // namespace

class DomainAccountPluginProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    sptr<DomainAccountPluginProxy> pluginProxy_ = nullptr;
};

void DomainAccountPluginProxyTest::SetUpTestCase(void)
{}

void DomainAccountPluginProxyTest::TearDownTestCase(void)
{}

void DomainAccountPluginProxyTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    sptr<DomainAccountPluginService> pluginServie_ = new (std::nothrow) DomainAccountPluginService(nullptr);
    ASSERT_NE(pluginServie_, nullptr);
    pluginProxy_ = new (std::nothrow) DomainAccountPluginProxy(pluginServie_);
    ASSERT_NE(pluginProxy_, nullptr);
}

void DomainAccountPluginProxyTest::TearDown(void)
{}

/**
 * @tc.name: DomainAccountPluginProxyTest_AuthCommonInterface_001
 * @tc.desc: AuthCommonInterface callback is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountPluginProxyTest, DomainAccountPluginProxyTest_AuthCommonInterface_001, TestSize.Level0)
{
    DomainAccountInfo info;
    std::vector<uint8_t> authData;
    EXPECT_EQ(pluginProxy_->AuthCommonInterface(info, authData, nullptr, AUTH_WITH_TOKEN_MODE),
        ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
}

/**
 * @tc.name: DomainAccountPluginProxyTest_IsAccountTokenValid_001
 * @tc.desc: IsAccountTokenValid callback is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountPluginProxyTest, DomainAccountPluginProxyTest_IsAccountTokenValid_001, TestSize.Level0)
{
    DomainAccountInfo info;
    std::vector<uint8_t> authData;
    EXPECT_EQ(pluginProxy_->IsAccountTokenValid(info, authData, nullptr), ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
}

/**
 * @tc.name: DomainAccountPluginProxyTest_GetAccessToken_001
 * @tc.desc: GetAccessToken callback is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountPluginProxyTest, DomainAccountPluginProxyTest_GetAccessToken_001, TestSize.Level0)
{
    DomainAccountInfo info;
    std::vector<uint8_t> authData;
    GetAccessTokenOptions option;
    EXPECT_EQ(pluginProxy_->GetAccessToken(info, authData, option, nullptr), ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
}

/**
 * @tc.name: DomainAccountPluginProxyTest_GetAuthStatusInfo_001
 * @tc.desc: GetAuthStatusInfo callback is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountPluginProxyTest, DomainAccountPluginProxyTest_GetAuthStatusInfo_001, TestSize.Level0)
{
    DomainAccountInfo info;
    EXPECT_EQ(pluginProxy_->GetAuthStatusInfo(info, nullptr), ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
}

/**
 * @tc.name: DomainAccountPluginProxyTest_GetAuthStatusInfo_002
 * @tc.desc: GetAuthStatusInfo success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountPluginProxyTest, DomainAccountPluginProxyTest_GetAuthStatusInfo_002, TestSize.Level0)
{
    DomainAccountInfo info;
    std::shared_ptr<DomainAccountCallback> callback = nullptr;
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    EXPECT_NE(callbackService, nullptr);
    EXPECT_NE(pluginProxy_->GetAuthStatusInfo(info, callbackService), ERR_OK);
}

/**
 * @tc.name: DomainAccountPluginProxyTest_AuthWithToken_001
 * @tc.desc: GetAuthStatusInfo callback is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountPluginProxyTest, DomainAccountPluginProxyTest_AuthWithToken_001, TestSize.Level0)
{
    DomainAccountInfo info;
    std::vector<uint8_t> token;
    EXPECT_EQ(pluginProxy_->AuthWithToken(info, token, nullptr), ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
}

/**
 * @tc.name: DomainAccountPluginProxyTest_AuthWithToken_002
 * @tc.desc: GetAuthStatusInfo success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountPluginProxyTest, DomainAccountPluginProxyTest_AuthWithToken_002, TestSize.Level0)
{
    DomainAccountInfo info;
    std::shared_ptr<DomainAccountCallback> callback = nullptr;
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    EXPECT_NE(callbackService, nullptr);
    std::vector<uint8_t> token;
    EXPECT_NE(pluginProxy_->AuthWithToken(info, token, callbackService), ERR_OK);
}

/**
 * @tc.name: DomainAccountPluginProxyTest_GetDomainAccountInfo_001
 * @tc.desc: GetDomainAccountInfo callback is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountPluginProxyTest, DomainAccountPluginProxyTest_GetDomainAccountInfo_001, TestSize.Level0)
{
    GetDomainAccountInfoOptions options;
    EXPECT_EQ(pluginProxy_->GetDomainAccountInfo(options, nullptr), ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
}

/**
 * @tc.name: DomainAccountPluginProxyTest_OnAccountBound_001
 * @tc.desc: OnAccountBound callback is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountPluginProxyTest, DomainAccountPluginProxyTest_OnAccountBound_001, TestSize.Level0)
{
    DomainAccountInfo info;
    EXPECT_EQ(pluginProxy_->OnAccountBound(info, 0, nullptr), ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
}

/**
 * @tc.name: DomainAccountPluginProxyTest_OnAccountUnBound_001
 * @tc.desc: OnAccountUnBound callback is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountPluginProxyTest, DomainAccountPluginProxyTest_OnAccountUnBound_001, TestSize.Level0)
{
    DomainAccountInfo info;
    EXPECT_EQ(pluginProxy_->OnAccountUnBound(info, nullptr), ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
}

/**
 * @tc.name: DomainAccountPluginProxyTest_DomainHasDomainInfoCallback_001
 * @tc.desc: OnResult callback is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountPluginProxyTest, DomainAccountPluginProxyTest_DomainHasDomainInfoCallback_001, TestSize.Level0)
{
    auto callbackWrapper = std::make_shared<DomainHasDomainInfoCallback>(nullptr, "test", "name");
    Parcel parcel;
    callbackWrapper->OnResult(0, parcel);
    EXPECT_EQ(callbackWrapper->innerCallback_, nullptr);
}

/**
 * @tc.name: DomainAccountPluginProxyTest_DomainHasDomainInfoCallback_002
 * @tc.desc: OnResult parcel is enpty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountPluginProxyTest, DomainAccountPluginProxyTest_DomainHasDomainInfoCallback_002, TestSize.Level0)
{
    std::shared_ptr<DomainAccountCallback> callback = nullptr;
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    EXPECT_NE(callbackService, nullptr);
    auto callbackWrapper = std::make_shared<DomainHasDomainInfoCallback>(callbackService, "test", "name");
    Parcel parcel;
    int32_t result = 0;
    EXPECT_EQ(parcel.WriteInt32(result), true);
    callbackWrapper->OnResult(0, parcel);
    EXPECT_NE(callbackWrapper->innerCallback_, nullptr);
}

/**
 * @tc.name: DomainAccountPluginProxyTest_DomainHasDomainInfoCallback_003
 * @tc.desc: OnResult domian is invalid and accountName is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountPluginProxyTest, DomainAccountPluginProxyTest_DomainHasDomainInfoCallback_003, TestSize.Level0)
{
    std::shared_ptr<DomainAccountCallback> callback = nullptr;
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    EXPECT_NE(callbackService, nullptr);
    auto callbackWrapper = std::make_shared<DomainHasDomainInfoCallback>(callbackService, "test", "test");
    Parcel parcel;
    DomainAccountInfo info1("111", "test");
    EXPECT_EQ(info1.Marshalling(parcel), true);
    callbackWrapper->OnResult(0, parcel);
    EXPECT_NE(callbackWrapper->innerCallback_, nullptr);
    Parcel parcel2;
    DomainAccountInfo info2("test", "111");
    EXPECT_EQ(info2.Marshalling(parcel2), true);
    callbackWrapper->OnResult(0, parcel2);
    EXPECT_NE(callbackWrapper->innerCallback_, nullptr);
}
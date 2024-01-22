/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#undef private
#include "mock_domain_plugin.h"
#include "want.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
std::shared_ptr<MockDomainPlugin> g_plugin = std::make_shared<MockDomainPlugin>();
} // namespace

class DomainPluginServiceModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    sptr<DomainAccountPluginService> pluginServie_ = nullptr;
};

void DomainPluginServiceModuleTest::SetUpTestCase(void)
{}

void DomainPluginServiceModuleTest::TearDownTestCase(void)
{}

void DomainPluginServiceModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
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

void DomainPluginServiceModuleTest::TearDown(void)
{}

/**
 * @tc.name: DomainPluginStubModuleTest_OnRemoteRequest_001
 * @tc.desc: AuthCommonInterface with innerPlugin is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginServiceModuleTest, DomainPluginServiceModuleTest_AuthCommonInterface_001, TestSize.Level0)
{
    DomainAccountInfo info;
    std::vector<uint8_t> authData;
    EXPECT_EQ(pluginServie_->AuthCommonInterface(info, authData, nullptr, AUTH_WITH_TOKEN_MODE),
        ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: DomainPluginStubModuleTest_OnRemoteRequest_002
 * @tc.desc: AuthCommonInterface success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginServiceModuleTest, DomainPluginServiceModuleTest_AuthCommonInterface_002, TestSize.Level0)
{
    DomainAccountInfo info;
    std::vector<uint8_t> authData;
    sptr<DomainAccountPluginService> pluginServie = new (std::nothrow) DomainAccountPluginService(g_plugin);
    ASSERT_NE(pluginServie, nullptr);
    EXPECT_EQ(pluginServie->AuthCommonInterface(info, authData, nullptr, AUTH_WITH_TOKEN_MODE), ERR_OK);
}

/**
 * @tc.name: DomainPluginStubModuleTest_OnRemoteRequest_003
 * @tc.desc: AuthCommonInterface with invalid mode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginServiceModuleTest, DomainPluginServiceModuleTest_AuthCommonInterface_003, TestSize.Level0)
{
    DomainAccountInfo info;
    std::vector<uint8_t> authData;
    sptr<DomainAccountPluginService> pluginServie = new (std::nothrow) DomainAccountPluginService(g_plugin);
    ASSERT_NE(pluginServie, nullptr);
    EXPECT_EQ(pluginServie->AuthCommonInterface(info, authData, nullptr, AUTH_MODE_END),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: DomainPluginStubModuleTest_IsAccountTokenValid_001
 * @tc.desc: AuthCommonInterface with innerPlugin nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginServiceModuleTest, DomainPluginStubModuleTest_IsAccountTokenValid_001, TestSize.Level0)
{
    DomainAccountInfo info;
    std::vector<uint8_t> authData;
    EXPECT_EQ(pluginServie_->IsAccountTokenValid(info, authData, nullptr), ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: DomainPluginStubModuleTest_GetAccessToken_001
 * @tc.desc: GetAccessToken with innerPlugin nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginServiceModuleTest, DomainPluginStubModuleTest_GetAccessToken_001, TestSize.Level0)
{
    DomainAccountInfo info;
    std::vector<uint8_t> authData;
    GetAccessTokenOptions option;
    EXPECT_EQ(pluginServie_->GetAccessToken(info, authData, option, nullptr), ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: DomainPluginStubModuleTest_GetAuthStatusInfo_001
 * @tc.desc: GetAccessToken with innerPlugin nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginServiceModuleTest, DomainPluginStubModuleTest_GetAuthStatusInfo_001, TestSize.Level0)
{
    DomainAccountInfo info;
    EXPECT_EQ(pluginServie_->GetAuthStatusInfo(info, nullptr), ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: DomainPluginStubModuleTest_GetAuthStatusInfo_002
 * @tc.desc: AuthCommonInterface success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginServiceModuleTest, DomainPluginStubModuleTest_GetAuthStatusInfo_002, TestSize.Level0)
{
    DomainAccountInfo info;
    sptr<DomainAccountPluginService> pluginServie = new (std::nothrow) DomainAccountPluginService(g_plugin);
    ASSERT_NE(pluginServie, nullptr);
    EXPECT_EQ(pluginServie->GetAuthStatusInfo(info, nullptr), ERR_OK);
}

/**
 * @tc.name: DomainPluginStubModuleTest_GetDomainAccountInfo_001
 * @tc.desc: GetDomainAccountInfo with innerPlugin nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginServiceModuleTest, DomainPluginStubModuleTest_GetDomainAccountInfo_001, TestSize.Level0)
{
    GetDomainAccountInfoOptions options;
    EXPECT_EQ(pluginServie_->GetDomainAccountInfo(options, nullptr), ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: DomainPluginStubModuleTest_OnAccountBound_001
 * @tc.desc: OnAccountBound with innerPlugin nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginServiceModuleTest, DomainPluginStubModuleTest_OnAccountBound_001, TestSize.Level0)
{
    DomainAccountInfo info;
    EXPECT_EQ(pluginServie_->OnAccountBound(info, 0, nullptr), ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: DomainPluginStubModuleTest_OnAccountUnBound_001
 * @tc.desc: OnAccountUnBound with innerPlugin nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainPluginServiceModuleTest, DomainPluginStubModuleTest_OnAccountUnBound_001, TestSize.Level0)
{
    DomainAccountInfo info;
    EXPECT_EQ(pluginServie_->OnAccountUnBound(info, nullptr), ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}
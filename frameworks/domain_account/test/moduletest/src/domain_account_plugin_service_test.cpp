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
#include "domain_account_common.h"
#define private public
#include "domain_account_plugin_service.h"
#undef private
#include "mock_domain_plugin.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
std::shared_ptr<MockDomainPlugin> g_plugin = std::make_shared<MockDomainPlugin>();
} // namespace

class DomainAccountPluginServiceModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DomainAccountPluginServiceModuleTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "SetUpTestCase enter";
}

void DomainAccountPluginServiceModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase";
}

void DomainAccountPluginServiceModuleTest::SetUp(void)
{}

void DomainAccountPluginServiceModuleTest::TearDown(void)
{}

/**
 * @tc.name: DomainAccountPluginServiceModuleTest_CheckAndInitExecEnv_001
 * @tc.desc: CheckAndInitExecEnv innerPlugin is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(
    DomainAccountPluginServiceModuleTest, DomainAccountPluginServiceModuleTest_CheckAndInitExecEnv_001, TestSize.Level0)
{
    auto pluginService = std::make_shared<DomainAccountPluginService>(nullptr);
    DomainAccountCallbackClient *callbackClient = nullptr;
    ErrCode result = pluginService->CheckAndInitExecEnv(nullptr, &callbackClient);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: DomainAccountPluginServiceModuleTest_AuthCommonInterface_001
 * @tc.desc: AuthCommonInterface innerPlugin is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(
    DomainAccountPluginServiceModuleTest, DomainAccountPluginServiceModuleTest_AuthCommonInterface_001, TestSize.Level0)
{
    auto pluginService = std::make_shared<DomainAccountPluginService>(nullptr);
    DomainAccountInfo info;
    std::vector<uint8_t> token;
    ErrCode result = pluginService->AuthCommonInterface(info, token, nullptr, AUTH_WITH_TOKEN_MODE);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: DomainAccountPluginServiceModuleTest_AuthCommonInterface_002
 * @tc.desc: AuthCommonInterface invalid mode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(
    DomainAccountPluginServiceModuleTest, DomainAccountPluginServiceModuleTest_AuthCommonInterface_002, TestSize.Level0)
{
    auto pluginService = std::make_shared<DomainAccountPluginService>(g_plugin);
    DomainAccountInfo info;
    std::vector<uint8_t> token;
    ErrCode result = pluginService->AuthCommonInterface(info, token, nullptr, AUTH_MODE_END);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: DomainAccountPluginServiceModuleTest_AuthWithToken_001
 * @tc.desc: AuthWithToken success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountPluginServiceModuleTest, DomainAccountPluginServiceModuleTest_AuthWithToken_001, TestSize.Level0)
{
    auto pluginService = std::make_shared<DomainAccountPluginService>(g_plugin);
    DomainAccountInfo info;
    std::vector<uint8_t> token;
    ErrCode result = pluginService->AuthWithToken(info, token, nullptr);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: DomainAccountPluginServiceModuleTest_GetAuthStatusInfo_001
 * @tc.desc: GetAuthStatusInfo success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(
    DomainAccountPluginServiceModuleTest, DomainAccountPluginServiceModuleTest_GetAuthStatusInfo_001, TestSize.Level0)
{
    auto pluginService = std::make_shared<DomainAccountPluginService>(g_plugin);
    DomainAccountInfo info;
    ErrCode result = pluginService->GetAuthStatusInfo(info, nullptr);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: DomainAccountPluginServiceModuleTest_GetAuthStatusInfo_002
 * @tc.desc: GetAuthStatusInfo success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(
    DomainAccountPluginServiceModuleTest, DomainAccountPluginServiceModuleTest_GetAuthStatusInfo_002, TestSize.Level0)
{
    auto pluginService = std::make_shared<DomainAccountPluginService>(nullptr);
    DomainAccountInfo info;
    ErrCode result = pluginService->GetAuthStatusInfo(info, nullptr);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}
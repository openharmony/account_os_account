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
#define private public
#include "bundle_manager_adapter.h"
#include "bundle_manager_adapter_proxy.h"
#undef private
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "system_ability.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

class BundleManagerModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    std::shared_ptr<BundleManagerAdapterProxy> g_bundleManagerAdapterProxyRemoteNull =
        std::make_shared<BundleManagerAdapterProxy>(nullptr);
};

namespace {
const std::string EMPTY_BUNDLE_NAME = "";
const std::string INVALID_BUNDLE_NAME = "testbundlename";
const std::string BUNDLE_NAME = "com.ohos.launcher";
const int32_t FLAGS = 1;
const int32_t USER_ID = 1;
} // namespace

void BundleManagerModuleTest::SetUpTestCase(void)
{}

void BundleManagerModuleTest::TearDownTestCase(void)
{}

void BundleManagerModuleTest::SetUp(void)
{}

void BundleManagerModuleTest::TearDown(void)
{}

/**
 * @tc.name: BundleManagerProxy_GetBundleInfo_0100
 * @tc.desc: test func failed with remote is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerProxy_GetBundleInfo_0100, TestSize.Level1)
{
    ASSERT_NE(g_bundleManagerAdapterProxyRemoteNull, nullptr);
    BundleInfo bundleInfo;
    bool result = g_bundleManagerAdapterProxyRemoteNull->GetBundleInfo(
        INVALID_BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, USER_ID);
    ASSERT_EQ(result, false);

    Want want;
    std::vector<AbilityInfo> abilityInfos;
    result = g_bundleManagerAdapterProxyRemoteNull->QueryAbilityInfos(want, FLAGS, USER_ID, abilityInfos);
    ASSERT_EQ(result, false);

    std::vector<ExtensionAbilityInfo> extensionInfos;
    result = g_bundleManagerAdapterProxyRemoteNull->QueryExtensionAbilityInfos(want, FLAGS, USER_ID, extensionInfos);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: BundleManagerProxy_GetBundleInfo_0200
 * @tc.desc: test GetBundleInfo param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerProxy_GetBundleInfo_0200, TestSize.Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    sptr<IRemoteObject> remoteObj = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    ASSERT_NE(remoteObj, nullptr);
    auto bundleManagerAdapterProxy = std::make_shared<BundleManagerAdapterProxy>(remoteObj);
    ASSERT_NE(bundleManagerAdapterProxy, nullptr);

    BundleInfo bundleInfo;
    bool result = bundleManagerAdapterProxy->GetBundleInfo(
        INVALID_BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, USER_ID);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: BundleManagerProxy_GetBundleInfo_0300
 * @tc.desc: test GetBundleInfo param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerProxy_GetBundleInfo_0300, TestSize.Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    sptr<IRemoteObject> remoteObj = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    ASSERT_NE(remoteObj, nullptr);
    auto bundleManagerAdapterProxy = std::make_shared<BundleManagerAdapterProxy>(remoteObj);
    ASSERT_NE(bundleManagerAdapterProxy, nullptr);

    BundleInfo bundleInfo;
    bool result = bundleManagerAdapterProxy->GetBundleInfo(
        EMPTY_BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, USER_ID);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: BundleManagerProxy_GetUidByBundleName_0100
 * @tc.desc: test GetUidByBundleName failed with bundlename is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerProxy_GetUidByBundleName_0100, TestSize.Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    sptr<IRemoteObject> remoteObj = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    ASSERT_NE(remoteObj, nullptr);
    auto bundleManagerAdapterProxy = std::make_shared<BundleManagerAdapterProxy>(remoteObj);
    ASSERT_NE(bundleManagerAdapterProxy, nullptr);

    int32_t result = bundleManagerAdapterProxy->GetUidByBundleName(EMPTY_BUNDLE_NAME, USER_ID);
    ASSERT_EQ(result, AppExecFwk::Constants::INVALID_UID);
}

/**
 * @tc.name: BundleManagerProxy_QueryAbilityInfos_0200
 * @tc.desc: test QueryAbilityInfos failed with param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerProxy_QueryAbilityInfos_0200, TestSize.Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    sptr<IRemoteObject> remoteObj = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    ASSERT_NE(remoteObj, nullptr);
    auto bundleManagerAdapterProxy = std::make_shared<BundleManagerAdapterProxy>(remoteObj);
    ASSERT_NE(bundleManagerAdapterProxy, nullptr);

    Want want;
    std::vector<AbilityInfo> abilityInfos;
    bool result = bundleManagerAdapterProxy->QueryAbilityInfos(want, FLAGS, USER_ID, abilityInfos);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: BundleManagerProxy_QueryExtensionAbilityInfos_0200
 * @tc.desc: test QueryExtensionAbilityInfos failed with param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerProxy_QueryExtensionAbilityInfos_0200, TestSize.Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    sptr<IRemoteObject> remoteObj = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    ASSERT_NE(remoteObj, nullptr);
    auto bundleManagerAdapterProxy = std::make_shared<BundleManagerAdapterProxy>(remoteObj);
    ASSERT_NE(bundleManagerAdapterProxy, nullptr);

    Want want;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool result = bundleManagerAdapterProxy->QueryExtensionAbilityInfos(want, FLAGS, USER_ID, extensionInfos);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: BundleManagerAdapter_GetBundleInfo_0100
 * @tc.desc: test GetBundleInfo failed with param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerAdapter_GetBundleInfo_0100, TestSize.Level1)
{
    BundleInfo bundleInfo;
    bool result = BundleManagerAdapter::GetInstance()->GetBundleInfo(
        BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, USER_ID);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: BundleManagerAdapter_QueryAbilityInfos_0100
 * @tc.desc: test QueryAbilityInfos failed with param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerAdapter_QueryAbilityInfos_0100, TestSize.Level1)
{
    Want want;
    std::vector<AbilityInfo> abilityInfos;
    bool result = BundleManagerAdapter::GetInstance()->QueryAbilityInfos(want, FLAGS, USER_ID, abilityInfos);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: BundleManagerAdapter_ResetProxy_0100
 * @tc.desc: test ResetProxy branch of remove proxy.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerAdapter_ResetProxy_0100, TestSize.Level1)
{
    auto bundleManagerAdapterSptr = BundleManagerAdapter::GetInstance();
    ErrCode result = bundleManagerAdapterSptr->Connect();
    ASSERT_EQ(result, ERR_OK);
    ASSERT_NE(bundleManagerAdapterSptr->proxy_, nullptr);
    auto sptr = bundleManagerAdapterSptr->proxy_->AsObject();
    ASSERT_NE(nullptr, sptr);
    bundleManagerAdapterSptr->ResetProxy(sptr);
    ASSERT_EQ(bundleManagerAdapterSptr->proxy_, nullptr);
}
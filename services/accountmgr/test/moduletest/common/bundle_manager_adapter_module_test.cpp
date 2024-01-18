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

#include "ashmem.h"
#include <gtest/gtest.h>
#include "nlohmann/json.hpp"
#include <sys/mman.h>

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
using Json = nlohmann::json;

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

void BundleManagerModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

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

/**
 * @tc.name: BundleManagerProxy_SendTransactCmd_0100
 * @tc.desc: test SendTransactCmd failed with param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerProxy_SendTransactCmd_0100, TestSize.Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    sptr<IRemoteObject> remoteObj = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    ASSERT_NE(remoteObj, nullptr);
    auto bundleManagerAdapterProxy = std::make_shared<BundleManagerAdapterProxy>(remoteObj);
    ASSERT_NE(bundleManagerAdapterProxy, nullptr);

    MessageParcel reply;
    MessageParcel data;
    EXPECT_EQ(bundleManagerAdapterProxy->SendTransactCmd(
        BundleMgrInterfaceCode::QUERY_ABILITY_INFOS_MUTI_PARAM, data, reply), false);
}

/**
 * @tc.name: BundleManagerProxy_SendData_0100
 * @tc.desc: test func SendData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerProxy_SendData_0100, TestSize.Level1)
{
    ASSERT_NE(g_bundleManagerAdapterProxyRemoteNull, nullptr);
    void *buffer = nullptr;

    bool result = g_bundleManagerAdapterProxyRemoteNull->SendData(buffer, 10, nullptr);
    EXPECT_EQ(result, false);

    result = g_bundleManagerAdapterProxyRemoteNull->SendData(buffer, 0, "test_data");
    EXPECT_EQ(result, false);

    // max value malloc failed
    result = g_bundleManagerAdapterProxyRemoteNull->SendData(buffer, -1, "test_data");
    EXPECT_EQ(result, false);

    result = g_bundleManagerAdapterProxyRemoteNull->SendData(buffer, 10, "test_data");
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: BundleManagerProxy_GetVectorFromParcelIntelligent_0100
 * @tc.desc: test GetVectorFromParcelIntelligent failed with param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerProxy_GetVectorFromParcelIntelligent_0100, TestSize.Level1)
{
    ASSERT_NE(g_bundleManagerAdapterProxyRemoteNull, nullptr);
    MessageParcel data;
    std::vector<AbilityInfo> abilityInfos;

    bool result =g_bundleManagerAdapterProxyRemoteNull->GetVectorFromParcelIntelligent<AbilityInfo>(
        BundleMgrInterfaceCode::QUERY_ABILITY_INFOS_MUTI_PARAM, data, abilityInfos);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: BundleManagerProxy_InnerGetVectorFromParcelIntelligent_0100
 * @tc.desc: test func failed with param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerProxy_InnerGetVectorFromParcelIntelligent_0100, TestSize.Level1)
{
    ASSERT_NE(g_bundleManagerAdapterProxyRemoteNull, nullptr);
    MessageParcel reply;
    std::vector<AbilityInfo> abilityInfos;

    bool result = g_bundleManagerAdapterProxyRemoteNull->InnerGetVectorFromParcelIntelligent<AbilityInfo>(
        reply, abilityInfos);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: BundleManagerAdapter_ParseStr_0100
 * @tc.desc: test ParseStr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerAdapter_ParseStr_0100, TestSize.Level1)
{
    // test buf is nullptr.
    int itemLen = 10;
    int index = 0;
    std::string result;
    EXPECT_EQ(g_bundleManagerAdapterProxyRemoteNull->ParseStr(nullptr, itemLen, index, result), false);

    // test itemLen is invalid.
    const char *buf = "test";
    itemLen = -1;
    EXPECT_EQ(g_bundleManagerAdapterProxyRemoteNull->ParseStr(buf, itemLen, index, result), false);

    // test index is invalid.
    itemLen = 10;
    index = -1;
    EXPECT_EQ(g_bundleManagerAdapterProxyRemoteNull->ParseStr(buf, itemLen, index, result), false);

    // test normal case.
    itemLen = 4;
    index = 0;
    EXPECT_EQ(g_bundleManagerAdapterProxyRemoteNull->ParseStr(buf, itemLen, index, result), true);
    EXPECT_EQ(result, "test");
}

/**
 * @tc.name: BundleManagerAdapter_ParseExtensionAbilityInfos_0100
 * @tc.desc: test ParseExtensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerAdapter_ParseExtensionAbilityInfos_0100, TestSize.Level1)
{
    ASSERT_NE(g_bundleManagerAdapterProxyRemoteNull, nullptr);

    std::vector<ExtensionAbilityInfo> extensionInfos;
    // test info with normal data.
    Json testBundleInfo = Json {
        {"name", "test_name"},
        {"label", "test_label"},
        {"description", "test_description"},
        {"type", 0},
        {"visible", true},
        {"uid", 123},
    };
    Json arrays[] = {
        testBundleInfo,
    };
    Json testBundleInfo1 = Json {
        {"extensionAbilityInfo", arrays},
    };
    EXPECT_EQ(g_bundleManagerAdapterProxyRemoteNull->ParseExtensionAbilityInfos(testBundleInfo1, extensionInfos), true);
}

/**
 * @tc.name: BundleManagerAdapter_ParseExtensionAbilityInfos_0200
 * @tc.desc: test invalid parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerAdapter_ParseExtensionAbilityInfos_0200, TestSize.Level1)
{
    ASSERT_NE(g_bundleManagerAdapterProxyRemoteNull, nullptr);

    std::vector<ExtensionAbilityInfo> extensionInfos;
    // invalid value
    Json testBundleInfo = Json {
        {"name", 1},
        {"label", 1},
        {"description", 1},
        {"type", "testtest"},
        {"visible", "test"},
        {"uid", "123"},
    };
    Json arrays1[] = {
        testBundleInfo,
    };
    // invalid JSON
    Json arrays2[] = {
        "invalidjsonobject",
    };
    Json testBundleInfo1 = Json {
        {"extensionAbilityInfo", arrays1},
    };
    Json testBundleInfo2 = Json {
        {"extensionAbilityInfo", arrays2},
    };
    EXPECT_EQ(g_bundleManagerAdapterProxyRemoteNull->ParseExtensionAbilityInfos(testBundleInfo1, extensionInfos), true);
    EXPECT_EQ(g_bundleManagerAdapterProxyRemoteNull->ParseExtensionAbilityInfos(testBundleInfo2, extensionInfos), true);
}

/**
 * @tc.name: BundleManagerAdapter_ParseExtensionInfo_0100
 * @tc.desc: an invalid json string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerAdapter_ParseExtensionInfo_0100, TestSize.Level1)
{
    ASSERT_NE(g_bundleManagerAdapterProxyRemoteNull, nullptr);
    ExtensionAbilityInfo extensionInfo;

    EXPECT_EQ(g_bundleManagerAdapterProxyRemoteNull->ParseExtensionInfo("invalidjsonobject", extensionInfo), false);
}

/**
 * @tc.name: BundleManagerAdapter_ParseExtensionInfo_0200
 * @tc.desc: an invalid json string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerAdapter_ParseExtensionInfo_0200, TestSize.Level1)
{
    ASSERT_NE(g_bundleManagerAdapterProxyRemoteNull, nullptr);
    ExtensionAbilityInfo extensionInfo;

    Json testBundleInfo = Json {
        {"invalid_name", 1},
        {"invalid_label", 1},
        {"invalid_description", 1},
        {"invalid_type", "testtest"},
        {"invalid_visible", "test"},
        {"invalid_uid", "123"},
    };
    std::string testStr = testBundleInfo.dump();
    EXPECT_EQ(g_bundleManagerAdapterProxyRemoteNull->ParseExtensionInfo(testStr, extensionInfo), true);
}

/**
 * @tc.name: BundleManagerAdapter_QueryExtensionAbilityInfos_0100
 * @tc.desc: QueryExtensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerAdapter_QueryExtensionAbilityInfos_0100, TestSize.Level1)
{
    ASSERT_NE(g_bundleManagerAdapterProxyRemoteNull, nullptr);
    Want want;
    int32_t flag = 1;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    EXPECT_EQ(g_bundleManagerAdapterProxyRemoteNull->QueryExtensionAbilityInfos(
        want, flag, USER_ID, extensionInfos), false);
}

/**
 * @tc.name: BundleManagerAdapter_QueryExtensionAbilityInfos_0200
 * @tc.desc: QueryExtensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleManagerModuleTest, BundleManagerAdapter_QueryExtensionAbilityInfos_0200, TestSize.Level1)
{
    ASSERT_NE(g_bundleManagerAdapterProxyRemoteNull, nullptr);
    Want want;
    int32_t flag = 1;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    EXPECT_EQ(g_bundleManagerAdapterProxyRemoteNull->QueryExtensionAbilityInfos(
        want, ExtensionAbilityType::BACKUP, flag, USER_ID, extensionInfos), false);
}

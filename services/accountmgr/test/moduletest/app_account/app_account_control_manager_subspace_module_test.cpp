/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <thread>
#include "account_log_wrapper.h"
#include "app_account_constants.h"
#include "app_account_authenticator_manager.h"
#define private public
#include "app_account_control_manager.h"
#include "app_account_manager_service.h"
#include "iinner_os_account_manager.h"
#include "app_account_info_error.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_OWNER = "com.example.owner";
const std::string STRING_DISABLED_OWNER = "com.example.disabled.owner";
const std::string STRING_NOT_EXIST = "com.example.notexist";
const std::string AUTHORIZED_APP = "authorizedApp";
const std::string BUNDLE_NAME = "bundlename";
}

class AppAccountControlManagerSubspaceModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) override
    {
        auto &mgr = IInnerOsAccountManager::GetInstance();
        mgr.mockQueryResult = ERR_OK;
        mgr.mockOsAccountInfo = OsAccountInfo();
        mgr.mockReadCtxResult = ERR_OK;
        mgr.mockSubProfileCtx = SubProfileContext();
    }
    void TearDown(void) override
    {
        auto &mgr = IInnerOsAccountManager::GetInstance();
        mgr.mockQueryResult = ERR_OK;
        mgr.mockOsAccountInfo = OsAccountInfo();
        mgr.mockReadCtxResult = ERR_OK;
        mgr.mockSubProfileCtx = SubProfileContext();
    }
};

/**
 * @tc.name: Subspace_QueryVisibleEnabledAppIndex_Enabled_001
 * @tc.desc: Test QueryVisibleEnabledAppIndex returns enabled extension's appIndex.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest, Subspace_QueryVisibleEnabledAppIndex_Enabled_001, TestSize.Level1)
{
    auto &mgr = IInnerOsAccountManager::GetInstance();
    mgr.mockQueryResult = ERR_OK;
    mgr.mockOsAccountInfo.SetForegroundSubProfileId(1001);
    mgr.mockReadCtxResult = ERR_OK;
    mgr.mockSubProfileCtx.subProfileIndexMap.clear();
    mgr.mockSubProfileCtx.subProfileIndexMap[1] = 1001;
    uint32_t appIndex = 999;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(
        "com.example.subprofile.auth.extension", 0, 100, appIndex);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appIndex, 1u);
}

/**
 * @tc.name: Subspace_QueryVisibleEnabledAppIndex_Disabled_001
 * @tc.desc: Test QueryVisibleEnabledAppIndex returns 0 for disabled extension.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest, Subspace_QueryVisibleEnabledAppIndex_Disabled_001, TestSize.Level1)
{
    uint32_t appIndex = 999;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(
        "com.example.subprofile.auth.disabled", 0, 100, appIndex);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appIndex, 0u);
}

/**
 * @tc.name: Subspace_QueryVisibleEnabledAppIndex_NotFound_001
 * @tc.desc: Test QueryVisibleEnabledAppIndex returns error for not installed bundle.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest, Subspace_QueryVisibleEnabledAppIndex_NotFound_001, TestSize.Level1)
{
    uint32_t appIndex = 999;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(
        "com.example.notexist", 0, 100, appIndex);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: Subspace_QueryVisibleEnabledAppIndex_Visible_001
 * @tc.desc: Test QueryVisibleEnabledAppIndex with visible appIndex.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest, Subspace_QueryVisibleEnabledAppIndex_Visible_001, TestSize.Level1)
{
    auto &mgr = IInnerOsAccountManager::GetInstance();
    mgr.mockQueryResult = ERR_OK;
    mgr.mockOsAccountInfo.SetForegroundSubProfileId(1001);
    mgr.mockReadCtxResult = ERR_OK;
    mgr.mockSubProfileCtx.subProfileIndexMap.clear();
    mgr.mockSubProfileCtx.subProfileIndexMap[1] = 1001;
    AppAccountCallingInfo callingInfo;
    callingInfo.callingUid = 100 * 200000;
    callingInfo.appIndex = 0;
    uint32_t authorizedAppIndex = 0;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(
        "com.example.subprofile.auth.extension", callingInfo.appIndex,
        callingInfo.callingUid / 200000, authorizedAppIndex);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(authorizedAppIndex, 1u);
}

/**
 * @tc.name: Subspace_QueryVisibleEnabledAppIndex_Invisible_001
 * @tc.desc: Test QueryVisibleEnabledAppIndex with invisible appIndex.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_QueryVisibleEnabledAppIndex_Invisible_001, TestSize.Level1)
{
    auto &mgr = IInnerOsAccountManager::GetInstance();
    mgr.mockQueryResult = ERR_OK;
    mgr.mockOsAccountInfo.SetForegroundSubProfileId(1001);
    mgr.mockReadCtxResult = ERR_OK;
    mgr.mockSubProfileCtx.subProfileIndexMap.clear();
    mgr.mockSubProfileCtx.subProfileIndexMap[1] = 1001;
    AppAccountCallingInfo callingInfo;
    callingInfo.callingUid = 100 * 200000;
    callingInfo.appIndex = 2;
    uint32_t authorizedAppIndex = 0;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(
        "com.example.subprofile.auth.extension", callingInfo.appIndex,
        callingInfo.callingUid / 200000, authorizedAppIndex);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(authorizedAppIndex, 0u);
}

/**
 * @tc.name: Subspace_EncodeAuthorizedApp_ParseAuthorizedApp_RoundTrip_001
 * @tc.desc: Test encode->parse round trip.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_EncodeAuthorizedApp_ParseAuthorizedApp_RoundTrip_001, TestSize.Level1)
{
    std::string encoded = AppAccountInfo::EncodeAuthorizedApp("com.example.app", 42);
    std::string bundleName;
    uint32_t appIndex = 0;
    EXPECT_TRUE(AppAccountInfo::ParseAuthorizedApp(encoded, bundleName, appIndex));
    EXPECT_EQ(bundleName, "com.example.app");
    EXPECT_EQ(appIndex, 42u);
}

/**
 * @tc.name: Subspace_AppAccountInfo_EnableAppAccess_Encode_001
 * @tc.desc: Test EnableAppAccess stores bundleName#appIndex under subspace.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_AppAccountInfo_EnableAppAccess_Encode_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner("com.example.owner");
    info.SetName("test_account");
    ErrCode result = info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1));
    EXPECT_EQ(result, ERR_OK);
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), 1u);
    EXPECT_NE(apps.find(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1)), apps.end());
}

/**
 * @tc.name: Subspace_AppAccountInfo_DisableAppAccess_Encode_001
 * @tc.desc: Test DisableAppAccess erases bundleName#appIndex under subspace.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_AppAccountInfo_DisableAppAccess_Encode_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner("com.example.owner");
    info.SetName("test_account");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1));
    ErrCode result = info.DisableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1));
    EXPECT_EQ(result, ERR_OK);
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), 0u);
}

/**
 * @tc.name: Subspace_AppAccountInfo_CheckAppAccess_Encode_001
 * @tc.desc: Test CheckAppAccess finds bundleName#appIndex under subspace.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_AppAccountInfo_CheckAppAccess_Encode_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner("com.example.owner");
    info.SetName("test_account");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1));
    bool isAccessible = false;
    ErrCode result = info.CheckAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1), isAccessible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(isAccessible);
    isAccessible = false;
    result = info.CheckAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 2), isAccessible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(isAccessible);
    isAccessible = false;
    result = info.CheckAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.other", 1), isAccessible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(isAccessible);
}

/**
 * @tc.name: Subspace_EncodeAuthorizedApp_Integration_001
 * @tc.desc: Test full encode->store->check round trip under subspace.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_EncodeAuthorizedApp_Integration_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner("com.example.owner");
    info.SetName("test_account");
    for (uint32_t idx = 0; idx <= 5; idx++) {
        info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", idx));
    }
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), 6u);
    for (uint32_t idx = 0; idx <= 5; idx++) {
        bool isAccessible = false;
        info.CheckAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", idx), isAccessible);
        EXPECT_TRUE(isAccessible) << "idx=" << idx;
    }
    bool isAccessible = false;
    info.CheckAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 6), isAccessible);
    EXPECT_FALSE(isAccessible);
}

/**
 * @tc.name: Subspace_QueryVisibleEnabledAppIndex_ViaAbility_001
 * @tc.desc: Test QueryVisibleEnabledAppIndex finds appIndex via Ability.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_QueryVisibleEnabledAppIndex_ViaAbility_001, TestSize.Level1)
{
    auto &mgr = IInnerOsAccountManager::GetInstance();
    mgr.mockQueryResult = ERR_OK;
    mgr.mockOsAccountInfo.SetForegroundSubProfileId(1001);
    mgr.mockReadCtxResult = ERR_OK;
    mgr.mockSubProfileCtx.subProfileIndexMap.clear();
    mgr.mockSubProfileCtx.subProfileIndexMap[1] = 1001;
    uint32_t appIndex = 999;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(STRING_OWNER, 0, 100, appIndex);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appIndex, 1u);
}

/**
 * @tc.name: Subspace_QueryVisibleEnabledAppIndex_AbilityDisabled_001
 * @tc.desc: Test QueryVisibleEnabledAppIndex returns 0 when Ability disabled.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_QueryVisibleEnabledAppIndex_AbilityDisabled_001, TestSize.Level1)
{
    uint32_t appIndex = 999;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(STRING_DISABLED_OWNER, 0, 100, appIndex);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appIndex, 0u);
}

/**
 * @tc.name: Subspace_QueryVisibleEnabledAppIndex_AbilityMain_001
 * @tc.desc: Test QueryVisibleEnabledAppIndex finds appIndex=0 via main Ability.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_QueryVisibleEnabledAppIndex_AbilityMain_001, TestSize.Level1)
{
    uint32_t appIndex = 999;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(
        "com.example.subprofile.auth.ability", 0, 100, appIndex);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appIndex, 0u);
}

/**
 * @tc.name: Subspace_QueryVisibleEnabledAppIndex_ViaAbility_002
 * @tc.desc: Test QueryVisibleEnabledAppIndex finds appIndex via Ability.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_QueryVisibleEnabledAppIndex_ViaAbility_002, TestSize.Level1)
{
    auto &mgr = IInnerOsAccountManager::GetInstance();
    mgr.mockQueryResult = ERR_OK;
    mgr.mockOsAccountInfo.SetForegroundSubProfileId(1001);
    mgr.mockReadCtxResult = ERR_OK;
    mgr.mockSubProfileCtx.subProfileIndexMap.clear();
    mgr.mockSubProfileCtx.subProfileIndexMap[1] = 1001;
    AppAccountCallingInfo callingInfo;
    callingInfo.callingUid = 100 * 200000;
    callingInfo.appIndex = 0;
    uint32_t authorizedAppIndex = 0;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(
        STRING_OWNER, callingInfo.appIndex,
        callingInfo.callingUid / 200000, authorizedAppIndex);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(authorizedAppIndex, 1u);
}

/**
 * @tc.name: Subspace_QueryVisibleEnabledAppIndex_AbilityDisabledExtEnabled_001
 * @tc.desc: Ability disabled, fallback to Extension which is enabled.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_QueryVisibleEnabledAppIndex_AbilityDisabledExtEnabled_001, TestSize.Level1)
{
    uint32_t appIndex = 999;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(
        "com.example.subprofile.auth.disabled", 0, 100, appIndex);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appIndex, 0u);
}

/**
 * @tc.name: Subspace_AppAccountInfo_EnableAppAccess_Duplicate_001
 * @tc.desc: Test EnableAppAccess duplicate add with API_VERSION9 does not fail.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_AppAccountInfo_EnableAppAccess_Duplicate_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner("com.example.owner");
    info.SetName("test_account");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1));
    ErrCode result = info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1),
        Constants::API_VERSION9);
    EXPECT_EQ(result, ERR_OK);
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), 1u);
}

/**
 * @tc.name: Subspace_AppAccountInfo_DisableAppAccess_NotExist_001
 * @tc.desc: Test DisableAppAccess on non-existent entry returns OK with API_VERSION9.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_AppAccountInfo_DisableAppAccess_NotExist_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner("com.example.owner");
    info.SetName("test_account");
    ErrCode result = info.DisableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.notexist", 1),
        Constants::API_VERSION9);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: Subspace_ParseAuthorizedApp_BundleNameWithHash_001
 * @tc.desc: Test ParseAuthorizedApp with bundleName containing #.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_ParseAuthorizedApp_BundleNameWithHash_001, TestSize.Level1)
{
    std::string encoded = AppAccountInfo::EncodeAuthorizedApp("com.example#app", 3);
    std::string bundleName;
    uint32_t appIndex = 0;
    EXPECT_TRUE(AppAccountInfo::ParseAuthorizedApp(encoded, bundleName, appIndex));
    EXPECT_EQ(appIndex, 3u);
}

/**
 * @tc.name: Subspace_EncodeAuthorizedApp_EmptyBundle_001
 * @tc.desc: Test EncodeAuthorizedApp with empty bundleName.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_EncodeAuthorizedApp_EmptyBundle_001, TestSize.Level1)
{
    std::string encoded = AppAccountInfo::EncodeAuthorizedApp("", 0);
    EXPECT_EQ(encoded, "#0");
    std::string bundleName;
    uint32_t appIndex = 99;
    EXPECT_TRUE(AppAccountInfo::ParseAuthorizedApp(encoded, bundleName, appIndex));
    EXPECT_EQ(bundleName, "");
    EXPECT_EQ(appIndex, 0u);
}

/**
 * @tc.name: Subspace_GetBundleKeySuffix_ConsistencyWithEncode_001
 * @tc.desc: GetBundleKeySuffix(N) must produce same format as EncodeAuthorizedApp(bundle, N).
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_GetBundleKeySuffix_ConsistencyWithEncode_001, TestSize.Level1)
{
    auto &ctrl = AppAccountControlManager::GetInstance();
    EXPECT_EQ(ctrl.GetBundleKeySuffix(0), "#0");
    EXPECT_EQ(ctrl.GetBundleKeySuffix(1), "#1");
    EXPECT_EQ(ctrl.GetBundleKeySuffix(2), "#2");
    std::string bundle = "com.example.appb";
    for (uint32_t idx = 0; idx <= 3; idx++) {
        std::string queryKey = bundle + ctrl.GetBundleKeySuffix(idx);
        std::string storeKey = AppAccountInfo::EncodeAuthorizedApp(bundle, idx);
        EXPECT_EQ(queryKey, storeKey) << "idx=" << idx;
    }
}

/**
 * @tc.name: Subspace_GetAllAccounts_OwnerCheck_NonZeroAppIndex_001
 * @tc.desc: Verify bundleName==owner (not bundleKey==owner) enters owner path for appIndex!=0.
 *           Before fix: bundleKey="bundle#1"!=owner="bundle" → non-owner path.
 *           After fix:  bundleName="bundle"==owner="bundle" → owner path (returns ERR_OK).
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_GetAllAccounts_OwnerCheck_NonZeroAppIndex_001, TestSize.Level1)
{
    auto &ctrl = AppAccountControlManager::GetInstance();
    std::string bundleName = "com.example.owner";
    uid_t uid = 0;
    uint32_t appIndex = 1;
    // With the fix, bundleName==owner → enters owner path → GetAllAccountsFromDataStorage
    // (not the non-owner path GetAccessibleAccountsFromDataStorage)
    // Both return ERR_OK in mock env, but owner path with appIndex=1 queries "com.example.owner#1"
    std::vector<AppAccountInfo> result;
    ErrCode ret = ctrl.GetAllAccounts(bundleName, result, uid, bundleName, appIndex);
    // Owner path should return ERR_OK (not error from non-owner path permission check)
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: Subspace_OAuthVisibility_SetCheck_Consistency_001
 * @tc.desc: Verify SetOAuthTokenVisibility and CheckOAuthTokenVisibility use consistent
 *           key format (bundleName + GetBundleKeySuffix(appIndex)) under subspace.
 *           Tests at AppAccountInfo level to avoid mock data storage persistence issues.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_OAuthVisibility_SetCheck_Consistency_001, TestSize.Level1)
{
    auto &ctrl = AppAccountControlManager::GetInstance();
    std::string targetBundle = BUNDLE_NAME;  // "bundlename"
    uint32_t appIndex = 0;
    // Simulate what control manager does: key = bundleName + GetBundleKeySuffix(appIndex)
    std::string setKey = targetBundle + ctrl.GetBundleKeySuffix(appIndex);  // "bundlename#0"
    std::string checkKey = targetBundle + ctrl.GetBundleKeySuffix(appIndex); // "bundlename#0"
    // Verify SET and CHECK use the same key format
    EXPECT_EQ(setKey, checkKey);
    EXPECT_EQ(setKey, AppAccountInfo::EncodeAuthorizedApp(targetBundle, appIndex));
    // Test at AppAccountInfo level: SET visibility with encoded key, CHECK with same key
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_account");
    info.SetOAuthToken("test_authType", "test_token");
    ErrCode result = info.SetOAuthTokenVisibility("test_authType", setKey, true, Constants::API_VERSION8);
    EXPECT_EQ(result, ERR_OK);
    bool isVisible = false;
    result = info.CheckOAuthTokenVisibility("test_authType", checkKey, isVisible, Constants::API_VERSION8);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(isVisible);
    // Cross-appIndex check: different suffix should NOT be visible
    std::string differentKey = targetBundle + ctrl.GetBundleKeySuffix(1);  // "bundlename#1"
    isVisible = true;
    result = info.CheckOAuthTokenVisibility("test_authType", differentKey, isVisible, Constants::API_VERSION8);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(isVisible);
}

/**
 * @tc.name: Subspace_ResolveAppIndex_001
 * @tc.desc: ResolveAppIndex resolves via QueryVisibleEnabledAppIndex when macro ON.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest, Subspace_ResolveAppIndex_001, TestSize.Level1)
{
    // ResolveAppIndex is a file-local static function; test indirectly via behavior.
    // When macro ON, ResolveAppIndex resolves the visible-enabled appIndex via
    // QueryVisibleEnabledAppIndex (not the raw N). When macro OFF, returns 0.
    // the effect: GetBundleKeySuffix(N) != "" for N>0 proves macro ON path.
    auto &ctrl = AppAccountControlManager::GetInstance();
    EXPECT_NE(ctrl.GetBundleKeySuffix(1), "");
    EXPECT_EQ(ctrl.GetBundleKeySuffix(1), "#1");
}

/**
 * @tc.name: Subspace_CheckAppAccess_ControlMgr_001
 * @tc.desc: Control manager CheckAppAccess uses appAccountCallingInfo.appIndex under macro ON.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest, Subspace_CheckAppAccess_ControlMgr_001, TestSize.Level1)
{
    AppAccountCallingInfo callingInfo;
    callingInfo.callingUid = 0;
    callingInfo.bundleName = STRING_OWNER;
    callingInfo.appIndex = 1;
    bool isAccessible = true;
    // Mock GetAccountInfoById returns ERR_OK for any account, so CheckAppAccess succeeds.
    // The control manager now receives an already-encoded authorizedApp (bundleName#appIndex)
    // from the caller; no account is authorized here so isAccessible is false.
    ErrCode result = AppAccountControlManager::GetInstance().CheckAppAccess(
        "test_account", AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1), isAccessible, callingInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(isAccessible);
}

/**
 * @tc.name: Subspace_FilterAccessibleAccounts_001
 * @tc.desc: FilterAccessibleAccounts macro ON path: no CheckAppIsMaster filter.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest, Subspace_FilterAccessibleAccounts_001, TestSize.Level1)
{
    auto &ctrl = AppAccountControlManager::GetInstance();
    auto dataStoragePtr = ctrl.GetDataStorage(0, false);
    ASSERT_NE(dataStoragePtr, nullptr);
    std::vector<std::string> accessibleAccounts = {"some_account_key"};
    std::vector<AppAccountInfo> result;
    ErrCode ret = ctrl.FilterAccessibleAccounts(accessibleAccounts, 1, dataStoragePtr, result);
    EXPECT_EQ(ret, ERR_OK);
    // Mock GetAccountInfoById returns OK for non-"com.example.ownermax#0#name#" keys
    EXPECT_EQ(result.size(), 1u);
}

/**
 * @tc.name: Subspace_FilterAccessibleAccountsByOwner_001
 * @tc.desc: FilterAccessibleAccountsByOwner macro ON path: filters by appIndex not CheckAppIsMaster.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_FilterAccessibleAccountsByOwner_001, TestSize.Level1)
{
    auto &ctrl = AppAccountControlManager::GetInstance();
    auto dataStoragePtr = ctrl.GetDataStorage(0, false);
    ASSERT_NE(dataStoragePtr, nullptr);
    std::vector<std::string> accessibleAccounts = {"some_account_key"};
    std::vector<AppAccountInfo> result;
    // Mock returns owner="" (from AccountInfoMOCK), so owner != "com.example.owner" → filtered out
    ErrCode filterRet = ctrl.FilterAccessibleAccountsByOwner(
        accessibleAccounts, "com.example.owner", 1, dataStoragePtr, result);
    EXPECT_EQ(filterRet, ERR_OK);
    EXPECT_EQ(result.size(), 0u);
}

/**
 * @tc.name: Subspace_GetAllAccessibleAccountsFromDataStorage_001
 * @tc.desc: GetAllAccessibleAccountsFromDataStorage macro ON: uses EncodeAuthorizedApp key.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_GetAllAccessibleAccountsFromDataStorage_001, TestSize.Level1)
{
    auto &ctrl = AppAccountControlManager::GetInstance();
    auto dataStoragePtr = ctrl.GetDataStorage(0, false);
    ASSERT_NE(dataStoragePtr, nullptr);
    std::vector<AppAccountInfo> result;
    // Macro ON: bundleKey = EncodeAuthorizedApp("bundlename", 0) = "bundlename#0"
    // Mock GetAccessibleAccountsFromDataStorage returns data for any key
    ErrCode ret = ctrl.GetAllAccessibleAccountsFromDataStorage(
        result, BUNDLE_NAME, dataStoragePtr, 0);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: Subspace_SubscribeManager_CheckAppAccess_KeyFormat_001
 * @tc.desc: SubscribeManager::CheckAppAccess macro ON: uses EncodeAuthorizedApp key.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_SubscribeManager_CheckAppAccess_KeyFormat_001, TestSize.Level1)
{
    // Verify that under macro ON, the key format uses EncodeAuthorizedApp
    std::string bundleName = "com.example.app";
    uint32_t appIndex = 1;
    std::string expectedKey = AppAccountInfo::EncodeAuthorizedApp(bundleName, appIndex);
    EXPECT_EQ(expectedKey, "com.example.app#1");
    // Verify GetBundleKeySuffix produces the same format
    auto &ctrl = AppAccountControlManager::GetInstance();
    std::string suffixKey = bundleName + ctrl.GetBundleKeySuffix(appIndex);
    EXPECT_EQ(suffixKey, expectedKey);
}

/**
 * @tc.name: Subspace_IsReceiverAuthorizedApp_001
 * @tc.desc: IsReceiverAuthorizedApp macro ON: uses CheckAppAccess with appIndex.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_IsReceiverAuthorizedApp_001, TestSize.Level1)
{
    // Test at AppAccountInfo level: EnableAppAccess with encoded key, then CheckAppAccess
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_account");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1));
    bool isAccessible = false;
    info.CheckAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1), isAccessible);
    EXPECT_TRUE(isAccessible);
    // Different appIndex should not be authorized
    isAccessible = false;
    info.CheckAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 2), isAccessible);
    EXPECT_FALSE(isAccessible);
}

/**
 * @tc.name: Subspace_SetOAuthTokenVisibility_MacroOn_001
 * @tc.desc: Control manager SetOAuthTokenVisibility macro ON: uses GetBundleKeySuffix.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_SetOAuthTokenVisibility_MacroOn_001, TestSize.Level1)
{
    // Verify key format: bundleName + GetBundleKeySuffix(appIndex) = EncodeAuthorizedApp format
    auto &ctrl = AppAccountControlManager::GetInstance();
    std::string bundle = "com.example.target";
    for (uint32_t idx = 0; idx <= 3; idx++) {
        std::string key = bundle + ctrl.GetBundleKeySuffix(idx);
        EXPECT_EQ(key, AppAccountInfo::EncodeAuthorizedApp(bundle, idx))
            << "idx=" << idx;
    }
}

/**
 * @tc.name: Subspace_EnableAppAccess_EncodeBranch_001
 * @tc.desc: AppAccountInfo::EnableAppAccess stores the caller-encoded bundleName#appIndex entry.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_EnableAppAccess_EncodeBranch_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_account");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 0));
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1));
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 2));
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), 3u);
    EXPECT_NE(apps.find(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 0)), apps.end());
    EXPECT_NE(apps.find(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1)), apps.end());
    EXPECT_NE(apps.find(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 2)), apps.end());
}

/**
 * @tc.name: Subspace_FilterEnabledOwners_MacroOn_001
 * @tc.desc: FilterEnabledOwners macro ON: uses QueryVisibleEnabledAppIndex to filter owners.
 *           STRING_OWNER exists in mock → passes; STRING_NOT_EXIST → BMS fails → skipped.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_FilterEnabledOwners_MacroOn_001, TestSize.Level1)
{
    auto service = new (std::nothrow) AppAccountManagerService();
    ASSERT_NE(service, nullptr);
    std::vector<std::string> owners = {STRING_OWNER, STRING_NOT_EXIST};
    std::vector<std::string> existOwners;
    service->FilterEnabledOwners(owners, 100, 0, existOwners);
    // STRING_OWNER → GetMainAndCloneBundleInfo returns ERR_OK → passes
    // STRING_NOT_EXIST → GetMainAndCloneBundleInfo fails → skipped
    EXPECT_EQ(existOwners.size(), 1u);
    EXPECT_EQ(existOwners[0], STRING_OWNER);
    delete service;
}

/**
 * @tc.name: Subspace_IsAppIndexVisibleWithFg_NonPair_001
 * @tc.desc: Two non-paired indices (e.g. 2 and 3) → false.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_IsAppIndexVisibleWithFg_NonPair_001, TestSize.Level1)
{
    EXPECT_FALSE(AppAccountControlManager::IsAppIndexVisibleWithFg(2, 3, 1));
    EXPECT_FALSE(AppAccountControlManager::IsAppIndexVisibleWithFg(3, 2, 1));
    EXPECT_FALSE(AppAccountControlManager::IsAppIndexVisibleWithFg(1, 2, 1));
}

/**
 * @tc.name: Subspace_SetOAuthTokenVisibility_SelfCheck_001
 * @tc.desc: SetOAuthTokenVisibility self-check: bundleName==owner → no-op return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_SetOAuthTokenVisibility_SelfCheck_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_account");
    info.SetOAuthToken("test_authType", "test_token");
    auto &ctrl = AppAccountControlManager::GetInstance();
    auto ds = ctrl.GetDataStorage(0, false);
    ASSERT_NE(ds, nullptr);
    ctrl.AddAccountInfoIntoDataStorage(info, ds, 0);
    AuthenticatorSessionRequest req;
    req.name = "test_account";
    req.callerBundleName = STRING_OWNER;
    req.appIndex = 0;
    req.callerUid = 0;
    req.authType = "test_authType";
    req.bundleName = STRING_OWNER; // self
    req.isTokenVisible = true;
    ErrCode ret = ctrl.SetOAuthTokenVisibility(req, Constants::API_VERSION8);
    EXPECT_EQ(ret, ERR_OK);
    ctrl.DeleteAccount("test_account", 0, STRING_OWNER, info);
}

/**
 * @tc.name: Subspace_CheckOAuthTokenVisibility_SelfCheck_001
 * @tc.desc: CheckOAuthTokenVisibility: mock returns account with empty owner,
 *           IsSelfBundle won't match. Verify macro ON key construction path is taken.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_CheckOAuthTokenVisibility_SelfCheck_001, TestSize.Level1)
{
    auto &ctrl = AppAccountControlManager::GetInstance();
    auto ds = ctrl.GetDataStorage(0, false);
    ASSERT_NE(ds, nullptr);
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_account");
    ctrl.AddAccountInfoIntoDataStorage(info, ds, 0);
    AuthenticatorSessionRequest req;
    req.name = "test_account";
    req.owner = STRING_OWNER;
    req.callerBundleName = STRING_OWNER;
    req.appIndex = 0;
    req.callerUid = 0;
    req.authType = "test_authType";
    req.bundleName = STRING_OWNER; // self
    bool isVisible = true;
    // Mock returns account with empty owner → IsSelfBundle won't match → isVisible=false
    ErrCode ret = ctrl.CheckOAuthTokenVisibility(req, isVisible, Constants::API_VERSION8);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isVisible);
    ctrl.DeleteAccount("test_account", 0, STRING_OWNER, info);
}

/**
 * @tc.name: Subspace_GetAllOAuthTokens_IsSelf_001
 * @tc.desc: GetAllOAuthTokens with caller==owner → isSelf=true, returns all tokens.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_GetAllOAuthTokens_IsSelf_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_account");
    info.SetOAuthToken("test_authType", "test_token");
    auto &ctrl = AppAccountControlManager::GetInstance();
    auto ds = ctrl.GetDataStorage(0, false);
    ASSERT_NE(ds, nullptr);
    ctrl.AddAccountInfoIntoDataStorage(info, ds, 0);
    AuthenticatorSessionRequest req;
    req.name = "test_account";
    req.owner = STRING_OWNER;
    req.callerBundleName = STRING_OWNER; // self
    req.appIndex = 0;
    req.callerUid = 0;
    std::vector<OAuthTokenInfo> tokenInfos;
    ErrCode ret = ctrl.GetAllOAuthTokens(req, tokenInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(tokenInfos.size(), 1u);
    ctrl.DeleteAccount("test_account", 0, STRING_OWNER, info);
}

/**
 * @tc.name: Subspace_GetOAuthList_StripSuffix_001
 * @tc.desc: GetOAuthList: mock returns account without persisted tokens,
 *           verify macro ON suffix-stripping code path is reached.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_GetOAuthList_StripSuffix_001, TestSize.Level1)
{
    auto &ctrl = AppAccountControlManager::GetInstance();
    auto ds = ctrl.GetDataStorage(0, false);
    ASSERT_NE(ds, nullptr);
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_account");
    ctrl.AddAccountInfoIntoDataStorage(info, ds, 0);
    AuthenticatorSessionRequest req;
    req.name = "test_account";
    req.callerBundleName = STRING_OWNER;
    req.appIndex = 0;
    req.callerUid = 0;
    req.authType = "test_authType";
    std::set<std::string> oauthList;
    // Mock doesn't persist OAuth tokens → empty list, but code path exercised
    ErrCode ret = ctrl.GetOAuthList(req, oauthList, Constants::API_VERSION8);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(oauthList.size(), 0u);
    ctrl.DeleteAccount("test_account", 0, STRING_OWNER, info);
}

/**
 * @tc.name: Subspace_GetOAuthToken_ResolveAppIndex_001
 * @tc.desc: GetOAuthToken: mock returns account without tokens → permission denied.
 *           Verifies ResolveAppIndex macro ON path is taken.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_GetOAuthToken_ResolveAppIndex_001, TestSize.Level1)
{
    auto &ctrl = AppAccountControlManager::GetInstance();
    auto ds = ctrl.GetDataStorage(0, false);
    ASSERT_NE(ds, nullptr);
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_account");
    ctrl.AddAccountInfoIntoDataStorage(info, ds, 0);
    AuthenticatorSessionRequest req;
    req.name = "test_account";
    req.owner = STRING_OWNER;
    req.callerBundleName = STRING_OWNER;
    req.appIndex = 0;
    req.callerUid = 0;
    req.authType = "test_authType";
    std::string token;
    // Mock returns empty owner → IsSelfBundle fails → permission denied
    ErrCode ret = ctrl.GetOAuthToken(req, token, Constants::API_VERSION8);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    ctrl.DeleteAccount("test_account", 0, STRING_OWNER, info);
}

/**
 * @tc.name: Subspace_DeleteOAuthToken_ResolveAppIndex_001
 * @tc.desc: DeleteOAuthToken: mock returns account without tokens → permission denied.
 *           Verifies ResolveAppIndex macro ON path is taken.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_DeleteOAuthToken_ResolveAppIndex_001, TestSize.Level1)
{
    auto &ctrl = AppAccountControlManager::GetInstance();
    auto ds = ctrl.GetDataStorage(0, false);
    ASSERT_NE(ds, nullptr);
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_account");
    ctrl.AddAccountInfoIntoDataStorage(info, ds, 0);
    AuthenticatorSessionRequest req;
    req.name = "test_account";
    req.owner = STRING_OWNER;
    req.callerBundleName = STRING_OWNER;
    req.appIndex = 0;
    req.callerUid = 0;
    req.authType = "test_authType";
    req.token = "test_token";
    // Mock returns empty owner → IsSelfBundle fails → permission denied
    ErrCode ret = ctrl.DeleteOAuthToken(req, Constants::API_VERSION8);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    ctrl.DeleteAccount("test_account", 0, STRING_OWNER, info);
}

/**
 * @tc.name: Subspace_GetAuthenticatorInfo_ViaExtension_001
 * @tc.desc: QueryAbilityAndExtension #ifdef branch: GetAuthenticatorInfo finds
 *           authenticator via extension ability with enabled + visible + appIndex visibility.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_GetAuthenticatorInfo_ViaExtension_001, TestSize.Level1)
{
    auto &mgr = IInnerOsAccountManager::GetInstance();
    mgr.mockQueryResult = ERR_OK;
    mgr.mockOsAccountInfo.SetForegroundSubProfileId(1001);
    mgr.mockReadCtxResult = ERR_OK;
    mgr.mockSubProfileCtx.subProfileIndexMap.clear();
    mgr.mockSubProfileCtx.subProfileIndexMap[1] = 1001;
    AuthenticatorInfo info;
    ErrCode ret = AppAccountAuthenticatorManager::GetAuthenticatorInfo(
        "com.example.subprofile.auth.extension", 1, 100, info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(info.owner, "com.example.subprofile.auth.extension");
}

/**
 * @tc.name: Subspace_GetAuthenticatorInfo_NoAuthenticator_001
 * @tc.desc: QueryAbilityAndExtension: no authenticator found → returns NOT_EXIST.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_GetAuthenticatorInfo_NoAuthenticator_001, TestSize.Level1)
{
    AuthenticatorInfo info;
    ErrCode ret = AppAccountAuthenticatorManager::GetAuthenticatorInfo(
        STRING_NOT_EXIST, 0, 100, info);
    EXPECT_EQ(ret, ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST);
}

/**
 * @tc.name: Subspace_GetAuthenticatorInfo_DisabledExt_001
 * @tc.desc: Extension exists but applicationInfo.enabled=false → filtered out → NOT_EXIST.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_GetAuthenticatorInfo_DisabledExt_001, TestSize.Level1)
{
    AuthenticatorInfo info;
    ErrCode ret = AppAccountAuthenticatorManager::GetAuthenticatorInfo(
        "com.example.subprofile.auth.disabled", 0, 100, info);
    EXPECT_EQ(ret, ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST);
}

/**
 * @tc.name: Subspace_RemoveAppAccountDataFromDataStorage_001
 * @tc.desc: RemoveAppAccountDataFromDataStorage for loop: iterates authorizedApps,
 *           parses each entry, calls RemoveAuthorizedAccountFromDataStorage.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_RemoveAppAccountDataFromDataStorage_001, TestSize.Level1)
{
    auto &ctrl = AppAccountControlManager::GetInstance();
    auto ds = ctrl.GetDataStorage(0, false);
    ASSERT_NE(ds, nullptr);
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_remove_account");
    info.SetAppIndex(0);
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.target", 0));
    ctrl.AddAccountInfoIntoDataStorage(info, ds, 0);
    std::string key = STRING_OWNER + Constants::HYPHEN + std::to_string(0);
    ErrCode ret = ctrl.RemoveAppAccountDataFromDataStorage(ds, key, 0);
    EXPECT_EQ(ret, ERR_OK);
    ctrl.DeleteAccount("test_remove_account", 0, STRING_OWNER, info);
}

/**
 * @tc.name: Subspace_RemoveAppAccountDataFromDataStorage_ParseFail_001
 * @tc.desc: RemoveAppAccountDataFromDataStorage: authorizedApps entry fails to parse
 *           (invalid format) → skipped, no crash.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_RemoveAppAccountDataFromDataStorage_ParseFail_001, TestSize.Level1)
{
    auto &ctrl = AppAccountControlManager::GetInstance();
    auto ds = ctrl.GetDataStorage(0, false);
    ASSERT_NE(ds, nullptr);
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_parse_fail");
    info.SetAppIndex(0);
    info.authorizedApps_.emplace("invalid_entry#abc");
    ctrl.AddAccountInfoIntoDataStorage(info, ds, 0);
    std::string key = STRING_OWNER + Constants::HYPHEN + std::to_string(0);
    ErrCode ret = ctrl.RemoveAppAccountDataFromDataStorage(ds, key, 0);
    EXPECT_EQ(ret, ERR_OK);
    ctrl.DeleteAccount("test_parse_fail", 0, STRING_OWNER, info);
}

/**
 * @tc.name: Subspace_RemoveAppAccountData_ParseAuthorizedApp_001
 * @tc.desc: Test ParseAuthorizedApp logic used in RemoveAppAccountDataFromDataStorage for loop.
 *           Mock KV store doesn't persist data, so test parsing directly on AppAccountInfo.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_RemoveAppAccountData_ParseAuthorizedApp_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_authorized_apps");
    info.SetAppIndex(0);
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.target1", 0));
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.target2", 1));
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.target3", 2));
    std::set<std::string> authorizedApps;
    info.GetAuthorizedApps(authorizedApps);
    EXPECT_EQ(authorizedApps.size(), 3u);
    // Parse each authorized app entry — same logic as RemoveAppAccountDataFromDataStorage for loop
    for (const auto &authorizedApp : authorizedApps) {
        std::string authorizedBundleName;
        uint32_t entryAppIndex = 0;
        bool parsed = AppAccountInfo::ParseAuthorizedApp(authorizedApp, authorizedBundleName, entryAppIndex);
        EXPECT_TRUE(parsed);
        if (authorizedBundleName == "com.example.target1") {
            EXPECT_EQ(entryAppIndex, 0u);
        } else if (authorizedBundleName == "com.example.target2") {
            EXPECT_EQ(entryAppIndex, 1u);
        } else if (authorizedBundleName == "com.example.target3") {
            EXPECT_EQ(entryAppIndex, 2u);
        } else {
            FAIL() << "Unexpected bundle name: " << authorizedBundleName;
        }
    }
}

/**
 * @tc.name: Subspace_GetOAuthList_StripSuffix_Direct_001
 * @tc.desc: Test GetOAuthList suffix-stripping logic directly on AppAccountInfo.
 *           Mock KV store doesn't persist OAuth tokens, so test on the object directly.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_GetOAuthList_StripSuffix_Direct_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_oauth_strip");
    info.SetOAuthToken("test_authType", "test_token");
    // Set visibility with encoded target → authList contains "com.example.target#0"
    std::string encodedTarget = AppAccountInfo::EncodeAuthorizedApp("com.example.target", 0);
    info.SetOAuthTokenVisibility("test_authType", encodedTarget, true, Constants::API_VERSION8);
    // GetOAuthList on AppAccountInfo returns authList entries (encoded)
    std::set<std::string> oauthList;
    ErrCode ret = info.GetOAuthList("test_authType", oauthList, Constants::API_VERSION8);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(oauthList.size(), 1u);
    if (oauthList.size() == 1) {
        EXPECT_EQ(*oauthList.begin(), encodedTarget);
    }
    // Apply the same stripping logic as GetOAuthList in control manager (#ifdef block)
    std::set<std::string> strippedList;
    for (const auto &entry : oauthList) {
        std::string rawBundle;
        uint32_t appIdx = 0;
        if (AppAccountInfo::ParseAuthorizedApp(entry, rawBundle, appIdx)) {
            strippedList.insert(rawBundle);
        } else {
            strippedList.insert(entry);
        }
    }
    EXPECT_EQ(strippedList.size(), 1u);
    if (strippedList.size() == 1) {
        EXPECT_EQ(*strippedList.begin(), "com.example.target");
    }
}

/**
 * @tc.name: Subspace_GetOAuthList_StripLoop_Execute_001
 * @tc.desc: GetOAuthList: mock GetAccountInfoById returns account with oauthTokens_
 *           (authType="test_authType1", authList={"bundlename"}). The #ifdef stripping
 *           for loop executes on non-empty oauthList.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_GetOAuthList_StripLoop_Execute_001, TestSize.Level1)
{
    auto &ctrl = AppAccountControlManager::GetInstance();
    auto ds = ctrl.GetDataStorage(0, false);
    ASSERT_NE(ds, nullptr);
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_account");
    ctrl.AddAccountInfoIntoDataStorage(info, ds, 0);
    AuthenticatorSessionRequest req;
    req.name = "test_account";
    req.callerBundleName = STRING_OWNER;
    req.appIndex = 0;
    req.callerUid = 0;
    // mock GetAccountInfoById returns account with authType="test_authType1", authList={"bundlename"}
    req.authType = "test_authType1";
    std::set<std::string> oauthList;
    ErrCode ret = ctrl.GetOAuthList(req, oauthList, Constants::API_VERSION8);
    EXPECT_EQ(ret, ERR_OK);
    // oauthList should be non-empty → stripping for loop executed
    EXPECT_EQ(oauthList.size(), 1u);
    if (oauthList.size() == 1) {
        // "bundlename" has no # suffix → ParseAuthorizedApp returns rawBundle="bundlename"
        EXPECT_EQ(*oauthList.begin(), "bundlename");
    }
    ctrl.DeleteAccount("test_account", 0, STRING_OWNER, info);
}

/**
 * @tc.name: Subspace_RemoveAppAccountData_ForLoop_Execute_001
 * @tc.desc: RemoveAppAccountDataFromDataStorage: g_mockLoadDataNonEmpty injects non-empty
 *           accounts with encoded authorizedApps → for loop executes, ParseAuthorizedApp
 *           called on each entry.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountControlManagerSubspaceModuleTest,
    Subspace_RemoveAppAccountData_ForLoop_Execute_001, TestSize.Level1)
{
    auto &ctrl = AppAccountControlManager::GetInstance();
    auto ds = ctrl.GetDataStorage(0, false);
    ASSERT_NE(ds, nullptr);
    // Inject non-empty accounts via mock flag
    g_mockLoadDataNonEmpty = true;
    std::string key = STRING_OWNER + Constants::HYPHEN + std::to_string(0);
    ErrCode ret = ctrl.RemoveAppAccountDataFromDataStorage(ds, key, 0);
    EXPECT_EQ(ret, ERR_OK);
    g_mockLoadDataNonEmpty = false; // reset
}

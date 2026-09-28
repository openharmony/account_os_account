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
#include <set>
#include <string>

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "app_account_authenticator_manager.h"
#include "app_account_common.h"
#include "app_account_constants.h"
#define private public
#include "app_account_info.h"
#include "app_account_control_manager.h"
#include "app_account_subscribe_manager.h"
#include "app_account_manager_service.h"
#include "inner_app_account_manager.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
    const std::string STRING_BUNDLE_NAME = "com.example.bundle";
    const std::string STRING_BUNDLE_NAME_2 = "com.example.other";
    const std::string STRING_DUAL_MODE_SECONDARY = "com.example.dualmode.secondary";
    const std::string STRING_DUAL_MODE_AUTH_EXTENSION = "com.example.dualmode.auth.extension";
    const std::string STRING_NOT_EXIST = "com.example.not_installed";
    const std::string STRING_ABILITY_NAME = "AuthServiceAbility";
    const int32_t TEST_USER_ID = 100;
    constexpr int32_t TEST_CALLER_UID = 20000000; // TEST_USER_ID * UID_TRANSFORM_DIVISOR(200000)
    constexpr size_t SIZE_ZERO = 0;
    constexpr size_t SIZE_ONE = 1;
    constexpr size_t SIZE_TWO = 2;
}   //namespace

class AppAccountDualModeTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) override {}
    void TearDown(void) override {}
};

/**
 * @tc.name: DualMode_EncodeAuthorizedApp_DualModeAppIndex_001
 * @tc.desc: EncodeAuthorizedApp with DUAL_MODE_APP_INDEX produces "bundleName#10000".
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_EncodeAuthorizedApp_DualModeAppIndex_001, TestSize.Level1)
{
    std::string encoded = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME, Constants::DUAL_MODE_APP_INDEX);
    EXPECT_EQ(encoded, STRING_BUNDLE_NAME + "#" + std::to_string(Constants::DUAL_MODE_APP_INDEX));
}

/**
 * @tc.name: DualMode_ParseAuthorizedApp_DualModeAppIndex_001
 * @tc.desc: ParseAuthorizedApp correctly decodes "bundleName#10000".
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_ParseAuthorizedApp_DualModeAppIndex_001, TestSize.Level1)
{
    std::string encoded = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME, Constants::DUAL_MODE_APP_INDEX);
    std::string bundleName;
    uint32_t appIndex = 0;
    EXPECT_TRUE(AppAccountInfo::ParseAuthorizedApp(encoded, bundleName, appIndex));
    EXPECT_EQ(bundleName, STRING_BUNDLE_NAME);
    EXPECT_EQ(appIndex, Constants::DUAL_MODE_APP_INDEX);
}

/**
 * @tc.name: DualMode_EnableAppAccess_StoreEncoded_001
 * @tc.desc: EnableAppAccess store "bundleName#10000" in authorizedApp.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_EnableAppAccess_StoreEncoded_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");
    std::string encoded = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME_2, Constants::DUAL_MODE_APP_INDEX);
    ErrCode result = info.EnableAppAccess(encoded);
    EXPECT_EQ(result, ERR_OK);
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), SIZE_ONE);
    EXPECT_NE(apps.find(encoded), apps.end());
}

/**
 * @tc.name: DualMode_EnableAppAccess_MainMode_NoSuffix_001
 * @tc.desc: main mode only bundleName.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_EnableAppAccess_MainMode_NoSuffix_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");

    ErrCode result = info.EnableAppAccess(STRING_BUNDLE_NAME_2);
    EXPECT_EQ(result, ERR_OK);
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), SIZE_ONE);
    EXPECT_NE(apps.find(STRING_BUNDLE_NAME_2), apps.end());
}

/**
 * @tc.name: DualMode_DisableAppAccess_EraseEncoded_001
 * @tc.desc: DisableAppAccess erases bundleName#10000 entry.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_DisableAppAccess_EraseEncoded_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");
    std::string encoded = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME_2, Constants::DUAL_MODE_APP_INDEX);

    info.EnableAppAccess(encoded);
    ErrCode result = info.DisableAppAccess(encoded);
    EXPECT_EQ(result, ERR_OK);
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), SIZE_ZERO);
}

/**
 * @tc.name: DualMode_DisableAppAccess_DifferentAppIndex_001
 * @tc.desc: DisableAppAccess with different appIndex does NOT erase the other entry.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_DisableAppAccess_DifferentAppIndex_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");
    std::string encoded = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME_2, Constants::DUAL_MODE_APP_INDEX);

    info.EnableAppAccess(encoded);
    ErrCode result = info.DisableAppAccess(STRING_BUNDLE_NAME_2, Constants::API_VERSION9);
    EXPECT_EQ(result, ERR_OK);
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), SIZE_ONE);
    EXPECT_NE(apps.find(encoded), apps.end());
}

/**
 * @tc.name: DualMode_CheckAppAccess_Encode_001
 * @tc.desc: CheckAppAccess finds bundleName#10000 entry -> isAccessible=true.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_CheckAppAccess_Encode_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");
    std::string encoded = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME_2, Constants::DUAL_MODE_APP_INDEX);

    info.EnableAppAccess(encoded);
    bool isAccessible = false;
    ErrCode result = info.CheckAppAccess(encoded, isAccessible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(isAccessible);
}

/**
 * @tc.name: DualMode_CheckAppAccess_DifferentAppIndex_001
 * @tc.desc: CheckAppAccess with different appIndex return false.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_CheckAppAccess_DifferentAppIndex_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");
    std::string encodedDualMode = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME_2, Constants::DUAL_MODE_APP_INDEX);

    info.EnableAppAccess(encodedDualMode);
    bool isAccessible = false;
    ErrCode result = info.CheckAppAccess(STRING_BUNDLE_NAME_2, isAccessible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(isAccessible);
}

/**
 * @tc.name: DualMode_CheckAppAccess_MainAndSecondary_001
 * @tc.desc: main mode bundlename and secondary mode bundlename#appindex coexist.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_CheckAppAccess_MainAndSecondary_001, TestSize.Level1)
{
    size_t dataSize = 2;
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");
    info.EnableAppAccess(STRING_BUNDLE_NAME_2);

    std::string encodedDualMode = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME_2, Constants::DUAL_MODE_APP_INDEX);
    info.EnableAppAccess(encodedDualMode);

    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), static_cast<size_t>(dataSize));

    bool isAccessible = false;
    info.CheckAppAccess(STRING_BUNDLE_NAME_2, isAccessible);
    EXPECT_TRUE(isAccessible);

    isAccessible = false;
    info.CheckAppAccess(encodedDualMode, isAccessible);
    EXPECT_TRUE(isAccessible);
}

/**
 * @tc.name: DualMode_RoundTrip_001
 * @tc.desc: Full round trip: enable -> check -> disable -> check for dual mode.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_RoundTrip_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");

    std::string encoded = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME_2, Constants::DUAL_MODE_APP_INDEX);
    info.EnableAppAccess(encoded);
    bool isAccessible = false;
    info.CheckAppAccess(encoded, isAccessible);
    EXPECT_TRUE(isAccessible);

    info.DisableAppAccess(encoded);
    isAccessible = true;
    info.CheckAppAccess(encoded, isAccessible);
    EXPECT_FALSE(isAccessible);
}

/**
 * @tc.name: DualMode_Marshalling_Encoded_001
 * @tc.desc: Marshalling/Unmarshalling preserves bundlename#appindex authorizedApps.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_Marshalling_Encoded_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");

    std::string encoded = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME_2, Constants::DUAL_MODE_APP_INDEX);
    info.EnableAppAccess(STRING_BUNDLE_NAME_2);
    info.EnableAppAccess(encoded);

    Parcel parcel;
    ASSERT_TRUE(info.Marshalling(parcel));
    auto restoredPtr = AppAccountInfo::Unmarshalling(parcel);
    ASSERT_NE(restoredPtr, nullptr);

    std::set<std::string> apps;
    restoredPtr->GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), static_cast<size_t>(2));
    EXPECT_NE(apps.find(STRING_BUNDLE_NAME_2), apps.end());
    EXPECT_NE(apps.find(encoded), apps.end());
}

/**
 * @tc.name: DualMode_IsSelfBundle_DualmodeAppIndex_001
 * @tc.desc: IsSelfBundle with DUAL_MODE_APP_INDEX matches encoded bundlename#appindex.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_IsSelfBundle_DualmodeAppIndex_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetAppIndex(Constants::DUAL_MODE_APP_INDEX);

    std::string encoded = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME, Constants::DUAL_MODE_APP_INDEX);
    EXPECT_TRUE(info.IsSelfBundle(encoded));
    EXPECT_FALSE(info.IsSelfBundle(AppAccountInfo::EncodeAuthorizedApp(STRING_BUNDLE_NAME, 0)));
    EXPECT_FALSE(info.IsSelfBundle(AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME_2, Constants::DUAL_MODE_APP_INDEX)));
}

/**
 * @tc.name: DualMode_IsSelfBundle_LegacyNoSuffix_DualModeAppIndex_001
 * @tc.desc: IsSelfBundle legacy no-suffix key.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_IsSelfBundle_LegacyNoSuffix_DualModeAppIndex_001,
    TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetAppIndex(Constants::DUAL_MODE_APP_INDEX);

    EXPECT_FALSE(info.IsSelfBundle(STRING_BUNDLE_NAME));
}

/**
 * @tc.name: DualMode_QueryVisibleEnabledAppIndex_Secondary_001
 * @tc.desc: QueryVisibleEnabledAppIndex return DUAL_MODE_APP_INDEX for dual mode.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_QueryVisibleEnabledAppIndex_Secondary_001,
    TestSize.Level1)
{
    uint32_t appIndex = 0;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(
        STRING_DUAL_MODE_SECONDARY, 0, TEST_USER_ID, appIndex);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appIndex, Constants::DUAL_MODE_APP_INDEX);
}

/**
 * @tc.name: DualMode_QueryVisibleEnabledAppIndex_MainMode_001
 * @tc.desc: QueryVisibleEnabledAppIndex return 0 for normal bundle.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_QueryVisibleEnabledAppIndex_MainMode_001,
    TestSize.Level1)
{
    uint32_t appIndex = 999;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(
        STRING_BUNDLE_NAME, 0, TEST_USER_ID, appIndex);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appIndex, 0u);
}

/**
 * @tc.name: DualMode_QueryVisibleEnabledAppIndex_NotInstalled_001
 * @tc.desc: QueryVisibleEnabledAppIndex fallback to main mode for not-installed bundle.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_QueryVisibleEnabledAppIndex_NotInstalled_001,
    TestSize.Level1)
{
    uint32_t appIndex = 999;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(
        STRING_NOT_EXIST, 0, TEST_USER_ID, appIndex);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: DualMode_EncodeAuthorizedAppPrecise_AppIndex_001
 * @tc.desc: EncodeAuthorizedAppPrecise with bundlename.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_EncodeAuthorizedAppPrecise_AppIndex_001,
    TestSize.Level1)
{
    std::string encodedApp;
    AppAccountControlManager::EncodeAuthorizedAppPrecise(
        STRING_BUNDLE_NAME, Constants::DUAL_MODE_APP_INDEX, encodedApp);
    EXPECT_EQ(encodedApp, AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME, Constants::DUAL_MODE_APP_INDEX));
}

/**
 * @tc.name: DualMode_EncodeAuthorizedAppPrecise_MainMode_001
 * @tc.desc: EncodeAuthorizedAppPrecise with appindex=0 produces pure bundlename.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_EncodeAuthorizedAppPrecise_MainMode_001,
    TestSize.Level1)
{
    std::string encodedApp;
    AppAccountControlManager::EncodeAuthorizedAppPrecise(
        STRING_BUNDLE_NAME, 0, encodedApp);
    EXPECT_EQ(encodedApp, STRING_BUNDLE_NAME);
}

/**
 * @tc.name: DualMode_TokenVisibility_WriteReadConsistency_001
 * @tc.desc: SetOAuthTokenVisibility and CheckOAuthTokenVisibility with same key.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_TokenVisibility_WriteReadConsistency_001,
    TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");
    info.SetAppIndex(Constants::DUAL_MODE_APP_INDEX);
    info.SetOAuthToken("authType1", "token123");

    std::string bundleKey;
    AppAccountControlManager::EncodeAuthorizedAppPrecise(
        STRING_BUNDLE_NAME_2, Constants::DUAL_MODE_APP_INDEX, bundleKey);
    bool isVisible = false;
    ErrCode ret = info.SetOAuthTokenVisibility("authType1", bundleKey, true, Constants::API_VERSION9);
    EXPECT_EQ(ret, ERR_OK);

    ret = info.CheckOAuthTokenVisibility("authType1", bundleKey, isVisible, Constants::API_VERSION9);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isVisible);
}

/**
 * @tc.name: DualMode_TokenVisibility_CrossModeIsolation_001
 * @tc.desc: secondary mode write visibility, main mode cannot read.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_TokenVisibility_CrossModeIsolation_001,
    TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");
    info.SetOAuthToken("authType1", "token123");

    std::string dualModeKey = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME_2, Constants::DUAL_MODE_APP_INDEX);
    ErrCode ret = info.SetOAuthTokenVisibility("authType1", dualModeKey, true, Constants::API_VERSION9);
    EXPECT_EQ(ret, ERR_OK);

    bool isVisible = false;
    ret = info.CheckOAuthTokenVisibility(
        "authType1", STRING_BUNDLE_NAME_2, isVisible, Constants::API_VERSION9);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isVisible);
}

/**
 * @tc.name: DualMode_TokenVisibility_MainModeCompatibility_001
 * @tc.desc: main mode write visibility, compatible with legacy data.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_TokenVisibility_MainModeCompatibility_001,
    TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");
    info.SetOAuthToken("authType1", "token123");

    ErrCode ret = info.SetOAuthTokenVisibility(
        "authType1", STRING_BUNDLE_NAME_2, true, Constants::API_VERSION9);
    EXPECT_EQ(ret, ERR_OK);

    bool isVisible = false;
    ret = info.CheckOAuthTokenVisibility(
        "authType1", STRING_BUNDLE_NAME_2, isVisible, Constants::API_VERSION9);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isVisible);
}

/**
 * @tc.name: DualMode_GetOAuthList_RetainsSuffix_001
 * @tc.desc: GetOAuthList retains appIndex suffix in entries at data layer.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_GetOAuthList_RetainsSuffix_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");
    info.SetOAuthToken("authType1", "token123");

    std::string dualModeKey = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME_2, Constants::DUAL_MODE_APP_INDEX);
    info.SetOAuthTokenVisibility(
        "authType1", dualModeKey, true, Constants::API_VERSION9);
    std::set<std::string> oauthList;
    info.GetOAuthList("authType1", oauthList);
    EXPECT_NE(oauthList.find(dualModeKey), oauthList.end());
}

/**
 * @tc.name: DualMode_GetAuthenticatorInfo_NotExist_001
 * @tc.desc: GetAuthenticatorInfo return error for non-existent bundle.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_GetAuthenticatorInfo_NotExist_001,
    TestSize.Level1)
{
    AuthenticatorInfo info;
    ErrCode result = AppAccountAuthenticatorManager::GetAuthenticatorInfo(
        STRING_NOT_EXIST, 0, TEST_USER_ID, info);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: DualMode_OTA_LegacyBareBundleName_001
 * @tc.desc: Legacy bare bundleName is stored as-is and parsed as appIndex=0 (OTA compat).
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_OTA_LegacyBareBundleName_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");
    ErrCode result = info.EnableAppAccess(STRING_BUNDLE_NAME_2);
    EXPECT_EQ(result, ERR_OK);
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), SIZE_ONE);
    EXPECT_NE(apps.find(STRING_BUNDLE_NAME_2), apps.end());
    std::string rawBundle;
    uint32_t appIdx = 0;
    EXPECT_TRUE(AppAccountInfo::ParseAuthorizedApp(STRING_BUNDLE_NAME_2, rawBundle, appIdx));
    EXPECT_EQ(rawBundle, STRING_BUNDLE_NAME_2);
    EXPECT_EQ(appIdx, 0u);
    EXPECT_EQ(AppAccountInfo::EncodeAuthorizedApp(STRING_BUNDLE_NAME_2, 0), STRING_BUNDLE_NAME_2);
}

/**
 * @tc.name: DualMode_IsSelfBundle_MainMode_001
 * @tc.desc: Main-mode account (appIndex=0) matches encoded bare self, rejects #10000.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_IsSelfBundle_MainMode_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetAppIndex(0);
    EXPECT_TRUE(info.IsSelfBundle(AppAccountInfo::EncodeAuthorizedApp(STRING_BUNDLE_NAME, 0)));
    EXPECT_FALSE(info.IsSelfBundle(
        AppAccountInfo::EncodeAuthorizedApp(STRING_BUNDLE_NAME, Constants::DUAL_MODE_APP_INDEX)));
}

/**
 * @tc.name: DualMode_IsSelfBundle_LegacyBare_MainMode_001
 * @tc.desc: Main-mode account matches legacy bare bundleName (no # suffix).
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_IsSelfBundle_LegacyBare_MainMode_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetAppIndex(0);
    EXPECT_TRUE(info.IsSelfBundle(STRING_BUNDLE_NAME));
}

/**
 * @tc.name: DualMode_ParseAuthorizedApp_Boundary_001
 * @tc.desc: ParseAuthorizedApp handles bare, encoded, trailing-#, non-numeric.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_ParseAuthorizedApp_Boundary_001, TestSize.Level1)
{
    std::string rawBundle;
    uint32_t appIdx = 0;
    EXPECT_TRUE(AppAccountInfo::ParseAuthorizedApp(STRING_BUNDLE_NAME, rawBundle, appIdx));
    EXPECT_EQ(rawBundle, STRING_BUNDLE_NAME);
    EXPECT_EQ(appIdx, 0u);
    std::string encoded = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME, Constants::DUAL_MODE_APP_INDEX);
    EXPECT_TRUE(AppAccountInfo::ParseAuthorizedApp(encoded, rawBundle, appIdx));
    EXPECT_EQ(rawBundle, STRING_BUNDLE_NAME);
    EXPECT_EQ(appIdx, Constants::DUAL_MODE_APP_INDEX);
    EXPECT_FALSE(AppAccountInfo::ParseAuthorizedApp(STRING_BUNDLE_NAME + "#", rawBundle, appIdx));
    EXPECT_FALSE(AppAccountInfo::ParseAuthorizedApp(STRING_BUNDLE_NAME + "#abc", rawBundle, appIdx));
}

/**
 * @tc.name: DualMode_GetPrimeKey_DualMode_001
 * @tc.desc: GetPrimeKey produces owner#appIndex#name# for both modes.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_GetPrimeKey_DualMode_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");
    info.SetAppIndex(Constants::DUAL_MODE_APP_INDEX);
    std::string key = info.GetPrimeKey();
    EXPECT_EQ(key, STRING_BUNDLE_NAME + "#10000#account1#");
    info.SetAppIndex(0);
    key = info.GetPrimeKey();
    EXPECT_EQ(key, STRING_BUNDLE_NAME + "#0#account1#");
}

/**
 * @tc.name: DualMode_GetBundleKeySuffix_001
 * @tc.desc: GetBundleKeySuffix returns empty for appIndex=0, #10000 for secondary.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_GetBundleKeySuffix_001, TestSize.Level1)
{
    EXPECT_EQ(AppAccountControlManager::GetInstance().GetBundleKeySuffix(0), "");
    EXPECT_EQ(AppAccountControlManager::GetInstance().GetBundleKeySuffix(
        Constants::DUAL_MODE_APP_INDEX), "#" + std::to_string(Constants::DUAL_MODE_APP_INDEX));
}

/**
 * @tc.name: DualMode_TokenVisibility_MainWrite_SecondaryRead_001
 * @tc.desc: Main-mode write visibility, secondary-mode key read -> not visible (isolation).
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_TokenVisibility_MainWrite_SecondaryRead_001,
    TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");
    info.SetOAuthToken("authType1", "token123");
    ErrCode ret = info.SetOAuthTokenVisibility(
        "authType1", STRING_BUNDLE_NAME_2, true, Constants::API_VERSION9);
    EXPECT_EQ(ret, ERR_OK);
    std::string secondaryKey = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME_2, Constants::DUAL_MODE_APP_INDEX);
    bool isVisible = true;
    ret = info.CheckOAuthTokenVisibility("authType1", secondaryKey, isVisible, Constants::API_VERSION9);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isVisible);
}

/**
 * @tc.name: DualMode_AppAccess_MainAuthorized_SecondaryInaccessible_001
 * @tc.desc: Authorize main-mode bare key, secondary-mode key check -> inaccessible.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_AppAccess_MainAuthorized_SecondaryInaccessible_001,
    TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");
    info.EnableAppAccess(STRING_BUNDLE_NAME_2);
    std::string secondaryKey = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME_2, Constants::DUAL_MODE_APP_INDEX);
    bool isAccessible = true;
    ErrCode result = info.CheckAppAccess(secondaryKey, isAccessible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(isAccessible);
}

/**
 * @tc.name: DualMode_AppAccess_IndependentDisable_001
 * @tc.desc: Main and secondary authorizations are independently removable.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_AppAccess_IndependentDisable_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_BUNDLE_NAME);
    info.SetName("account1");
    info.EnableAppAccess(STRING_BUNDLE_NAME_2);
    std::string secondaryKey = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME_2, Constants::DUAL_MODE_APP_INDEX);
    info.EnableAppAccess(secondaryKey);
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), SIZE_TWO);
    info.DisableAppAccess(STRING_BUNDLE_NAME_2);
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), SIZE_ONE);
    EXPECT_NE(apps.find(secondaryKey), apps.end());
    info.DisableAppAccess(secondaryKey);
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), SIZE_ZERO);
}

/**
 * @tc.name: DualMode_ResolveAndEncodeAuthorizedApp_NotInstalled_001
 * @tc.desc: ResolveAndEncodeAuthorizedApp succeeds for not-installed bundle to avoid leaking installation list.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_ResolveAndEncodeAuthorizedApp_NotInstalled_001,
    TestSize.Level1)
{
    std::string encodedApp;
    ErrCode result = AppAccountControlManager::ResolveAndEncodeAuthorizedApp(
        STRING_NOT_EXIST, 0, TEST_CALLER_UID, encodedApp);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(encodedApp.empty());
}

/**
 * @tc.name: DualMode_Event_Isolation_MainPublish_SecondarySubscribe_001
 * @tc.desc: Secondary subscriber not matched by main-mode publish key (isolation).
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_Event_Isolation_MainPublish_SecondarySubscribe_001,
    TestSize.Level1)
{
    auto &sm = AppAccountSubscribeManager::GetInstance();
    std::string secondaryKey = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME, Constants::DUAL_MODE_APP_INDEX);
    auto recordPtr = std::make_shared<AppAccountSubscribeRecord>();
    std::vector<std::string> subscribeOwners = {secondaryKey};
    recordPtr->subscribeInfoPtr = std::make_shared<AppAccountSubscribeInfo>(subscribeOwners);
    sm.InsertSubscribeRecord({secondaryKey}, recordPtr);
    std::string mainKey = AppAccountInfo::EncodeAuthorizedApp(STRING_BUNDLE_NAME, 0);
    EXPECT_TRUE(sm.GetSubscribeRecords(mainKey, 0).empty());
    EXPECT_FALSE(sm.GetSubscribeRecords(secondaryKey, 0).empty());
    std::lock_guard<std::recursive_mutex> lock(sm.mutex_);
    sm.ownerSubscribeRecords_.clear();
    sm.subscribeRecords_.clear();
}

/**
 * @tc.name: DualMode_PublishAccount_EncodedKeyMatch_001
 * @tc.desc: PublishAccount computes EncodeAuthorizedApp key; same-mode matches, cross-mode does not.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_PublishAccount_EncodedKeyMatch_001, TestSize.Level1)
{
    auto &sm = AppAccountSubscribeManager::GetInstance();
    std::string secondaryKey = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME, Constants::DUAL_MODE_APP_INDEX);
    auto recordPtr = std::make_shared<AppAccountSubscribeRecord>();
    std::vector<std::string> subscribeOwners = {secondaryKey};
    recordPtr->subscribeInfoPtr = std::make_shared<AppAccountSubscribeInfo>(subscribeOwners);
    sm.InsertSubscribeRecord({secondaryKey}, recordPtr);
    std::string secondaryPublishKey = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME, Constants::DUAL_MODE_APP_INDEX);
    EXPECT_FALSE(sm.GetSubscribeRecords(secondaryPublishKey, 0).empty());
    std::string mainPublishKey = AppAccountInfo::EncodeAuthorizedApp(STRING_BUNDLE_NAME, 0);
    EXPECT_TRUE(sm.GetSubscribeRecords(mainPublishKey, 0).empty());
    std::lock_guard<std::recursive_mutex> lock(sm.mutex_);
    sm.ownerSubscribeRecords_.clear();
    sm.subscribeRecords_.clear();
}

/**
 * @tc.name: DualMode_CheckOwnersAccessible_SelfSubscribe_Secondary_001
 * @tc.desc: Self-subscribe short-circuit when encoded owner equals caller bundleKey.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_CheckOwnersAccessible_SelfSubscribe_Secondary_001,
    TestSize.Level1)
{
    auto &sm = AppAccountSubscribeManager::GetInstance();
    std::string secondaryKey = AppAccountInfo::EncodeAuthorizedApp(
        STRING_BUNDLE_NAME, Constants::DUAL_MODE_APP_INDEX);
    ErrCode ret = sm.CheckOwnersAccessible({secondaryKey}, secondaryKey, {});
    EXPECT_EQ(ret, ERR_OK);
    std::string mainKey = AppAccountInfo::EncodeAuthorizedApp(STRING_BUNDLE_NAME, 0);
    ret = sm.CheckOwnersAccessible({mainKey}, secondaryKey, {});
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: DualMode_GetAllAccessibleAccounts_CallerAppIndexMismatch_001
 * @tc.desc: Returns empty when caller appIndex does not match visible appIndex (anti-spoof).
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_GetAllAccessibleAccounts_CallerAppIndexMismatch_001,
    TestSize.Level1)
{
    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = AppAccountControlManager::GetInstance().GetAllAccessibleAccounts(
        appAccounts, TEST_CALLER_UID, STRING_BUNDLE_NAME, Constants::DUAL_MODE_APP_INDEX);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(appAccounts.empty());
}

/**
 * @tc.name: DualMode_GetAuthenticatorInfo_DualMode_Success_001
 * @tc.desc: GetAuthenticatorInfo discovers dual-mode extension with matching appIndex.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_GetAuthenticatorInfo_DualMode_Success_001,
    TestSize.Level1)
{
    AuthenticatorInfo info;
    ErrCode result = AppAccountAuthenticatorManager::GetAuthenticatorInfo(
        STRING_DUAL_MODE_AUTH_EXTENSION, 0, TEST_USER_ID, info);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(info.abilityName, STRING_ABILITY_NAME);
}

/**
 * @tc.name: DualMode_EncodeOwners_DualMode_001
 * @tc.desc: EncodeOwners encodes dual-mode owner as #10000, normal owner as bare.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_EncodeOwners_DualMode_001, TestSize.Level1)
{
    auto service = new (std::nothrow) AppAccountManagerService();
    ASSERT_NE(service, nullptr);
    std::vector<std::string> owners = {STRING_DUAL_MODE_SECONDARY, STRING_BUNDLE_NAME};
    std::vector<std::string> encodedOwners;
    service->EncodeOwners(owners, 0, TEST_USER_ID, encodedOwners);
    EXPECT_EQ(encodedOwners.size(), SIZE_TWO);
    EXPECT_EQ(encodedOwners[0], STRING_DUAL_MODE_SECONDARY + "#" +
        std::to_string(Constants::DUAL_MODE_APP_INDEX));
    EXPECT_EQ(encodedOwners[1], STRING_BUNDLE_NAME);
    delete service;
}

/**
 * @tc.name: DualMode_EncodeOwners_AllFailed_001
 * @tc.desc: EncodeOwners returns empty when all owners fail BMS lookup.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_EncodeOwners_AllFailed_001, TestSize.Level1)
{
    auto service = new (std::nothrow) AppAccountManagerService();
    ASSERT_NE(service, nullptr);
    std::vector<std::string> owners = {STRING_NOT_EXIST};
    std::vector<std::string> encodedOwners;
    service->EncodeOwners(owners, 0, TEST_USER_ID, encodedOwners);
    EXPECT_TRUE(encodedOwners.empty());
    delete service;
}

/**
 * @tc.name: DualMode_CheckAppAccess_Inner_BMSFail_001
 * @tc.desc: InnerAppAccountManager::CheckAppAccess returns error on BMS failure (no fallback).
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountDualModeTest, DualMode_CheckAppAccess_Inner_BMSFail_001, TestSize.Level1)
{
    InnerAppAccountManager innerManager;
    AppAccountCallingInfo callingInfo;
    callingInfo.callingUid = TEST_CALLER_UID;
    callingInfo.bundleName = STRING_BUNDLE_NAME;
    callingInfo.appIndex = 0;
    bool isAccessible = false;
    ErrCode result = innerManager.CheckAppAccess(
        "account1", STRING_NOT_EXIST, isAccessible, callingInfo);
    EXPECT_NE(result, ERR_OK);
}

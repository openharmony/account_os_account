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
#include <map>
#include <set>
#include <string>

#define private public
#include "app_account_info.h"
#include "app_account_constants.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string BUNDLE_NAME = "com.example.bundle";
const std::string BUNDLE_NAME_2 = "com.example.other";
constexpr size_t SIZE_ZERO = 0;
constexpr size_t SIZE_ONE = 1;
constexpr size_t SIZE_TWO = 2;
}  // namespace

class AppAccountSubspaceTest : public testing::Test {
public:
    void SetUp(void) override {}
    void TearDown(void) override {}
};

/**
 * @tc.name: Subspace_EnableAppAccess_StoresEncoded_001
 * @tc.desc: EnableAppAccess stores bundleName#appIndex in authorizedApps_.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_EnableAppAccess_StoresEncoded_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    ErrCode result = info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1));
    EXPECT_EQ(result, ERR_OK);
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), SIZE_ONE);
    EXPECT_NE(apps.find(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1)), apps.end());
}

/**
 * @tc.name: Subspace_EnableAppAccess_MultipleAppIndex_001
 * @tc.desc: EnableAppAccess for different appIndex stores separate entries.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_EnableAppAccess_MultipleAppIndex_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 0));
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1));
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 2));
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), SIZE_TWO + 1); // 3 entries: #0, #1, #2
}

/**
 * @tc.name: Subspace_DisableAppAccess_ErasesEncoded_001
 * @tc.desc: DisableAppAccess erases the encoded bundleName#appIndex entry.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_DisableAppAccess_ErasesEncoded_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1));
    ErrCode result = info.DisableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1));
    EXPECT_EQ(result, ERR_OK);
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), SIZE_ZERO);
}

/**
 * @tc.name: Subspace_DisableAppAccess_DifferentAppIndex_001
 * @tc.desc: DisableAppAccess with different appIndex does NOT erase the other entry.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_DisableAppAccess_DifferentAppIndex_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1));
    // Disable appIndex=2, should NOT erase appIndex=1
    ErrCode result = info.DisableAppAccess(
        AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 2), Constants::API_VERSION9);
    EXPECT_EQ(result, ERR_OK);
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), SIZE_ONE);
    EXPECT_NE(apps.find(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1)), apps.end());
}

/**
 * @tc.name: Subspace_DisableAppAccess_NotExist_001
 * @tc.desc: DisableAppAccess on non-existent entry returns OK with API_VERSION9.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_DisableAppAccess_NotExist_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    ErrCode result = info.DisableAppAccess(
        AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME_2, 1), Constants::API_VERSION9);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: Subspace_EnableAppAccess_Duplicate_001
 * @tc.desc: EnableAppAccess duplicate add with API_VERSION9 does not fail.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_EnableAppAccess_Duplicate_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1));
    ErrCode result = info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1), Constants::API_VERSION9);
    EXPECT_EQ(result, ERR_OK);
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), SIZE_ONE);
}

/**
 * @tc.name: Subspace_CheckAppAccess_Encoded_001
 * @tc.desc: CheckAppAccess finds encoded bundleName#appIndex entry.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_CheckAppAccess_Encoded_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1));
    bool isAccessible = false;
    ErrCode result = info.CheckAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1), isAccessible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(isAccessible);
}

/**
 * @tc.name: Subspace_CheckAppAccess_DifferentAppIndex_001
 * @tc.desc: CheckAppAccess with different appIndex returns false.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_CheckAppAccess_DifferentAppIndex_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1));
    bool isAccessible = false;
    ErrCode result = info.CheckAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 2), isAccessible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(isAccessible);
}

/**
 * @tc.name: Subspace_CheckAppAccess_DifferentBundle_001
 * @tc.desc: CheckAppAccess with different bundleName returns false.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_CheckAppAccess_DifferentBundle_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1));
    bool isAccessible = true;
    ErrCode result = info.CheckAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME_2, 1), isAccessible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(isAccessible);
}

/**
 * @tc.name: Subspace_RoundTrip_001
 * @tc.desc: Full round trip: enable -> check -> disable -> check.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_RoundTrip_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    for (uint32_t idx = 0; idx <= 5; idx++) {
        info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, idx));
    }
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), static_cast<size_t>(6));
    for (uint32_t idx = 0; idx <= 5; idx++) {
        bool isAccessible = false;
        info.CheckAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, idx), isAccessible);
        EXPECT_TRUE(isAccessible) << "idx=" << idx;
    }
    bool isAccessible = false;
    info.CheckAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 6), isAccessible);
    EXPECT_FALSE(isAccessible);
    // Disable one
    info.DisableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 3));
    info.CheckAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 3), isAccessible);
    EXPECT_FALSE(isAccessible);
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), static_cast<size_t>(5));
}

/**
 * @tc.name: Subspace_Marshalling_Encoded_001
 * @tc.desc: Marshalling/Unmarshalling preserves encoded authorizedApps.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_Marshalling_Encoded_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 0));
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1));
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME_2, 2));

    Parcel parcel;
    ASSERT_TRUE(info.Marshalling(parcel));
    auto restoredPtr = AppAccountInfo::Unmarshalling(parcel);
    ASSERT_NE(restoredPtr, nullptr);

    std::set<std::string> apps;
    restoredPtr->GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), static_cast<size_t>(3));
    EXPECT_NE(apps.find(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 0)), apps.end());
    EXPECT_NE(apps.find(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1)), apps.end());
    EXPECT_NE(apps.find(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME_2, 2)), apps.end());
}

/**
 * @tc.name: Subspace_IsSelfBundle_SameAppIndex_001
 * @tc.desc: IsSelfBundle: same bundle + same appIndex → true; same bundle + different appIndex → false;
 *           different bundle → false.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_IsSelfBundle_SameAppIndex_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetAppIndex(1);
    EXPECT_TRUE(info.IsSelfBundle(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1)));
    EXPECT_FALSE(info.IsSelfBundle(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 0)));
    EXPECT_FALSE(info.IsSelfBundle(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 2)));
    EXPECT_FALSE(info.IsSelfBundle(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME_2, 1)));
}

/**
 * @tc.name: Subspace_IsSelfBundle_LegacyNoSuffix_ZeroAppIndex_001
 * @tc.desc: IsSelfBundle: legacy no-suffix key with appIndex_=0 → true (backward compat).
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_IsSelfBundle_LegacyNoSuffix_ZeroAppIndex_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetAppIndex(0);
    EXPECT_TRUE(info.IsSelfBundle(BUNDLE_NAME));
}

/**
 * @tc.name: Subspace_IsSelfBundle_LegacyNoSuffix_NonZeroAppIndex_001
 * @tc.desc: IsSelfBundle: legacy no-suffix key with appIndex_=1 → false (cross-appIndex isolation).
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_IsSelfBundle_LegacyNoSuffix_NonZeroAppIndex_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetAppIndex(1);
    EXPECT_FALSE(info.IsSelfBundle(BUNDLE_NAME));
}

/**
 * @tc.name: Subspace_OAuthVisibility_CrossAppIndex_Authorized_001
 * @tc.desc: Cross-appIndex: SetOAuthTokenVisibility records to authList (not self),
 *           CheckOAuthTokenVisibility finds it → isVisible=true.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_OAuthVisibility_CrossAppIndex_Authorized_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    info.SetAppIndex(1);
    info.SetOAuthToken("authType", "token");
    // cross-appIndex: bundle#0 is NOT self for account at appIndex=1
    std::string crossKey = AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 0);
    ErrCode ret = info.SetOAuthTokenVisibility("authType", crossKey, true, Constants::API_VERSION8);
    EXPECT_EQ(ret, ERR_OK);
    bool isVisible = false;
    ret = info.CheckOAuthTokenVisibility("authType", crossKey, isVisible, Constants::API_VERSION8);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isVisible);
}

/**
 * @tc.name: Subspace_OAuthVisibility_CrossAppIndex_Unauthorized_001
 * @tc.desc: Cross-appIndex without prior authorization: CheckOAuthTokenVisibility → isVisible=false.
 *           This is the key test that would FAIL before the IsSelfBundle fix.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_OAuthVisibility_CrossAppIndex_Unauthorized_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    info.SetAppIndex(1);
    info.SetOAuthToken("authType", "token");
    // cross-appIndex: NOT self, NOT in authList → isVisible=false
    std::string crossKey = AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 0);
    bool isVisible = false;
    ErrCode ret = info.CheckOAuthTokenVisibility("authType", crossKey, isVisible, Constants::API_VERSION8);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isVisible);
}

/**
 * @tc.name: Subspace_OAuthVisibility_SameAppIndex_Self_001
 * @tc.desc: Same appIndex self-check: SetOAuthTokenVisibility is no-op (self),
 *           CheckOAuthTokenVisibility → isVisible=true (self always visible).
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubspaceTest, Subspace_OAuthVisibility_SameAppIndex_Self_001, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    info.SetAppIndex(1);
    info.SetOAuthToken("authType", "token");
    // same appIndex: self → no-op
    std::string selfKey = AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1);
    ErrCode ret = info.SetOAuthTokenVisibility("authType", selfKey, true, Constants::API_VERSION8);
    EXPECT_EQ(ret, ERR_OK);
    bool isVisible = false;
    ret = info.CheckOAuthTokenVisibility("authType", selfKey, isVisible, Constants::API_VERSION8);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isVisible);
}

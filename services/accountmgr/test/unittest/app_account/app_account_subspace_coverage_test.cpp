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
#include <string>
#include <vector>

#define private public
#include "app_account_control_manager.h"
#include "app_account_info.h"
#undef private
#include "app_account_constants.h"
#include "app_account_info_json_parser.h"
#include "iinner_os_account_manager.h"
#include "bundle_manager_adapter.h"
#include "account_error_no.h"
#include "account_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string BUNDLE_NAME = "com.example.bundle";
const std::string STRING_OWNER = "com.example.owner";
const std::string STRING_DISABLED_OWNER = "com.example.disabled.owner";
const std::string STRING_BOTH_DISABLED = "com.example.both.disabled";
const std::string STRING_NOT_EXIST = "com.example.notexist";
constexpr uint32_t MAX_AUTH = MAX_APP_AUTH_LIST_SIZE;
}  // namespace

class AppAccountSubspaceCoverageTest : public testing::Test {
public:
    void SetUp() override
    {
        auto &mgr = IInnerOsAccountManager::GetInstance();
        mgr.mockQueryResult = ERR_OK;
        mgr.mockOsAccountInfo = OsAccountInfo();
        mgr.mockReadCtxResult = ERR_OK;
        mgr.mockSubProfileCtx = SubProfileContext();
    }
    void TearDown() override
    {
        auto &mgr = IInnerOsAccountManager::GetInstance();
        mgr.mockQueryResult = ERR_OK;
        mgr.mockOsAccountInfo = OsAccountInfo();
        mgr.mockReadCtxResult = ERR_OK;
        mgr.mockSubProfileCtx = SubProfileContext();
    }
};

/* ============================================================
 * GetForegroundIndex — 3 uncovered branches
 * ============================================================ */

HWTEST_F(AppAccountSubspaceCoverageTest, GetForegroundIndex_QueryFail, TestSize.Level1)
{
    auto &mgr = IInnerOsAccountManager::GetInstance();
    mgr.mockQueryResult = ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    int32_t foregroundIndex = -1;
    EXPECT_FALSE(AppAccountControlManager::GetForegroundIndex(100, foregroundIndex));
    EXPECT_EQ(foregroundIndex, -1);
}

HWTEST_F(AppAccountSubspaceCoverageTest, GetForegroundIndex_ReadCtxFail, TestSize.Level1)
{
    auto &mgr = IInnerOsAccountManager::GetInstance();
    mgr.mockQueryResult = ERR_OK;
    mgr.mockOsAccountInfo.SetForegroundSubProfileId(1001);
    mgr.mockReadCtxResult = ERR_ACCOUNT_COMMON_FILE_NOT_EXIST;
    int32_t foregroundIndex = -1;
    EXPECT_FALSE(AppAccountControlManager::GetForegroundIndex(100, foregroundIndex));
    EXPECT_EQ(foregroundIndex, -1);
}

HWTEST_F(AppAccountSubspaceCoverageTest, GetForegroundIndex_FgIdNotFound, TestSize.Level1)
{
    auto &mgr = IInnerOsAccountManager::GetInstance();
    mgr.mockQueryResult = ERR_OK;
    mgr.mockOsAccountInfo.SetForegroundSubProfileId(9999);
    mgr.mockReadCtxResult = ERR_OK;
    mgr.mockSubProfileCtx.subProfileIndexMap.clear();
    mgr.mockSubProfileCtx.subProfileIndexMap[1] = 1001;
    int32_t foregroundIndex = -1;
    EXPECT_FALSE(AppAccountControlManager::GetForegroundIndex(100, foregroundIndex));
    EXPECT_EQ(foregroundIndex, -1);
}

/* ============================================================
 * IsAppIndexVisibleWithFg — 2 uncovered branches
 * ============================================================ */

HWTEST_F(AppAccountSubspaceCoverageTest, IsAppIndexVisibleWithFg_NoForeground, TestSize.Level1)
{
    EXPECT_FALSE(AppAccountControlManager::IsAppIndexVisibleWithFg(0, 1, -1));
    EXPECT_FALSE(AppAccountControlManager::IsAppIndexVisibleWithFg(1, 0, -1));
    EXPECT_FALSE(AppAccountControlManager::IsAppIndexVisibleWithFg(2, 3, -1));
}

HWTEST_F(AppAccountSubspaceCoverageTest, IsAppIndexVisibleWithFg_HeadlessForegroundPair, TestSize.Level1)
{
    EXPECT_TRUE(AppAccountControlManager::IsAppIndexVisibleWithFg(0, 1, 1));
    EXPECT_TRUE(AppAccountControlManager::IsAppIndexVisibleWithFg(1, 0, 1));
    EXPECT_FALSE(AppAccountControlManager::IsAppIndexVisibleWithFg(1, 2, 1));
    EXPECT_FALSE(AppAccountControlManager::IsAppIndexVisibleWithFg(2, 1, 1));
}

/* ============================================================
 * QueryVisibleEnabledAppIndex — 1 uncovered branch (both disabled)
 * ============================================================ */

HWTEST_F(AppAccountSubspaceCoverageTest, QueryVisibleEnabledAppIndex_BothDisabled, TestSize.Level1)
{
    uint32_t appIndex = 999;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(
        STRING_BOTH_DISABLED, 0, 100, appIndex);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appIndex, 0u);
}

/* ============================================================
 * AppAccountInfo — 3 uncovered branches (macro ON)
 * ============================================================ */

HWTEST_F(AppAccountSubspaceCoverageTest, EnableAppAccess_DuplicateV7, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1));
    ErrCode result = info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1));
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ENABLE_APP_ACCESS_ALREADY_EXISTS);
}

HWTEST_F(AppAccountSubspaceCoverageTest, EnableAppAccess_Overflow, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    for (uint32_t i = 0; i <= MAX_AUTH; i++) {
        std::string bundle = "com.example.app" + std::to_string(i);
        ErrCode result = info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp(bundle, i));
        if (i < MAX_AUTH) {
            EXPECT_EQ(result, ERR_OK);
        } else {
            EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_LIST_MAX_SIZE);
        }
    }
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), static_cast<size_t>(MAX_AUTH));
}

HWTEST_F(AppAccountSubspaceCoverageTest, DisableAppAccess_NotExistV7, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(BUNDLE_NAME);
    info.SetName("account1");
    ErrCode result = info.DisableAppAccess(AppAccountInfo::EncodeAuthorizedApp(BUNDLE_NAME, 1));
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_DISABLE_APP_ACCESS_NOT_EXISTED);
}

/* ============================================================
 * Control manager instance — #ifdef success paths
 * ============================================================ */

HWTEST_F(AppAccountSubspaceCoverageTest, EnableAppAccess_SubspaceSuccess, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_account");
    ErrCode result = info.EnableAppAccess(
        AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1), Constants::API_VERSION9);
    EXPECT_EQ(result, ERR_OK);
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), 1u);
    EXPECT_NE(apps.find(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1)), apps.end());
}

HWTEST_F(AppAccountSubspaceCoverageTest, CheckAppAccess_Subspace, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_account");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1));
    bool isAccessible = false;
    ErrCode result = info.CheckAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1), isAccessible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(isAccessible);
    isAccessible = true;
    result = info.CheckAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 2), isAccessible);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(isAccessible);
}

HWTEST_F(AppAccountSubspaceCoverageTest, DisableAppAccess_SubspaceSuccess, TestSize.Level1)
{
    AppAccountInfo info;
    info.SetOwner(STRING_OWNER);
    info.SetName("test_account");
    info.EnableAppAccess(AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1));
    ErrCode result = info.DisableAppAccess(
        AppAccountInfo::EncodeAuthorizedApp("com.example.app", 1), Constants::API_VERSION9);
    EXPECT_EQ(result, ERR_OK);
    std::set<std::string> apps;
    info.GetAuthorizedApps(apps);
    EXPECT_EQ(apps.size(), 0u);
}

/* ============================================================
 * QueryVisibleEnabledAppIndex — BMS query failure (L-03 blocking path)
 * ============================================================ */

HWTEST_F(AppAccountSubspaceCoverageTest, QueryVisibleEnabledAppIndex_BundleNotExist, TestSize.Level1)
{
    // Unknown bundle -> GetMainAndCloneBundleInfo fails. QueryVisibleEnabledAppIndex masks the
    // bundle error as ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO (tested here). The upper wrappers
    // ResolveAppIndex / ResolveAndEncodeAuthorizedApp fall back to the caller's raw appIndex on
    // this failure (they do NOT propagate 12300002), so OAuth/Enable/Disable proceed and surface
    // as 12300003 (account not found) or success, matching the acts spec.
    // Under non-subspace no query is performed (macro-isolated), appIndex defaults to 0.
    // callerAppIndex=1 (non-headless) keeps GetForegroundCandidates from calling GetForegroundIndex.
    uint32_t appIndex = 999;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(
        STRING_NOT_EXIST, 1, 100, appIndex);
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO);
#else
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(appIndex, 0u);
#endif
}

/* ============================================================
 * ownerAppIndex resolution — value propagated by GetAllAccounts (L-04)
 * ============================================================ */

HWTEST_F(AppAccountSubspaceCoverageTest, QueryVisibleEnabledAppIndex_ResolvesOwnerEnabled, TestSize.Level1)
{
    // STRING_OWNER mock: appIndex 0 disabled, appIndex 1 enabled. Caller at appIndex 1
    // (non-headless) has candidates {1, HEADLESS(0)}; the owner's enabled appIndex 1 is
    // visible -> resolves to 1. This ownerAppIndex is what GetAllAccounts now propagates
    // under subspace (L-04) to load the owner's partition owner#1 instead of the caller's.
    uint32_t ownerAppIndex = 999;
    ErrCode result = AppAccountControlManager::QueryVisibleEnabledAppIndex(
        STRING_OWNER, 1, 100, ownerAppIndex);
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(ownerAppIndex, 1u);
#else
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(ownerAppIndex, 0u);
#endif
}

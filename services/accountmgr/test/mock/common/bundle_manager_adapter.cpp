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
#include "os_account_constants.h"
#include "bundle_manager_adapter.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string TEST_AUTH_APP_BUNDLE = "com.example.authapp";
const std::string PERMISSION_START_SYSTEM_DIALOG = "ohos.permission.START_SYSTEM_DIALOG";
const std::string STRING_BUNDLE_NAME_NOT_INSTALLED = "com.example.not_installed";
const std::string STRING_BUNDLE_GET_FAIL = "com.example.get_fail";
const std::string STRING_OWNER = "com.example.owner";
const std::string STRING_DISABLED_OWNER = "com.example.disabled.owner";
const std::string STRING_SUBPROFILE_AUTH_EXTENSION = "com.example.subprofile.auth.extension";
const std::string STRING_SUBPROFILE_AUTH_ABILITY = "com.example.subprofile.auth.ability";
const std::string STRING_SUBPROFILE_AUTH_DISABLED = "com.example.subprofile.auth.disabled";
const std::string STRING_BOTH_DISABLED_OWNER = "com.example.both.disabled";
const std::string STRING_NORMAL_BUNDLENAME = "com.example.normal.bundle";
const std::string STRING_BUNDLEINFO_WITH_NO_VALID_EXTENSION = "com.bundleInfo.noExtension";
const std::string STRING_BUNDLEINFO_WITH_NO_VALID_TYPE_EXTENSION = "com.bundleInfo.noValidTypeExtension";
const std::string STRING_BUNDLEINFO_WITH_MULTIPLE_VALID_EXTENSION = "com.bundleInfo.noExtension";
const std::string STRING_ABILITY_NAME = "com.example.owner.MainAbility";
const std::string STRING_ABILITY_NAME_TWO = "com.example.owner.MainAbility2";
const std::string STRING_ABILITY_NAME_WITH_NO_INFO = "com.example.owner.MainAbilityWithNoInfo";
const std::string STRING_ABILITY_NAME_WITH_CONNECT_FAILED = "com.example.MainAbilityWithConnectFailed";
const std::string STRING_ABILITY_NAME_WITH_NO_PROXY = "com.example.MainAbilityWithNoProxy";
constexpr int32_t TEST_ACCESS_TOKEN_ID_NORMAL_BUNDLE = 789012;
constexpr int32_t TEST_ACCESS_TOKEN_ID_AUTH_APP = 100001;
constexpr int32_t TEST_ACCESS_TOKEN_ID_OWNER = 123456;
}  // namespace

BundleManagerAdapter *BundleManagerAdapter::GetInstance()
{
    static BundleManagerAdapter *instance = new (std::nothrow) BundleManagerAdapter();
    return instance;
}

BundleManagerAdapter::BundleManagerAdapter()
{
    ACCOUNT_LOGI("create BundleManagerAdapter mock");
}

BundleManagerAdapter::~BundleManagerAdapter()
{
    ACCOUNT_LOGI("destroy BundleManagerAdapter mock");
}

ErrCode BundleManagerAdapter::CreateNewUser(int32_t userId, const std::vector<std::string> &disallowedHapList,
    const std::optional<std::vector<std::string>> &allowedHapList)
{
    ACCOUNT_LOGI("CreateNewUser mock");
    return ERR_OK;
}

ErrCode BundleManagerAdapter::RemoveUser(int32_t userId)
{
    ACCOUNT_LOGI("RemoveUser mock");
    return ERR_OK;
}

ErrCode BundleManagerAdapter::GetNameForUid(const int uid, std::string &bundleName)
{
    ACCOUNT_LOGI("mock enter, uid = %{public}d", uid);
    bundleName = STRING_OWNER;
    ACCOUNT_LOGI("mock bundleName = %{public}s", bundleName.c_str());
    return g_resultCode;
}

ErrCode BundleManagerAdapter::CreateNewBundleDir(int32_t userId)
{
    ACCOUNT_LOGI("RemoveUser mock");
    return ERR_OK;
}

bool GetSubprofileBundleInfo(const std::string &bundleName, AppExecFwk::BundleInfo &bundleInfo);

static bool HandleExtensionBundle(const std::string &bundleName, AppExecFwk::BundleInfo &bundleInfo)
{
    if (bundleName == STRING_NORMAL_BUNDLENAME) {
        bundleInfo.applicationInfo.accessTokenId = TEST_ACCESS_TOKEN_ID_NORMAL_BUNDLE;
        AppExecFwk::ExtensionAbilityInfo ext;
        ext.name = STRING_ABILITY_NAME;
        ext.type = AppExecFwk::ExtensionAbilityType::APP_ACCOUNT_AUTHORIZATION;
        bundleInfo.extensionInfos.emplace_back(ext);
        return true;
    }
    if (bundleName == STRING_BUNDLEINFO_WITH_NO_VALID_EXTENSION) {
        return true;
    }
    if (bundleName == STRING_BUNDLEINFO_WITH_NO_VALID_TYPE_EXTENSION) {
        AppExecFwk::ExtensionAbilityInfo ext;
        ext.name = STRING_ABILITY_NAME;
        bundleInfo.extensionInfos.emplace_back(ext);
        return true;
    }
    if (bundleName == STRING_BUNDLEINFO_WITH_MULTIPLE_VALID_EXTENSION) {
        AppExecFwk::ExtensionAbilityInfo ext1;
        ext1.name = STRING_ABILITY_NAME;
        ext1.type = AppExecFwk::ExtensionAbilityType::APP_ACCOUNT_AUTHORIZATION;
        bundleInfo.extensionInfos.emplace_back(ext1);
        AppExecFwk::ExtensionAbilityInfo ext2;
        ext2.name = STRING_ABILITY_NAME_TWO;
        ext2.type = AppExecFwk::ExtensionAbilityType::APP_ACCOUNT_AUTHORIZATION;
        bundleInfo.extensionInfos.emplace_back(ext2);
        return true;
    }
    return false;
}

bool BundleManagerAdapter::GetBundleInfo(const std::string &bundleName, const AppExecFwk::BundleFlag flag,
    AppExecFwk::BundleInfo &bundleInfo, int32_t userId)
{
    ACCOUNT_LOGI("mock enter, bundleName = %{public}s, userId = %{public}d.", bundleName.c_str(), userId);
    if (bundleName == STRING_BUNDLE_NAME_NOT_INSTALLED || bundleName == STRING_BUNDLE_GET_FAIL) {
        return false;
    }
    if (HandleExtensionBundle(bundleName, bundleInfo)) {
        return true;
    }
    if (bundleName == TEST_AUTH_APP_BUNDLE) {
        bundleInfo.reqPermissions.emplace_back(PERMISSION_START_SYSTEM_DIALOG);
        bundleInfo.applicationInfo.accessTokenId = TEST_ACCESS_TOKEN_ID_AUTH_APP;
        return true;
    }
    if (GetSubprofileBundleInfo(bundleName, bundleInfo)) {
        return true;
    }
    // Subprofile extension/ability bundles are not installed as regular bundles
    if (bundleName == STRING_SUBPROFILE_AUTH_EXTENSION ||
        bundleName == STRING_SUBPROFILE_AUTH_ABILITY ||
        bundleName == STRING_SUBPROFILE_AUTH_DISABLED) {
        return false;
    }
    return true;
}

bool GetSubprofileBundleInfo(const std::string &bundleName, AppExecFwk::BundleInfo &bundleInfo)
{
    if (bundleName == STRING_OWNER) {
        bundleInfo.applicationInfo.accessTokenId = TEST_ACCESS_TOKEN_ID_OWNER;
        bundleInfo.applicationInfo.enabled = true;
        return true;
    }
    if (bundleName == STRING_DISABLED_OWNER) {
        bundleInfo.applicationInfo.enabled = false;
        return true;
    }
    return false;
}

ErrCode BundleManagerAdapter::IsBundleInstalled(const std::string &bundleName, int32_t userId,
    int32_t &appIndex, bool &isBundleInstalled)
{
    ACCOUNT_LOGI("mock enter, bundleName = %{public}s, userId = %{public}d.", bundleName.c_str(), userId);
    // test not installed
    if (userId == Constants::MAINTENANCE_MODE_ID) {
        isBundleInstalled = false;
    } else {
        isBundleInstalled = true;
    }
    return ERR_OK;
}

const std::string STRING_SUBPROFILE_AUTH_ABILITY_NAME = "AuthServiceAbility";

bool BundleManagerAdapter::QueryAbilityInfos(const AAFwk::Want &want, int32_t flags, int32_t userId,
    std::vector<AppExecFwk::AbilityInfo> &abilityInfos)
{
    ACCOUNT_LOGI("mock enter, userId = %{public}d", userId);
    std::string bundleName = want.GetBundle();
    if (bundleName == STRING_SUBPROFILE_AUTH_ABILITY) {
        AppExecFwk::AbilityInfo abilityInfo;
        abilityInfo.name = STRING_SUBPROFILE_AUTH_ABILITY_NAME;
        abilityInfo.type = AppExecFwk::AbilityType::SERVICE;
        abilityInfo.visible = true;
        abilityInfo.appIndex = 0;
        abilityInfo.applicationInfo.enabled = true;
        abilityInfos.emplace_back(abilityInfo);
        return true;
    }
    if (bundleName == STRING_OWNER) {
        AppExecFwk::AbilityInfo abilityInfo;
        abilityInfo.name = STRING_SUBPROFILE_AUTH_ABILITY_NAME;
        abilityInfo.type = AppExecFwk::AbilityType::SERVICE;
        abilityInfo.visible = true;
        abilityInfo.appIndex = 1;
        abilityInfo.applicationInfo.enabled = true;
        abilityInfos.emplace_back(abilityInfo);
        return true;
    }
    if (bundleName == STRING_DISABLED_OWNER) {
        AppExecFwk::AbilityInfo abilityInfo;
        abilityInfo.name = STRING_SUBPROFILE_AUTH_ABILITY_NAME;
        abilityInfo.type = AppExecFwk::AbilityType::SERVICE;
        abilityInfo.visible = true;
        abilityInfo.appIndex = 1;
        abilityInfo.applicationInfo.enabled = false;
        abilityInfos.emplace_back(abilityInfo);
        return true;
    }
    return false;
}

bool BundleManagerAdapter::QueryExtensionAbilityInfos(const AAFwk::Want &want, const int32_t &flag,
    const int32_t &userId, std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    ACCOUNT_LOGI("mock enter, userId = %{public}d", userId);
    std::string bundleName = want.GetBundle();
    if (bundleName == STRING_SUBPROFILE_AUTH_EXTENSION) {
        AppExecFwk::ExtensionAbilityInfo extensionInfo;
        extensionInfo.name = STRING_SUBPROFILE_AUTH_ABILITY_NAME;
        extensionInfo.type = AppExecFwk::ExtensionAbilityType::SERVICE;
        extensionInfo.visible = true;
        extensionInfo.appIndex = 1;
        extensionInfo.applicationInfo.enabled = true;
        extensionInfos.emplace_back(extensionInfo);
        return true;
    }
    if (bundleName == STRING_SUBPROFILE_AUTH_DISABLED) {
        AppExecFwk::ExtensionAbilityInfo extensionInfo;
        extensionInfo.name = STRING_SUBPROFILE_AUTH_ABILITY_NAME;
        extensionInfo.type = AppExecFwk::ExtensionAbilityType::SERVICE;
        extensionInfo.visible = true;
        extensionInfo.appIndex = 1;
        extensionInfo.applicationInfo.enabled = false;
        extensionInfos.emplace_back(extensionInfo);
        return true;
    }
    if (bundleName == STRING_DISABLED_OWNER) {
        AppExecFwk::ExtensionAbilityInfo extensionInfo;
        extensionInfo.name = STRING_SUBPROFILE_AUTH_ABILITY_NAME;
        extensionInfo.type = AppExecFwk::ExtensionAbilityType::SERVICE;
        extensionInfo.visible = true;
        extensionInfo.appIndex = 0;
        extensionInfo.applicationInfo.enabled = false;
        extensionInfos.emplace_back(extensionInfo);
        return true;
    }
    return false;
}

ErrCode BundleManagerAdapter::QueryExtensionAbilityInfosV9(const AAFwk::Want &want, int32_t flags, int32_t userId,
    std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    ACCOUNT_LOGI("mock V9 enter, userId = %{public}d", userId);
    bool ret = QueryExtensionAbilityInfos(want, flags, userId, extensionInfos);
    return ret ? ERR_OK : ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO;
}

bool BundleManagerAdapter::QueryExtensionAbilityInfos(
    const AAFwk::Want &want, const AppExecFwk::ExtensionAbilityType &extensionType,
    const int32_t &flag, const int32_t &userId, std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    ACCOUNT_LOGI("mock enter, userId = %{public}d", userId);
    AppExecFwk::ElementName element = want.GetElement();
    std::string abilityName = element.GetAbilityName();
    ACCOUNT_LOGI("mock enter, abilityName = %{public}s", abilityName.c_str());
    if ((abilityName == STRING_ABILITY_NAME) || (abilityName == STRING_ABILITY_NAME_WITH_CONNECT_FAILED) ||
        (abilityName == STRING_ABILITY_NAME_WITH_NO_PROXY)) {
        AppExecFwk::ExtensionAbilityInfo extensionInfo;
        extensionInfo.name = abilityName;
        extensionInfo.type = AppExecFwk::ExtensionAbilityType::APP_ACCOUNT_AUTHORIZATION;
        extensionInfos.emplace_back(extensionInfo);
        return true;
    }
    if (abilityName == STRING_ABILITY_NAME_WITH_NO_INFO) {
        return true;
    }
    return false;
}

int BundleManagerAdapter::GetUidByBundleName(const std::string &bundleName, const int userId)
{
    ACCOUNT_LOGI("mock enter, bundleName = %{public}s, userId = %{public}d.", bundleName.c_str(), userId);
    return -1;
}

static void AddBundleEntry(std::vector<AppExecFwk::BundleInfo> &infos, int32_t appIndex, bool enabled)
{
    AppExecFwk::BundleInfo info;
    info.applicationInfo.appIndex = appIndex;
    info.applicationInfo.enabled = enabled;
    infos.emplace_back(info);
}

ErrCode BundleManagerAdapter::GetMainAndCloneBundleInfo(
    const std::string &bundleName, int32_t flags, int32_t userId,
    std::vector<AppExecFwk::BundleInfo> &bundleInfos)
{
    ACCOUNT_LOGI("mock enter, bundleName = %{public}s, userId = %{public}d", bundleName.c_str(), userId);
    bundleInfos.clear();
    if (bundleName == STRING_OWNER) {
        AddBundleEntry(bundleInfos, 0, false);
        AddBundleEntry(bundleInfos, 1, true);
        return ERR_OK;
    }
    if (bundleName == STRING_DISABLED_OWNER) {
        AddBundleEntry(bundleInfos, 0, true);
        AddBundleEntry(bundleInfos, 1, false);
        return ERR_OK;
    }
    if (bundleName == STRING_SUBPROFILE_AUTH_ABILITY) {
        AddBundleEntry(bundleInfos, 0, true);
        return ERR_OK;
    }
    if (bundleName == STRING_SUBPROFILE_AUTH_EXTENSION) {
        AddBundleEntry(bundleInfos, 0, false);
        AddBundleEntry(bundleInfos, 1, true);
        return ERR_OK;
    }
    if (bundleName == STRING_SUBPROFILE_AUTH_DISABLED) {
        AddBundleEntry(bundleInfos, 0, true);
        AddBundleEntry(bundleInfos, 1, false);
        return ERR_OK;
    }
    if (bundleName == STRING_BOTH_DISABLED_OWNER) {
        AddBundleEntry(bundleInfos, 0, false);
        AddBundleEntry(bundleInfos, 1, false);
        return ERR_OK;
    }
    return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
}
}  // namespace AccountSA
}  // namespace OHOS
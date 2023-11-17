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
#include "bundle_manager_adapter.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string STRING_BUNDLE_NAME_NOT_INSTALLED = "com.example.not_installed";
const std::string STRING_OWNER = "com.example.owner";
const std::string STRING_NORMAL_BUNDLENAME = "com.example.normal.bundle";
const std::string STRING_BUNDLEINFO_WITH_NO_VALID_EXTENSION = "com.bundleInfo.noExtension";
const std::string STRING_BUNDLEINFO_WITH_NO_VALID_TYPE_EXTENSION = "com.bundleInfo.noValidTypeExtension";
const std::string STRING_BUNDLEINFO_WITH_MULTIPLE_VALID_EXTENSION = "com.bundleInfo.noExtension";
const std::string STRING_ABILITY_NAME = "com.example.owner.MainAbility";
const std::string STRING_ABILITY_NAME_TWO = "com.example.owner.MainAbility2";
const std::string STRING_ABILITY_NAME_WITH_NO_INFO = "com.example.owner.MainAbilityWithNoInfo";
const std::string STRING_ABILITY_NAME_WITH_CONNECT_FAILED = "com.example.MainAbilityWithConnectFailed";
const std::string STRING_ABILITY_NAME_WITH_NO_PROXY = "com.example.MainAbilityWithNoProxy";
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

ErrCode BundleManagerAdapter::CreateNewUser(int32_t userId, const std::vector<std::string> &disallowedHapList)
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
    return ERR_OK;
}

bool BundleManagerAdapter::GetBundleInfo(const std::string &bundleName, const AppExecFwk::BundleFlag flag,
    AppExecFwk::BundleInfo &bundleInfo, int32_t userId)
{
    ACCOUNT_LOGI("mock enter, bundleName = %{public}s", bundleName.c_str());
    if (bundleName == STRING_BUNDLE_NAME_NOT_INSTALLED) {
        return false;
    }
    if (bundleName == STRING_NORMAL_BUNDLENAME) {
        AppExecFwk::ExtensionAbilityInfo extensionInfo;
        extensionInfo.name = STRING_ABILITY_NAME;
        extensionInfo.type = AppExecFwk::ExtensionAbilityType::APP_ACCOUNT_AUTHORIZATION;
        bundleInfo.extensionInfos.emplace_back(extensionInfo);
        return true;
    }
    if (bundleName == STRING_BUNDLEINFO_WITH_NO_VALID_EXTENSION) {
        return true;
    }
    if (bundleName == STRING_BUNDLEINFO_WITH_NO_VALID_TYPE_EXTENSION) {
        AppExecFwk::ExtensionAbilityInfo extensionInfo;
        extensionInfo.name = STRING_ABILITY_NAME;
        bundleInfo.extensionInfos.emplace_back(extensionInfo);
        return true;
    }
    if (bundleName == STRING_BUNDLEINFO_WITH_MULTIPLE_VALID_EXTENSION) {
        AppExecFwk::ExtensionAbilityInfo extensionInfo1;
        extensionInfo1.name = STRING_ABILITY_NAME;
        extensionInfo1.type = AppExecFwk::ExtensionAbilityType::APP_ACCOUNT_AUTHORIZATION;
        bundleInfo.extensionInfos.emplace_back(extensionInfo1);
        AppExecFwk::ExtensionAbilityInfo extensionInfo2;
        extensionInfo2.name = STRING_ABILITY_NAME_TWO;
        extensionInfo2.type = AppExecFwk::ExtensionAbilityType::APP_ACCOUNT_AUTHORIZATION;
        bundleInfo.extensionInfos.emplace_back(extensionInfo2);
        return true;
    }
    return true;
}

bool BundleManagerAdapter::QueryAbilityInfos(const AAFwk::Want &want, int32_t flags, int32_t userId,
    std::vector<AppExecFwk::AbilityInfo> &abilityInfos)
{
    ACCOUNT_LOGI("mock enter, userId = %{public}d", userId);
    return false;
}

bool BundleManagerAdapter::QueryExtensionAbilityInfos(const AAFwk::Want &want, const int32_t &flag,
    const int32_t &userId, std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    ACCOUNT_LOGI("mock enter, userId = %{public}d", userId);
    return false;
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
}  // namespace AccountSA
}  // namespace OHOS
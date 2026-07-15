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

#include "app_account_authenticator_manager.h"

#include <algorithm>
#include "account_error_no.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "app_account_constants.h"
#include "bundle_manager_adapter.h"
#include "account_hisysevent_adapter.h"
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
#include "app_account_control_manager.h"
#endif

namespace OHOS {
namespace AccountSA {
namespace {
const char SYSTEM_ACTION_APP_ACCOUNT_AUTH[] = "ohos.appAccount.action.auth";
const char SYSTEM_ACTION_APP_ACCOUNT_OAUTH[] = "ohos.account.appAccount.action.oauth";
}

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
static bool QueryAbilityAndExtension(AAFwk::Want &want, int32_t userId,
    std::vector<AppExecFwk::AbilityInfo> &abilityInfos,
    std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    int32_t abilityFlag = AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES
        | AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION
        | AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_DISABLE;
    int32_t extensionFlag = static_cast<int32_t>(
        AppExecFwk::GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION)
        | static_cast<int32_t>(AppExecFwk::GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_DISABLE);
    bool result = BundleManagerAdapter::GetInstance()->QueryAbilityInfos(
        want, abilityFlag, userId, abilityInfos);
    ErrCode ret = BundleManagerAdapter::GetInstance()->QueryExtensionAbilityInfosV9(
        want, extensionFlag, userId, extensionInfos);
    return result || (ret == ERR_OK);
}
#endif

static ErrCode QueryAbilityInfos(const std::string &owner, int32_t userId,
    std::vector<AppExecFwk::AbilityInfo> &abilityInfos,
    std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    AAFwk::Want want;
    want.SetBundle(owner);
    want.SetAction(SYSTEM_ACTION_APP_ACCOUNT_AUTH);
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    if (!QueryAbilityAndExtension(want, userId, abilityInfos, extensionInfos)) {
        want.SetAction(SYSTEM_ACTION_APP_ACCOUNT_OAUTH);
        if (!QueryAbilityAndExtension(want, userId, abilityInfos, extensionInfos)) {
            return ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST;
        }
    }
    return ERR_OK;
#else
    bool result = BundleManagerAdapter::GetInstance()->QueryAbilityInfos(
        want, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, userId, abilityInfos);
    if (!result) {
        result = BundleManagerAdapter::GetInstance()->QueryExtensionAbilityInfos(
            want, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, userId, extensionInfos);
    }
    if (!result) {
        want.SetAction(SYSTEM_ACTION_APP_ACCOUNT_OAUTH);
        result = BundleManagerAdapter::GetInstance()->QueryAbilityInfos(
            want, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, userId, abilityInfos);
    }
    if (!result) {
        result = BundleManagerAdapter::GetInstance()->QueryExtensionAbilityInfos(
            want, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, userId, extensionInfos);
    }
    if (!result) {
        ACCOUNT_LOGE("failed to query ability info");
        REPORT_APP_ACCOUNT_FAIL("", owner, Constants::APP_DFX_GET_AUTHENTICATOR_INFO,
            ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST, "Query ability info failed");
        return ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST;
    }
    return ERR_OK;
#endif
}

ErrCode AppAccountAuthenticatorManager::GetAuthenticatorInfo(
    const std::string &owner, uint32_t callerAppIndex, int32_t userId, AuthenticatorInfo &info)
{
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    ErrCode ret = QueryAbilityInfos(owner, userId, abilityInfos, extensionInfos);
    if (ret != ERR_OK) {
        return ret;
    }
    if (FillAuthenticatorInfoFromAbilities(abilityInfos, callerAppIndex, userId, owner, info) ||
        FillAuthenticatorInfoFromExtensions(extensionInfos, callerAppIndex, userId, owner, info)) {
        return ERR_OK;
    }
    REPORT_APP_ACCOUNT_FAIL("", owner, Constants::APP_DFX_AUTHENTICATOR_SESSION,
        ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST, "No authenticator ability found");
    return ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST;
}

bool AppAccountAuthenticatorManager::FillAuthenticatorInfoFromAbilities(
    const std::vector<AppExecFwk::AbilityInfo> &abilityInfos, uint32_t callerAppIndex,
    int32_t userId, const std::string &owner, AuthenticatorInfo &info)
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    int32_t foregroundIndex = -1;
    AppAccountControlManager::GetForegroundIndex(userId, foregroundIndex);
    auto iter = std::find_if(abilityInfos.begin(), abilityInfos.end(),
        [callerAppIndex, foregroundIndex](const AppExecFwk::AbilityInfo &ai) {
            return (ai.type == AppExecFwk::AbilityType::SERVICE) && (ai.visible)
                && (ai.applicationInfo.enabled)
                && AppAccountControlManager::IsAppIndexVisibleWithFg(callerAppIndex,
                    static_cast<uint32_t>(ai.appIndex), foregroundIndex);
        });
#else
    auto iter = std::find_if(abilityInfos.begin(), abilityInfos.end(),
        [](const AppExecFwk::AbilityInfo &ai) {
            return (ai.type == AppExecFwk::AbilityType::SERVICE) && (ai.visible) && (ai.appIndex == 0);
        });
#endif
    if (iter != abilityInfos.end()) {
        info.owner = owner;
        info.abilityName = iter->name;
        info.iconId = iter->iconId;
        info.labelId = iter->labelId;
        return true;
    }
    return false;
}

bool AppAccountAuthenticatorManager::FillAuthenticatorInfoFromExtensions(
    const std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos, uint32_t callerAppIndex,
    int32_t userId, const std::string &owner, AuthenticatorInfo &info)
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    int32_t foregroundIndex = -1;
    AppAccountControlManager::GetForegroundIndex(userId, foregroundIndex);
    auto iter = std::find_if(extensionInfos.begin(), extensionInfos.end(),
        [callerAppIndex, foregroundIndex](const AppExecFwk::ExtensionAbilityInfo &ei) {
            return (ei.type == AppExecFwk::ExtensionAbilityType::SERVICE) && (ei.visible)
                && (ei.applicationInfo.enabled)
                && AppAccountControlManager::IsAppIndexVisibleWithFg(callerAppIndex,
                    static_cast<uint32_t>(ei.appIndex), foregroundIndex);
        });
#else
    auto iter = std::find_if(extensionInfos.begin(), extensionInfos.end(),
        [](const AppExecFwk::ExtensionAbilityInfo &ei) {
            return (ei.type == AppExecFwk::ExtensionAbilityType::SERVICE) && (ei.visible) && (ei.appIndex == 0);
        });
#endif
    if (iter != extensionInfos.end()) {
        info.owner = owner;
        info.abilityName = iter->name;
        info.iconId = iter->iconId;
        info.labelId = iter->labelId;
        return true;
    }
    return false;
}
}  // namespace AccountSA
}  // namespace OHOS

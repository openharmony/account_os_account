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

#include "app_account_authenticator_manager.h"

#include <algorithm>
#include "account_error_no.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "app_account_constants.h"
#include "bundle_manager_adapter.h"

namespace OHOS {
namespace AccountSA {
AppAccountAuthenticatorManager::AppAccountAuthenticatorManager()
{}

AppAccountAuthenticatorManager::~AppAccountAuthenticatorManager()
{}

static ErrCode QueryAbilityInfos(const std::string &owner, int32_t userId,
    std::vector<AppExecFwk::AbilityInfo> &abilityInfos,
    std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    AAFwk::Want want;
    want.SetBundle(owner);
    want.SetAction(Constants::SYSTEM_ACTION_APP_ACCOUNT_AUTH);
    bool result = BundleManagerAdapter::GetInstance()->QueryAbilityInfos(
        want, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, userId, abilityInfos);
    if (!result) {
        result = BundleManagerAdapter::GetInstance()->QueryExtensionAbilityInfos(
            want, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, userId, extensionInfos);
    }
    if (!result) {
        want.SetAction(Constants::SYSTEM_ACTION_APP_ACCOUNT_OAUTH);
        result = BundleManagerAdapter::GetInstance()->QueryAbilityInfos(
            want, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, userId, abilityInfos);
    }
    if (!result) {
        result = BundleManagerAdapter::GetInstance()->QueryExtensionAbilityInfos(
            want, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, userId, extensionInfos);
    }
    if (!result) {
        ACCOUNT_LOGE("failed to query ability info");
        return ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode AppAccountAuthenticatorManager::GetAuthenticatorInfo(
    const std::string &owner, int32_t userId, AuthenticatorInfo &info)
{
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    ErrCode ret = QueryAbilityInfos(owner, userId, abilityInfos, extensionInfos);
    if (ret != ERR_OK) {
        return ret;
    }

    auto iter = std::find_if(abilityInfos.begin(), abilityInfos.end(),
        [abilityInfos](AppExecFwk::AbilityInfo abilityInfo) {
            return ((abilityInfo.type == AppExecFwk::AbilityType::SERVICE) && (abilityInfo.visible));
        });
    if (iter != abilityInfos.end()) {
        info.owner = owner;
        info.abilityName = iter->name;
        info.iconId = iter->iconId;
        info.labelId = iter->labelId;
        return ERR_OK;
    }

    auto iter_extensionInfos = std::find_if(extensionInfos.begin(), extensionInfos.end(),
        [extensionInfos](AppExecFwk::ExtensionAbilityInfo extensionInfo) {
            return ((extensionInfo.type == AppExecFwk::ExtensionAbilityType::SERVICE) && (extensionInfo.visible));
        });
    if (iter_extensionInfos != extensionInfos.end()) {
        info.owner = owner;
        info.abilityName = iter_extensionInfos->name;
        info.iconId = iter_extensionInfos->iconId;
        info.labelId = iter_extensionInfos->labelId;
        return ERR_OK;
    }
    return ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST;
}
}  // namespace AccountSA
}  // namespace OHOS
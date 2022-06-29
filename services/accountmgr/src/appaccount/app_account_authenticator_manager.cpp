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

#include "account_error_no.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "app_account_constants.h"
#include "bundle_manager_adapter.h"

namespace OHOS {
namespace AccountSA {
AppAccountAuthenticatorManager::AppAccountAuthenticatorManager()
{
    ACCOUNT_LOGD("enter");
    Init();
}

AppAccountAuthenticatorManager::~AppAccountAuthenticatorManager()
{
    ACCOUNT_LOGD("enter");
}

void AppAccountAuthenticatorManager::Init()
{
    ACCOUNT_LOGD("enter");
    if (isInitialized_) {
        ACCOUNT_LOGD("app account authenticator manager has been initialized");
        return;
    }
    isInitialized_ = true;
}

ErrCode AppAccountAuthenticatorManager::GetAuthenticatorInfo(
    const std::string &owner, int32_t userId, AuthenticatorInfo &info)
{
    if (!isInitialized_) {
        Init();
    }

    AAFwk::Want want;
    want.SetBundle(owner);
    want.SetAction(Constants::SYSTEM_ACTION_APP_ACCOUNT_OAUTH);
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    bool result = BundleManagerAdapter::GetInstance()->QueryAbilityInfos(
        want, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, userId, abilityInfos);
    if (!result) {
        result = BundleManagerAdapter::GetInstance()->QueryExtensionAbilityInfos(
            want, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, userId, extensionInfos);
    }
    if (!result) {
        ACCOUNT_LOGE("failed to query ability info");
        return ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST;
    }
    for (auto abilityInfo: abilityInfos) {
        if ((abilityInfo.type == AppExecFwk::AbilityType::SERVICE) && (abilityInfo.visible)) {
            info.owner = owner;
            info.abilityName = abilityInfo.name;
            info.iconId = abilityInfo.iconId;
            info.labelId = abilityInfo.labelId;
            return ERR_OK;
        }
    }
    for (auto extensionInfo: extensionInfos) {
        if ((extensionInfo.type == AppExecFwk::ExtensionAbilityType::SERVICE) && (extensionInfo.visible)) {
            info.owner = owner;
            info.abilityName = extensionInfo.name;
            info.iconId = extensionInfo.iconId;
            info.labelId = extensionInfo.labelId;
            return ERR_OK;
        }
    }
    return ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST;
}
}  // namespace AccountSA
}  // namespace OHOS

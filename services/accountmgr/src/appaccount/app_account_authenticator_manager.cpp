/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "ability_info.h"
#include "account_error_no.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "app_account_constants.h"
#include "bundle_info.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
AppAccountAuthenticatorManager::AppAccountAuthenticatorManager()
{
    ACCOUNT_LOGI("enter");
    Init();
}

AppAccountAuthenticatorManager::~AppAccountAuthenticatorManager()
{
    ACCOUNT_LOGI("enter");
}

void AppAccountAuthenticatorManager::Init()
{
    ACCOUNT_LOGI("enter");
    if (isInitialized_) {
        ACCOUNT_LOGI("app account authenticator manager has been initialized");
        return;
    }
    sptr<ISystemAbilityManager> samgrClient = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrClient == nullptr) {
        ACCOUNT_LOGE("failed to system ability manager");
        return;
    }
    bundleMgr_ = iface_cast<AppExecFwk::IBundleMgr>(
        samgrClient->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID));
    if (bundleMgr_ == nullptr) {
        ACCOUNT_LOGE("failed to get bms");
        return;
    }
    isInitialized_ = true;
}

ErrCode AppAccountAuthenticatorManager::GetAuthenticatorInfo(const OAuthRequest &request, AuthenticatorInfo &info)
{
    if (!isInitialized_) {
        Init();
    }
    if (bundleMgr_ == nullptr) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST;
    }
    AAFwk::Want want;
    want.SetBundle(request.owner);
    want.SetAction(Constants::SYSTEM_ACTION_APP_ACCOUNT_OAUTH);
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    int32_t userId = request.callerUid / UID_TRANSFORM_DIVISOR;
    bool result = bundleMgr_->QueryAbilityInfos(
        want, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, userId, abilityInfos);
    if (!result) {
        ACCOUNT_LOGE("failed to query ability info");
        return ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST;
    }
    for (auto abilityInfo: abilityInfos) {
        if ((abilityInfo.type == AppExecFwk::AbilityType::SERVICE) && (abilityInfo.visible)) {
            info.owner = request.owner;
            info.abilityName = abilityInfo.name;
            info.iconId = abilityInfo.iconId;
            info.labelId = abilityInfo.labelId;
            return ERR_OK;
        }
    }
    return ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST;
}
}  // namespace AccountSA
}  // namespace OHOS

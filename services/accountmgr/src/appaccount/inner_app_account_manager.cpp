/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "account_log_wrapper.h"
#include "app_account_authenticator_session.h"
#include "app_account_control_manager.h"
#include "app_account_subscribe_manager.h"

#include "inner_app_account_manager.h"

namespace OHOS {
namespace AccountSA {
InnerAppAccountManager::InnerAppAccountManager()
    : controlManagerPtr_(AppAccountControlManager::GetInstance()),
      subscribeManagerPtr_(AppAccountSubscribeManager::GetInstance()),
      sessionManagerPtr_(AppAccountAuthenticatorSessionManager::GetInstance()),
      authenticatorManagerPtr_(AppAccountAuthenticatorManager::GetInstance())
{
    ACCOUNT_LOGI("enter");
}

InnerAppAccountManager::~InnerAppAccountManager()
{}

ErrCode InnerAppAccountManager::AddAccount(
    const std::string &name, const std::string &extraInfo, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s, extraInfo = %{public}s.", name.c_str(), extraInfo.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->AddAccount(name, extraInfo, uid, bundleName, appAccountInfo);

    return result;
}

ErrCode InnerAppAccountManager::AddAccountImplicitly(const OAuthRequest &request)
{
    ACCOUNT_LOGI("enter");
    if (!sessionManagerPtr_) {
        ACCOUNT_LOGE("sessionManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_SESSION_MANAGER_PTR_IS_NULLPTR;
    }
    return sessionManagerPtr_->AddAccountImplicitly(request);
}

ErrCode InnerAppAccountManager::DeleteAccount(const std::string &name, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s", name.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->DeleteAccount(name, uid, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, uid, bundleName) != true) {
        ACCOUNT_LOGI("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::GetAccountExtraInfo(
    const std::string &name, std::string &extraInfo, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s.", name.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetAccountExtraInfo(name, extraInfo, uid, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::SetAccountExtraInfo(
    const std::string &name, const std::string &extraInfo, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s, extraInfo = %{public}s.", name.c_str(), extraInfo.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->SetAccountExtraInfo(name, extraInfo, uid, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, uid, bundleName) != true) {
        ACCOUNT_LOGI("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::EnableAppAccess(
    const std::string &name, const std::string &authorizedApp, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s, authorizedApp = %{public}s.", name.c_str(), authorizedApp.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->EnableAppAccess(name, authorizedApp, uid, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, uid, bundleName) != true) {
        ACCOUNT_LOGI("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::DisableAppAccess(
    const std::string &name, const std::string &authorizedApp, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s, authorizedApp = %{public}s.", name.c_str(), authorizedApp.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->DisableAppAccess(name, authorizedApp, uid, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, uid, bundleName) != true) {
        ACCOUNT_LOGI("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::CheckAppAccountSyncEnable(
    const std::string &name, bool &syncEnable, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s.", name.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->CheckAppAccountSyncEnable(name, syncEnable, uid, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::SetAppAccountSyncEnable(
    const std::string &name, const bool &syncEnable, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s, syncEnable = %{public}d.", name.c_str(), syncEnable);

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->SetAppAccountSyncEnable(name, syncEnable, uid, bundleName, appAccountInfo);

    return result;
}

ErrCode InnerAppAccountManager::GetAssociatedData(const std::string &name, const std::string &key, std::string &value,
    const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s, key = %{public}s.", name.c_str(), key.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetAssociatedData(name, key, value, uid, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::SetAssociatedData(const std::string &name, const std::string &key,
    const std::string &value, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s, key = %{public}s, value = %{public}s.",
        name.c_str(), key.c_str(), value.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->SetAssociatedData(name, key, value, uid, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, uid, bundleName) != true) {
        ACCOUNT_LOGI("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::GetAccountCredential(const std::string &name, const std::string &credentialType,
    std::string &credential, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s, credentialType = %{public}s.", name.c_str(), credentialType.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetAccountCredential(name, credentialType, credential, uid, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::SetAccountCredential(const std::string &name, const std::string &credentialType,
    const std::string &credential, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s, credentialType = %{public}s.", name.c_str(), credentialType.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result =
        controlManagerPtr_->SetAccountCredential(name, credentialType, credential, uid, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, uid, bundleName) != true) {
        ACCOUNT_LOGI("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::Authenticate(const OAuthRequest &request)
{
    ACCOUNT_LOGI("enter");
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    std::string token;
    ErrCode result = controlManagerPtr_->GetOAuthToken(request, token);
    if (result == ERR_OK) {
        if ((request.callback != nullptr) && (request.callback->AsObject() != nullptr)) {
            AAFwk::Want result;
            result.SetParam(Constants::KEY_NAME, request.name);
            result.SetParam(Constants::KEY_AUTH_TYPE, request.authType);
            result.SetParam(Constants::KEY_TOKEN, token);
            request.callback->OnResult(ERR_OK, result);
        }
        return ERR_OK;
    }
    if (!sessionManagerPtr_) {
        ACCOUNT_LOGE("sessionManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_SESSION_MANAGER_PTR_IS_NULLPTR;
    }
    return sessionManagerPtr_->Authenticate(request);
}

ErrCode InnerAppAccountManager::GetOAuthToken(const OAuthRequest &request, std::string &token)
{
    ACCOUNT_LOGI("enter");
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    return controlManagerPtr_->GetOAuthToken(request, token);
}

ErrCode InnerAppAccountManager::SetOAuthToken(const OAuthRequest &request)
{
    ACCOUNT_LOGI("enter");
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    ErrCode result = controlManagerPtr_->SetOAuthToken(request);
    if (result != ERR_OK) {
        return result;
    }
    AppAccountInfo appAccountInfo(request.name, request.callerBundleName);
    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGI("subscribeManagerPtr_ is nullptr");
        return ERR_OK;
    }
    if (!subscribeManagerPtr_->PublishAccount(appAccountInfo, request.callerUid, request.callerBundleName)) {
        ACCOUNT_LOGI("failed to publish account");
    }
    return ERR_OK;
}

ErrCode InnerAppAccountManager::DeleteOAuthToken(const OAuthRequest &request)
{
    ACCOUNT_LOGI("enter");
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    return controlManagerPtr_->DeleteOAuthToken(request);
}
 
ErrCode InnerAppAccountManager::SetOAuthTokenVisibility(const OAuthRequest &request)
{
    ACCOUNT_LOGI("enter");
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    return controlManagerPtr_->SetOAuthTokenVisibility(request);
}

ErrCode InnerAppAccountManager::CheckOAuthTokenVisibility(const OAuthRequest &request, bool &isVisible)
{
    ACCOUNT_LOGI("enter");
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    return controlManagerPtr_->CheckOAuthTokenVisibility(request, isVisible);
}

ErrCode InnerAppAccountManager::GetAuthenticatorInfo(const OAuthRequest &request, AuthenticatorInfo &info)
{
    ACCOUNT_LOGI("enter");
    if (!authenticatorManagerPtr_) {
        ACCOUNT_LOGE("authenticatorManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_AUTHENTICATOR_MANAGER_PTR_IS_NULLPTR;
    }
    return authenticatorManagerPtr_->GetAuthenticatorInfo(request, info);
}

ErrCode InnerAppAccountManager::GetAllOAuthTokens(
    const OAuthRequest &request, std::vector<OAuthTokenInfo> &tokenInfos)
{
    ACCOUNT_LOGI("enter");
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    return controlManagerPtr_->GetAllOAuthTokens(request, tokenInfos);
}

ErrCode InnerAppAccountManager::GetOAuthList(const OAuthRequest &request, std::set<std::string> &oauthList)
{
    ACCOUNT_LOGI("enter");
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    return controlManagerPtr_->GetOAuthList(request, oauthList);
}

ErrCode InnerAppAccountManager::GetAuthenticatorCallback(const OAuthRequest &request, sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("enter");
    callback = nullptr;
    if (!sessionManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    ErrCode result = sessionManagerPtr_->GetAuthenticatorCallback(request, callback);
    ACCOUNT_LOGI("end");
    return result;
}

ErrCode InnerAppAccountManager::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts,
    const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, owner = %{public}s", owner.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetAllAccounts(owner, appAccounts, uid, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::GetAllAccessibleAccounts(
    std::vector<AppAccountInfo> &appAccounts, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetAllAccessibleAccounts(appAccounts, uid, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::SubscribeAppAccount(const AppAccountSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &eventListener, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR;
    }

    auto subscribeInfoPtr = std::make_shared<AppAccountSubscribeInfo>(subscribeInfo);
    ErrCode result = subscribeManagerPtr_->SubscribeAppAccount(subscribeInfoPtr, eventListener, uid, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = subscribeManagerPtr_->UnsubscribeAppAccount(eventListener);

    return result;
}

ErrCode InnerAppAccountManager::OnPackageRemoved(const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->OnPackageRemoved(uid, bundleName);
    return result;
}
}  // namespace AccountSA
}  // namespace OHOS

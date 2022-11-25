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

#include "inner_app_account_manager.h"

#include "account_info.h"
#include "account_log_wrapper.h"
#include "app_account_authenticator_session.h"
#include "app_account_control_manager.h"
#include "app_account_subscribe_manager.h"

namespace OHOS {
namespace AccountSA {
InnerAppAccountManager::InnerAppAccountManager()
    : controlManagerPtr_(AppAccountControlManager::GetInstance()),
      subscribeManagerPtr_(AppAccountSubscribeManager::GetInstance()),
      sessionManagerPtr_(AppAccountAuthenticatorSessionManager::GetInstance()),
      authenticatorManagerPtr_(AppAccountAuthenticatorManager::GetInstance())
{}

InnerAppAccountManager::~InnerAppAccountManager()
{}

ErrCode InnerAppAccountManager::AddAccount(const std::string &name, const std::string &extraInfo,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    appAccountInfo.SetAppIndex(appIndex);
    ErrCode result = controlManagerPtr_->AddAccount(name, extraInfo, uid, bundleName, appAccountInfo);

    return result;
}

ErrCode InnerAppAccountManager::AddAccountImplicitly(const AuthenticatorSessionRequest &request)
{
    if (!sessionManagerPtr_) {
        ACCOUNT_LOGE("sessionManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_SESSION_MANAGER_PTR_IS_NULLPTR;
    }
    return sessionManagerPtr_->AddAccountImplicitly(request);
}

ErrCode InnerAppAccountManager::CreateAccount(const std::string &name, const CreateAccountOptions &options,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    appAccountInfo.SetAppIndex(appIndex);
    ErrCode result = controlManagerPtr_->CreateAccount(name, options, uid, bundleName, appAccountInfo);

    return result;
}

ErrCode InnerAppAccountManager::CreateAccountImplicitly(const AuthenticatorSessionRequest &request)
{
    if (!sessionManagerPtr_) {
        ACCOUNT_LOGE("sessionManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_SESSION_MANAGER_PTR_IS_NULLPTR;
    }
    return sessionManagerPtr_->CreateAccountImplicitly(request);
}

ErrCode InnerAppAccountManager::DeleteAccount(
    const std::string &name, const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    appAccountInfo.SetAppIndex(appIndex);
    ErrCode result = controlManagerPtr_->DeleteAccount(name, uid, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, uid, bundleName) != true) {
        ACCOUNT_LOGE("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::GetAccountExtraInfo(const std::string &name, std::string &extraInfo,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetAccountExtraInfo(name, extraInfo, uid, bundleName, appIndex);

    return result;
}

ErrCode InnerAppAccountManager::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    appAccountInfo.SetAppIndex(appIndex);
    ErrCode result = controlManagerPtr_->SetAccountExtraInfo(name, extraInfo, uid, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, uid, bundleName) != true) {
        ACCOUNT_LOGE("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::EnableAppAccess(const std::string &name, const std::string &authorizedApp,
    AppAccountCallingInfo &appAccountCallingInfo, const uint32_t apiVersion)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, appAccountCallingInfo.bundleName);
    appAccountInfo.SetAppIndex(appAccountCallingInfo.appIndex);
    ErrCode result = controlManagerPtr_->EnableAppAccess(
        name, authorizedApp, appAccountCallingInfo, appAccountInfo, apiVersion);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(
        appAccountInfo, appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName) != true) {
        ACCOUNT_LOGE("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::DisableAppAccess(const std::string &name, const std::string &authorizedApp,
    AppAccountCallingInfo &appAccountCallingInfo, const uint32_t apiVersion)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, appAccountCallingInfo.bundleName);
    appAccountInfo.SetAppIndex(appAccountCallingInfo.appIndex);
    ErrCode result = controlManagerPtr_->DisableAppAccess(
        name, authorizedApp, appAccountCallingInfo, appAccountInfo, apiVersion);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (!subscribeManagerPtr_->PublishAccount(
        appAccountInfo, appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName)) {
        ACCOUNT_LOGE("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::CheckAppAccess(const std::string &name, const std::string &authorizedApp,
    bool &isAccessible, const AppAccountCallingInfo &appAccountCallingInfo)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    return controlManagerPtr_->CheckAppAccess(name, authorizedApp, isAccessible, appAccountCallingInfo);
}

ErrCode InnerAppAccountManager::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->CheckAppAccountSyncEnable(name, syncEnable, uid, bundleName, appIndex);

    return result;
}

ErrCode InnerAppAccountManager::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    appAccountInfo.SetAppIndex(appIndex);
    ErrCode result = controlManagerPtr_->SetAppAccountSyncEnable(name, syncEnable, uid, bundleName, appAccountInfo);

    return result;
}

ErrCode InnerAppAccountManager::GetAssociatedData(const std::string &name, const std::string &key,
    std::string &value, const uid_t &uid)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetAssociatedData(name, key, value, uid);

    return result;
}

ErrCode InnerAppAccountManager::SetAssociatedData(const std::string &name, const std::string &key,
    const std::string &value, const AppAccountCallingInfo &appAccountCallingInfo)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->SetAssociatedData(name, key, value, appAccountCallingInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
        return result;
    }
    AppAccountInfo appAccountInfo(name, appAccountCallingInfo.bundleName);
    appAccountInfo.SetAppIndex(appAccountCallingInfo.appIndex);
    if (!subscribeManagerPtr_->PublishAccount(appAccountInfo,
        appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName)) {
        ACCOUNT_LOGE("failed to publish account");
    }
    return result;
}

ErrCode InnerAppAccountManager::GetAccountCredential(const std::string &name, const std::string &credentialType,
    std::string &credential, const AppAccountCallingInfo &appAccountCallingInfo)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetAccountCredential(name, credentialType, credential, appAccountCallingInfo);

    return result;
}

ErrCode InnerAppAccountManager::SetAccountCredential(const std::string &name, const std::string &credentialType,
    const std::string &credential, const AppAccountCallingInfo &appAccountCallingInfo)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result =
        controlManagerPtr_->SetAccountCredential(name, credentialType, credential, appAccountCallingInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
        return result;
    }
    AppAccountInfo appAccountInfo(name, appAccountCallingInfo.bundleName);
    appAccountInfo.SetAppIndex(appAccountCallingInfo.appIndex);
    if (subscribeManagerPtr_->PublishAccount(appAccountInfo,
        appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName) != true) {
        ACCOUNT_LOGE("failed to publish account");
    }
    return result;
}

ErrCode InnerAppAccountManager::DeleteAccountCredential(const std::string &name, const std::string &credentialType,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = uid;
    appAccountCallingInfo.bundleName = bundleName;
    appAccountCallingInfo.appIndex = appIndex;
    ErrCode result = controlManagerPtr_->SetAccountCredential(name, credentialType, "", appAccountCallingInfo, true);
    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
        return result;
    }
    AppAccountInfo appAccountInfo(name, bundleName);
    appAccountInfo.SetAppIndex(appIndex);
    if (subscribeManagerPtr_->PublishAccount(appAccountInfo, uid, bundleName) != true) {
        ACCOUNT_LOGE("failed to publish account");
    }
    return result;
}

ErrCode InnerAppAccountManager::Authenticate(const AuthenticatorSessionRequest &request)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    std::string token;
    ErrCode ret = ERR_OK;
    bool isApi9 = request.options.GetBoolParam(Constants::API_V9, false);
    if (isApi9) {
        ret = controlManagerPtr_->GetOAuthToken(request, token, Constants::API_VERSION9);
    } else {
        ret = controlManagerPtr_->GetOAuthToken(request, token);
    }
    if (ret == ERR_OK) {
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

    if (isApi9) {
        return sessionManagerPtr_->Auth(request);
    }
    return sessionManagerPtr_->Authenticate(request);
}

ErrCode InnerAppAccountManager::GetOAuthToken(
    const AuthenticatorSessionRequest &request, std::string &token, const uint32_t apiVersion)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    return controlManagerPtr_->GetOAuthToken(request, token, apiVersion);
}

ErrCode InnerAppAccountManager::SetOAuthToken(const AuthenticatorSessionRequest &request)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    ErrCode result = controlManagerPtr_->SetOAuthToken(request);
    if (result != ERR_OK) {
        return result;
    }
    AppAccountInfo appAccountInfo(request.name, request.callerBundleName);
    appAccountInfo.SetAppIndex(request.appIndex);
    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGI("subscribeManagerPtr_ is nullptr");
        return ERR_OK;
    }
    if (!subscribeManagerPtr_->PublishAccount(appAccountInfo, request.callerUid, request.callerBundleName)) {
        ACCOUNT_LOGE("failed to publish account");
    }
    return ERR_OK;
}

ErrCode InnerAppAccountManager::DeleteOAuthToken(const AuthenticatorSessionRequest &request, const uint32_t apiVersion)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    return controlManagerPtr_->DeleteOAuthToken(request, apiVersion);
}

ErrCode InnerAppAccountManager::SetOAuthTokenVisibility(
    const AuthenticatorSessionRequest &request, const uint32_t apiVersion)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    return controlManagerPtr_->SetOAuthTokenVisibility(request, apiVersion);
}

ErrCode InnerAppAccountManager::CheckOAuthTokenVisibility(
    const AuthenticatorSessionRequest &request, bool &isVisible, const uint32_t apiVersion)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    return controlManagerPtr_->CheckOAuthTokenVisibility(request, isVisible, apiVersion);
}

ErrCode InnerAppAccountManager::GetAuthenticatorInfo(
    const AuthenticatorSessionRequest &request, AuthenticatorInfo &info)
{
    if (!authenticatorManagerPtr_) {
        ACCOUNT_LOGE("authenticatorManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_AUTHENTICATOR_MANAGER_PTR_IS_NULLPTR;
    }
    int32_t userId = request.callerUid / UID_TRANSFORM_DIVISOR;
    return authenticatorManagerPtr_->GetAuthenticatorInfo(request.owner, userId, info);
}

ErrCode InnerAppAccountManager::GetAllOAuthTokens(
    const AuthenticatorSessionRequest &request, std::vector<OAuthTokenInfo> &tokenInfos)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    return controlManagerPtr_->GetAllOAuthTokens(request, tokenInfos);
}

ErrCode InnerAppAccountManager::GetOAuthList(
    const AuthenticatorSessionRequest &request, std::set<std::string> &oauthList, const uint32_t apiVersion)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    return controlManagerPtr_->GetOAuthList(request, oauthList, apiVersion);
}

ErrCode InnerAppAccountManager::GetAuthenticatorCallback(
    const AuthenticatorSessionRequest &request, sptr<IRemoteObject> &callback)
{
    callback = nullptr;
    if (!sessionManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    ErrCode result = sessionManagerPtr_->GetAuthenticatorCallback(request, callback);

    return result;
}

ErrCode InnerAppAccountManager::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetAllAccounts(owner, appAccounts, uid, bundleName, appIndex);

    return result;
}

ErrCode InnerAppAccountManager::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetAllAccessibleAccounts(appAccounts, uid, bundleName, appIndex);

    return result;
}

ErrCode InnerAppAccountManager::SelectAccountsByOptions(
    const SelectAccountsOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    AuthenticatorSessionRequest request;
    ErrCode result = controlManagerPtr_->SelectAccountsByOptions(options, callback, uid, bundleName, appIndex);
    return result;
}

ErrCode InnerAppAccountManager::VerifyCredential(const AuthenticatorSessionRequest &request)
{
    if (!sessionManagerPtr_) {
        ACCOUNT_LOGE("sessionManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_SESSION_MANAGER_PTR_IS_NULLPTR;
    }
    return sessionManagerPtr_->VerifyCredential(request);
}

ErrCode InnerAppAccountManager::CheckAccountLabels(const AuthenticatorSessionRequest &request)
{
    if (!sessionManagerPtr_) {
        ACCOUNT_LOGE("sessionManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_SESSION_MANAGER_PTR_IS_NULLPTR;
    }
    return sessionManagerPtr_->CheckAccountLabels(request);
}

ErrCode InnerAppAccountManager::SetAuthenticatorProperties(const AuthenticatorSessionRequest &request)
{
    if (!sessionManagerPtr_) {
        ACCOUNT_LOGE("sessionManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    return sessionManagerPtr_->SetAuthenticatorProperties(request);
}

ErrCode InnerAppAccountManager::SubscribeAppAccount(const AppAccountSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &eventListener, const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR;
    }

    auto subscribeInfoPtr = std::make_shared<AppAccountSubscribeInfo>(subscribeInfo);
    ErrCode result = subscribeManagerPtr_->
        SubscribeAppAccount(subscribeInfoPtr, eventListener, uid, bundleName, appIndex);

    return result;
}

ErrCode InnerAppAccountManager::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = subscribeManagerPtr_->UnsubscribeAppAccount(eventListener);

    return result;
}

ErrCode InnerAppAccountManager::OnPackageRemoved(
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->OnPackageRemoved(uid, bundleName, appIndex);
    return result;
}

ErrCode InnerAppAccountManager::OnUserRemoved(int32_t userId)
{
    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }
    return controlManagerPtr_->OnUserRemoved(userId);
}
}  // namespace AccountSA
}  // namespace OHOS

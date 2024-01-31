/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "ability_manager_adapter.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "app_account_authenticator_session.h"
#include "app_account_control_manager.h"
#include "app_account_subscribe_manager.h"
#include "app_account_authorization_extension_callback_service.h"
#include "app_account_authorization_extension_stub.h"
#include "bundle_manager_adapter.h"

namespace OHOS {
namespace AccountSA {
InnerAppAccountManager::InnerAppAccountManager()
    : controlManager_(AppAccountControlManager::GetInstance()),
      subscribeManager_(AppAccountSubscribeManager::GetInstance()),
      sessionManager_(AppAccountAuthenticatorSessionManager::GetInstance())
{}

InnerAppAccountManager::~InnerAppAccountManager()
{}

ErrCode InnerAppAccountManager::AddAccount(const std::string &name, const std::string &extraInfo,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    AppAccountInfo appAccountInfo(name, bundleName);
    appAccountInfo.SetAppIndex(appIndex);
    return controlManager_.AddAccount(name, extraInfo, uid, bundleName, appAccountInfo);
}

ErrCode InnerAppAccountManager::AddAccountImplicitly(const AuthenticatorSessionRequest &request)
{
    return sessionManager_.AddAccountImplicitly(request);
}

ErrCode InnerAppAccountManager::CreateAccount(const std::string &name, const CreateAccountOptions &options,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    AppAccountInfo appAccountInfo(name, bundleName);
    appAccountInfo.SetAppIndex(appIndex);
    return controlManager_.CreateAccount(name, options, uid, bundleName, appAccountInfo);
}

ErrCode InnerAppAccountManager::CreateAccountImplicitly(const AuthenticatorSessionRequest &request)
{
    return sessionManager_.CreateAccountImplicitly(request);
}

ErrCode InnerAppAccountManager::DeleteAccount(
    const std::string &name, const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    AppAccountInfo appAccountInfo(name, bundleName);
    appAccountInfo.SetAppIndex(appIndex);
    ErrCode result = controlManager_.DeleteAccount(name, uid, bundleName, appAccountInfo);
    if ((result == ERR_OK) && (!subscribeManager_.PublishAccount(appAccountInfo, uid, bundleName))) {
        ACCOUNT_LOGE("failed to publish account");
    }
    return result;
}

ErrCode InnerAppAccountManager::GetAccountExtraInfo(const std::string &name, std::string &extraInfo,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    return controlManager_.GetAccountExtraInfo(name, extraInfo, uid, bundleName, appIndex);
}

ErrCode InnerAppAccountManager::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    AppAccountInfo appAccountInfo(name, bundleName);
    appAccountInfo.SetAppIndex(appIndex);
    ErrCode result = controlManager_.SetAccountExtraInfo(name, extraInfo, uid, bundleName, appAccountInfo);
    if ((result == ERR_OK) && (!subscribeManager_.PublishAccount(appAccountInfo, uid, bundleName))) {
        ACCOUNT_LOGE("failed to publish account");
    }
    return result;
}

ErrCode InnerAppAccountManager::EnableAppAccess(const std::string &name, const std::string &authorizedApp,
    AppAccountCallingInfo &appAccountCallingInfo, const uint32_t apiVersion)
{
    AppAccountInfo appAccountInfo(name, appAccountCallingInfo.bundleName);
    appAccountInfo.SetAppIndex(appAccountCallingInfo.appIndex);
    ErrCode result = controlManager_.EnableAppAccess(
        name, authorizedApp, appAccountCallingInfo, appAccountInfo, apiVersion);
    if ((result == ERR_OK) && (!subscribeManager_.PublishAccount(
        appAccountInfo, appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName))) {
        ACCOUNT_LOGE("failed to publish account");
    }
    return result;
}

ErrCode InnerAppAccountManager::DisableAppAccess(const std::string &name, const std::string &authorizedApp,
    AppAccountCallingInfo &appAccountCallingInfo, const uint32_t apiVersion)
{
    AppAccountInfo appAccountInfo(name, appAccountCallingInfo.bundleName);
    appAccountInfo.SetAppIndex(appAccountCallingInfo.appIndex);
    ErrCode result = controlManager_.DisableAppAccess(
        name, authorizedApp, appAccountCallingInfo, appAccountInfo, apiVersion);
    if ((result == ERR_OK) && (!subscribeManager_.PublishAccount(
        appAccountInfo, appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName))) {
        ACCOUNT_LOGE("failed to publish account");
    }
    return result;
}

ErrCode InnerAppAccountManager::CheckAppAccess(const std::string &name, const std::string &authorizedApp,
    bool &isAccessible, const AppAccountCallingInfo &appAccountCallingInfo)
{
    return controlManager_.CheckAppAccess(name, authorizedApp, isAccessible, appAccountCallingInfo);
}

ErrCode InnerAppAccountManager::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    return controlManager_.CheckAppAccountSyncEnable(name, syncEnable, uid, bundleName, appIndex);
}

ErrCode InnerAppAccountManager::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    AppAccountInfo appAccountInfo(name, bundleName);
    appAccountInfo.SetAppIndex(appIndex);
    return controlManager_.SetAppAccountSyncEnable(name, syncEnable, uid, bundleName, appAccountInfo);
}

ErrCode InnerAppAccountManager::GetAssociatedData(const std::string &name, const std::string &key,
    std::string &value, const uid_t &uid)
{
    return controlManager_.GetAssociatedData(name, key, value, uid);
}

ErrCode InnerAppAccountManager::SetAssociatedData(const std::string &name, const std::string &key,
    const std::string &value, const AppAccountCallingInfo &appAccountCallingInfo)
{
    ErrCode result = controlManager_.SetAssociatedData(name, key, value, appAccountCallingInfo);
    if (result != ERR_OK) {
        return result;
    }
    AppAccountInfo appAccountInfo(name, appAccountCallingInfo.bundleName);
    appAccountInfo.SetAppIndex(appAccountCallingInfo.appIndex);
    if (!subscribeManager_.PublishAccount(appAccountInfo,
        appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName)) {
        ACCOUNT_LOGE("failed to publish account");
    }
    return result;
}

ErrCode InnerAppAccountManager::GetAccountCredential(const std::string &name, const std::string &credentialType,
    std::string &credential, const AppAccountCallingInfo &appAccountCallingInfo)
{
    return controlManager_.GetAccountCredential(name, credentialType, credential, appAccountCallingInfo);
}

ErrCode InnerAppAccountManager::SetAccountCredential(const std::string &name, const std::string &credentialType,
    const std::string &credential, const AppAccountCallingInfo &appAccountCallingInfo)
{
    ErrCode result = controlManager_.SetAccountCredential(name, credentialType, credential, appAccountCallingInfo);
    if (result != ERR_OK) {
        return result;
    }
    AppAccountInfo appAccountInfo(name, appAccountCallingInfo.bundleName);
    appAccountInfo.SetAppIndex(appAccountCallingInfo.appIndex);
    if (!subscribeManager_.PublishAccount(appAccountInfo,
        appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName)) {
        ACCOUNT_LOGE("failed to publish account");
    }
    return result;
}

ErrCode InnerAppAccountManager::DeleteAccountCredential(const std::string &name, const std::string &credentialType,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = uid;
    appAccountCallingInfo.bundleName = bundleName;
    appAccountCallingInfo.appIndex = appIndex;
    ErrCode result = controlManager_.DeleteAccountCredential(name, credentialType, appAccountCallingInfo);
    if (result != ERR_OK) {
        return result;
    }
    AppAccountInfo appAccountInfo(name, bundleName);
    appAccountInfo.SetAppIndex(appIndex);
    if (!subscribeManager_.PublishAccount(appAccountInfo, uid, bundleName)) {
        ACCOUNT_LOGE("failed to publish account");
    }
    return result;
}

ErrCode InnerAppAccountManager::Authenticate(const AuthenticatorSessionRequest &request)
{
    std::string token;
    ErrCode ret = ERR_OK;
    bool isApi9 = request.options.GetBoolParam(Constants::API_V9, false);
    if (isApi9) {
        ret = controlManager_.GetOAuthToken(request, token, Constants::API_VERSION9);
    } else {
        ret = controlManager_.GetOAuthToken(request, token);
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
    if (isApi9) {
        return sessionManager_.Auth(request);
    }
    return sessionManager_.Authenticate(request);
}

ErrCode InnerAppAccountManager::GetOAuthToken(
    const AuthenticatorSessionRequest &request, std::string &token, const uint32_t apiVersion)
{
    return controlManager_.GetOAuthToken(request, token, apiVersion);
}

ErrCode InnerAppAccountManager::SetOAuthToken(const AuthenticatorSessionRequest &request)
{
    ErrCode result = controlManager_.SetOAuthToken(request);
    if (result != ERR_OK) {
        return result;
    }
    AppAccountInfo appAccountInfo(request.name, request.callerBundleName);
    appAccountInfo.SetAppIndex(request.appIndex);
    if (!subscribeManager_.PublishAccount(appAccountInfo, request.callerUid, request.callerBundleName)) {
        ACCOUNT_LOGE("failed to publish account");
    }
    return ERR_OK;
}

ErrCode InnerAppAccountManager::DeleteOAuthToken(const AuthenticatorSessionRequest &request, const uint32_t apiVersion)
{
    return controlManager_.DeleteOAuthToken(request, apiVersion);
}

ErrCode InnerAppAccountManager::SetOAuthTokenVisibility(
    const AuthenticatorSessionRequest &request, const uint32_t apiVersion)
{
    return controlManager_.SetOAuthTokenVisibility(request, apiVersion);
}

ErrCode InnerAppAccountManager::CheckOAuthTokenVisibility(
    const AuthenticatorSessionRequest &request, bool &isVisible, const uint32_t apiVersion)
{
    return controlManager_.CheckOAuthTokenVisibility(request, isVisible, apiVersion);
}

ErrCode InnerAppAccountManager::GetAuthenticatorInfo(
    const AuthenticatorSessionRequest &request, AuthenticatorInfo &info)
{
    return AppAccountAuthenticatorManager::GetAuthenticatorInfo(
        request.owner, request.callerUid / UID_TRANSFORM_DIVISOR, info);
}

ErrCode InnerAppAccountManager::GetAllOAuthTokens(
    const AuthenticatorSessionRequest &request, std::vector<OAuthTokenInfo> &tokenInfos)
{
    return controlManager_.GetAllOAuthTokens(request, tokenInfos);
}

ErrCode InnerAppAccountManager::GetOAuthList(
    const AuthenticatorSessionRequest &request, std::set<std::string> &oauthList, const uint32_t apiVersion)
{
    return controlManager_.GetOAuthList(request, oauthList, apiVersion);
}

ErrCode InnerAppAccountManager::GetAuthenticatorCallback(
    const AuthenticatorSessionRequest &request, sptr<IRemoteObject> &callback)
{
    callback = nullptr;
    return sessionManager_.GetAuthenticatorCallback(request, callback);
}

ErrCode InnerAppAccountManager::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    return controlManager_.GetAllAccounts(owner, appAccounts, uid, bundleName, appIndex);
}

ErrCode InnerAppAccountManager::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    return controlManager_.GetAllAccessibleAccounts(appAccounts, uid, bundleName, appIndex);
}

ErrCode InnerAppAccountManager::SelectAccountsByOptions(
    const SelectAccountsOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    AuthenticatorSessionRequest request;
    return controlManager_.SelectAccountsByOptions(options, callback, uid, bundleName, appIndex);
}

ErrCode InnerAppAccountManager::VerifyCredential(const AuthenticatorSessionRequest &request)
{
    return sessionManager_.VerifyCredential(request);
}

ErrCode InnerAppAccountManager::CheckAccountLabels(const AuthenticatorSessionRequest &request)
{
    return sessionManager_.CheckAccountLabels(request);
}

ErrCode InnerAppAccountManager::SetAuthenticatorProperties(const AuthenticatorSessionRequest &request)
{
    return sessionManager_.SetAuthenticatorProperties(request);
}

ErrCode InnerAppAccountManager::SubscribeAppAccount(const AppAccountSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &eventListener, const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    auto subscribeInfoPtr = std::make_shared<AppAccountSubscribeInfo>(subscribeInfo);
    return subscribeManager_.SubscribeAppAccount(subscribeInfoPtr, eventListener, uid, bundleName, appIndex);
}

ErrCode InnerAppAccountManager::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    return subscribeManager_.UnsubscribeAppAccount(eventListener);
}

ErrCode InnerAppAccountManager::OnPackageRemoved(
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    return controlManager_.OnPackageRemoved(uid, bundleName, appIndex);
}

ErrCode InnerAppAccountManager::OnUserRemoved(int32_t userId)
{
    return controlManager_.OnUserRemoved(userId);
}
}  // namespace AccountSA
}  // namespace OHOS

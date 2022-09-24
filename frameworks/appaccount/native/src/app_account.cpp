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

#include "app_account.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_proxy.h"
#include "app_account_common.h"
#include "app_account_constants.h"
#include "app_account_death_recipient.h"
#include "iaccount.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
#define RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(str)         \
    if (CheckSpecialCharacters(str) != ERR_OK) {            \
        ACCOUNT_LOGE("failed to check special characters"); \
        return ERR_APPACCOUNT_KIT_INVALID_PARAMETER;        \
    }                                                       \

#define RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(str, maxSize, msg)                                                \
    if ((str).empty() || ((str).size() > (maxSize))) {                                                            \
        ACCOUNT_LOGE("%{public}s, input size: %{public}zu, max size: %{public}zu", msg, (str).size(), maxSize); \
        return ERR_APPACCOUNT_KIT_INVALID_PARAMETER;                                                            \
    }

#define RETURN_IF_STRING_IS_OVERSIZE(str, maxSize, msg)                                                         \
    if ((str).size() > (maxSize)) {                                                                             \
        ACCOUNT_LOGE("%{public}s, input size: %{public}zu, max size: %{public}zu", msg, (str).size(), maxSize); \
        return ERR_APPACCOUNT_KIT_INVALID_PARAMETER;                                                            \
    }                                                                                                           \

#define RETURN_IF_PROXY_IS_NULLPTR()                        \
    do {                                                    \
        ErrCode err = GetAppAccountProxy();                 \
        if (err != ERR_OK) {                                \
            ACCOUNT_LOGE("failed to get appAccountProxy_"); \
            return err;                                     \
        }                                                   \
    } while (0)                                             \

ErrCode AppAccount::AddAccount(const std::string &name, const std::string &extraInfo)
{
    ACCOUNT_LOGD("enter");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_OVERSIZE(extraInfo, Constants::EXTRA_INFO_MAX_SIZE, "extraInfo is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->AddAccount(name, extraInfo);
}

ErrCode AppAccount::AddAccountImplicitly(const std::string &owner, const std::string &authType,
    const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    sptr<IRemoteObject> callbackObj = nullptr;
    if (callback != nullptr) {
        callbackObj = callback->AsObject();
    }
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(options.GetStringParam(Constants::KEY_CALLER_ABILITY_NAME),
        Constants::ABILITY_NAME_MAX_SIZE, "abilityName is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->AddAccountImplicitly(owner, authType, options, callbackObj);
}

ErrCode AppAccount::DeleteAccount(const std::string &name)
{
    ACCOUNT_LOGD("enter");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->DeleteAccount(name);
}

ErrCode AppAccount::GetAccountExtraInfo(const std::string &name, std::string &extraInfo)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_OVERSIZE(extraInfo, Constants::EXTRA_INFO_MAX_SIZE, "extraInfo is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->GetAccountExtraInfo(name, extraInfo);
}

ErrCode AppAccount::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_OVERSIZE(extraInfo, Constants::EXTRA_INFO_MAX_SIZE, "extraInfo is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->SetAccountExtraInfo(name, extraInfo);
}

ErrCode AppAccount::EnableAppAccess(const std::string &name, const std::string &bundleName)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->EnableAppAccess(name, bundleName);
}

ErrCode AppAccount::DisableAppAccess(const std::string &name, const std::string &bundleName)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->DisableAppAccess(name, bundleName);
}

ErrCode AppAccount::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->CheckAppAccountSyncEnable(name, syncEnable);
}

ErrCode AppAccount::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->SetAppAccountSyncEnable(name, syncEnable);
}

ErrCode AppAccount::GetAssociatedData(const std::string &name, const std::string &key, std::string &value)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(key, Constants::ASSOCIATED_KEY_MAX_SIZE, "key is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->GetAssociatedData(name, key, value);
}

ErrCode AppAccount::SetAssociatedData(const std::string &name, const std::string &key, const std::string &value)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(key, Constants::ASSOCIATED_KEY_MAX_SIZE, "key is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(value, Constants::ASSOCIATED_VALUE_MAX_SIZE, "value is oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->SetAssociatedData(name, key, value);
}

ErrCode AppAccount::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(credentialType, Constants::CREDENTIAL_TYPE_MAX_SIZE,
        "credentialType is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->GetAccountCredential(name, credentialType, credential);
}

ErrCode AppAccount::SetAccountCredential(
    const std::string &name, const std::string &credentialType, const std::string &credential)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(credentialType, Constants::CREDENTIAL_TYPE_MAX_SIZE,
        "credentialType is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(credential, Constants::CREDENTIAL_MAX_SIZE, "credential is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->SetAccountCredential(name, credentialType, credential);
}

ErrCode AppAccount::Authenticate(const std::string &name, const std::string &owner, const std::string &authType,
    const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    sptr<IRemoteObject> callbackObj = nullptr;
    if (callback != nullptr) {
        callbackObj = callback->AsObject();
    }
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(options.GetStringParam(Constants::KEY_CALLER_ABILITY_NAME),
        Constants::ABILITY_NAME_MAX_SIZE, "abilityName is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->Authenticate(name, owner, authType, options, callbackObj);
}

ErrCode AppAccount::GetOAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->GetOAuthToken(name, owner, authType, token);
}

ErrCode AppAccount::SetOAuthToken(const std::string &name, const std::string &authType, const std::string &token)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    RETURN_IF_STRING_IS_OVERSIZE(token, Constants::TOKEN_MAX_SIZE, "token is oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->SetOAuthToken(name, authType, token);
}

ErrCode AppAccount::DeleteOAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, const std::string &token)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    RETURN_IF_STRING_IS_OVERSIZE(token, Constants::TOKEN_MAX_SIZE, "token is oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->DeleteOAuthToken(name, owner, authType, token);
}

ErrCode AppAccount::SetOAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool isVisible)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->SetOAuthTokenVisibility(name, authType, bundleName, isVisible);
}

ErrCode AppAccount::CheckOAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool &isVisible)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->CheckOAuthTokenVisibility(name, authType, bundleName, isVisible);
}

ErrCode AppAccount::GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &info)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->GetAuthenticatorInfo(owner, info);
}

ErrCode AppAccount::GetAllOAuthTokens(
    const std::string &name, const std::string &owner, std::vector<OAuthTokenInfo> &tokenInfos)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->GetAllOAuthTokens(name, owner, tokenInfos);
}

ErrCode AppAccount::GetOAuthList(
    const std::string &name, const std::string &authType, std::set<std::string> &oauthList)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->GetOAuthList(name, authType, oauthList);
}

ErrCode AppAccount::GetAuthenticatorCallback(const std::string &sessionId, sptr<IRemoteObject> &callback)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(sessionId, Constants::SESSION_ID_MAX_SIZE,
        "session id is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->GetAuthenticatorCallback(sessionId, callback);
}

ErrCode AppAccount::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->GetAllAccounts(owner, appAccounts);
}

ErrCode AppAccount::CheckAppAccess(const std::string &name, const std::string &authorizedApp, bool &isAccessible)
{
    ACCOUNT_LOGD("enter");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(authorizedApp, Constants::BUNDLE_NAME_MAX_SIZE,
        "authorizedApp is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    ErrCode result = appAccountProxy_->CheckAppAccess(name, authorizedApp, isAccessible);
    return result;
}

ErrCode AppAccount::DeleteAccountCredential(const std::string &name, const std::string &credentialType)
{
    ACCOUNT_LOGD("enter");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(credentialType, Constants::CREDENTIAL_TYPE_MAX_SIZE,
        "credential type is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->DeleteAccountCredential(name, credentialType);
}

ErrCode AppAccount::SelectAccountsByOptions(
    const SelectAccountsOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    ACCOUNT_LOGD("enter");
    if (callback == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return ERR_APPACCOUNT_KIT_INVALID_PARAMETER;
    }
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->SelectAccountsByOptions(options, callback->AsObject());
}

ErrCode AppAccount::VerifyCredential(const std::string &name, const std::string &owner,
    const VerifyCredentialOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    ACCOUNT_LOGD("enter");
    if (callback == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return ERR_APPACCOUNT_KIT_INVALID_PARAMETER;
    }
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->VerifyCredential(name, owner, options, callback->AsObject());
}

ErrCode AppAccount::CheckAccountLabels(const std::string &name, const std::string &owner,
    const std::vector<std::string> &labels, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    ACCOUNT_LOGD("enter");
    if (callback == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return ERR_APPACCOUNT_KIT_INVALID_PARAMETER;
    }
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->CheckAccountLabels(name, owner, labels, callback->AsObject());
}

ErrCode AppAccount::SetAuthenticatorProperties(const std::string &owner,
    const SetPropertiesOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    ACCOUNT_LOGD("enter");
    if (callback == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return ERR_APPACCOUNT_KIT_INVALID_PARAMETER;
    }
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->SetAuthenticatorProperties(owner, options, callback->AsObject());
}

ErrCode AppAccount::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGD("enter");
    RETURN_IF_PROXY_IS_NULLPTR();
    return appAccountProxy_->GetAllAccessibleAccounts(appAccounts);
}

ErrCode AppAccount::SubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber)
{
    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return ERR_APPACCOUNT_KIT_SUBSCRIBER_IS_NULLPTR;
    }

    AppAccountSubscribeInfo subscribeInfo;
    if (subscriber->GetSubscribeInfo(subscribeInfo) != ERR_OK) {
        ACCOUNT_LOGE("get subscribeInfo failed");
        return ERR_APPACCOUNT_KIT_GET_SUBSCRIBE_INFO;
    }

    std::vector<std::string> owners;
    if (subscribeInfo.GetOwners(owners) != ERR_OK) {
        ACCOUNT_LOGE("failed to get owners");
        return ERR_APPACCOUNT_KIT_GET_OWNERS;
    }

    ACCOUNT_LOGD("owners.size() = %{public}zu", owners.size());
    if (owners.size() == 0) {
        return ERR_APPACCOUNT_KIT_SUBSCRIBER_HAS_NO_OWNER;
    }

    // remove duplicate ones
    std::sort(owners.begin(), owners.end());
    owners.erase(std::unique(owners.begin(), owners.end()), owners.end());
    ACCOUNT_LOGD("owners.size() = %{public}zu", owners.size());
    if (subscribeInfo.SetOwners(owners) != ERR_OK) {
        ACCOUNT_LOGE("failed to set owners");
        return ERR_APPACCOUNT_KIT_SET_OWNERS;
    }

    for (auto owner : owners) {
        if (owner.size() > Constants::OWNER_MAX_SIZE) {
            ACCOUNT_LOGE("owner is out of range, owner.size() = %{public}zu", owner.size());
            return ERR_APPACCOUNT_KIT_OWNER_OUT_OF_RANGE;
        }
    }

    if (GetAppAccountProxy() != ERR_OK) {
        ACCOUNT_LOGE("app account proxy is nullptr");
        return ERR_APPACCOUNT_KIT_APP_ACCOUNT_PROXY_IS_NULLPTR;
    }

    sptr<IRemoteObject> appAccountEventListener = nullptr;
    ErrCode subscribeState = CreateAppAccountEventListener(subscriber, appAccountEventListener);
    if (subscribeState == INITIAL_SUBSCRIPTION) {
        subscribeState = appAccountProxy_->SubscribeAppAccount(subscribeInfo, appAccountEventListener);
        if (subscribeState != ERR_OK) {
            eventListeners_.erase(subscriber);
        }
        return subscribeState;
    } else if (subscribeState == ALREADY_SUBSCRIBED) {
        return ERR_OK;
    } else {
        return ERR_APPACCOUNT_KIT_SUBSCRIBE;
    }
}

ErrCode AppAccount::UnsubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber)
{
    ACCOUNT_LOGD("enter");

    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return ERR_APPACCOUNT_KIT_SUBSCRIBER_IS_NULLPTR;
    }

    if (GetAppAccountProxy() != ERR_OK) {
        ACCOUNT_LOGE("app account proxy is nullptr");
        return ERR_APPACCOUNT_KIT_APP_ACCOUNT_PROXY_IS_NULLPTR;
    }

    std::lock_guard<std::mutex> lock(eventListenersMutex_);

    auto eventListener = eventListeners_.find(subscriber);
    if (eventListener != eventListeners_.end()) {
        ErrCode result = appAccountProxy_->UnsubscribeAppAccount(eventListener->second->AsObject());
        if (result == ERR_OK) {
            eventListener->second->Stop();
            eventListeners_.erase(eventListener);
        }

        return result;
    } else {
        ACCOUNT_LOGE("no specified subscriber has been registered");
        return ERR_APPACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED;
    }
}

ErrCode AppAccount::ResetAppAccountProxy()
{
    ACCOUNT_LOGD("enter");

    std::lock_guard<std::mutex> lock(mutex_);
    if ((appAccountProxy_ != nullptr) && (appAccountProxy_->AsObject() != nullptr)) {
        appAccountProxy_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
    appAccountProxy_ = nullptr;

    return ERR_OK;
}

ErrCode AppAccount::CheckSpecialCharacters(const std::string &name)
{
    for (auto specialCharacter : Constants::SPECIAL_CHARACTERS) {
        std::size_t found = name.find(specialCharacter);
        if (found != std::string::npos) {
            ACCOUNT_LOGE("found a special character, specialCharacter = %{public}c", specialCharacter);
            return ERR_APPACCOUNT_KIT_INVALID_PARAMETER;
        }
    }

    return ERR_OK;
}

ErrCode AppAccount::GetAppAccountProxy()
{
    ACCOUNT_LOGD("enter");

    std::lock_guard<std::mutex> lock(mutex_);
    if (!appAccountProxy_) {
        sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (!systemAbilityManager) {
            ACCOUNT_LOGE("failed to get system ability manager");
            return ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER;
        }

        sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
        if (!remoteObject) {
            ACCOUNT_LOGE("failed to get account system ability");
            return ERR_APPACCOUNT_KIT_GET_ACCOUNT_SYSTEM_ABILITY;
        }

        sptr<IAccount> accountProxy = iface_cast<AccountProxy>(remoteObject);
        if ((!accountProxy) || (!accountProxy->AsObject())) {
            ACCOUNT_LOGE("failed to cast account proxy");
            return ERR_APPACCOUNT_KIT_CAST_ACCOUNT_PROXY;
        }

        auto appAccountRemoteObject = accountProxy->GetAppAccountService();
        if (!appAccountRemoteObject) {
            ACCOUNT_LOGE("failed to get app account service");
            return ERR_APPACCOUNT_KIT_GET_APP_ACCOUNT_SERVICE;
        }

        appAccountProxy_ = iface_cast<IAppAccount>(appAccountRemoteObject);
        if ((!appAccountProxy_) || (!appAccountProxy_->AsObject())) {
            ACCOUNT_LOGE("failed to cast app account proxy");
            appAccountProxy_ = nullptr;
            return ERR_APPACCOUNT_KIT_GET_APP_ACCOUNT_PROXY;
        }

        deathRecipient_ = new (std::nothrow) AppAccountDeathRecipient();
        if (!deathRecipient_) {
            ACCOUNT_LOGE("failed to create app account death recipient");
            appAccountProxy_ = nullptr;
            return ERR_APPACCOUNT_KIT_CREATE_APP_ACCOUNT_DEATH_RECIPIENT;
        }

        appAccountProxy_->AsObject()->AddDeathRecipient(deathRecipient_);
    }

    return ERR_OK;
}

ErrCode AppAccount::CreateAppAccountEventListener(
    const std::shared_ptr<AppAccountSubscriber> &subscriber, sptr<IRemoteObject> &appAccountEventListener)
{
    ACCOUNT_LOGD("enter");

    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return SUBSCRIBE_FAILED;
    }

    std::lock_guard<std::mutex> lock(eventListenersMutex_);

    auto eventListener = eventListeners_.find(subscriber);
    if (eventListener != eventListeners_.end()) {
        appAccountEventListener = eventListener->second->AsObject();
        ACCOUNT_LOGI("subscriber already has app account event listener");
        return ALREADY_SUBSCRIBED;
    } else {
        if (eventListeners_.size() == Constants::APP_ACCOUNT_SUBSCRIBER_MAX_SIZE) {
            ACCOUNT_LOGE("the maximum number of subscribers has been reached");
            return SUBSCRIBE_FAILED;
        }

        sptr<AppAccountEventListener> listener = new (std::nothrow) AppAccountEventListener(subscriber);
        if (!listener) {
            ACCOUNT_LOGE("the app account event listener is null");
            return SUBSCRIBE_FAILED;
        }
        appAccountEventListener = listener->AsObject();
        eventListeners_[subscriber] = listener;
    }

    return INITIAL_SUBSCRIPTION;
}
}  // namespace AccountSA
}  // namespace OHOS

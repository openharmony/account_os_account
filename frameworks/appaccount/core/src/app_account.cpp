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

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_proxy.h"
#include "app_account_death_recipient.h"
#include "iaccount.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "app_account.h"

namespace OHOS {
namespace AccountSA {
ErrCode AppAccount::AddAccount(const std::string &name, const std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    ErrCode result = CheckParameters(name, extraInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check parameters");
        return result;
    }

    result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->AddAccount(name, extraInfo);
}

ErrCode AppAccount::DeleteAccount(const std::string &name)
{
    ACCOUNT_LOGI("enter");

    ErrCode result = CheckParameters(name);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check parameters");
        return result;
    }

    result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->DeleteAccount(name);
}

ErrCode AppAccount::GetAccountExtraInfo(const std::string &name, std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("extraInfo = %{public}s", extraInfo.c_str());

    ErrCode result = CheckParameters(name, extraInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check parameters");
        return result;
    }

    result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->GetAccountExtraInfo(name, extraInfo);
}

ErrCode AppAccount::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("extraInfo = %{public}s", extraInfo.c_str());

    ErrCode result = CheckParameters(name, extraInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check parameters");
        return result;
    }

    result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->SetAccountExtraInfo(name, extraInfo);
}

ErrCode AppAccount::EnableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("authorizedApp = %{public}s", authorizedApp.c_str());

    ErrCode result = CheckParameters(name);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check parameters");
        return result;
    }

    if (authorizedApp.size() == 0) {
        ACCOUNT_LOGE("authorizedApp is empty");
        return ERR_APPACCOUNT_KIT_AUTHORIZED_APP_IS_EMPTY;
    }

    if (authorizedApp.size() > AUTHORIZED_APP_MAX_SIZE) {
        ACCOUNT_LOGE("authorizedApp is out of range");
        return ERR_APPACCOUNT_KIT_AUTHORIZED_APP_OUT_OF_RANGE;
    }

    result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->EnableAppAccess(name, authorizedApp);
}

ErrCode AppAccount::DisableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("authorizedApp = %{public}s", authorizedApp.c_str());

    ErrCode result = CheckParameters(name);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check parameters");
        return result;
    }

    if (authorizedApp.size() == 0) {
        ACCOUNT_LOGE("authorizedApp is empty");
        return ERR_APPACCOUNT_KIT_AUTHORIZED_APP_IS_EMPTY;
    }

    if (authorizedApp.size() > AUTHORIZED_APP_MAX_SIZE) {
        ACCOUNT_LOGE("authorizedApp is out of range");
        return ERR_APPACCOUNT_KIT_AUTHORIZED_APP_OUT_OF_RANGE;
    }

    result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->DisableAppAccess(name, authorizedApp);
}

ErrCode AppAccount::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());

    ErrCode result = CheckParameters(name);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check parameters");
        return result;
    }

    result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->CheckAppAccountSyncEnable(name, syncEnable);
}

ErrCode AppAccount::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("syncEnable = %{public}d", syncEnable);

    ErrCode result = CheckParameters(name);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check parameters");
        return result;
    }

    result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->SetAppAccountSyncEnable(name, syncEnable);
}

ErrCode AppAccount::GetAssociatedData(const std::string &name, const std::string &key, std::string &value)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("key = %{public}s", key.c_str());

    ErrCode result = CheckParameters(name);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check parameters");
        return result;
    }

    if (key.size() == 0) {
        ACCOUNT_LOGE("key is empty");
        return ERR_APPACCOUNT_KIT_ASSOCIATED_KEY_IS_EMPTY;
    }

    if (key.size() > ASSOCIATED_KEY_MAX_SIZE) {
        ACCOUNT_LOGE("key is out of range");
        return ERR_APPACCOUNT_KIT_ASSOCIATED_KEY_OUT_OF_RANGE;
    }

    result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->GetAssociatedData(name, key, value);
}

ErrCode AppAccount::SetAssociatedData(const std::string &name, const std::string &key, const std::string &value)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("key = %{public}s, value = %{public}s", key.c_str(), value.c_str());

    ErrCode result = CheckParameters(name);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check parameters");
        return result;
    }

    if (key.size() == 0) {
        ACCOUNT_LOGE("key is empty");
        return ERR_APPACCOUNT_KIT_ASSOCIATED_KEY_IS_EMPTY;
    }

    if (key.size() > ASSOCIATED_KEY_MAX_SIZE) {
        ACCOUNT_LOGE("key is out of range");
        return ERR_APPACCOUNT_KIT_ASSOCIATED_KEY_OUT_OF_RANGE;
    }

    if (value.size() > ASSOCIATED_VALUE_MAX_SIZE) {
        ACCOUNT_LOGE("value is out of range");
        return ERR_APPACCOUNT_KIT_ASSOCIATED_VALUE_OUT_OF_RANGE;
    }

    result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->SetAssociatedData(name, key, value);
}

ErrCode AppAccount::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("credentialType = %{public}s", credentialType.c_str());

    ErrCode result = CheckParameters(name);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check parameters");
        return result;
    }

    if (credentialType.size() == 0) {
        ACCOUNT_LOGE("credentialType is empty");
        return ERR_APPACCOUNT_KIT_CREDENTIAL_TYPE_IS_EMPTY;
    }

    if (credentialType.size() > CREDENTIAL_TYPE_MAX_SIZE) {
        ACCOUNT_LOGE("credentialType is out of range");
        return ERR_APPACCOUNT_KIT_CREDENTIAL_TYPE_OUT_OF_RANGE;
    };

    result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->GetAccountCredential(name, credentialType, credential);
}

ErrCode AppAccount::SetAccountCredential(
    const std::string &name, const std::string &credentialType, const std::string &credential)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("credentialType = %{public}s, credential = %{public}s", credentialType.c_str(), credential.c_str());

    ErrCode result = CheckParameters(name);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check parameters");
        return result;
    }

    if (credentialType.size() == 0) {
        ACCOUNT_LOGE("credentialType is empty");
        return ERR_APPACCOUNT_KIT_CREDENTIAL_TYPE_IS_EMPTY;
    }

    if (credentialType.size() > CREDENTIAL_TYPE_MAX_SIZE) {
        ACCOUNT_LOGE("credentialType is out of range");
        return ERR_APPACCOUNT_KIT_CREDENTIAL_TYPE_OUT_OF_RANGE;
    };

    if (credential.size() > CREDENTIAL_MAX_SIZE) {
        ACCOUNT_LOGE("credential is out of range");
        return ERR_APPACCOUNT_KIT_CREDENTIAL_OUT_OF_RANGE;
    }

    result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->SetAccountCredential(name, credentialType, credential);
}

ErrCode AppAccount::GetOAuthToken(const std::string &name, std::string &token)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("token = %{public}s", token.c_str());

    ErrCode result = CheckParameters(name);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check parameters");
        return result;
    }

    result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->GetOAuthToken(name, token);
}

ErrCode AppAccount::SetOAuthToken(const std::string &name, const std::string &token)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("token = %{public}s", token.c_str());

    ErrCode result = CheckParameters(name);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check parameters");
        return result;
    }

    if (token.size() > TOKEN_MAX_SIZE) {
        ACCOUNT_LOGE("token is out of range");
        return ERR_APPACCOUNT_KIT_TOKEN_OUT_OF_RANGE;
    }

    result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->SetOAuthToken(name, token);
}

ErrCode AppAccount::ClearOAuthToken(const std::string &name)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());

    ErrCode result = CheckParameters(name);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check parameters");
        return result;
    }

    result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->ClearOAuthToken(name);
}

ErrCode AppAccount::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("owner = %{public}s", owner.c_str());

    if (owner.size() == 0) {
        ACCOUNT_LOGE("owner is empty");
        return ERR_APPACCOUNT_KIT_OWNER_IS_EMPTY;
    }

    if (owner.size() > OWNER_MAX_SIZE) {
        ACCOUNT_LOGE("owner is out of range");
        return ERR_APPACCOUNT_KIT_OWNER_OUT_OF_RANGE;
    }

    ErrCode result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->GetAllAccounts(owner, appAccounts);
}

ErrCode AppAccount::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGI("enter");

    ErrCode result = GetAppAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get appAccountProxy_");
        return result;
    }

    return appAccountProxy_->GetAllAccessibleAccounts(appAccounts);
}

ErrCode AppAccount::SubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber)
{
    ACCOUNT_LOGI("enter");

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

    if (owners.size() == 0) {
        ACCOUNT_LOGE("owners.size() = %{public}zu", owners.size());
        return ERR_APPACCOUNT_KIT_SUBSCRIBER_HAS_NO_OWNER;
    }

    if (GetAppAccountProxy() != ERR_OK) {
        ACCOUNT_LOGE("app account proxy is nullptr");
        return ERR_APPACCOUNT_KIT_APP_ACCOUNT_PROXY_IS_NULLPTR;
    }

    sptr<IRemoteObject> appAccountEventListener = nullptr;
    ErrCode subscribeState = CreateAppAccountEventListener(subscriber, appAccountEventListener);
    if (subscribeState == INITIAL_SUBSCRIPTION) {
        return appAccountProxy_->SubscribeAppAccount(subscribeInfo, appAccountEventListener);
    } else if (subscribeState == ALREADY_SUBSCRIBED) {
        return ERR_OK;
    } else {
        return ERR_APPACCOUNT_KIT_SUBSCRIBE;
    }
}

ErrCode AppAccount::UnsubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber)
{
    ACCOUNT_LOGI("enter");

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
        ACCOUNT_LOGI("no specified subscriber has been registered");
        return ERR_APPACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED;
    }
}

ErrCode AppAccount::ResetAppAccountProxy()
{
    ACCOUNT_LOGI("enter");

    std::lock_guard<std::mutex> lock(mutex_);
    if ((appAccountProxy_ != nullptr) && (appAccountProxy_->AsObject() != nullptr)) {
        appAccountProxy_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
    appAccountProxy_ = nullptr;

    return ERR_OK;
}

ErrCode AppAccount::CheckParameters(const std::string &name, const std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("extraInfo = %{public}s", extraInfo.c_str());

    if (name.size() == 0) {
        ACCOUNT_LOGE("name is empty");
        return ERR_APPACCOUNT_KIT_NAME_IS_EMPTY;
    }

    if (name.size() > trim_copy(name).size()) {
        ACCOUNT_LOGE("name contains blank spaces");
        return ERR_APPACCOUNT_KIT_NAME_CONTAINS_BLANK_SPACES;
    }

    if (name.size() > NAME_MAX_SIZE) {
        ACCOUNT_LOGE("name is out of range");
        return ERR_APPACCOUNT_KIT_NAME_OUT_OF_RANGE;
    }

    if (extraInfo.size() > EXTRA_INFO_MAX_SIZE) {
        ACCOUNT_LOGE("extra info is out of range");
        return ERR_APPACCOUNT_KIT_EXTRA_INFO_OUT_OF_RANGE;
    }

    return ERR_OK;
}

ErrCode AppAccount::GetAppAccountProxy()
{
    ACCOUNT_LOGI("enter");

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
            return ERR_APPACCOUNT_KIT_GET_APP_ACCOUNT_PROXY;
        }

        deathRecipient_ = new AppAccountDeathRecipient();
        if (!deathRecipient_) {
            ACCOUNT_LOGE("failed to create app account death recipient");
            return ERR_APPACCOUNT_KIT_CREATE_APP_ACCOUNT_DEATH_RECIPIENT;
        }

        appAccountProxy_->AsObject()->AddDeathRecipient(deathRecipient_);
    }

    return ERR_OK;
}

ErrCode AppAccount::CreateAppAccountEventListener(
    const std::shared_ptr<AppAccountSubscriber> &subscriber, sptr<IRemoteObject> &appAccountEventListener)
{
    ACCOUNT_LOGI("enter");

    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return SUBSCRIBE_FAILD;
    }

    std::lock_guard<std::mutex> lock(eventListenersMutex_);

    auto eventListener = eventListeners_.find(subscriber);
    if (eventListener != eventListeners_.end()) {
        appAccountEventListener = eventListener->second->AsObject();
        ACCOUNT_LOGI("subscriber already has app account event listener");
        return ALREADY_SUBSCRIBED;
    } else {
        if (eventListeners_.size() == SUBSCRIBER_MAX_SIZE) {
            ACCOUNT_LOGE("the maximum number of subscribers has been reached");
            return SUBSCRIBE_FAILD;
        }

        sptr<AppAccountEventListener> listener = new AppAccountEventListener(subscriber);
        if (!listener) {
            ACCOUNT_LOGE("the app account event listener is null");
            return SUBSCRIBE_FAILD;
        }
        appAccountEventListener = listener->AsObject();
        eventListeners_[subscriber] = listener;
    }

    return INITIAL_SUBSCRIPTION;
}
}  // namespace AccountSA
}  // namespace OHOS

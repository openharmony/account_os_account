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

#include "account_log_wrapper.h"
#include "app_account_control_manager.h"
#include "app_account_subscribe_manager.h"

#include "inner_app_account_manager.h"

namespace OHOS {
namespace AccountSA {
InnerAppAccountManager::InnerAppAccountManager()
    : controlManagerPtr_(AppAccountControlManager::GetInstance()),
      subscribeManagerPtr_(AppAccountSubscribeManager::GetInstance())
{
    ACCOUNT_LOGI("enter");
}

InnerAppAccountManager::~InnerAppAccountManager()
{
    ACCOUNT_LOGI("enter");
}

ErrCode InnerAppAccountManager::AddAccount(
    const std::string &name, const std::string &extraInfo, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("extraInfo = %{public}s", extraInfo.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->AddAccount(name, extraInfo, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, bundleName) != true) {
        ACCOUNT_LOGI("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::DeleteAccount(const std::string &name, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->DeleteAccount(name, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, bundleName) != true) {
        ACCOUNT_LOGI("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::GetAccountExtraInfo(
    const std::string &name, std::string &extraInfo, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("extraInfo = %{public}s", extraInfo.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetAccountExtraInfo(name, extraInfo, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::SetAccountExtraInfo(
    const std::string &name, const std::string &extraInfo, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("extraInfo = %{public}s", extraInfo.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->SetAccountExtraInfo(name, extraInfo, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, bundleName) != true) {
        ACCOUNT_LOGI("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::EnableAppAccess(
    const std::string &name, const std::string &authorizedApp, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("authorizedApp = %{public}s", authorizedApp.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->EnableAppAccess(name, authorizedApp, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, bundleName) != true) {
        ACCOUNT_LOGI("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::DisableAppAccess(
    const std::string &name, const std::string &authorizedApp, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("authorizedApp = %{public}s", authorizedApp.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->DisableAppAccess(name, authorizedApp, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, bundleName) != true) {
        ACCOUNT_LOGI("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::CheckAppAccountSyncEnable(
    const std::string &name, bool &syncEnable, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("syncEnable = %{public}d", syncEnable);

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->CheckAppAccountSyncEnable(name, syncEnable, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::SetAppAccountSyncEnable(
    const std::string &name, const bool &syncEnable, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("syncEnable = %{public}d", syncEnable);

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->SetAppAccountSyncEnable(name, syncEnable, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, bundleName) != true) {
        ACCOUNT_LOGI("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::GetAssociatedData(
    const std::string &name, const std::string &key, std::string &value, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("key = %{public}s", key.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetAssociatedData(name, key, value, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::SetAssociatedData(
    const std::string &name, const std::string &key, const std::string &value, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("key = %{public}s, value = %{public}s", key.c_str(), value.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = controlManagerPtr_->SetAssociatedData(name, key, value, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, bundleName) != true) {
        ACCOUNT_LOGI("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("credentialType = %{public}s", credentialType.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetAccountCredential(name, credentialType, credential, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::SetAccountCredential(const std::string &name, const std::string &credentialType,
    const std::string &credential, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("credentialType = %{public}s, credential = %{public}s", credentialType.c_str(), credential.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result =
        controlManagerPtr_->SetAccountCredential(name, credentialType, credential, bundleName, appAccountInfo);

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
    } else if (subscribeManagerPtr_->PublishAccount(appAccountInfo, bundleName) != true) {
        ACCOUNT_LOGI("failed to publish account");
    }

    return result;
}

ErrCode InnerAppAccountManager::GetOAuthToken(
    const std::string &name, std::string &token, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("token = %{public}s", token.c_str());
    ACCOUNT_LOGI("bundleName = %{public}s", bundleName.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetOAuthToken(name, token, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::SetOAuthToken(
    const std::string &name, const std::string &token, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("token = %{public}s", token.c_str());
    ACCOUNT_LOGI("bundleName = %{public}s", bundleName.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->SetOAuthToken(name, token, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::ClearOAuthToken(const std::string &name, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("bundleName = %{public}s", bundleName.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->ClearOAuthToken(name, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::GetAllAccounts(
    const std::string &owner, std::vector<AppAccountInfo> &appAccounts, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("owner = %{public}s", owner.c_str());

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetAllAccounts(owner, appAccounts, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::GetAllAccessibleAccounts(
    std::vector<AppAccountInfo> &appAccounts, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    if (!controlManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    ErrCode result = controlManagerPtr_->GetAllAccessibleAccounts(appAccounts, bundleName);

    return result;
}

ErrCode InnerAppAccountManager::SubscribeAppAccount(const AppAccountSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &eventListener, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR;
    }

    auto subscribeInfoPtr = std::make_shared<AppAccountSubscribeInfo>(subscribeInfo);
    ErrCode result = subscribeManagerPtr_->SubscribeAppAccount(subscribeInfoPtr, eventListener, bundleName);

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

ErrCode InnerAppAccountManager::OnPackageRemoved(const int32_t &uid, const std::string &bundleName)
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

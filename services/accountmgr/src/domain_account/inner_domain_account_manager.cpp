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

#include "inner_domain_account_manager.h"
#include "account_log_wrapper.h"
#include "domain_account_plugin_death_recipient.h"
#include "domain_auth_callback_proxy.h"
#include "iinner_os_account_manager.h"

namespace OHOS {
namespace AccountSA {
ErrCode InnerDomainAccountManager::RegisterPlugin(const sptr<IDomainAccountPlugin> &plugin)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (plugin == nullptr) {
        ACCOUNT_LOGE("the registered plugin is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    }
    if (plugin_ != nullptr) {
        ACCOUNT_LOGE("plugin already exists");
        return ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_ALREADY_EXIST;
    }
    auto deathRecipient = GetDeathRecipient();
    if ((deathRecipient == nullptr) || (!plugin->AsObject()->AddDeathRecipient(deathRecipient))) {
        ACCOUNT_LOGE("failed to add death recipient for plugin");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }
    plugin_ = plugin;
    return ERR_OK;
}

void InnerDomainAccountManager::UnregisterPlugin()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if ((plugin_ != nullptr) && (plugin_->AsObject() != nullptr)) {
        plugin_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
    plugin_ = nullptr;
    deathRecipient_ = nullptr;
}

ErrCode InnerDomainAccountManager::StartAuth(const sptr<IDomainAccountPlugin> &plugin, const DomainAccountInfo &info,
    const std::vector<uint8_t> &password, const sptr<IDomainAuthCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("invalid callback");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    }
    DomainAuthResult emptyResult = {};
    if (plugin == nullptr) {
        ACCOUNT_LOGE("plugin is nullptr");
        callback->OnResult(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, emptyResult);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    }
    ErrCode errCode = plugin->Auth(info, password, callback);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to auth domain account, errCode: %{public}d", errCode);
        callback->OnResult(errCode, emptyResult);
        return errCode;
    }
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const sptr<IDomainAuthCallback> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto handler = GetEventHandler();
    if (handler == nullptr) {
        ACCOUNT_LOGE("failed to create EventHandler");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    AppExecFwk::InnerEvent::Callback task =
        std::bind(&InnerDomainAccountManager::StartAuth, this, plugin_, info, password, callback);
    if (!handler->PostTask(task)) {
        ACCOUNT_LOGE("failed to post task");
        return ERR_ACCOUNT_COMMON_POST_TASK;
    }
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::AuthUser(int32_t userId, const std::vector<uint8_t> &password,
    const sptr<IDomainAuthCallback> &callback)
{
    OsAccountInfo accountInfo;
    ErrCode errCode = IInnerOsAccountManager::GetInstance()->QueryOsAccountById(userId, accountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get os account info failed, errCode: %{public}d", errCode);
        return errCode;
    }
    DomainAccountInfo domainInfo;
    accountInfo.GetDomainInfo(domainInfo);
    if (domainInfo.accountName_.empty()) {
        ACCOUNT_LOGE("the target user is not a domain account");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto handler = GetEventHandler();
    if (handler == nullptr) {
        ACCOUNT_LOGE("failed to create EventHandler");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    AppExecFwk::InnerEvent::Callback task =
        std::bind(&InnerDomainAccountManager::StartAuth, this, plugin_, domainInfo, password, callback);
    if (!handler->PostTask(task)) {
        ACCOUNT_LOGE("failed to post task");
        return ERR_ACCOUNT_COMMON_POST_TASK;
    }
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::GetAuthProperty(const DomainAccountInfo &info, DomainAuthProperty &property)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (plugin_ == nullptr) {
        ACCOUNT_LOGE("plugin not exists");
        return ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST;
    }
    return plugin_->GetAuthProperty(info, property);
}

std::shared_ptr<AppExecFwk::EventHandler> InnerDomainAccountManager::GetEventHandler()
{
    if (handler_ != nullptr) {
        return handler_;
    }
    handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::Create());
    return handler_;
}

sptr<IRemoteObject::DeathRecipient> InnerDomainAccountManager::GetDeathRecipient()
{
    if (deathRecipient_ != nullptr) {
        return deathRecipient_;
    }
    deathRecipient_ = new (std::nothrow) DomainAccountPluginDeathRecipient();
    return deathRecipient_;
}

bool InnerDomainAccountManager::IsPluginAvailable()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return plugin_ != nullptr;
}
}  // namespace AccountSA
}  // namespace OHOS

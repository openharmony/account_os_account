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

#include "domain_account_client.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_proxy.h"
#include "domain_account_callback_adapters.h"
#include "domain_account_callback_service.h"
#include "domain_account_plugin_service.h"
#include "domain_account_proxy.h"
#include "domain_account_status_listener.h"
#include "domain_account_status_listener_service.h"
#include "domain_auth_callback_service.h"
#include "ohos_account_kits_impl.h"

namespace OHOS {
namespace AccountSA {
DomainAccountClient &DomainAccountClient::GetInstance()
{
    static DomainAccountClient instance;
    return instance;
}

ErrCode DomainAccountClient::RegisterPlugin(const std::shared_ptr<DomainAccountPlugin> &plugin)
{
    if (plugin == nullptr) {
        ACCOUNT_LOGE("plugin is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    sptr<DomainAccountPluginService> pluginService = new (std::nothrow) DomainAccountPluginService(plugin);
    if (pluginService == nullptr) {
        ACCOUNT_LOGE("failed to create DomainAccountPluginService");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->RegisterPlugin(pluginService);
}

ErrCode DomainAccountClient::UnregisterPlugin()
{
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->UnregisterPlugin();
}

ErrCode DomainAccountClient::AuthProxyInit(const std::shared_ptr<DomainAuthCallback> &callback,
    sptr<DomainAuthCallbackService> &callbackService, sptr<IDomainAccount> &proxy)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    callbackService = new (std::nothrow) DomainAuthCallbackService(callback);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("failed to create DomainAuthCallbackService");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return ERR_OK;
}

ErrCode DomainAccountClient::GetAccessToken(const DomainAccountInfo &info, const AAFwk::WantParams &parameters,
    const std::shared_ptr<GetAccessTokenCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    auto callbackPtr = std::make_shared<GetAccessTokenCallbackAdapter>(callback);
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callbackPtr);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("failed to new callback service");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAccessToken(info, parameters, callbackService);
}

ErrCode DomainAccountClient::HasDomainAccount(
    const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("failed to check domain account callback service");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->HasDomainAccount(info, callbackService);
}

ErrCode DomainAccountClient::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const std::shared_ptr<DomainAuthCallback> &callback)
{
    sptr<DomainAuthCallbackService> callbackService = nullptr;
    sptr<IDomainAccount> proxy = nullptr;
    ErrCode result = AuthProxyInit(callback, callbackService, proxy);
    if (result != ERR_OK) {
        return result;
    }
    return proxy->Auth(info, password, callbackService);
}

ErrCode DomainAccountClient::AuthUser(int32_t userId, const std::vector<uint8_t> &password,
    const std::shared_ptr<DomainAuthCallback> &callback)
{
    sptr<DomainAuthCallbackService> callbackService = nullptr;
    sptr<IDomainAccount> proxy = nullptr;
    ErrCode result = AuthProxyInit(callback, callbackService, proxy);
    if (result != ERR_OK) {
        return result;
    }
    return proxy->AuthUser(userId, password, callbackService);
}

ErrCode DomainAccountClient::AuthWithPopup(int32_t userId, const std::shared_ptr<DomainAuthCallback> &callback)
{
    sptr<DomainAuthCallbackService> callbackService = nullptr;
    sptr<IDomainAccount> proxy = nullptr;
    ErrCode result = AuthProxyInit(callback, callbackService, proxy);
    if (result != ERR_OK) {
        return result;
    }
    return proxy->AuthWithPopup(userId, callbackService);
}

ErrCode DomainAccountClient::UpdateAccountToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token)
{
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->UpdateAccountToken(info, token);
}

void DomainAccountClient::ResetDomainAccountProxy(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ == nullptr) {
        ACCOUNT_LOGD("proxy is nullptr");
        return;
    }
    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
    }
    proxy_ = nullptr;
    deathRecipient_ = nullptr;
}

ErrCode DomainAccountClient::GetAccountStatus(const DomainAccountInfo &info, DomainAccountStatus &status)
{
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAccountStatus(info, status);
}

ErrCode DomainAccountClient::RegisterAccountStatusListener(
    const DomainAccountInfo &info, const std::shared_ptr<DomainAccountStatusListener> &listener)
{
    if (listener == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    std::lock_guard<std::mutex> lock(recordMutex_);
    auto recordIter = listenerRecords_.find(listener);
    sptr<IDomainAccountCallback> callback = nullptr;
    if (recordIter == listenerRecords_.end()) {
        std::shared_ptr<DomainAccountStatusListenerService> listenerService =
            std::make_shared<DomainAccountStatusListenerService>(listener);
        callback = new (std::nothrow) DomainAccountCallbackService(listenerService);
        if (callback == nullptr) {
            ACCOUNT_LOGE("failed to check domain account callback service");
            return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
        }
    } else {
        callback = recordIter->second.callback_;
    }
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    ErrCode result = proxy->RegisterAccountStatusListener(info, callback);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("RegisterAccountStatusListener failed, error is %{public}d", result);
        return result;
    }
    if (recordIter == listenerRecords_.end()) {
        listenerRecords_.emplace(listener, DomainAccountClient::DomainAccountListenerRecord(info, callback));
    } else {
        recordIter->second.infos_.emplace_back(info);
    }
    return result;
}

ErrCode DomainAccountClient::RegisterAccountStatusListener(const std::shared_ptr<DomainAccountStatusListener> &listener)
{
    if (listener == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    std::lock_guard<std::mutex> lock(recordMutex_);
    auto recordIt = listenerRecords_.find(listener);
    if (recordIt != listenerRecords_.end()) {
        ACCOUNT_LOGI("listener already exist");
        return ERR_OK;
    }
    std::shared_ptr<DomainAccountStatusListenerService> listenerService =
        std::make_shared<DomainAccountStatusListenerService>(listener);

    sptr<IDomainAccountCallback> callback = new (std::nothrow) DomainAccountCallbackService(listenerService);
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to check domain account callback service");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    ErrCode result = proxy->RegisterAccountStatusListener(callback);
    if (result == ERR_OK) {
        listenerRecords_.emplace(listener, DomainAccountClient::DomainAccountListenerRecord(callback));
    }
    return result;
}

ErrCode DomainAccountClient::UnregisterAccountStatusListener(
    const std::shared_ptr<DomainAccountStatusListener> &listener)
{
    if (listener == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    std::lock_guard<std::mutex> lock(recordMutex_);
    auto recordIt = listenerRecords_.find(listener);
    if (recordIt == listenerRecords_.end()) {
        ACCOUNT_LOGI("listener not register");
        return ERR_OK;
    }
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    ErrCode result = proxy->UnregisterAccountStatusListener(recordIt->second.callback_);
    if (result == ERR_OK) {
        listenerRecords_.erase(recordIt);
    }
    return result;
}

ErrCode DomainAccountClient::UnregisterAccountStatusListener(
    const DomainAccountInfo &info, const std::shared_ptr<DomainAccountStatusListener> &listener)
{
    if (listener == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    std::lock_guard<std::mutex> lock(recordMutex_);
    auto recordIt = listenerRecords_.find(listener);
    if (recordIt == listenerRecords_.end()) {
        ACCOUNT_LOGI("listener not exist");
        return ERR_OK;
    }
    ErrCode result = proxy->UnregisterAccountStatusListener(info, recordIt->second.callback_);
    if (result != ERR_OK) {
        return result;
    }
    for (auto it = recordIt->second.infos_.begin(); it != recordIt->second.infos_.end(); ++it) {
        if ((info.accountId_ == it->accountId_) ||
            ((info.accountName_ == it->accountName_) && (info.domain_ == it->domain_))) {
            recordIt->second.infos_.erase(it);
            if (recordIt->second.infos_.empty()) {
                listenerRecords_.erase(recordIt);
            }
            break;
        }
    }
    return result;
}

void DomainAccountClient::DomainAccountDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr");
        return;
    }
    DomainAccountClient::GetInstance().ResetDomainAccountProxy(remote);
}

sptr<IDomainAccount> DomainAccountClient::GetDomainAccountProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }
    sptr<IRemoteObject> object = OhosAccountKitsImpl::GetInstance().GetDomainAccountService();
    if (object == nullptr) {
        ACCOUNT_LOGE("failed to get domain account service");
        return nullptr;
    }
    deathRecipient_ = new (std::nothrow) DomainAccountDeathRecipient();
    if (deathRecipient_ == nullptr) {
        ACCOUNT_LOGE("failed to create domain account death recipient");
        return nullptr;
    }
    if (!object->AddDeathRecipient(deathRecipient_)) {
        ACCOUNT_LOGE("failed to add app account death recipient");
        deathRecipient_ = nullptr;
        return nullptr;
    }
    proxy_ = iface_cast<IDomainAccount>(object);
    return proxy_;
}
}  // namespace AccountSA
}  // namespace OHOS

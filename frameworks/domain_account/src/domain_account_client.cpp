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
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
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
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
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
    const std::shared_ptr<DomainAccountCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    }
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
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
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
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

ErrCode DomainAccountClient::GetAccountStatus(const std::string &domain,
    const std::string &accountName, DomainAccountStatus &status)
{
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAccountStatus(domain, accountName, status);
}

ErrCode DomainAccountClient::RegisterAccountStatusListener(
    const DomainAccountInfo &info, const std::shared_ptr<DomainAccountStatusListener> &listener)
{
    if (listener == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    }
    std::shared_ptr<DomainAccountStatusListenerService> listenerService =
        std::make_shared<DomainAccountStatusListenerService>(listener);

    sptr<IDomainAccountCallback> callback =
        new (std::nothrow) DomainAccountCallbackService(listenerService);
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to check domain account callback service");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->RegisterAccountStatusListener(info, callback);
}

ErrCode DomainAccountClient::UnregisterAccountStatusListener(const DomainAccountInfo &info)
{
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->UnregisterAccountStatusListener(info);
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

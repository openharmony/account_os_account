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

#include "domain_account_client.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_proxy.h"
#include "domain_account_plugin_service.h"
#include "domain_account_proxy.h"
#include "domain_auth_callback_service.h"
#include "ohos_account_kits_impl.h"

namespace OHOS {
namespace AccountSA {
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

ErrCode DomainAccountClient::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const std::shared_ptr<DomainAuthCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    }
    sptr<DomainAuthCallbackService> callbackService = new (std::nothrow) DomainAuthCallbackService(callback);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("failed to create DomainAuthCallbackService");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->Auth(info, password, callbackService);
}

ErrCode DomainAccountClient::AuthUser(int32_t userId, const std::vector<uint8_t> &password,
    const std::shared_ptr<DomainAuthCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    }
    sptr<DomainAuthCallbackService> callbackService = new (std::nothrow) DomainAuthCallbackService(callback);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("failed to create DomainAuthCallbackService");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->AuthUser(userId, password, callbackService);
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
    sptr<IRemoteObject> object = DelayedRefSingleton<OhosAccountKitsImpl>::GetInstance().GetDomainAccountService();
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

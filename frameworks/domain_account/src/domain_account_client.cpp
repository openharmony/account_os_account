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
#include "domain_account_status_listener_manager.h"
#include "ohos_account_kits_impl.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
DomainAccountClient &DomainAccountClient::GetInstance()
{
    static DomainAccountClient *instance = new (std::nothrow) DomainAccountClient();
    return *instance;
}

std::function<void(int32_t, const std::string &)> callbackFunc()
{
    return [](int32_t systemAbilityId, const std::string &deviceId) {
        if (systemAbilityId == SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN) {
            DomainAccountClient::GetInstance().RestoreListenerRecords();
            DomainAccountClient::GetInstance().RestorePlugin();
        }
    };
}

DomainAccountClient::DomainAccountClient()
{
    (void)OhosAccountKitsImpl::GetInstance().SubscribeSystemAbility(callbackFunc());
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
    ErrCode result = proxy->RegisterPlugin(pluginService);
    if (result == ERR_OK) {
        pluginService_ = pluginService;
    }
    return result;
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

ErrCode DomainAccountClient::AuthProxyInit(const std::shared_ptr<DomainAccountCallback> &callback,
    sptr<DomainAccountCallbackService> &callbackService, sptr<IDomainAccount> &proxy)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("failed to create DomainAccountCallbackService");
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

ErrCode DomainAccountClient::HasAccount(
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
    const std::shared_ptr<DomainAccountCallback> &callback)
{
    sptr<DomainAccountCallbackService> callbackService = nullptr;
    sptr<IDomainAccount> proxy = nullptr;
    ErrCode result = AuthProxyInit(callback, callbackService, proxy);
    if (result != ERR_OK) {
        return result;
    }
    return proxy->Auth(info, password, callbackService);
}

ErrCode DomainAccountClient::AuthUser(int32_t userId, const std::vector<uint8_t> &password,
    const std::shared_ptr<DomainAccountCallback> &callback)
{
    sptr<DomainAccountCallbackService> callbackService = nullptr;
    sptr<IDomainAccount> proxy = nullptr;
    ErrCode result = AuthProxyInit(callback, callbackService, proxy);
    if (result != ERR_OK) {
        return result;
    }
    return proxy->AuthUser(userId, password, callbackService);
}

ErrCode DomainAccountClient::AuthWithPopup(int32_t userId, const std::shared_ptr<DomainAccountCallback> &callback)
{
    sptr<DomainAccountCallbackService> callbackService = nullptr;
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

ErrCode DomainAccountClient::IsAuthenticationExpired(const DomainAccountInfo &info, bool &isExpired)
{
    isExpired = true;
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Get domain account proxy failed.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->IsAuthenticationExpired(info, isExpired);
}

ErrCode DomainAccountClient::SetAccountPolicy(const DomainAccountPolicy &policy)
{
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Get domain account proxy failed.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SetAccountPolicy(policy);
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

ErrCode DomainAccountClient::GetDomainAccountInfo(
    const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetDomainAccountInfo(info, callbackService);
}

ErrCode DomainAccountClient::UpdateAccountInfo(
    const DomainAccountInfo &oldAccountInfo, const DomainAccountInfo &newAccountInfo)
{
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->UpdateAccountInfo(oldAccountInfo, newAccountInfo);
}

ErrCode DomainAccountClient::RegisterAccountStatusListener(const std::shared_ptr<DomainAccountStatusListener> &listener)
{
    if (listener == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    std::lock_guard<std::mutex> lock(recordMutex_);
    if (listenerManager_ == nullptr) {
        listenerManager_ = std::make_shared<DomainAccountStatusListenerManager>();
    }
    if (!listenerManager_->IsRecordEmpty()) {
        listenerManager_->InsertRecord(listener);
        return ERR_OK;
    }
    if (callback_ == nullptr) {
        callback_ = new (std::nothrow) DomainAccountCallbackService(listenerManager_);
        if (callback_ == nullptr) {
            ACCOUNT_LOGE("failed to check domain account callback service");
            return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
        }
    }
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    ErrCode result = proxy->RegisterAccountStatusListener(callback_);
    if (result == ERR_OK) {
        listenerManager_->InsertRecord(listener);
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
    if (listenerManager_ == nullptr) {
        ACCOUNT_LOGE("listenerManager_ is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    listenerManager_->RemoveRecord(listener);
    if (!listenerManager_->IsRecordEmpty()) {
        return ERR_OK;
    }
    ErrCode result = proxy->UnregisterAccountStatusListener(callback_);
    if (result != ERR_OK) {
        listenerManager_->InsertRecord(listener);
        return result;
    }
    return ERR_OK;
}

ErrCode DomainAccountClient::AddServerConfig(const std::string &parameters, DomainServerConfig &config)
{
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get domain account proxy.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->AddServerConfig(parameters, config);
}

ErrCode DomainAccountClient::RemoveServerConfig(const std::string &configId)
{
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get domain account proxy.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->RemoveServerConfig(configId);
}

ErrCode DomainAccountClient::GetAccountServerConfig(const DomainAccountInfo &info, DomainServerConfig &config)
{
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get domain account proxy.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAccountServerConfig(info, config);
}

void DomainAccountClient::RestoreListenerRecords()
{
    if (listenerManager_ == nullptr) {
        ACCOUNT_LOGI("listenerManager_ is nullptr");
        return;
    }
    sptr<IDomainAccount> proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("proxy is nullptr");
        return;
    }
    if (!listenerManager_->IsRecordEmpty()) {
        (void)proxy->RegisterAccountStatusListener(callback_);
    }
}

void DomainAccountClient::RestorePlugin()
{
    if (pluginService_ == nullptr) {
        ACCOUNT_LOGI("pluginService_ is nullptr");
        return;
    }
    sptr<IDomainAccount> proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("proxy is nullptr");
        return;
    }
    (void)proxy->RegisterPlugin(pluginService_);
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
        ACCOUNT_LOGE("failed to add domain account death recipient");
        deathRecipient_ = nullptr;
        return nullptr;
    }
    proxy_ = iface_cast<IDomainAccount>(object);
    return proxy_;
}
}  // namespace AccountSA
}  // namespace OHOS

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

#include <thread>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#ifdef SUPPORT_DOMAIN_ACCOUNTS
#include "domain_account_callback_adapters.h"
#include "domain_account_plugin_service.h"
#include "domain_account_proxy.h"
#include "ohos_account_kits_impl.h"
#include "system_ability_definition.h"
#endif // SUPPORT_DOMAIN_ACCOUNTS

namespace OHOS {
namespace AccountSA {
namespace {
#ifdef SUPPORT_DOMAIN_ACCOUNTS
static const uint32_t CONTEXT_ID_HIGH_LENGTH = 32;
#endif // SUPPORT_DOMAIN_ACCOUNTS
};

DomainAccountClient &DomainAccountClient::GetInstance()
{
    static DomainAccountClient *instance = new (std::nothrow) DomainAccountClient();
    return *instance;
}

#ifdef SUPPORT_DOMAIN_ACCOUNTS
std::function<void(int32_t, const std::string &)> callbackFunc()
{
    return [](int32_t systemAbilityId, const std::string &deviceId) {
        if (systemAbilityId == SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN) {
            DomainAccountClient::GetInstance().RestoreListenerRecords();
            DomainAccountClient::GetInstance().RestorePlugin();
        }
    };
}
#endif // SUPPORT_DOMAIN_ACCOUNTS

DomainAccountClient::DomainAccountClient()
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    (void)OhosAccountKitsImpl::GetInstance().SubscribeSystemAbility(callbackFunc());
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::RegisterPlugin(const std::shared_ptr<DomainAccountPlugin> &plugin)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
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
        std::lock_guard<std::mutex> lock(pluginServiceMutex_);
        pluginService_ = pluginService;
    }
    return result;
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::UnregisterPlugin()
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    ErrCode ret = proxy->UnregisterPlugin();
    if (ret == ERR_OK) {
        std::lock_guard<std::mutex> lock(pluginServiceMutex_);
        pluginService_ = nullptr;
    }
    return ret;
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

#ifdef SUPPORT_DOMAIN_ACCOUNTS
ErrCode DomainAccountClient::AuthProxyInit(const std::shared_ptr<DomainAccountCallback> &callback,
    sptr<DomainAccountCallbackService> &callbackService, sptr<IDomainAccount> &proxy, uint64_t &contextId)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (!GenerateCallbackAndContextId(callback, callbackService, contextId)) {
        ACCOUNT_LOGE("GenerateCallbackAndContextId failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return ERR_OK;
}
#endif // SUPPORT_DOMAIN_ACCOUNTS

ErrCode DomainAccountClient::GetAccessToken(const DomainAccountInfo &info, const AAFwk::WantParams &parameters,
    const std::shared_ptr<GetAccessTokenCallback> &callback)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
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
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::HasAccount(
    const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
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
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const std::shared_ptr<DomainAccountCallback> &callback)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    sptr<DomainAccountCallbackService> callbackService = nullptr;
    sptr<IDomainAccount> proxy = nullptr;
    uint64_t contextId = 0;
    std::lock_guard<std::recursive_mutex> lock(contextIdMutex_);
    ErrCode result = AuthProxyInit(callback, callbackService, proxy, contextId);
    if (result != ERR_OK) {
        return result;
    }
    result = proxy->Auth(info, password, callbackService);
    if (result != ERR_OK) {
        EraseContext(contextId);
    }
    return result;
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::AuthUser(int32_t userId, const std::vector<uint8_t> &password,
    const std::shared_ptr<DomainAccountCallback> &callback, uint64_t &contextId)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    sptr<DomainAccountCallbackService> callbackService = nullptr;
    sptr<IDomainAccount> proxy = nullptr;
    std::lock_guard<std::recursive_mutex> lock(contextIdMutex_);
    ErrCode result = AuthProxyInit(callback, callbackService, proxy, contextId);
    if (result != ERR_OK) {
        return result;
    }
    result = proxy->AuthUser(userId, password, callbackService);
    if (result != ERR_OK) {
        EraseContext(contextId);
    }
    return result;
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::AuthUser(int32_t userId,
    const std::function<std::vector<uint8_t>()> getPasswordHooks,
    const std::shared_ptr<DomainAccountCallback> &callback, uint64_t &contextId)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    if ((callback == nullptr) || (getPasswordHooks == nullptr)) {
        ACCOUNT_LOGE("callback or hooks is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    sptr<DomainAccountCallbackService> callbackService = nullptr;
    sptr<IDomainAccount> proxy = nullptr;
    uint64_t genContextId = 0;
    std::lock_guard<std::recursive_mutex> lock(contextIdMutex_);
    ErrCode result = AuthProxyInit(callback, callbackService, proxy, genContextId);
    if (result != ERR_OK) {
        return result;
    }
    contextId = genContextId;
    auto task = [getPasswordHooks, proxy, callbackService, userId]() {
        std::vector<uint8_t> password = getPasswordHooks();
        ErrCode errCode = proxy->AuthUser(userId, password, callbackService);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Failed to auth for domain account, errCode=%{public}d", errCode);
            Parcel emptyParcel;
            DomainAccountParcel emptyDomainParcel;
            AccountSA::DomainAuthResult emptyResult;
            if (!emptyResult.Marshalling(emptyParcel)) {
                ACCOUNT_LOGE("authResult Marshalling failed");
                errCode = ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
            }
            emptyDomainParcel.SetParcelData(emptyParcel);
            callbackService->OnResult(errCode, emptyDomainParcel);
        }
    };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), "DomainAuthThread");
    taskThread.detach();

    return ERR_OK;
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::AuthWithPopup(int32_t userId, const std::shared_ptr<DomainAccountCallback> &callback)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    sptr<DomainAccountCallbackService> callbackService = nullptr;
    sptr<IDomainAccount> proxy = nullptr;
    uint64_t contextId = 0;
    std::lock_guard<std::recursive_mutex> lock(contextIdMutex_);
    ErrCode result = AuthProxyInit(callback, callbackService, proxy, contextId);
    if (result != ERR_OK) {
        return result;
    }
    result = proxy->AuthWithPopup(userId, callbackService);
    if (result != ERR_OK) {
        EraseContext(contextId);
    }
    return result;
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::CancelAuth(const uint64_t contextId)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    std::lock_guard<std::recursive_mutex> lock(contextIdMutex_);
    auto it = contextIdMap_.find(contextId);
    if (it == contextIdMap_.end()) {
        ACCOUNT_LOGE("ContextId not found.");
        return ERR_JS_INVALID_CONTEXT_ID;
    }
    sptr<IDomainAccount> proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Get domain account proxy failed.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CancelAuth(it->second);
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::UpdateAccountToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->UpdateAccountToken(info, token);
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::IsAuthenticationExpired(const DomainAccountInfo &info, bool &isExpired)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    isExpired = true;
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Get domain account proxy failed.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->IsAuthenticationExpired(info, isExpired);
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

#ifdef SUPPORT_DOMAIN_ACCOUNTS
void DomainAccountClient::ResetDomainAccountProxy(const wptr<IRemoteObject>& remote)
{
    {
        std::lock_guard<std::recursive_mutex> lock(contextIdMutex_);
        Parcel emptyParcel;
        AccountSA::DomainAuthResult emptyResult;
        DomainAccountParcel emptyDomainParcel;
        (void)emptyResult.Marshalling(emptyParcel);
        emptyDomainParcel.SetParcelData(emptyParcel);
        for (const auto &pair : contextIdMap_) {
            pair.second->OnResult(ERR_JS_SYSTEM_SERVICE_EXCEPTION, emptyDomainParcel);
        }
        ACCOUNT_LOGE("Service is exit abnormally, interrupt auth context number = %{public}zu", contextIdMap_.size());
        contextIdMap_.clear();
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ == nullptr) {
        ACCOUNT_LOGE("Proxy is nullptr");
        return;
    }
    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
    }
    proxy_ = nullptr;
    deathRecipient_ = nullptr;
}
#endif // SUPPORT_DOMAIN_ACCOUNTS

ErrCode DomainAccountClient::GetAccountStatus(const DomainAccountInfo &info, DomainAccountStatus &status)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    int32_t statusResult;
    auto errCode = proxy->GetAccountStatus(info, statusResult);
    status = static_cast<DomainAccountStatus>(statusResult);
    return errCode;
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::GetDomainAccountInfo(
    const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
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
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::UpdateAccountInfo(
    const DomainAccountInfo &oldAccountInfo, const DomainAccountInfo &newAccountInfo)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get domain account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->UpdateAccountInfo(oldAccountInfo, newAccountInfo);
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::RegisterAccountStatusListener(const std::shared_ptr<DomainAccountStatusListener> &listener)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
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
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::UnregisterAccountStatusListener(
    const std::shared_ptr<DomainAccountStatusListener> &listener)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
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
    listenerManager_ = nullptr;
    callback_ = nullptr;
    return ERR_OK;
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::AddServerConfig(const std::string &parameters, DomainServerConfig &config)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get domain account proxy.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->AddServerConfig(parameters, config);
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::RemoveServerConfig(const std::string &configId)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get domain account proxy.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->RemoveServerConfig(configId);
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::UpdateServerConfig(const std::string &configId, const std::string &parameters,
    DomainServerConfig &config)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get domain account proxy.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->UpdateServerConfig(configId, parameters, config);
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::GetServerConfig(const std::string &configId, DomainServerConfig &config)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get domain account proxy.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetServerConfig(configId, config);
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::GetAllServerConfigs(std::vector<DomainServerConfig> &configs)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get domain account proxy.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAllServerConfigs(configs);
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::GetAccountServerConfig(const DomainAccountInfo &info, DomainServerConfig &config)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get domain account proxy.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAccountServerConfig(info, config);
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::SetAccountPolicy(const DomainAccountInfo &info, const std::string &policy)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get domain account proxy.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SetAccountPolicy(info, policy);
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode DomainAccountClient::GetAccountPolicy(const DomainAccountInfo &info, std::string &policy)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    auto proxy = GetDomainAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get domain account proxy.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAccountPolicy(info, policy);
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

#ifdef SUPPORT_DOMAIN_ACCOUNTS
bool DomainAccountClient::GenerateCallbackAndContextId(const std::shared_ptr<DomainAccountCallback> &callback,
    sptr<DomainAccountCallbackService> &callbackService, uint64_t &contextId)
{
    std::lock_guard<std::recursive_mutex> lock(contextIdMutex_);
    if (contextIdCount_ >= UINT32_MAX) {
        contextIdCount_ = 0;
    }
    contextIdCount_++;
    uint32_t higherContextId = getuid();
    uint64_t tmpContextId = higherContextId;
    tmpContextId = (tmpContextId << CONTEXT_ID_HIGH_LENGTH);
    if (contextIdMap_.find(tmpContextId + contextIdCount_) != contextIdMap_.end()) {
        for (uint32_t i = 1; i < UINT32_MAX; i++) {
            if (contextIdMap_.find(tmpContextId + i) == contextIdMap_.end()) {
                contextIdCount_ = i;
                break;
            }
            if (i == (UINT32_MAX - 1)) {
                ACCOUNT_LOGE("ContextId reach max value.");
                contextIdCount_ = 0;
                return false;
            }
        }
    }
    contextId = tmpContextId + contextIdCount_;
    std::function<void()> afterOnResultCallback = [contextId]() {
        DomainAccountClient::GetInstance().EraseContext(contextId);
    };
    callbackService = sptr<DomainAccountCallbackService>::MakeSptr(callback, afterOnResultCallback);
    contextIdMap_[contextId] = callbackService;
    return true;
}

void DomainAccountClient::EraseContext(const uint64_t contextId)
{
    std::lock_guard<std::recursive_mutex> lock(contextIdMutex_);
    contextIdMap_.erase(contextId);
}

void DomainAccountClient::RestoreListenerRecords()
{
    std::lock_guard<std::mutex> lock(recordMutex_);
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
    std::lock_guard<std::mutex> lock(pluginServiceMutex_);
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

    if ((object->IsProxyObject()) && (!object->AddDeathRecipient(deathRecipient_))) {
        ACCOUNT_LOGE("Failed to add death recipient");
        deathRecipient_ = nullptr;
    }
    proxy_ = iface_cast<IDomainAccount>(object);
    return proxy_;
}
#endif // SUPPORT_DOMAIN_ACCOUNTS
}  // namespace AccountSA
}  // namespace OHOS

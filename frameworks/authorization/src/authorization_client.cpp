/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "authorization_client.h"
#include <mutex>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "app_mgr_client.h"
#include "auth_remote_object_stub.h"
#ifdef SUPPORT_AUTHORIZATION
#include "ohos_account_kits_impl.h"
#endif // SUPPORT_AUTHORIZATION
#include "privileges_map.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
namespace {
static std::mutex g_mutex;
// for auth app
static sptr<IRemoteObject> g_AuthAppRemoteObj = nullptr;
// for start request app
static sptr<AuthRemoteObjectStub> g_requestRemoteObj = nullptr;
}
AuthorizationClient::AuthorizationClient()
{}

AuthorizationClient::~AuthorizationClient()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_requestRemoteObj = nullptr;
    g_AuthAppRemoteObj = nullptr;
}

AuthorizationClient& AuthorizationClient::GetInstance()
{
    static AuthorizationClient instance;
    return instance;
}

ErrCode AuthorizationClient::RegisterAuthAppRemoteObject()
{
#ifdef SUPPORT_AUTHORIZATION
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_AuthAppRemoteObj != nullptr) {
        ACCOUNT_LOGI("Already has register");
        return ERR_OK;
    }
    g_AuthAppRemoteObj = new (std::nothrow) AuthRemoteObjectStub();
    if (g_AuthAppRemoteObj == nullptr) {
        ACCOUNT_LOGE("Remote object is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    auto proxy = GetAuthorizationProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get authorization proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    ErrCode errCode = proxy->RegisterAuthAppRemoteObject(g_AuthAppRemoteObj);
    if (errCode != ERR_OK) {
        g_AuthAppRemoteObj = nullptr;
    }
    return errCode;
#else
    return ERR_OK;
#endif // SUPPORT_AUTHORIZATION
}

ErrCode AuthorizationClient::UnRegisterAuthAppRemoteObject()
{
#ifdef SUPPORT_AUTHORIZATION
    std::lock_guard<std::mutex> lock(g_mutex);
    auto proxy = GetAuthorizationProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get authorization proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    ErrCode errCode = proxy->UnRegisterAuthAppRemoteObject();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to call unRegisterAuthAppRemoteObject, error:%{public}d", errCode);
        return errCode;
    }
    if (g_AuthAppRemoteObj != nullptr) {
        g_AuthAppRemoteObj = nullptr;
    }
    return ERR_OK;
#else
    return ERR_OK;
#endif // SUPPORT_AUTHORIZATION
}

void AuthorizationClient::EraseAuthCallBack()
{
#ifdef SUPPORT_AUTHORIZATION
    std::lock_guard<std::recursive_mutex> lock(callbackMutex_);
    if (callbackService_ != nullptr) {
        ACCOUNT_LOGI("Clear callbackService.");
        callbackService_ = nullptr;
    }
#endif // SUPPORT_AUTHORIZATION
}

#ifdef SUPPORT_AUTHORIZATION
bool AuthorizationClient::CheckCallbackService(const std::string &privilege,
    const std::shared_ptr<AuthorizationCallback> &callback)
{
    std::lock_guard<std::recursive_mutex> lock(callbackMutex_);
    if (callbackService_ != nullptr) {
        ACCOUNT_LOGE("Already has request");
        AuthorizationResult result;
        result.resultCode = AuthorizationResultCode::AUTHORIZATION_SYSTEM_BUSY;
        result.privilege = privilege;
        callback->OnResult(ERR_OK, result);
        return false;
    }
    return true;
}
#endif // SUPPORT_AUTHORIZATION

#ifdef SUPPORT_AUTHORIZATION
sptr<AuthRemoteObjectStub> AuthorizationClient::GetOrCreateRequestRemoteObject()
{
    std::lock_guard<std::mutex> glock(g_mutex);
    if (g_requestRemoteObj == nullptr) {
        g_requestRemoteObj = new (std::nothrow) AuthRemoteObjectStub();
        if (g_requestRemoteObj == nullptr) {
            ACCOUNT_LOGE("Remote object is nullptr");
            return nullptr;
        }
    }
    return g_requestRemoteObj;
}
#endif // SUPPORT_AUTHORIZATION

ErrCode AuthorizationClient::AcquireAuthorization(const std::string &privilege,
    const AcquireAuthorizationOptions &options, const std::shared_ptr<AuthorizationCallback> &callback,
    AuthorizationResult &authorizationResult)
{
#ifdef SUPPORT_AUTHORIZATION
    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (!CheckCallbackService(privilege, callback)) {
        return ERR_OK;
    }

    sptr<AuthRemoteObjectStub> requestRemoteObj = GetOrCreateRequestRemoteObject();
    if (requestRemoteObj == nullptr) {
        ACCOUNT_LOGE("Failed to get or create request remote object");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }

    sptr<AuthorizationCallbackService> temp = sptr<AuthorizationCallbackService>::MakeSptr(callback,
        []() { AuthorizationClient::GetInstance().EraseAuthCallBack(); });

    auto proxy = GetAuthorizationProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get authorization proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    ErrCode errCode = proxy->AcquireAuthorization(privilege, options,
        temp->AsObject(), requestRemoteObj->AsObject(), authorizationResult);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to acquire authorization, errCode:%{public}d", errCode);
        return errCode;
    }
    if (authorizationResult.resultCode == AUTHORIZATION_RESULT_FROM_CACHE) {
        ACCOUNT_LOGE("Get result form cache");
        return static_cast<int32_t>(authorizationResult.resultCode);
    }
    {
        std::lock_guard<std::recursive_mutex> lock(callbackMutex_);
        callbackService_ = temp;
    }

    return ERR_OK;
#else
    return static_cast<int32_t>(AUTHORIZATION_DENIED);
#endif // SUPPORT_AUTHORIZATION
}

ErrCode AuthorizationClient::ReleaseAuthorization(const std::string &privilege)
{
#ifdef SUPPORT_AUTHORIZATION
    auto proxy = GetAuthorizationProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get authorization proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->ReleaseAuthorization(privilege);
#else
    ErrCode res = AccountPermissionManager::CheckSystemApp();
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Caller is not system application, result = %{public}d.", res);
        return res;
    }
    uint32_t privilegeId = 0;
    if (!TransferPrivilegeToCode(privilege, privilegeId)) {
        ACCOUNT_LOGE("TransferPrivilegeToCode failed, privilege = %{public}s.", privilege.c_str());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return ERR_OK;
#endif // SUPPORT_AUTHORIZATION
}

ErrCode AuthorizationClient::CheckAuthorization(const std::string &privilege, bool &isAuthorized)
{
#ifdef SUPPORT_AUTHORIZATION
    isAuthorized = false;
    auto proxy = GetAuthorizationProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get authorization proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CheckAuthorization(privilege, isAuthorized);
#else
    isAuthorized = false;
    ErrCode errCode = AccountPermissionManager::CheckSystemApp();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Caller is not system application, errCode: %{public}d", errCode);
        return errCode;
    }
    uint32_t privilegeId = 0;
    if (!TransferPrivilegeToCode(privilege, privilegeId)) {
        ACCOUNT_LOGE("Failed to get privilegeId from privilege");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return ERR_OK;
#endif // SUPPORT_AUTHORIZATION
}

ErrCode AuthorizationClient::CheckAuthorization(const std::string &privilege, int32_t pid, bool &isAuthorized)
{
#ifdef SUPPORT_AUTHORIZATION
    isAuthorized = false;
    auto proxy = GetAuthorizationProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get authorization proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CheckAuthorization(privilege, pid, isAuthorized);
#else
    isAuthorized = true;
    ErrCode errCode = AccountPermissionManager::CheckSystemApp();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Caller is not system application, errCode: %{public}d", errCode);
        return errCode;
    }
    uint32_t privilegeId = 0;
    if (!TransferPrivilegeToCode(privilege, privilegeId)) {
        ACCOUNT_LOGE("Failed to get privilegeId from privilege");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return ERR_OK;
#endif // SUPPORT_AUTHORIZATION
}

ErrCode AuthorizationClient::CheckAuthorization(const std::string &privilege, int32_t pid,
    const std::vector<uint8_t> &token, CheckAuthorizationResult &result)
{
#ifdef SUPPORT_AUTHORIZATION
    result.isAuthorized = false;
    result.challenge = {};
    auto proxy = GetAuthorizationProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get authorization proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CheckAuthorization(privilege, pid, token, result);
#else
    result.isAuthorized = true;
    result.challenge = {};
    ErrCode errCode = AccountPermissionManager::CheckSystemApp();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Caller is not system application, errCode: %{public}d", errCode);
        return errCode;
    }
    uint32_t privilegeId = 0;
    if (!TransferPrivilegeToCode(privilege, privilegeId)) {
        ACCOUNT_LOGE("Failed to get privilegeId from privilege");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (token.empty()) {
        ACCOUNT_LOGE("Failed to get parameter, token is empty");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return ERR_OK;
#endif // SUPPORT_AUTHORIZATION
}

#ifdef SUPPORT_AUTHORIZATION
void AuthorizationClient::ResetAuthorizationProxy(const wptr<IRemoteObject>& remote)
{
    {
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
    {
        std::lock_guard<std::recursive_mutex> lock(callbackMutex_);
        if (callbackService_ != nullptr) {
            AuthorizationResult result;
            callbackService_->OnResult(ERR_ACCOUNT_COMMON_GET_PROXY, result);
        }
    }
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_AuthAppRemoteObj != nullptr) {
            int32_t errCode = DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->KillApplicationSelf();
            ACCOUNT_LOGI("KillAppApplicationSelf end, errCode:%{public}d", errCode);
        }
    }
}

void AuthorizationClient::AuthorizationDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr");
        return;
    }
    AuthorizationClient::GetInstance().ResetAuthorizationProxy(remote);
}

sptr<IAuthorization> AuthorizationClient::GetAuthorizationProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }
    sptr<IRemoteObject> object = OhosAccountKitsImpl::GetInstance().GetAuthorizationService();
    if (object == nullptr) {
        ACCOUNT_LOGE("Failed to get authorizationt service");
        return nullptr;
    }
    deathRecipient_ = new (std::nothrow) AuthorizationDeathRecipient();
    if (deathRecipient_ == nullptr) {
        ACCOUNT_LOGE("Failed to create authorization death recipient");
        return nullptr;
    }

    if ((object->IsProxyObject()) && (!object->AddDeathRecipient(deathRecipient_))) {
        ACCOUNT_LOGE("Failed to add death recipient");
        deathRecipient_ = nullptr;
        return nullptr;
    }
    proxy_ = iface_cast<IAuthorization>(object);
    if (proxy_ == nullptr) {
        ACCOUNT_LOGE("Failed to get os account proxy");
        object->RemoveDeathRecipient(deathRecipient_);
        deathRecipient_ = nullptr;
    }
    return proxy_;
}
#endif // SUPPORT_AUTHORIZATION
}
}

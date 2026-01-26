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
#include "account_error_no.h"
#include "account_log_wrapper.h"
#ifdef SUPPORT_AUTHORIZATION
#include "ohos_account_kits_impl.h"
#endif // SUPPORT_AUTHORIZATION

namespace OHOS {
namespace AccountSA {
AuthorizationClient::AuthorizationClient()
{}

AuthorizationClient& AuthorizationClient::GetInstance()
{
    static AuthorizationClient instance;
    return instance;
}

ErrCode AuthorizationClient::AcquireAuthorization(const std::string &privilege,
    const AcquireAuthorizationOptions &options, const std::shared_ptr<AuthorizationResultCallback> &callback)
{
#ifdef SUPPORT_AUTHORIZATION
    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    auto proxy = GetAuthorizationProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Failed to get authorization proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->AcquireAuthorization(privilege, options, callback->AsObject());
#else
    return ERR_JS_INVALID_PARAMETER;
#endif // SUPPORT_AUTHORIZATION
}

#ifdef SUPPORT_AUTHORIZATION
void AuthorizationClient::ResetAuthorizationProxy(const wptr<IRemoteObject>& remote)
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

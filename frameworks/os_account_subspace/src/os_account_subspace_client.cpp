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

#include "os_account_subspace_client.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "ohos_account_kits_impl.h"

namespace OHOS {
namespace AccountSA {
OsAccountSubspaceClient &OsAccountSubspaceClient::GetInstance()
{
    static OsAccountSubspaceClient instance;
    return instance;
}

OsAccountSubspaceClient::OsAccountSubspaceClient() {}

ErrCode OsAccountSubspaceClient::CreateOsAccountSubspace(
    int32_t osAccountId, OsAccountSubspaceResult &subspaceResult)
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    auto proxy = GetOsAccountSubspaceProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("proxy is nullptr");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CreateOsAccountSubspace(osAccountId, subspaceResult);
#else
    (void)osAccountId;
    (void)subspaceResult;
    return ERR_OS_ACCOUNT_SUBSPACE_LIMIT;
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
}

ErrCode OsAccountSubspaceClient::DeleteOsAccountSubspace(
    int32_t osAccountId, int32_t subspaceId)
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    auto proxy = GetOsAccountSubspaceProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("proxy is nullptr");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->DeleteOsAccountSubspace(osAccountId, subspaceId);
#else
    (void)osAccountId;
    (void)subspaceId;
    return ERR_ACCOUNT_COMMON_ACCOUNT_IS_RESTRICTED;
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
}

ErrCode OsAccountSubspaceClient::SwitchOsAccountSubspace(
    int32_t osAccountId, int32_t subspaceId)
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    auto proxy = GetOsAccountSubspaceProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("proxy is nullptr");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SwitchOsAccountSubspace(osAccountId, subspaceId);
#else
    constexpr int32_t singleSubspaceMultiplier = 1000;
    return (subspaceId == osAccountId * singleSubspaceMultiplier) ? ERR_OK
        : ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
}

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
void OsAccountSubspaceClient::OsAccountSubspaceDeathRecipient::OnRemoteDied(
    const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr");
        return;
    }
    OsAccountSubspaceClient::GetInstance().ResetProxy(remote);
}

sptr<IOsAccountSubspace> OsAccountSubspaceClient::GetOsAccountSubspaceProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }
    sptr<IRemoteObject> object = OhosAccountKitsImpl::GetInstance().GetOsAccountSubspaceService();
    if (object == nullptr) {
        ACCOUNT_LOGE("failed to get distributed account space service");
        return nullptr;
    }
    deathRecipient_ = new (std::nothrow) OsAccountSubspaceDeathRecipient();
    if (deathRecipient_ == nullptr) {
        ACCOUNT_LOGE("failed to create death recipient");
        return nullptr;
    }
    if ((object->IsProxyObject()) && (!object->AddDeathRecipient(deathRecipient_))) {
        ACCOUNT_LOGE("Failed to add death recipient");
        deathRecipient_ = nullptr;
        return nullptr;
    }
    proxy_ = iface_cast<IOsAccountSubspace>(object);
    return proxy_;
}

void OsAccountSubspaceClient::ResetProxy(const wptr<IRemoteObject> &remote)
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
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

ErrCode OsAccountSubspaceClient::GetOsAccountForegroundSubProfileId(
    int32_t &subProfileId)
{
    return OhosAccountKits::GetInstance().GetOsAccountForegroundSubProfileId(subProfileId);
}

ErrCode OsAccountSubspaceClient::GetOsAccountForegroundSubProfileId(
    int32_t osAccountId, int32_t &subProfileId)
{
    return OhosAccountKits::GetInstance().GetOsAccountForegroundSubProfileId(osAccountId, subProfileId);
}

ErrCode OsAccountSubspaceClient::GetOsAccountSubProfileIds(
    std::vector<int32_t> &subProfileIds)
{
    return OhosAccountKits::GetInstance().GetOsAccountSubProfileIds(subProfileIds);
}

ErrCode OsAccountSubspaceClient::GetOsAccountSubProfileIds(
    int32_t osAccountId, std::vector<int32_t> &subProfileIds)
{
    return OhosAccountKits::GetInstance().GetOsAccountSubProfileIds(osAccountId, subProfileIds);
}

ErrCode OsAccountSubspaceClient::GetOsAccountLocalIdForSubProfile(
    int32_t subProfileId, int32_t &osAccountId)
{
    return OhosAccountKits::GetInstance().GetOsAccountLocalIdForSubProfile(subProfileId, osAccountId);
}

ErrCode OsAccountSubspaceClient::GetOsAccountSubProfile(
    int32_t subProfileId, OsAccountSubspaceResult &subspaceResult,
    OhosAccountInfo &distributedInfo)
{
    return OhosAccountKits::GetInstance().GetOsAccountSubProfile(subProfileId, subspaceResult, distributedInfo);
}

ErrCode OsAccountSubspaceClient::GetOsAccountSubProfile(
    int32_t osAccountId, int32_t subProfileId, OsAccountSubspaceResult &subspaceResult,
    OhosAccountInfo &distributedInfo)
{
    return OhosAccountKits::GetInstance().GetOsAccountSubProfile(osAccountId, subProfileId, subspaceResult,
        distributedInfo);
}
}  // namespace AccountSA
}  // namespace OHOS
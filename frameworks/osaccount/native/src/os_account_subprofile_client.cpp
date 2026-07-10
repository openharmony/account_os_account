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

#include "os_account_subprofile_client.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "ohos_account_kits_impl.h"
#include "os_account_constants.h"
#include "os_account_sub_profile_event_service.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
OsAccountSubProfileClient &OsAccountSubProfileClient::GetInstance()
{
    static OsAccountSubProfileClient instance;
    return instance;
}

OsAccountSubProfileClient::OsAccountSubProfileClient()
{
    auto callbackFunc = [] (int32_t systemAbilityId, const std::string &deviceId) {
        if (systemAbilityId == SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN) {
            OsAccountSubProfileClient::GetInstance().RestoreSubscribe();
        }
    };
    OhosAccountKitsImpl::GetInstance().SubscribeSystemAbility(callbackFunc);
}

ErrCode OsAccountSubProfileClient::CreateOsAccountSubProfile(
    int32_t osAccountId, OsAccountSubspaceResult &subspaceResult)
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    auto proxy = GetOsAccountSubProfileProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("proxy is nullptr");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CreateOsAccountSubProfile(osAccountId, subspaceResult);
#else
    (void)osAccountId;
    (void)subspaceResult;
    return ERR_OS_ACCOUNT_SUBSPACE_LIMIT;
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
}

ErrCode OsAccountSubProfileClient::DeleteOsAccountSubProfile(
    int32_t osAccountId, int32_t subspaceId)
{
    // Headless subprofile (index=0) cannot be deleted
    if (subspaceId == osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER) {
        ACCOUNT_LOGE("Cannot delete headless subprofile (index=0), subspaceId=%{public}d", subspaceId);
        return ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED;
    }
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    auto proxy = GetOsAccountSubProfileProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("proxy is nullptr");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->DeleteOsAccountSubProfile(osAccountId, subspaceId);
#else
    (void)osAccountId;
    (void)subspaceId;
    return ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED;
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
}

ErrCode OsAccountSubProfileClient::SwitchOsAccountSubProfile(
    int32_t osAccountId, int32_t subspaceId)
{
    // Headless subprofile (index=0) cannot be switched to as foreground
    if (subspaceId == osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER) {
        ACCOUNT_LOGE("Cannot switch to headless subprofile (index=0), subspaceId=%{public}d", subspaceId);
        return ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED;
    }
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    auto proxy = GetOsAccountSubProfileProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("proxy is nullptr");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SwitchOsAccountSubProfile(osAccountId, subspaceId);
#else
    constexpr int32_t singleSubspaceMultiplier = 1000;
    return (subspaceId == osAccountId * singleSubspaceMultiplier) ? ERR_OK
        : ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
}

void OsAccountSubProfileClient::OsAccountSubProfileDeathRecipient::OnRemoteDied(
    const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr");
        return;
    }
    OsAccountSubProfileClient::GetInstance().ResetProxy(remote);
}

sptr<IOsAccountSubProfile> OsAccountSubProfileClient::GetOsAccountSubProfileProxy()
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
    deathRecipient_ = new (std::nothrow) OsAccountSubProfileDeathRecipient();
    if (deathRecipient_ == nullptr) {
        ACCOUNT_LOGE("failed to create death recipient");
        return nullptr;
    }
    if ((object->IsProxyObject()) && (!object->AddDeathRecipient(deathRecipient_))) {
        ACCOUNT_LOGE("Failed to add death recipient");
        deathRecipient_ = nullptr;
        return nullptr;
    }
    proxy_ = iface_cast<IOsAccountSubProfile>(object);
    return proxy_;
}

void OsAccountSubProfileClient::ResetProxy(const wptr<IRemoteObject> &remote)
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

ErrCode OsAccountSubProfileClient::GetOsAccountForegroundSubProfileId(
    int32_t &subProfileId)
{
    return OhosAccountKits::GetInstance().GetOsAccountForegroundSubProfileId(subProfileId);
}

ErrCode OsAccountSubProfileClient::GetOsAccountForegroundSubProfileId(
    int32_t osAccountId, int32_t &subProfileId)
{
    return OhosAccountKits::GetInstance().GetOsAccountForegroundSubProfileId(osAccountId, subProfileId);
}

ErrCode OsAccountSubProfileClient::GetOsAccountSubProfileIds(
    std::vector<int32_t> &subProfileIds)
{
    return OhosAccountKits::GetInstance().GetOsAccountSubProfileIds(subProfileIds);
}

ErrCode OsAccountSubProfileClient::GetOsAccountSubProfileIds(
    int32_t osAccountId, std::vector<int32_t> &subProfileIds)
{
    return OhosAccountKits::GetInstance().GetOsAccountSubProfileIds(osAccountId, subProfileIds);
}

ErrCode OsAccountSubProfileClient::GetOsAccountLocalIdForSubProfile(
    int32_t subProfileId, int32_t &osAccountId)
{
    return OhosAccountKits::GetInstance().GetOsAccountLocalIdForSubProfile(subProfileId, osAccountId);
}

ErrCode OsAccountSubProfileClient::GetOsAccountSubProfile(
    int32_t subProfileId, OsAccountSubspaceResult &subspaceResult,
    OhosAccountInfo &distributedInfo)
{
    return OhosAccountKits::GetInstance().GetOsAccountSubProfile(subProfileId, subspaceResult, distributedInfo);
}

ErrCode OsAccountSubProfileClient::GetOsAccountSubProfile(
    int32_t osAccountId, int32_t subProfileId, OsAccountSubspaceResult &subspaceResult,
    OhosAccountInfo &distributedInfo)
{
    return OhosAccountKits::GetInstance().GetOsAccountSubProfile(osAccountId, subProfileId, subspaceResult,
        distributedInfo);
}

void OsAccountSubProfileClient::RestoreSubscribe()
{
    auto proxy = GetOsAccountSubProfileProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed.");
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    std::set<OsAccountSubProfileEventType> existingTypes;
    OsAccountSubProfileEventService::GetInstance()->GetAllType(existingTypes);
    if (existingTypes.empty()) {
        return;
    }
    ErrCode result = SubscribeNewTypesToService(proxy, existingTypes);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Subscribe to service space failed, result=%{public}d.", result);
    }
}

void OsAccountSubProfileClient::GetNewSubProfileEventTypes(
    const std::set<OsAccountSubProfileEventType> &types,
    std::set<OsAccountSubProfileEventType> &newTypes)
{
    std::set<OsAccountSubProfileEventType> existingTypes;
    OsAccountSubProfileEventService::GetInstance()->GetAllType(existingTypes);
    for (auto type : types) {
        if (existingTypes.find(type) == existingTypes.end()) {
            newTypes.insert(type);
        }
    }
}

ErrCode OsAccountSubProfileClient::SubscribeNewTypesToService(
    const sptr<IOsAccountSubProfile> &proxy,
    const std::set<OsAccountSubProfileEventType> &newTypes)
{
    std::vector<int32_t> typeInts;
    for (auto type : newTypes) {
        typeInts.push_back(static_cast<int32_t>(type));
    }
    return proxy->SubscribeOsAccountSubProfileEvents(typeInts,
        OsAccountSubProfileEventService::GetInstance()->AsObject());
}

ErrCode OsAccountSubProfileClient::SubscribeOsAccountSubProfileEvents(
    const std::set<OsAccountSubProfileEventType>& types,
    const std::shared_ptr<OsAccountSubProfileSubscribeCallback>& callback)
{
    ACCOUNT_LOGI("Batch subscribe os account sub profile events in client.");
    if (callback == nullptr || types.empty()) {
        ACCOUNT_LOGE("Invalid parameter, callback null or types empty.");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    auto proxy = GetOsAccountSubProfileProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    if (OsAccountSubProfileEventService::GetInstance()->IsAllTypeExist(types, callback)) {
        ACCOUNT_LOGI("Callback already has sub profile event listener.");
        return ERR_OK;
    }

    if (OsAccountSubProfileEventService::GetInstance()->GetCallbackSize() >=
        Constants::DISTRIBUTED_SUBSCRIBER_MAX_SIZE) {
        ACCOUNT_LOGE("The maximum number of eventListeners has been reached.");
        return ERR_OHOSACCOUNT_KIT_SUBSCRIBE_MAX_SIZE_ERROR;
    }

    if (OsAccountSubProfileEventService::GetInstance()->AsObject() == nullptr) {
        ACCOUNT_LOGE("Create sub profile event service failed.");
        return ERR_OHOSACCOUNT_KIT_SUBSCRIBE_ERROR;
    }

    std::set<OsAccountSubProfileEventType> newTypes;
    GetNewSubProfileEventTypes(types, newTypes);

    ErrCode result = ERR_OK;
    if (!newTypes.empty()) {
        result = SubscribeNewTypesToService(proxy, newTypes);
    }
    if (result == ERR_OK) {
        OsAccountSubProfileEventService::GetInstance()->AddTypes(types, callback);
    }
    return result;
}

ErrCode OsAccountSubProfileClient::UnsubscribeOsAccountSubProfileEvents(
    const std::shared_ptr<OsAccountSubProfileSubscribeCallback>& callback)
{
    ACCOUNT_LOGI("Unsubscribe os account sub profile events in client.");
    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr.");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    auto proxy = GetOsAccountSubProfileProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    sptr<IRemoteObject> listener = OsAccountSubProfileEventService::GetInstance()->AsObject();
    std::lock_guard<std::mutex> lock(mutex_);

    std::set<OsAccountSubProfileEventType> removedTypes;
    OsAccountSubProfileEventService::GetInstance()->GetTypesToRemove(callback, removedTypes);

    if (removedTypes.empty()) {
        ACCOUNT_LOGI("All types still have other subscribers, only delete client data.");
        OsAccountSubProfileEventService::GetInstance()->DeleteCallback(callback);
        return ERR_OK;
    }

    std::vector<int32_t> typeInts;
    for (auto type : removedTypes) {
        typeInts.push_back(static_cast<int32_t>(type));
    }
    ErrCode result = proxy->UnsubscribeOsAccountSubProfileEvents(typeInts, listener);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Unsubscribe sub profile events from service failed, result=%{public}d.", result);
        return result;
    }

    OsAccountSubProfileEventService::GetInstance()->DeleteCallback(callback);
    return ERR_OK;
}

ErrCode OsAccountSubProfileClient::GetOsAccountSubProfileId(
    int32_t osAccountLocalId, int32_t appIndex, int32_t &subProfileId)
{
    return OhosAccountKits::GetInstance().GetOsAccountSubProfileId(
        osAccountLocalId, appIndex, subProfileId);
}

ErrCode OsAccountSubProfileClient::GetOsAccountSubProfileId(
    uint32_t tokenId, int32_t &subProfileId)
{
    return OhosAccountKits::GetInstance().GetOsAccountSubProfileId(tokenId, subProfileId);
}

ErrCode OsAccountSubProfileClient::GetOsAccountSubProfileIndex(
    int32_t osAccountLocalId, int32_t subProfileId, int32_t &index)
{
    return OhosAccountKits::GetInstance().GetOsAccountSubProfileIndex(
        osAccountLocalId, subProfileId, index);
}
}  // namespace AccountSA
}  // namespace OHOS

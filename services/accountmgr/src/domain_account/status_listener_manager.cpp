/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "status_listener_manager.h"

#include <datetime_ex.h>
#include <future>
#include <pthread.h>
#include <thread>

#include "account_error_no.h"
#include "account_event_provider.h"
#include "account_log_wrapper.h"
#ifdef HAS_CES_PART
#include "common_event_support.h"
#endif // HAS_CES_PART
#include "domain_account_callback_proxy.h"
#include "status_listener_death_recipient.h"

namespace OHOS {
namespace AccountSA {
namespace {
static const int INVALID_USERID = -1;
}

StatusListenerManager& StatusListenerManager::GetInstance()
{
    static StatusListenerManager instance;
    return instance;
}

StatusListenerManager::StatusListenerManager() : listenerDeathRecipient_(sptr<IRemoteObject::DeathRecipient>(
    new (std::nothrow) StatusListenerDeathRecipient()))
{
}

StatusListenerManager::~StatusListenerManager()
{
}

std::string StatusListenerManager::GetDomainAccountStr(const std::string &domain, const std::string &accountName) const
{
    return domain + "&" + accountName;
}

sptr<IRemoteObject> StatusListenerManager::GetListenerInMap(const std::string &domainAccountStr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = statusListenerMap_.find(domainAccountStr);
    if (iter != statusListenerMap_.end()) {
        return iter->second;
    }
    return nullptr;
}

ErrCode StatusListenerManager::InsertListenerToMap(
    const std::string &domain, const std::string &accountName, const sptr<IRemoteObject> &listener)
{
    if (listener == nullptr) {
        ACCOUNT_LOGE("input is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    std::string domainAccountStr = GetDomainAccountStr(domain, accountName);
    if (GetListenerInMap(domainAccountStr) != nullptr) {
        ACCOUNT_LOGE("listener has exist");
        return ERR_ACCOUNT_COMMON_LISTENER_EXIST_FAILED;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if ((listenerDeathRecipient_ != nullptr) && (!listener->AddDeathRecipient(listenerDeathRecipient_))) {
        ACCOUNT_LOGE("AddDeathRecipient failed");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }

    statusListenerMap_[domainAccountStr] = listener;
    return 0;
}

ErrCode StatusListenerManager::RemoveListenerByStr(const std::string &domain, const std::string &accountName)
{
    ACCOUNT_LOGI("RemoveListenerByStr enter.");
    std::string domainAccountStr = GetDomainAccountStr(domain, accountName);
    sptr<IRemoteObject> listener = GetListenerInMap(domainAccountStr);
    if (listener == nullptr) {
        ACCOUNT_LOGE("listener does not exist.");
        return ERR_ACCOUNT_COMMON_LISTENER_NOT_EXIST_FAILED;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    statusListenerMap_.erase(domainAccountStr);
    if (listenerDeathRecipient_ != nullptr) {
        listener->RemoveDeathRecipient(listenerDeathRecipient_);
    }
    return ERR_OK;
}

ErrCode StatusListenerManager::RemoveListenerByObject(const sptr<IRemoteObject> &listener)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = statusListenerMap_.begin();
    while (iter != statusListenerMap_.end()) {
        if (listener == iter->second) {
            statusListenerMap_.erase(iter->first);
            if (listenerDeathRecipient_ != nullptr) {
                listener->RemoveDeathRecipient(listenerDeathRecipient_);
            }
            ACCOUNT_LOGI("listener erased");
            return ERR_OK;
        }
        iter++;
    }
    return ERR_ACCOUNT_COMMON_LISTENER_NOT_EXIST_FAILED;
}

void StatusListenerManager::DomainAccountEventParcel(const DomainAccountEventData &report, Parcel &parcel)
{
    if (!report.domainAccountInfo.Marshalling(parcel)) {
        ACCOUNT_LOGE("write domainAccountInfo failed.");
        return;
    }
    if (!parcel.WriteInt32(report.event)) {
        ACCOUNT_LOGE("write event failed.");
        return;
    }
    if (!parcel.WriteInt32(report.status)) {
        ACCOUNT_LOGE("write status failed.");
        return;
    }
    return;
}

void StatusListenerManager::NotifyEventAsync(const DomainAccountEventData &report)
{
    ACCOUNT_LOGI("report.event %{public}d", report.event);
#ifdef HAS_CES_PART
    AccountEventProvider::EventPublish(
        EventFwk::CommonEventSupport::COMMON_EVENT_DOMAIN_ACCOUNT_STATUS_CHANGED, INVALID_USERID, &report);
#else  // HAS_CES_PART
    ACCOUNT_LOGI("No common event part! Publish nothing!");
#endif // HAS_CES_PART

    std::string domainAccountStr = GetDomainAccountStr(
        report.domainAccountInfo.domain_, report.domainAccountInfo.accountName_);
    auto listener = GetListenerInMap(domainAccountStr);
    if (listener == nullptr) {
        ACCOUNT_LOGE("userId listener does not exist.");
        return;
    }
    auto callback = iface_cast<IDomainAccountCallback>(listener);
    if (callback != nullptr) {
        ACCOUNT_LOGI("callback execute");
        Parcel parcel;
        DomainAccountEventParcel(report, parcel);
        callback->OnResult(ERR_OK, parcel);
        ACCOUNT_LOGI("The callback execution is complete");
        return;
    }
    ACCOUNT_LOGE("callback is null.");
    return;
}
} // namespace AccountSA
} // namespace OHOS

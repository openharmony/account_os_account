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
#ifdef HAS_CES_PART
static const int INVALID_USERID = -1;
#endif // HAS_CES_PART
} // namespace

StatusListenerManager& StatusListenerManager::GetInstance()
{
    static StatusListenerManager *instance = new (std::nothrow) StatusListenerManager();
    return *instance;
}

StatusListenerManager::StatusListenerManager() : listenerDeathRecipient_(sptr<IRemoteObject::DeathRecipient>(
    new (std::nothrow) StatusListenerDeathRecipient()))
{
}

StatusListenerManager::~StatusListenerManager()
{}

ErrCode StatusListenerManager::InsertListenerToRecords(const sptr<IRemoteObject> &listener)
{
    if (listener == nullptr) {
        ACCOUNT_LOGE("listener is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (listenerAll_.find(listener) != listenerAll_.end()) {
        ACCOUNT_LOGI("listener is already exist");
        return ERR_OK;
    }
    if ((listener->IsProxyObject()) && (listenerDeathRecipient_ != nullptr) &&
        (!listener->AddDeathRecipient(listenerDeathRecipient_))) {
        ACCOUNT_LOGE("AddDeathRecipient failed");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }
    listenerAll_.insert(listener);
    return ERR_OK;
}

ErrCode StatusListenerManager::RemoveListenerByListener(const sptr<IRemoteObject> &listener)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto listenerToAllIt = listenerAll_.find(listener);
    if (listenerToAllIt != listenerAll_.end()) {
        listenerAll_.erase(listenerToAllIt);
    }
    if ((listener->IsProxyObject()) && (listenerDeathRecipient_ != nullptr)) {
        listener->RemoveDeathRecipient(listenerDeathRecipient_);
    }
    return ERR_OK;
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
    if (!parcel.WriteInt32(report.userId)) {
        ACCOUNT_LOGE("write userId failed.");
        return;
    }
    return;
}

void StatusListenerManager::NotifyEventAsync(const DomainAccountEventData &report)
{
    ACCOUNT_LOGI("report.event %{public}d, report.status %{public}d", report.event, report.status);
#ifdef HAS_CES_PART
    AccountEventProvider::EventPublish(
        EventFwk::CommonEventSupport::COMMON_EVENT_DOMAIN_ACCOUNT_STATUS_CHANGED, INVALID_USERID, &report);
#else  // HAS_CES_PART
    ACCOUNT_LOGI("No common event part! Publish nothing!");
#endif // HAS_CES_PART
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto record : listenerAll_) {
        auto callback = iface_cast<IDomainAccountCallback>(record);
        if (callback == nullptr) {
            ACCOUNT_LOGE("callback is nullptr!");
            continue;
        }
        Parcel parcel;
        DomainAccountEventParcel(report, parcel);
        callback->OnResult(ERR_OK, parcel);
    }
}
} // namespace AccountSA
} // namespace OHOS

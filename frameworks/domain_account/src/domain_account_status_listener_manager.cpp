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

#include "domain_account_status_listener_manager.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
DomainAccountStatusListenerManager::DomainAccountStatusListenerManager()
{}

DomainAccountStatusListenerManager::~DomainAccountStatusListenerManager()
{}

void DomainAccountStatusListenerManager::OnResult(const int32_t errCode, Parcel &parcel)
{
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("OnResult err is %{public}d", errCode);
        return;
    }
    DomainAccountEventData report;
    if (!report.domainAccountInfo.ReadFromParcel(parcel)) {
        ACCOUNT_LOGE("ReadFromParcel failed");
        return;
    }
    int32_t event;
    if (!parcel.ReadInt32(event)) {
        ACCOUNT_LOGE("Read event failed");
        return;
    }
    report.event = static_cast<DomainAccountEvent>(event);
    int32_t status;
    if (!parcel.ReadInt32(status)) {
        ACCOUNT_LOGE("Read status failed");
        return;
    }
    report.status = static_cast<DomainAccountStatus>(status);
    int32_t userId;
    if (!parcel.ReadInt32(userId)) {
        ACCOUNT_LOGE("Read userId failed");
        return;
    }
    report.userId = userId;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto listener : listenerAll_) {
        listener->OnStatusChanged(report);
    }
}

void DomainAccountStatusListenerManager::InsertRecord(const std::shared_ptr<DomainAccountStatusListener> &listener)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (listenerAll_.find(listener) != listenerAll_.end()) {
        ACCOUNT_LOGI("listener alredy exist");
        return;
    }
    listenerAll_.insert(listener);
}

void DomainAccountStatusListenerManager::RemoveRecord(const std::shared_ptr<DomainAccountStatusListener> &listener)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto listenerAllIter = listenerAll_.find(listener);
    if (listenerAllIter == listenerAll_.end()) {
        return;
    }
    listenerAll_.erase(listenerAllIter);
}

bool DomainAccountStatusListenerManager::IsRecordEmpty()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return listenerAll_.empty();
}
}  // namespace AccountSA
}  // namespace OHOS
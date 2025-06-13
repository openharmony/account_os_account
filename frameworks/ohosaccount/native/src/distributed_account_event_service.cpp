/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "account_log_wrapper.h"
#include "distributed_account_event_service.h"

namespace OHOS {
namespace AccountSA {
DistributedAccountEventService::DistributedAccountEventService()
{}

DistributedAccountEventService::~DistributedAccountEventService()
{}

int32_t DistributedAccountEventService::GetCallbackSize()
{
    std::lock_guard<std::mutex> lock(mapLock_);
    return callbackMap_.size();
}

bool DistributedAccountEventService::IsTypeExist(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
    const std::shared_ptr<DistributedAccountSubscribeCallback> &callback)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    auto it = callbackMap_.find(callback);
    if (it == callbackMap_.end()) {
        return false;
    }
    auto types = it->second;
    return types.find(type) != types.end();
}

void DistributedAccountEventService::AddType(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
    const std::shared_ptr<DistributedAccountSubscribeCallback> &callback)
{
    if (callback == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(mapLock_);
    auto it = callbackMap_.find(callback);
    if (it == callbackMap_.end()) {
        callbackMap_[callback] = {type};
    } else {
        it->second.insert(type);
    }

    auto itemType = typeMap_.find(type);
    if (itemType == typeMap_.end()) {
        typeMap_[type] = {callback};
    } else {
        itemType->second.insert(callback);
    }
    ACCOUNT_LOGI("Distributed client subscribe, type size=%{public}zu, callback size=%{public}zu.",
        typeMap_.size(), callbackMap_.size());
}

void DistributedAccountEventService::DeleteType(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
    const std::shared_ptr<DistributedAccountSubscribeCallback> &callback)
{
    if (callback == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(mapLock_);
    auto it = callbackMap_.find(callback);
    if (it == callbackMap_.end()) {
        return;
    }
    it->second.erase(type);

    if (it->second.size() == 0) {
        callbackMap_.erase(it);
    }

    auto itemType = typeMap_.find(type);
    if (itemType == typeMap_.end()) {
        return;
    }
    itemType->second.erase(callback);
    if (itemType->second.size() == 0) {
        typeMap_.erase(itemType);
    }
    ACCOUNT_LOGI("Distributed client unsubscribe, type size=%{public}zu, callback size=%{public}zu.",
        typeMap_.size(), callbackMap_.size());
}

void DistributedAccountEventService::GetAllType(std::set<DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE> &typeList)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    for (auto &item : typeMap_) {
        typeList.insert(item.first);
    }
}

ErrCode DistributedAccountEventService::OnAccountsChanged(const DistributedAccountEventData &eventData)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    auto it = typeMap_.find(eventData.type_);
    if (it == typeMap_.end()) {
        ACCOUNT_LOGI("callback is empty");
        return ERR_OK;
    }
    for (const auto &item : it->second) {
        item->OnAccountsChanged(eventData);
    }
    return ERR_OK;
}

DistributedAccountEventService *DistributedAccountEventService::GetInstance()
{
    static sptr<DistributedAccountEventService> instance = new (std::nothrow) DistributedAccountEventService();
    return instance.GetRefPtr();
}
}  // namespace AccountSA
}  // namespace OHOS

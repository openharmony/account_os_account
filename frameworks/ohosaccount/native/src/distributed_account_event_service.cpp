/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
#include <algorithm>
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

int32_t DistributedAccountEventService::GetSpaceCallbackSize()
{
    std::lock_guard<std::mutex> lock(spaceMapLock_);
    return spaceCallbackMap_.size();
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

void DistributedAccountEventService::AddSpaceTypes(const std::set<DistributedAccountSpaceEventType>& types,
    const std::shared_ptr<DistributedAccountSubscribeCallback> &callback)
{
    if (callback == nullptr || types.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(spaceMapLock_);
    auto it = spaceCallbackMap_.find(callback);
    if (it == spaceCallbackMap_.end()) {
        spaceCallbackMap_[callback] = types;
    } else {
        it->second.insert(types.begin(), types.end());
    }

    for (auto type : types) {
        auto itemType = spaceTypeMap_.find(type);
        if (itemType == spaceTypeMap_.end()) {
            spaceTypeMap_[type] = {callback};
        } else {
            itemType->second.insert(callback);
        }
    }
    ACCOUNT_LOGI("Distributed client subscribe space events, type size=%{public}zu, callback size=%{public}zu.",
        spaceTypeMap_.size(), spaceCallbackMap_.size());
}

void DistributedAccountEventService::DeleteSpaceCallback(
    const std::shared_ptr<DistributedAccountSubscribeCallback> &callback)
{
    if (callback == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(spaceMapLock_);
    auto it = spaceCallbackMap_.find(callback);
    if (it == spaceCallbackMap_.end()) {
        return;
    }

    auto callbackTypes = it->second;
    spaceCallbackMap_.erase(it);

    for (auto type : callbackTypes) {
        auto itemType = spaceTypeMap_.find(type);
        if (itemType != spaceTypeMap_.end()) {
            itemType->second.erase(callback);
            if (itemType->second.empty()) {
                spaceTypeMap_.erase(itemType);
            }
        }
    }
    ACCOUNT_LOGI("Distributed client delete space callback.");
}

void DistributedAccountEventService::GetSpaceTypesToRemove(
    const std::shared_ptr<DistributedAccountSubscribeCallback> &callback,
    std::set<DistributedAccountSpaceEventType> &removedTypes)
{
    if (callback == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(spaceMapLock_);
    auto it = spaceCallbackMap_.find(callback);
    if (it == spaceCallbackMap_.end()) {
        return;
    }

    auto callbackTypes = it->second;
    for (auto type : callbackTypes) {
        auto itemType = spaceTypeMap_.find(type);
        if (itemType != spaceTypeMap_.end()) {
            if (itemType->second.size() == 1) {
                removedTypes.insert(type);
            }
        }
    }
    ACCOUNT_LOGI("Distributed client query space types to remove, removed types=%{public}zu.",
        removedTypes.size());
}

void DistributedAccountEventService::GetAllSpaceType(std::set<DistributedAccountSpaceEventType> &typeList)
{
    std::lock_guard<std::mutex> lock(spaceMapLock_);
    for (auto &item : spaceTypeMap_) {
        typeList.insert(item.first);
    }
}

bool DistributedAccountEventService::IsAllSpaceTypeExist(const std::set<DistributedAccountSpaceEventType>& types,
    const std::shared_ptr<DistributedAccountSubscribeCallback> &callback)
{
    if (callback == nullptr || types.empty()) {
        return false;
    }
    std::lock_guard<std::mutex> lock(spaceMapLock_);
    auto it = spaceCallbackMap_.find(callback);
    if (it == spaceCallbackMap_.end()) {
        return false;
    }
    for (auto type : types) {
        if (it->second.find(type) == it->second.end()) {
            return false;
        }
    }
    return true;
}

ErrCode DistributedAccountEventService::OnSpaceAccountsChanged(const DistributedAccountSpaceEventData &eventData)
{
    std::lock_guard<std::mutex> lock(spaceMapLock_);
    auto it = spaceTypeMap_.find(eventData.type_);
    if (it == spaceTypeMap_.end()) {
        return ERR_OK;
    }
    for (const auto &callback : it->second) {
        callback->OnSpaceAccountsChanged(eventData);
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

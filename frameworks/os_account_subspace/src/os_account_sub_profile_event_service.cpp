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

#include "os_account_sub_profile_event_service.h"

#include <algorithm>
#include <pthread.h>
#include <thread>

#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
namespace {
#ifndef FUZZ_TEST
const char THREAD_OS_ACCOUNT_SUB_PROFILE_EVENT[] = "SubProfileEvent";
#endif
}

OsAccountSubProfileEventService::OsAccountSubProfileEventService()
{}

OsAccountSubProfileEventService::~OsAccountSubProfileEventService()
{}

int32_t OsAccountSubProfileEventService::GetCallbackSize()
{
    std::lock_guard<std::mutex> lock(mapLock_);
    return callbackMap_.size();
}

bool OsAccountSubProfileEventService::IsAllTypeExist(const std::set<OsAccountSubProfileEventType>& types,
    const std::shared_ptr<OsAccountSubProfileSubscribeCallback> &callback)
{
    if (callback == nullptr || types.empty()) {
        ACCOUNT_LOGE("Check all type exist failed, callback is nullptr or types is empty.");
        return false;
    }
    std::lock_guard<std::mutex> lock(mapLock_);
    auto it = callbackMap_.find(callback);
    if (it == callbackMap_.end()) {
        ACCOUNT_LOGE("Query callback from map failed, callback not registered.");
        return false;
    }
    for (auto type : types) {
        if (it->second.find(type) == it->second.end()) {
            ACCOUNT_LOGE("Check event type for callback failed, callback does not subscribe this event type.");
            return false;
        }
    }
    return true;
}

void OsAccountSubProfileEventService::AddTypes(const std::set<OsAccountSubProfileEventType>& types,
    const std::shared_ptr<OsAccountSubProfileSubscribeCallback> &callback)
{
    if (callback == nullptr || types.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(mapLock_);
    auto it = callbackMap_.find(callback);
    if (it == callbackMap_.end()) {
        callbackMap_[callback] = types;
    } else {
        it->second.insert(types.begin(), types.end());
    }

    for (auto type : types) {
        auto itemType = typeMap_.find(type);
        if (itemType == typeMap_.end()) {
            typeMap_[type] = {callback};
        } else {
            itemType->second.insert(callback);
        }
    }
    ACCOUNT_LOGI("Sub profile client subscribe, type size=%{public}zu, callback size=%{public}zu.",
        typeMap_.size(), callbackMap_.size());
}

void OsAccountSubProfileEventService::DeleteCallback(
    const std::shared_ptr<OsAccountSubProfileSubscribeCallback> &callback)
{
    if (callback == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(mapLock_);
    auto it = callbackMap_.find(callback);
    if (it == callbackMap_.end()) {
        return;
    }

    auto callbackTypes = it->second;
    callbackMap_.erase(it);

    for (auto type : callbackTypes) {
        auto itemType = typeMap_.find(type);
        if (itemType != typeMap_.end()) {
            itemType->second.erase(callback);
            if (itemType->second.empty()) {
                typeMap_.erase(itemType);
            }
        }
    }
    ACCOUNT_LOGI("Sub profile client delete callback.");
}

void OsAccountSubProfileEventService::GetTypesToRemove(
    const std::shared_ptr<OsAccountSubProfileSubscribeCallback> &callback,
    std::set<OsAccountSubProfileEventType> &removedTypes)
{
    if (callback == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(mapLock_);
    auto it = callbackMap_.find(callback);
    if (it == callbackMap_.end()) {
        return;
    }

    auto callbackTypes = it->second;
    for (auto type : callbackTypes) {
        auto itemType = typeMap_.find(type);
        if (itemType != typeMap_.end()) {
            if (itemType->second.size() == 1) {
                removedTypes.insert(type);
            }
        }
    }
    ACCOUNT_LOGI("Sub profile client query types to remove, removed types=%{public}zu.", removedTypes.size());
}

void OsAccountSubProfileEventService::GetAllType(std::set<OsAccountSubProfileEventType> &typeList)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    for (auto &item : typeMap_) {
        typeList.insert(item.first);
    }
}

ErrCode OsAccountSubProfileEventService::OnSubProfileChanged(const SubProfileEventData &eventData)
{
    std::vector<std::shared_ptr<OsAccountSubProfileSubscribeCallback>> callbacks;
    {
        std::lock_guard<std::mutex> lock(mapLock_);
        auto it = typeMap_.find(eventData.type_);
        if (it == typeMap_.end()) {
            ACCOUNT_LOGI("callback is empty");
            return ERR_OK;
        }
        callbacks.assign(it->second.begin(), it->second.end());
    }
    for (const auto &item : callbacks) {
        auto task = [item, eventData]() {
            item->OnSubProfileChanged(eventData);
        };
#ifdef FUZZ_TEST
        task();
#else
        std::thread taskThread(task);
        pthread_setname_np(taskThread.native_handle(), THREAD_OS_ACCOUNT_SUB_PROFILE_EVENT);
        taskThread.detach();
#endif
    }
    return ERR_OK;
}

OsAccountSubProfileEventService* OsAccountSubProfileEventService::GetInstance()
{
    /* returned pointer is managed by static sptr, caller does not need to free */
    static sptr<OsAccountSubProfileEventService> instance = new (std::nothrow) OsAccountSubProfileEventService();
    return instance.GetRefPtr();
}

}  // namespace AccountSA
}  // namespace OHOS

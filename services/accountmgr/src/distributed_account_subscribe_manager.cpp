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

#include <pthread.h>
#include <thread>
#include "account_constants.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"
#include "account_permission_manager.h"
#include "distributed_account_subscribe_death_recipient.h"
#include "distributed_account_subscribe_manager.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
namespace {
#ifndef FUZZ_TEST
const char THREAD_DISTRIBUTED_ACCOUNT_EVENT[] = "distributedAccountEvent";
#endif
}

void DistributedSubscribeRecord::AddSpaceTypes(const std::set<DistributedAccountSpaceEventType> &newTypes)
{
    spaceTypes_.insert(newTypes.begin(), newTypes.end());
}

void DistributedSubscribeRecord::RemoveSpaceTypes(const std::set<DistributedAccountSpaceEventType> &types)
{
    for (auto type : types) {
        spaceTypes_.erase(type);
    }
}

DistributedAccountSubscribeManager::DistributedAccountSubscribeManager()
    : subscribeDeathRecipient_(sptr<IRemoteObject::DeathRecipient>(
        new (std::nothrow) DistributedAccountSubscribeDeathRecipient()))
{}

DistributedAccountSubscribeManager &DistributedAccountSubscribeManager::GetInstance()
{
    static DistributedAccountSubscribeManager *instance = new (std::nothrow) DistributedAccountSubscribeManager();
    return *instance;
}

DistributedSubscribeRecordPtr DistributedAccountSubscribeManager::FindSubscribeRecordByEventListener(
    const sptr<IRemoteObject> &eventListener)
{
    auto it = std::find_if(subscribeRecords_.begin(), subscribeRecords_.end(),
        [&eventListener](const auto& record) {
            return record->eventListener_ == eventListener;
        });
    if (it != subscribeRecords_.end()) {
        return *it;
    }
    return nullptr;
}

std::vector<sptr<IRemoteObject>> DistributedAccountSubscribeManager::GetSubscribersToNotify(
    DistributedAccountSpaceEventType eventType, int32_t eventLocalId)
{
    std::vector<sptr<IRemoteObject>> subscribersToNotify;
    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end(); ++it) {
        if ((*it)->spaceTypes_.find(eventType) == (*it)->spaceTypes_.end()) {
            continue;
        }
        bool shouldNotify = false;
        // isSaCall_ indicates whether the caller is from sa or application:
        // - If true (from sa): notify for any user's events
        // - If false (from application): only notify for events from the user where the application resides
        if ((*it)->isSaCall_) {
            shouldNotify = true;
        } else if ((*it)->localId_ == eventLocalId) {
            shouldNotify = true;
        }
        if (shouldNotify) {
            subscribersToNotify.emplace_back((*it)->eventListener_);
        }
    }
    return subscribersToNotify;
}

ErrCode DistributedAccountSubscribeManager::SubscribeDistributedAccountEvent(
    const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type, const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("Subscribe distributed account in submanager.");
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("EventListener is nullptr.");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    auto it = std::find_if(subscribeRecords_.begin(), subscribeRecords_.end(), [&eventListener](const auto& record) {
        return record->eventListener_ == eventListener;
    });
    if (it != subscribeRecords_.end()) {
        (*it)->types_.insert(type);
        ACCOUNT_LOGI("Subscribe already exsits, update type only, type size=%{public}zu.", (*it)->types_.size());
        return ERR_OK;
    }

    auto subscribeRecordPtr = std::make_shared<DistributedSubscribeRecord>(eventListener);
    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->AddDeathRecipient(subscribeDeathRecipient_);
    }
    subscribeRecordPtr->eventListener_ = eventListener;
    subscribeRecordPtr->types_.insert(type);
    ACCOUNT_LOGI("Subscribe add, type size=%{public}zu.", subscribeRecordPtr->types_.size());
    subscribeRecords_.emplace_back(subscribeRecordPtr);
    return ERR_OK;
}

ErrCode DistributedAccountSubscribeManager::SubscribeDistributedAccountSpaceEvents(
    const std::set<DistributedAccountSpaceEventType> &types, const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("Batch subscribe distributed account space events.");
    if (eventListener == nullptr || types.empty()) {
        ACCOUNT_LOGE("Invalid parameter, eventListener null or types empty.");
        REPORT_OHOS_ACCOUNT_FAIL(-1, Constants::OPERATION_SUBSCRIBE_SPACE_EVENT,
            ERR_ACCOUNT_COMMON_INVALID_PARAMETER, "Invalid parameter for space events subscribe");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t localId = callingUid / UID_TRANSFORM_DIVISOR;
    int32_t isSaCall = AccountPermissionManager::CheckSaCall();
    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    auto record = FindSubscribeRecordByEventListener(eventListener);
    if (record != nullptr) {
        record->AddSpaceTypes(types);
        record->localId_ = localId;
        return ERR_OK;
    }

    auto subscribeRecordPtr = std::make_shared<DistributedSubscribeRecord>(eventListener, localId, isSaCall);
    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->AddDeathRecipient(subscribeDeathRecipient_);
    }
    subscribeRecordPtr->AddSpaceTypes(types);
    subscribeRecords_.emplace_back(subscribeRecordPtr);
    return ERR_OK;
}

ErrCode DistributedAccountSubscribeManager::UnsubscribeDistributedAccountSpaceEvents(
    const std::set<DistributedAccountSpaceEventType> &types, const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("Batch unsubscribe distributed account space events.");
    if (eventListener == nullptr || types.empty()) {
        ACCOUNT_LOGE("Invalid parameter, eventListener null or types empty.");
        REPORT_OHOS_ACCOUNT_FAIL(-1, Constants::OPERATION_UNSUBSCRIBE_SPACE_EVENT,
            ERR_ACCOUNT_COMMON_INVALID_PARAMETER, "Invalid parameter for space events unsubscribe");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    auto record = FindSubscribeRecordByEventListener(eventListener);
    if (record == nullptr) {
        ACCOUNT_LOGE("Unsubscribe failed, subscribe record not found.");
        REPORT_OHOS_ACCOUNT_FAIL(-1, Constants::OPERATION_UNSUBSCRIBE_SPACE_EVENT,
            ERR_OHOSACCOUNT_KIT_NO_SPECIFIED_CALLBACK_HAS_BEEN_REGISTERED, "Subscribe record not found");
        return ERR_OHOSACCOUNT_KIT_NO_SPECIFIED_CALLBACK_HAS_BEEN_REGISTERED;
    }
    record->RemoveSpaceTypes(types);
    if (!record->spaceTypes_.empty() || !record->types_.empty()) {
        return ERR_OK;
    }
    if (subscribeDeathRecipient_ != nullptr && record->eventListener_ != nullptr) {
        record->eventListener_->RemoveDeathRecipient(subscribeDeathRecipient_);
    }
    record->eventListener_ = nullptr;
    subscribeRecords_.erase(
        std::remove_if(subscribeRecords_.begin(), subscribeRecords_.end(),
            [&record](const auto& r) { return r == record; }),
        subscribeRecords_.end());
    return ERR_OK;
}

ErrCode DistributedAccountSubscribeManager::UnsubscribeDistributedAccountEvent(
    const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type, const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("Unsubscribe distributed account in submanager.");
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("EventListener is nullptr.");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end(); ++it) {
        if ((*it)->eventListener_ == eventListener) {
            (*it)->types_.erase(type);
            if (!(*it)->types_.empty() || !(*it)->spaceTypes_.empty()) {
                return ERR_OK;
            }
            if (subscribeDeathRecipient_ != nullptr) {
                eventListener->RemoveDeathRecipient(subscribeDeathRecipient_);
            }
            (*it)->eventListener_ = nullptr;
            subscribeRecords_.erase(it);
            return ERR_OK;
        }
    }
    ACCOUNT_LOGE("Unsubscribe failed, subscribe record not find.");
    return ERR_OHOSACCOUNT_KIT_NO_SPECIFIED_CALLBACK_HAS_BEEN_REGISTERED;
}

ErrCode DistributedAccountSubscribeManager::UnsubscribeDistributedAccountEvent(
    const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("Unsubscribe distributed account in submanager.");
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("EventListener is nullptr.");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->RemoveDeathRecipient(subscribeDeathRecipient_);
    }
    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end(); ++it) {
        if (eventListener == (*it)->eventListener_) {
            (*it)->eventListener_ = nullptr;
            subscribeRecords_.erase(it);
            break;
        }
    }
    return ERR_OK;
}

/**
 * @brief Send distributed account event notification via IPC.
 * @param ipcCall IPC call function to execute.
 * @param logPrefix Log message prefix for error reporting.
 * @return ErrCode result of the IPC call.
 */
template<typename Func>
ErrCode SendDistributedAccountEventNotify(Func ipcCall, const std::string& logPrefix)
{
    int32_t retryTimes = 0;
    ErrCode result = ERR_OK;
    while (retryTimes < Constants::MAX_RETRY_TIMES) {
        result = ipcCall();
        if (result == ERR_OK || (result != Constants::E_IPC_ERROR &&
            result != Constants::E_IPC_SA_DIED)) {
            break;
        }
        retryTimes++;
        ACCOUNT_LOGE("%{public}s failed, code=%{public}d, retryTimes=%{public}d",
            logPrefix.c_str(), result, retryTimes);
        std::this_thread::sleep_for(std::chrono::milliseconds(Constants::DELAY_FOR_EXCEPTION));
    }
    return result;
}

/**
 * @brief Execute distributed account event callback notification asynchronously in a detached thread.
 * @param task Task function to execute asynchronously.
 * @note In FUZZ_TEST mode, task is executed synchronously.
 */
void ExecuteDistributedAccountEventNotifyAsync(std::function<void()> task)
{
#ifdef FUZZ_TEST
    task();
#else
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_DISTRIBUTED_ACCOUNT_EVENT);
    taskThread.detach();
#endif
}

bool DistributedAccountSubscribeManager::OnAccountsChanged(
    const sptr<IDistributedAccountEvent> &eventProxy, const int id, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE subscribeType,
    const int32_t subProfileId)
{
    if (eventProxy == nullptr) {
        ACCOUNT_LOGE("Get app account event proxy failed.");
        return false;
    }
    DistributedAccountEventData eventData;
    eventData.id_ = id;
    eventData.type_ = subscribeType;
    eventData.subspaceId_ = subProfileId;
    ErrCode result = SendDistributedAccountEventNotify(
        [&]() { return eventProxy->OnAccountsChanged(eventData); }, "Send distributed account event request");
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest for account changed failed, result=%{public}d eventData.id=%{public}d.",
            result, eventData.id_);
        REPORT_OHOS_ACCOUNT_FAIL(eventData.id_, Constants::OPERATION_EVENT_PUBLISH,
            result, "Send OnAccountsChanged failed.");
        return false;
    }
    return true;
}

bool DistributedAccountSubscribeManager::OnSpaceAccountsChanged(
    const sptr<IDistributedAccountEvent> &eventProxy, const DistributedAccountSpaceEventData &eventData)
{
    if (eventProxy == nullptr) {
        ACCOUNT_LOGE("Event proxy is nullptr.");
        return false;
    }

    ErrCode result = SendDistributedAccountEventNotify(
        [&]() { return eventProxy->OnSpaceAccountsChanged(eventData); }, "Send space event request");
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest for space account changed failed, result=%{public}d osAccountId=%{public}d.",
            result, eventData.osAccountId_);
        return false;
    }
    return true;
}

ErrCode DistributedAccountSubscribeManager::Publish(DistributedAccountSpaceEventType eventType,
    int32_t localId, int32_t distributedAccountId, int32_t previousDistributedAccountId)
{
    ACCOUNT_LOGI("Publish distributed account space event, eventType=%{public}d, localId=%{public}d",
        static_cast<int32_t>(eventType), localId);
    auto subscribersToNotify = GetSubscribersToNotify(eventType, localId);

    DistributedAccountSpaceEventData eventData;
    eventData.type_ = eventType;
    eventData.osAccountId_ = localId;
    eventData.subspaceId_ = distributedAccountId;
    eventData.previousSubspaceId_ = previousDistributedAccountId;

    for (const auto& eventListener : subscribersToNotify) {
        auto eventProxy = iface_cast<IDistributedAccountEvent>(eventListener);
        if (eventProxy == nullptr) {
            ACCOUNT_LOGW("Failed to cast event proxy");
            continue;
        }
        auto task = [this, eventProxy, eventData] {
            this->OnSpaceAccountsChanged(eventProxy, eventData);
        };
        ExecuteDistributedAccountEventNotifyAsync(task);
    }
    ACCOUNT_LOGI("Publish space event %{public}d succeed, localId=%{public}d, size=%{public}zu.",
        static_cast<int32_t>(eventType), localId, subscribersToNotify.size());
    return ERR_OK;
}

ErrCode DistributedAccountSubscribeManager::Publish(const int id, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE subscribeType,
    int32_t subProfileId)
{
    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    uint32_t sendCnt = 0;
    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end(); ++it) {
        if ((*it)->types_.find(subscribeType) != (*it)->types_.end()) {
            auto eventProxy = iface_cast<IDistributedAccountEvent>((*it)->eventListener_);
            if (eventProxy == nullptr) {
                ACCOUNT_LOGE("Get eventProxy failed");
                break;
            }
            auto task = [this, eventProxy, id, subscribeType, subProfileId] {
                this->OnAccountsChanged(eventProxy, id, subscribeType, subProfileId);
            };
            ExecuteDistributedAccountEventNotifyAsync(task);
            ++sendCnt;
        }
    }
    ACCOUNT_LOGI("Publish DistributedAccountEvent %{public}d succeed, id=%{public}d, sendCnt=%{public}u.",
        subscribeType, id, sendCnt);
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

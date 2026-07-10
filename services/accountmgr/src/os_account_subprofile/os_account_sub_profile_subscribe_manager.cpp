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

#include "os_account_sub_profile_subscribe_manager.h"

#include <pthread.h>
#include <thread>

#include "account_constants.h"
#include "account_hisysevent_adapter.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "ipc_skeleton.h"
#include "os_account_sub_profile_subscribe_death_recipient.h"

namespace OHOS {
namespace AccountSA {
namespace {
#ifndef FUZZ_TEST
const char THREAD_SUB_PROFILE_EVENT[] = "subProfileEvent";
#endif
}

void OsAccountSubProfileSubscribeRecord::AddTypes(const std::set<OsAccountSubProfileEventType> &newTypes)
{
    types_.insert(newTypes.begin(), newTypes.end());
}

void OsAccountSubProfileSubscribeRecord::RemoveTypes(const std::set<OsAccountSubProfileEventType> &types)
{
    for (auto type : types) {
        types_.erase(type);
    }
}

OsAccountSubProfileSubscribeManager::OsAccountSubProfileSubscribeManager()
    : subscribeDeathRecipient_(sptr<IRemoteObject::DeathRecipient>(
        new (std::nothrow) OsAccountSubProfileSubscribeDeathRecipient()))
{}

OsAccountSubProfileSubscribeManager& OsAccountSubProfileSubscribeManager::GetInstance()
{
    /* returned reference is managed by static pointer, caller does not need to free */
    static OsAccountSubProfileSubscribeManager* instance = new (std::nothrow) OsAccountSubProfileSubscribeManager();
    return *instance;
}

OsAccountSubProfileSubscribeRecordPtr OsAccountSubProfileSubscribeManager::FindSubscribeRecordByEventListener(
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

std::vector<sptr<IRemoteObject>> OsAccountSubProfileSubscribeManager::GetSubscribersToNotify(
    OsAccountSubProfileEventType eventType, int32_t eventLocalId)
{
    std::vector<sptr<IRemoteObject>> subscribersToNotify;
    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end(); ++it) {
        if ((*it)->types_.find(eventType) == (*it)->types_.end()) {
            continue;
        }
        bool shouldNotify = false;
        if ((*it)->isNotifyAllUsers_) {
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

ErrCode OsAccountSubProfileSubscribeManager::SubscribeOsAccountSubProfileEvents(
    const std::set<OsAccountSubProfileEventType> &types, const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("Batch subscribe os account sub profile events.");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t localId = callingUid / Constants::UID_TRANSFORM_DIVISOR;
    if (eventListener == nullptr || types.empty()) {
        ACCOUNT_LOGE("Invalid parameter, eventListener null or types empty.");
        REPORT_OS_ACCOUNT_FAIL(localId, Constants::OPERATION_SUBSCRIBE_SPACE_EVENT,
            ERR_ACCOUNT_COMMON_INVALID_PARAMETER, "Invalid parameter for sub profile events subscribe");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    bool isNotifyAllUsers = (localId == 0);
    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    auto record = FindSubscribeRecordByEventListener(eventListener);
    if (record != nullptr) {
        record->AddTypes(types);
        record->localId_ = localId;
        return ERR_OK;
    }

    auto subscribeRecordPtr = std::make_shared<OsAccountSubProfileSubscribeRecord>(eventListener, localId,
        isNotifyAllUsers);
    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->AddDeathRecipient(subscribeDeathRecipient_);
    }
    subscribeRecordPtr->AddTypes(types);
    subscribeRecords_.emplace_back(subscribeRecordPtr);
    return ERR_OK;
}

ErrCode OsAccountSubProfileSubscribeManager::UnsubscribeOsAccountSubProfileEvents(
    const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("Unsubscribe all os account sub profile events for listener.");
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("Invalid parameter, eventListener null.");
        REPORT_OS_ACCOUNT_FAIL(-1, Constants::OPERATION_UNSUBSCRIBE_SPACE_EVENT,
            ERR_ACCOUNT_COMMON_INVALID_PARAMETER, "Invalid parameter for sub profile events unsubscribe");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->RemoveDeathRecipient(subscribeDeathRecipient_);
    }
    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end();) {
        if ((*it)->eventListener_ == eventListener) {
            (*it)->eventListener_ = nullptr;
            it = subscribeRecords_.erase(it);
        } else {
            ++it;
        }
    }
    return ERR_OK;
}

ErrCode OsAccountSubProfileSubscribeManager::UnsubscribeOsAccountSubProfileEvents(
    const std::set<OsAccountSubProfileEventType> &types, const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("Batch unsubscribe os account sub profile events.");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t localId = callingUid / Constants::UID_TRANSFORM_DIVISOR;
    if (eventListener == nullptr || types.empty()) {
        ACCOUNT_LOGE("Invalid parameter, eventListener null or types empty.");
        REPORT_OS_ACCOUNT_FAIL(localId, Constants::OPERATION_UNSUBSCRIBE_SPACE_EVENT,
            ERR_ACCOUNT_COMMON_INVALID_PARAMETER, "Invalid parameter for sub profile events unsubscribe");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    auto record = FindSubscribeRecordByEventListener(eventListener);
    if (record == nullptr) {
        ACCOUNT_LOGE("Unsubscribe failed, subscribe record not found.");
        REPORT_OS_ACCOUNT_FAIL(localId, Constants::OPERATION_UNSUBSCRIBE_SPACE_EVENT,
            ERR_OHOSACCOUNT_KIT_NO_SPECIFIED_CALLBACK_HAS_BEEN_REGISTERED, "Subscribe record not found");
        return ERR_OHOSACCOUNT_KIT_NO_SPECIFIED_CALLBACK_HAS_BEEN_REGISTERED;
    }
    record->RemoveTypes(types);
    if (!record->types_.empty()) {
        return ERR_OK;
    }
    if (subscribeDeathRecipient_ != nullptr && record->eventListener_ != nullptr) {
        record->eventListener_->RemoveDeathRecipient(subscribeDeathRecipient_);
    }
    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end();) {
        if ((*it)->eventListener_ == eventListener) {
            (*it)->eventListener_ = nullptr;
            it = subscribeRecords_.erase(it);
        } else {
            ++it;
        }
    }
    return ERR_OK;
}

template<typename Func>
ErrCode SendSubProfileEventNotify(Func ipcCall, const std::string& logPrefix)
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

void ExecuteSubProfileEventNotifyAsync(std::function<void()> task)
{
#ifdef FUZZ_TEST
    task();
#else
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_SUB_PROFILE_EVENT);
    taskThread.detach();
#endif
}

bool OsAccountSubProfileSubscribeManager::OnSubProfileChanged(
    const sptr<IOsAccountSubProfileEvent> &eventProxy, const SubProfileEventData &eventData)
{
    if (eventProxy == nullptr) {
        ACCOUNT_LOGE("Event proxy is nullptr.");
        return false;
    }

    ErrCode result = SendSubProfileEventNotify(
        [&]() { return eventProxy->OnSubProfileChanged(eventData); }, "Send sub profile event request");
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest for sub profile changed failed, result=%{public}d osAccountId=%{public}d.",
            result, eventData.osAccountId_);
        return false;
    }
    return true;
}

ErrCode OsAccountSubProfileSubscribeManager::Publish(OsAccountSubProfileEventType eventType,
    int32_t localId, int32_t subProfileId, int32_t previousSubProfileId)
{
    ACCOUNT_LOGI("Publish os account sub profile event, eventType=%{public}d, localId=%{public}d",
        static_cast<int32_t>(eventType), localId);
    auto subscribersToNotify = GetSubscribersToNotify(eventType, localId);

    SubProfileEventData eventData;
    eventData.type_ = eventType;
    eventData.osAccountId_ = localId;
    eventData.subProfileId_ = subProfileId;
    eventData.previousSubProfileId_ = previousSubProfileId;

    for (const auto& eventListener : subscribersToNotify) {
        auto eventProxy = iface_cast<IOsAccountSubProfileEvent>(eventListener);
        if (eventProxy == nullptr) {
            ACCOUNT_LOGW("Failed to cast event proxy");
            continue;
        }
        auto task = [this, eventProxy, eventData] {
            this->OnSubProfileChanged(eventProxy, eventData);
        };
        ExecuteSubProfileEventNotifyAsync(task);
    }
    ACCOUNT_LOGI("Publish sub profile event %{public}d succeed, localId=%{public}d, size=%{public}zu.",
        static_cast<int32_t>(eventType), localId, subscribersToNotify.size());
    return ERR_OK;
}

}  // namespace AccountSA
}  // namespace OHOS

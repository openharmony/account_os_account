/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "os_account_constraint_subscribe_manager.h"

#include <thread>
#include "account_constants.h"
#include "account_hisysevent_adapter.h"
#include "account_log_wrapper.h"
#include "os_account_constraint_subscribe_death_recipient.h"
#include "ipc_skeleton.h"
#ifdef HICOLLIE_ENABLE
#include "account_timer.h"
#include "xcollie/xcollie.h"
#endif // HICOLLIE_ENABLE

namespace OHOS {
namespace AccountSA {
namespace {
const char THREAD_CONSTRAINT_EVENT[] = "constraintEvent";
}
OsAccountConstraintSubscribeManager::OsAccountConstraintSubscribeManager()
    : subscribeDeathRecipient_(sptr<IRemoteObject::DeathRecipient>(
        new (std::nothrow) OsAccountConstraintSubscribeDeathRecipient()))
{}

OsAccountConstraintSubscribeManager &OsAccountConstraintSubscribeManager::GetInstance()
{
    static OsAccountConstraintSubscribeManager instance;
    return instance;
}

void OsAccountConstraintSubscribeManager::RemoveSubscribeRecord(
    const ConstraintRecordPtr &recordPtr, const std::set<std::string> &constraints)
{
    for (auto const &constraint : constraints) {
        constraint2RecordMap_[constraint].erase(recordPtr);
        if (constraint2RecordMap_[constraint].empty()) {
            constraint2RecordMap_.erase(constraint);
        }
        recordPtr->constraintSet_.erase(constraint);
    }
    if (recordPtr->constraintSet_.empty()) {
        constraintRecords_.erase(recordPtr);
    }
}

void OsAccountConstraintSubscribeManager::InsertSubscribeRecord(
    const ConstraintRecordPtr &recordPtr)
{
    constraintRecords_.emplace(recordPtr);
    for (auto const &constraint : recordPtr->constraintSet_) {
        constraint2RecordMap_[constraint].emplace(recordPtr);
    }
}

ErrCode OsAccountConstraintSubscribeManager::SubscribeConstraints(const std::set<std::string> &constraints,
    const sptr<IRemoteObject> &eventListener)
{
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("EventListener is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    for (auto const &recordPtr : constraintRecords_) {
        if (recordPtr->callingUid_ != callingUid) {
            continue;
        }
        if (recordPtr->constraintSet_ == constraints) {
            return ERR_ACCOUNT_COMMON_ACCOUNT_SUBSCRIBE_AREADY_ERROR;
        }
        recordPtr->constraintSet_ = constraints;
        InsertSubscribeRecord(recordPtr);
        return ERR_OK;
    }
    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->AddDeathRecipient(subscribeDeathRecipient_);
    }
    auto recordPtr = std::make_shared<ConstraintRecord>(constraints, eventListener, callingUid);
    InsertSubscribeRecord(recordPtr);
    return ERR_OK;
}

ErrCode OsAccountConstraintSubscribeManager::UnsubscribeConstraints(const sptr<IRemoteObject> &eventListener)
{
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("EventListener is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->RemoveDeathRecipient(subscribeDeathRecipient_);
    }
    for (auto const &recordPtr : constraintRecords_) {
        if (recordPtr->eventListener_ != eventListener) {
            continue;
        }
        std::set<std::string> constraints = recordPtr->constraintSet_;
        RemoveSubscribeRecord(recordPtr, constraints);
        return ERR_OK;
    }
    return ERR_ACCOUNT_COMMON_ACCOUNT_SUBSCRIBE_NOT_FOUND_ERROR;
}

ErrCode OsAccountConstraintSubscribeManager::UnsubscribeConstraints(const std::set<std::string> &constraints,
    const sptr<IRemoteObject> &eventListener)
{
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("EventListener is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    for (auto const &recordPtr : constraintRecords_) {
        if (recordPtr->callingUid_ != callingUid) {
            continue;
        }
        bool isInclude = std::includes(recordPtr->constraintSet_.begin(), recordPtr->constraintSet_.end(),
                                        constraints.begin(), constraints.end());
        if (!isInclude) {
            return ERR_ACCOUNT_COMMON_ACCOUNT_SUBSCRIBE_NOT_FOUND_ERROR;
        }
        RemoveSubscribeRecord(recordPtr, constraints);
        return ERR_OK;
    }
    return ERR_ACCOUNT_COMMON_ACCOUNT_SUBSCRIBE_NOT_FOUND_ERROR;
}

void OsAccountConstraintSubscribeManager::PublishToSubsriber(const ConstraintRecordPtr &recordPtr, int32_t localId,
    const std::set<std::string> &constraints, bool enable)
{
    if (recordPtr->eventListener_ == nullptr) {
        ACCOUNT_LOGE("Subscribe constraint is null, localId=%{public}d, uid=%{public}d.", localId,
            recordPtr->callingUid_);
        return;
    }
    auto eventProxy = iface_cast<IConstraintEvent>(recordPtr->eventListener_);
    if (eventProxy == nullptr) {
        ACCOUNT_LOGE("Event proxy is nullptr");
        return;
    }
    int32_t retryTimes = 0;
    ErrCode result;
    while (retryTimes < Constants::MAX_RETRY_TIMES) {
        result = eventProxy->OnConstraintChanged(localId, constraints, enable);
        if (result == ERR_OK || (result != Constants::E_IPC_ERROR &&
            result != Constants::E_IPC_SA_DIED)) {
            break;
        }
        retryTimes++;
        ACCOUNT_LOGE("Failed to send the OS account event, reqCode: %{public}d, retryTimes: %{public}d",
            result, retryTimes);
        std::this_thread::sleep_for(std::chrono::milliseconds(Constants::DELAY_FOR_EXCEPTION));
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest for constraint changed failed! result %{public}d, localId %{public}d.",
            result, localId);
        REPORT_OS_ACCOUNT_FAIL(localId, Constants::OPERATION_EVENT_PUBLISH,
            result, "Send OnConstraintChanged subscribe failed");
    }
}

void OsAccountConstraintSubscribeManager::Publish(int32_t localId, const std::set<std::string> &constraints,
    const bool enable)
{
    std::set<ConstraintRecordPtr> recordPtrSet;
    for (auto const &item : constraints) {
        auto iter = constraint2RecordMap_.find(item);
        if (iter != constraint2RecordMap_.end()) {
            recordPtrSet.insert(iter->second.begin(), iter->second.end());
        }
    }
    for (auto const &item : recordPtrSet) {
        auto task = [item, localId, constraints, enable, this] {
            ACCOUNT_LOGI("Publish start, to uid=%{public}d asynch, accountId=%{public}d, enable=%{public}d",
                item->callingUid_, localId, enable);
            this->PublishToSubsriber(item, localId, constraints, enable);
            ACCOUNT_LOGI("Publish end.");
        };
        std::thread taskThread(task);
        pthread_setname_np(taskThread.native_handle(), THREAD_CONSTRAINT_EVENT);
        taskThread.detach();
    }
}

void OsAccountConstraintSubscribeManager::Publish(int32_t localId, const std::set<std::string> &oldConstraints,
    const std::set<std::string> &newConstraints, const bool enable)
{
    std::set<std::string> modifyEffectiveConstraints;
    if (enable) {
        for (auto const &constraint : newConstraints) {
            if (oldConstraints.find(constraint) == oldConstraints.end()) {
                modifyEffectiveConstraints.emplace(constraint);
            }
        }
        return Publish(localId, modifyEffectiveConstraints, enable);
    }
    for (auto const &constraint : oldConstraints) {
        if (newConstraints.find(constraint) == newConstraints.end()) {
            modifyEffectiveConstraints.emplace(constraint);
        }
    }
    return Publish(localId, modifyEffectiveConstraints, enable);
}
} // AccountSA
} // OHOS
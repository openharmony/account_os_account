/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "os_account_subscribe_manager.h"
#include <pthread.h>
#include <thread>
#include "account_log_wrapper.h"
#include "ios_account_event.h"
#include "os_account_subscribe_death_recipient.h"

namespace OHOS {
namespace AccountSA {
namespace {
const char THREAD_OS_ACCOUNT_EVENT[] = "osAccountEvent";
}

OsAccountSubscribeManager::OsAccountSubscribeManager()
    : subscribeDeathRecipient_(sptr<IRemoteObject::DeathRecipient>(
        new (std::nothrow) OsAccountSubscribeDeathRecipient()))
{}

OsAccountSubscribeManager &OsAccountSubscribeManager::GetInstance()
{
    static OsAccountSubscribeManager *instance = new (std::nothrow) OsAccountSubscribeManager();
    return *instance;
}

ErrCode OsAccountSubscribeManager::SubscribeOsAccount(
    const std::shared_ptr<OsAccountSubscribeInfo> &subscribeInfoPtr, const sptr<IRemoteObject> &eventListener)
{
    if (subscribeInfoPtr == nullptr) {
        ACCOUNT_LOGE("subscribeInfoPtr is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    if (eventListener == nullptr) {
        ACCOUNT_LOGE("eventListener is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    auto subscribeRecordPtr = std::make_shared<OsSubscribeRecord>(subscribeInfoPtr, eventListener);
    if (subscribeRecordPtr == nullptr) {
        ACCOUNT_LOGE("subscribeRecordPtr is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->AddDeathRecipient(subscribeDeathRecipient_);
    }
    subscribeRecordPtr->subscribeInfoPtr_ = subscribeInfoPtr;
    subscribeRecordPtr->eventListener_ = eventListener;
    return InsertSubscribeRecord(subscribeRecordPtr);
}

ErrCode OsAccountSubscribeManager::UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener)
{
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("eventListener is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->RemoveDeathRecipient(subscribeDeathRecipient_);
    }

    return RemoveSubscribeRecord(eventListener);
}

ErrCode OsAccountSubscribeManager::InsertSubscribeRecord(const OsSubscribeRecordPtr &subscribeRecordPtr)
{
    if (subscribeRecordPtr == nullptr) {
        ACCOUNT_LOGE("subscribeRecordPtr is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);

    subscribeRecords_.emplace_back(subscribeRecordPtr);

    return ERR_OK;
}

ErrCode OsAccountSubscribeManager::RemoveSubscribeRecord(const sptr<IRemoteObject> &eventListener)
{
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("eventListener is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);

    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end(); ++it) {
        if (eventListener == (*it)->eventListener_) {
            (*it)->eventListener_ = nullptr;
            subscribeRecords_.erase(it);
            break;
        }
    }

    return ERR_OK;
}

const std::shared_ptr<OsAccountSubscribeInfo> OsAccountSubscribeManager::GetSubscribeRecordInfo(
    const sptr<IRemoteObject> &eventListener)
{
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("eventListener is nullptr");
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);

    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end(); ++it) {
        if (eventListener == (*it)->eventListener_) {
            return (*it)->subscribeInfoPtr_;
        }
    }

    return nullptr;
}

bool OsAccountSubscribeManager::OnAccountsChanged(const OsSubscribeRecordPtr &osSubscribeRecordPtr, const int id)
{
    auto osAccountEventProxy = iface_cast<IOsAccountEvent>(osSubscribeRecordPtr->eventListener_);
    if (osAccountEventProxy == nullptr) {
        ACCOUNT_LOGE("failed to get app account event proxy");
        return false;
    }
    osAccountEventProxy->OnAccountsChanged(id);
    return true;
}

bool OsAccountSubscribeManager::OnAccountsSwitch(const OsSubscribeRecordPtr &osSubscribeRecordPtr, const int newId,
                                                 const int oldId)
{
    auto osAccountEventProxy = iface_cast<IOsAccountEvent>(osSubscribeRecordPtr->eventListener_);
    if (osAccountEventProxy == nullptr) {
        ACCOUNT_LOGE("Get os account event proxy failed.");
        return false;
    }
    osAccountEventProxy->OnAccountsSwitch(newId, oldId);
    return true;
}

ErrCode OsAccountSubscribeManager::Publish(const int id, OS_ACCOUNT_SUBSCRIBE_TYPE subscribeType)
{
    if (subscribeType == SWITCHING || subscribeType == SWITCHED) {
        ACCOUNT_LOGE("Switch event need two ids.");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    uint32_t sendCnt = 0;
    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end(); ++it) {
        if ((*it)->subscribeInfoPtr_ == nullptr) {
            ACCOUNT_LOGE("subscribeInfoPtr_ is null, id %{public}d.", id);
            continue;
        }
        OS_ACCOUNT_SUBSCRIBE_TYPE osAccountSubscribeType;
        (*it)->subscribeInfoPtr_->GetOsAccountSubscribeType(osAccountSubscribeType);
        if (osAccountSubscribeType == subscribeType) {
            auto task = std::bind(&OsAccountSubscribeManager::OnAccountsChanged, this, (*it), id);
            std::thread taskThread(task);
            pthread_setname_np(taskThread.native_handle(), THREAD_OS_ACCOUNT_EVENT);
            taskThread.detach();
            ++sendCnt;
        }
    }

    ACCOUNT_LOGI("Publish OsAccountEvent %{public}d succeed! id %{public}d, sendCnt %{public}u.",
        subscribeType, id, sendCnt);
    return ERR_OK;
}

ErrCode OsAccountSubscribeManager::Publish(const int newId, const int oldId, OS_ACCOUNT_SUBSCRIBE_TYPE subscribeType)
{
    if (subscribeType != SWITCHING && subscribeType != SWITCHED) {
        ACCOUNT_LOGE("Only switch event need two ids.");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    uint32_t sendCnt = 0;
    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end(); ++it) {
        if ((*it)->subscribeInfoPtr_ == nullptr) {
            ACCOUNT_LOGE("SubscribeInfoPtr_ is null.");
            continue;
        }
        OS_ACCOUNT_SUBSCRIBE_TYPE osAccountSubscribeType;
        (*it)->subscribeInfoPtr_->GetOsAccountSubscribeType(osAccountSubscribeType);
        if (osAccountSubscribeType == subscribeType) {
            auto task = std::bind(&OsAccountSubscribeManager::OnAccountsSwitch, this, (*it), newId, oldId);
            std::thread taskThread(task);
            pthread_setname_np(taskThread.native_handle(), THREAD_OS_ACCOUNT_EVENT);
            taskThread.detach();
            ++sendCnt;
        }
    }

    ACCOUNT_LOGI("Publish %{public}d successful, newId=%{public}d, oldId=%{public}d, sendCnt=%{public}u.",
                 subscribeType, newId, oldId, sendCnt);
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

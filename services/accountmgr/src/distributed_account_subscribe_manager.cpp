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

#include <pthread.h>
#include <thread>
#include "account_constants.h"
#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"
#include "distributed_account_subscribe_death_recipient.h"
#include "distributed_account_subscribe_manager.h"

namespace OHOS {
namespace AccountSA {
namespace {
const char THREAD_DISTRIBUTED_ACCOUNT_EVENT[] = "distributedAccountEvent";
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
        return ERR_OK;
    }

    auto subscribeRecordPtr = std::make_shared<DistributedSubscribeRecord>(eventListener);
    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->AddDeathRecipient(subscribeDeathRecipient_);
    }
    subscribeRecordPtr->eventListener_ = eventListener;
    subscribeRecordPtr->types_.insert(type);
    subscribeRecords_.emplace_back(subscribeRecordPtr);
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
            if (!(*it)->types_.empty()) {
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

bool DistributedAccountSubscribeManager::OnAccountsChanged(
    const sptr<IDistributedAccountEvent> &eventProxy, const int id, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE subscribeType)
{
    if (eventProxy == nullptr) {
        ACCOUNT_LOGE("Get app account event proxy failed.");
        return false;
    }
    DistributedAccountEventData eventData;
    eventData.id_ = id;
    eventData.type_ = subscribeType;

    int32_t retryTimes = 0;
    ErrCode result;
    while (retryTimes < Constants::MAX_RETRY_TIMES) {
        result = eventProxy->OnAccountsChanged(eventData);
        if (result == ERR_OK || (result != Constants::E_IPC_ERROR &&
            result != Constants::E_IPC_SA_DIED)) {
            break;
        }
        retryTimes++;
        ACCOUNT_LOGE("Send distributed account event request failed, code=%{public}d, retryTimes=%{public}d",
            result, retryTimes);
        std::this_thread::sleep_for(std::chrono::milliseconds(Constants::DELAY_FOR_EXCEPTION));
    }
    if (result != ERR_OK) {
        if (result == ERR_TRANSACTION_FAILED) {
            result = ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
        } else if (result == ERR_INVALID_DATA) {
            result = ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
        } else if (result == IPC_STUB_UNKNOW_TRANS_ERR) {
            result = IPC_PROXY_INVALID_CODE_ERR;
        }
        ACCOUNT_LOGE("SendRequest for account changed failed, result=%{public}d eventData.id=%{public}d.",
            result, eventData.id_);
        REPORT_OHOS_ACCOUNT_FAIL(eventData.id_, Constants::OPERATION_EVENT_PUBLISH,
            result, "Send OnAccountsChanged failed.");
    }
    return true;
}

ErrCode DistributedAccountSubscribeManager::Publish(const int id, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE subscribeType)
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
            auto task = [this, eventProxy, id, subscribeType] {
                this->OnAccountsChanged(eventProxy, id, subscribeType);
            };
            std::thread taskThread(task);
            pthread_setname_np(taskThread.native_handle(), THREAD_DISTRIBUTED_ACCOUNT_EVENT);
            taskThread.detach();
            ++sendCnt;
        }
    }
    ACCOUNT_LOGI("Publish DistributedAccountEvent %{public}d succeed, id=%{public}d, sendCnt=%{public}u.",
        subscribeType, id, sendCnt);
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

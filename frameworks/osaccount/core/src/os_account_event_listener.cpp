/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "ipc_skeleton.h"
#include "os_account_constants.h"
#include "os_account_event_listener.h"
#include "os_account_state_reply_callback_proxy.h"
#include <atomic>
#include <pthread.h>
#include <thread>

namespace OHOS {
namespace AccountSA {
namespace {
constexpr int32_t WAIT_SECONDS = 5;
const char THREAD_OS_ACCOUNT_EVENT[] = "OsAccountEvent";
const char THREAD_WAIT_COMPLETE[] = "WaitComplete";
const uid_t ACCOUNT_UID = 3058;
}
OsAccountEventListener::OsAccountEventListener()
{}

OsAccountEventListener::~OsAccountEventListener()
{}

static ErrCode WaitForComplete(const sptr<IRemoteObject> &callback, std::shared_ptr<std::condition_variable> &cvPtr,
    std::shared_ptr<std::atomic<int>> &pendingCounter)
{
    if (callback == nullptr) {
        return ERR_OK;
    }
    sptr<OsAccountStateReplyCallbackProxy> remoteCallback = iface_cast<OsAccountStateReplyCallbackProxy>(callback);
    if (remoteCallback == nullptr) {
        return ERR_OK;
    }
    std::mutex mutex;
    std::unique_lock<std::mutex> waitLock(mutex);
    auto result = cvPtr->wait_for(waitLock, std::chrono::seconds(WAIT_SECONDS),
        [pendingCounter]() { return pendingCounter->load() == 0;});
    remoteCallback->OnComplete();
    if (!result) {
        ACCOUNT_LOGE("Wait reply timed out");
        return ERR_ACCOUNT_COMMON_OPERATION_TIMEOUT;
    }
    return ERR_OK;
}

static void NotifySubscriber(std::shared_ptr<OsAccountSubscriber> &subscriber, OsAccountStateData &data,
    std::shared_ptr<std::condition_variable> &cvPtr, std::shared_ptr<std::atomic<int>> &pendingCounter)
{
    OsAccountSubscribeInfo info;
    subscriber->GetSubscribeInfo(info);
    std::set<OsAccountState> states;
    info.GetStates(states);
    if (!states.empty()) {
        if (info.IsWithHandshake() &&
            (data.state == OsAccountState::STOPPING || data.state == OsAccountState::LOCKING)) {
            pendingCounter->fetch_add(1);
            data.callback = std::make_shared<OsAccountStateReplyCallback>(cvPtr, pendingCounter);
        }
        subscriber->OnStateChanged(data);
    } else if (data.state == OsAccountState::SWITCHING || data.state == OsAccountState::SWITCHED) {
        subscriber->OnAccountsSwitch(data.toId, data.fromId);
    } else {
        subscriber->OnAccountsChanged(data.fromId);
    }
}

ErrCode OsAccountEventListener::OnStateChanged(const OsAccountStateParcel &parcel)
{
     ACCOUNT_LOGI("State: %{public}d, fromId: %{public}d, toId: %{public}d, callback_isnull: %{public}d",
        parcel.state, parcel.fromId, parcel.toId, static_cast<int>(parcel.callback == nullptr));
    OsAccountStateData data;
    data.fromId = parcel.fromId;
    data.toId = parcel.toId;
    data.state = parcel.state;
    auto cvPtr = std::make_shared<std::condition_variable>();
    auto pendingCounter = std::make_shared<std::atomic<int>>(0);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto &it : subscriberAll_) {
            if (it.second.find(data.state) == it.second.end()) {
                continue;
            }
            auto task = [subscriber = it.first, data, cvPtr, pendingCounter]() mutable {
                NotifySubscriber(subscriber, data, cvPtr, pendingCounter);
            };
            std::thread taskThread(task);
            pthread_setname_np(taskThread.native_handle(), THREAD_OS_ACCOUNT_EVENT);
            taskThread.detach();
        }
    }
    if (parcel.callback == nullptr) {
        return ERR_OK;
    }
    std::thread waitThread([callback = parcel.callback, cvPtr, pendingCounter]() mutable {
        WaitForComplete(callback, cvPtr, pendingCounter);
    });
    pthread_setname_np(waitThread.native_handle(), THREAD_WAIT_COMPLETE);
    waitThread.detach();
    return ERR_OK;
}

ErrCode OsAccountEventListener::OnAccountsChanged(int32_t id)
{
    return ERR_OK;
}

ErrCode OsAccountEventListener::OnAccountsSwitch(int32_t newId, int32_t oldId)
{
    return ERR_OK;
}

ErrCode OsAccountEventListener::InsertRecord(const std::shared_ptr<OsAccountSubscriber> &subscriber)
{
    std::lock_guard<std::mutex> lock(mutex_);
    OsAccountSubscribeInfo info;
    subscriber->GetSubscribeInfo(info);
    std::set<OsAccountState> states;
    info.GetStates(states);
    if (states.empty()) {
        OsAccountState state;
        info.GetOsAccountSubscribeType(state);
        states.insert(state);
    }
    if (subscriberAll_.find(subscriber) != subscriberAll_.end()) {
        if (states == subscriberAll_[subscriber]) {
            ACCOUNT_LOGI("Subscribe repeatedly");
            return ERR_OK;
        }
    }
    if (subscriberAll_.size() >= Constants::SUBSCRIBER_MAX_SIZE) {
        ACCOUNT_LOGE("The maximum number of subscribers has been reached");
        return ERR_OSACCOUNT_KIT_SUBSCRIBE_ERROR;
    }
    subscriberAll_[subscriber] = states;
    ACCOUNT_LOGI("subscribeOsAccount subscriber size=%{public}zu.", subscriberAll_.size());
    return ERR_OK;
}

ErrCode OsAccountEventListener::RemoveRecord(const std::shared_ptr<OsAccountSubscriber> &subscriber)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (subscriberAll_.find(subscriber) == subscriberAll_.end()) {
        return ERR_OSACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED;
    }
    subscriberAll_.erase(subscriber);
    ACCOUNT_LOGI("UnsubscribeOsAccount subscriber size=%{public}zu.", subscriberAll_.size());
    return ERR_OK;
}

uint32_t OsAccountEventListener::Size()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return subscriberAll_.size();
}

OsAccountSubscribeInfo OsAccountEventListener::GetTotalSubscribeInfo()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::set<OsAccountState> allStates;
    bool withHandshake = false;
    for (const auto &it : subscriberAll_) {
        allStates.insert(it.second.begin(), it.second.end());
        OsAccountSubscribeInfo info;
        it.first->GetSubscribeInfo(info);
        if (info.IsWithHandshake()) {
            withHandshake = true;
        }
    }
    OsAccountSubscribeInfo res(allStates, withHandshake);
    return res;
}

ErrCode OsAccountEventListener::CallbackEnter([[maybe_unused]] uint32_t code)
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != ACCOUNT_UID) {
        ACCOUNT_LOGE("GetCallingUid failed, please check callingUid: %{public}d", callingUid);
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode OsAccountEventListener::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

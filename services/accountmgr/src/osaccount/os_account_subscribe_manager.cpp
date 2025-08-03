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

#include "os_account_subscribe_manager.h"
#include <pthread.h>
#include <thread>
#include <cinttypes>
#include "account_constants.h"
#include "account_hisysevent_adapter.h"
#include "account_log_wrapper.h"
#include "ipc_skeleton.h"
#include "os_account_constants.h"
#include "os_account_state_parcel.h"
#include "os_account_state_reply_callback_service.h"
#include "os_account_subscribe_death_recipient.h"
#ifdef HICOLLIE_ENABLE
#include "account_timer.h"
#include "xcollie/xcollie.h"
#endif // HICOLLIE_ENABLE

namespace OHOS {
namespace AccountSA {
namespace {
const char THREAD_OS_ACCOUNT_EVENT[] = "osAccountEvent";
constexpr int32_t DEACTIVATION_WAIT_SECONDS = 5;
}

SwitchSubcribeWork::SwitchSubcribeWork(const sptr<IOsAccountEvent> &eventProxy,
    const OsAccountStateParcel &stateParcel)
{
    eventProxy_ = eventProxy;
    stateParcel_ = stateParcel;
}

SwitchSubscribeInfo::SwitchSubscribeInfo(OS_ACCOUNT_SUBSCRIBE_TYPE osAccountSubscribeType)
{
    if (osAccountSubscribeType == OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING ||
        osAccountSubscribeType == OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED) {
        count_ = 1;
    }
}

SwitchSubscribeInfo::~SwitchSubscribeInfo()
{
}

void SwitchSubscribeInfo::AddSubscribeInfo()
{
    count_++;
}

bool SwitchSubscribeInfo::SubSubscribeInfo()
{
    if (count_ == 0) {
        return false;
    }
    count_--;
    return true;
}

bool SwitchSubscribeInfo::IsEmpty()
{
    return count_ == 0;
}

static void ConsumerTask(std::weak_ptr<SwitchSubscribeInfo> weakInfo)
{
    bool exitFlag = false;
    while (!exitFlag) {
        std::shared_ptr<SwitchSubcribeWork> work;
        auto shareInfo = weakInfo.lock();
        if (shareInfo == nullptr) {
            return;
        }
        std::unique_lock<std::mutex> lock(shareInfo->mutex_);
        if (shareInfo->workDeque_.empty()) {
            shareInfo->workThread_.reset();
            return;
        }
        work = shareInfo->workDeque_.front();
        shareInfo->workDeque_.pop_front();
        lock.unlock();
#ifdef HICOLLIE_ENABLE
        int32_t timerId = HiviewDFX::XCollie::GetInstance().SetTimer(TIMER_NAME,
            TIMEOUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
#endif // HICOLLIE_ENABLE
        if (work != nullptr && work->eventProxy_ != nullptr) {
            work->eventProxy_->OnStateChanged(work->stateParcel_);
        }
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
    }
}

bool SwitchSubscribeInfo::ProductTask(const sptr<IOsAccountEvent> &eventProxy, OsAccountStateParcel &stateParcel)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto work = std::make_shared<SwitchSubcribeWork>(eventProxy, stateParcel);
    workDeque_.push_back(work);
    if (workThread_ == nullptr) {
        workThread_ = std::make_unique<std::thread>(&ConsumerTask, weak_from_this());
        pthread_setname_np(workThread_->native_handle(), THREAD_OS_ACCOUNT_EVENT);
        workThread_->detach();
    }
    return true;
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
        ACCOUNT_LOGE("SubscribeInfoPtr is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    if (eventListener == nullptr) {
        ACCOUNT_LOGE("EventListener is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    auto it = std::find_if(subscribeRecords_.begin(), subscribeRecords_.end(),
        [eventListener] (const OsSubscribeRecordPtr &record) {
            return eventListener == record->eventListener_;
        });
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    std::set<OsAccountState> states;
    subscribeInfoPtr->GetStates(states);
    if (it != subscribeRecords_.end()) {
        std::set<OsAccountState> tmpStates;
        (*it)->subscribeInfoPtr_->GetStates(tmpStates);
        if (states == tmpStates) {
            int32_t callingPid = IPCSkeleton::GetCallingRealPid();
            ACCOUNT_LOGI("EventListener(%{public}d) already exists.", callingPid);
        } else {
            (*it)->subscribeInfoPtr_ = subscribeInfoPtr;
        }
    } else {
        auto subscribeRecordPtr = std::make_shared<OsSubscribeRecord>(subscribeInfoPtr, eventListener, callingUid);
        if (subscribeRecordPtr == nullptr) {
            ACCOUNT_LOGE("SubscribeRecordPtr is nullptr");
            return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
        }
        if (subscribeDeathRecipient_ != nullptr) {
            eventListener->AddDeathRecipient(subscribeDeathRecipient_);
        }
        subscribeRecords_.insert(subscribeRecordPtr);
    }
    ACCOUNT_LOGI("SubscribeOsAccount status size=%{public}zu.", states.size());
    if (states.find(SWITCHING) != states.end() || states.find(SWITCHED) != states.end()) {
        if (switchRecordMap_.count(callingUid) != 0) {
            switchRecordMap_[callingUid]->AddSubscribeInfo();
            return ERR_OK;
        }
        switchRecordMap_.emplace(callingUid, std::make_shared<SwitchSubscribeInfo>());
    }
    return ERR_OK;
}

ErrCode OsAccountSubscribeManager::UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener)
{
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("EventListener is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->RemoveDeathRecipient(subscribeDeathRecipient_);
    }

    return RemoveSubscribeRecord(eventListener);
}

ErrCode OsAccountSubscribeManager::RemoveSubscribeRecord(const sptr<IRemoteObject> &eventListener)
{
    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end(); ++it) {
        if (eventListener == (*it)->eventListener_) {
            ACCOUNT_LOGI("UnsubscribeOsAccount eventListener.");
            (*it)->eventListener_ = nullptr;
            int32_t callingUid = (*it)->callingUid_;
            std::set<OsAccountState> states;
            (*it)->subscribeInfoPtr_->GetStates(states);
            subscribeRecords_.erase(it);
            if (states.find(SWITCHING) == states.end() && states.find(SWITCHED) == states.end()) {
                break;
            }
            if (switchRecordMap_.count(callingUid) == 0) {
                break;
            }
            switchRecordMap_[callingUid]->SubSubscribeInfo();
            if (switchRecordMap_[callingUid]->IsEmpty()) {
                switchRecordMap_.erase(callingUid);
            }
            break;
        }
    }
    return ERR_OK;
}

const std::shared_ptr<OsAccountSubscribeInfo> OsAccountSubscribeManager::GetSubscribeRecordInfo(
    const sptr<IRemoteObject> &eventListener)
{
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("EventListener is nullptr");
        return nullptr;
    }

    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end(); ++it) {
        if (eventListener == (*it)->eventListener_) {
            return (*it)->subscribeInfoPtr_;
        }
    }

    return nullptr;
}

std::string OsAccountSubscribeManager::FormatStateInfo(const OsAccountStateParcel& stateParcel,
    int32_t targetUid, const std::string& phase, ErrCode errCode) const
{
    std::string info = "Publish " + phase + ", state=" + std::to_string(stateParcel.state) +
        " to uid=" + std::to_string(targetUid) + " async, fromId=" + std::to_string(stateParcel.fromId) +
        ", toId=" + std::to_string(stateParcel.toId);
    if ((stateParcel.state == SWITCHING || stateParcel.state == SWITCHED) &&
        stateParcel.displayId.has_value()) {
        info += ", displayId=" + std::to_string(stateParcel.displayId.value());
    }
    info += ", withHandshake=" + std::to_string(stateParcel.callback != nullptr);
    if (phase == "end") {
        info += ", result=" + std::to_string(errCode);
    }
    return info;
}

void OsAccountSubscribeManager::LogPublishEvent(const OsAccountStateParcel& stateParcel,
    int32_t targetUid, const std::string& phase, ErrCode errCode) const
{
    std::string logInfo = FormatStateInfo(stateParcel, targetUid, phase, errCode);
    ACCOUNT_LOGI("%{public}s", logInfo.c_str());
}

bool OsAccountSubscribeManager::OnStateChanged(
    const sptr<IOsAccountEvent> &eventProxy, OsAccountStateParcel &stateParcel, int32_t targetUid)
{
    if (stateParcel.state == SWITCHING || stateParcel.state == SWITCHED) {
        if (switchRecordMap_.count(targetUid) == 0) {
            return false;
        }
        return switchRecordMap_[targetUid]->ProductTask(eventProxy, stateParcel);
    }
    auto task = [this, eventProxy, stateParcel, targetUid]() mutable {
        if (stateParcel.toId == -1 && (stateParcel.state != OsAccountState::SWITCHED)
            && (stateParcel.state != OsAccountState::SWITCHING)) {
            stateParcel.toId = stateParcel.fromId;
        }
        
        LogPublishEvent(stateParcel, targetUid, "start");
        ErrCode errCode = eventProxy->OnStateChanged(stateParcel);
        LogPublishEvent(stateParcel, targetUid, "end", errCode);
        if (errCode != ERR_OK) {
            std::string errorMsg = FormatStateInfo(stateParcel, targetUid, "failed", errCode);
            REPORT_OS_ACCOUNT_FAIL(stateParcel.toId, Constants::OPERATION_EVENT_PUBLISH, errCode,
                "Send OnStateChanged " + errorMsg);
        }
        auto callback = iface_cast<OsAccountStateReplyCallbackService>(stateParcel.callback);
        if (callback == nullptr) {
            return;
        }
        callback->SetStartTime(std::chrono::system_clock::now());
        if (errCode != ERR_OK) {
            callback->OnComplete();
        }
    };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_OS_ACCOUNT_EVENT);
    taskThread.detach();
    return true;
}

bool OsAccountSubscribeManager::OnStateChangedV0(const sptr<IOsAccountEvent> &eventProxy,
    OsAccountState state, int32_t fromId, int32_t toId, int32_t targetUid, const std::optional<uint64_t> &displayId)
{
    if (state == SWITCHING || state == SWITCHED) {
        if (switchRecordMap_.count(targetUid) == 0) {
            return false;
        }
        OsAccountStateParcel stateParcel;
        stateParcel.fromId = fromId;
        stateParcel.toId = toId;
        stateParcel.state = state;
        stateParcel.displayId = displayId;
        return switchRecordMap_[targetUid]->ProductTask(eventProxy, stateParcel);
    }
    return OnAccountsChanged(eventProxy, state, fromId, targetUid);
}

bool OsAccountSubscribeManager::OnAccountsChanged(
    const sptr<IOsAccountEvent> &eventProxy, OsAccountState state, int32_t id, int32_t targetUid)
{
    auto task = [eventProxy, state, id, targetUid] {
        ACCOUNT_LOGI("Publish start, state=%{public}d to uid=%{public}d asynch, accountId=%{public}d",
            state, targetUid, id);
        eventProxy->OnAccountsChanged(id);
        ACCOUNT_LOGI("Publish end, state=%{public}d to uid=%{public}d asynch, accountId=%{public}d",
            state, targetUid, id);
    };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_OS_ACCOUNT_EVENT);
    taskThread.detach();
    return true;
}

static bool IsStateNeedHandShake(const OsAccountState& state)
{
    if (state == OsAccountState::STOPPING || state == OsAccountState::LOCKING) {
        return true;
    }

    return false;
}

ErrCode OsAccountSubscribeManager::Publish(int32_t fromId, OsAccountState state,
    int32_t toId, std::optional<uint64_t> displayId)
{
    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);
    auto cvPtr = std::make_shared<std::condition_variable>();
    auto safeQueue = std::make_shared<SafeQueue<uint8_t>>();
    
    PublishToAllSubscribers(fromId, state, toId, displayId, cvPtr, safeQueue);
    
    if ((state == SWITCHING || state == SWITCHED) && displayId.has_value()) {
        ACCOUNT_LOGI("End, state: %{public}d, fromId: %{public}d, toId: %{public}d, displayId: %{public}d",
            state, fromId, toId, static_cast<int>(displayId.value()));
    } else {
        ACCOUNT_LOGI("End, state: %{public}d, fromId: %{public}d, toId: %{public}d", state, fromId, toId);
    }
    ErrCode result = WaitForAllReplies(cvPtr, safeQueue);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Wait reply timed out");
        REPORT_OS_ACCOUNT_FAIL(fromId, OsAccountStateReplyCallbackService::ConvertStateToSceneFlag(state),
            ERR_ACCOUNT_COMMON_OPERATION_TIMEOUT, "Wait reply timed out");
    }
    return result;
}

void OsAccountSubscribeManager::PublishToAllSubscribers(int32_t fromId, OsAccountState state, int32_t toId,
    std::optional<uint64_t> displayId, std::shared_ptr<std::condition_variable> cvPtr,
    std::shared_ptr<SafeQueue<uint8_t>> safeQueue)
{
    for (const auto &subscribeRecord : subscribeRecords_) {
        if (subscribeRecord->subscribeInfoPtr_ == nullptr) {
            ACCOUNT_LOGE("Subscribe info is null, fromId: %{public}d, toId: %{public}d", fromId, toId);
            continue;
        }
        auto eventProxy = iface_cast<IOsAccountEvent>(subscribeRecord->eventListener_);
        if (eventProxy == nullptr) {
            ACCOUNT_LOGE("Event proxy is nullptr");
            continue;
        }
        int32_t subscriberUid = subscribeRecord->callingUid_;
        OS_ACCOUNT_SUBSCRIBE_TYPE subscribeType;
        subscribeRecord->subscribeInfoPtr_->GetOsAccountSubscribeType(subscribeType);
        if (subscribeType == state) { // For old version
            OnStateChangedV0(eventProxy, state, fromId, toId, subscriberUid, displayId);
            continue;
        }
        std::set<OsAccountState> states;
        subscribeRecord->subscribeInfoPtr_->GetStates(states);
        if (states.find(state) == states.end()) {
            continue;
        }
        OsAccountStateParcel stateParcel;
        stateParcel.fromId = fromId;
        stateParcel.toId = toId;
        stateParcel.state = state;
        if (state == SWITCHING || state == SWITCHED) {
            stateParcel.displayId = displayId;
        }
        if (IsStateNeedHandShake(state) && (subscribeRecord->subscribeInfoPtr_->IsWithHandshake())) {
            safeQueue->Push(1);
            stateParcel.callback = new (std::nothrow) OsAccountStateReplyCallbackService(
                fromId, state, cvPtr, safeQueue, subscriberUid);
        }
        OnStateChanged(eventProxy, stateParcel, subscriberUid);
    }
}

ErrCode OsAccountSubscribeManager::WaitForAllReplies(std::shared_ptr<std::condition_variable> cvPtr,
    std::shared_ptr<SafeQueue<uint8_t>> safeQueue)
{
    std::mutex mutex;
    std::unique_lock<std::mutex> waitLock(mutex);
    auto result = cvPtr->wait_for(waitLock, std::chrono::seconds(DEACTIVATION_WAIT_SECONDS),
        [safeQueue]() { return safeQueue->Size() == 0; });
    if (!result) {
        return ERR_ACCOUNT_COMMON_OPERATION_TIMEOUT;
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

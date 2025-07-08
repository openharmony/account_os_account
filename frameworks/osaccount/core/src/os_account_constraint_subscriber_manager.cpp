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

#include "os_account_constraint_subscriber_manager.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#include <pthread.h>
#include <thread>

namespace OHOS {
namespace AccountSA {
namespace {
const char THREAD_OS_ACCOUNT_CONSTRAINT_EVENT[] = "OsAccountConstraintEvent";
}
OsAccountConstraintSubscriberManager* OsAccountConstraintSubscriberManager::GetInstance()
{
    static sptr<OsAccountConstraintSubscriberManager> instance =
        new (std::nothrow) OsAccountConstraintSubscriberManager();
    return instance.GetRefPtr();
}

OsAccountConstraintSubscriberManager::OsAccountConstraintSubscriberManager() {}

ErrCode OsAccountConstraintSubscriberManager::OnConstraintChanged(
    int32_t localId, const std::set<std::string> &constraints, bool enable)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto const &constraint : constraints) {
        for (auto const &subscriber: constraint2SubscriberMap_[constraint]) {
            OsAccountConstraintStateData data{localId, constraint, enable};
            auto task = [subscriber, data]() mutable {
                subscriber->OnConstraintChanged(data);
            };
            std::thread taskThread(task);
            pthread_setname_np(taskThread.native_handle(), THREAD_OS_ACCOUNT_CONSTRAINT_EVENT);
            taskThread.detach();
        }
    }
    return ERR_OK;
}

void OsAccountConstraintSubscriberManager::InsertSubscriberRecord(
    const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber)
{
    std::set<std::string> constraintSet;
    subscriber->GetConstraintSet(constraintSet);
    subscriberSet_.emplace(subscriber);
    for (auto const &constraint : constraintSet) {
        constraint2SubscriberMap_[constraint].emplace(subscriber);
        constraintSet_.emplace(constraint);
    }
}

bool OsAccountConstraintSubscriberManager::HasSubscribed(
    const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber)
{
    return subscriberSet_.find(subscriber) != subscriberSet_.end();
}

void OsAccountConstraintSubscriberManager::RemoveSubscriberRecord(
    const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber)
{
    std::set<std::string> constraintSet;
    subscriber->GetConstraintSet(constraintSet);
    subscriberSet_.erase(subscriber);
    for (auto const &item :  constraintSet) {
        constraint2SubscriberMap_[item].erase(subscriber);
        if (constraint2SubscriberMap_[item].empty()) {
            constraint2SubscriberMap_.erase(item);
            constraintSet_.erase(item);
        }
    }
}

ErrCode OsAccountConstraintSubscriberManager::SubscribeOsAccountConstraints(
    const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber, sptr<IOsAccount> &proxy)
{
    if (subscriber == nullptr) {
        ACCOUNT_LOGE("Subscriber is nullptr.");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    std::set<std::string> constraintSet;
    subscriber->GetConstraintSet(constraintSet);
    if (constraintSet.empty()) {
        ACCOUNT_LOGE("Empty constraints.");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (constraintSet.size() > Constants::CONSTRAINT_MAX_SIZE) {
        ACCOUNT_LOGE("Constraints size=%{public}zu is too large.", constraintSet.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Proxy is nullptr.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    if (HasSubscribed(subscriber)) {
        ACCOUNT_LOGE("Already subscribed.");
        return ERR_ACCOUNT_COMMON_ACCOUNT_AREADY_SUBSCRIBE_ERROR;
    }
    constraintSet.insert(constraintSet_.begin(), constraintSet_.end());
    if (constraintSet.size() == constraintSet_.size()) {
        ACCOUNT_LOGI("No need to sync data service.");
        InsertSubscriberRecord(subscriber);
        return ERR_OK;
    }
    OsAccountConstraintSubscribeInfo subscribeInfo(constraintSet);
    ErrCode errCode = proxy->SubscribeOsAccountConstraints(subscribeInfo, GetInstance()->AsObject());
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SubscribeOsAccountConstraints fail, errcode:%{public}d", errCode);
        return errCode;
    }
    InsertSubscriberRecord(subscriber);
    return ERR_OK;
}

ErrCode OsAccountConstraintSubscriberManager::UnsubscribeOsAccountConstraints(
    const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber, sptr<IOsAccount> &proxy)
{
    if (subscriber == nullptr) {
        ACCOUNT_LOGE("Subscriber is nullptr.");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    std::set<std::string> constraintSet;
    subscriber->GetConstraintSet(constraintSet);
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Proxy is nullptr.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    if (!HasSubscribed(subscriber)) {
        ACCOUNT_LOGE("Not subscribed.");
        return ERR_ACCOUNT_COMMON_ACCOUNT_SUBSCRIBE_NOT_FOUND_ERROR;
    }
    std::set<std::string> syncData;
    for (auto const &constraint : constraintSet) {
        if (constraint2SubscriberMap_[constraint].size() == 1) {
            syncData.emplace(constraint);
        }
    }
    if (syncData.empty()) {
        ACCOUNT_LOGI("No need to sync data service.");
        RemoveSubscriberRecord(subscriber);
        return ERR_OK;
    }
    OsAccountConstraintSubscribeInfo info(syncData);
    ErrCode errCode =  proxy->UnsubscribeOsAccountConstraints(info, GetInstance()->AsObject());
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("UnsubscribeOsAccountConstraints fail, errcode:%{public}d", errCode);
        return errCode;
    }
    RemoveSubscriberRecord(subscriber);
    return ERR_OK;
}

void OsAccountConstraintSubscriberManager::RestoreConstraintSubscriberRecords(sptr<IOsAccount> &proxy)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy == nullptr) {
        ACCOUNT_LOGE("Proxy is nullptr.");
        return;
    }
    if (constraintSet_.empty()) {
        ACCOUNT_LOGD("RestoreConstraintSubscriberRecords empty.");
        return;
    }
    OsAccountConstraintSubscribeInfo subscribeInfo(constraintSet_);
    ErrCode errCode = proxy->SubscribeOsAccountConstraints(subscribeInfo, GetInstance()->AsObject());
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("RestoreConstraintSubscriberRecords failed, errCode=%{public}d.", errCode);
        return;
    }
    ACCOUNT_LOGI("RestoreConstraintSubscriberRecords success.");
}
}  // namespace AccountSA
}  // namespace OHOS
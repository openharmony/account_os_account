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

#include "os_account_constraint_event_listener.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include <pthread.h>
#include <thread>

namespace OHOS {
namespace AccountSA {
OsAccountConstraintEventListener* OsAccountConstraintEventListener::GetInstance()
{
    static OsAccountConstraintEventListener *instance = new (std::nothrow) OsAccountConstraintEventListener();
    return instance;
}

OsAccountConstraintEventListener::OsAccountConstraintEventListener()
{}

ErrCode OsAccountConstraintEventListener::OnConstraintChanged(
    int localId, const std::set<std::string> &constraints, bool enable)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto const &constraint : constraints) {
        for (auto const &subscriber: constraint2SubscriberMap_[constraint]) {
            subscriber->OnConstraintChanged(localId, constraint, enable);
        }
    }
    return ERR_OK;
}

void OsAccountConstraintEventListener::InsertSubscriberRecord(
    const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber)
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::set<std::string> constraintSet;
    subscriber->GetConstraintSet(constraintSet);
    subscriberSet_.emplace(subscriber);
    for (auto const &constraint : constraintSet) {
        constraint2SubscriberMap_[constraint].emplace(subscriber);
        constraintSet_.emplace(constraint);
    }
}

bool OsAccountConstraintEventListener::HasSubscribed(const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return subscriberSet_.find(subscriber) != subscriberSet_.end();
}

bool OsAccountConstraintEventListener::IsNeedDataSync(const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber)
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::set<std::string> constraints;
    subscriber->GetConstraintSet(constraints);
    return !std::includes(constraintSet_.begin(), constraintSet_.end(),
                            constraints.begin(), constraints.end());
}

void OsAccountConstraintEventListener::RemoveSubscriberRecord(
    const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber)
{
    std::lock_guard<std::mutex> lock(mutex_);
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

void OsAccountConstraintEventListener::GetAllConstraintSubscribeInfos(
    OsAccountConstraintSubscribeInfo &osAccountConstraintSubscribeInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::set<std::string> allConstraints = constraintSet_;
    osAccountConstraintSubscribeInfo.SetConstraints(allConstraints);
}
}  // namespace AccountSA
}  // namespace OHOS
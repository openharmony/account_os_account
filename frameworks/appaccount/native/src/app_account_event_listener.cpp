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

#include "app_account_event_listener.h"

#include "account_log_wrapper.h"
#include "app_account.h"

namespace OHOS {
namespace AccountSA {
AppAccountEventListener::AppAccountEventListener()
{}

AppAccountEventListener::~AppAccountEventListener()
{}

ErrCode AppAccountEventListener::OnAccountsChanged(const std::vector<AppAccountInfo> &accounts,
    const std::string &owner)
{
    std::string ownerKey;
    if (accounts.empty()) {
        ACCOUNT_LOGI("accounts is empty");
        ownerKey = owner;
    } else {
        AppAccountInfo info = accounts[0];
        info.GetOwner(ownerKey);
    }

    std::lock_guard<std::mutex> lock(appAccountsMutex_);
    auto it = owner2Subscribers_.find(ownerKey);
    if (it == owner2Subscribers_.end()) {
        ACCOUNT_LOGI("appAccountSubscriber is nullptr");
        return ERR_OK;
    }

    for (const auto &appAccountSubscriber : it->second) {
        appAccountSubscriber->OnAccountsChanged(accounts);
    }
    return ERR_OK;
}

ErrCode AppAccountEventListener::SubscribeAppAccount(
    const std::shared_ptr<AppAccountSubscriber> &subscriber, bool &needNotifyService)
{
    AppAccountSubscribeInfo subscribeInfo;
    subscriber->GetSubscribeInfo(subscribeInfo);
    std::vector<std::string> owners;
    subscribeInfo.GetOwners(owners);
    if (owners.size() == 0) {
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    std::sort(owners.begin(), owners.end());
    owners.erase(std::unique(owners.begin(), owners.end()), owners.end());
    subscribeInfo.SetOwners(owners);
    for (auto owner : owners) {
        if (owner.size() > Constants::OWNER_MAX_SIZE) {
            ACCOUNT_LOGE("owner is out of range, owner.size() = %{public}zu", owner.size());
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }
    }

    std::lock_guard<std::mutex> lock(appAccountsMutex_);
    auto subIt = std::find(appAccountSubscriberList_.begin(), appAccountSubscriberList_.end(), subscriber);
    if (subIt != appAccountSubscriberList_.end()) {
        ACCOUNT_LOGI("subscriber already has app account event listener");
        return ERR_APPACCOUNT_SUBSCRIBER_ALREADY_REGISTERED;
    }

    if (appAccountSubscriberList_.size() == Constants::APP_ACCOUNT_SUBSCRIBER_MAX_SIZE) {
        ACCOUNT_LOGE("the maximum number of subscribers has been reached");
        return ERR_APPACCOUNT_KIT_SUBSCRIBE;
    }
    appAccountSubscriberList_.emplace_back(subscriber);

    for (auto &owner : owners) {
        auto it = owner2Subscribers_.find(owner);
        if (it == owner2Subscribers_.end()) {
            needNotifyService = true;
            owner2Subscribers_[owner] = {subscriber};
        } else {
            owner2Subscribers_[owner].emplace_back(subscriber);
        }
    }
    ACCOUNT_LOGI("APP client subscribe, owner size=%{public}zu, subscriber size=%{public}zu.",
        owner2Subscribers_.size(), appAccountSubscriberList_.size());
    return ERR_OK;
}

ErrCode AppAccountEventListener::UnsubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber,
    bool &needNotifyService, std::vector<std::string> &deleteOwners)
{
    std::lock_guard<std::mutex> lock(appAccountsMutex_);
    auto subIt = std::find(appAccountSubscriberList_.begin(), appAccountSubscriberList_.end(), subscriber);
    if (subIt == appAccountSubscriberList_.end()) {
        ACCOUNT_LOGE("no specified subscriber has been registered");
        return ERR_APPACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED;
    }
    appAccountSubscriberList_.erase(subIt);

    deleteOwners.clear();
    for (auto &owner : owner2Subscribers_) {
        auto it = std::find(owner.second.begin(), owner.second.end(), subscriber);
        if (it == owner.second.end()) {
            continue;
        }

        owner.second.erase(it);
        if (owner.second.empty()) {
            needNotifyService = true;
            deleteOwners.emplace_back(owner.first);
        }
    }

    for (std::string &owner : deleteOwners) {
        owner2Subscribers_.erase(owner);
    }
    ACCOUNT_LOGI("APP client unsubscribe, owner size=%{public}zu, subscriber size=%{public}zu.",
        owner2Subscribers_.size(), appAccountSubscriberList_.size());
    return ERR_OK;
}

bool AppAccountEventListener::GetRestoreData(AppAccountSubscribeInfo &subscribeInfo)
{
    std::lock_guard<std::mutex> lock(appAccountsMutex_);
    if (appAccountSubscriberList_.empty()) {
        return false;
    }
    std::vector<std::string> owners;
    std::transform(owner2Subscribers_.begin(), owner2Subscribers_.end(), std::back_inserter(owners),
        [](const auto &pair) { return pair.first; });

    subscribeInfo.SetOwners(owners);
    return true;
}

AppAccountEventListener *AppAccountEventListener::GetInstance()
{
    static sptr<AppAccountEventListener> instance = new (std::nothrow) AppAccountEventListener();
    return instance.GetRefPtr();
}
}  // namespace AccountSA
}  // namespace OHOS

/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

void AppAccountEventListener::OnAccountsChanged(const std::vector<AppAccountInfo> &accounts,
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
        return;
    }

    for (const auto &appAccountSubscriber : it->second) {
        appAccountSubscriber->OnAccountsChanged(accounts);
    }
}

ErrCode AppAccountEventListener::SubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber,
    bool &isIPC, std::vector<std::string> &owners)
{
    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return AppAccount::SUBSCRIBE_FAILED;
    }

    std::lock_guard<std::mutex> lock(appAccountsMutex_);
    auto subIt = std::find(appAccountSubscriberList_.begin(), appAccountSubscriberList_.end(), subscriber);
    if (subIt != appAccountSubscriberList_.end()) {
        ACCOUNT_LOGI("subscriber already has app account event listener");
        return AppAccount::ALREADY_SUBSCRIBED;
    }

    if (appAccountSubscriberList_.size() == Constants::APP_ACCOUNT_SUBSCRIBER_MAX_SIZE) {
        ACCOUNT_LOGE("the maximum number of subscribers has been reached");
        return AppAccount::SUBSCRIBE_FAILED;
    }
    appAccountSubscriberList_.emplace_back(subscriber);

    for (auto &owner : owners) {
        auto it = owner2Subscribers_.find(owner);
        if (it == owner2Subscribers_.end()) {
            isIPC = true;
            owner2Subscribers_[owner] = {subscriber};
        } else {
            owner2Subscribers_[owner].emplace_back(subscriber);
        }
    }
    if (isIPC) {
        owners.clear();
        std::transform(owner2Subscribers_.begin(), owner2Subscribers_.end(), std::back_inserter(owners),
            [](const auto &pair) { return pair.first; });
    }
    ACCOUNT_LOGI("APP client subscribe, owner size=%{public}zu, subscriber size=%{public}zu.",
        owner2Subscribers_.size(), appAccountSubscriberList_.size());
    return AppAccount::INITIAL_SUBSCRIPTION;
}

ErrCode AppAccountEventListener::UnsubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber,
    bool &isIPC, std::vector<std::string> &owners)
{
    std::lock_guard<std::mutex> lock(appAccountsMutex_);
    auto subIt = std::find(appAccountSubscriberList_.begin(), appAccountSubscriberList_.end(), subscriber);
    if (subIt == appAccountSubscriberList_.end()) {
        ACCOUNT_LOGE("no specified subscriber has been registered");
        return ERR_APPACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED;
    }
    appAccountSubscriberList_.erase(subIt);

    owners.clear();
    for (auto &owner : owner2Subscribers_) {
        auto it = std::find(owner.second.begin(), owner.second.end(), subscriber);
        if (it == owner.second.end()) {
            continue;
        }

        owner.second.erase(it);
        if (owner.second.empty()) {
            isIPC = true;
            owners.emplace_back(owner.first);
        }
    }

    for (std::string &owner : owners) {
        owner2Subscribers_.erase(owner);
    }
    ACCOUNT_LOGI("APP client unsubscribe, owner size=%{public}zu, subscriber size=%{public}zu.",
        owner2Subscribers_.size(), appAccountSubscriberList_.size());
    return AppAccount::INITIAL_SUBSCRIPTION;
}

bool AppAccountEventListener::GetRestoreData(AppAccountSubscribeInfo &subscribeInfo)
{
    std::lock_guard<std::mutex> lock(appAccountsMutex_);
    if (appAccountSubscriberList_.empty()) {
        return false;
    }
    std::shared_ptr<AppAccountSubscriber> subscriber = appAccountSubscriberList_[0];
    if (subscriber->GetSubscribeInfo(subscribeInfo) != ERR_OK) {
        ACCOUNT_LOGE("get subscribeInfo failed");
        return false;
    }
    std::vector<std::string> owners;
    std::transform(owner2Subscribers_.begin(), owner2Subscribers_.end(), std::back_inserter(owners),
        [](const auto &pair) { return pair.first; });

    if (subscribeInfo.SetOwners(owners) != ERR_OK) {
        ACCOUNT_LOGE("failed to set owners");
        return false;
    }
    return true;
}

AppAccountEventListener *AppAccountEventListener::GetInstance()
{
    static sptr<AppAccountEventListener> instance = new (std::nothrow) AppAccountEventListener();
    return instance.GetRefPtr();
}
}  // namespace AccountSA
}  // namespace OHOS

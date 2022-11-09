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

#include "app_account_subscribe_manager.h"

#include "account_log_wrapper.h"
#include "app_account_control_manager.h"
#include "app_account_subscribe_death_recipient.h"
#include "iapp_account_event.h"
#include "ipc_skeleton.h"
#include "ohos_account_kits.h"

namespace OHOS {
namespace AccountSA {
AppAccountSubscribeManager::AppAccountSubscribeManager()
    : subscribeDeathRecipient_(sptr<IRemoteObject::DeathRecipient>(
        new (std::nothrow) AppAccountSubscribeDeathRecipient()))
{}

ErrCode AppAccountSubscribeManager::GetEventHandler(void)
{
    if (!handler_) {
        handler_ = std::make_shared<EventHandler>(EventRunner::Create());
        if (handler_ == nullptr) {
            ACCOUNT_LOGE("failed to create event handler");
            return ERR_APPACCOUNT_SERVICE_CREATE_EVENT_HANDLER;
        }
    }

    return ERR_OK;
}

ErrCode AppAccountSubscribeManager::SubscribeAppAccount(
    const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr, const sptr<IRemoteObject> &eventListener,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (subscribeInfoPtr == nullptr) {
        ACCOUNT_LOGE("subscribeInfoPtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_INFO_PTR_IS_NULLPTR;
    }

    if (eventListener == nullptr) {
        ACCOUNT_LOGE("eventListener is nullptr");
        return ERR_APPACCOUNT_SERVICE_EVENT_LISTENER_IS_NULLPTR;
    }

    std::vector<std::string> owners;
    if (subscribeInfoPtr->GetOwners(owners) != ERR_OK) {
        ACCOUNT_LOGE("failed to get owners");
        return ERR_APPACCOUNT_SERVICE_GET_OWNERS;
    }

    if (owners.size() == 0) {
        ACCOUNT_LOGE("owners size is 0");
        return ERR_APPACCOUNT_SERVICE_OWNERS_SIZE_IS_ZERO;
    }

    ErrCode result = CheckAppAccess(subscribeInfoPtr, uid, bundleName, appIndex);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check app access, result %{public}d.", result);
        return result;
    }

    auto subscribeRecordPtr = std::make_shared<AppAccountSubscribeRecord>();
    if (subscribeRecordPtr == nullptr) {
        ACCOUNT_LOGE("subscribeRecordPtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_RECORD_PTR_IS_NULLPTR;
    }

    subscribeRecordPtr->subscribeInfoPtr = subscribeInfoPtr;
    subscribeRecordPtr->eventListener = eventListener;
    subscribeRecordPtr->bundleName = bundleName;
    subscribeRecordPtr->appIndex = appIndex;

    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->AddDeathRecipient(subscribeDeathRecipient_);
    }

    return InsertSubscribeRecord(owners, subscribeRecordPtr);
}

ErrCode AppAccountSubscribeManager::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("eventListener is nullptr");
        return ERR_APPACCOUNT_SERVICE_EVENT_LISTENER_IS_NULLPTR;
    }

    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->RemoveDeathRecipient(subscribeDeathRecipient_);
    }

    return RemoveSubscribeRecord(eventListener);
}

std::vector<AppAccountSubscribeRecordPtr> AppAccountSubscribeManager::GetSubscribeRecords(const std::string &owner)
{
    auto records = std::vector<AppAccountSubscribeRecordPtr>();

    std::lock_guard<std::mutex> lock(mutex_);
    if (ownerSubscribeRecords_.size() == 0) {
        return records;
    }

    auto subscribeRecordsPtr = ownerSubscribeRecords_.find(owner);
    if (subscribeRecordsPtr == ownerSubscribeRecords_.end()) {
        return records;
    }

    auto subscribeRecords = subscribeRecordsPtr->second;
    for (auto it = subscribeRecords.begin(); it != subscribeRecords.end(); it++) {
        std::vector<std::string> owners;
        ErrCode result = (*it)->subscribeInfoPtr->GetOwners(owners);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get owners for subscribeInfoPtr, result %{public}d.", result);
            return records;
        }

        if (std::find(owners.begin(), owners.end(), owner) == owners.end()) {
            ACCOUNT_LOGE("failed to find owner in owners");
            return records;
        }

        records.emplace_back(*it);
    }

    return records;
}

ErrCode AppAccountSubscribeManager::CheckAppAccess(const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (subscribeInfoPtr == nullptr) {
        ACCOUNT_LOGE("subscribeInfoPtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_INFO_PTR_IS_NULLPTR;
    }

    std::vector<std::string> owners;
    ErrCode result = subscribeInfoPtr->GetOwners(owners);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get owners, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_GET_OWNERS;
    }

    auto controlManagerPtr = AppAccountControlManager::GetInstance();
    if (controlManagerPtr == nullptr) {
        ACCOUNT_LOGE("controlManagerPtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    auto dataStoragePtr = controlManagerPtr->GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::vector<std::string> accessibleAccounts;
    ErrCode ret = dataStoragePtr->GetAccessibleAccountsFromDataStorage(bundleName, accessibleAccounts);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to get accessible account from data storage, ret %{public}d.", ret);
        return ret;
    }
    for (auto owner : owners) {
        if (owner == bundleName) {
            continue;
        }
        auto it = std::find_if(
            accessibleAccounts.begin(),
            accessibleAccounts.end(),
            [owner](const std::string &account) {
                auto position = account.find(owner);
                if (position != 0) {
                    return false;
                }

                return true;
            });
        if (it == accessibleAccounts.end()) {
            ACCOUNT_LOGE("failed to find accessible account");
            return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_PERMISSION_DENIED;
        }
    }

    return ERR_OK;
}

ErrCode AppAccountSubscribeManager::InsertSubscribeRecord(
    const std::vector<std::string> &owners, const AppAccountSubscribeRecordPtr &subscribeRecordPtr)
{
    if (owners.size() == 0) {
        ACCOUNT_LOGE("owners size is 0");
        return ERR_APPACCOUNT_SERVICE_OWNERS_SIZE_IS_ZERO;
    }

    if (subscribeRecordPtr == nullptr) {
        ACCOUNT_LOGE("subscribeRecordPtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_RECORD_PTR_IS_NULLPTR;
    }

    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);

    for (auto owner : owners) {
        auto item = ownerSubscribeRecords_.find(owner);
        if (item != ownerSubscribeRecords_.end()) {
            item->second.insert(subscribeRecordPtr);
        } else {
            std::multiset<AppAccountSubscribeRecordPtr> subscribeRecords;
            subscribeRecords.insert(subscribeRecordPtr);
            ownerSubscribeRecords_[owner] = subscribeRecords;
        }
    }

    subscribeRecords_.emplace_back(subscribeRecordPtr);

    return ERR_OK;
}

ErrCode AppAccountSubscribeManager::RemoveSubscribeRecord(const sptr<IRemoteObject> &eventListener)
{
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("eventListener is nullptr");
        return ERR_APPACCOUNT_SERVICE_EVENT_LISTENER_IS_NULLPTR;
    }

    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);

    std::vector<std::string> owners;
    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end(); ++it) {
        if (eventListener == (*it)->eventListener) {
            (*it)->eventListener = nullptr;
            (*it)->subscribeInfoPtr->GetOwners(owners);
            subscribeRecords_.erase(it);
            break;
        }
    }

    for (auto owner : owners) {
        for (auto it = ownerSubscribeRecords_[owner].begin(); it != ownerSubscribeRecords_[owner].end(); ++it) {
            if ((eventListener == (*it)->eventListener) || ((*it)->eventListener == nullptr)) {
                (*it)->eventListener = nullptr;
                ownerSubscribeRecords_[owner].erase(it);
                break;
            }
        }

        if (ownerSubscribeRecords_[owner].size() == 0) {
            ownerSubscribeRecords_.erase(owner);
        }
    }

    return ERR_OK;
}

bool AppAccountSubscribeManager::PublishAccount(
    AppAccountInfo &appAccountInfo, const uid_t &uid, const std::string &bundleName)
{
    std::string name;
    appAccountInfo.GetName(name);
    uint32_t appIndex = appAccountInfo.GetAppIndex();

    auto eventRecordPtr = std::make_shared<AppAccountEventRecord>();
    if (eventRecordPtr == nullptr) {
        ACCOUNT_LOGE("failed to create AppAccountEventRecord");
        return false;
    }
    eventRecordPtr->info = std::make_shared<AppAccountInfo>(appAccountInfo);
    eventRecordPtr->receivers = GetSubscribeRecords(bundleName);
    eventRecordPtr->uid = uid;
    eventRecordPtr->bundleName = bundleName;
    eventRecordPtr->appIndex = appIndex;

    if (GetEventHandler() != ERR_OK) {
        ACCOUNT_LOGE("failed to get event handler");
        return false;
    }

    Callback callback = std::bind(&AppAccountSubscribeManager::OnAccountsChanged, this, eventRecordPtr);

    return handler_->PostTask(callback);
}

ErrCode AppAccountSubscribeManager::OnAccountsChanged(const std::shared_ptr<AppAccountEventRecord> &record)
{
    auto uid = record->uid;
    auto controlManagerPtr = AppAccountControlManager::GetInstance();
    if (controlManagerPtr == nullptr) {
        ACCOUNT_LOGE("controlManagerPtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    auto dataStoragePtr = controlManagerPtr->GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    for (auto receiver : record->receivers) {
        std::vector<AppAccountInfo> accessibleAccounts;
        ErrCode result = controlManagerPtr->GetAllAccessibleAccountsFromDataStorage(
            accessibleAccounts, receiver->bundleName, dataStoragePtr, record->appIndex);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get all accessible accounts from data storage, result = %{public}d", result);
            return result;
        }

        std::vector<AppAccountInfo> appAccounts;
        result = GetAccessibleAccountsBySubscribeInfo(receiver->subscribeInfoPtr, accessibleAccounts, appAccounts);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get accessible accounts by subscribe info");
            continue;
        }

        auto appAccountEventProxy = iface_cast<IAppAccountEvent>(receiver->eventListener);
        if (appAccountEventProxy == nullptr) {
            ACCOUNT_LOGE("failed to get app account event proxy");
            continue;
        }

        appAccountEventProxy->OnAccountsChanged(appAccounts);
    }

    return ERR_OK;
}

ErrCode AppAccountSubscribeManager::GetAccessibleAccountsBySubscribeInfo(
    const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr,
    const std::vector<AppAccountInfo> &accessibleAccounts, std::vector<AppAccountInfo> &appAccounts)
{
    if (subscribeInfoPtr == nullptr) {
        ACCOUNT_LOGE("subscribeInfoPtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_INFO_PTR_IS_NULLPTR;
    }

    appAccounts.clear();

    std::vector<std::string> owners;
    ErrCode result = subscribeInfoPtr->GetOwners(owners);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get owners");
        return ERR_APPACCOUNT_SERVICE_GET_OWNERS;
    }

    for (auto accessibleAccount : accessibleAccounts) {
        std::string name;
        accessibleAccount.GetName(name);

        std::string owner;
        accessibleAccount.GetOwner(owner);

        if (std::find(owners.begin(), owners.end(), owner) != owners.end()) {
            appAccounts.emplace_back(accessibleAccount);
        }
    }

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

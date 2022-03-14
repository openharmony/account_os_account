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

#include "account_log_wrapper.h"
#include "app_account_control_manager.h"
#include "app_account_subscribe_death_recipient.h"
#include "iapp_account_event.h"
#include "ipc_skeleton.h"
#include "ohos_account_kits.h"

#include "app_account_subscribe_manager.h"

namespace OHOS {
namespace AccountSA {
AppAccountSubscribeManager::AppAccountSubscribeManager()
    : subscribeDeathRecipient_(sptr<IRemoteObject::DeathRecipient>(new AppAccountSubscribeDeathRecipient()))
{
    ACCOUNT_LOGI("enter");
}

std::shared_ptr<AppAccountDataStorage> AppAccountSubscribeManager::GetDataStorage(
    const uid_t &uid, const bool &autoSync)
{
    ACCOUNT_LOGI("enter");

    std::string storeId;
    ErrCode result = GetStoreId(uid, storeId);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get store id, result = %{public}d", result);
        return nullptr;
    }

    if (autoSync == true) {
        storeId = storeId + AppAccountDataStorage::DATA_STORAGE_SUFFIX;
    }

    ACCOUNT_LOGI("storeId = %{public}s", storeId.c_str());

    return std::make_shared<AppAccountDataStorage>(storeId, autoSync);
}

ErrCode AppAccountSubscribeManager::GetStoreId(const uid_t &uid, std::string &storeId)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("uid = %{public}d", uid);

    std::int32_t uidToGetDeviceAccountId = uid;

    auto deviceAccountId = OhosAccountKits::GetInstance().GetDeviceAccountIdByUID(uidToGetDeviceAccountId);
    ACCOUNT_LOGI("deviceAccountId = %{public}d", deviceAccountId);

    storeId = std::to_string(deviceAccountId);

    ACCOUNT_LOGI("end, storeId = %{public}s", storeId.c_str());

    return ERR_OK;
}

ErrCode AppAccountSubscribeManager::GetEventHandler(void)
{
    ACCOUNT_LOGI("enter");

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
    const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

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

    ErrCode result = CheckAppAccess(subscribeInfoPtr, uid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to check app access");
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

    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->AddDeathRecipient(subscribeDeathRecipient_);
    }

    return InsertSubscribeRecord(owners, subscribeRecordPtr);
}

ErrCode AppAccountSubscribeManager::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");

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
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("owner = %{public}s", owner.c_str());

    auto records = std::vector<AppAccountSubscribeRecordPtr>();

    std::lock_guard<std::mutex> lock(mutex_);
    if (ownerSubscribeRecords_.size() == 0) {
        ACCOUNT_LOGI("ownerSubscribeRecords_ size is 0");
        return records;
    }

    auto subscribeRecordsPtr = ownerSubscribeRecords_.find(owner);
    if (subscribeRecordsPtr == ownerSubscribeRecords_.end()) {
        ACCOUNT_LOGI("subscribeRecordsPtr is ownerSubscribeRecords_ end");
        return records;
    }

    auto subscribeRecords = subscribeRecordsPtr->second;
    for (auto it = subscribeRecords.begin(); it != subscribeRecords.end(); it++) {
        std::vector<std::string> owners;
        ErrCode result = (*it)->subscribeInfoPtr->GetOwners(owners);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to get owners for subscribeInfoPtr");
            return records;
        }

        ACCOUNT_LOGI("owners.size() = %{public}zu", owners.size());
        for (auto ownerTemp : owners) {
            ACCOUNT_LOGI("owner = %{public}s", ownerTemp.c_str());
        }

        if (std::find(owners.begin(), owners.end(), owner) == owners.end()) {
            ACCOUNT_LOGI("failed to find owner in owners");
            return records;
        }

        records.emplace_back(*it);
    }

    return records;
}

ErrCode AppAccountSubscribeManager::CheckAppAccess(
    const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    if (subscribeInfoPtr == nullptr) {
        ACCOUNT_LOGE("subscribeInfoPtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_INFO_PTR_IS_NULLPTR;
    }

    std::vector<std::string> owners;
    ErrCode result = subscribeInfoPtr->GetOwners(owners);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get owners");
        return ERR_APPACCOUNT_SERVICE_GET_OWNERS;
    }

    auto dataStoragePtr = GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    for (auto owner : owners) {
        ACCOUNT_LOGI("owner = %{public}s", owner.c_str());
        if (owner == bundleName) {
            continue;
        }

        std::vector<std::string> accessibleAccounts;
        ErrCode ret = dataStoragePtr->GetAccessibleAccountsFromDataStorage(bundleName, accessibleAccounts);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("failed to get accessiable account from data storage");
            return ret;
        }

        auto it = std::find_if(accessibleAccounts.begin(), accessibleAccounts.end(), [owner](std::string account) {
            auto position = account.find(owner);
            ACCOUNT_LOGI("account = %{public}s, position = %{public}zu", account.c_str(), position);
            if (position != 0) {
                return false;
            }

            return true;
        });
        if (it == accessibleAccounts.end()) {
            ACCOUNT_LOGE("failed to find accessiable account");
            return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_PERMISSON_DENIED;
        }
    }

    return ERR_OK;
}

ErrCode AppAccountSubscribeManager::InsertSubscribeRecord(
    const std::vector<std::string> &owners, const AppAccountSubscribeRecordPtr &subscribeRecordPtr)
{
    ACCOUNT_LOGI("enter");

    if (owners.size() == 0) {
        ACCOUNT_LOGE("owners size is 0");
        return ERR_APPACCOUNT_SERVICE_OWNERS_SIZE_IS_ZERO;
    }

    if (subscribeRecordPtr == nullptr) {
        ACCOUNT_LOGE("subscribeRecordPtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_RECORD_PTR_IS_NULLPTR;
    }

    std::lock_guard<std::mutex> lock(subscribeRecordMutex_);

    ACCOUNT_LOGI("owners.size() = %{public}zu", owners.size());
    ACCOUNT_LOGI("subscribeRecordPtr = %{public}p", subscribeRecordPtr.get());

    for (auto owner : owners) {
        ACCOUNT_LOGI("owner = %{public}s", owner.c_str());

        auto item = ownerSubscribeRecords_.find(owner);
        if (item != ownerSubscribeRecords_.end()) {
            ACCOUNT_LOGI("item != ownerSubscribeRecords_.end()");
            item->second.insert(subscribeRecordPtr);
        } else {
            ACCOUNT_LOGI("item == ownerSubscribeRecords_.end()");
            std::multiset<AppAccountSubscribeRecordPtr> subscribeRecords;
            subscribeRecords.insert(subscribeRecordPtr);
            ownerSubscribeRecords_[owner] = subscribeRecords;
        }
    }

    subscribeRecords_.emplace_back(subscribeRecordPtr);
    ACCOUNT_LOGI("subscribeRecords_.size() = %{public}zu", subscribeRecords_.size());

    return ERR_OK;
}

ErrCode AppAccountSubscribeManager::RemoveSubscribeRecord(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");

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
    ACCOUNT_LOGI("enter");

    std::string name;
    if (appAccountInfo.GetName(name) == ERR_OK) {
        ACCOUNT_LOGI("name = %{public}s", name.c_str());
    }
    ACCOUNT_LOGI("bundleName = %{public}s", bundleName.c_str());

    auto eventRecordPtr = std::make_shared<AppAccountEventRecord>();
    if (eventRecordPtr == nullptr) {
        ACCOUNT_LOGE("failed to create AppAccountEventRecord");
        return false;
    }
    eventRecordPtr->info = std::make_shared<AppAccountInfo>(appAccountInfo);
    eventRecordPtr->receivers = GetSubscribeRecords(bundleName);
    eventRecordPtr->uid = uid;
    eventRecordPtr->bundleName = bundleName;

    if (GetEventHandler() != ERR_OK) {
        ACCOUNT_LOGE("failed to get event handler");
        return false;
    }

    Callback callback = std::bind(&AppAccountSubscribeManager::OnAccountsChanged, this, eventRecordPtr);

    return handler_->PostTask(callback);
}

ErrCode AppAccountSubscribeManager::OnAccountsChanged(const std::shared_ptr<AppAccountEventRecord> &record)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("record->uid = %{public}d", record->uid);
    // bundle name to publish
    ACCOUNT_LOGI("record->bundleName = %{public}s", record->bundleName.c_str());
    ACCOUNT_LOGI("record->receivers.size() = %{public}zu", record->receivers.size());

    auto uid = record->uid;

    auto dataStoragePtr = GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    auto controlManagerPtr = AppAccountControlManager::GetInstance();
    if (controlManagerPtr == nullptr) {
        ACCOUNT_LOGE("controlManagerPtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_CONTROL_MANAGER_PTR_IS_NULLPTR;
    }

    for (auto receiver : record->receivers) {
        ACCOUNT_LOGI("receiver = %{public}p", receiver.get());

        std::vector<AppAccountInfo> accessibleAccounts;
        ErrCode result = controlManagerPtr->GetAllAccessibleAccountsFromDataStorage(
            accessibleAccounts, receiver->bundleName, dataStoragePtr);
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

        ACCOUNT_LOGI("appAccounts.size() = %{public}zu", appAccounts.size());
        for (auto appAccount : appAccounts) {
            ACCOUNT_LOGI("appAccount.GetId() = %{public}s", appAccount.GetPrimeKey().c_str());
            ACCOUNT_LOGI("appAccount.ToString() = %{public}s", appAccount.ToString().c_str());
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
    ACCOUNT_LOGI("enter");

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

    ACCOUNT_LOGI("owners.size() = %{public}zu", owners.size());
    for (auto owner : owners) {
        ACCOUNT_LOGI("owner = %{public}s", owner.c_str());
    }

    ACCOUNT_LOGI("accessibleAccounts.size() = %{public}zu", accessibleAccounts.size());
    for (auto accessibleAccount : accessibleAccounts) {
        std::string name;
        result = accessibleAccount.GetName(name);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get name");
            return result;
        }

        std::string owner;
        result = accessibleAccount.GetOwner(owner);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get owner");
            return result;
        }

        ACCOUNT_LOGI("owner = %{public}s, name = %{public}s", owner.c_str(), name.c_str());

        if (std::find(owners.begin(), owners.end(), owner) != owners.end()) {
            ACCOUNT_LOGI("found owner");
            appAccounts.emplace_back(accessibleAccount);
        }
    }

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

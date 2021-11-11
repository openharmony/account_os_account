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

AppAccountSubscribeManager::~AppAccountSubscribeManager()
{
    ACCOUNT_LOGI("enter");
}

std::shared_ptr<AppAccountDataStorage> AppAccountSubscribeManager::GetDataStorage(
    const bool &autoSync, const int32_t uid)
{
    ACCOUNT_LOGI("enter");

    std::string storeId;
    ErrCode result = GetStoreId(storeId, uid);
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

ErrCode AppAccountSubscribeManager::GetStoreId(std::string &storeId, int32_t uid)
{
    ACCOUNT_LOGI("enter");

    if (uid == AppExecFwk::Constants::INVALID_UID) {
        uid = IPCSkeleton::GetCallingUid();
    }
    ACCOUNT_LOGI("uid = %{public}d", uid);

    auto deviceAccountId = OhosAccountKits::GetInstance().GetDeviceAccountIdByUID(uid);
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
    const std::string &bundleName)
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

    ErrCode result = CheckAppAccess(subscribeInfoPtr, bundleName);
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
        for (auto owner : owners) {
            ACCOUNT_LOGI("owner = %{public}s", owner.c_str());
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
    const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr, const std::string &bundleName)
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

    for (auto owner : owners) {
        ACCOUNT_LOGI("owner = %{public}s", owner.c_str());
        if (owner == bundleName) {
            continue;
        }

        auto dataStoragePtr = GetDataStorage();
        if (dataStoragePtr == nullptr) {
            ACCOUNT_LOGE("dataStoragePtr is nullptr");
            return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
        }

        std::vector<std::string> accessibleAccounts;
        ErrCode result = dataStoragePtr->GetAccessibleAccountsFromDataStorage(bundleName, accessibleAccounts);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get accessiable account from data storage");
            return result;
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

    for (auto owner : owners) {
        ACCOUNT_LOGI("owner = %{public}s", owner.c_str());

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

bool AppAccountSubscribeManager::PublishAccount(AppAccountInfo &appAccountInfo, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    auto subscribeManagerPtr = DelayedSingleton<AppAccountSubscribeManager>::GetInstance();

    auto eventRecordPtr = std::make_shared<AppAccountEventRecord>();
    eventRecordPtr->info = std::make_shared<AppAccountInfo>(appAccountInfo);
    eventRecordPtr->receivers = subscribeManagerPtr->GetSubscribeRecords(bundleName);
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

    ACCOUNT_LOGI("record->bundleName = %{public}s", record->bundleName.c_str());

    for (auto receiver : record->receivers) {
        ErrCode result = CheckAppAccess(receiver->subscribeInfoPtr, record->bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to check app access");
            continue;
        }

        auto appAccountEventProxy = iface_cast<IAppAccountEvent>(receiver->eventListener);
        if (appAccountEventProxy == nullptr) {
            ACCOUNT_LOGE("failed to get app account event proxy");
            continue;
        }

        auto dataStoragePtr = GetDataStorage();
        if (dataStoragePtr == nullptr) {
            ACCOUNT_LOGE("dataStoragePtr is nullptr");
            continue;
        }

        std::vector<AppAccountInfo> accounts;

        auto controlManagerPtr = AppAccountControlManager::GetInstance();
        result = controlManagerPtr->GetAllAccessibleAccounts(accounts, record->bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get all accessible accounts");
            return result;
        }

        ACCOUNT_LOGI("accounts.size() = %{public}zu", accounts.size());
        for (auto account : accounts) {
            ACCOUNT_LOGI("account.GetId() = %{public}s", account.GetPrimeKey().c_str());
            ACCOUNT_LOGI("account.ToString() = %{public}s", account.ToString().c_str());
        }

        appAccountEventProxy->OnAccountsChanged(accounts);
    }

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

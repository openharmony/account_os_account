/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include <pthread.h>
#include <thread>
#include "account_constants.h"
#include "account_log_wrapper.h"
#include "app_account_control_manager.h"
#include "app_account_data_storage.h"
#include "app_account_info.h"
#include "app_account_subscribe_death_recipient.h"
#include "iapp_account_event.h"
#include "ipc_skeleton.h"
#include "ohos_account_kits.h"
#include "account_info.h"
#include "account_hisysevent_adapter.h"

namespace OHOS {
namespace AccountSA {
namespace {
#ifndef FUZZ_TEST
const char THREAD_APP_ACCOUNT_EVENT[] = "appAccountEvent";
#endif
const std::string HYPHEN = "#";
}

AppAccountSubscribeManager::AppAccountSubscribeManager()
    : subscribeDeathRecipient_(sptr<IRemoteObject::DeathRecipient>(
        new (std::nothrow) AppAccountSubscribeDeathRecipient()))
{}

AppAccountSubscribeManager &AppAccountSubscribeManager::GetInstance()
{
    static AppAccountSubscribeManager *instance = new (std::nothrow) AppAccountSubscribeManager();
    return *instance;
}

ErrCode AppAccountSubscribeManager::SubscribeAppAccount(
    const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr, const sptr<IRemoteObject> &eventListener,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    if (subscribeInfoPtr == nullptr) {
        ACCOUNT_LOGE("subscribeInfoPtr is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    if (eventListener == nullptr) {
        ACCOUNT_LOGE("eventListener is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    std::vector<std::string> owners;
    subscribeInfoPtr->GetOwners(owners);

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
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    subscribeRecordPtr->subscribeInfoPtr = subscribeInfoPtr;
    subscribeRecordPtr->eventListener = eventListener;
    subscribeRecordPtr->bundleName = bundleName;
    subscribeRecordPtr->appIndex = appIndex;
    subscribeRecordPtr->subscribedAppIndex = appIndex;

    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->AddDeathRecipient(subscribeDeathRecipient_);
    }

    return InsertSubscribeRecord(owners, subscribeRecordPtr);
}

ErrCode AppAccountSubscribeManager::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener,
    std::vector<std::string> &owners)
{
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("eventListener is nullptr");
        REPORT_APP_ACCOUNT_FAIL("", "", Constants::APP_DFX_UNSUBSCRIBE,
            ERR_ACCOUNT_COMMON_NULL_PTR_ERROR, "EventListener is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    if (subscribeDeathRecipient_ != nullptr) {
        eventListener->RemoveDeathRecipient(subscribeDeathRecipient_);
    }

    return RemoveSubscribeRecord(eventListener, owners);
}

std::vector<AppAccountSubscribeRecordPtr> AppAccountSubscribeManager::GetSubscribeRecords(const std::string &owner,
    const uint32_t &appIndex)
{
    // |owner| is the encoded subscriber key (same form as InsertSubscribeRecord
    // keys), not a raw bundleName. ownerSubscribeRecords_ is keyed by that
    // encoded form, so the lookup narrows to subscribers of one specific mode.
    auto records = std::vector<AppAccountSubscribeRecordPtr>();

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (ownerSubscribeRecords_.size() == 0) {
        return records;
    }

    auto subscribeRecordsPtr = ownerSubscribeRecords_.find(owner);
    if (subscribeRecordsPtr == ownerSubscribeRecords_.end()) {
        return records;
    }

    auto subscribeRecords = subscribeRecordsPtr->second;
    for (auto it = subscribeRecords.begin(); it != subscribeRecords.end(); it++) {
        if ((*it)->subscribeInfoPtr == nullptr) {
            ACCOUNT_LOGE("subscribeInfoPtr is nullptr, skip this record");
            continue;
        }
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
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    std::vector<std::string> owners;
    subscribeInfoPtr->GetOwners(owners);
    auto dataStoragePtr = AppAccountControlManager::GetInstance().GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }
    std::vector<std::string> accessibleAccounts;
    // bundleKey encodes the caller itself (EncodeAuthorizedApp(bundleName,
    // appIndex)). It is the AUTHORIZED_ACCOUNTS JSON key under which accounts
    // authorized TO this caller are stored, so GetAccessibleAccountsFromDataStorage
    // returns those accounts' PrimeKeys ("owner#appIndex#name#"). |owners| passed
    // to CheckOwnersAccessible are the encoded subscriber targets.
    std::string bundleKey = AppAccountInfo::EncodeAuthorizedApp(bundleName, appIndex);
    ErrCode ret = dataStoragePtr->GetAccessibleAccountsFromDataStorage(bundleKey, accessibleAccounts);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to get accessible account from data storage, ret %{public}d.", ret);
        return ret;
    }
    return CheckOwnersAccessible(owners, bundleKey, accessibleAccounts);
}

ErrCode AppAccountSubscribeManager::CheckOwnersAccessible(const std::vector<std::string> &owners,
    const std::string &bundleKey, const std::vector<std::string> &accessibleAccounts)
{
    // |owners|: encoded subscriber targets (form: bare "bundle" or "bundle#appIndex").
    // |bundleKey|: the caller's own encoded key, same encoding as |owners|.
    // |accessibleAccounts|: PrimeKeys ("owner#appIndex#name#") of accounts that
    //   were authorized TO the caller (indexed by bundleKey in AUTHORIZED_ACCOUNTS).
    //
    // Self-subscribe shortcut: when an encoded owner equals the caller's
    // bundleKey, the caller is subscribing to its own accounts -> no extra
    // authorization needed (continue). Comparing against bundleKey (not the raw
    // bundleName) is what makes dual-mode self-subscribe work: both sides carry
    // the #appIndex suffix, so "com.B#10000" == "com.B#10000" matches.
    //
    // Cross-app subscribe: for a non-self owner, the account must have been
    // authorized to the caller. A PrimeKey "targetOwner#appIndex#name#" starts
    // with the encoded owner "targetOwner#appIndex" (or bare "targetOwner" for
    // main mode), so account.find(owner) == 0 is the prefix match.
    for (auto owner : owners) {
        if (owner == bundleKey) {
            continue;
        }
        auto it = std::find_if(accessibleAccounts.begin(), accessibleAccounts.end(),
            [&owner](const std::string &account) { return account.find(owner) == 0; });
        if (it == accessibleAccounts.end()) {
            ACCOUNT_LOGE("failed to find accessible account");
            REPORT_APP_ACCOUNT_FAIL("", owner, Constants::APP_DFX_SUBSCRIBE,
                ERR_ACCOUNT_COMMON_PERMISSION_DENIED, "Find accessible account failed");
            return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
        }
    }

    return ERR_OK;
}

void AppAccountSubscribeManager::ClearOldData(const sptr<IRemoteObject> &eventListener, const std::string &owner,
    std::map<std::string, std::multiset<AppAccountSubscribeRecordPtr>>::iterator &item)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto it = item->second.begin(); it != item->second.end(); ++it) {
        if ((eventListener == (*it)->eventListener) || ((*it)->eventListener == nullptr)) {
            ACCOUNT_LOGI("The subscription record already exists. Update the owner operation");
            (*it)->eventListener = nullptr;
            ownerSubscribeRecords_[owner].erase(it);
            break;
        }
    }
}

ErrCode AppAccountSubscribeManager::InsertSubscribeRecord(
    const std::vector<std::string> &owners, const AppAccountSubscribeRecordPtr &subscribeRecordPtr)
{
    if (owners.size() == 0) {
        ACCOUNT_LOGE("owners size is 0");
        REPORT_APP_ACCOUNT_FAIL("", "", Constants::APP_DFX_SUBSCRIBE,
            ERR_APPACCOUNT_SERVICE_OWNERS_SIZE_IS_ZERO, "Owners size is 0");
        return ERR_APPACCOUNT_SERVICE_OWNERS_SIZE_IS_ZERO;
    }

    if (subscribeRecordPtr == nullptr) {
        ACCOUNT_LOGE("subscribeRecordPtr is nullptr");
        REPORT_APP_ACCOUNT_FAIL("", "", Constants::APP_DFX_SUBSCRIBE,
            ERR_ACCOUNT_COMMON_NULL_PTR_ERROR, "SubscribeRecordPtr is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    std::lock_guard<std::recursive_mutex> lock(mutex_);

    // |owners| here are already encoded by EncodeOwners (form: bare "bundle"
    // for appIndex 0, or "bundle#appIndex" otherwise). They are used directly
    // as the ownerSubscribeRecords_ map key, so subscription lookup at publish
    // time matches on the same encoded form (see GetSubscribeRecords/PublishAccount).
    auto eventListener = subscribeRecordPtr->eventListener;
    for (auto owner : owners) {
        auto item = ownerSubscribeRecords_.find(owner);
        if (item != ownerSubscribeRecords_.end()) {
            ClearOldData(eventListener, owner, item);
            item->second.insert(subscribeRecordPtr);
        } else {
            std::multiset<AppAccountSubscribeRecordPtr> subscribeRecords;
            subscribeRecords.insert(subscribeRecordPtr);
            ownerSubscribeRecords_[owner] = subscribeRecords;
        }
    }
    ACCOUNT_LOGI("Update owner only, owner size=%{public}zu.", owners.size());

    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end(); ++it) {
        if ((eventListener == (*it)->eventListener) || ((*it)->eventListener == nullptr)) {
            (*it)->eventListener = nullptr;
            subscribeRecords_.erase(it);
            break;
        }
    }
    subscribeRecords_.emplace_back(subscribeRecordPtr);

    return ERR_OK;
}

void AppAccountSubscribeManager::RefreshOldData(const sptr<IRemoteObject> &eventListener, const std::string &owner,
    const std::vector<std::string> &ownerList, const std::vector<std::string> &newOwners)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto it = ownerSubscribeRecords_[owner].begin(); it != ownerSubscribeRecords_[owner].end(); ++it) {
        if ((eventListener == (*it)->eventListener) || ((*it)->eventListener == nullptr)) {
            ACCOUNT_LOGI("Clear owner only, owner size=%{public}zu.", newOwners.size());
            if ((!ownerList.empty()) && (std::find(ownerList.begin(), ownerList.end(), owner) == ownerList.end())) {
                (*it)->subscribeInfoPtr->SetOwners(newOwners);
                break;
            }
            (*it)->eventListener = nullptr;
            ownerSubscribeRecords_[owner].erase(it);
            break;
        }
    }
}

ErrCode AppAccountSubscribeManager::RemoveSubscribeRecord(const sptr<IRemoteObject> &eventListener,
    std::vector<std::string> &ownerList)
{
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("eventListener is nullptr");
        REPORT_APP_ACCOUNT_FAIL("", "", Constants::APP_DFX_UNSUBSCRIBE,
            ERR_ACCOUNT_COMMON_NULL_PTR_ERROR, "EventListener is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    std::lock_guard<std::recursive_mutex> lock(mutex_);

    std::vector<std::string> owners;
    std::vector<std::string> newOwners;
    for (auto it = subscribeRecords_.begin(); it != subscribeRecords_.end(); ++it) {
        if (eventListener == (*it)->eventListener) {
            (*it)->subscribeInfoPtr->GetOwners(owners);
            if (!ownerList.empty()) {
                std::sort(owners.begin(), owners.end());
                std::sort(ownerList.begin(), ownerList.end());
                std::set_difference(owners.begin(), owners.end(), ownerList.begin(), ownerList.end(),
                    std::back_inserter(newOwners));
                (*it)->subscribeInfoPtr->SetOwners(newOwners);
                break;
            }
            subscribeRecords_.erase(it);
            break;
        }
    }

    for (auto owner : owners) {
        RefreshOldData(eventListener, owner, ownerList, newOwners);

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
    // bundleKey = EncodeAuthorizedApp(account owner, account appIndex) has the
    // same encoding as the subscriber-side owners stored by InsertSubscribeRecord,
    // so GetSubscribeRecords finds exactly the subscribers of this app's mode
    // (main-mode subscribers match bare key, dual-mode subscribers match #10000).
    std::string bundleKey = AppAccountInfo::EncodeAuthorizedApp(bundleName, appIndex);
    eventRecordPtr->receivers = GetSubscribeRecords(bundleKey, appIndex);
    eventRecordPtr->uid = uid;
    eventRecordPtr->bundleName = bundleName;
    eventRecordPtr->appIndex = appIndex;

    auto callback = [this, eventRecordPtr] { this->OnAccountsChanged(eventRecordPtr); };

#ifdef FUZZ_TEST
    callback();
#else
    std::thread taskThread(callback);
    pthread_setname_np(taskThread.native_handle(), THREAD_APP_ACCOUNT_EVENT);
    taskThread.detach();
#endif
    return true;
}

bool AppAccountSubscribeManager::IsReceiverAuthorizedApp(
    const std::shared_ptr<AppAccountEventRecord> &record, const AppAccountSubscribeRecordPtr &receiver)
{
    bool isAuthorizedApp = false;
    // precise lookup: encode the receiver's raw appIndex (no visibility query).
    std::string encodedApp;
    AppAccountControlManager::EncodeAuthorizedAppPrecise(receiver->bundleName, receiver->appIndex, encodedApp);
    record->info->CheckAppAccess(encodedApp, isAuthorizedApp);
    return isAuthorizedApp;
}

ErrCode AppAccountSubscribeManager::OnAccountsChanged(const std::shared_ptr<AppAccountEventRecord> &record)
{
    auto uid = record->uid;
    auto &controlManagerPtr = AppAccountControlManager::GetInstance();
    auto dataStoragePtr = controlManagerPtr.GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }
    std::string ownerName;
    record->info->GetOwner(ownerName);

    for (auto receiver : record->receivers) {
        bool isAuthorizedApp = IsReceiverAuthorizedApp(record, receiver);
        if (!isAuthorizedApp && receiver->bundleName != ownerName) {
            continue;
        }
        std::vector<AppAccountInfo> accessibleAccounts;
        ErrCode result = controlManagerPtr.GetAllAccessibleAccountsFromDataStorage(
            accessibleAccounts, receiver->bundleName, dataStoragePtr, receiver->appIndex);
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

        int32_t retryTimes = 0;
        ErrCode errCode;
        while (retryTimes < Constants::MAX_RETRY_TIMES) {
            errCode = appAccountEventProxy->OnAccountsChanged(appAccounts, record->info->GetOwner());
            if (errCode == ERR_OK || (errCode != Constants::E_IPC_ERROR &&
                errCode != Constants::E_IPC_SA_DIED)) {
                break;
            }
            retryTimes++;
            ACCOUNT_LOGE("Failed to SendRequest, code = %{public}d, retryTimes = %{public}d",
                errCode, retryTimes);
            std::this_thread::sleep_for(std::chrono::milliseconds(Constants::DELAY_FOR_EXCEPTION));
        }
    }

    return ERR_OK;
}

ErrCode AppAccountSubscribeManager::GetAccessibleAccountsBySubscribeInfo(
    const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr,
    const std::vector<AppAccountInfo> &accessibleAccounts, std::vector<AppAccountInfo> &appAccounts)
{
    if (subscribeInfoPtr == nullptr) {
        ACCOUNT_LOGE("subscribeInfoPtr is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    appAccounts.clear();

    std::vector<std::string> owners;
    subscribeInfoPtr->GetOwners(owners);

    for (auto accessibleAccount : accessibleAccounts) {
        std::string owner;
        accessibleAccount.GetOwner(owner);
        std::string encodedOwner = AppAccountInfo::EncodeAuthorizedApp(owner, accessibleAccount.GetAppIndex());
        if (std::find(owners.begin(), owners.end(), encodedOwner) != owners.end()) {
            appAccounts.emplace_back(accessibleAccount);
        }
    }

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

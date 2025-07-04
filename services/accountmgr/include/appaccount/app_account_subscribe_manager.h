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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_SUBSCRIBE_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_SUBSCRIBE_MANAGER_H

#include <map>
#include <set>

#include "app_account_event_record.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
class AppAccountSubscribeManager {
public:
    static AppAccountSubscribeManager &GetInstance();
    ErrCode SubscribeAppAccount(const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr,
        const sptr<IRemoteObject> &eventListener, const uid_t &uid,
        const std::string &bundleName, const uint32_t &appIndex);
    ErrCode UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener, std::vector<std::string> &owners);
    static bool CheckAppIsMaster(const std::string &account);

    bool PublishAccount(AppAccountInfo &appAccountInfo, const uid_t &uid, const std::string &bundleName);

private:
    AppAccountSubscribeManager();
    ~AppAccountSubscribeManager() = default;
    DISALLOW_COPY_AND_MOVE(AppAccountSubscribeManager);
    ErrCode GetStoreId(const uid_t &uid, std::string &storeId);

    std::vector<AppAccountSubscribeRecordPtr> GetSubscribeRecords(const std::string &owner,
        const uint32_t &appIndex = 0);
    ErrCode OnAccountsChanged(const std::shared_ptr<AppAccountEventRecord> &record);
    ErrCode GetAccessibleAccountsBySubscribeInfo(const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr,
        const std::vector<AppAccountInfo> &accessibleAccounts, std::vector<AppAccountInfo> &appAccounts);

    ErrCode CheckAppAccess(const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr, const uid_t &uid,
        const std::string &bundleName, const uint32_t &appIndex);

    void ClearOldData(const sptr<IRemoteObject> &eventListener, const std::string &owner,
        std::map<std::string, std::multiset<AppAccountSubscribeRecordPtr>>::iterator &item);

    ErrCode InsertSubscribeRecord(
        const std::vector<std::string> &owners, const AppAccountSubscribeRecordPtr &subscribeRecordPtr);
    void RefreshOldData(const sptr<IRemoteObject> &eventListener, const std::string &owner,
            const std::vector<std::string> &ownerList, const std::vector<std::string> &newOwners);
    
    ErrCode RemoveSubscribeRecord(const sptr<IRemoteObject> &eventListener, std::vector<std::string> &ownerList);

private:
    std::mutex mutex_;
    sptr<IRemoteObject::DeathRecipient> subscribeDeathRecipient_;
    std::mutex subscribeRecordMutex_;
    std::map<std::string, std::multiset<AppAccountSubscribeRecordPtr>> ownerSubscribeRecords_;
    std::vector<AppAccountSubscribeRecordPtr> subscribeRecords_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_SUBSCRIBE_MANAGER_H

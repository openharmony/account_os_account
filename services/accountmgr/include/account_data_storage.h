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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_DATA_STORAGE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_DATA_STORAGE_H

#include <string>
#include <map>

#include "account_error_no.h"
#ifndef SQLITE_DLCLOSE_ENABLE
#include "distributed_kv_data_manager.h"
#else
#include "database_adapter_loader.h"
#endif // SQLITE_DLCLOSE_ENABLE
#include "iaccount_info.h"

namespace OHOS {
namespace AccountSA {
#ifndef SQLITE_DLCLOSE_ENABLE
struct AccountDataStorageOptions {
    bool encrypt = false;
    bool autoSync = false;
    DistributedKv::SecurityLevel securityLevel = DistributedKv::SecurityLevel::S1;
    OHOS::DistributedKv::Area area = OHOS::DistributedKv::EL1;
    std::string baseDir;
};
#endif // SQLITE_DLCLOSE_ENABLE

#ifndef SQLITE_DLCLOSE_ENABLE
class AccountDataStorage {
public:
    AccountDataStorage() = delete;
    AccountDataStorage(const std::string &appId, const std::string &storeId, const AccountDataStorageOptions &options);
    virtual ~AccountDataStorage();
    ErrCode LoadAllData(std::map<std::string, std::shared_ptr<IAccountInfo>> &infos);
    ErrCode AddAccountInfo(const IAccountInfo &iAccountInfo);
    ErrCode SaveAccountInfo(const IAccountInfo &iAccountInfo);
    ErrCode LoadDataByLocalFuzzyQuery(std::string subId, std::map<std::string, std::shared_ptr<IAccountInfo>> &infos);
    void TryTwice(const std::function<DistributedKv::Status()> &func) const;
    virtual void SaveEntries(const std::vector<OHOS::DistributedKv::Entry> &allEntries,
        std::map<std::string, std::shared_ptr<IAccountInfo>> &infos) = 0;
    ErrCode Close();
    int DeleteKvStore();
    ErrCode GetAccountInfoById(const std::string id, IAccountInfo &iAccountInfo);
    bool IsKeyExists(const std::string keyStr);
    ErrCode PutValueToKvStore(const std::string &keyStr, const std::string &valueStr);
    ErrCode GetValueFromKvStore(const std::string &keyStr, std::string &valueStr);
    ErrCode RemoveValueFromKvStore(const std::string &keyStr);
    ErrCode MoveData(const std::shared_ptr<AccountDataStorage> &ptr);
    ErrCode StartTransaction();
    ErrCode Commit();
    ErrCode Rollback();

protected:
    OHOS::DistributedKv::Status GetEntries(
        std::string subId, std::vector<OHOS::DistributedKv::Entry> &allEntries) const;
    OHOS::DistributedKv::Status GetKvStore();
    bool CheckKvStore();
    OHOS::DistributedKv::DistributedKvDataManager dataManager_;
    std::shared_ptr<OHOS::DistributedKv::SingleKvStore> kvStorePtr_;
    mutable std::mutex kvStorePtrMutex_;
    OHOS::DistributedKv::AppId appId_;
    OHOS::DistributedKv::StoreId storeId_;
    AccountDataStorageOptions options_;
    std::string baseDir_;
    std::recursive_mutex transactionMutex_;
};
#else
class AccountDataStorage {
public:
    AccountDataStorage() = delete;
    AccountDataStorage(const std::string &appId, const std::string &storeId, const DbAdapterOptions &options);
    virtual ~AccountDataStorage();
    ErrCode LoadAllData(std::map<std::string, std::shared_ptr<IAccountInfo>> &infos);
    ErrCode AddAccountInfo(const IAccountInfo &iAccountInfo);
    ErrCode SaveAccountInfo(const IAccountInfo &iAccountInfo);
    ErrCode LoadDataByLocalFuzzyQuery(std::string subId, std::map<std::string, std::shared_ptr<IAccountInfo>> &infos);
    void TryTwice(const std::function<DbAdapterStatus()> &func) const;
    virtual void SaveEntries(const std::vector<DbAdapterEntry> &allEntries,
        std::map<std::string, std::shared_ptr<IAccountInfo>> &infos) = 0;
    ErrCode Close();
    int DeleteKvStore();
    ErrCode GetAccountInfoById(const std::string id, IAccountInfo &iAccountInfo);
    bool IsKeyExists(const std::string keyStr);
    ErrCode PutValueToKvStore(const std::string &keyStr, const std::string &valueStr);
    ErrCode GetValueFromKvStore(const std::string &keyStr, std::string &valueStr);
    ErrCode RemoveValueFromKvStore(const std::string &keyStr);
    ErrCode MoveData(const std::shared_ptr<AccountDataStorage> &ptr);
    ErrCode StartTransaction();
    ErrCode Commit();
    ErrCode Rollback();

protected:
    DbAdapterStatus GetEntries(
        std::string subId, std::vector<DbAdapterEntry> &allEntries) const;
    DbAdapterStatus GetKvStore();
    bool CheckKvStore();
    std::shared_ptr<IDbAdapterDataManager> dataManager_ = nullptr;
    std::shared_ptr<IDbAdapterSingleStore> kvStorePtr_ = nullptr;
    mutable std::mutex kvStorePtrMutex_;
    std::string appId_;
    std::string storeId_;
    DbAdapterOptions options_;
    std::string baseDir_;
};
#endif // SQLITE_DLCLOSE_ENABLE

typedef std::unique_ptr<bool, std::function<void(bool *)>> DatabaseTransaction;

ErrCode StartDbTransaction(
    const std::shared_ptr<AccountDataStorage> &dataStoragePtr, DatabaseTransaction &dbTransaction);
ErrCode CommitDbTransaction(
    const std::shared_ptr<AccountDataStorage> &dataStoragePtr, DatabaseTransaction &dbTransaction);
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_DATA_STORAGE_H

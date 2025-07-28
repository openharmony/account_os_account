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
#include "app_account_info.h"
#include "os_account_info.h"
#ifdef SQLITE_DLCLOSE_ENABLE
#include "database_adapter_loader.h"
#else
#include "kvstore_adapter_impl.h"
#endif // SQLITE_DLCLOSE_ENABLE

namespace OHOS {
namespace AccountSA {

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
    ErrCode GetAccountInfoById(const std::string id, OHOS::AccountSA::AppAccountInfo &accountInfo);
    ErrCode GetAccountInfoById(const std::string id, OHOS::AccountSA::OsAccountInfo &accountInfo);
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
    mutable std::recursive_mutex kvStorePtrMutex_;
    std::string appId_;
    std::string storeId_;
    DbAdapterOptions options_;
    std::string baseDir_;
    std::recursive_mutex transactionMutex_;
};

typedef std::unique_ptr<bool, std::function<void(bool *)>> DatabaseTransaction;

ErrCode StartDbTransaction(
    const std::shared_ptr<AccountDataStorage> &dataStoragePtr, DatabaseTransaction &dbTransaction);
ErrCode CommitDbTransaction(
    const std::shared_ptr<AccountDataStorage> &dataStoragePtr, DatabaseTransaction &dbTransaction);
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_DATA_STORAGE_H

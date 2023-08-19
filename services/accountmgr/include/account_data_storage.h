/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "distributed_kv_data_manager.h"
#include "account_error_no.h"
#include "iaccount_info.h"

namespace OHOS {
namespace AccountSA {
struct AccountDataStorageOptions {
    bool autoSync = false;
    DistributedKv::SecurityLevel securityLevel = DistributedKv::SecurityLevel::S1;
    OHOS::DistributedKv::Area area = OHOS::DistributedKv::EL1;
    std::string baseDir;
};

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
    virtual void SaveEntries(std::vector<OHOS::DistributedKv::Entry> allEntries,
        std::map<std::string, std::shared_ptr<IAccountInfo>> &infos) = 0;
    int DeleteKvStore();
    ErrCode GetAccountInfoById(const std::string id, IAccountInfo &iAccountInfo);
    bool IsKeyExists(const std::string keyStr);
    ErrCode PutValueToKvStore(const std::string &keyStr, const std::string &valueStr);
    ErrCode GetValueFromKvStore(const std::string &keyStr, std::string &valueStr);
    ErrCode RemoveValueFromKvStore(const std::string &keyStr);

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
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_DATA_STORAGE_H

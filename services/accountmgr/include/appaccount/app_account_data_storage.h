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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_DATA_STORAGE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_DATA_STORAGE_H

#include "account_data_storage.h"
#include "app_account_info.h"
#include "json_utils.h"
namespace OHOS {
namespace AccountSA {
class AppAccountDataStorage : public AccountDataStorage {
public:
    AppAccountDataStorage() = delete;
#ifndef SQLITE_DLCLOSE_ENABLE
    AppAccountDataStorage(const std::string &storeId, const AccountDataStorageOptions &options);
#else
    AppAccountDataStorage(const std::string &storeId, const DbAdapterOptions &options);
#endif // SQLITE_DLCLOSE_ENABLE
    ~AppAccountDataStorage() override = default;

    CJsonUnique GetAccessibleAccountsFromAuthorizedAccounts(const std::string &authorizedAccounts,
        const std::string &authorizedApp, std::vector<std::string> &accessibleAccounts);
    ErrCode GetAccessibleAccountsFromDataStorage(
        const std::string &authorizedApp, std::vector<std::string> &accessibleAccounts);

    ErrCode GetAccountInfoFromDataStorage(AppAccountInfo &appAccountInfo);
    ErrCode AddAccountInfoIntoDataStorage(AppAccountInfo &appAccountInfo);
    ErrCode SaveAccountInfoIntoDataStorage(AppAccountInfo &appAccountInfo);
    ErrCode DeleteAccountInfoFromDataStorage(AppAccountInfo &appAccountInfo);

private:
#ifndef SQLITE_DLCLOSE_ENABLE
    void SaveEntries(const std::vector<OHOS::DistributedKv::Entry> &allEntries,
        std::map<std::string, std::shared_ptr<IAccountInfo>> &infos) override;
#else
    void SaveEntries(const std::vector<DbAdapterEntry> &allEntries,
        std::map<std::string, std::shared_ptr<IAccountInfo>> &infos) override;
#endif // SQLITE_DLCLOSE_ENABLE
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_DATA_STORAGE_H

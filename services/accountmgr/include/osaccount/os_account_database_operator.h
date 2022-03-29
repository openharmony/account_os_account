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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_DATABSE_OPERATOR_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_DATABSE_OPERATOR_H

#include <memory>
#include "account_data_storage.h"
#include "ios_account_control.h"

namespace OHOS {
namespace AccountSA {
class OsAccountDatabaseOperator {
public:
    OsAccountDatabaseOperator();
    virtual ~OsAccountDatabaseOperator();
    void Init();

    // update infos to database
    void UpdateOsAccountIDListInDatabase(const Json &accountListJson);
    void UpdateOsAccountInDatabase(const OsAccountInfo &osAccountInfo);
    void InsertOsAccountIntoDataBase(const OsAccountInfo &osAccountInfo);
    void DelOsAccountFromDatabase(const int id);

    ErrCode GetCreatedOsAccountNumFromDatabase(const std::string& storeID, int &createdOsAccountNum);
    ErrCode GetSerialNumberFromDatabase(const std::string& storeID, int64_t &serialNumber);
    ErrCode GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id);
    ErrCode GetOsAccountFromDatabase(const std::string& storeID, const int id, OsAccountInfo &osAccountInfo);
    ErrCode GetOsAccountListFromDatabase(const std::string& storeID, std::vector<OsAccountInfo> &osAccountList);

private:
    ErrCode GetAccountListFromStoreID(const std::string& storeID, Json &accountListJson);
    ErrCode SaveAccountListToDatabase(const Json &accountListJson);
    bool InnerInit();

private:
    std::shared_ptr<AccountDataStorage> accountDataStorage_;
    std::string storeID_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CONTROL_DATABSE_MANAGER_H
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CONTROL_FILE_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CONTROL_FILE_MANAGER_H

#include <memory>
#include <mutex>
#include "ios_account_control.h"
#include "os_account_database_operator.h"
#include "os_account_file_operator.h"
#include "os_account_photo_operator.h"
namespace OHOS {
namespace AccountSA {

bool GetValidAccountID(const std::string& dirName, std::int32_t& accountID);

class OsAccountControlFileManager : public IOsAccountControl {
public:
    OsAccountControlFileManager();
    virtual ~OsAccountControlFileManager();
    void Init() override;
    ErrCode GetOsAccountList(std::vector<OsAccountInfo> &osAccountList) override;
    ErrCode GetOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo) override;
    ErrCode GetConstraintsByType(const OsAccountType type, std::vector<std::string> &constraints) override;
    ErrCode InsertOsAccount(OsAccountInfo &osAccountInfo) override;
    ErrCode DelOsAccount(const int id) override;
    ErrCode UpdateOsAccount(OsAccountInfo &osAccountInfo) override;
    ErrCode GetMaxCreatedOsAccountNum(int &maxCreatedOsAccountNum) override;
    ErrCode GetSerialNumber(int64_t &serialNumber) override;
    ErrCode GetAllowCreateId(int &id) override;
    ErrCode IsOsAccountExists(const int id, bool &isExists) override;
    ErrCode GetPhotoById(const int id, std::string &photo) override;
    ErrCode SetPhotoById(const int id, const std::string &photo) override;
    ErrCode GetIsMultiOsAccountEnable(bool &isMultiOsAccountEnable) override;
    ErrCode CheckConstraintsList(const std::vector<std::string> &constraints,
        bool &isExists, bool &isOverSize) override;
    ErrCode IsAllowedCreateAdmin(bool &isAllowedCreateAdmin) override;

    ErrCode GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
        int &createdOsAccountNum) override;
    ErrCode GetSerialNumberFromDatabase(const std::string& storeID,
        int64_t &serialNumber) override;
    ErrCode GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id) override;
    ErrCode GetOsAccountFromDatabase(const std::string& storeID,
        const int id, OsAccountInfo& osAccountInfo) override;
    ErrCode GetOsAccountListFromDatabase(const std::string& storeID,
        std::vector<OsAccountInfo>& osAccountList) override;

    ErrCode RemoveOAConstraintsInfo(const int32_t id) override;
    ErrCode IsFromBaseOAConstraintsList(const int32_t id, const std::string constraint, bool &isExits) override;
    ErrCode IsFromGlobalOAConstraintsList(const int32_t id, const int32_t deviceOwnerId,
        const std::string constraint, std::vector<ConstraintSourceTypeInfo> &globalSourceList) override;
    ErrCode IsFromSpecificOAConstraintsList(const int32_t id, const int32_t deviceOwnerId,
        const std::string constraint, std::vector<ConstraintSourceTypeInfo> &specificSourceList) override;
    ErrCode GetGlobalOAConstraintsList(std::vector<std::string> &constraintsList) override;
    ErrCode GetSpecificOAConstraintsList(const int32_t id, std::vector<std::string> &constraintsList) override;
    ErrCode UpdateBaseOAConstraints(const std::string& idStr,
        const std::vector<std::string>& ConstraintStr, bool isAdd) override;
    ErrCode UpdateGlobalOAConstraints(const std::string& idStr,
        const std::vector<std::string>& ConstraintStr, bool isAdd) override;
    ErrCode UpdateSpecificOAConstraints(const std::string& idStr,
        const std::string& targetIdStr, const std::vector<std::string>& ConstraintStr, bool isAdd) override;
    ErrCode GetDeviceOwnerId(int32_t &deviceOwnerId) override;
    ErrCode UpdateDeviceOwnerId(const int32_t deviceOwnerId) override;

private:
    ErrCode UpdateAccountList(const std::string& idStr, bool isAdd);
    ErrCode GetAccountListFromFile(Json& accountListJson);
    ErrCode SaveAccountListToFile(const Json& accountListJson);
    ErrCode SaveAccountListToFileAndDataBase(const Json& accountListJson);
    void BuildAndSaveAccountListJsonFile(const std::vector<std::string>& accounts);
    void RecoverAccountListJsonFile();
    void BuildAndSaveBaseOAConstraintsJsonFile();
    void BuildAndSaveGlobalOAConstraintsJsonFile();
    void BuildAndSaveSpecificOAConstraintsJsonFile();
    void GlobalConstraintsDataOperate(const std::string& idStr,
        const std::vector<std::string>& ConstraintStr, bool isAdd, Json &globalOAConstraintsJson);
    void SpecificConstraintsDataOperate(const std::string& idStr, const std::string& targetIdStr,
        const std::vector<std::string>& ConstraintStr, bool isAdd, Json& userPrivateConstraintsDataJson);

    ErrCode GetBaseOAConstraintsFromFile(Json &baseOAConstraintsJson);
    ErrCode GetGlobalOAConstraintsFromFile(Json &globalOAConstraintsJson);
    ErrCode GetSpecificOAConstraintsFromFile(Json &specificOAConstraintsJson);
    ErrCode SaveBaseOAConstraintsToFile(const Json &baseOAConstraints);
    ErrCode SaveGlobalOAConstraintsToFile(const Json &globalOAConstraints);
    ErrCode SaveSpecificOAConstraintsToFile(const Json &specificOAConstraints);

    ErrCode RemoveOABaseConstraintsInfo(const int32_t id);
    ErrCode RemoveOAGlobalConstraintsInfo(const int32_t id);
    ErrCode RemoveOASpecificConstraintsInfo(const int32_t id);

private:
    std::shared_ptr<AccountFileOperator> accountFileOperator_;
    std::shared_ptr<OsAccountDatabaseOperator> osAccountDataBaseOperator_;
    std::shared_ptr<OsAccountFileOperator> osAccountFileOperator_;
    std::shared_ptr<OsAccountPhotoOperator> osAccountPhotoOperator_;
    std::mutex accountListFileLock_;
    std::mutex baseOAConstraintsFileLock_;
    std::mutex globalOAConstraintsFileLock_;
    std::mutex specificOAConstraintsFileLock_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CONTROL_FILE_MANAGER_H

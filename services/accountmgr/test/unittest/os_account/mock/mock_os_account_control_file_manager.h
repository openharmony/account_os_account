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

#ifndef MOCK_OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CONTROL_FILE_MANAGER_H
#define MOCK_OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CONTROL_FILE_MANAGER_H

#include "gmock/gmock.h"
#include <memory>
#include <mutex>
#include "ios_account_control.h"
#include "os_account_database_operator.h"
#include "os_account_file_operator.h"
#include "os_account_photo_operator.h"
#include "os_account_control_file_manager.h"


namespace OHOS {
namespace AccountSA {
class MockOsAccountControlFileManager : public IOsAccountControl {
public:
    MockOsAccountControlFileManager() {}
    virtual ~MockOsAccountControlFileManager() {}
    MOCK_METHOD1(GetOsAccountConfig, ErrCode(OsAccountConfig &config));
    MOCK_METHOD1(GetOsAccountIdList, ErrCode(std::vector<int32_t> &idList));
    MOCK_METHOD1(GetOsAccountList, ErrCode(std::vector<OsAccountInfo> &osAccountList));
    MOCK_METHOD2(GetConstraintsByType, ErrCode(const OsAccountType type, std::vector<std::string> &constraints));
    MOCK_METHOD2(GetOsAccountInfoById, ErrCode(const int id, OsAccountInfo &osAccountInfo));
    MOCK_METHOD1(GetSerialNumber, ErrCode(int64_t &serialNumber));
    MOCK_METHOD1(GetAllowCreateId, ErrCode(int &id));
    MOCK_METHOD1(InsertOsAccount, ErrCode(OsAccountInfo &osAccountInfo));
    MOCK_METHOD3(UpdateBaseOAConstraints, ErrCode(const std::string& idStr,
        const std::vector<std::string>& ConstraintStr, bool isAdd));
    MOCK_METHOD1(UpdateOsAccount, ErrCode(OsAccountInfo &osAccountInfo));
    MOCK_METHOD1(RemoveOAConstraintsInfo, ErrCode(const int32_t id));
    MOCK_METHOD1(DelOsAccount, ErrCode(const int id));
    MOCK_METHOD1(GetGlobalOAConstraintsList, ErrCode(std::vector<std::string> &constraintsList));
    MOCK_METHOD2(GetSpecificOAConstraintsList, ErrCode (const int32_t id, std::vector<std::string> &constraintsList));
    MOCK_METHOD4(IsFromGlobalOAConstraintsList, ErrCode(const int32_t id, const int32_t deviceOwnerId,
        const std::string constraint, std::vector<ConstraintSourceTypeInfo> &globalSourceList));
    MOCK_METHOD4(IsFromSpecificOAConstraintsList, ErrCode(const int32_t id, const int32_t deviceOwnerId,
        const std::string constraint, std::vector<ConstraintSourceTypeInfo> &specificSourceList));
    MOCK_METHOD3(CheckConstraintsList, ErrCode(const std::vector<std::string> &constraints,
        bool &isExists, bool &isOverSize));
    MOCK_METHOD2(GetPhotoById, ErrCode(const int id, std::string &photo));
    MOCK_METHOD1(GetIsMultiOsAccountEnable, ErrCode(bool &isMultiOsAccountEnable));
    MOCK_METHOD2(SetPhotoById, ErrCode(const int id, const std::string &photo));
    MOCK_METHOD1(UpdateDeviceOwnerId, ErrCode(const int32_t deviceOwnerId));
    MOCK_METHOD1(SetDefaultActivatedOsAccount, ErrCode(const int32_t initialStartupId));
    MOCK_METHOD3(UpdateGlobalOAConstraints, ErrCode(const std::string& idStr,
        const std::vector<std::string>& ConstraintStr, bool isAdd));
    void Init() {}
    ErrCode GetAccountIndexFromFile(Json &accountIndexJson) { return ERR_OK; }
    ErrCode IsOsAccountExists(const int id, bool &isExists) { return ERR_OK; }
    ErrCode IsAllowedCreateAdmin(bool &isAllowedCreateAdmin) { return ERR_OK; }
    ErrCode GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
        int &createdOsAccountNum) { return ERR_OK; }
    ErrCode GetSerialNumberFromDatabase(const std::string& storeID,
        int64_t &serialNumber) { return ERR_OK; }
    ErrCode GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id) { return ERR_OK; }
    ErrCode GetOsAccountFromDatabase(const std::string& storeID,
        const int id, OsAccountInfo &osAccountInfo) { return ERR_OK; }
    ErrCode GetOsAccountListFromDatabase(const std::string& storeID,
        std::vector<OsAccountInfo> &osAccountList) { return ERR_OK; }
    ErrCode IsFromBaseOAConstraintsList(const int32_t id, const std::string constraint, bool &isExits)
    {
        return ERR_OK;
    }
    ErrCode UpdateSpecificOAConstraints(const std::string& idStr,
        const std::string& targetIdStr, const std::vector<std::string>& ConstraintStr, bool isAdd) { return ERR_OK; }
    ErrCode GetDeviceOwnerId(int32_t &deviceOwnerId) { return ERR_OK; }
    ErrCode GetDefaultActivatedOsAccount(int32_t &id) { return ERR_OK; }
    ErrCode UpdateAccountIndex(const OsAccountInfo &osAccountInfo, const bool isDelete) { return ERR_OK; }
};

}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CONTROL_FILE_MANAGER_H

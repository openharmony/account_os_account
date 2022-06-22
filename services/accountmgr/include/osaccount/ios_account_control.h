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
#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_IOS_ACCOUNT_CONTROL_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_IOS_ACCOUNT_CONTROL_H
#include "os_account_info.h"
#include "account_error_no.h"
namespace OHOS {
namespace AccountSA {
class IOsAccountControl {
public:
    virtual void Init() = 0;
    virtual ErrCode GetOsAccountList(std::vector<OsAccountInfo> &osAccountList) = 0;
    virtual ErrCode GetOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo) = 0;
    virtual ErrCode GetConstraintsByType(const OsAccountType type, std::vector<std::string> &constraints) = 0;
    virtual ErrCode InsertOsAccount(OsAccountInfo &osAccountInfo) = 0;
    virtual ErrCode DelOsAccount(const int id) = 0;
    virtual ErrCode UpdateOsAccount(OsAccountInfo &osAccountInfo) = 0;
    virtual ErrCode GetMaxCreatedOsAccountNum(int &maxCreatedOsAccountNum) = 0;
    virtual ErrCode GetSerialNumber(int64_t &serialNumber) = 0;
    virtual ErrCode GetAllowCreateId(int &id) = 0;
    virtual ErrCode IsOsAccountExists(const int id, bool &isExists) = 0;
    virtual ErrCode GetPhotoById(const int id, std::string &photo) = 0;
    virtual ErrCode SetPhotoById(const int id, const std::string &photo) = 0;
    virtual ErrCode GetIsMultiOsAccountEnable(bool &isMultiOsAccountEnable) = 0;
    virtual ErrCode CheckConstraintsList(const std::vector<std::string> &constraints,
        bool &isExists, bool &isOverSize) = 0;
    virtual ErrCode IsAllowedCreateAdmin(bool &isAllowedCreateAdmin) = 0;

    virtual ErrCode GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
        int &createdOsAccountNum) = 0;
    virtual ErrCode GetSerialNumberFromDatabase(const std::string& storeID,
        int64_t &serialNumber) = 0;
    virtual ErrCode GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id) = 0;
    virtual ErrCode GetOsAccountFromDatabase(const std::string& storeID,
        const int id, OsAccountInfo &osAccountInfo) = 0;
    virtual ErrCode GetOsAccountListFromDatabase(const std::string& storeID,
        std::vector<OsAccountInfo> &osAccountList) = 0;

    virtual ErrCode RemoveOAConstraintsInfo(const int32_t id) = 0;
    virtual ErrCode IsFromBaseOAConstraintsList(const int32_t id, const std::string constraint, bool &isExits) = 0;
    virtual ErrCode IsFromGlobalOAConstraintsList(const int32_t id, const int32_t deviceOwnerId,
        const std::string constraint, std::vector<ConstraintSourceTypeInfo> &globalSourceList) = 0;
    virtual ErrCode IsFromSpecificOAConstraintsList(const int32_t id, const int32_t deviceOwnerId,
        const std::string constraint, std::vector<ConstraintSourceTypeInfo> &specificSourceList) = 0;
    virtual ErrCode GetGlobalOAConstraintsList(std::vector<std::string> &constraintsList) = 0;
    virtual ErrCode GetSpecificOAConstraintsList(const int32_t id, std::vector<std::string> &constraintsList) = 0;
    virtual ErrCode UpdateBaseOAConstraints(const std::string& idStr,
        const std::vector<std::string>& ConstraintStr, bool isAdd) = 0;
    virtual ErrCode UpdateGlobalOAConstraints(const std::string& idStr,
        const std::vector<std::string>& ConstraintStr, bool isAdd) = 0;
    virtual ErrCode UpdateSpecificOAConstraints(const std::string& idStr,
        const std::string& targetIdStr, const std::vector<std::string>& ConstraintStr, bool isAdd) = 0;
    virtual ErrCode GetDeviceOwnerId(int32_t &deviceOwnerId) = 0;
    virtual ErrCode UpdateDeviceOwnerId(const int32_t deviceOwnerId) = 0;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_IOS_ACCOUNT_CONTROL_H

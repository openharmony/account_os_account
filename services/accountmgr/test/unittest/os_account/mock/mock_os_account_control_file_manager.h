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
class MockOsAccountControlFileManager : public OsAccountControlFileManager {
public:
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
    MOCK_METHOD1(GetMaxCreatedOsAccountNum, ErrCode(int &maxCreatedOsAccountNum));
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
    MOCK_METHOD3(UpdateGlobalOAConstraints, ErrCode(const std::string& idStr,
        const std::vector<std::string>& ConstraintStr, bool isAdd));
};

}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CONTROL_FILE_MANAGER_H

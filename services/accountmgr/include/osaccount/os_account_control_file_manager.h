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
#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CONTROL_FILE_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CONTROL_FILE_MANAGER_H
#include <memory>
#include "ios_account_control.h"
#include "os_account_file_operator.h"
#include "os_account_photo_operator.h"
namespace OHOS {
namespace AccountSA {
class OsAccountControlFileManager : public IOsAccountControl {
public:
    OsAccountControlFileManager();
    virtual ~OsAccountControlFileManager();
    virtual void Init() override;
    virtual ErrCode GetOsAccountList(std::vector<OsAccountInfo> &osAccountList) override;
    virtual ErrCode GetOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo) override;
    virtual ErrCode GetConstraintsByType(const OsAccountType type, std::vector<std::string> &constratins) override;
    virtual ErrCode InsertOsAccount(OsAccountInfo &osAccountInfo) override;
    virtual ErrCode DelOsAccount(const int id) override;
    virtual ErrCode UpdateOsAccount(OsAccountInfo &osAccountInfo) override;
    virtual ErrCode GetMaxCreatedOsAccountNum(int &maxCreatedOsAccountNum) override;
    virtual ErrCode GetSerialNumber(int64_t &serialNumber) override;
    virtual ErrCode GetAllowCreateId(int &id) override;
    virtual ErrCode IsOsAccountExists(const int id, bool &isExists) override;
    virtual ErrCode GetPhotoById(const int id, std::string &photo) override;
    virtual ErrCode SetPhotoById(const int id, const std::string &photo) override;
    virtual ErrCode GetIsMultiOsAccountEnable(bool &isMultiOsAccountEnable) override;
    virtual ErrCode IsConstrarionsInTypeList(const std::vector<std::string> &constrains, bool &isExists) override;
    virtual ErrCode IsAllowedCreateAdmin(bool &isAllowedCreateAdmin) override;

private:
    ErrCode GetAccountList(Json &accountListJson);
    ErrCode SaveAccountList(const Json &accountListJson);

private:
    std::shared_ptr<AccountFileOperator> accountFileOperator_;
    std::shared_ptr<OsAccountFileOperator> osAccountFileOperator_;
    std::shared_ptr<OsAccountPhotoOperator> osAccountPhotoOperator_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif /* OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CONTROL_FILE_MANAGER_H */
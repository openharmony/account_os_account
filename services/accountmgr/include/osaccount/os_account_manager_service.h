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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_MANAGER_SERVICE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_MANAGER_SERVICE_H

#include <memory>
#include "account_permission_manager.h"
#include "os_account_stub.h"
#include "iinner_os_account.h"

namespace OHOS {
namespace AccountSA {
class OsAccountManagerService : public OsAccountStub {
public:
    OsAccountManagerService();
    ~OsAccountManagerService() override;

    ErrCode CreateOsAccount(
        const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo) override;
    ErrCode CreateOsAccountForDomain(
        const OsAccountType &type, const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo) override;
    ErrCode RemoveOsAccount(const int id) override;

    ErrCode IsOsAccountExists(const int id, bool &isOsAccountExists) override;
    ErrCode IsOsAccountActived(const int id, bool &isOsAccountActived) override;

    ErrCode IsOsAccountConstraintEnable(
        const int id, const std::string &constraint, bool &isConstraintEnable) override;
    ErrCode CheckOsAccountConstraintEnabled(
        const int id, const std::string &constraint, bool &isEnabled) override;
    ErrCode IsOsAccountVerified(const int id, bool &isVerified) override;

    ErrCode GetCreatedOsAccountsCount(unsigned int &osAccountsCount) override;
    ErrCode GetOsAccountLocalIdFromProcess(int &id) override;
    ErrCode IsMainOsAccount(bool &isMainOsAccount) override;

    ErrCode GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id) override;
    ErrCode QueryMaxOsAccountNumber(int &maxOsAccountNumber) override;

    ErrCode GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints) override;
    ErrCode QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos) override;

    ErrCode QueryCurrentOsAccount(OsAccountInfo &osAccountInfo) override;
    ErrCode QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo) override;

    ErrCode GetOsAccountTypeFromProcess(OsAccountType &type) override;
    ErrCode GetOsAccountProfilePhoto(const int id, std::string &photo) override;

    ErrCode IsMultiOsAccountEnable(bool &isMultiOsAccountEnable) override;
    ErrCode SetOsAccountName(const int id, const std::string &name) override;

    ErrCode SetOsAccountConstraints(
        const int id, const std::vector<std::string> &constraints, const bool enable) override;
    ErrCode SetOsAccountProfilePhoto(const int id, const std::string &photo) override;

    ErrCode ActivateOsAccount(const int id) override;

    ErrCode StartOsAccount(const int id) override;
    ErrCode StopOsAccount(const int id) override;

    ErrCode GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id) override;
    ErrCode GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber) override;

    ErrCode SubscribeOsAccount(
        const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener) override;
    ErrCode UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener) override;

    OS_ACCOUNT_SWITCH_MOD GetOsAccountSwitchMod() override;
    ErrCode IsCurrentOsAccountVerified(bool &isVerified) override;

    ErrCode IsOsAccountCompleted(const int id, bool &isOsAccountCompleted) override;
    ErrCode SetCurrentOsAccountIsVerified(const bool isVerified) override;
    ErrCode SetOsAccountIsVerified(const int id, const bool isVerified) override;
    ErrCode DumpState(const int &id, std::vector<std::string> &state) override;
    ErrCode DumpOsAccountInfo(std::vector<std::string> &state);

    void CreateBasicAccounts() override;
    ErrCode GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
        int &createdOsAccountNum) override;
    ErrCode GetSerialNumberFromDatabase(const std::string& storeID,
        int64_t &serialNumber) override;
    ErrCode GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id) override;
    ErrCode GetOsAccountFromDatabase(const std::string& storeID,
        const int id, OsAccountInfo &osAccountInfo) override;
    ErrCode GetOsAccountListFromDatabase(const std::string& storeID,
        std::vector<OsAccountInfo> &osAccountList) override;
    ErrCode QueryActiveOsAccountIds(std::vector<int32_t>& ids) override;

    ErrCode QueryOsAccountConstraintSourceTypes(const int32_t id,
        const std::string &constraint, std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos) override;
    ErrCode SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool enable, const int32_t enforcerId, const bool isDeviceOwner) override;
    ErrCode SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner) override;

private:
    virtual ErrCode DumpStateByAccounts(
        const std::vector<OsAccountInfo> &osAccountInfos, std::vector<std::string> &state);
    bool PermissionCheck(const std::string& permissionName, const std::string& constraintName);

private:
    std::shared_ptr<IInnerOsAccount> innerManager_;
    std::shared_ptr<AccountPermissionManager> permissionManagerPtr_;
    DISALLOW_COPY_AND_MOVE(OsAccountManagerService);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_MANAGER_SERVICE_H

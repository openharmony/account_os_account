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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_MANAGER_SERVICE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_MANAGER_SERVICE_H

#include <stdint.h>
#include <sys/types.h>
#include <memory>
#include "account_permission_manager.h"
#include "os_account_constraint_manager.h"
#include "os_account_stub.h"
#include "idomain_account_callback.h"
#include "iinner_os_account_manager.h"

namespace OHOS {
namespace AccountSA {
class OsAccountManagerService : public OsAccountStub {
public:
    OsAccountManagerService();
    ~OsAccountManagerService() override;

    ErrCode CreateOsAccount(
        const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo);
    ErrCode CreateOsAccount(const std::string &localName, const std::string &shortName,
        const OsAccountType &type, OsAccountInfo &osAccountInfo, const CreateOsAccountOptions &options = {});

    ErrCode CreateOsAccount(
        const std::string &name, int32_t typeValue, StringRawData& stringRawData) override;
    ErrCode CreateOsAccount(const std::string &localName, const std::string &shortName, int32_t typeValue,
        StringRawData& stringRawData) override;
    ErrCode CreateOsAccount(const std::string &localName, const std::string &shortName,
        int32_t typeValue, StringRawData& stringRawData, const CreateOsAccountOptions &options) override;
    ErrCode CreateOsAccountForDomain(const OsAccountType &type, const DomainAccountInfo &domainInfo,
        const sptr<IDomainAccountCallback> &callback, const CreateOsAccountForDomainOptions &options = {});
    ErrCode CreateOsAccountForDomain(int32_t typeValue, const DomainAccountInfo &domainInfo,
        const sptr<IDomainAccountCallback> &callback) override;
    ErrCode CreateOsAccountForDomain(int32_t typeValue, const DomainAccountInfo &domainInfo,
        const sptr<IDomainAccountCallback> &callback, const CreateOsAccountForDomainOptions &options) override;

    ErrCode CreateOsAccountWithFullInfo(const OsAccountInfo& osAccountInfo) override;
    ErrCode CreateOsAccountWithFullInfo(const OsAccountInfo& osAccountInfo,
        const CreateOsAccountOptions &options) override;
    ErrCode UpdateOsAccountWithFullInfo(const OsAccountInfo& osAccountInfo) override;

    ErrCode RemoveOsAccount(int32_t id) override;

    ErrCode IsOsAccountExists(int32_t id, bool &isOsAccountExists) override;
    ErrCode IsOsAccountActived(int32_t id, bool &isOsAccountActived) override;

    ErrCode IsOsAccountConstraintEnable(
        int32_t id, const std::string &constraint, bool &isConstraintEnable) override;
    ErrCode CheckOsAccountConstraintEnabled(
        int32_t id, const std::string &constraint, bool &isEnabled) override;
    ErrCode IsOsAccountVerified(int32_t id, bool &isVerified) override;
    ErrCode IsOsAccountDeactivating(int32_t id, bool &isDeactivating) override;

    ErrCode GetCreatedOsAccountsCount(unsigned int &osAccountsCount) override;
    ErrCode GetOsAccountLocalIdFromProcess(int &id) override;
    ErrCode IsMainOsAccount(bool &isMainOsAccount) override;
    ErrCode GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id) override;
    ErrCode QueryMaxOsAccountNumber(uint32_t &maxOsAccountNumber) override;
    ErrCode QueryMaxLoggedInOsAccountNumber(uint32_t &maxNum) override;

    ErrCode GetOsAccountAllConstraints(int32_t id, std::vector<std::string> &constraints) override;
    ErrCode QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos);
    ErrCode QueryAllCreatedOsAccounts(StringRawData& osAccountInfos) override;

    ErrCode QueryCurrentOsAccount(OsAccountInfo &osAccountInfo);
    ErrCode QueryCurrentOsAccount(StringRawData& stringRawData) override;
    ErrCode QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo);
    ErrCode QueryOsAccountById(int32_t id, StringRawData& stringRawData) override;

    ErrCode GetOsAccountTypeFromProcess(int32_t& typeValue) override;
    ErrCode GetOsAccountType(int32_t id, int32_t& typeValue) override;
    ErrCode GetOsAccountProfilePhoto(const int id, std::string &photo);
    ErrCode GetOsAccountProfilePhoto(int32_t id, StringRawData& stringRawData) override;

    ErrCode IsMultiOsAccountEnable(bool &isMultiOsAccountEnable) override;
    ErrCode SetOsAccountName(int32_t id, const std::string &name) override;

    ErrCode SetOsAccountConstraints(
        int32_t id, const std::vector<std::string> &constraints, bool enable) override;
    ErrCode SetOsAccountProfilePhoto(const int id, const std::string &photo);
    ErrCode SetOsAccountProfilePhoto(int32_t id, const StringRawData& stringRawData) override;

    ErrCode ActivateOsAccount(int32_t id) override;
    ErrCode ActivateOsAccount(int32_t id, const uint64_t displayId) override;
    ErrCode DeactivateOsAccount(int32_t id) override;
    ErrCode DeactivateAllOsAccounts() override;

    ErrCode StartOsAccount(int32_t id) override;

    ErrCode GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id) override;
    ErrCode GetSerialNumberByOsAccountLocalId(int32_t id, int64_t &serialNumber) override;

    ErrCode SubscribeOsAccount(
        const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener) override;
    ErrCode UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener) override;
    ErrCode GetOsAccountSwitchMod(int32_t &switchMod) override;
    ErrCode IsCurrentOsAccountVerified(bool &isVerified) override;

    ErrCode IsOsAccountCompleted(int32_t id, bool &isOsAccountCompleted) override;
    ErrCode SetCurrentOsAccountIsVerified(bool isVerified) override;
    ErrCode SetOsAccountIsVerified(int32_t id, bool isVerified) override;
    ErrCode DumpState(int32_t id, std::vector<std::string> &state) override;
    ErrCode DumpOsAccountInfo(std::vector<std::string> &state);

    ErrCode GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
        int &createdOsAccountNum) override;
    ErrCode GetSerialNumberFromDatabase(const std::string& storeID,
        int64_t &serialNumber) override;
    ErrCode GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id) override;
    ErrCode GetOsAccountFromDatabase(const std::string& storeID,
        const int id, OsAccountInfo &osAccountInfo);
    ErrCode GetOsAccountFromDatabase(const std::string& storeID,
        int32_t id, StringRawData& stringRawData) override;
    ErrCode GetOsAccountListFromDatabase(const std::string& storeID,
        std::vector<OsAccountInfo> &osAccountList);
    ErrCode GetOsAccountListFromDatabase(const std::string& storeID,
        StringRawData& osAccountInfos) override;
    ErrCode QueryActiveOsAccountIds(std::vector<int32_t>& ids) override;
    ErrCode GetUnlockedOsAccountLocalIds(std::vector<int32_t>& ids) override;
    ErrCode QueryOsAccountConstraintSourceTypes(int32_t id,
        const std::string &constraint, std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos) override;
    ErrCode SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
        bool enable, int32_t enforcerId, bool isDeviceOwner) override;
    ErrCode SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
        bool enable, int32_t targetId, int32_t enforcerId, bool isDeviceOwner) override;
    ErrCode SubscribeOsAccountConstraints(const OsAccountConstraintSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &eventListener) override;
    ErrCode UnsubscribeOsAccountConstraints(const OsAccountConstraintSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &eventListener) override;

    ErrCode SetDefaultActivatedOsAccount(int32_t id) override;
    ErrCode SetDefaultActivatedOsAccount(const uint64_t displayId, int32_t id) override;
    ErrCode GetDefaultActivatedOsAccount(int32_t &id) override;
    ErrCode GetDefaultActivatedOsAccount(const uint64_t displayId, int32_t &id) override;
    ErrCode GetAllDefaultActivatedOsAccounts(std::map<uint64_t, int32_t> &activatedIds);
    ErrCode GetOsAccountShortName(std::string &shortName) override;
    ErrCode GetOsAccountName(std::string &name) override;
    ErrCode GetOsAccountNameById(int32_t id, std::string &name) override;
    ErrCode GetOsAccountShortNameById(int32_t id, std::string &shortName) override;

    ErrCode IsOsAccountForeground(int32_t localId, const uint64_t displayId, bool &isForeground) override;
    ErrCode GetForegroundOsAccountLocalId(int32_t &localId) override;
    ErrCode GetForegroundOsAccountLocalId(const uint64_t displayId, int32_t &localId) override;
    ErrCode GetForegroundOsAccountDisplayId(const int32_t localId, uint64_t &displayId) override;
    ErrCode GetForegroundOsAccounts(std::vector<ForegroundOsAccount> &accounts) override;
    ErrCode GetBackgroundOsAccountLocalIds(std::vector<int32_t> &localIds) override;
    ErrCode SetOsAccountToBeRemoved(int32_t localId, bool toBeRemoved) override;
    ErrCode GetOsAccountDomainInfo(int32_t localId, DomainAccountInfo &domainInfo) override;
#ifdef SUPPORT_LOCK_OS_ACCOUNT
    ErrCode PublishOsAccountLockEvent(const int32_t localId, bool isLocking) override;
    ErrCode LockOsAccount(const int32_t localId) override;
#endif
    ErrCode BindDomainAccount(const int32_t localId, const DomainAccountInfo &domainInfo,
        const sptr<IDomainAccountCallback> &callback) override;
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    ErrCode GetServerConfigInfo(OsAccountInfo &osAccountInfo);
#endif // SUPPORT_DOMAIN_ACCOUNTS
    ErrCode CallbackEnter([[maybe_unused]] uint32_t code) override;
    ErrCode CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    virtual ErrCode DumpStateByAccounts(
        const std::vector<OsAccountInfo> &osAccountInfos, std::vector<std::string> &state);
    bool PermissionCheck(const std::string& permissionName, const std::string& constraintName);
    bool CheckCreateOsAccountWhiteList();
    ErrCode ValidateShortName(const std::string &shortName);
    void GetCurrentLocalId(int32_t &localId);
    ErrCode GetOsAccountShortNameCommon(const int32_t id, std::string &shortName);
    ErrCode ValidateAccountCreateParamAndPermission(const std::string &localName, const OsAccountType &type);
    void ConstraintPublish(const std::vector<std::string> &oldConstraints,
        const std::vector<std::string> &constraints, int32_t localId, bool enable);
    ErrCode CheckLocalIdRestricted(int32_t localId);
    ErrCode ActivateOsAccountCommon(const int32_t id, const uint64_t displayId);

private:
    IInnerOsAccountManager &innerManager_;
    OsAccountConstraintManager &constraintManger_;
    DISALLOW_COPY_AND_MOVE(OsAccountManagerService);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_MANAGER_SERVICE_H

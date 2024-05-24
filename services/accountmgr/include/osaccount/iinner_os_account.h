/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_IINNER_OS_ACCOUNT_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_IINNER_OS_ACCOUNT_H

#include <string>
#include "account_error_no.h"
#include "idomain_account_callback.h"
#include "os_account_info.h"
#include "iremote_object.h"
#include "os_account_subscribe_info.h"

namespace OHOS {
namespace AccountSA {
class IInnerOsAccount {
public:
    virtual void Init() = 0;
    virtual ErrCode CreateOsAccount(
        const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo) = 0;
    virtual ErrCode CreateOsAccount(const std::string &localName, const std::string &shortName,
        const OsAccountType &type, OsAccountInfo &osAccountInfo, const CreateOsAccountOptions &options = {}) = 0;
    virtual ErrCode CreateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo) = 0;
    virtual ErrCode UpdateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo) = 0;
    virtual ErrCode CreateOsAccountForDomain(const OsAccountType &type, const DomainAccountInfo &domainInfo,
        const sptr<IDomainAccountCallback> &callback, const CreateOsAccountForDomainOptions &options = {}) = 0;
    virtual ErrCode RemoveOsAccount(const int id) = 0;
    virtual ErrCode IsOsAccountExists(const int id, bool &isOsAccountExits) = 0;
    virtual ErrCode IsOsAccountActived(const int id, bool &isOsAccountActived) = 0;
    virtual ErrCode IsOsAccountConstraintEnable(
        const int id, const std::string &constraint, bool &isOsAccountConstraintEnable) = 0;
    virtual ErrCode IsOsAccountVerified(const int id, bool &isVerified) = 0;
    virtual ErrCode GetCreatedOsAccountsCount(unsigned int &createdOsAccountCount) = 0;
    virtual ErrCode QueryMaxOsAccountNumber(uint32_t &maxOsAccountNumber) = 0;
    virtual ErrCode QueryMaxLoggedInOsAccountNumber(uint32_t &maxNum) = 0;
    virtual ErrCode GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints) = 0;
    virtual ErrCode QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos) = 0;
    virtual ErrCode QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo) = 0;
    virtual ErrCode GetOsAccountShortName(const int id, std::string &shortName) = 0;
    virtual ErrCode GetOsAccountName(const int id, std::string &name) = 0;
    virtual ErrCode GetOsAccountType(const int id, OsAccountType &type) = 0;
    virtual ErrCode GetOsAccountProfilePhoto(const int id, std::string &photo) = 0;
    virtual ErrCode IsMultiOsAccountEnable(bool &isMultiOsAccountEnable) = 0;
    virtual ErrCode SetOsAccountName(const int id, const std::string &name) = 0;
    virtual ErrCode SetOsAccountConstraints(
        const int id, const std::vector<std::string> &constraints, const bool enable) = 0;
    virtual ErrCode SetOsAccountProfilePhoto(const int id, const std::string &photo) = 0;
    virtual ErrCode ActivateOsAccount(const int id, const bool startStorage = true, const uint64_t displayId = 0) = 0;
    virtual ErrCode DeactivateOsAccount(const int id) = 0;
    virtual ErrCode StartOsAccount(const int id) = 0;
    virtual ErrCode GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id) = 0;
    virtual ErrCode GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber) = 0;
    virtual ErrCode SubscribeOsAccount(
        const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener) = 0;
    virtual ErrCode UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener) = 0;
    virtual const std::shared_ptr<OsAccountSubscribeInfo> GetSubscribeRecordInfo(
        const sptr<IRemoteObject> &eventListener) = 0;
    virtual OS_ACCOUNT_SWITCH_MOD GetOsAccountSwitchMod() = 0;
    virtual ErrCode IsOsAccountCompleted(const int id, bool &isOsAccountCompleted) = 0;
    virtual ErrCode SetOsAccountIsVerified(const int id, const bool isVerified) = 0;
    virtual ErrCode SetOsAccountIsLoggedIn(const int32_t id, const bool isLoggedIn) = 0;
    virtual ErrCode GetOsAccountCredentialId(const int id, uint64_t &credentialId) = 0;
    virtual ErrCode SetOsAccountCredentialId(const int id, uint64_t credentialId) = 0;
    virtual ErrCode IsAllowedCreateAdmin(bool &isAllowedCreateAdmin) = 0;
    virtual ErrCode GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id) = 0;
    virtual ErrCode GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
        int &createdOsAccountNum) = 0;
    virtual ErrCode GetSerialNumberFromDatabase(const std::string& storeID, int64_t &serialNumber) = 0;
    virtual ErrCode GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id) = 0;
    virtual ErrCode GetOsAccountFromDatabase(const std::string& storeID, const int id,
        OsAccountInfo &osAccountInfo) = 0;
    virtual ErrCode GetOsAccountListFromDatabase(const std::string& storeID,
        std::vector<OsAccountInfo> &osAccountList) = 0;
    virtual ErrCode QueryActiveOsAccountIds(std::vector<int32_t>& ids) = 0;
    virtual ErrCode QueryOsAccountConstraintSourceTypes(const int32_t id,
        const std::string &constraint, std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos) = 0;
    virtual ErrCode SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool enable, const int32_t enforcerId, const bool isDeviceOwner) = 0;
    virtual ErrCode SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner) = 0;
    virtual ErrCode SetBaseOsAccountConstraints(const int32_t id,
        const std::vector<std::string> &constraints, const bool enable) = 0;
    virtual ErrCode SetDefaultActivatedOsAccount(const int32_t id) = 0;
    virtual ErrCode GetDefaultActivatedOsAccount(int32_t &id) = 0;
    virtual ErrCode ValidateShortName(const std::string &shortName) = 0;
    virtual ErrCode GetTypeNumber(const OsAccountType& type, int32_t& typeNumber) = 0;
    virtual ErrCode CheckTypeNumber(const OsAccountType& type) = 0;
    virtual ErrCode IsOsAccountForeground(const int32_t localId, const uint64_t displayId, bool &isForeground) = 0;
    virtual ErrCode GetForegroundOsAccountLocalId(const uint64_t displayId, int32_t &localId) = 0;
    virtual ErrCode GetForegroundOsAccounts(std::vector<ForegroundOsAccount> &accounts) = 0;
    virtual ErrCode GetBackgroundOsAccountLocalIds(std::vector<int32_t> &localIds) = 0;
    virtual ErrCode SetOsAccountToBeRemoved(int32_t localId, bool toBeRemoved) = 0;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_IINNER_OS_ACCOUNT_H

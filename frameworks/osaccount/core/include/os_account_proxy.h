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

#ifndef OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_PROXY_H
#define OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_PROXY_H

#include "ios_account.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AccountSA {
class OsAccountProxy : public IRemoteProxy<IOsAccount> {
public:
    explicit OsAccountProxy(const sptr<IRemoteObject> &object);
    ~OsAccountProxy() override;

    ErrCode CreateOsAccount(
        const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo) override;
    ErrCode CreateOsAccount(const std::string &localName, const std::string &shortName, const OsAccountType &type,
        OsAccountInfo &osAccountInfo, const CreateOsAccountOptions &options = {}) override;
    ErrCode CreateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo,
        const CreateOsAccountOptions &options = {}) override;
    ErrCode UpdateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo) override;
    ErrCode CreateOsAccountForDomain(const OsAccountType &type, const DomainAccountInfo &domainInfo,
        const sptr<IDomainAccountCallback> &callback, const CreateOsAccountForDomainOptions& options) override;
    ErrCode RemoveOsAccount(const int id) override;
    ErrCode IsOsAccountExists(const int id, bool &isOsAccountExists) override;
    ErrCode IsOsAccountActived(const int id, bool &isOsAccountActived) override;
    ErrCode IsOsAccountConstraintEnable(
        const int id, const std::string &constraint, bool &isConstraintEnable) override;
    ErrCode CheckOsAccountConstraintEnabled(
        const int id, const std::string &constraint, bool &isEnabled) override;
    ErrCode IsOsAccountVerified(const int id, bool &isVerified) override;
    ErrCode IsOsAccountDeactivating(const int id, bool &isDeactivating) override;
    ErrCode GetCreatedOsAccountsCount(unsigned int &osAccountsCount) override;
    ErrCode GetOsAccountLocalIdFromProcess(int &id) override;
    ErrCode IsMainOsAccount(bool &isMainOsAccount) override;
    ErrCode GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id) override;
    ErrCode QueryMaxOsAccountNumber(uint32_t &maxOsAccountNumber) override;
    ErrCode QueryMaxLoggedInOsAccountNumber(uint32_t &maxNum) override;
    ErrCode GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints) override;
    ErrCode QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos) override;
    ErrCode QueryCurrentOsAccount(OsAccountInfo &osAccountInfo) override;
    ErrCode QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo) override;
    ErrCode GetOsAccountTypeFromProcess(OsAccountType &type) override;
    ErrCode GetOsAccountType(const int id, OsAccountType& type) override;
    ErrCode GetOsAccountProfilePhoto(const int id, std::string &photo) override;
    ErrCode IsMultiOsAccountEnable(bool &isMultiOsAccountEnable) override;
    ErrCode SetOsAccountName(const int id, const std::string &localName) override;
    ErrCode SetOsAccountConstraints(
        const int id, const std::vector<std::string> &constraints, const bool enable) override;
    ErrCode SetOsAccountProfilePhoto(const int id, const std::string &photo) override;
    ErrCode ActivateOsAccount(const int id) override;
    ErrCode DeactivateOsAccount(const int id) override;
    ErrCode DeactivateAllOsAccounts() override;
    ErrCode StartOsAccount(const int id) override;
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

    ErrCode GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
        int &createdOsAccountNum) override;
    ErrCode GetSerialNumberFromDatabase(const std::string& storeID, int64_t &serialNumber) override;
    ErrCode GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id) override;
    ErrCode GetOsAccountFromDatabase(const std::string& storeID, const int id,
        OsAccountInfo &osAccountInfo) override;
    ErrCode GetOsAccountListFromDatabase(const std::string& storeID,
        std::vector<OsAccountInfo> &osAccountList) override;
    ErrCode QueryActiveOsAccountIds(std::vector<int32_t>& ids) override;
    ErrCode QueryOsAccountConstraintSourceTypes(const int32_t id,
        const std::string &constraint, std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos) override;
    ErrCode SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool enable, const int32_t enforcerId, const bool isDeviceOwner) override;
    ErrCode SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner) override;
    ErrCode SetDefaultActivatedOsAccount(const int32_t id) override;
    ErrCode GetDefaultActivatedOsAccount(int32_t &id) override;
    ErrCode GetOsAccountShortName(std::string &shortName) override;
    ErrCode GetOsAccountName(std::string &name) override;
    ErrCode GetOsAccountNameById(int32_t id, std::string &name) override;
    ErrCode GetOsAccountShortNameById(const int32_t id, std::string &shortName) override;
    ErrCode IsOsAccountForeground(const int32_t localId, const uint64_t displayId, bool &isForeground) override;
    ErrCode GetForegroundOsAccountLocalId(const uint64_t displayId, int32_t &localId) override;
    ErrCode GetForegroundOsAccounts(std::vector<ForegroundOsAccount> &accounts) override;
    ErrCode GetBackgroundOsAccountLocalIds(std::vector<int32_t> &localIds) override;
    ErrCode SetOsAccountToBeRemoved(int32_t localId, bool toBeRemoved) override;
    ErrCode GetOsAccountDomainInfo(const int32_t localId, DomainAccountInfo &domainInfo) override;
#ifdef SUPPORT_LOCK_OS_ACCOUNT
    ErrCode PublishOsAccountLockEvent(const int32_t localId, bool isLocking) override;
    ErrCode LockOsAccount(const int32_t localId) override;
#endif

private:
    bool ReadOsAccountInfoList(MessageParcel &data, std::vector<OsAccountInfo> &parcelableInfos);
    bool ReadOsAccountInfo(MessageParcel &data, OsAccountInfo &accountInfo);
    ErrCode SendRequest(OsAccountInterfaceCode code, MessageParcel &data, MessageParcel &reply);
    ErrCode CheckOsAccountConstraintEnabled(
        OsAccountInterfaceCode code, const int id, const std::string &constraint, bool &isConstraintEnable);
    ErrCode SendRequestWithAccountId(OsAccountInterfaceCode code, MessageParcel &reply, int id);
private:
    static inline BrokerDelegator<OsAccountProxy> delegator_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_PROXY_H

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

#ifndef OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_H
#define OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_H

#include "domain_account_callback.h"
#include "ios_account.h"
#include "os_account_event_listener.h"

namespace OHOS {
namespace AccountSA {
class OsAccount {
public:
    enum SubscribeState { ALREADY_SUBSCRIBED = 0, INITIAL_SUBSCRIPTION, SUBSCRIBE_FAILED };
    static OsAccount &GetInstance();
    ErrCode CreateOsAccount(const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo);
    ErrCode CreateOsAccount(const std::string &localName, const std::string &shortName, const OsAccountType &type,
        OsAccountInfo &osAccountInfo, const CreateOsAccountOptions &options = {});
    ErrCode CreateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo);
    ErrCode UpdateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo);
    ErrCode CreateOsAccountForDomain(const OsAccountType &type, const DomainAccountInfo &domainInfo,
        const std::shared_ptr<DomainAccountCallback> &callback, const CreateOsAccountForDomainOptions& options = {});
    ErrCode RemoveOsAccount(const int id);
    ErrCode IsOsAccountExists(const int id, bool &isOsAccountExists);
    ErrCode IsOsAccountActived(const int id, bool &isOsAccountActived);
    ErrCode IsOsAccountConstraintEnable(const int id, const std::string &constraint, bool &isConstraintEnable);
    ErrCode CheckOsAccountConstraintEnabled(const int id, const std::string &constraint, bool &isEnabled);
    ErrCode IsOsAccountVerified(const int id, bool &isVerified);
    ErrCode GetCreatedOsAccountsCount(unsigned int &osAccountsCount);
    ErrCode GetOsAccountLocalIdFromProcess(int &id);
    ErrCode IsMainOsAccount(bool &isMainOsAccount);
    ErrCode GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id);
    ErrCode QueryMaxOsAccountNumber(uint32_t &maxOsAccountNumber);
    ErrCode QueryMaxLoggedInOsAccountNumber(uint32_t &maxNum);
    ErrCode GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints);
    ErrCode QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos);
    ErrCode QueryCurrentOsAccount(OsAccountInfo &osAccountInfo);
    ErrCode QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo);
    ErrCode GetOsAccountTypeFromProcess(OsAccountType &type);
    ErrCode GetOsAccountType(const int id, OsAccountType& type);
    ErrCode GetOsAccountProfilePhoto(const int id, std::string &photo);
    ErrCode IsMultiOsAccountEnable(bool &isMultiOsAccountEnable);
    ErrCode SetOsAccountName(const int id, const std::string &localName);
    ErrCode SetOsAccountConstraints(const int id, const std::vector<std::string> &constraints, const bool enable);
    ErrCode SetOsAccountProfilePhoto(const int id, const std::string &photo);
    ErrCode GetDistributedVirtualDeviceId(std::string &deviceId);
    ErrCode ActivateOsAccount(const int id);
    ErrCode DeactivateOsAccount(const int id);
    ErrCode DeactivateAllOsAccounts();
    ErrCode StartOsAccount(const int id);
    ErrCode SubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber);
    ErrCode UnsubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber);
    ErrCode GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id);
    ErrCode GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber);
    OS_ACCOUNT_SWITCH_MOD GetOsAccountSwitchMod();
    ErrCode IsCurrentOsAccountVerified(bool &isVerified);
    ErrCode IsOsAccountCompleted(const int id, bool &isOsAccountCompleted);
    ErrCode SetCurrentOsAccountIsVerified(const bool isVerified);
    ErrCode SetOsAccountIsVerified(const int id, const bool isVerified);
    ErrCode DumpState(const int &id, std::vector<std::string> &state);
    ErrCode ResetOsAccountProxy();

    ErrCode GetCreatedOsAccountNumFromDatabase(const std::string& storeID, int &createdOsAccountNum);
    ErrCode GetSerialNumberFromDatabase(const std::string& storeID, int64_t &serialNumber);
    ErrCode GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id);
    ErrCode GetOsAccountFromDatabase(const std::string& storeID, const int id,
        OsAccountInfo &osAccountInfo);
    ErrCode GetOsAccountListFromDatabase(const std::string& storeID,
        std::vector<OsAccountInfo> &osAccountList);
    ErrCode QueryActiveOsAccountIds(std::vector<int32_t>& ids);
    ErrCode QueryOsAccountConstraintSourceTypes(const int32_t id, const std::string &constraint,
        std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos);
    ErrCode SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool enable, const int32_t enforcerId, const bool isDeviceOwner);
    ErrCode SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner);
    ErrCode SetDefaultActivatedOsAccount(const int32_t id);
    ErrCode GetDefaultActivatedOsAccount(int32_t &id);
    ErrCode GetOsAccountShortName(std::string &shortName);
    ErrCode GetOsAccountName(std::string &name);
    ErrCode GetOsAccountShortNameById(const int32_t id, std::string &shortName);

    ErrCode IsOsAccountForeground(bool &isForeground);
    ErrCode IsOsAccountForeground(const int32_t localId, bool &isForeground);
    ErrCode IsOsAccountForeground(const int32_t localId, const uint64_t displayId, bool &isForeground);
    ErrCode GetForegroundOsAccountLocalId(int32_t &localId);
    ErrCode GetForegroundOsAccountLocalId(const uint64_t displayId, int32_t &localId);
    ErrCode GetForegroundOsAccounts(std::vector<ForegroundOsAccount> &accounts);
    ErrCode GetBackgroundOsAccountLocalIds(std::vector<int32_t> &localIds);
    ErrCode SetOsAccountToBeRemoved(int32_t localId, bool toBeRemoved);

private:
    OsAccount() = default;
    ~OsAccount() = default;
    DISALLOW_COPY_AND_MOVE(OsAccount);
    sptr<IOsAccount> GetOsAccountProxy();
    ErrCode CreateOsAccountEventListener(
        const std::shared_ptr<OsAccountSubscriber> &subscriber, sptr<IRemoteObject> &osAccountEventListener);
    ErrCode IsOsAccountForegroundCommon(int32_t localId, uint64_t displayId, bool &isForeground);
    ErrCode GetForegroundLocalIdCommon(uint64_t displayId, int32_t &localId);

private:
    std::mutex mutex_;
    sptr<IOsAccount> proxy_;
    std::mutex eventListenersMutex_;
    std::map<std::shared_ptr<OsAccountSubscriber>, sptr<OsAccountEventListener>> eventListeners_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_H

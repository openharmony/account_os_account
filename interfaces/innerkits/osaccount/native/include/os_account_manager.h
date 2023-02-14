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
#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_MANAGER_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_MANAGER_H

#include <string>
#include <vector>
#include "os_account_info.h"
#include "os_account_subscriber.h"
#include "account_error_no.h"
namespace OHOS {
namespace AccountSA {
class OsAccountManager {
public:
    static ErrCode CreateOsAccount(const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo);
    static ErrCode CreateOsAccountForDomain(
        const OsAccountType &type, const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo);
    static ErrCode RemoveOsAccount(const int id);
    static ErrCode IsOsAccountExists(const int id, bool &isOsAccountExists);
    static ErrCode IsOsAccountActived(const int id, bool &isOsAccountActived);
    static ErrCode IsOsAccountConstraintEnable(const int id, const std::string &constraint, bool &isConstraintEnable);
    static ErrCode CheckOsAccountConstraintEnabled(
        const int id, const std::string &constraint, bool &isEnabled);
    static ErrCode IsOsAccountVerified(const int id, bool &isVerified);
    static ErrCode GetCreatedOsAccountsCount(unsigned int &osAccountsCount);
    static ErrCode GetOsAccountLocalIdFromProcess(int &id);
    static ErrCode IsMainOsAccount(bool &isMainOsAccount);
    static ErrCode GetOsAccountLocalIdFromUid(const int uid, int &id);
    static ErrCode GetBundleIdFromUid(const int uid, int &bundleId);
    static ErrCode GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id);
    static ErrCode QueryMaxOsAccountNumber(int &maxOsAccountNumber);
    static ErrCode GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints);
    static ErrCode QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos);
    static ErrCode QueryCurrentOsAccount(OsAccountInfo &osAccountInfo);
    static ErrCode QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo);
    static ErrCode GetOsAccountTypeFromProcess(OsAccountType &type);
    static ErrCode GetOsAccountProfilePhoto(const int id, std::string &photo);
    static ErrCode IsMultiOsAccountEnable(bool &isMultiOsAccountEnable);
    static ErrCode SetOsAccountName(const int id, const std::string &localName);
    static ErrCode SetOsAccountConstraints(
        const int id, const std::vector<std::string> &constraints, const bool enable);
    static ErrCode SetOsAccountProfilePhoto(const int id, const std::string &photo);
    static ErrCode GetDistributedVirtualDeviceId(std::string &deviceId);
    static ErrCode ActivateOsAccount(const int id);
    static ErrCode StartOsAccount(const int id);
    static ErrCode StopOsAccount(const int id);
    static ErrCode GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id);
    static ErrCode GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber);
    static ErrCode SubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber);
    static ErrCode UnsubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber);
    static OS_ACCOUNT_SWITCH_MOD GetOsAccountSwitchMod();
    static ErrCode IsCurrentOsAccountVerified(bool &isVerified);
    static ErrCode IsOsAccountCompleted(const int id, bool &isOsAccountCompleted);
    static ErrCode SetCurrentOsAccountIsVerified(const bool isVerified);
    static ErrCode SetOsAccountIsVerified(const int id, const bool isVerified);

    static ErrCode GetCreatedOsAccountNumFromDatabase(const std::string& storeID, int &createdOsAccountNum);
    static ErrCode GetSerialNumberFromDatabase(const std::string& storeID, int64_t &serialNumber);
    static ErrCode GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id);
    static ErrCode GetOsAccountFromDatabase(const std::string& storeID,
                                            const int id,
                                            OsAccountInfo &osAccountInfo);
    static ErrCode GetOsAccountListFromDatabase(const std::string& storeID,
                                                std::vector<OsAccountInfo> &osAccountList);
    static ErrCode QueryActiveOsAccountIds(std::vector<int32_t>& ids);
    static ErrCode QueryOsAccountConstraintSourceTypes(const int32_t id, const std::string constraint,
        std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos);
    static ErrCode SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool isEnabled, const int32_t enforcerId = 0, const bool isDeviceOwner = false);
    static ErrCode SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner);
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_MANAGER_H

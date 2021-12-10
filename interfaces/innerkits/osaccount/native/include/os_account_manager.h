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
    static ErrCode CreateOsAccount(
        const std::string &name, const int &type, OsAccountInfo &osAccountInfo);
    static ErrCode RemoveOsAccount(const int id);
    static ErrCode IsOsAccountExists(const int id, bool &isOsAccountExists);
    static ErrCode IsOsAccountActived(const int id, bool &isOsAccountActived);
    static ErrCode IsOsAccountConstraintEnable(const int id, const std::string constraint, bool &isConstraintEnable);
    static ErrCode IsOsAccountVerified(const int id, bool &isOsAccountVerified);
    static ErrCode GetCreatedOsAccountsCount(int &osAccountsCount);
    static ErrCode GetOsAccountLocalIdFromProcess(int &id);
    static ErrCode GetOsAccountLocalIdFromUid(const int uid, int &id);
    static ErrCode QueryMaxOsAccountNumber(int &maxOsAccountNumber);
    static ErrCode GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints);
    static ErrCode QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos);
    static ErrCode QueryCurrentOsAccount(OsAccountInfo &osAccountInfos);
    static ErrCode QueryOsAccountById(const int id, OsAccountInfo &osAccountInfos);
    static ErrCode GetOsAccountTypeFromProcess(int &type);
    static ErrCode GetOsAccountProfilePhoto(const int id, std::string &photo);
    static ErrCode IsMultiOsAccountEnable(bool &isMultiOsAccountEnable);
    static ErrCode SetOsAccountName(const int id, const std::string &localName);
    static ErrCode SetOsAccountConstraints(
        const int id, const std::vector<std::string> &constraints, const bool enable);
    static ErrCode SetOsAccountProfilePhoto(const int id, const std::string &photo);
    static ErrCode GetDistributedVirtualDeviceId(std::int32_t &deviceId);
    static ErrCode ActivateOsAccount(const int id);
    static ErrCode StartOsAccount(const int id);
    static ErrCode StopOsAccount(const int id);
    static ErrCode GetOsAccountLocalIdForSerialNumber(const int64_t serialNumber, int &id);
    static ErrCode GetSerialNumberForOsAccount(const int &id, int64_t &serialNumber);
    static ErrCode SubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber);
    static ErrCode UnsubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber);
    static OS_ACCOUNT_SWITCH_MOD GetOsAccountSwitchMod();
    static ErrCode IsCurrentOsAccountVerified(bool &isOsAccountVerified);
    static ErrCode IsOsAccountCompleted(const int id, bool &isOsAccountCompleted);
    static ErrCode SetCurrentOsAccountIsVerified(const bool isOsAccountVerified);
    static ErrCode SetOsAccountIsVerified(const int id, const bool isOsAccountVerified);
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_MANAGER_H

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
#ifndef OS_ACCOUNT_FRAMEWORK_OSACCOUNT_CORE_INCLUDE_IOS_ACCOUNT_H
#define OS_ACCOUNT_FRAMEWORK_OSACCOUNT_CORE_INCLUDE_IOS_ACCOUNT_H
#include <string>
#include "iremote_broker.h"
#include "iremote_object.h"
#include "os_account_info.h"
#include "account_error_no.h"
#include "os_account_constants.h"
#include "os_account_event_listener.h"
namespace OHOS {
namespace AccountSA {
class IOsAccount : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IOsAccount");

    virtual ErrCode CreateOsAccount(
        const std::string &name, const int &type, OsAccountInfo &osAccountInfo) = 0;
    virtual ErrCode RemoveOsAccount(const int id) = 0;
    virtual ErrCode IsOsAccountExists(const int id, bool &isOsAccountExists) = 0;
    virtual ErrCode IsOsAccountActived(const int id, bool &isOsAccountActived) = 0;
    virtual ErrCode IsOsAccountConstraintEnable(
        const int id, const std::string &constraint, bool &isConstraintEnable) = 0;
    virtual ErrCode IsOsAccountVerified(const int id, bool &isOsAccountVerified) = 0;
    virtual ErrCode GetCreatedOsAccountsCount(int &osAccountsCount) = 0;
    virtual ErrCode GetOsAccountLocalIdFromProcess(int &id) = 0;
    virtual ErrCode GetOsAccountLocalIdFromUid(const int uid, int &id) = 0;
    virtual ErrCode QueryMaxOsAccountNumber(int &maxOsAccountNumber) = 0;
    virtual ErrCode GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints) = 0;
    virtual ErrCode QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos) = 0;
    virtual ErrCode QueryCurrentOsAccount(OsAccountInfo &osAccountInfo) = 0;
    virtual ErrCode QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo) = 0;
    virtual ErrCode GetOsAccountTypeFromProcess(int &type) = 0;
    virtual ErrCode GetOsAccountProfilePhoto(const int id, std::string &photo) = 0;
    virtual ErrCode IsMultiOsAccountEnable(bool &isMultiOsAccountEnable) = 0;
    virtual ErrCode SetOsAccountName(const int id, const std::string &localName) = 0;
    virtual ErrCode SetOsAccountConstraints(
        const int id, const std::vector<std::string> &constraints, const bool enable) = 0;
    virtual ErrCode SetOsAccountProfilePhoto(const int id, const std::string &photo) = 0;
    virtual ErrCode GetDistributedVirtualDeviceId(std::int32_t &deviceId) = 0;
    virtual ErrCode ActivateOsAccount(const int id) = 0;
    virtual ErrCode StartOsAccount(const int id) = 0;
    virtual ErrCode StopOsAccount(const int id) = 0;
    virtual ErrCode GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id) = 0;
    virtual ErrCode GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber) = 0;
    virtual ErrCode SubscribeOsAccount(
        const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener) = 0;
    virtual ErrCode UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener) = 0;
    virtual OS_ACCOUNT_SWITCH_MOD GetOsAccountSwitchMod() = 0;
    virtual ErrCode IsCurrentOsAccountVerified(bool &isOsAccountVerified) = 0;
    virtual ErrCode IsOsAccountCompleted(const int id, bool &isOsAccountCompleted) = 0;
    virtual ErrCode SetCurrentOsAccountIsVerified(const bool isOsAccountVerified) = 0;
    virtual ErrCode SetOsAccountIsVerified(const int id, const bool isOsAccountVerified) = 0;
    enum class Message {
        CREATE_OS_ACCOUNT = 0,
        REMOVE_OS_ACCOUNT,
        IS_OS_ACCOUNT_EXISTS,
        IS_OS_ACCOUNT_ACTIVED,
        IS_OS_ACCOUNT_CONSTRAINT_ENABLE,
        IS_OS_ACCOUNT_VERIFIED,
        GET_CREATED_OS_ACCOUNT_COUNT,
        GET_OS_ACCOUNT_LOCAL_ID_FROM_PROCESS,
        GET_OS_ACCOUNT_LOCAL_ID_FROM_UID,
        QUERY_MAX_OS_ACCOUNT_NUMBER,
        GET_OS_ACCOUNT_ALL_CONSTRAINTS,
        QUERY_ALL_CREATED_OS_ACCOUNTS,
        QUERY_CURRENT_OS_ACCOUNT,
        QUERY_OS_ACCOUNT_BY_ID,
        GET_OS_ACCOUNT_TYPE_FROM_PROCESS,
        GET_OS_ACCOUNT_PROFILE_PHOTO,
        IS_MULTI_OS_ACCOUNT_ENABLE,
        SET_OS_ACCOUNT_NAME,
        SET_OS_ACCOUNT_CONSTRAINTS,
        SET_OS_ACCOUNT_PROFILE_PHOTO,
        GET_DISTRIBUTED_VIRTUAL_DEVICE_ID,
        ACTIVATE_OS_ACCOUNT,
        START_OS_ACCOUNT,
        STOP_OS_ACCOUNT,
        SUBSCRIBE_ACCOUNT,
        UNSUBSCRIBE_ACCOUNT,
        GET_OS_ACCOUNT_LOCAL_ID_FOR_SERIAL_NUMBER,
        GET_SERIAL_NUMBER_FOR_OS_ACCOUNT,
        GET_OS_ACCOUNT_SWITCH_MOD,
        IS_CURRENT_OS_ACCOUNT_VERIFIED,
        IS_OS_ACCOUNT_COMPLETED,
        SET_CURRENT_OS_ACCOUNT_IS_VERIFIED,
        SET_OS_ACCOUNT_IS_VERIFIED,
    };
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_FRAMEWORK_OSACCOUNT_CORE_INCLUDE_IOS_ACCOUNT_H

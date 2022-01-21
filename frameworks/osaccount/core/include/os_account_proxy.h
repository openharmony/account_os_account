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
#ifndef OS_ACCOUNT_FRAMEWORK_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_PROXY_H
#define OS_ACCOUNT_FRAMEWORK_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_PROXY_H
#include "ios_account.h"
#include "iremote_proxy.h"
namespace OHOS {
namespace AccountSA {
class OsAccountProxy : public IRemoteProxy<IOsAccount> {
public:
    explicit OsAccountProxy(const sptr<IRemoteObject> &object);
    virtual ~OsAccountProxy() override;

    virtual ErrCode CreateOsAccount(
        const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo) override;
    virtual ErrCode CreateOsAccountForDomain(
        const OsAccountType &type, const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo) override;
    virtual ErrCode RemoveOsAccount(const int id) override;
    virtual ErrCode IsOsAccountExists(const int id, bool &isOsAccountExists) override;
    virtual ErrCode IsOsAccountActived(const int id, bool &isOsAccountActived) override;
    virtual ErrCode IsOsAccountConstraintEnable(
        const int id, const std::string &constraint, bool &isConstraintEnable) override;
    virtual ErrCode IsOsAccountVerified(const int id, bool &isVerified) override;
    virtual ErrCode GetCreatedOsAccountsCount(unsigned int &osAccountsCount) override;
    virtual ErrCode GetOsAccountLocalIdFromProcess(int &id) override;
    virtual ErrCode GetOsAccountLocalIdFromUid(const int uid, int &id) override;
    virtual ErrCode GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id) override;
    virtual ErrCode QueryMaxOsAccountNumber(int &maxOsAccountNumber) override;
    virtual ErrCode GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints) override;
    virtual ErrCode QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos) override;
    virtual ErrCode QueryCurrentOsAccount(OsAccountInfo &osAccountInfo) override;
    virtual ErrCode QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo) override;
    virtual ErrCode GetOsAccountTypeFromProcess(OsAccountType &type) override;
    virtual ErrCode GetOsAccountProfilePhoto(const int id, std::string &photo) override;
    virtual ErrCode IsMultiOsAccountEnable(bool &isMultiOsAccountEnable) override;
    virtual ErrCode SetOsAccountName(const int id, const std::string &localName) override;
    virtual ErrCode SetOsAccountConstraints(
        const int id, const std::vector<std::string> &constraints, const bool enable) override;
    virtual ErrCode SetOsAccountProfilePhoto(const int id, const std::string &photo) override;
    virtual ErrCode ActivateOsAccount(const int id) override;
    virtual ErrCode StartOsAccount(const int id) override;
    virtual ErrCode StopOsAccount(const int id) override;
    virtual ErrCode GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id) override;
    virtual ErrCode GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber) override;
    virtual ErrCode SubscribeOsAccount(
        const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener) override;
    virtual ErrCode UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener) override;
    virtual OS_ACCOUNT_SWITCH_MOD GetOsAccountSwitchMod() override;
    virtual ErrCode IsCurrentOsAccountVerified(bool &isVerified) override;
    virtual ErrCode IsOsAccountCompleted(const int id, bool &isOsAccountCompleted) override;
    virtual ErrCode SetCurrentOsAccountIsVerified(const bool isVerified) override;
    virtual ErrCode SetOsAccountIsVerified(const int id, const bool isVerified) override;
    virtual ErrCode DumpState(const int &id, std::vector<std::string> &state) override;

    virtual void CreateBasicAccounts() override;
    virtual ErrCode GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
        int &createdOsAccountNum) override;
    virtual ErrCode GetSerialNumberFromDatabase(const std::string& storeID, int64_t &serialNumber) override;
    virtual ErrCode GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id) override;
    virtual ErrCode GetOsAccountFromDatabase(const std::string& storeID, const int id,
        OsAccountInfo &osAccountInfo) override;
    virtual ErrCode GetOsAccountListFromDatabase(const std::string& storeID,
        std::vector<OsAccountInfo> &osAccountList) override;

private:
    template<typename T>
    bool WriteParcelableVector(const std::vector<T> &parcelableVector, MessageParcel &data);
    template<typename T>
    bool ReadParcelableVector(std::vector<T> &parcelableInfos, MessageParcel &data);
    ErrCode SendRequest(IOsAccount::Message code, MessageParcel &data, MessageParcel &reply);

private:
    static inline BrokerDelegator<OsAccountProxy> delegator_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif /* OS_ACCOUNT_FRAMEWORK_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_PROXY_H */

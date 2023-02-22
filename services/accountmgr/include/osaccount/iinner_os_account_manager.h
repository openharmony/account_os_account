/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_IINNER_OS_ACCOUNT_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_IINNER_OS_ACCOUNT_MANAGER_H

#include <memory>
#include "iinner_os_account.h"
#include "ios_account_control.h"
#include "ios_account_subscribe.h"
#include "os_account_interface.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
class IInnerOsAccountManager : public IInnerOsAccount, public DelayedSingleton<IInnerOsAccountManager> {
public:
    IInnerOsAccountManager();
    virtual ~IInnerOsAccountManager() = default;
    void Init() override;
    ErrCode CreateOsAccount(
        const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo) override;
    ErrCode CreateOsAccountForDomain(
        const OsAccountType &type, const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo) override;
    ErrCode RemoveOsAccount(const int id) override;
    ErrCode IsOsAccountExists(const int id, bool &isOsAccountExits) override;
    ErrCode IsOsAccountActived(const int id, bool &isOsAccountActived) override;
    ErrCode IsOsAccountConstraintEnable(
        const int id, const std::string &constraint, bool &isOsAccountConstraintEnable) override;
    ErrCode IsOsAccountVerified(const int id, bool &isVerified) override;
    ErrCode GetCreatedOsAccountsCount(unsigned int &createdOsAccountCount) override;
    ErrCode QueryMaxOsAccountNumber(int &maxOsAccountNumber) override;
    ErrCode GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints) override;
    ErrCode QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos) override;
    ErrCode QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo) override;
    ErrCode GetOsAccountType(const int id, OsAccountType &type) override;
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
    ErrCode IsOsAccountCompleted(const int id, bool &isOsAccountCompleted) override;
    ErrCode SetOsAccountIsVerified(const int id, const bool isVerified) override;
    ErrCode IsAllowedCreateAdmin(bool &isAllowedCreateAdmin) override;
    ErrCode GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id) override;
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
    ErrCode SetBaseOsAccountConstraints(const int32_t id,
        const std::vector<std::string> &constraints, const bool enable) override;
    ErrCode SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool enable, const int32_t enforcerId, const bool isDeviceOwner) override;
    ErrCode SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner) override;

private:
    void SetOsAccountControl(std::shared_ptr<IOsAccountControl> ptr);
    void StartAccount();
    void RestartActiveAccount();
    void CreateBaseAdminAccount();
    void CreateBaseStandardAccount();
    void CreateBaseStandardAccountSendToOther();
    void StartBaseStandardAccount(OsAccountInfo &osAccountInfo);
    void ResetAccountStatus(void);
    void StartActivatedAccount(int32_t id);
    ErrCode DeActivateOsAccount(const int id);
    ErrCode GetEventHandler(void);
    ErrCode PrepareOsAccountInfo(const std::string &name, const OsAccountType &type,
        const DomainAccountInfo &domainAccount, OsAccountInfo &osAccountInfo);
    ErrCode SendMsgForAccountCreate(OsAccountInfo &osAccountInfo);
    ErrCode SendMsgForAccountActivate(OsAccountInfo &osAccountInfo);
    ErrCode SendMsgForAccountStop(OsAccountInfo &osAccountInfo);
    ErrCode SendMsgForAccountRemove(OsAccountInfo &osAccountInfo);
    void AddLocalIdToOperating(int32_t localId);
    void RemoveLocalIdToOperating(int32_t localId);
    bool IsLocalIdInOperating(int32_t localId);
    void CleanGarbageAccounts();
    ErrCode DealWithDeviceOwnerId(const bool isDeviceOwner, const int32_t localId);

    // operations for active list
    void PushIdIntoActiveList(int32_t id);
    void EraseIdFromActiveList(int32_t id);
    bool IsOsAccountIDInActiveList(int32_t id);
    void CopyFromActiveList(std::vector<int32_t>& idList);
    void RefreshActiveList(int32_t newId);

private:
    std::shared_ptr<IOsAccountControl> osAccountControl_;
    std::vector<int32_t> activeAccountId_;
    std::vector<int32_t> operatingId_;
    std::shared_ptr<IOsAccountSubscribe> subscribeManagerPtr_;
    std::int32_t counterForStandard_;
    std::int32_t counterForStandardCreate_;
    std::int32_t counterForAccountStart_;
    std::int32_t deviceOwnerId_;
    bool isSendToStorageCreate_;
    bool isSendToStorageStart_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler_;
    static constexpr std::int32_t DELAY_FOR_FOUNDATION_SERVICE = 2 * 1000; // 2s
    static constexpr std::int32_t DELAY_FOR_TIME_INTERVAL = 100;           // 0.1s
    static constexpr std::int32_t MAX_TRY_TIMES = 1000;
    mutable std::mutex ativeMutex_;
    mutable std::mutex operatingMutex_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_IINNER_OS_ACCOUNT_MANAGER_H

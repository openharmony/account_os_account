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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_IINNER_OS_ACCOUNT_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_IINNER_OS_ACCOUNT_MANAGER_H

#include <map>
#include <memory>
#include <mutex>
#include "iinner_os_account.h"
#ifdef SUPPORT_DOMAIN_ACCOUNTS
#include "inner_domain_account_manager.h"
#endif // SUPPORT_DOMAIN_ACCOUNTS
#include "ios_account_control.h"
#include "ios_account_subscribe.h"
#include "ohos_account_manager.h"
#include "os_account_control_file_manager.h"
#include "os_account_interface.h"
#include "os_account_activate_lock_plugin_manager.h"
#ifdef SUPPORT_LOCK_OS_ACCOUNT
#include "os_account_lock_os_account_plugin_manager.h"
#endif // SUPPORT_LOCK_OS_ACCOUNT
#include "safe_map.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
class IInnerOsAccountManager : public IInnerOsAccount {
public:
    static IInnerOsAccountManager &GetInstance();
    bool Init(const std::set<int32_t> &initAccounts = {Constants::START_USER_ID}) override;
    ErrCode CreateOsAccount(
        const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo) override;
    ErrCode CreateOsAccount(const std::string &localName, const std::string &shortName,
        const OsAccountType &type, OsAccountInfo &osAccountInfo, const CreateOsAccountOptions &options = {}) override;
    ErrCode CreateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo,
        const CreateOsAccountOptions &options = {}) override;
    ErrCode UpdateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo) override;
    ErrCode UpdateFirstOsAccountInfo(OsAccountInfo& accountInfoOld, OsAccountInfo& osAccountInfo) override;
    ErrCode RemoveOsAccount(const int id) override;
    ErrCode IsOsAccountExists(const int id, bool &isOsAccountExits) override;
    ErrCode IsOsAccountActived(const int id, bool &isOsAccountActived) override;
    ErrCode IsOsAccountConstraintEnable(
        const int id, const std::string &constraint, bool &isOsAccountConstraintEnable) override;
    ErrCode IsOsAccountVerified(const int id, bool &isVerified) override;
    ErrCode IsOsAccountDeactivating(const int id, bool &isDeactivating) override;
    ErrCode GetCreatedOsAccountsCount(unsigned int &createdOsAccountCount) override;
    ErrCode QueryMaxOsAccountNumber(uint32_t &maxOsAccountNumber) override;
    ErrCode QueryMaxLoggedInOsAccountNumber(uint32_t &maxNum) override;
    ErrCode GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints) override;
    ErrCode QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos) override;
    ErrCode QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo) override;
    ErrCode GetOsAccountShortName(const int id, std::string &shortName) override;
    ErrCode GetOsAccountName(const int id, std::string &name) override;
    ErrCode GetOsAccountType(const int id, OsAccountType &type) override;
    ErrCode GetOsAccountProfilePhoto(const int id, std::string &photo) override;
    ErrCode IsMultiOsAccountEnable(bool &isMultiOsAccountEnable) override;
    ErrCode SetOsAccountName(const int id, const std::string &name) override;
    ErrCode SetOsAccountConstraints(
        const int id, const std::vector<std::string> &constraints, const bool enable) override;
    ErrCode SetOsAccountProfilePhoto(const int id, const std::string &photo) override;
    ErrCode ActivateOsAccount(const int id, const bool startStorage = true,
        const uint64_t displayId = 0, bool isAppRecovery = false) override;
    ErrCode DeactivateOsAccount(const int id, bool isStopStorage = true) override;
    ErrCode StartOsAccount(const int id) override;
    ErrCode GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id) override;
    ErrCode GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber) override;
    ErrCode SubscribeOsAccount(
        const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener) override;
    ErrCode UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener) override;
    const std::shared_ptr<OsAccountSubscribeInfo> GetSubscribeRecordInfo(
        const sptr<IRemoteObject> &eventListener) override;
    OS_ACCOUNT_SWITCH_MOD GetOsAccountSwitchMod() override;
    ErrCode IsOsAccountCompleted(const int id, bool &isOsAccountCompleted) override;
    ErrCode SetOsAccountIsVerified(const int id, const bool isVerified) override;
    ErrCode SetOsAccountIsLoggedIn(const int32_t id, const bool isLoggedIn) override;
    ErrCode GetOsAccountCredentialId(const int id, uint64_t &credentialId) override;
    ErrCode SetOsAccountCredentialId(const int id, uint64_t credentialId) override;
    ErrCode IsAllowedCreateAdmin(bool &isAllowedCreateAdmin) override;
    ErrCode GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
        int &createdOsAccountNum) override;
    ErrCode GetSerialNumberFromDatabase(const std::string& storeID, int64_t &serialNumber) override;
    ErrCode GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id) override;
    ErrCode GetOsAccountFromDatabase(const std::string& storeID, const int id,
        OsAccountInfo &osAccountInfo) override;
    ErrCode GetOsAccountListFromDatabase(const std::string& storeID,
        std::vector<OsAccountInfo> &osAccountList) override;
    ErrCode QueryActiveOsAccountIds(std::vector<int32_t>& ids) override;
    ErrCode GetUnlockedOsAccountLocalIds(std::vector<int32_t>& ids) override;
    ErrCode QueryOsAccountConstraintSourceTypes(const int32_t id,
        const std::string &constraint, std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos) override;
    ErrCode SetBaseOsAccountConstraints(const int32_t id,
        const std::vector<std::string> &constraints, const bool enable) override;
    ErrCode SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool enable, const int32_t enforcerId, const bool isDeviceOwner) override;
    ErrCode SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner) override;

    ErrCode SetDefaultActivatedOsAccount(const int32_t id) override;
    ErrCode SetDefaultActivatedOsAccount(const uint64_t displayId, const int32_t id) override;
    ErrCode GetDefaultActivatedOsAccount(int32_t &id) override;
    ErrCode GetDefaultActivatedOsAccount(const uint64_t displayId, int32_t &id) override;
    ErrCode GetAllDefaultActivatedOsAccounts(std::map<uint64_t, int32_t> &activatedIds);
    ErrCode IsOsAccountForeground(const int32_t localId, const uint64_t displayId, bool &isForeground) override;
    ErrCode GetForegroundOsAccountLocalId(const uint64_t displayId, int32_t &localId) override;
    ErrCode GetForegroundOsAccountDisplayId(const int32_t localId, uint64_t &displayId) override;
    ErrCode GetForegroundOsAccounts(std::vector<ForegroundOsAccount> &accounts) override;
    ErrCode GetBackgroundOsAccountLocalIds(std::vector<int32_t> &localIds) override;
    ErrCode SetOsAccountToBeRemoved(int32_t localId, bool toBeRemoved) override;
    ErrCode SendMsgForAccountCreate(OsAccountInfo &osAccountInfo, const CreateOsAccountOptions &options = {});
    ErrCode GetOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo);
    ErrCode GetTypeNumber(const OsAccountType& type, int32_t& typeNumber) override;
    ErrCode CheckTypeNumber(const OsAccountType& type) override;
    ErrCode ActivateDefaultOsAccount() override;

    int32_t CleanGarbageOsAccounts(int32_t excludeId = -1) override;
    void ResetAccountStatus() override;
    bool CheckAndCleanOsAccounts();
    ErrCode GetRealOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo);
    void CleanGarbageOsAccountsAsync() override;
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    ErrCode BindDomainAccount(const OsAccountType &type, const DomainAccountInfo &domainAccountInfo,
        OsAccountInfo &osAccountInfo, const CreateOsAccountForDomainOptions &options = {});
    ErrCode UpdateAccountStatusForDomain(const int id, DomainAccountStatus status);
    ErrCode UpdateAccountInfoByDomainAccountInfo(int32_t userId, const DomainAccountInfo &newDomainAccountInfo);
    bool IsSameAccount(const DomainAccountInfo &domainInfoSrc, const DomainAccountInfo &domainInfoTar);
    ErrCode CheckDomainAccountBound(const DomainAccountInfo &info, bool &isBound);
#endif // SUPPORT_DOMAIN_ACCOUNTS
    ErrCode CreateOsAccountForDomain(const OsAccountType &type, const DomainAccountInfo &domainInfo,
        const sptr<IDomainAccountCallback> &callback, const CreateOsAccountForDomainOptions &options = {}) override;
    ErrCode GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id) override;
    ErrCode GetOsAccountDomainInfo(const int32_t localId, DomainAccountInfo &domainInfo) override;
    ErrCode UpdateServerConfig(const std::string &configId, const DomainServerConfig &config);
#ifdef SUPPORT_LOCK_OS_ACCOUNT
    ErrCode IsOsAccountLocking(const int id, bool &isLocking) override;
    ErrCode PublishOsAccountLockEvent(const int32_t localId, bool isLocking) override;
    ErrCode LockOsAccount(const int32_t localId) override;
#endif
    void RemoveLocalIdToOperating(int32_t localId);
    bool CheckAndAddLocalIdOperating(int32_t localId);
    OsAccountControlFileManager &GetFileController();
private:
    IInnerOsAccountManager();
    ~IInnerOsAccountManager() = default;
    DISALLOW_COPY_AND_MOVE(IInnerOsAccountManager);
    void RestartActiveAccount();
    void CreateBaseAdminAccount();
    bool CreateBaseStandardAccount(OsAccountInfo &osAccountInfo);
    ErrCode SendMsgForAccountActivateInBackground(OsAccountInfo &osAccountInfo);
    ErrCode ActivateOsAccountInBackground(const int32_t id);
    bool IsLoggedInAccountsOversize();
    void ExecuteDeactivationAnimation(int32_t pipeFd, const OsAccountInfo &osAccountInfo);
    ErrCode WaitForAnimationReady(int32_t pipeFd);
    void LaunchDeactivationAnimation(const OsAccountInfo &osAccountInfo);
    ErrCode PrepareRemoveOsAccount(OsAccountInfo &osAccountInfo, bool isCleanGarbage = false);
    ErrCode RemoveOsAccountOperate(const int id, OsAccountInfo &osAccountInfo, bool isCleanGarbage = false);
    ErrCode DeactivateOsAccountById(const int id);
    ErrCode DeactivateOsAccountByInfo(OsAccountInfo &osAccountInfo);
    void CleanForegroundAccountMap(const OsAccountInfo &osAccountInfo);
    ErrCode PrepareOsAccountInfo(const std::string &name, const OsAccountType &type,
        const DomainAccountInfo &domainAccount, OsAccountInfo &osAccountInfo);
    ErrCode PrepareOsAccountInfo(const std::string &localName, const std::string &shortName, const OsAccountType &type,
        const DomainAccountInfo &domainAccount, OsAccountInfo &osAccountInfo);
    ErrCode FillOsAccountInfo(const std::string &localName, const std::string &shortName, const OsAccountType &type,
        const DomainAccountInfo &domainAccount, OsAccountInfo &osAccountInfo);
    ErrCode PrepareOsAccountInfoWithFullInfo(OsAccountInfo &osAccountInfo);
    ErrCode SendMsgForAccountActivate(OsAccountInfo &osAccountInfo, const bool startStorage = true,
                                      const uint64_t dispalyId = 0, const bool isAppRecovery = false);
    ErrCode SendToStorageAccountStart(OsAccountInfo &osAccountInfo);
    ErrCode SendToAMSAccountStart(OsAccountInfo &osAccountInfo, const uint64_t dispalyId, const bool isAppRecovery);
    ErrCode SendMsgForAccountDeactivate(OsAccountInfo &osAccountInfo, bool isStopStorage = true);
    void SendMsgForAccountUnlocked(OsAccountInfo &osAccountInfo);
    void SendMsgForAccountSwitched(OsAccountInfo &osAccountInfo);
    ErrCode SendMsgForAccountStop(OsAccountInfo &osAccountInfo);
    ErrCode SendMsgForAccountRemove(OsAccountInfo &osAccountInfo);
    ErrCode ValidateOsAccount(const OsAccountInfo &osAccountInfo);
    ErrCode DealWithDeviceOwnerId(const bool isDeviceOwner, const int32_t localId);
    void CheckAndRefreshLocalIdRecord(const int id);
    void RollBackToEarlierAccount(int32_t fromId, int32_t toId, uint64_t displayId = 0);
    void RollbackOsAccount(OsAccountInfo &osAccountInfo, bool needDelStorage, bool needDelBms);
    bool IsToBeRemoved(const int32_t localId);
    // operations for active list
    void PushIdIntoActiveList(int32_t id);
    void EraseIdFromActiveList(int32_t id);
    bool IsOsAccountIDInActiveList(int32_t id);
    void CopyFromActiveList(std::vector<int32_t>& idList);
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    ErrCode GetOsAccountsByDomainInfo(const DomainAccountInfo &info, std::vector<OsAccountInfo> &osAccountInfos);
#endif // SUPPORT_DOMAIN_ACCOUNTS
    void RetryToGetAccount(OsAccountInfo &osAccountInfo);
    ErrCode RetryToInsertOsAccount(OsAccountInfo &osAccountInfo);
    bool JudgeOsAccountUpdate(cJSON *accountIndexJson);
    std::shared_ptr<std::mutex> GetOrInsertUpdateLock(int32_t id);
    ErrCode UpdateAccountToBackground(int32_t oldId);
    ErrCode IsValidOsAccount(const OsAccountInfo &osAccountInfo);
    ErrCode GetNonSACreatedOACount(unsigned int &nonSACreatedOACount) const;
    std::vector<int32_t> GetVerifiedAccountIds(const SafeMap<int32_t, bool> &verifiedAccounts);
    ErrCode SendToStorageAndAMSAccountStart(OsAccountInfo &osAccountInfo, const bool startStorage,
        const uint64_t displayId, const bool isAppRecovery, int32_t oldId);
    ErrCode PrepareActivateOsAccount(const int32_t id, const uint64_t displayId,
        OsAccountInfo &osAccountInfo, int32_t &foregroundId);
    ErrCode ResetDefaultActivatedAccount(int32_t localId);
    ErrCode CheckHighestHapInstallForCreate(OsAccountInfo &osAccountInfo);
#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
    void QueryAllDisplayIds(std::vector<uint64_t> &displayIds);
    ErrCode ValidateDisplayForActivation(const int id, const uint64_t displayId);
    ErrCode ValidateDisplayId(const uint64_t displayId);
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS

private:
    std::shared_ptr<IOsAccountControl> osAccountControl_;
    std::vector<int32_t> activeAccountId_;
    std::vector<int32_t> operatingId_;
    IOsAccountSubscribe &subscribeManager_;
    std::int32_t deviceOwnerId_ = -1;
    SafeMap<uint64_t, int32_t> defaultActivatedIds_;
    OsAccountConfig config_;
    mutable std::mutex ativeMutex_;
    mutable std::mutex operatingMutex_;
    mutable std::mutex updateLockMutex_;
    mutable std::mutex createOsAccountMutex_;
    SafeMap<uint64_t, int32_t> foregroundAccountMap_;
#ifdef SUPPORT_LOCK_OS_ACCOUNT
    OsAccountLockOsAccountPluginManager &lockOsAccountPluginManager_;
#endif
    OsAccountActivateLockPluginManager &activateLockPluginManager_;
    SafeMap<int32_t, bool> loggedInAccounts_;
    SafeMap<int32_t, bool> verifiedAccounts_;
    SafeMap<int32_t, bool> deactivatingAccounts_;
#ifdef SUPPORT_LOCK_OS_ACCOUNT
    SafeMap<int32_t, bool> lockingAccounts_;
#endif
    std::map<int32_t, std::shared_ptr<std::mutex>> updateLocks_;
    
    // Helper functions for ActivateDefaultOsAccount
    ErrCode ActivateU1Account();
    ErrCode PrepareForDefaultAccount(int32_t activatedId, OsAccountInfo &osAccountInfo);

public:
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    std::mutex createOrBindDomainAccountMutex_;
#endif // SUPPORT_DOMAIN_ACCOUNTS
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_IINNER_OS_ACCOUNT_MANAGER_H

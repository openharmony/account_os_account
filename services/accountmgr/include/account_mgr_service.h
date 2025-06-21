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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_MGR_SERVICE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_MGR_SERVICE_H

#include <memory>
#include <mutex>

#include "account_dump_helper.h"
#include "account_event_provider.h"
#include "account_info.h"
#include "account_stub.h"
#include "iaccount.h"
#include "iaccount_context.h"
#include "iremote_object.h"
#include "ohos_account_manager.h"
#include "os_account_manager_service.h"
#include "singleton.h"
#include "system_ability.h"

namespace OHOS {
namespace AccountSA {
enum ServiceRunningState { STATE_NOT_START, STATE_RUNNING };

class AccountMgrService : public SystemAbility,
                          public AccountStub,
                          public IAccountContext,
                          public OHOS::DelayedRefSingleton<AccountMgrService> {
public:
    AccountMgrService();
    ~AccountMgrService() override;
    DISALLOW_COPY_AND_MOVE(AccountMgrService);
    DECLARE_SYSTEM_ABILITY(AccountMgrService);
    ErrCode UpdateOhosAccountInfo(
        const std::string &accountName, const std::string &uid, const std::string &eventStr) override;
    ErrCode SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo,
        const std::string &eventStr) override;
    ErrCode SetOsAccountDistributedInfo(
        const int32_t localId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr) override;
    ErrCode QueryOhosAccountInfo(std::string& accountName, std::string& uid, int32_t& status) override;
    ErrCode QueryDistributedVirtualDeviceId(std::string &dvid) override;
    ErrCode QueryDistributedVirtualDeviceId(const std::string &bundleName, int32_t localId, std::string &dvid) override;
    ErrCode QueryOsAccountDistributedInfo(
        std::int32_t localId, std::string& accountName, std::string& uid, int32_t& status) override;
    ErrCode GetOhosAccountInfo(OhosAccountInfo &info) override;
    ErrCode GetOsAccountDistributedInfo(int32_t localId, OhosAccountInfo &info) override;
    ErrCode QueryDeviceAccountId(std::int32_t &accountId) override;
    ErrCode SubscribeDistributedAccountEvent(int32_t typeInt, const sptr<IRemoteObject>& eventListener) override;
    ErrCode UnsubscribeDistributedAccountEvent(int32_t typeInt, const sptr<IRemoteObject>& eventListener) override;
    ErrCode GetAppAccountService(sptr<IRemoteObject>& funcResult) override;
    ErrCode GetOsAccountService(sptr<IRemoteObject>& funcResult) override;
    ErrCode GetAccountIAMService(sptr<IRemoteObject>& funcResult) override;
    ErrCode GetDomainAccountService(sptr<IRemoteObject>& funcResult) override;

    void OnStart() override;
    void OnStop() override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    bool IsServiceStarted(void) const override;
    static AccountMgrService &GetInstance()
    {
        return DelayedRefSingleton<AccountMgrService>::GetInstance();
    }
    ErrCode Dump(std::int32_t fd, const std::vector<std::u16string> &args) override;
    void HandleNotificationEvents(const std::string &eventStr) override;
    std::int32_t GetCallingUserID();

    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    bool Init();
    void SelfClean();
    std::int32_t GetDeviceAccountIdFromCurrentProcess();
    bool CreateOsAccountService();
    bool CreateAppAccountService();
    bool CreateIAMService();
    bool CreateDomainService();
    bool IsDefaultOsAccountVerified();
    void GetUncreatedInitAccounts(std::set<int32_t> &initAccounts);
    ErrCode GetOsAccountDistributedInfoInner(int32_t localId, OhosAccountInfo &info);
    bool HasAccountRequestPermission(const std::string &permissionName);
    int32_t CheckUserIdValid(int32_t userId);
#ifdef HAS_APP_ACCOUNT_PART
    void MoveAppAccountData();
#endif

    bool registerToService_ = false;
    ServiceRunningState state_ = ServiceRunningState::STATE_NOT_START;
    std::unique_ptr<AccountDumpHelper> dumpHelper_{};

    std::mutex serviceMutex_;
    wptr<IRemoteObject> appAccountManagerService_ = nullptr;
    wptr<OsAccountManagerService> osAccountManagerService_ = nullptr;
    wptr<IRemoteObject> accountIAMService_ = nullptr;
    wptr<IRemoteObject> domainAccountMgrService_ = nullptr;

    std::mutex statusMutex_;
    bool isStorageReady_ = false;
    bool isAmsReady_ = false;
    bool isBmsReady_ = false;
    bool isDefaultOsAccountActivated_ = false;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_MGR_SERVICE_H

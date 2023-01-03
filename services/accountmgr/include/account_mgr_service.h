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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_MGR_SERVICE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_MGR_SERVICE_H

#include <memory>
#include <mutex>
#include <thread>
#include "account_dump_helper.h"
#include "account_event_provider.h"
#include "account_info.h"
#ifdef HAS_USER_AUTH_PART
#include "account_iam_service.h"
#endif
#include "account_stub.h"
#include "app_account_manager_service.h"
#include "domain_account_manager_service.h"
#include "os_account_manager_service.h"
#include "iaccount.h"
#include "iremote_object.h"
#include "ohos_account_manager.h"
#include "singleton.h"
#include "system_ability.h"

namespace OHOS {
namespace AccountSA {
enum ServiceRunningState { STATE_NOT_START, STATE_RUNNING };

class AccountMgrService : public SystemAbility,
                          public AccountStub,
                          public OHOS::DelayedRefSingleton<AccountMgrService> {
public:
    AccountMgrService();
    ~AccountMgrService();
    DISALLOW_COPY_AND_MOVE(AccountMgrService);
    DECLARE_SYSTEM_ABILITY(AccountMgrService);
    bool UpdateOhosAccountInfo(
        const std::string &accountName, const std::string &uid, const std::string &eventStr) override;
    std::int32_t SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo,
        const std::string &eventStr) override;
    std::pair<bool, OhosAccountInfo> QueryOhosAccountInfo(void) override;
    std::pair<bool, OhosAccountInfo> QueryOhosAccountInfoByUserId(std::int32_t userId) override;
    ErrCode GetOhosAccountInfo(OhosAccountInfo &accountInfo) override;
    ErrCode GetOhosAccountInfoByUserId(int32_t userId, OhosAccountInfo &accountInfo) override;
    std::int32_t QueryDeviceAccountId(std::int32_t &accountId) override;
    sptr<IRemoteObject> GetAppAccountService() override;
    sptr<IRemoteObject> GetOsAccountService() override;
    sptr<IRemoteObject> GetAccountIAMService() override;
    sptr<IRemoteObject> GetDomainAccountService() override;

    void OnStart() override;
    void OnStop() override;
    bool IsServiceStarted(void) const override;
    static AccountMgrService &GetInstance()
    {
        return DelayedRefSingleton<AccountMgrService>::GetInstance();
    }
    std::int32_t Dump(std::int32_t fd, const std::vector<std::u16string> &args) override;
    void HandleNotificationEvents(const std::string &eventStr) override;

private:
    bool Init();
    void SelfClean();
    std::int32_t GetDeviceAccountIdFromCurrentProcess();
    bool CreateIAMService();
    bool CreateDomainService();

    bool registerToService_ = false;
    ServiceRunningState state_ = ServiceRunningState::STATE_NOT_START;
    std::unique_ptr<AccountDumpHelper> dumpHelper_{};
    std::shared_ptr<OhosAccountManager> ohosAccountMgr_{};

    sptr<AppAccountManagerService> appAccountManagerService_ = nullptr;
    sptr<OsAccountManagerService> osAccountManagerService_ = nullptr;
#ifdef HAS_USER_AUTH_PART
    sptr<AccountIAMService> accountIAMService_ = nullptr;
#endif
    sptr<DomainAccountManagerService> domainAccountMgrService_ = nullptr;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_MGR_SERVICE_H

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
#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_IINNER_OS_ACCOUNT_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_IINNER_OS_ACCOUNT_MANAGER_H
#include <memory>
#include "iinner_os_account.h"
#include "ios_account_control.h"
#include "ios_account_subscribe.h"
#include "os_account_standard_interface.h"
namespace OHOS {
namespace AccountSA {
class IInnerOsAccountManager : public IInnerOsAccount {
public:
    IInnerOsAccountManager();
    virtual ~IInnerOsAccountManager();
    virtual void Init() override;
    virtual ErrCode CreateOsAccount(
        const std::string &name, const int &type, OsAccountInfo &osAccountInfo) override;
    virtual ErrCode RemoveOsAccount(const int id) override;
    virtual ErrCode IsOsAccountExists(const int id, bool &isOsAccountExits) override;
    virtual ErrCode IsOsAccountActived(const int id, bool &isOsAccountActived) override;
    virtual ErrCode IsOsAccountConstraintEnable(
        const int id, const std::string &constraint, bool &isOsAccountConstraintEnable) override;
    virtual ErrCode IsOsAccountVerified(const int id, bool &isOsAccountVerified) override;
    virtual ErrCode GetCreatedOsAccountsCount(int &createdOsAccountCount) override;
    virtual ErrCode QueryMaxOsAccountNumber(int &maxOsAccountNumber) override;
    virtual ErrCode GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints) override;
    virtual ErrCode QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos) override;
    virtual ErrCode QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo) override;
    virtual ErrCode GetOsAccountType(const int id, int &type) override;
    virtual ErrCode GetOsAccountProfilePhoto(const int id, std::string &photo) override;
    virtual ErrCode IsMultiOsAccountEnable(bool &isMultiOsAccountEnable) override;
    virtual ErrCode SetOsAccountName(const int id, const std::string &name) override;
    virtual ErrCode SetOsAccountConstraints(
        const int id, const std::vector<std::string> &constraints, const bool enable) override;
    virtual ErrCode SetOsAccountProfilePhoto(const int id, const std::string &photo) override;
    virtual ErrCode GetDistributedVirtualDeviceId(std::int32_t &deviceId, std::int32_t uid) override;
    virtual ErrCode ActivateOsAccount(const int id) override;
    virtual ErrCode StartOsAccount(const int id) override;
    virtual ErrCode StopOsAccount(const int id) override;
    virtual ErrCode GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id) override;
    virtual ErrCode GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber) override;
    virtual ErrCode SubscribeOsAccount(
        const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener) override;
    virtual ErrCode UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener) override;
    virtual OS_ACCOUNT_SWITCH_MOD GetOsAccountSwitchMod() override;
    virtual ErrCode IsOsAccountCompleted(const int id, bool &isOsAccountCompleted) override;
    virtual ErrCode SetOsAccountIsVerified(const int id, const bool isOsAccountVerified) override;

private:
    void CreateBaseAdminAccount();
    void CreateBaseStandardAccount();
    void StartBaseAccount(void);
    ErrCode GetEventHandler(void);

private:
    std::shared_ptr<IOsAccountControl> osAccountControl_;
    std::vector<int> activeAccountId_;
    std::shared_ptr<IOsAccountSubscribe> subscribeManagerPtr_;
    std::int32_t counter_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler_;
    static constexpr std::int32_t DELAY_FOR_FOUNDATION_SERVICE = 5 * 1000;  // 5s
    static constexpr std::int32_t DELAY_FOR_TIME_INTERVAL = 1 * 1000;       // 1s
    static constexpr std::int32_t MAX_TRY_TIMES = 10;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif /* OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_IINNER_OS_ACCOUNT_MANAGER_H */
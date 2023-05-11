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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OHOS_ACCOUNT_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OHOS_ACCOUNT_MANAGER_H

#include <map>
#include <mutex>
#include <string>
#include "account_info.h"
#include "account_state_machine.h"
#include "ohos_account_data_deal.h"

namespace OHOS {
namespace AccountSA {
const std::string ACCOUNT_CFG_DIR_ROOT_PATH = "/data/service/el1/public/account/";

class OhosAccountManager;
using OhosAccountEventFunc = bool (OhosAccountManager::*)(const OhosAccountInfo &ohosAccountInfo,
    const std::string &eventStr);
/**
 * Ohos account manager
 */
class OhosAccountManager {
public:
    /**
     * Get current ohos account information.
     *
     * @return current account information.
     */
    AccountInfo GetCurrentOhosAccountInfo();

    /**
     * Get ohos account information by local userId.
     *
     * @param userId target local account id
     * @return ohos account info which is bound to the local userId.
     */
    ErrCode GetAccountInfoByUserId(std::int32_t userId, AccountInfo &info);

    /**
     * Get current account state.
     *
     * @return current account state id.
     */
    int GetCurrentOhosAccountState();

    /**
     * Init ohos account manager.
     *
     */
    bool OnInitialize();

    /**
     * Process an account event.
     *
     * @param curOhosAccount current ohos account info
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    bool HandleEvent(AccountInfo &curOhosAccount, const std::string &eventStr);

    /**
     * login ohos (for distributed network) account.
     *
     * @param name ohos account name
     * @param uid ohos account uid
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    bool LoginOhosAccount(const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr);

    /**
     * logout ohos (for distributed network) account.
     *
     * @param name ohos account name
     * @param uid ohos account uid
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    bool LogoutOhosAccount(const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr);

    /**
     * logoff ohos (for distributed network) account.
     *
     * @param name ohos account name
     * @param uid ohos account uid
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    bool LogoffOhosAccount(const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr);

    /**
     * Handle token_invalid event of ohos (for distributed network) account .
     *
     * @param name ohos account name
     * @param uid ohos account uid
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    bool HandleOhosAccountTokenInvalidEvent(const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr);

    /**
     * Handle device account switch event.
     *
     * @param None
     * @return None
     */
    void HandleDevAccountSwitchEvent();

    /**
     * Ohos account state change.
     *
     * @param name ohos account name
     * @param uid ohos account uid
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    bool OhosAccountStateChange(const std::string &name, const std::string &uid, const std::string &eventStr);

    /**
     * Ohos account state change.
     *
     * @param ohosAccountInfo ohos account information
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    bool OhosAccountStateChange(const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr);

private:
    /**
     * Account state machine.
     */
    std::unique_ptr<AccountStateMachine> accountState_{};

    /**
     * Deal with file storage.
     */
    std::unique_ptr<OhosAccountDataDeal> dataDealer_{};

    /**
     * event mapper.
     */
    std::map<std::string, ACCOUNT_INNER_EVENT_TYPE> eventMap_;

    /**
     * mutex lock for synchronization.
     */
    std::mutex mgrMutex_;

    /**
     * build event mapper.
     */
    void BuildEventsMapper();

    /**
     * Config current account config.
     *
     * @param ohosAccountInfo target ohos account information.
     * @return true if success.
     */
    bool SaveOhosAccountInfo(AccountInfo &ohosAccountInfo) const;

    /**
     * Clear current account config.
     * @param curOhosAccountInfo current ohos account info.
     * @param clrStatus account status.
     */
    bool ClearOhosAccount(AccountInfo &curOhosAccountInfo, std::int32_t clrStatus = ACCOUNT_STATE_UNBOUND) const;

    /**
     * Check whether the ohos account can be bound to the current user or not
     * @return true if can.
     */
    bool CheckOhosAccountCanBind(const AccountInfo &currAccountInfo,
        const OhosAccountInfo &newOhosAccountInfo, const std::string &newOhosUid) const;

    /**
     * Get current ohos account info and check whether input information match or not
     * @return true if matches.
     */
    bool GetCurOhosAccountAndCheckMatch(AccountInfo &curOhosAccountInfo,
                                        const std::string &inputName,
                                        const std::string &inputUid,
                                        const std::int32_t callingUserId) const;

    /**
     * event function map
     */
    std::map<std::string, OhosAccountEventFunc> eventFuncMap_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OHOS_ACCOUNT_MANAGER_H

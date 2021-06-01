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

#ifndef ACCOUNT_OHOSACCOUNTMANAGER_H
#define ACCOUNT_OHOSACCOUNTMANAGER_H

#include <string>
#include <map>
#include <mutex>
#include "account_state_machine.h"
#include "account_info.h"
#include "ohos_account_data_deal.h"

namespace OHOS {
namespace AccountSA {
const std::string ACCOUNT_CFG_DIR_ROOT_PATH = "/data/system/users/";
const std::string ACCOUNT_CFG_FILE_NAME = "/account.json";
class OhosAccountManager;
using OhosAccountEventFunc = bool (OhosAccountManager::*)(const std::string &name, const std::string &uid,
    const std::string &eventStr);
/**
 * Ohos account manager
 */
class OhosAccountManager {
public:
    /**
     * Get current account information.
     *
     * @return current account information.
     */
    AccountInfo GetAccountInfo();

    /**
     * Get current account state.
     *
     * @return current account state id.
     */
    int GetAccountState() const;

    /**
     * Init ohos account manager.
     *
     */
    bool OnInitialize();

    /**
     * Process an account event.
     *
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    bool HandleEvent(const std::string &eventStr);

    /**
     * login ohos (for distributed network) account.
     *
     * @param name ohos account name
     * @param uid ohos account uid
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    bool LoginOhosAccount(const std::string &name, const std::string &uid, const std::string &eventStr);

    /**
     * logout ohos (for distributed network) account.
     *
     * @param name ohos account name
     * @param uid ohos account uid
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    bool LogoutOhosAccount(const std::string &name, const std::string &uid, const std::string &eventStr);

    /**
     * logoff ohos (for distributed network) account.
     *
     * @param name ohos account name
     * @param uid ohos account uid
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    bool LogoffOhosAccount(const std::string &name, const std::string &uid, const std::string &eventStr);

    /**
     * Handle token_invalid event of ohos (for distributed network) account .
     *
     * @param name ohos account name
     * @param uid ohos account uid
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    bool HandleOhosAccountTokenInvalidEvent(const std::string &name,
        const std::string &uid, const std::string &eventStr);

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

private:
    /**
     * Get Current user Id.
     */
    std::int32_t GetUserId();

    /**
     * Account state machine.
     */
    std::unique_ptr<AccountStateMachine> accountState_{};

    /**
     * Current account.
     */
    AccountInfo currentAccount_;

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
     * Records dfx event of ohos account status
     */
    void ReportPublishFailureEvent(std::int32_t errCode, std::int32_t oldStatus);

    /**
     * Config current account config.
     *
     * @param account account information.
     * @return true if success.
     */
    bool SetAccount(AccountInfo &account);

    /**
     * Clear current account config.
     * @param clrStatus account status.
     */
    bool ClearAccount(std::int32_t clrStatus = ACCOUNT_STATE_UNBOUND);

    /**
     * event function map
     */
    std::map<std::string, OhosAccountEventFunc> eventFuncMap_;
};
} // namespace AccountSA
} // namespace OHOS
#endif // ACCOUNT_OHOSACCOUNTMANAGER_H

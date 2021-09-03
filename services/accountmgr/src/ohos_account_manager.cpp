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

#include "ohos_account_manager.h"
#include "account_event_provider.h"
#include "account_helper_data.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_mgr_service.h"
#include "common_event_support.h"
#include "hisysevent.h"
#include "system_ability_definition.h"

using namespace OHOS::EventFwk;

namespace OHOS {
namespace AccountSA {
namespace {
constexpr std::int32_t MAX_RETRY_TIMES = 2; // give another chance when json file corrupted
const std::string KEY_ACCOUNT_EVENT_LOGIN = "LOGIN";
const std::string KEY_ACCOUNT_EVENT_LOGOUT = "LOGOUT";
const std::string KEY_ACCOUNT_EVENT_TOKEN_INVALID = "TOKEN_INVALID";
const std::string KEY_ACCOUNT_EVENT_LOGOFF = "LOGOFF";

std::string GetAccountEventStr(const std::map<std::string, std::string> &accountEventMap,
    const std::string &eventKey, const std::string &defaultValue)
{
    const auto &it = accountEventMap.find(eventKey);
    if (it != accountEventMap.end()) {
        return it->second;
    }
    return defaultValue;
}
}

/**
 * Ohos account state change.
 *
 * @param name ohos account name
 * @param uid ohos account uid
 * @param eventStr ohos account state change event
 * @return true if the processing was completed, otherwise false
 */
bool OhosAccountManager::OhosAccountStateChange(const std::string &name, const std::string &uid,
    const std::string &eventStr)
{
    auto itFunc = eventFuncMap_.find(eventStr);
    if (itFunc == eventFuncMap_.end()) {
        ACCOUNT_LOGE("invalid event: %{public}s", eventStr.c_str());
        return false;
    }
    return (this->*(itFunc->second))(name, uid, eventStr);
}

/**
 * Clear current account information
 *
 */
bool OhosAccountManager::ClearAccount(std::int32_t clrStatus)
{
    currentAccount_.clear(clrStatus);
    ErrCode errCode = dataDealer_->AccountInfoToJson(currentAccount_);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("AccountInfoToJson error");
        return false;
    }
    return true;
}

/**
 * Config current account config.
 *
 * @param account account information.
 * @return true if success.
 */
bool OhosAccountManager::SetAccount(AccountInfo &account)
{
    currentAccount_ = account;
    ErrCode errCode = dataDealer_->AccountInfoToJson(currentAccount_);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("AccountInfoToJson error");
        return false;
    }
    return true;
}

/**
 * Get current account information.
 *
 * @return current account information.
 */
AccountInfo OhosAccountManager::GetAccountInfo()
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);
    return currentAccount_;
}

/**
 * Get current account state.
 *
 * @return current account state id.
 */
std::int32_t OhosAccountManager::GetAccountState() const
{
    return currentAccount_.ohosAccountStatus_;
}

/**
 * Process an account event.
 *
 * @param eventStr ohos account state change event
 * @return true if the processing was completed, otherwise false
 */
bool OhosAccountManager::HandleEvent(const std::string &eventStr)
{
    auto iter = eventMap_.find(eventStr);
    if (iter == eventMap_.end()) {
        ACCOUNT_LOGE("invalid event: %{public}s", eventStr.c_str());
        return false;
    }

    int event = iter->second;
    bool ret = accountState_->StateChangeProcess(event);
    if (!ret) {
        ACCOUNT_LOGE("Handle event %{public}d failed", event);
        return false;
    }
    std::int32_t newState = accountState_->GetAccountState();
    if (newState != currentAccount_.ohosAccountStatus_) {
        HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCOUNT, "AccountServiceStateMachineEvent",
            HiviewDFX::HiSysEvent::EventType::FAULT, "DEVICE_MODE", currentAccount_.userId_,
            "OPERATION_TYPE", event, "OLD_STATE", currentAccount_.ohosAccountStatus_, "NEW_STATE", newState);
        currentAccount_.ohosAccountStatus_ = newState;
    }
    return true;
}

/**
 * login ohos (for distributed network) account.
 *
 * @param name ohos account name
 * @param uid ohos account uid
 * @param eventStr ohos account state change event
 * @return true if the processing was completed, otherwise false
 */
bool OhosAccountManager::LoginOhosAccount(const std::string &name, const std::string &uid, const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);
    std::int32_t oldStatus = currentAccount_.ohosAccountStatus_;
    bool ret = HandleEvent(eventStr); // update account status
    if (!ret) {
        ACCOUNT_LOGE("LoginOhosAccount: HandleEvent %{public}s failed", eventStr.c_str());
        return false;
    }

    AccountInfo accountInfo(name, uid, currentAccount_.ohosAccountStatus_);
    accountInfo.bindTime_ = std::time(nullptr);
    accountInfo.userId_ = GetUserId();
    ret = SetAccount(accountInfo); // set account info
    if (!ret) {
        ACCOUNT_LOGE("LoginOhosAccount: SetAccount failed");
        return false;
    }
    bool errCode = AccountEventProvider::EventPublish(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGIN);
    if (errCode != true) {
        ACCOUNT_LOGE("publish account login event failed");
        ReportPublishFailureEvent(errCode, oldStatus);
        return false;
    }
    ACCOUNT_LOGI("LoginOhosAccount success");
    return true;
}

/**
 * logout ohos (for distributed network) account.
 *
 * @param name ohos account name
 * @param uid ohos account uid
 * @param eventStr ohos account state change event
 * @return true if the processing was completed, otherwise false
 */
bool OhosAccountManager::LogoutOhosAccount(const std::string &name, const std::string &uid, const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);
    std::int32_t oldStatus = currentAccount_.ohosAccountStatus_;
    bool ret = HandleEvent(eventStr); // update account status
    if (!ret) {
        ACCOUNT_LOGE("LogoutOhosAccount: HandleEvent %{public}s failed", eventStr.c_str());
        return false;
    }

    ret = ClearAccount(); // clear account info with ACCOUNT_STATE_LOGOUT
    if (!ret) {
        ACCOUNT_LOGE("LogoutOhosAccount: ClearAccount failed");
        return false;
    }
    bool errCode = AccountEventProvider::EventPublish(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT);
    if (errCode != true) {
        ACCOUNT_LOGE("publish account logout event failed");
        ReportPublishFailureEvent(errCode, oldStatus);
        return false;
    }
    ACCOUNT_LOGI("LogoutOhosAccount success");
    return true;
}

/**
 * logoff ohos (for distributed network) account.
 *
 * @param name ohos account name
 * @param uid ohos account uid
 * @param eventStr ohos account state change event
 * @return true if the processing was completed, otherwise false
 */
bool OhosAccountManager::LogoffOhosAccount(const std::string &name, const std::string &uid, const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);
    std::int32_t oldStatus = currentAccount_.ohosAccountStatus_;
    bool ret = HandleEvent(eventStr); // update account status
    if (!ret) {
        ACCOUNT_LOGE("LogoffOhosAccount: HandleEvent %{public}s failed", eventStr.c_str());
        return false;
    }

    ret = ClearAccount(ACCOUNT_STATE_LOGOFF); // clear account info with ACCOUNT_STATE_LOGOFF
    if (!ret) {
        ACCOUNT_LOGE("LogoffOhosAccount: ClearAccount failed");
        return false;
    }
    bool errCode = AccountEventProvider::EventPublish(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOFF);
    if (errCode != true) {
        ACCOUNT_LOGE("publish account logoff event failed");
        ReportPublishFailureEvent(errCode, oldStatus);
        return false;
    }
    ACCOUNT_LOGI("LogoffOhosAccount success");
    return true;
}

/**
 * Handle token_invalid event.
 *
 * @param name ohos account name
 * @param uid ohos account uid
 * @param eventStr ohos account state change event
 * @return true if the processing was completed, otherwise false
 */
bool OhosAccountManager::HandleOhosAccountTokenInvalidEvent(const std::string &name,
    const std::string &uid, const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);
    std::int32_t oldStatus = currentAccount_.ohosAccountStatus_;
    bool ret = HandleEvent(eventStr); // update account status
    if (!ret) {
        ACCOUNT_LOGE("HandleOhosAccountTokenInvalidEvent: HandleEvent %{public}s failed", eventStr.c_str());
        return false;
    }

    AccountInfo accountInfo(name, uid, currentAccount_.ohosAccountStatus_);
    accountInfo.userId_ = GetUserId();
    ret = SetAccount(accountInfo);
    if (!ret) {
        // moving on even if failed to update account info
        ACCOUNT_LOGW("Handle TokenInvalid event: SetAccount failed");
    }
    bool errCode = AccountEventProvider::EventPublish(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_TOKEN_INVALID);
    if (errCode != true) {
        ACCOUNT_LOGE("publish account token invalid event failed");
        ReportPublishFailureEvent(errCode, oldStatus);
        return false;
    }
    ACCOUNT_LOGI("HandleOhosAccountTokenInvalidEvent success");
    return true;
}

std::int32_t OhosAccountManager::GetUserId()
{
    std::int32_t id = DEVICE_ACCOUNT_OWNER; // default to OWNER MODE

    if (!AccountMgrService::GetInstance().IsServiceStarted()) {
        ACCOUNT_LOGW("account mgr not ready, default as OWNER");
        return id;
    }

    auto ret = AccountMgrService::GetInstance().QueryDeviceAccountId(id);
    if (ret != ERR_OK) {
        ACCOUNT_LOGW("Get device account Id failed: %d", ret);
    }

    return (id == DEVICE_ACCOUNT_ID_INVALID) ? DEVICE_ACCOUNT_OWNER : id;
}

/**
 * Init event mapper.
 */
void OhosAccountManager::BuildEventsMapper()
{
    const std::map<std::string, std::string> accountEventMap = AccountHelperData::GetAccountEventMap();
    std::string eventLogin = GetAccountEventStr(accountEventMap, KEY_ACCOUNT_EVENT_LOGIN, OHOS_ACCOUNT_EVENT_LOGIN);
    std::string eventLogout = GetAccountEventStr(accountEventMap, KEY_ACCOUNT_EVENT_LOGOUT, OHOS_ACCOUNT_EVENT_LOGOUT);
    std::string eventTokenInvalid = GetAccountEventStr(accountEventMap, KEY_ACCOUNT_EVENT_TOKEN_INVALID,
        OHOS_ACCOUNT_EVENT_TOKEN_INVALID);
    std::string eventLogoff = GetAccountEventStr(accountEventMap, KEY_ACCOUNT_EVENT_LOGOFF, OHOS_ACCOUNT_EVENT_LOGOFF);

    eventMap_.insert(std::pair<std::string, ACCOUNT_INNER_EVENT_TYPE>(eventLogin, ACCOUNT_BIND_SUCCESS_EVT));
    eventMap_.insert(std::pair<std::string, ACCOUNT_INNER_EVENT_TYPE>(eventLogout, ACCOUNT_MANUAL_UNBOUND_EVT));
    eventMap_.insert(std::pair<std::string, ACCOUNT_INNER_EVENT_TYPE>(eventTokenInvalid, ACCOUNT_TOKEN_EXPIRED_EVT));
    eventMap_.insert(std::pair<std::string, ACCOUNT_INNER_EVENT_TYPE>(eventLogoff, ACCOUNT_MANUAL_LOGOFF_EVT));

    eventFuncMap_.insert(std::make_pair(eventLogin, &OhosAccountManager::LoginOhosAccount));
    eventFuncMap_.insert(std::make_pair(eventLogout, &OhosAccountManager::LogoutOhosAccount));
    eventFuncMap_.insert(std::make_pair(eventLogoff, &OhosAccountManager::LogoffOhosAccount));
    eventFuncMap_.insert(std::make_pair(eventTokenInvalid, &OhosAccountManager::HandleOhosAccountTokenInvalidEvent));
}

/**
 * Init ohos account manager.
 *
 */
bool OhosAccountManager::OnInitialize()
{
    accountState_ = std::make_unique<AccountStateMachine>();
    BuildEventsMapper();

    std::int32_t userId = GetUserId();
    std::string filePath;
    filePath.append(ACCOUNT_CFG_DIR_ROOT_PATH).append(std::to_string(userId)).append(ACCOUNT_CFG_FILE_NAME);
    dataDealer_ = std::make_unique<OhosAccountDataDeal>(filePath);

    std::int32_t tryTimes = 0;
    while (tryTimes < MAX_RETRY_TIMES) {
        tryTimes++;
        ErrCode errCode = dataDealer_->Init();
        if (errCode == ERR_OK) {
            break;
        }

        // when json file corrupted, have it another try
        if ((tryTimes == MAX_RETRY_TIMES) || (errCode != ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION)) {
            ACCOUNT_LOGE("parse json file failed: %{public}d, tryTime: %{public}d", errCode, tryTimes);
            eventMap_.clear();
            eventFuncMap_.clear();
            return false;
        }
    }

    // get account info from config file
    dataDealer_->AccountInfoFromJson(currentAccount_);
    accountState_->SetAccountState(currentAccount_.ohosAccountStatus_);
    return true;
}

/**
 * Handle device account switch event.
 *
 * @param None
 * @return None
 */
void OhosAccountManager::HandleDevAccountSwitchEvent()
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);
    eventMap_.clear();
    eventFuncMap_.clear();

    // Re-Init
    if (!OnInitialize()) {
        ACCOUNT_LOGE("Handle dev Account SwitchEvent failed");
    }
}

void OhosAccountManager::ReportPublishFailureEvent(std::int32_t errCode, std::int32_t oldStatus)
{
    HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCOUNT, "AccountServicePublishEventFailed",
        HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_TYPE", errCode, "OLD_STATE", oldStatus,
        "NEW_STATE", currentAccount_.ohosAccountStatus_, "DEVICE_MODE", currentAccount_.userId_);
}
} // namespace AccountSA
} // namespace OHOS

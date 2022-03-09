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

#include "ohos_account_manager.h"
#include <cerrno>
#include <dirent.h>
#include <iomanip>
#include <sstream>
#include <sys/types.h>
#include "account_event_provider.h"
#include "account_helper_data.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_mgr_service.h"
#include "common_event_support.h"
#include "hisysevent.h"
#include "ipc_skeleton.h"
#include "mbedtls/sha256.h"
#include "system_ability_definition.h"

using namespace OHOS::EventFwk;

namespace OHOS {
namespace AccountSA {
namespace {
constexpr std::int32_t MAX_RETRY_TIMES = 2; // give another chance when json file corrupted
constexpr std::uint32_t MAX_NAME_LENGTH = 256;
constexpr std::uint32_t MAX_UID_LENGTH = 512;
constexpr std::uint32_t HASH_LENGTH = 32;
constexpr std::uint32_t OHOS_ACCOUNT_UDID_LENGTH = HASH_LENGTH * 2;
constexpr std::uint32_t WIDTH_FOR_HEX = 2;
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

std::string GenerateOhosUdidWithSha256(const std::string &name, const std::string &uid)
{
    if (name.empty() || name.length() > MAX_NAME_LENGTH) {
        ACCOUNT_LOGE("input name empty or too long, length %{public}zu", name.length());
        return std::string("");
    }

    if (uid.empty() || uid.length() > MAX_UID_LENGTH) {
        ACCOUNT_LOGE("input uid empty or too long, length %{public}zu", uid.length());
        return std::string("");
    }

    unsigned char hash[HASH_LENGTH] = { 0 };
    mbedtls_sha256_context context;
    mbedtls_sha256_init(&context);
    mbedtls_sha256_starts_ret(&context, 0);

    std::string plainStr = name + uid;
    mbedtls_sha256_update_ret(&context, (const unsigned char*)plainStr.c_str(), plainStr.length());
    mbedtls_sha256_finish_ret(&context, hash);
    mbedtls_sha256_free(&context);

    std::stringstream ss;
    for (std::uint32_t i = 0; i < HASH_LENGTH; ++i) {
        ss << std::hex << std::uppercase << std::setw(WIDTH_FOR_HEX)
            << std::setfill('0') << std::uint16_t(hash[i]);
    }

    std::string ohosUidStr;
    ss >> ohosUidStr;
    return ohosUidStr;
}

std::int32_t GetCallingUserID()
{
    std::int32_t callingUId = IPCSkeleton::GetCallingUid();
    return (callingUId / UID_TRANSFORM_DIVISOR);
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
 */
bool OhosAccountManager::ClearOhosAccount(AccountInfo &curOhosAccountInfo, std::int32_t clrStatus) const
{
    curOhosAccountInfo.clear(clrStatus);
    ErrCode errCode = dataDealer_->AccountInfoToJson(curOhosAccountInfo);
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
bool OhosAccountManager::SaveOhosAccountInfo(AccountInfo &ohosAccountInfo) const
{
    ErrCode errCode = dataDealer_->AccountInfoToJson(ohosAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("AccountInfoToJson error.");
        return false;
    }
    return true;
}

/**
 * Get current account information.
 *
 * @return current account information.
 */
AccountInfo OhosAccountManager::GetCurrentOhosAccountInfo()
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);

    AccountInfo currOhosAccountInfo;
    std::int32_t callingUserId = GetCallingUserID();
    if (dataDealer_->AccountInfoFromJson(currOhosAccountInfo, callingUserId) != ERR_OK) {
        ACCOUNT_LOGE("get current ohos account info failed, callingUserId %{public}d.", callingUserId);
        currOhosAccountInfo.clear();
    }
    return currOhosAccountInfo;
}

/**
 * Get current account state.
 *
 * @return current account state id.
 */
std::int32_t OhosAccountManager::GetCurrentOhosAccountState()
{
    AccountInfo currOhosAccountInfo = GetCurrentOhosAccountInfo();
    return currOhosAccountInfo.ohosAccountStatus_;
}

/**
 * Process an account event.
 * @param curOhosAccount current ohos account info
 * @param eventStr ohos account state change event
 * @return true if the processing was completed, otherwise false
 */
bool OhosAccountManager::HandleEvent(AccountInfo &curOhosAccount, const std::string &eventStr)
{
    auto iter = eventMap_.find(eventStr);
    if (iter == eventMap_.end()) {
        ACCOUNT_LOGE("invalid event: %{public}s", eventStr.c_str());
        return false;
    }

    int event = iter->second;
    accountState_->SetAccountState(curOhosAccount.ohosAccountStatus_);
    bool ret = accountState_->StateChangeProcess(event);
    if (!ret) {
        ACCOUNT_LOGE("Handle event %{public}d failed", event);
        return false;
    }
    std::int32_t newState = accountState_->GetAccountState();
    if (newState != curOhosAccount.ohosAccountStatus_) {
        HiviewDFX::HiSysEvent::Write("OS_ACCOUNT", "OHOS_ACCOUNT_STATE_MACHINE_EVENT",
            HiviewDFX::HiSysEvent::EventType::FAULT, "USER_ID", curOhosAccount.userId_,
            "OPERATION_TYPE", event, "OLD_STATE", curOhosAccount.ohosAccountStatus_, "NEW_STATE", newState);
        curOhosAccount.ohosAccountStatus_ = newState;
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

    std::int32_t callingUserId = GetCallingUserID();
    AccountInfo currOhosAccountInfo;
    if (dataDealer_->AccountInfoFromJson(currOhosAccountInfo, callingUserId) != ERR_OK) {
        ACCOUNT_LOGE("get current ohos account info failed, callingUserId %{public}d.", callingUserId);
        return false;
    }

    // current local user cannot be bound again when it has already been bound to an ohos account
    if (currOhosAccountInfo.ohosAccountStatus_ == ACCOUNT_STATE_LOGIN) {
        ACCOUNT_LOGE("current account has already been bounded. callingUserId %{public}d.", callingUserId);
        return false;
    }

    // traversal check
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(name, uid);
    bool ret = CheckOhosAccountCanBind(ohosAccountUid);
    if (!ret) {
        ACCOUNT_LOGE("check can be bound failed, callingUserId %{public}d, ohosAccountUid %{public}s.",
            callingUserId, ohosAccountUid.c_str());
        return false;
    }

    std::int32_t oldStatus = currOhosAccountInfo.ohosAccountStatus_;
    ret = HandleEvent(currOhosAccountInfo, eventStr); // update account status
    if (!ret) {
        ACCOUNT_LOGE("HandleEvent %{public}s failed! callingUserId %{public}d, ohosAccountUid %{public}s.",
            eventStr.c_str(), callingUserId, ohosAccountUid.c_str());
        return false;
    }

    // update account info
    currOhosAccountInfo.ohosAccountName_ = name;
    currOhosAccountInfo.ohosAccountUid_ = ohosAccountUid;
    currOhosAccountInfo.bindTime_ = std::time(nullptr);
    currOhosAccountInfo.userId_ = callingUserId;
    ret = SaveOhosAccountInfo(currOhosAccountInfo);
    if (!ret) {
        ACCOUNT_LOGE("SaveOhosAccountInfo failed! callingUserId %{public}d, ohosAccountUid %{public}s.",
            callingUserId, ohosAccountUid.c_str());
        return false;
    }

    // publish event
    bool errCode = AccountEventProvider::EventPublish(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGIN);
    if (!errCode) {
        ACCOUNT_LOGE("publish ohos account login event failed! callingUserId %{public}d, ohosAccountUid %{public}s.",
            callingUserId, ohosAccountUid.c_str());
        ReportPublishFailureEvent(errCode, oldStatus, currOhosAccountInfo);
        return false;
    }
    ACCOUNT_LOGI("LoginOhosAccount success! callingUserId %{public}d, ohosAccountUid %{public}s.",
        callingUserId, ohosAccountUid.c_str());
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

    std::int32_t callingUserId = GetCallingUserID();
    AccountInfo currentAccount;
    if (!GetCurOhosAccountAndCheckMatch(currentAccount, name, uid, callingUserId)) {
        ACCOUNT_LOGE("check match failed, callingUserId %{public}d, ohosAccountUid %{public}s.",
            callingUserId, uid.c_str());
        return false;
    }

    std::int32_t oldStatus = currentAccount.ohosAccountStatus_;
    bool ret = HandleEvent(currentAccount, eventStr); // update account status
    if (!ret) {
        ACCOUNT_LOGE("HandleEvent %{public}s failed, callingUserId %{public}d, ohosAccountUid %{public}s.",
            eventStr.c_str(), callingUserId, uid.c_str());
        return false;
    }

    ret = ClearOhosAccount(currentAccount); // clear account info with ACCOUNT_STATE_UNBOUND
    if (!ret) {
        ACCOUNT_LOGE("ClearOhosAccount failed! callingUserId %{public}d, ohosAccountUid %{public}s.",
            callingUserId, uid.c_str());
        return false;
    }

    ret = AccountEventProvider::EventPublish(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT);
    if (!ret) {
        ACCOUNT_LOGE("publish account logout event failed, callingUserId %{public}d, ohosAccountUid %{public}s.",
            callingUserId, uid.c_str());
        ReportPublishFailureEvent(ret, oldStatus, currentAccount);
        return false;
    }
    ACCOUNT_LOGI("LogoutOhosAccount success, callingUserId %{public}d, ohosAccountUid %{public}s.",
        callingUserId, uid.c_str());
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

    std::int32_t callingUserId = GetCallingUserID();
    AccountInfo currentAccount;
    if (!GetCurOhosAccountAndCheckMatch(currentAccount, name, uid, callingUserId)) {
        ACCOUNT_LOGE("check match failed, callingUserId %{public}d, ohosAccountUid %{public}s.",
            callingUserId, uid.c_str());
        return false;
    }

    std::int32_t oldStatus = currentAccount.ohosAccountStatus_;
    bool ret = HandleEvent(currentAccount, eventStr); // update account status
    if (!ret) {
        ACCOUNT_LOGE("HandleEvent %{public}s failed, callingUserId %{public}d, ohosAccountUid %{public}s.",
            eventStr.c_str(), callingUserId, uid.c_str());
        return false;
    }

    ret = ClearOhosAccount(currentAccount, ACCOUNT_STATE_LOGOFF); // clear account info with ACCOUNT_STATE_LOGOFF
    if (!ret) {
        ACCOUNT_LOGE("ClearOhosAccount failed, callingUserId %{public}d, ohosAccountUid %{public}s.",
            callingUserId, uid.c_str());
        return false;
    }
    bool errCode = AccountEventProvider::EventPublish(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOFF);
    if (errCode != true) {
        ACCOUNT_LOGE("publish account logoff event failed, callingUserId %{public}d, ohosAccountUid %{public}s.",
            callingUserId, uid.c_str());
        ReportPublishFailureEvent(errCode, oldStatus, currentAccount);
        return false;
    }
    ACCOUNT_LOGI("LogoffOhosAccount success, callingUserId %{public}d, ohosAccountUid %{public}s.",
        callingUserId, uid.c_str());
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

    std::int32_t callingUserId = GetCallingUserID();
    AccountInfo currentOhosAccount;
    if (!GetCurOhosAccountAndCheckMatch(currentOhosAccount, name, uid, callingUserId)) {
        ACCOUNT_LOGE("check match failed, callingUserId %{public}d, ohosAccountUid %{public}s.",
            callingUserId, uid.c_str());
        return false;
    }

    std::int32_t oldStatus = currentOhosAccount.ohosAccountStatus_;
    bool ret = HandleEvent(currentOhosAccount, eventStr); // update account status
    if (!ret) {
        ACCOUNT_LOGE("HandleEvent %{public}s failed, callingUserId %{public}d, ohosAccountUid %{public}s.",
            eventStr.c_str(), callingUserId, uid.c_str());
        return false;
    }

    ret = SaveOhosAccountInfo(currentOhosAccount);
    if (!ret) {
        // moving on even if failed to update account info
        ACCOUNT_LOGW("SaveOhosAccountInfo failed, callingUserId %{public}d, ohosAccountUid %{public}s.",
            callingUserId, uid.c_str());
    }
    bool errCode = AccountEventProvider::EventPublish(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_TOKEN_INVALID);
    if (errCode != true) {
        ACCOUNT_LOGE("publish token invalid event failed, callingUserId %{public}d, ohosAccountUid %{public}s.",
            callingUserId, uid.c_str());
        ReportPublishFailureEvent(errCode, oldStatus, currentOhosAccount);
        return false;
    }
    ACCOUNT_LOGI("success, callingUserId %{public}d, ohosAccountUid %{public}s.", callingUserId, uid.c_str());
    return true;
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

    dataDealer_ = std::make_unique<OhosAccountDataDeal>(ACCOUNT_CFG_DIR_ROOT_PATH);

    std::int32_t tryTimes = 0;
    while (tryTimes < MAX_RETRY_TIMES) {
        tryTimes++;
        ErrCode errCode = dataDealer_->Init(DEVICE_ACCOUNT_OWNER);
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

void OhosAccountManager::ReportPublishFailureEvent(std::int32_t errCode,
                                                   std::int32_t oldStatus,
                                                   const AccountInfo &account)
{
    HiviewDFX::HiSysEvent::Write("OS_ACCOUNT", "PUBLISH_COMMON_EVENT_FAILED",
        HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_TYPE", errCode, "OLD_STATE", oldStatus,
        "NEW_STATE", account.ohosAccountStatus_, "USER_ID", account.userId_);
}

bool OhosAccountManager::CheckOhosAccountCanBind(const std::string &newOhosUid) const
{
    if (newOhosUid.length() != OHOS_ACCOUNT_UDID_LENGTH) {
        ACCOUNT_LOGE("newOhosUid invalid length, %{public}s.", newOhosUid.c_str());
        return false;
    }

    // check whether newOhosUid has been already bound to another account or not
    DIR* rootDir = opendir(ACCOUNT_CFG_DIR_ROOT_PATH.c_str());
    if (rootDir == nullptr) {
        ACCOUNT_LOGE("cannot open dir %{public}s, err %{public}d.", ACCOUNT_CFG_DIR_ROOT_PATH.c_str(), errno);
        return false;
    }
    struct dirent* curDir = nullptr;
    while ((curDir = readdir(rootDir)) != nullptr) {
        std::string curDirName(curDir->d_name);
        if (curDirName == "." || curDirName == ".." || curDir->d_type != DT_DIR) {
            continue;
        }

        AccountInfo curInfo;
        std::stringstream sstream;
        sstream << curDirName;
        std::int32_t userId = -1;
        sstream >> userId;
        if (dataDealer_->AccountInfoFromJson(curInfo, userId) != ERR_OK) {
            ACCOUNT_LOGI("get ohos account info from user %{public}s failed.", curDirName.c_str());
            continue;
        }

        if (curInfo.ohosAccountStatus_ != ACCOUNT_STATE_LOGIN) {
            continue; // account not bind, skip check
        }

        if (newOhosUid == curInfo.ohosAccountUid_) {
            ACCOUNT_LOGE("cannot bind, it has been bound with local account %{public}d.", curInfo.userId_);
            (void)closedir(rootDir);
            return false;
        }
    }

    (void)closedir(rootDir);
    return true;
}

bool OhosAccountManager::GetCurOhosAccountAndCheckMatch(AccountInfo &curOhosAccountInfo,
                                                        const std::string &inputName,
                                                        const std::string &inputUid,
                                                        const std::int32_t callingUserId) const
{
    if (dataDealer_->AccountInfoFromJson(curOhosAccountInfo, callingUserId) != ERR_OK) {
        ACCOUNT_LOGE("cannot read from config, inputName %{public}s.", inputName.c_str());
        return false;
    }

    std::string ohosAccountUid = GenerateOhosUdidWithSha256(inputName, inputUid);
    if (inputName != curOhosAccountInfo.ohosAccountName_ || ohosAccountUid != curOhosAccountInfo.ohosAccountUid_) {
        ACCOUNT_LOGE("account name %{public}s or ohosAccountUid %{public}s mismatch, calling user %{public}d.",
            inputName.c_str(), ohosAccountUid.c_str(), callingUserId);
        return false;
    }
    return true;
}
} // namespace AccountSA
} // namespace OHOS

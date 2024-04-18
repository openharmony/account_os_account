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

#include "ohos_account_manager.h"
#include <cerrno>
#include <dirent.h>
#include <dlfcn.h>
#include <iomanip>
#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>
#include <mbedtls/pkcs5.h>
#include <sys/types.h>
#include <sstream>
#include <string_ex.h>
#include "accesstoken_kit.h"
#include "account_constants.h"
#include "account_event_provider.h"
#include "account_event_subscribe.h"
#include "account_helper_data.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_mgr_service.h"
#include "account_permission_manager.h"
#ifdef HAS_CES_PART
#include "common_event_support.h"
#endif // HAS_CES_PART
#include "account_hisysevent_adapter.h"
#include "distributed_account_subscribe_manager.h"
#include "ipc_skeleton.h"
#include "mbedtls/sha256.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"

#ifdef HAS_CES_PART
using namespace OHOS::EventFwk;
#endif // HAS_CES_PART

namespace OHOS {
namespace AccountSA {
namespace {
constexpr unsigned int ITERATE_CNT = 1000;
constexpr std::int32_t OUTPUT_LENGTH_IN_BYTES = 32;
constexpr std::uint8_t TWO_BYTE_MASK = 0xF0;
constexpr std::int32_t MAX_RETRY_TIMES = 2; // give another chance when json file corrupted
constexpr std::uint32_t MAX_NAME_LENGTH = 256;
constexpr std::uint32_t MAX_UID_LENGTH = 512;
constexpr std::uint32_t HASH_LENGTH = 32;
constexpr std::uint32_t WIDTH_FOR_HEX = 2;
constexpr std::uint32_t OHOS_ACCOUNT_UDID_LENGTH = HASH_LENGTH * 2;
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

bool GetCallerBundleName(std::string &bundleName)
{
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    Security::AccessToken::AccessTokenID tokenId = fullTokenId & TOKEN_ID_LOWMASK;
    Security::AccessToken::ATokenTypeEnum tokenType = Security::AccessToken::AccessTokenKit::GetTokenType(tokenId);
    if ((tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) &&
        (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId))) {
        Security::AccessToken::HapTokenInfo hapTokenInfo;
        int result = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo);
        if (result) {
            ACCOUNT_LOGE("failed to get hap token info, result = %{public}d", result);
            return false;
        }
        bundleName = hapTokenInfo.bundleName;
    }
    return true;
}

std::string ReturnOhosUdidWithSha256(const std::string &uid)
{
    unsigned char hash[HASH_LENGTH] = {0};
    mbedtls_sha256_context context;
    mbedtls_sha256_init(&context);
    mbedtls_sha256_starts(&context, 0);

    std::string plainStr = uid;
    mbedtls_sha256_update(&context, reinterpret_cast<const unsigned char *>(plainStr.c_str()), plainStr.length());
    mbedtls_sha256_finish(&context, hash);
    mbedtls_sha256_free(&context);

    std::stringstream ss;
    for (std::uint32_t i = 0; i < HASH_LENGTH; ++i) {
        ss << std::hex << std::uppercase << std::setw(WIDTH_FOR_HEX) << std::setfill('0') << std::uint16_t(hash[i]);
    }
    std::string ohosUidStr;
    ss >> ohosUidStr;
    return ohosUidStr;
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

    std::string bundleName = "";
    if (!GetCallerBundleName(bundleName)) {
        ACCOUNT_LOGE("GetCallerBundleName failed");
        return std::string("");
    }
    if (bundleName.empty()) {
        return ReturnOhosUdidWithSha256(uid);
    }
    unsigned char newId[OUTPUT_LENGTH_IN_BYTES + 1] = {};
    mbedtls_md_context_t md_context;
    mbedtls_md_init(&md_context);
    const mbedtls_md_info_t *mbedtls_sha256_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_setup(&md_context, mbedtls_sha256_info, 1);
    if (ret != 0) {
        ACCOUNT_LOGE("mbedtls_md_setup failed");
        mbedtls_md_free(&md_context);
        return std::string("");
    }
    ret = mbedtls_pkcs5_pbkdf2_hmac(&md_context, reinterpret_cast<const unsigned char *>(uid.c_str()), uid.size(),
        reinterpret_cast<const unsigned char *>(bundleName.c_str()), bundleName.size(), ITERATE_CNT,
        OUTPUT_LENGTH_IN_BYTES, newId);
    if (ret != 0) {
        ACCOUNT_LOGE("mbedtls_pkcs5_pbkdf2_hmac failed");
        mbedtls_md_free(&md_context);
        return std::string("");
    }
    mbedtls_md_free(&md_context);
    std::string ohosUidStr;
    for (int i = 0; i < OUTPUT_LENGTH_IN_BYTES; i++) {
        if ((newId[i] & TWO_BYTE_MASK) == 0) {
            ohosUidStr.append("0");
        }
        ohosUidStr.append(DexToHexString(newId[i], true));
    }
    return ohosUidStr;
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
    OhosAccountInfo ohosAccountInfo;
    ohosAccountInfo.name_ = name;
    ohosAccountInfo.uid_ = uid;
    std::int32_t userId = AccountMgrService::GetInstance().GetCallingUserID();
    return (this->*(itFunc->second))(userId, ohosAccountInfo, eventStr);
}

bool OhosAccountManager::OhosAccountStateChange(
    const int32_t userId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    auto itFunc = eventFuncMap_.find(eventStr);
    if (itFunc == eventFuncMap_.end()) {
        ACCOUNT_LOGE("invalid event: %{public}s", eventStr.c_str());
        return false;
    }
    return (this->*(itFunc->second))(userId, ohosAccountInfo, eventStr);
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
 * @param ohosAccountInfo distribute account information.
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
    std::int32_t callingUserId = AccountMgrService::GetInstance().GetCallingUserID();
    if (dataDealer_->AccountInfoFromJson(currOhosAccountInfo, callingUserId) != ERR_OK) {
        ACCOUNT_LOGE("get current ohos account info failed, callingUserId %{public}d.", callingUserId);
        currOhosAccountInfo.clear();
    }
    return currOhosAccountInfo;
}

ErrCode OhosAccountManager::GetAccountInfoByUserId(std::int32_t userId, AccountInfo &info)
{
    if (userId == 0) {
        userId = AccountMgrService::GetInstance().GetCallingUserID();
    }
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);

    ErrCode ret = dataDealer_->AccountInfoFromJson(info, userId);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("get ohos account info failed, userId %{public}d.", userId);
        info.clear();
        return ret;
    }
    return ERR_OK;
}

ErrCode OhosAccountManager::SubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
    const sptr<IRemoteObject> &eventListener)
{
    return subscribeManager_.SubscribeDistributedAccountEvent(type, eventListener);
}

ErrCode OhosAccountManager::UnsubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
    const sptr<IRemoteObject> &eventListener)
{
    return subscribeManager_.UnsubscribeDistributedAccountEvent(type, eventListener);
}

/**
 * Get current account state.
 *
 * @return current account state id.
 */
std::int32_t OhosAccountManager::GetCurrentOhosAccountState()
{
    AccountInfo currOhosAccountInfo = GetCurrentOhosAccountInfo();
    return currOhosAccountInfo.ohosAccountInfo_.status_;
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
    accountState_->SetAccountState(curOhosAccount.ohosAccountInfo_.status_);
    bool ret = accountState_->StateChangeProcess(event);
    if (!ret) {
        ACCOUNT_LOGE("Handle event %{public}d failed", event);
        return false;
    }
    std::int32_t newState = accountState_->GetAccountState();
    if (newState != curOhosAccount.ohosAccountInfo_.status_) {
        ReportOhosAccountStateChange(curOhosAccount.userId_, event, curOhosAccount.ohosAccountInfo_.status_, newState);
        curOhosAccount.ohosAccountInfo_.status_ = newState;
    }
    return true;
}

/**
 * login ohos (for distributed network) account.
 *
 * @param userId target local account id.
 * @param ohosAccountInfo ohos account information
 * @param eventStr ohos account state change event
 * @return true if the processing was completed, otherwise false
 */
bool OhosAccountManager::LoginOhosAccount(
    const int32_t userId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);

    AccountInfo currAccountInfo;
    if (dataDealer_->AccountInfoFromJson(currAccountInfo, userId) != ERR_OK) {
        ACCOUNT_LOGE("get current ohos account info failed, userId %{public}d.", userId);
        return false;
    }
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(ohosAccountInfo.name_, ohosAccountInfo.uid_);
    // current local user cannot be bound again when it has already been bound to an ohos account
    if (!CheckOhosAccountCanBind(currAccountInfo, ohosAccountInfo, ohosAccountUid)) {
        ACCOUNT_LOGE("check can be bound failed, userId %{public}d.", userId);
        return false;
    }

#ifdef HAS_CES_PART
    // check whether need to publish event or not
    bool isPubLoginEvent = false;
    if (currAccountInfo.ohosAccountInfo_.status_ != ACCOUNT_STATE_LOGIN) {
        isPubLoginEvent = true;
    }
#endif // HAS_CES_PART
    // update account status
    if (!HandleEvent(currAccountInfo, eventStr)) {
        ACCOUNT_LOGE("HandleEvent %{public}s failed! userId %{public}d.", eventStr.c_str(), userId);
        return false;
    }

    // update account info
    currAccountInfo.ohosAccountInfo_ = ohosAccountInfo;
    currAccountInfo.ohosAccountInfo_.SetRawUid(ohosAccountInfo.uid_);
    currAccountInfo.ohosAccountInfo_.uid_ = ohosAccountUid;
    currAccountInfo.ohosAccountInfo_.status_ = ACCOUNT_STATE_LOGIN;
    currAccountInfo.bindTime_ = std::time(nullptr);
    currAccountInfo.ohosAccountInfo_.callingUid_ = IPCSkeleton::GetCallingUid();

    if (!SaveOhosAccountInfo(currAccountInfo)) {
        ACCOUNT_LOGE("SaveOhosAccountInfo failed! userId %{public}d.", userId);
        return false;
    }
    subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN);

#ifdef HAS_CES_PART
    if (!isPubLoginEvent) {
        AccountEventProvider::EventPublish(EventFwk::CommonEventSupport::COMMON_EVENT_USER_INFO_UPDATED,
            userId, nullptr);
        (void)CreateCommonEventSubscribe();
        return true;
    }
    AccountEventProvider::EventPublish(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGIN, userId, nullptr);
    AccountEventProvider::EventPublish(
        EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN, userId, nullptr);
#else  // HAS_CES_PART
    ACCOUNT_LOGI("No common event part, publish nothing!");
#endif // HAS_CES_PART
    (void)CreateCommonEventSubscribe();
    ACCOUNT_LOGI("LoginOhosAccount success! userId %{public}d", userId);
    return true;
}

/**
 * logout ohos (for distributed network) account.
 *
 * @param userId target local account id.
 * @param ohosAccountInfo ohos account information
 * @param eventStr ohos account state change event
 * @return true if the processing was completed, otherwise false
 */
bool OhosAccountManager::LogoutOhosAccount(
    const int32_t userId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);

    AccountInfo currentAccount;
    if (!GetCurOhosAccountAndCheckMatch(currentAccount, ohosAccountInfo.name_,
                                        ohosAccountInfo.uid_, userId)) {
        ACCOUNT_LOGE("check match failed, userId %{public}d.", userId);
        return false;
    }

    bool ret = HandleEvent(currentAccount, eventStr); // update account status
    if (!ret) {
        ACCOUNT_LOGE("HandleEvent %{public}s failed, userId %{public}d.", eventStr.c_str(), userId);
        return false;
    }

    ret = ClearOhosAccount(currentAccount); // clear account info with ACCOUNT_STATE_UNBOUND
    if (!ret) {
        ACCOUNT_LOGE("ClearOhosAccount failed! userId %{public}d.", userId);
        return false;
    }
    subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT);

#ifdef HAS_CES_PART
    AccountEventProvider::EventPublish(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT, userId, nullptr);
    AccountEventProvider::EventPublish(
        EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT, userId, nullptr);
#else  // HAS_CES_PART
    ACCOUNT_LOGI("No common event part! Publish nothing!");
#endif // HAS_CES_PART
    ACCOUNT_LOGI("LogoutOhosAccount success, userId %{public}d.", userId);
    return true;
}

/**
 * logoff ohos (for distributed network) account.
 *
 * @param userId target local account id.
 * @param ohosAccountInfo ohos account information
 * @param eventStr ohos account state change event
 * @return true if the processing was completed, otherwise false
 */
bool OhosAccountManager::LogoffOhosAccount(
    const int32_t userId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);

    AccountInfo currentAccount;
    if (!GetCurOhosAccountAndCheckMatch(currentAccount, ohosAccountInfo.name_, ohosAccountInfo.uid_, userId)) {
        ACCOUNT_LOGE("check match failed, userId %{public}d.", userId);
        return false;
    }

    bool ret = HandleEvent(currentAccount, eventStr); // update account status
    if (!ret) {
        ACCOUNT_LOGE("HandleEvent %{public}s failed, userId %{public}d.", eventStr.c_str(), userId);
        return false;
    }

    ret = ClearOhosAccount(currentAccount); // clear account info with ACCOUNT_STATE_UNBOUND
    if (!ret) {
        ACCOUNT_LOGE("ClearOhosAccount failed, userId %{public}d.", userId);
        return false;
    }
    subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOFF);

#ifdef HAS_CES_PART
    AccountEventProvider::EventPublish(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOFF, userId, nullptr);
    AccountEventProvider::EventPublish(
        EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOFF, userId, nullptr);
#else  // HAS_CES_PART
    ACCOUNT_LOGI("No common event part, publish nothing for logoff!");
#endif // HAS_CES_PART
    ACCOUNT_LOGI("LogoffOhosAccount success, userId %{public}d.", userId);
    return true;
}

/**
 * Handle token_invalid event.
 *
 * @param userId target local account id.
 * @param ohosAccountInfo ohos account information
 * @param eventStr ohos account state change event
 * @return true if the processing was completed, otherwise false
 */
bool OhosAccountManager::HandleOhosAccountTokenInvalidEvent(
    const int32_t userId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);

    AccountInfo currentOhosAccount;
    if (!GetCurOhosAccountAndCheckMatch(currentOhosAccount, ohosAccountInfo.name_,
                                        ohosAccountInfo.uid_, userId)) {
        ACCOUNT_LOGE("check match failed, userId %{public}d.", userId);
        return false;
    }

    bool ret = HandleEvent(currentOhosAccount, eventStr); // update account status
    if (!ret) {
        ACCOUNT_LOGE("HandleEvent %{public}s failed, userId %{public}d.", eventStr.c_str(), userId);
        return false;
    }

    ret = SaveOhosAccountInfo(currentOhosAccount);
    if (!ret) {
        // moving on even if failed to update account info
        ACCOUNT_LOGW("SaveOhosAccountInfo failed, userId %{public}d.", userId);
    }
    subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::TOKEN_INVALID);

#ifdef HAS_CES_PART
    AccountEventProvider::EventPublish(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_TOKEN_INVALID,
        userId, nullptr);
    AccountEventProvider::EventPublish(
        EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_TOKEN_INVALID, userId, nullptr);
#else  // HAS_CES_PART
    ACCOUNT_LOGI("No common event part, publish nothing for token invalid event.");
#endif // HAS_CES_PART
    ACCOUNT_LOGI("success, userId %{public}d.", userId);
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

OhosAccountManager &OhosAccountManager::GetInstance()
{
    static OhosAccountManager *instance = new (std::nothrow) OhosAccountManager();
    return *instance;
}

OhosAccountManager::OhosAccountManager() : subscribeManager_(DistributedAccountSubscribeManager::GetInstance())
{
    accountState_ = std::make_unique<AccountStateMachine>();
    dataDealer_ = std::make_unique<OhosAccountDataDeal>(ACCOUNT_CFG_DIR_ROOT_PATH);
}

/**
 * Init ohos account manager.
 *
 */
bool OhosAccountManager::OnInitialize()
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);
    if (isInit_) {
        return true;
    }
    BuildEventsMapper();

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
    isInit_ = true;
    return true;
}

#ifdef HAS_CES_PART
bool OhosAccountManager::CreateCommonEventSubscribe()
{
    if (accountEventSubscribe_ == nullptr) {
        AccountCommonEventCallback callback = {
            std::bind(&OhosAccountManager::OnPackageRemoved, this, std::placeholders::_1)};
        accountEventSubscribe_ = std::make_shared<AccountEventSubscriber>(callback);
        if (!accountEventSubscribe_->CreateEventSubscribe()) {
            ACCOUNT_LOGE("CreateEventSubscribe is failed");
            return false;
        }
    }
    return true;
}

void OhosAccountManager::OnPackageRemoved(const std::int32_t callingUid)
{
    std::vector<OsAccountInfo> osAccountInfos;
    (void)IInnerOsAccountManager::GetInstance().QueryAllCreatedOsAccounts(osAccountInfos);
    for (const auto &info : osAccountInfos) {
        AccountInfo accountInfo;
        (void)GetAccountInfoByUserId(info.GetLocalId(), accountInfo);
        if (accountInfo.ohosAccountInfo_.callingUid_ == callingUid) {
            (void)ClearOhosAccount(accountInfo);
            AccountEventProvider::EventPublish(
                EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT, info.GetLocalId(), nullptr);
            AccountEventProvider::EventPublish(
                EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT, info.GetLocalId(), nullptr);
        }
    }
}
#endif // HAS_CES_PART

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

bool OhosAccountManager::CheckOhosAccountCanBind(const AccountInfo &currAccountInfo,
    const OhosAccountInfo &newOhosAccountInfo, const std::string &newOhosUid) const
{
    if (newOhosUid.length() != OHOS_ACCOUNT_UDID_LENGTH) {
        ACCOUNT_LOGE("newOhosUid invalid length, %{public}s.", newOhosUid.c_str());
        return false;
    }

    // check if current account has been bound or not
    if ((currAccountInfo.ohosAccountInfo_.status_ == ACCOUNT_STATE_LOGIN) &&
        ((currAccountInfo.ohosAccountInfo_.uid_ != newOhosUid) ||
        (currAccountInfo.ohosAccountInfo_.name_ != newOhosAccountInfo.name_))) {
        ACCOUNT_LOGE("current account has already been bounded. callingUserId %{public}d.",
            AccountMgrService::GetInstance().GetCallingUserID());
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

        if (curInfo.ohosAccountInfo_.status_ != ACCOUNT_STATE_LOGIN) {
            continue; // account not bind, skip check
        }
    }

    (void)closedir(rootDir);
    return true;
}

bool OhosAccountManager::GetCurOhosAccountAndCheckMatch(AccountInfo &curAccountInfo,
                                                        const std::string &inputName,
                                                        const std::string &inputUid,
                                                        const std::int32_t callingUserId) const
{
    if (dataDealer_->AccountInfoFromJson(curAccountInfo, callingUserId) != ERR_OK) {
        ACCOUNT_LOGE("cannot read from config, inputName %{public}s.", inputName.c_str());
        return false;
    }

    std::string ohosAccountUid = GenerateOhosUdidWithSha256(inputName, inputUid);
    if (inputName != curAccountInfo.ohosAccountInfo_.name_ ||
        ohosAccountUid != curAccountInfo.ohosAccountInfo_.uid_) {
        ACCOUNT_LOGE("account name %{public}s or ohosAccountUid %{public}s mismatch, calling user %{public}d.",
            inputName.c_str(), ohosAccountUid.c_str(), callingUserId);
        return false;
    }
    return true;
}
} // namespace AccountSA
} // namespace OHOS

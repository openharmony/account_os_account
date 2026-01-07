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

#include "ohos_account_manager.h"
#include <cerrno>
#include <codecvt>
#include <dirent.h>
#include <dlfcn.h>
#include <iomanip>
#include <locale>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/types.h>
#include <sys/types.h>
#include <sstream>
#include <string_ex.h>
#include "accesstoken_kit.h"
#include "account_constants.h"
#include "account_event_provider.h"
#include "account_event_subscribe.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_mgr_service.h"
#include "account_permission_manager.h"
#ifdef HAS_CES_PART
#include "common_event_support.h"
#endif // HAS_CES_PART
#include "account_hisysevent_adapter.h"
#include "device_account_info.h"
#include "distributed_account_subscribe_manager.h"
#include "ipc_skeleton.h"
#include "ohos_account_constants.h"
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
constexpr unsigned char UTF8_SINGLE_BYTE_MASK = 0x80;
constexpr unsigned char UTF8_DOUBLE_BYTE_MASK = 0xE0;
constexpr unsigned char UTF8_TRIPLE_BYTE_MASK = 0xF0;
constexpr unsigned char UTF8_QUAD_BYTE_MASK = 0xF8;
constexpr unsigned char UTF8_SINGLE_BYTE_PREFIX = 0x00; // 00000000
constexpr unsigned char UTF8_DOUBLE_BYTE_PREFIX = 0xC0; // 11000000
constexpr unsigned char UTF8_TRIPLE_BYTE_PREFIX = 0xE0; // 11100000
constexpr unsigned char UTF8_QUAD_BYTE_PREFIX = 0xF0;   // 11110000
constexpr size_t UTF8_SINGLE_BYTE_CHAR_LENGTH = 1;
constexpr size_t UTF8_DOUBLE_BYTE_CHAR_LENGTH = 2;
constexpr size_t UTF8_TRIPLE_BYTE_CHAR_LENGTH = 3;
constexpr size_t UTF8_QUAD_BYTE_CHAR_LENGTH = 4;
const char DEFAULT_ANON_STR[] = "**********";
constexpr int32_t INTERCEPT_HEAD_PART_LEN_FOR_NAME = 1;

std::string AnonymizeNameStr(const std::string& nameStr)
{
    if (nameStr.empty()) {
        return nameStr;
    }
    return nameStr.substr(0, INTERCEPT_HEAD_PART_LEN_FOR_NAME) + DEFAULT_ANON_STR;
}

bool GetCallerBundleName(std::string &bundleName, bool &isSystemApp)
{
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    Security::AccessToken::AccessTokenID tokenId = fullTokenId & TOKEN_ID_LOWMASK;
    Security::AccessToken::ATokenTypeEnum tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    isSystemApp = Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        Security::AccessToken::HapTokenInfo hapTokenInfo;
        int result = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo);
        if (result) {
            ACCOUNT_LOGE("Failed to get hap token info, result = %{public}d", result);
            return false;
        }
        bundleName = hapTokenInfo.bundleName;
    }
    return true;
}

std::string ReturnOhosUdidWithSha256(const std::string &uid)
{
    unsigned char hash[HASH_LENGTH] = {0};
    SHA256_CTX sha256Ctx;
    SHA256_Init(&sha256Ctx);
    SHA256_Update(&sha256Ctx, uid.c_str(), uid.length());
    SHA256_Final(hash, &sha256Ctx);

    std::stringstream ss;
    for (std::uint32_t i = 0; i < HASH_LENGTH; ++i) {
        ss << std::hex << std::uppercase << std::setw(WIDTH_FOR_HEX) << std::setfill('0') << std::uint16_t(hash[i]);
    }
    std::string ohosUidStr;
    ss >> ohosUidStr;
    return ohosUidStr;
}

std::string GenerateDVID(const std::string &bundleName, const std::string &uid)
{
    unsigned char newId[OUTPUT_LENGTH_IN_BYTES + 1] = {};
    EVP_MD *sha256Md = EVP_MD_fetch(nullptr, "SHA2-256", nullptr);
    if (sha256Md == nullptr) {
        ACCOUNT_LOGE("EVP_MD_fetch failed");
        return std::string("");
    }
    int ret = PKCS5_PBKDF2_HMAC(
        reinterpret_cast<const char *>(uid.c_str()), uid.size(),
        reinterpret_cast<const unsigned char *>(bundleName.c_str()), bundleName.size(),
        ITERATE_CNT,
        sha256Md,
        OUTPUT_LENGTH_IN_BYTES,
        newId);
    // When calling PKCS5_PBKDF2_HMAC, returning 1 indicates success, and returning 0 indicates failure
    if (ret != 1) {
        ACCOUNT_LOGE("EVP_PBKDF2 failed ret: %{public}d", ret);
        EVP_MD_free(sha256Md);
        return std::string("");
    }
    std::string ohosUidStr;
    for (int i = 0; i < OUTPUT_LENGTH_IN_BYTES; i++) {
        if ((newId[i] & TWO_BYTE_MASK) == 0) {
            ohosUidStr.append("0");
        }
        ohosUidStr.append(DexToHexString(newId[i], true));
    }
    EVP_MD_free(sha256Md);
    return ohosUidStr;
}

std::string GenerateOhosUdidWithSha256(const std::string &name, const std::string &uid)
{
    if (name.empty() || name.length() > MAX_NAME_LENGTH) {
        ACCOUNT_LOGE("Input name empty or too long, length %{public}zu", name.length());
        return std::string("");
    }

    if (uid.empty() || uid.length() > MAX_UID_LENGTH) {
        ACCOUNT_LOGE("Input uid empty or too long, length %{public}zu", uid.length());
        return std::string("");
    }

    return ReturnOhosUdidWithSha256(uid);
}
}

static ErrCode ProcDistributedAccountStateChange(
    OhosAccountManager *ptr, const std::int32_t userId, const OhosAccountInfo &info, const std::string &eventStr)
{
    static const std::map<std::string, OhosAccountEventFunc> eventFuncMap = {
        {
            OHOS_ACCOUNT_EVENT_LOGIN,
            [ptr] (const std::int32_t userId, const OhosAccountInfo &info, const std::string &eventStr) {
                return ptr->LoginOhosAccount(userId, info, eventStr);
            }
        },
        {
            OHOS_ACCOUNT_EVENT_LOGOUT,
            [ptr] (const std::int32_t userId, const OhosAccountInfo &info, const std::string &eventStr) {
                return ptr->LogoutOhosAccount(userId, info, eventStr);
            }
        },
        {
            OHOS_ACCOUNT_EVENT_LOGOFF,
            [ptr] (const std::int32_t userId, const OhosAccountInfo &info, const std::string &eventStr) {
                return ptr->LogoffOhosAccount(userId, info, eventStr);
            }
        },
        {
            OHOS_ACCOUNT_EVENT_TOKEN_INVALID,
            [ptr] (const std::int32_t userId, const OhosAccountInfo &info, const std::string &eventStr) {
                return ptr->HandleOhosAccountTokenInvalidEvent(userId, info, eventStr);
            }
        },
    };
    auto itFunc = eventFuncMap.find(eventStr);
    if (itFunc == eventFuncMap.end()) {
        ACCOUNT_LOGE("invalid event: %{public}s", eventStr.c_str());
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_SET_INFO, ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
            eventStr.c_str());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return (itFunc->second)(userId, info, eventStr);
}

/**
 * Ohos account state change.
 *
 * @param name ohos account name
 * @param uid ohos account uid
 * @param eventStr ohos account state change event
 * @return true if the processing was completed, otherwise false
 */
ErrCode OhosAccountManager::OhosAccountStateChange(const std::string &name, const std::string &uid,
    const std::string &eventStr)
{
    OhosAccountInfo ohosAccountInfo;
    ohosAccountInfo.name_ = name;
    ohosAccountInfo.uid_ = uid;
    std::int32_t userId = AccountMgrService::GetInstance().GetCallingUserID();
    return ProcDistributedAccountStateChange(this, userId, ohosAccountInfo, eventStr);
}

ErrCode OhosAccountManager::OhosAccountStateChange(
    const int32_t userId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    return ProcDistributedAccountStateChange(this, userId, ohosAccountInfo, eventStr);
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

ErrCode OhosAccountManager::QueryDistributedVirtualDeviceId(std::string &dvid)
{
    int32_t localId = AccountMgrService::GetInstance().GetCallingUserID();
    AccountInfo accountInfo;
    ErrCode errCode = GetAccountInfoByUserId(localId, accountInfo);
    if (errCode != ERR_OK) {
        REPORT_OHOS_ACCOUNT_FAIL(localId, Constants::OPERATION_GET_INFO, errCode, "Get ohos account info failed");
        ACCOUNT_LOGE("Get ohos account info failed, errcode=%{public}d, localId=%{public}d.", errCode, localId);
        return errCode;
    }
    OhosAccountInfo ohosAccountInfo = accountInfo.ohosAccountInfo_;
    if (ohosAccountInfo.uid_ == DEFAULT_OHOS_ACCOUNT_UID) {
        return ERR_OK;
    }
    std::string bundleName = "";
    bool isSystemApp = false;
    GetCallerBundleName(bundleName, isSystemApp);

    dvid = GenerateDVID(bundleName, ohosAccountInfo.GetRawUid());
    return ERR_OK;
}

ErrCode OhosAccountManager::QueryDistributedVirtualDeviceId(const std::string &bundleName, int32_t localId,
    std::string &dvid)
{
    dvid = "";
    AccountInfo accountInfo;
    ErrCode errCode = GetAccountInfoByUserId(localId, accountInfo);
    if (errCode != ERR_OK) {
        REPORT_OHOS_ACCOUNT_FAIL(localId, Constants::OPERATION_GET_INFO, errCode, "Get ohos account info failed");
        ACCOUNT_LOGE("Get ohos account info failed, errcode=%{public}d, localId=%{public}d.", errCode, localId);
        return errCode;
    }
    OhosAccountInfo ohosAccountInfo = accountInfo.ohosAccountInfo_;
    if (ohosAccountInfo.uid_ == DEFAULT_OHOS_ACCOUNT_UID) {
        return ERR_OK;
    }

    dvid = GenerateDVID(bundleName, ohosAccountInfo.GetRawUid());
    return ERR_OK;
}

std::string OhosAccountManager::ExtractFirstUtf8Char(const std::string &str)
{
    if (str.empty()) {
        return std::string("");
    }
    unsigned char firstByte = static_cast<unsigned char>(str[0]);
    size_t charLength = UTF8_SINGLE_BYTE_CHAR_LENGTH;

    if ((firstByte & UTF8_SINGLE_BYTE_MASK) == UTF8_SINGLE_BYTE_PREFIX) {
        charLength = UTF8_SINGLE_BYTE_CHAR_LENGTH;
    } else if ((firstByte & UTF8_DOUBLE_BYTE_MASK) == UTF8_DOUBLE_BYTE_PREFIX) {
        charLength = UTF8_DOUBLE_BYTE_CHAR_LENGTH;
    } else if ((firstByte & UTF8_TRIPLE_BYTE_MASK) == UTF8_TRIPLE_BYTE_PREFIX) {
        charLength = UTF8_TRIPLE_BYTE_CHAR_LENGTH;
    } else if ((firstByte & UTF8_QUAD_BYTE_MASK) == UTF8_QUAD_BYTE_PREFIX) {
        charLength = UTF8_QUAD_BYTE_CHAR_LENGTH;
    } else {
        return std::string("");
    }
    charLength = std::min(charLength, str.length());

    return str.substr(0, charLength);
}

void OhosAccountManager::AnonymizeOhosAccountInfo(OhosAccountInfo &ohosAccountInfo, const std::string &bundleName)
{
    if (!(ohosAccountInfo.uid_ == DEFAULT_OHOS_ACCOUNT_UID || ohosAccountInfo.uid_.empty())) {
        ohosAccountInfo.uid_ = GenerateDVID(bundleName, ohosAccountInfo.GetRawUid());
    }

    if (!(ohosAccountInfo.name_ == DEFAULT_OHOS_ACCOUNT_NAME || ohosAccountInfo.name_.empty())) {
        std::string firstChar = ExtractFirstUtf8Char(ohosAccountInfo.name_);
        ohosAccountInfo.name_ = firstChar + DEFAULT_ANON_STR;
    }

    if (!ohosAccountInfo.nickname_.empty()) {
        std::string firstChar = ExtractFirstUtf8Char(ohosAccountInfo.nickname_);
        ohosAccountInfo.nickname_ = firstChar + DEFAULT_ANON_STR;
    }

    if (!ohosAccountInfo.avatar_.empty()) {
        ohosAccountInfo.avatar_ = DEFAULT_ANON_STR;
    }

    ohosAccountInfo.scalableData_ = {};
}

ErrCode OhosAccountManager::GetOhosAccountDistributedInfo(const int32_t userId, OhosAccountInfo &ohosAccountInfo)
{
    AccountInfo osAccountInfo;
    ErrCode ret = GetAccountInfoByUserId(userId, osAccountInfo);
    if (ret != ERR_OK) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_GET_INFO, ret, "Get ohos account info failed");
        ACCOUNT_LOGE("get ohos account info failed, userId %{public}d.", userId);
        return ret;
    }
    ohosAccountInfo = osAccountInfo.ohosAccountInfo_;
    std::string rawUid = ohosAccountInfo.GetRawUid();
    if (rawUid == DEFAULT_OHOS_ACCOUNT_UID || osAccountInfo.version_ == ACCOUNT_VERSION_DEFAULT) {
        return ERR_OK;
    }
    std::string bundleName = "";
    bool isSystemApp = false;
    GetCallerBundleName(bundleName, isSystemApp);
    if (isSystemApp || bundleName.empty()) {
        return ERR_OK;
    }
    ReportOsAccountLifeCycle(userId, "GetDistributedInfo_" + bundleName);
    AnonymizeOhosAccountInfo(ohosAccountInfo, bundleName);
    return ERR_OK;
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
    ErrCode errCode = subscribeManager_.SubscribeDistributedAccountEvent(type, eventListener);
    if (errCode != ERR_OK) {
        REPORT_OHOS_ACCOUNT_FAIL(-1, Constants::OPERATION_SUBSCRIBE, errCode,
            "Subscribe error, type=" + std::to_string(static_cast<int32_t>(type)));
    }
    return errCode;
}

ErrCode OhosAccountManager::UnsubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
    const sptr<IRemoteObject> &eventListener)
{
    ErrCode errCode = subscribeManager_.UnsubscribeDistributedAccountEvent(type, eventListener);
    if (errCode != ERR_OK) {
        REPORT_OHOS_ACCOUNT_FAIL(-1, Constants::OPERATION_UNSUBSCRIBE, errCode,
            "Unsubscribe error, type=" + std::to_string(static_cast<int32_t>(type)));
    }
    return errCode;
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

static bool CheckEventValid(const std::string &eventStr, int &event)
{
    static const std::map<std::string, ACCOUNT_INNER_EVENT_TYPE> eventMap = {
        { OHOS_ACCOUNT_EVENT_LOGIN, ACCOUNT_BIND_SUCCESS_EVT },
        { OHOS_ACCOUNT_EVENT_LOGOUT, ACCOUNT_MANUAL_UNBOUND_EVT },
        { OHOS_ACCOUNT_EVENT_TOKEN_INVALID, ACCOUNT_TOKEN_EXPIRED_EVT },
        { OHOS_ACCOUNT_EVENT_LOGOFF, ACCOUNT_MANUAL_LOGOFF_EVT },
    };
    auto iter = eventMap.find(eventStr);
    if (iter == eventMap.end()) {
        ACCOUNT_LOGE("invalid event: %{public}s", eventStr.c_str());
        return false;
    }
    event = iter->second;
    return true;
}

bool OhosAccountManager::HandleEvent(AccountInfo &curOhosAccount, const std::string &eventStr)
{
    int event;
    if (!CheckEventValid(eventStr, event)) {
        ACCOUNT_LOGE("invalid event: %{public}s", eventStr.c_str());
        return false;
    }
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

static void UpdateOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo, const std::string &ohosAccountUid,
    AccountInfo &currAccountInfo)
{
    currAccountInfo.ohosAccountInfo_ = ohosAccountInfo;
    currAccountInfo.ohosAccountInfo_.SetRawUid(ohosAccountInfo.uid_);
    currAccountInfo.ohosAccountInfo_.uid_ = ohosAccountUid;
    currAccountInfo.ohosAccountInfo_.status_ = ACCOUNT_STATE_LOGIN;
    currAccountInfo.bindTime_ = std::time(nullptr);
    currAccountInfo.version_ = ACCOUNT_VERSION_ANON;
    currAccountInfo.ohosAccountInfo_.callingUid_ = IPCSkeleton::GetCallingUid();
}

/**
 * login ohos (for distributed network) account.
 *
 * @param userId target local account id.
 * @param ohosAccountInfo ohos account information
 * @param eventStr ohos account state change event
 * @return ERR_OK if the processing was completed
 */
ErrCode OhosAccountManager::LoginOhosAccount(const int32_t userId, const OhosAccountInfo &ohosAccountInfo,
    const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);
    AccountInfo currAccountInfo;
    ErrCode res = dataDealer_->AccountInfoFromJson(currAccountInfo, userId);
    if (res != ERR_OK) {
        ACCOUNT_LOGE("get current ohos account info failed, userId %{public}d.", userId);
        return res;
    }
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(ohosAccountInfo.name_, ohosAccountInfo.uid_);
    // current local user cannot be bound again when it has already been bound to an ohos account
    if (!CheckOhosAccountCanBind(currAccountInfo, ohosAccountInfo, ohosAccountUid)) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGIN, ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR,
            "Call checkOhosAccountCanBind failed.");
        ACCOUNT_LOGE("check can be bound failed, userId %{public}d.", userId);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR;
    }
#ifdef HAS_CES_PART
    // check whether need to publish event or not
    bool isPubLoginEvent = (currAccountInfo.ohosAccountInfo_.status_ != ACCOUNT_STATE_LOGIN);
#endif // HAS_CES_PART
    // update account status
    if (!HandleEvent(currAccountInfo, eventStr)) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGIN, ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR,
            "Call handleEvent failed.");
        ACCOUNT_LOGE("HandleEvent %{public}s failed! userId %{public}d.", eventStr.c_str(), userId);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR;
    }
    // update account info
    UpdateOhosAccountInfo(ohosAccountInfo, ohosAccountUid, currAccountInfo);
    if (!SaveOhosAccountInfo(currAccountInfo)) {
        ACCOUNT_LOGE("SaveOhosAccountInfo failed! userId %{public}d.", userId);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR;
    }
    subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN);
    if (ohosAccountInfo.avatar_.empty()) {
        ACCOUNT_LOGE("Avatar is empty.! userId %{public}d.", userId);
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGIN, ERR_OK, "Avatar is empty.");
    }
#ifdef HAS_CES_PART
    if (!isPubLoginEvent) {
        AccountEventProvider::EventPublish(CommonEventSupport::COMMON_EVENT_USER_INFO_UPDATED, userId, nullptr);
        (void)CreateCommonEventSubscribe();
        return ERR_OK;
    }
    AccountEventProvider::EventPublishAsUser(CommonEventSupport::COMMON_EVENT_HWID_LOGIN, userId);
    AccountEventProvider::EventPublishAsUser(
        CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN, userId);
#else  // HAS_CES_PART
    ACCOUNT_LOGI("No common event part, publish nothing!");
#endif // HAS_CES_PART
    (void)CreateCommonEventSubscribe();
    ACCOUNT_LOGI("LoginOhosAccount success! userId %{public}d", userId);
    return ERR_OK;
}

/**
 * logout ohos (for distributed network) account.
 *
 * @param userId target local account id.
 * @param ohosAccountInfo ohos account information
 * @param eventStr ohos account state change event
 * @return ERR_OK if the processing was completed
 */
ErrCode OhosAccountManager::LogoutOhosAccount(
    const int32_t userId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);

    AccountInfo currentAccount;
    if (!GetCurOhosAccountAndCheckMatch(currentAccount, ohosAccountInfo.name_,
                                        ohosAccountInfo.uid_, userId)) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGOUT, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR,
            "Call getCurOhosAccountAndCheckMatch failed.");
        ACCOUNT_LOGE("check match failed, userId %{public}d.", userId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    bool ret = HandleEvent(currentAccount, eventStr); // update account status
    if (!ret) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGOUT, ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR,
            "Call handleEvent failed.");
        ACCOUNT_LOGE("HandleEvent %{public}s failed, userId %{public}d.", eventStr.c_str(), userId);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR;
    }

    ret = ClearOhosAccount(currentAccount); // clear account info with ACCOUNT_STATE_UNBOUND
    if (!ret) {
        ACCOUNT_LOGE("ClearOhosAccount failed! userId %{public}d.", userId);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR;
    }
    subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT);

#ifdef HAS_CES_PART
    AccountEventProvider::EventPublishAsUser(
        EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT, userId);
    AccountEventProvider::EventPublishAsUser(
        EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT, userId);
#else  // HAS_CES_PART
    ACCOUNT_LOGI("No common event part! Publish nothing!");
#endif // HAS_CES_PART
    ACCOUNT_LOGI("LogoutOhosAccount success, userId %{public}d.", userId);
    return ERR_OK;
}

/**
 * logoff ohos (for distributed network) account.
 *
 * @param userId target local account id.
 * @param ohosAccountInfo ohos account information
 * @param eventStr ohos account state change event
 * @return ERR_OK if the processing was completed
 */
ErrCode OhosAccountManager::LogoffOhosAccount(
    const int32_t userId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);

    AccountInfo currentAccount;
    if (!GetCurOhosAccountAndCheckMatch(currentAccount, ohosAccountInfo.name_, ohosAccountInfo.uid_, userId)) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGOFF, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR,
            "Call getCurOhosAccountAndCheckMatch failed.");
        ACCOUNT_LOGE("check match failed, userId %{public}d.", userId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    bool ret = HandleEvent(currentAccount, eventStr); // update account status
    if (!ret) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGOFF, ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR,
            "Call handleEvent failed.");
        ACCOUNT_LOGE("HandleEvent %{public}s failed, userId %{public}d.", eventStr.c_str(), userId);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR;
    }

    ret = ClearOhosAccount(currentAccount); // clear account info with ACCOUNT_STATE_UNBOUND
    if (!ret) {
        ACCOUNT_LOGE("ClearOhosAccount failed, userId %{public}d.", userId);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR;
    }
    subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOFF);

#ifdef HAS_CES_PART
    AccountEventProvider::EventPublishAsUser(
        EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOFF, userId);
    AccountEventProvider::EventPublishAsUser(
        EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOFF, userId);
#else  // HAS_CES_PART
    ACCOUNT_LOGI("No common event part, publish nothing for logoff!");
#endif // HAS_CES_PART
    ACCOUNT_LOGI("LogoffOhosAccount success, userId %{public}d.", userId);
    return ERR_OK;
}

/**
 * Handle token_invalid event.
 *
 * @param userId target local account id.
 * @param ohosAccountInfo ohos account information
 * @param eventStr ohos account state change event
 * @return ERR_OK if the processing was completed
 */
ErrCode OhosAccountManager::HandleOhosAccountTokenInvalidEvent(
    const int32_t userId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);

    AccountInfo currentOhosAccount;
    if (!GetCurOhosAccountAndCheckMatch(currentOhosAccount, ohosAccountInfo.name_,
                                        ohosAccountInfo.uid_, userId)) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_TOKEN_INVALID, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR,
            "Call getCurOhosAccountAndCheckMatch failed.");
        ACCOUNT_LOGE("check match failed, userId %{public}d.", userId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    bool ret = HandleEvent(currentOhosAccount, eventStr); // update account status
    if (!ret) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_TOKEN_INVALID, ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR,
            "Call handleEvent failed.");
        ACCOUNT_LOGE("HandleEvent %{public}s failed, userId %{public}d.", eventStr.c_str(), userId);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR;
    }

    ret = SaveOhosAccountInfo(currentOhosAccount);
    if (!ret) {
        // moving on even if failed to update account info
        ACCOUNT_LOGW("SaveOhosAccountInfo failed, userId %{public}d.", userId);
    }
    subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::TOKEN_INVALID);

#ifdef HAS_CES_PART
    AccountEventProvider::EventPublishAsUser(
        EventFwk::CommonEventSupport::COMMON_EVENT_HWID_TOKEN_INVALID, userId);
    AccountEventProvider::EventPublishAsUser(
        EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_TOKEN_INVALID, userId);
#else  // HAS_CES_PART
    ACCOUNT_LOGI("No common event part, publish nothing for token invalid event.");
#endif // HAS_CES_PART
    ACCOUNT_LOGI("success, userId %{public}d.", userId);
    return ERR_OK;
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
            [this](int32_t userId) { this->OnPackageRemoved(userId); } };
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
            AccountEventProvider::EventPublishAsUser(
                EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT, info.GetLocalId());
            AccountEventProvider::EventPublishAsUser(
                EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT, info.GetLocalId());
        }
    }
}
#endif // HAS_CES_PART

bool OhosAccountManager::CheckOhosAccountCanBind(const AccountInfo &currAccountInfo,
    const OhosAccountInfo &newOhosAccountInfo, const std::string &newOhosUid) const
{
    if (newOhosUid.length() != OHOS_ACCOUNT_UDID_LENGTH) {
        ACCOUNT_LOGE("newOhosUid invalid length, %{public}zu.", newOhosUid.length());
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
            AnonymizeNameStr(inputName).c_str(), AnonymizeNameStr(ohosAccountUid).c_str(), callingUserId);
        return false;
    }
    return true;
}
} // namespace AccountSA
} // namespace OHOS

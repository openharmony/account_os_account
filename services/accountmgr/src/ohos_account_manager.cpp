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
#ifndef DLOPEN_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/types.h>
#endif
#include <sys/types.h>
#include <sstream>
#include <thread>
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
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
#include "os_account_subspace_manager.h"
#endif
#include "ipc_skeleton.h"
#include "ohos_account_constants.h"
#include "os_account_constants.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"

#ifdef HAS_CES_PART
using namespace OHOS::EventFwk;
#endif // HAS_CES_PART

#ifdef DLOPEN_OPENSSL
#ifdef __cplusplus
extern "C" {
#endif
#define SHA_LBLOCK 16
#define SHA256_CBLOCK (SHA_LBLOCK*4)

struct sha256_state_st {
    uint32_t h[8];
    uint32_t Nl, Nh;
    uint8_t data[SHA256_CBLOCK];
    unsigned num, md_len;
};

#ifdef __cplusplus
}
#endif
typedef struct evp_md_st EVP_MD;
using SHA256_CTX = struct sha256_state_st;
#endif // DLOPEN_OPENSSL

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

#ifdef DLOPEN_OPENSSL
using SHA256_InitFunc = int (*)(SHA256_CTX *);
using SHA256_UpdateFunc = int (*)(SHA256_CTX *, const void *, size_t);
using SHA256_FinalFunc = int (*)(unsigned char *, SHA256_CTX *);
using EVP_MD_fetchFunc = EVP_MD *(*)(void *, const char *, const char *);
using EVP_MD_freeFunc = void (*)(EVP_MD *);
using PKCS5_PBKDF2_HMAC_Func = int (*)(const char *, int, const unsigned char *, int,
    int, const EVP_MD *, int, unsigned char *);
using Clean_Func = void (*)();

static std::mutex g_mutex;
static void *g_opensslLib = nullptr;
static SHA256_InitFunc SHA256_Init = nullptr;
static SHA256_UpdateFunc SHA256_Update = nullptr;
static SHA256_FinalFunc SHA256_Final = nullptr;
static EVP_MD_fetchFunc EVP_MD_fetch = nullptr;
static EVP_MD_freeFunc EVP_MD_free = nullptr;
static PKCS5_PBKDF2_HMAC_Func PKCS5_PBKDF2_HMAC = nullptr;
static Clean_Func g_OpensslCleanFunc = nullptr;

static void UnloadOpenSSL()
{
    if (g_opensslLib != nullptr) {
        if (g_OpensslCleanFunc != nullptr) {
            g_OpensslCleanFunc();
        }
        dlclose(g_opensslLib);
        g_opensslLib = nullptr;
    }
}

static bool LoadOpenSSL()
{
    if (g_opensslLib != nullptr) {
        return true;
    }
    g_opensslLib = dlopen("libcrypto_openssl.z.so", RTLD_LAZY);
    if (g_opensslLib == nullptr) {
        ACCOUNT_LOGE("Failed to load libcrypto.so: %{public}s", dlerror());
        return false;
    }
    SHA256_Init = reinterpret_cast<SHA256_InitFunc>(dlsym(g_opensslLib, "SHA256_Init"));
    SHA256_Update = reinterpret_cast<SHA256_UpdateFunc>(dlsym(g_opensslLib, "SHA256_Update"));
    SHA256_Final = reinterpret_cast<SHA256_FinalFunc>(dlsym(g_opensslLib, "SHA256_Final"));
    EVP_MD_fetch = reinterpret_cast<EVP_MD_fetchFunc>(dlsym(g_opensslLib, "EVP_MD_fetch"));
    EVP_MD_free = reinterpret_cast<EVP_MD_freeFunc>(dlsym(g_opensslLib, "EVP_MD_free"));
    PKCS5_PBKDF2_HMAC = reinterpret_cast<PKCS5_PBKDF2_HMAC_Func>(dlsym(g_opensslLib, "PKCS5_PBKDF2_HMAC"));
    g_OpensslCleanFunc = reinterpret_cast<Clean_Func>(dlsym(g_opensslLib, "OPENSSL_cleanup"));
    if (SHA256_Init == nullptr || SHA256_Update == nullptr || SHA256_Final == nullptr ||
        EVP_MD_fetch == nullptr || EVP_MD_free == nullptr || PKCS5_PBKDF2_HMAC == nullptr ||
        g_OpensslCleanFunc == nullptr) {
        ACCOUNT_LOGE("Failed to load OpenSSL functions");
        UnloadOpenSSL();
        return false;
    }
    return true;
}
#endif

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
#ifdef DLOPEN_OPENSSL
    std::lock_guard<std::mutex> mutexLock(g_mutex);
    if (!LoadOpenSSL()) {
        ACCOUNT_LOGE("LoadOpenSSL failed in ComputeHash");
        return "";
    }
#endif
    SHA256_CTX sha256Ctx;
    SHA256_Init(&sha256Ctx);
    SHA256_Update(&sha256Ctx, uid.c_str(), uid.length());
    SHA256_Final(hash, &sha256Ctx);
#ifdef DLOPEN_OPENSSL
    UnloadOpenSSL();
#endif
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
#ifdef DLOPEN_OPENSSL
    std::lock_guard<std::mutex> mutexLock(g_mutex);
    if (!LoadOpenSSL()) {
        ACCOUNT_LOGE("LoadOpenSSL failed in ComputeHash");
        return "";
    }
#endif
    EVP_MD *sha256Md = EVP_MD_fetch(nullptr, "SHA2-256", nullptr);
    if (sha256Md == nullptr) {
        ACCOUNT_LOGE("EVP_MD_fetch failed");
#ifdef DLOPEN_OPENSSL
        UnloadOpenSSL();
#endif
        return std::string("");
    }
    int ret = PKCS5_PBKDF2_HMAC(
        reinterpret_cast<const char *>(uid.c_str()), uid.size(),
        reinterpret_cast<const unsigned char *>(bundleName.c_str()), bundleName.size(),
        ITERATE_CNT,
        sha256Md,
        OUTPUT_LENGTH_IN_BYTES,
        newId);
    if (ret != 1) {
        ACCOUNT_LOGE("EVP_PBKDF2 failed ret: %{public}d", ret);
        EVP_MD_free(sha256Md);
#ifdef DLOPEN_OPENSSL
        UnloadOpenSSL();
#endif
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
#ifdef DLOPEN_OPENSSL
    UnloadOpenSSL();
#endif
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

#ifndef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
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
#else
static ErrCode ProcDistributedAccountSpaceStateChange(
    OhosAccountManager *ptr, const std::int32_t userId, const OhosAccountInfo &info, const std::string &eventStr)
{
    OsAccountInfo osAccountInfo;
    ErrCode ret = IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(userId, osAccountInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("GetOsAccountInfoByLocalId failed, userId=%{public}d", userId);
        return ret;
    }
    int32_t subspaceId = osAccountInfo.GetForegroundSubspaceId();

    static const std::map<std::string, OhosAccountEventFunc> eventFuncMap = {
        {
            OHOS_ACCOUNT_EVENT_LOGIN,
            [ptr](const std::int32_t userId, const int32_t subspaceId,
                const OhosAccountInfo &info, const std::string &eventStr) {
                return ptr->LoginOhosAccountSpace(userId, subspaceId, info, eventStr);
            }
        },
        {
            OHOS_ACCOUNT_EVENT_LOGOUT,
            [ptr](const std::int32_t userId, const int32_t subspaceId,
                const OhosAccountInfo &info, const std::string &eventStr) {
                return ptr->LogoutOhosAccountSpace(userId, subspaceId, info, eventStr);
            }
        },
        {
            OHOS_ACCOUNT_EVENT_LOGOFF,
            [ptr](const std::int32_t userId, const int32_t subspaceId,
                const OhosAccountInfo &info, const std::string &eventStr) {
                return ptr->LogoffOhosAccountSpace(userId, subspaceId, info, eventStr);
            }
        },
        {
            OHOS_ACCOUNT_EVENT_TOKEN_INVALID,
            [ptr](const std::int32_t userId, const int32_t subspaceId,
                const OhosAccountInfo &info, const std::string &eventStr) {
                return ptr->HandleOhosAccountSpaceTokenInvalidEvent(userId, subspaceId, info, eventStr);
            }
        },
    };
    auto itFunc = eventFuncMap.find(eventStr);
    if (itFunc == eventFuncMap.end()) {
        ACCOUNT_LOGE("invalid event for space: %{public}s", eventStr.c_str());
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_SET_INFO, ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
            eventStr.c_str());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return (itFunc->second)(userId, subspaceId, info, eventStr);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

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
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    return ProcDistributedAccountSpaceStateChange(this, userId, ohosAccountInfo, eventStr);
#else
    return ProcDistributedAccountStateChange(this, userId, ohosAccountInfo, eventStr);
#endif
}

ErrCode OhosAccountManager::OhosAccountStateChange(
    const int32_t userId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    return ProcDistributedAccountSpaceStateChange(this, userId, ohosAccountInfo, eventStr);
#else
    return ProcDistributedAccountStateChange(this, userId, ohosAccountInfo, eventStr);
#endif
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

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    // Resolve foreground subspace: if non-base, read from subspace data
    OsAccountInfo osAccountInfo;
    ErrCode getInfoRet = IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(userId, osAccountInfo);
    if (getInfoRet == ERR_OK) {
        int32_t fgSubspaceId = osAccountInfo.GetForegroundSubspaceId();
        if (fgSubspaceId != -1) {
            OsAccountSubspaceInfo subspaceInfo;
            ErrCode loadRet = GetDistributedAccountSpaceInfo(userId, fgSubspaceId, subspaceInfo);
            if (loadRet == ERR_OK) {
                info = subspaceInfo;  // Copy AccountInfo base fields from subspace info
                return ERR_OK;
            }
            ACCOUNT_LOGW("load subspace info failed, fgSubspaceId=%{public}d, ret=%{public}d, "
                         "fallback to base subspace.", fgSubspaceId, loadRet);
        }
    } else {
        ACCOUNT_LOGW("GetOsAccountInfoById failed for userId=%{public}d, ret=%{public}d, "
                     "fallback to base subspace.", userId, getInfoRet);
    }
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

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

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
#ifdef HAS_CES_PART
static void SendMultiSubSpaceCommonEvt(const std::int32_t userId, const int32_t subspaceId, const std::string &eventStr)
{
    EventFwk::Want want;
    want.SetParam("userId", userId);
    want.SetParam("subProfileId", subspaceId);
    AccountEventProvider::EventPublishAsUser(eventStr, want, userId);
}
#endif // HAS_CES_PART

void OhosAccountManager::InitOsAccountSubspaceManager(const std::string &rootPath)
{
    OsAccountSubspaceManager::GetInstance().Init(rootPath);
    auto task = []() { OsAccountSubspaceManager::GetInstance().CleanupOrphanedSubspaces(); };
#ifdef FUZZ_TEST
    task();
#else
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), "DistAccSpaceCln");
    taskThread.detach();
#endif
}

ErrCode OhosAccountManager::CreateOsAccountSubspace(int32_t osAccountId, OsAccountSubspaceResult &result)
{
    int32_t newSubspaceId = 0;
    ErrCode ret = OsAccountSubspaceManager::GetInstance().CreateSubspace(osAccountId, newSubspaceId);
    if (ret != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(osAccountId, "subspace_create", ret,
            "CreateOsAccountSubspace failed");
        return ret;
    }
    result.id = newSubspaceId;
    result.osAccountId = osAccountId;
    result.index = newSubspaceId - osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;

    ErrCode publishRet = subscribeManager_.Publish(
        DistributedAccountSpaceEventType::CREATED, osAccountId, newSubspaceId);
    if (publishRet != ERR_OK) {
        ACCOUNT_LOGW("Failed to publish CREATE event for distId=%{public}d, ret=%{public}d (space is still valid)",
            newSubspaceId, publishRet);
    }
    ACCOUNT_LOGI("CreateOsAccountSubspace successful, osAccountId=%{public}d, subspaceId=%{public}d",
        osAccountId, newSubspaceId);
    ReportOsAccountLifeCycle(newSubspaceId, "subspace_create");
    return ERR_OK;
}

ErrCode OhosAccountManager::DeleteOsAccountSubspace(int32_t osAccountId, int32_t subspaceId)
{
    ErrCode ret = OsAccountSubspaceManager::GetInstance().RemoveSubspace(osAccountId, subspaceId);
    if (ret != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(osAccountId, "subspace_delete", ret,
            "DeleteOsAccountSubspace failed");
        return ret;
    }
    ErrCode publishRet = subscribeManager_.Publish(
        DistributedAccountSpaceEventType::DELETED, osAccountId, subspaceId);
    if (publishRet != ERR_OK) {
        ACCOUNT_LOGW("Failed to publish DELETED event for distId=%{public}d, ret=%{public}d",
            subspaceId, publishRet);
    }
    ACCOUNT_LOGI("DeleteOsAccountSubspace successful, osAccountId=%{public}d, subspaceId=%{public}d",
        osAccountId, subspaceId);
    ReportOsAccountLifeCycle(subspaceId, "subspace_delete");
    return ERR_OK;
}

ErrCode OhosAccountManager::SwitchOsAccountSubspace(
    int32_t osAccountId, int32_t subspaceId, int32_t &fromSubspaceId)
{
    // index-0 active session check: mgrMutex_ + dataDealer_->AccountInfoFromJson() reads the
    // distributed account LOGIN state — this data is owned exclusively by OhosAccountManager.
    // Foreground checks for non-0 spaces are handled internally inside SwitchSubspace.
    int32_t base = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    OsAccountInfo osAccountInfo;
    ErrCode err = IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(osAccountId, osAccountInfo);
    if (err != ERR_OK) {
        ACCOUNT_LOGW("GetOsAccountInfoById failed, skip base subspace check and proceed");
    } else if (osAccountInfo.GetForegroundSubspaceId() == base) {
        std::lock_guard<std::mutex> lock(mgrMutex_);
        AccountInfo currentAccountInfo;
        if (dataDealer_->AccountInfoFromJson(currentAccountInfo, osAccountId) == ERR_OK &&
            currentAccountInfo.ohosAccountInfo_.status_ == ACCOUNT_STATE_LOGIN) {
            ACCOUNT_LOGE("Current foreground base subspace has active session, switch rejected");
            return ERR_OS_ACCOUNT_SUBSPACE_HAS_ACTIVE_SESSION;
        }
    }

    ErrCode ret = OsAccountSubspaceManager::GetInstance().SwitchSubspace(
        osAccountId, subspaceId, fromSubspaceId);
    if (ret != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(osAccountId, "subspace_switch", ret,
            "SwitchOsAccountSubspace failed");
        return ret;
    }
    ErrCode publishRet = subscribeManager_.Publish(
        DistributedAccountSpaceEventType::SWITCHED, osAccountId, subspaceId, fromSubspaceId);
    if (publishRet != ERR_OK) {
        ACCOUNT_LOGW("Failed to publish SWITCHED event for distId=%{public}d, ret=%{public}d",
            subspaceId, publishRet);
    }
    ACCOUNT_LOGI("SwitchOsAccountSubspace successful, osAccountId=%{public}d, from=%{public}d, to=%{public}d",
        osAccountId, fromSubspaceId, subspaceId);
    ReportOsAccountLifeCycle(subspaceId, "subspace_switch");
    return ERR_OK;
}
#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

ErrCode OhosAccountManager::SubscribeDistributedAccountSpaceEvents(
    const std::set<DistributedAccountSpaceEventType> &types, const sptr<IRemoteObject> &eventListener)
{
    return subscribeManager_.SubscribeDistributedAccountSpaceEvents(types, eventListener);
}

ErrCode OhosAccountManager::UnsubscribeDistributedAccountSpaceEvents(
    const std::set<DistributedAccountSpaceEventType> &types, const sptr<IRemoteObject> &eventListener)
{
    return subscribeManager_.UnsubscribeDistributedAccountSpaceEvents(types, eventListener);
}

ErrCode OhosAccountManager::GetOsAccountForegroundSubProfileId(
    int32_t osAccountId, int32_t &subProfileId)
{
    // Caller MUST validate account existence before calling this method.
    OsAccountInfo osAccountInfo;
    ErrCode ret = IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(osAccountId, osAccountInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("GetOsAccountInfoById failed, osAccountId=%{public}d, ret=%{public}d", osAccountId, ret);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    subProfileId = osAccountInfo.GetForegroundSubspaceId();
    return ERR_OK;
}

ErrCode OhosAccountManager::GetOsAccountSubProfileIds(
    int32_t osAccountId, std::vector<int32_t> &subProfileIds)
{
    subProfileIds.clear();
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    return OsAccountSubspaceManager::GetInstance().GetSubProfileIds(osAccountId, subProfileIds);
#else
    int32_t subProfileId = 0;
    ErrCode ret = GetOsAccountForegroundSubProfileId(osAccountId, subProfileId);
    if (ret == ERR_OK) {
        subProfileIds.push_back(subProfileId);
    }
    return ret;
#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
}

ErrCode OhosAccountManager::GetOsAccountLocalIdForSubProfile(
    int32_t subProfileId, int32_t &osAccountId)
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    ErrCode res = OsAccountSubspaceManager::GetInstance().GetLocalIdForSubProfile(subProfileId, osAccountId);
    if (res != ERR_OK) {
        return res;
    }
#else
    auto id = subProfileId / Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    if (subProfileId != id * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER) {
        ACCOUNT_LOGE("SubProfile %{public}d does not exist", subProfileId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    osAccountId = id;
#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    OsAccountInfo osAccountInfo;
    ErrCode ret = IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(osAccountId, osAccountInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("OsAccount %{public}d not found for subProfileId=%{public}d", osAccountId, subProfileId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    return ERR_OK;
}

ErrCode OhosAccountManager::GetOsAccountSubProfile(int32_t osAccountId, int32_t subProfileId,
    OsAccountSubspaceResult &subspaceResult, OhosAccountInfo &distributedInfo)
{
    int32_t base = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    ErrCode ret;
    if (subProfileId == base) {
        subspaceResult.id = subProfileId;
        subspaceResult.osAccountId = osAccountId;
        subspaceResult.index = 0;
        AccountInfo accountInfo;
        ret = dataDealer_->AccountInfoFromJson(accountInfo, osAccountId);
        if (ret != ERR_OK) {
            return ret;
        }
        distributedInfo = accountInfo.ohosAccountInfo_;
    } else {
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
        ret = OsAccountSubspaceManager::GetInstance().GetSubProfile(
            osAccountId, subProfileId, subspaceResult, distributedInfo);
        if (ret != ERR_OK) {
            return ret;
        }
#else
        ACCOUNT_LOGE("SubProfile %{public}d does not exist", subProfileId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    }
    return ERR_OK;
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
#ifndef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
        { OHOS_ACCOUNT_EVENT_LOGOUT, ACCOUNT_MANUAL_UNBOUND_EVT },
#else
        { OHOS_ACCOUNT_EVENT_LOGOUT, ACCOUNT_MANUAL_LOGOUT_EVT },
#endif
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

#ifndef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    int32_t originalStatus = currAccountInfo.ohosAccountInfo_.status_;
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
    if (ohosAccountInfo.avatar_.empty()) {
        ACCOUNT_LOGE("Avatar is empty.! userId %{public}d.", userId);
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGIN, ERR_OK, "Avatar is empty.");
    }
    return PublishLoginEvents(userId, originalStatus);
}

ErrCode OhosAccountManager::PublishLoginEvents(int32_t userId, int32_t originalStatus)
{
    if (originalStatus == ACCOUNT_STATE_UNBOUND) {
        subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::BOUND);
    }
    subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN);
#ifdef HAS_CES_PART
    bool isPubLoginEvent = (originalStatus != ACCOUNT_STATE_LOGIN);
    if (!isPubLoginEvent) {
        AccountEventProvider::EventPublish(CommonEventSupport::COMMON_EVENT_USER_INFO_UPDATED, userId, nullptr);
        (void)CreateCommonEventSubscribe();
        return ERR_OK;
    }
    AccountEventProvider::EventPublishAsUser(CommonEventSupport::COMMON_EVENT_HWID_LOGIN, userId);
    AccountEventProvider::EventPublishAsUser(
        CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN, userId);
    (void)CreateCommonEventSubscribe();
#endif // HAS_CES_PART
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
    subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::UNBOUND);
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
    subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::UNBOUND);
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
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

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
    if (IInnerOsAccountManager::GetInstance().QueryAllCreatedOsAccounts(osAccountInfos) != ERR_OK) {
        return;
    }
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);
    for (const auto &info : osAccountInfos) {
        int32_t localId = info.GetLocalId();
        ClearMainAccountIfMatch(localId, callingUid);
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
        ClearDistributedAccountSpacesIfMatch(localId, callingUid);
#endif
    }
}

void OhosAccountManager::ClearMainAccountIfMatch(int32_t localId, const std::int32_t bundleUid)
{
    AccountInfo accountInfo;
    if (dataDealer_->AccountInfoFromJson(accountInfo, localId) != ERR_OK) {
        return;
    }
    if (accountInfo.ohosAccountInfo_.callingUid_ != bundleUid ||
        accountInfo.ohosAccountInfo_.status_ == ACCOUNT_STATE_UNBOUND) {
        return;
    }
    (void)ClearOhosAccount(accountInfo);
#ifndef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    subscribeManager_.Publish(localId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT);
    subscribeManager_.Publish(localId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::UNBOUND);
    AccountEventProvider::EventPublishAsUser(
        EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT, localId);
    AccountEventProvider::EventPublishAsUser(
        EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT, localId);
#else
    PublishLogoutSpaceEvents(localId, localId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER, true);
#endif
}

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
void OhosAccountManager::ClearDistributedAccountSpacesIfMatch(int32_t localId, const std::int32_t bundleUid)
{
    auto &spaceManager = OsAccountSubspaceManager::GetInstance();
    std::set<int32_t> spaceIds;
    if (spaceManager.ScanOsAccountSubspaceIds(localId, spaceIds) != ERR_OK) {
        return;
    }
    for (int32_t spaceId : spaceIds) {
        ClearDistributedAccountSpaceIfMatch(localId, spaceId, bundleUid);
    }
}

void OhosAccountManager::ClearDistributedAccountSpaceIfMatch(
    int32_t localId, int32_t spaceId, const std::int32_t bundleUid)
{
    OsAccountSubspaceInfo spaceInfo;
    if (GetDistributedAccountSpaceInfo(localId, spaceId, spaceInfo) != ERR_OK) {
        return;
    }
    if (spaceInfo.ohosAccountInfo_.callingUid_ != bundleUid ||
        spaceInfo.ohosAccountInfo_.status_ == ACCOUNT_STATE_UNBOUND) {
        return;
    }
    spaceInfo.clear();
    SetDistributedAccountSpaceInfo(spaceInfo);
    PublishLogoutSpaceEvents(localId, spaceId, true);
}
#endif
#endif // HAS_CES_PART

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
ErrCode OhosAccountManager::HandleSpaceStateChange(OsAccountSubspaceInfo &spaceInfo, const std::string &eventStr)
{
    int event;
    if (!CheckEventValid(eventStr, event)) {
        ACCOUNT_LOGE("invalid event for space: %{public}s", eventStr.c_str());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    accountState_->SetAccountState(spaceInfo.ohosAccountInfo_.status_);
    bool ret = accountState_->StateChangeProcess(event);
    if (!ret) {
        ACCOUNT_LOGE("Handle space event %{public}d failed", event);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR;
    }
    std::int32_t newState = accountState_->GetAccountState();
    if (newState != spaceInfo.ohosAccountInfo_.status_) {
        ReportOhosAccountStateChange(spaceInfo.subspaceId, event,
            spaceInfo.ohosAccountInfo_.status_, newState);
        spaceInfo.ohosAccountInfo_.status_ = newState;
    }
    return ERR_OK;
}

static void UpdateOhosAccountSpaceInfo(const OhosAccountInfo &ohosAccountInfo, const std::string &ohosAccountUid,
    OsAccountSubspaceInfo &spaceInfo)
{
    spaceInfo.ohosAccountInfo_.SetRawUid(ohosAccountInfo.uid_);
    spaceInfo.ohosAccountInfo_.uid_ = ohosAccountUid;
    spaceInfo.ohosAccountInfo_.name_ = ohosAccountInfo.name_;
    spaceInfo.ohosAccountInfo_.nickname_ = ohosAccountInfo.nickname_;
    spaceInfo.ohosAccountInfo_.avatar_ = ohosAccountInfo.avatar_;
    spaceInfo.ohosAccountInfo_.callingUid_ = IPCSkeleton::GetCallingUid();
    spaceInfo.bindTime_ = std::time(nullptr);
    spaceInfo.version_ = ACCOUNT_VERSION_ANON;
}

ErrCode OhosAccountManager::LoginOhosAccountSpace(int32_t userId, int32_t subspaceId,
    const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);
    OsAccountSubspaceInfo spaceInfo;
    ErrCode ret = GetDistributedAccountSpaceInfo(userId, subspaceId, spaceInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("GetDistributedAccountSpaceInfo failed, userId=%{public}d, spaceId=%{public}d, ret=%{public}d",
            userId, subspaceId, ret);
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGIN, ret, "Get ohos space info failed");
        return ret;
    }

    std::string ohosAccountUid = GenerateOhosUdidWithSha256(ohosAccountInfo.name_, ohosAccountInfo.uid_);
    if (ohosAccountUid.length() != OHOS_ACCOUNT_UDID_LENGTH) {
        ACCOUNT_LOGE("ohosAccountUid invalid length, %{public}zu.", ohosAccountUid.length());
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR;
    }
    int32_t originalStatus = spaceInfo.ohosAccountInfo_.status_;
    ret = VerifySpaceAccountBinding(userId, subspaceId, ohosAccountInfo, spaceInfo);
    if (ret != ERR_OK) {
        return ret;
    }

    ret = HandleSpaceStateChange(spaceInfo, eventStr);
    if (ret != ERR_OK) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGIN, ret, "Call HandleSpaceStateChange failed.");
        return ret;
    }

    UpdateOhosAccountSpaceInfo(ohosAccountInfo, ohosAccountUid, spaceInfo);

    ret = SetDistributedAccountSpaceInfo(spaceInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("SetDistributedAccountSpaceInfo failed, spaceId=%{public}d", subspaceId);
        return ret;
    }

    if (ohosAccountInfo.avatar_.empty()) {
        ACCOUNT_LOGE("Avatar is empty, userId %{public}d.", userId);
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGIN, ERR_OK, "Avatar is empty.");
    }
    return PublishLoginSpaceEvents(userId, subspaceId, spaceInfo, originalStatus);
}

ErrCode OhosAccountManager::VerifySpaceAccountBinding(int32_t userId, int32_t subspaceId,
    const OhosAccountInfo &accountInfo, const OsAccountSubspaceInfo &spaceInfo)
{
    bool isUnbound = (spaceInfo.ohosAccountInfo_.status_ == ACCOUNT_STATE_UNBOUND);
    if (isUnbound) {
        return ERR_OK; // no need to check if space is unbound
    }
    if (!CheckSameDistributedAccount(spaceInfo.ohosAccountInfo_, accountInfo, userId)) {
        REPORT_OHOS_ACCOUNT_FAIL(spaceInfo.subspaceId, Constants::OPERATION_LOGIN,
            ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, "Call CheckSameDistributedAccount failed.");
        ACCOUNT_LOGE("uid mismatch for space %{public}d", subspaceId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    return ERR_OK;
}

ErrCode OhosAccountManager::PublishLoginSpaceEvents(int32_t userId, int32_t subspaceId,
    const OsAccountSubspaceInfo &spaceInfo, int32_t originalStatus)
{
    if (originalStatus == ACCOUNT_STATE_UNBOUND) {
        subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::BOUND, subspaceId);
    }
    subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, subspaceId);
    bool isPubLoginEvent = (originalStatus != ACCOUNT_STATE_LOGIN);
    if (!isPubLoginEvent) {
#ifdef HAS_CES_PART
        AccountEventProvider::EventPublish(CommonEventSupport::COMMON_EVENT_USER_INFO_UPDATED, userId, nullptr);
#endif // HAS_CES_PART
        return ERR_OK;
    }
#ifdef HAS_CES_PART
    SendMultiSubSpaceCommonEvt(userId, subspaceId, CommonEventSupport::COMMON_EVENT_HWID_LOGIN);
    SendMultiSubSpaceCommonEvt(userId, subspaceId, CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN);
#endif // HAS_CES_PART
    ACCOUNT_LOGI("LoginOhosAccountSpace success, userId=%{public}d, spaceId=%{public}d", userId, subspaceId);
    return ERR_OK;
}

ErrCode OhosAccountManager::LogoutOhosAccountSpace(int32_t userId, int32_t subspaceId,
    const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);

    // Load space info
    OsAccountSubspaceInfo spaceInfo;
    ErrCode ret = GetDistributedAccountSpaceInfo(userId, subspaceId, spaceInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("GetDistributedAccountSpaceInfo failed, userId=%{public}d, spaceId=%{public}d, ret=%{public}d",
            userId, subspaceId, ret);
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGOUT, ret, "Get ohos space info failed");
        return ret;
    }

    // Verify uid matches
    if (!CheckSameDistributedAccount(spaceInfo.ohosAccountInfo_, ohosAccountInfo, userId)) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGOUT, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR,
            "Call CheckSameDistributedAccount failed.");
        ACCOUNT_LOGE("uid mismatch for space %{public}d", subspaceId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    // State change via state machine
    ret = HandleSpaceStateChange(spaceInfo, eventStr);
    if (ret != ERR_OK) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGOUT, ret, "Call HandleSpaceStateChange failed.");
        return ret;
    }

    // Persist
    ret = SetDistributedAccountSpaceInfo(spaceInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("SetDistributedAccountSpaceInfo failed, spaceId=%{public}d", subspaceId);
        return ret;
    }

    PublishLogoutSpaceEvents(userId, subspaceId, false);

    ACCOUNT_LOGI("LogoutOhosAccountSpace success, userId=%{public}d, spaceId=%{public}d", userId, subspaceId);
    return ERR_OK;
}

void OhosAccountManager::PublishLogoutSpaceEvents(int32_t localId, int32_t subspaceId, bool isUnbound)
{
    // Publish IPC event
    subscribeManager_.Publish(localId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT, subspaceId);
    if (isUnbound) {
        subscribeManager_.Publish(localId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::UNBOUND, subspaceId);
    }
#ifdef HAS_CES_PART
    EventFwk::Want want;
    want.SetParam("userId", localId);
    want.SetParam("subProfileId", subspaceId);
    want.SetParam("isUnbound", isUnbound);
    AccountEventProvider::EventPublishAsUser(
        EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT, want, localId);
    AccountEventProvider::EventPublishAsUser(
        EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT, want, localId);
#endif // HAS_CES_PART
}

ErrCode OhosAccountManager::HandleOhosAccountSpaceTokenInvalidEvent(int32_t userId, int32_t subspaceId,
    const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);

    OsAccountSubspaceInfo spaceInfo;
    ErrCode ret = GetDistributedAccountSpaceInfo(userId, subspaceId, spaceInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("GetDistributedAccountSpaceInfo failed, userId=%{public}d, spaceId=%{public}d, ret=%{public}d",
            userId, subspaceId, ret);
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_TOKEN_INVALID, ret, "Get ohos space info failed");
        return ret;
    }
    if (!CheckSameDistributedAccount(spaceInfo.ohosAccountInfo_, ohosAccountInfo, userId)) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_TOKEN_INVALID, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR,
            "Call CheckSameDistributedAccount failed.");
        ACCOUNT_LOGE("uid mismatch for space %{public}d", subspaceId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    ret = HandleSpaceStateChange(spaceInfo, eventStr);
    if (ret != ERR_OK) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_TOKEN_INVALID, ret,
            "Call HandleSpaceStateChange failed.");
        return ret;
    }

    ret = SetDistributedAccountSpaceInfo(spaceInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGW("SetDistributedAccountSpaceInfo failed, spaceId=%{public}d", subspaceId);
        return ret;
    }

    subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::TOKEN_INVALID, subspaceId);

#ifdef HAS_CES_PART
    SendMultiSubSpaceCommonEvt(userId, subspaceId, CommonEventSupport::COMMON_EVENT_HWID_TOKEN_INVALID);
    SendMultiSubSpaceCommonEvt(userId, subspaceId, CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_TOKEN_INVALID);
#endif // HAS_CES_PART

    ACCOUNT_LOGI("HandleOhosAccountSpaceTokenInvalidEvent success, userId=%{public}d, spaceId=%{public}d",
        userId, subspaceId);
    return ERR_OK;
}

ErrCode OhosAccountManager::LogoffOhosAccountSpace(int32_t userId, int32_t subspaceId,
    const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);

    OsAccountSubspaceInfo spaceInfo;
    ErrCode ret = GetDistributedAccountSpaceInfo(userId, subspaceId, spaceInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("GetDistributedAccountSpaceInfo failed, userId=%{public}d, spaceId=%{public}d, ret=%{public}d",
            userId, subspaceId, ret);
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_TOKEN_INVALID, ret, "Get ohos space info failed");
        return ret;
    }
    if (!CheckSameDistributedAccount(spaceInfo.ohosAccountInfo_, ohosAccountInfo, userId)) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGOFF, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR,
            "Call CheckSameDistributedAccount failed.");
        ACCOUNT_LOGE("uid mismatch for space %{public}d", subspaceId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    ret = HandleSpaceStateChange(spaceInfo, eventStr);
    if (ret != ERR_OK) {
        REPORT_OHOS_ACCOUNT_FAIL(userId, Constants::OPERATION_LOGOFF, ret, "Call HandleSpaceStateChange failed.");
        return ret;
    }

    ret = SetDistributedAccountSpaceInfo(spaceInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("SetDistributedAccountSpaceInfo failed, spaceId=%{public}d", subspaceId);
        return ret;
    }

    subscribeManager_.Publish(userId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOFF, subspaceId);

#ifdef HAS_CES_PART
    SendMultiSubSpaceCommonEvt(userId, subspaceId, CommonEventSupport::COMMON_EVENT_HWID_LOGOFF);
    SendMultiSubSpaceCommonEvt(userId, subspaceId, CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOFF);
#endif // HAS_CES_PART
    ACCOUNT_LOGI("LogoffOhosAccountSpace success, userId=%{public}d, spaceId=%{public}d", userId, subspaceId);
    return ERR_OK;
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

#ifndef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
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
    return true;
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

bool OhosAccountManager::CheckSameDistributedAccount(const OhosAccountInfo &currAccountInfo,
    const OhosAccountInfo &newOhosAccountInfo, const std::int32_t callingUserId) const
{
    std::string ohosAccountUid = GenerateOhosUdidWithSha256(newOhosAccountInfo.name_, newOhosAccountInfo.uid_);
    if (newOhosAccountInfo.name_ != currAccountInfo.name_ || ohosAccountUid != currAccountInfo.uid_) {
        ACCOUNT_LOGE("account name %{public}s or ohosAccountUid %{public}s mismatch, calling user %{public}d.",
            AnonymizeNameStr(newOhosAccountInfo.name_).c_str(), AnonymizeNameStr(ohosAccountUid).c_str(),
            callingUserId);
        return false;
    }
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

    OhosAccountInfo newInfo;
    newInfo.name_ = inputName;
    newInfo.uid_ = inputUid;
    return CheckSameDistributedAccount(curAccountInfo.ohosAccountInfo_, newInfo, callingUserId);
}

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
ErrCode OhosAccountManager::GetDistributedAccountSpaceInfo(int32_t userId,
    int32_t subspaceId, OsAccountSubspaceInfo &spaceInfo)
{
    if (subspaceId == userId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER) {
        AccountInfo curInfo;
        ErrCode res = dataDealer_->AccountInfoFromJson(curInfo, userId);
        if (res != ERR_OK) {
            ACCOUNT_LOGE("get current ohos account info failed, userId %{public}d.", userId);
            return res;
        }
        spaceInfo.ohosAccountInfo_ = curInfo.ohosAccountInfo_;
        spaceInfo.subspaceId = subspaceId;
        spaceInfo.userId_ = userId;
        spaceInfo.isCreateCompleted = true;
        spaceInfo.toBeRemoved = false;
        spaceInfo.bindTime_ = curInfo.bindTime_;
        spaceInfo.version_ = curInfo.version_;
        return ERR_OK;
    }
    return OsAccountSubspaceManager::GetInstance().LoadSubspaceInfo(userId, subspaceId, spaceInfo);
}

ErrCode OhosAccountManager::SetDistributedAccountSpaceInfo(const OsAccountSubspaceInfo &spaceInfo)
{
    if (spaceInfo.subspaceId == spaceInfo.userId_ * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER) {
        AccountInfo curInfo;
        curInfo.ohosAccountInfo_ = spaceInfo.ohosAccountInfo_;
        curInfo.bindTime_ = spaceInfo.bindTime_;
        curInfo.userId_ = spaceInfo.userId_;
        curInfo.version_ = ACCOUNT_VERSION_ANON;
        curInfo.digest_ = "";
        return dataDealer_->AccountInfoToJson(curInfo);
    }
    return OsAccountSubspaceManager::GetInstance().SaveSubspaceInfo(spaceInfo);
}

ErrCode OhosAccountManager::SendMultiSpaceLogoutOnDelOsAccount(int32_t localId)
{
    std::lock_guard<std::mutex> mutexLock(mgrMutex_);
    std::set<int32_t> subSpaceIds;
    ErrCode ret = OsAccountSubspaceManager::GetInstance().ScanOsAccountSubspaceIds(localId, subSpaceIds);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("ScanOsAccountSubspaceIds failed, localId=%{public}d", localId);
        return ret;
    }
    subSpaceIds.insert(localId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER); // include base space
    for (int32_t spaceId : subSpaceIds) {
        OsAccountSubspaceInfo spaceInfo;
        ret = GetDistributedAccountSpaceInfo(localId, spaceId, spaceInfo);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("GetDistributedAccountSpaceInfo failed, localId=%{public}d, spaceId=%{public}d",
                localId, spaceId);
            continue;
        }
        if (spaceInfo.ohosAccountInfo_.status_ == ACCOUNT_STATE_UNBOUND) {
            continue;
        }
        if (spaceInfo.ohosAccountInfo_.status_ == ACCOUNT_STATE_LOGIN) {
            PublishLogoutSpaceEvents(localId, spaceId, true);
            continue;
        }
        subscribeManager_.Publish(localId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::UNBOUND, spaceId);
    }
    return ERR_OK;
}

#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

ErrCode OhosAccountManager::SendLogoutEventOnDelOsAccount(int32_t localId)
{
#ifndef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    AccountInfo ohosInfo;
    ErrCode ret = GetAccountInfoByUserId(localId, ohosInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("GetAccountInfoByUserId failed, localId=%{public}d.", localId);
        return ret;
    }
    if (ohosInfo.ohosAccountInfo_.name_ != DEFAULT_OHOS_ACCOUNT_NAME) {
        subscribeManager_.Publish(localId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT);
        subscribeManager_.Publish(localId, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::UNBOUND);
#ifdef HAS_CES_PART
        AccountEventProvider::EventPublishAsUser(
            EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT, localId);
        AccountEventProvider::EventPublishAsUser(
            EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT, localId);
#endif // HAS_CES_PART
    }
    return ERR_OK;
#else
    return SendMultiSpaceLogoutOnDelOsAccount(localId);
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
}
} // namespace AccountSA
} // namespace OHOS

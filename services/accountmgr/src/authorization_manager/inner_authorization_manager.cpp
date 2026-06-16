/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "inner_authorization_manager.h"

#include <cstdint>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <securec.h>
#include <set>
#include <string>
#include <sstream>
#include <utility>
#include <vector>

#include "account_error_no.h"
#include "account_hisysevent_adapter.h"
#include "account_iam_info.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "authorization_common.h"
#include "bundle_manager_adapter.h"
#include "iadmin_authorization_callback.h"
#include "iinner_os_account_manager.h"
#include "inner_account_iam_manager.h"
#include "ipc_skeleton.h"
#include "os_account_constants.h"
#include "os_account_info.h"
#include "privilege_cache_manager.h"
#include "privilege_hisysevent_utils.h"
#include "privilege_utils.h"
#include "privileges_map.h"
#include "service_extension_connect.h"
#include "singleton.h"
#include "tee_auth_adapter.h"
#include "user_auth_client.h"
#include "token_setproc.h"

namespace OHOS {
namespace AccountSA {
namespace {
std::mutex g_mutex;
static std::map<int32_t, sptr<IAuthorizationCallback>> g_callbackMap;
static std::map<int32_t, sptr<IRemoteObject>> g_requestRemoteObjectMap;
static std::map<int32_t, sptr<ConnectAbilityCallback>> g_connectbackMap;
static std::map<int32_t, int32_t> g_pidToUidMap;
std::map<int32_t, SmartPidFd> g_pidFdMap;
static std::map<std::string, int32_t> g_sessionIdToPidMap;  // sessionId → callingPid (modal app only)
static const std::int32_t GRANT_VALIDITY_PERIOD = 300;
const std::int32_t START_USER_ID = 100;
const std::string PERMISSION_START_SYSTEM_DIALOG = "ohos.permission.START_SYSTEM_DIALOG";
const std::string RANDOM_DEVICE_PATH = "/dev/urandom";
constexpr int HEX_WIDTH_UINT64 = 16;
constexpr int HEX_WIDTH_UINT8 = 2;
static std::atomic<uint64_t> g_sessionIdCounter{0};
static std::atomic<bool> g_sessionIdCounterInitialized{false};
static std::mutex g_sessionIdInitMutex;

static ErrCode InitSessionIdCounterOnce()
{
    if (g_sessionIdCounterInitialized.load(std::memory_order_acquire)) {
        return ERR_OK;
    }
    std::lock_guard<std::mutex> lock(g_sessionIdInitMutex);
    if (g_sessionIdCounterInitialized.load(std::memory_order_relaxed)) {
        return ERR_OK;
    }
    int64_t bootTimeMs = 0;
    ErrCode ret = GetUptimeMs(bootTimeMs);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to get boot time, errCode=%{public}d", ret);
        return ret;
    }
    g_sessionIdCounter.store(static_cast<uint64_t>(bootTimeMs), std::memory_order_release);
    g_sessionIdCounterInitialized.store(true, std::memory_order_release);
    return ERR_OK;
}
}

static void CleanupAuthorizationSessionMaps(int32_t requesterPid)
{
    auto connectIt = g_connectbackMap.find(requesterPid);
    if (connectIt != g_connectbackMap.end()) {
        ConnectAbilityInfo info;
        connectIt->second->GetConnectInfo(info);
        g_sessionIdToPidMap.erase(info.sessionId);
    }
    g_connectbackMap.erase(requesterPid);
    g_requestRemoteObjectMap.erase(requesterPid);
    g_pidToUidMap.erase(requesterPid);
    g_pidFdMap.erase(requesterPid);
}

static std::string GetHexString(uint64_t num)
{
    std::stringstream ss;
    ss << std::hex << std::setw(HEX_WIDTH_UINT64) << std::setfill('0') << num;
    return ss.str();
}

static std::string GenerateRandom64()
{
    uint64_t randomValue = 0;
    int fd = open(RANDOM_DEVICE_PATH.c_str(), O_RDONLY);
    if (fd < 0) {
        ACCOUNT_LOGW("Failed to open %{public}s", RANDOM_DEVICE_PATH.c_str());
        return "";
    }
    ssize_t readSize = read(fd, &randomValue, sizeof(uint64_t));
    if (readSize != sizeof(uint64_t)) {
        ACCOUNT_LOGW("Failed to read random data, readSize=%{public}zd", readSize);
        close(fd);
        return "";
    }
    close(fd);
    return GetHexString(randomValue);
}

static std::string GenerateSessionId()
{
    ErrCode ret = InitSessionIdCounterOnce();
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to init sessionId counter, errCode=%{public}d", ret);
        return "";
    }
    std::string randomStr = GenerateRandom64();
    if (randomStr.empty()) {
        ACCOUNT_LOGE("Failed to generate random part for sessionId");
        return "";
    }

    uint64_t counter = g_sessionIdCounter.fetch_add(1);
    std::string counterStr = GetHexString(counter);
    return randomStr + counterStr;
}

static std::string VectorToString(const std::vector<uint8_t>& vec)
{
    std::stringstream ss;
    for (uint8_t b : vec) {
        ss << std::hex << std::setw(HEX_WIDTH_UINT8) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

ConnectAbilityCallback::ConnectAbilityCallback(ConnectAbilityInfo &info,
    AcquireOnResultfunc authorizationOnResultfunc, const AuthorizationResult &result)
{
    func_ = authorizationOnResultfunc;
    result_ = result;
    info_ = info;
}

std::function<ErrCode(int32_t,  AuthorizationResult &, int32_t)> acquireAuthorizationOnResultfunc()
{
    return [](int32_t errorCode, AuthorizationResult &result, int32_t callingPid) -> ErrCode {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_callbackMap.find(callingPid);
        if (it == g_callbackMap.end()) {
            ACCOUNT_LOGE("Can not find AuthorizationResultCallback.");
            REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_ACQUIRE_AUTH, ERR_AUTHORIZATION_GET_PROXY_ERROR,
                "Can not find AuthorizationResultCallback.");
            return ERR_AUTHORIZATION_GET_PROXY_ERROR;
        }
        if (it->second == nullptr) {
            ACCOUNT_LOGE("AuthorizationResultCallback is nullptr");
            REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_ACQUIRE_AUTH, ERR_AUTHORIZATION_GET_PROXY_ERROR,
                "AuthorizationResultCallback is nullptr.");
            return ERR_AUTHORIZATION_GET_PROXY_ERROR;
        }
        ErrCode errCode = it->second->OnResult(errorCode, result);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("OnResult failed, errCode:%{public}d", errCode);
            REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_ACQUIRE_AUTH,
                errCode, "Return uiextension result failed");
        }
        CleanupAuthorizationSessionMaps(callingPid);
        g_callbackMap.erase(it);
        return errCode;
    };
}

void ConnectAbilityCallback::GetConnectInfo(ConnectAbilityInfo &info)
{
    info = info_;
}

void ConnectAbilityCallback::UpdateAuthorizationResult(ErrCode errCode, AuthorizationResultCode &resultCode,
    const std::vector<uint8_t> &taToken, int32_t remainValidityTime)
{
    errCode_ = errCode;
    result_.privilege = info_.privilege;
    result_.resultCode = resultCode;
    result_.validityPeriod = remainValidityTime;
    result_.token = taToken;
    hasUpdateAuthInfo_.store(true, std::memory_order_release);
}

bool ConnectAbilityCallback::IsSameSession(std::string &sessionId)
{
    return info_.sessionId == sessionId;
}

ErrCode ConnectAbilityCallback::OnResult(int32_t errorCode, const std::vector<uint8_t> &iamToken, int32_t accountId,
    int32_t iamResultCode)
{
    ACCOUNT_LOGI("ConnectAbilityCallback OnResult errCode:%{public}d,resultCode:%{public}d", errorCode, iamResultCode);
    if (func_ == nullptr) {
        ACCOUNT_LOGE("Func_ is nullptr");
        REPORT_OS_ACCOUNT_FAIL(accountId, PRIVILEGE_OPT_ACQUIRE_AUTH, ERR_AUTHORIZATION_GET_PROXY_ERROR,
            "Func_ is nullptr");
        return ERR_AUTHORIZATION_GET_PROXY_ERROR;
    }
    AuthorizationResult result;
    if (errorCode != ERR_OK) {
        return func_(errorCode, result, info_.callingPid);
    }
    result.resultCode = static_cast<AuthorizationResultCode>(iamResultCode);
    if (iamResultCode != ERR_OK) {
        return func_(ERR_OK, result, info_.callingPid);
    }
    if (hasUpdateAuthInfo_.load(std::memory_order_acquire)) {
        return func_(errCode_, result_, info_.callingPid);
    }
    result.resultCode = AuthorizationResultCode::AUTHORIZATION_CANCELED;
    return func_(ERR_OK, result, info_.callingPid);
}

std::pair<ErrCode, AuthorizationResultCode> InnerAuthorizationManager::ApplyTaAuthorization(
    const std::vector<uint8_t> &iamToken, int32_t accountId, ApplyUserTokenResult &tokenResult,
    ConnectAbilityInfo &info)
{
    // 1. Verify account type
    auto [errCode, resultCode] = VerifyAdminAccount(accountId);
    if (errCode != ERR_OK || resultCode != AuthorizationResultCode::AUTHORIZATION_SUCCESS) {
        return {errCode, resultCode};
    }

    // 2. Call TA authorization
    errCode = CallTaAuthorization(iamToken, accountId, tokenResult, info);
    if (errCode != ERR_OK) {
        return {errCode, AuthorizationResultCode::AUTHORIZATION_SUCCESS};
    }

    // 3. Update privilege cache
    errCode = UpdatePrivilegeCache(info, tokenResult);
    return {errCode, AuthorizationResultCode::AUTHORIZATION_SUCCESS};
}

void InnerAuthorizationManager::AppDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    if (remote == nullptr) {
        ACCOUNT_LOGE("Remote object is nullptr");
        REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_ACQUIRE_AUTH, ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
            "Remote object is nullptr");
        return;
    }

    sptr<IRemoteObject> object = remote.promote();
    if (object == nullptr) {
        ACCOUNT_LOGE("Object is nullptr");
        REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_ACQUIRE_AUTH, ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
            "Object is nullptr");
        return;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto it = g_callbackMap.begin(); it != g_callbackMap.end(); ++it) {
        if (object == it->second->AsObject()) {
            ACCOUNT_LOGI("remove remote.");
            int32_t callingPid = it->first;
            CleanupAuthorizationSessionMaps(callingPid);
            g_callbackMap.erase(it);
            break;
        }
    }
}

InnerAuthorizationManager &InnerAuthorizationManager::GetInstance()
{
    static InnerAuthorizationManager instance;
    return instance;
}

InnerAuthorizationManager::InnerAuthorizationManager()
{}

InnerAuthorizationManager::~InnerAuthorizationManager()
{}

std::pair<ErrCode, AuthorizationResultCode> InnerAuthorizationManager::VerifyAdminAccount(int32_t accountId)
{
    OsAccountType accountType;
    ErrCode errCode = IInnerOsAccountManager::GetInstance().GetOsAccountType(accountId, accountType);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Fail to get OsAccountType, errCode:%{public}d", errCode);
        REPORT_OS_ACCOUNT_FAIL(accountId, PRIVILEGE_OPT_ACQUIRE_AUTH, errCode, "Fail to get OsAccountType");
        return {errCode, AuthorizationResultCode::AUTHORIZATION_SUCCESS};
    }
    if (accountType != OsAccountType::ADMIN) {
        ACCOUNT_LOGE("Fail to check osAccountType, errCode:%{public}d", static_cast<int32_t>(accountType));
        REPORT_OS_ACCOUNT_FAIL(accountId, PRIVILEGE_OPT_ACQUIRE_AUTH,
            static_cast<int32_t>(AuthorizationResultCode::AUTHORIZATION_DENIED), "Fail to check osAccountType");
        return {ERR_OK, AuthorizationResultCode::AUTHORIZATION_DENIED};
    }
    return {ERR_OK, AuthorizationResultCode::AUTHORIZATION_SUCCESS};
}

ErrCode InnerAuthorizationManager::CallTaAuthorization(const std::vector<uint8_t> &iamToken, int32_t accountId,
    ApplyUserTokenResult &tokenResult, ConnectAbilityInfo &info)
{
    ApplyUserTokenParam param;
    param.pid = static_cast<uint32_t>(info.callingPid);
    param.grantUserId = accountId;
    int32_t ret = memcpy_s(param.permission, sizeof(param.permission), info.privilege.data(), info.privilege.size());
    if (ret != EOK) {
        ACCOUNT_LOGE("Get privilege failed due to memcpy_s failed, %{public}d", ret);
        REPORT_OS_ACCOUNT_FAIL(accountId, PRIVILEGE_OPT_ACQUIRE_AUTH, ret,
            "Get privilege failed due to memcpy_s failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    param.permissionSize = info.privilege.size();
    param.authTokenSize = 0;
    (void)memset_s(param.authToken, sizeof(param.authToken), 0, sizeof(param.authToken));
    if (iamToken.size() > AUTH_TOKEN_LEN) {
        ACCOUNT_LOGE("AuthToken size %{public}zu exceeds maximum", iamToken.size());
        REPORT_OS_ACCOUNT_FAIL(accountId, PRIVILEGE_OPT_ACQUIRE_AUTH, ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
            "AuthToken size exceeds maximum");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (iamToken.size() != 0) {
        ret = memcpy_s(param.authToken, sizeof(param.authToken), iamToken.data(), iamToken.size());
        if (ret != EOK) {
            ACCOUNT_LOGE("Get token failed due to memcpy_s failed, %{public}d", ret);
            REPORT_OS_ACCOUNT_FAIL(accountId, PRIVILEGE_OPT_ACQUIRE_AUTH, ret,
                "Get token failed due to memcpy_s failed");
            return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
        }
        param.authTokenSize = iamToken.size();
    }

    param.grantValidityPeriod = info.timeout;

    OsAccountTeeAdapter teeAdapter;
    ErrCode errCode = teeAdapter.TaAcquireAuthorization(param, tokenResult);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Fail to get authorization from ta, errCode:%{public}d", errCode);
        REPORT_OS_ACCOUNT_FAIL(accountId, PRIVILEGE_OPT_ACQUIRE_AUTH, errCode, "Fail to get authorization from ta");
    }
    return errCode;
}

ErrCode InnerAuthorizationManager::UpdatePrivilegeCache(ConnectAbilityInfo &info,
    ApplyUserTokenResult &tokenResult)
{
    uint32_t code;
    bool ret = TransferPrivilegeToCode(info.privilege, code);
    if (!ret) {
        ACCOUNT_LOGE("Fail to check privilege, privilege:%{public}s", info.privilege.c_str());
        REPORT_OS_ACCOUNT_FAIL(info.callingUid / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH,
            ret, "Fail to check privilege");
        return ERR_AUTHORIZATION_CACHE_ERROR;
    }

    AuthenCallerInfo callerInfo;
    callerInfo.privilegeIdx = code;
    callerInfo.pid = info.callingPid;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        callerInfo.remoteObject = g_requestRemoteObjectMap[info.callingPid];
        g_requestRemoteObjectMap.erase(info.callingPid);
    }

    ErrCode errCode = PrivilegeCacheManager::GetInstance().AddCache(callerInfo, tokenResult.grantTime);
    if (errCode != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(info.callingUid / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH, errCode,
            "Fail to add cache.");
        ACCOUNT_LOGE("Fail to add cache privilege=%{public}s approved, errCode:%{public}d",
            info.privilege.c_str(), errCode);
        return ERR_AUTHORIZATION_CACHE_ERROR;
    }
    return ERR_OK;
}

ErrCode InnerAuthorizationManager::AcquireAuthorization(const PrivilegeBriefDef &pdef,
    const AcquireAuthorizationOptions &options, const OsAccountConfig &config,
    const sptr<IRemoteObject> &authorizationCallback, const sptr<IRemoteObject> &requestRemoteObj)
{
    auto callback = iface_cast<IAuthorizationCallback>(authorizationCallback);
    if (callback == nullptr) {
        ACCOUNT_LOGE("Get AuthorizationResultCallback proxy is nullptr");
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH,
            ERR_AUTHORIZATION_GET_PROXY_ERROR, "Get AuthorizationResultCallback proxy is nullptr.");
        return ERR_AUTHORIZATION_GET_PROXY_ERROR;
    }

    AuthorizationResult result;
    result.privilege = pdef.privilegeName;
    result.isReused = options.isReuseNeeded;

    ConnectAbilityInfo info;
    ErrCode errCode = InitializeConnectAbilityInfo(pdef, options, config, info);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("InitializeConnectAbilityInfo failed, errCode=%{public}d", errCode);
        return errCode;
    }
    if (!VerifyWidget(info.bundleName)) {
        ACCOUNT_LOGE("Check bundleName legal failed");
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH,
            ERR_AUTHORIZATION_EXTENSION_ILLEGAL, "Check bundleName legal failed");
        return ERR_AUTHORIZATION_EXTENSION_ILLEGAL;
    }
    if (options.hasContext) {
        return StartUIExtensionConnection(info, config.authAppUIExtensionAbilityName,
            callback, result, requestRemoteObj);
    }
    return StartServiceExtensionConnection(info, config.authAppServiceExtensionAbilityName,
        callback, result, requestRemoteObj);
}

bool InnerAuthorizationManager::VerifyWidget(const std::string &bundleName)
{
    int32_t localId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (localId < START_USER_ID) {
        auto errCode = IInnerOsAccountManager::GetInstance().GetForegroundOsAccountLocalId(
            Constants::DEFAULT_DISPLAY_ID, localId);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Get foreground local id failed");
            REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH,
                errCode, "Get foreground local id failed");
            return false;
        }
    }
    AppExecFwk::BundleInfo bundleInfo;
    bool ret = BundleManagerAdapter::GetInstance()->GetBundleInfo(
        bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, localId);
    if (!ret) {
        ACCOUNT_LOGE("Failed to get bundleInfo");
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, -1, "Failed to get bundleInfo");
        return false;
    }
    auto result = AccountPermissionManager::VerifyPermission(bundleInfo.applicationInfo.accessTokenId,
        PERMISSION_START_SYSTEM_DIALOG);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to verify auth permission, result = %{public}d", result);
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, result, "Failed to verify auth permission");
        return false;
    }
    return true;
}

bool InnerAuthorizationManager::GetAuthSessionInfo(const std::vector<uint8_t> &inputChallenge,
    std::string &outSessionId, std::vector<uint8_t> &outChallenge, int32_t widgetPid)
{
    ConnectAbilityInfo info;
    outSessionId = VectorToString(inputChallenge);
    // Modal system: query SessionAbilityConnection singleton (single connection, internal mutex protection)
    if (SessionAbilityConnection::GetInstance().GetConnectInfo(widgetPid, info)) {
        if (outSessionId == info.sessionId) {
            ACCOUNT_LOGD("GetConnectInfo success for modal system");
            outChallenge = info.challenge;
            return true;
        }
    }
    // Non-modal application: query global g_connectbackMap (multiple connections, external mutex protection)
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto it = g_connectbackMap.begin(); it != g_connectbackMap.end(); ++it) {
        if (it->second->IsSameSession(outSessionId)) {
            it->second->GetConnectInfo(info);
            outChallenge = info.challenge;
            ACCOUNT_LOGD("GetConnectInfo success for non-modal system");
            return true;
        }
    }
    ACCOUNT_LOGE("Fail to getConnectInfo, sessionId not found");
    return false;
}

ErrCode InnerAuthorizationManager::UpdateAuthInfo(const std::vector<uint8_t> &iamToken, int32_t accountId,
    int32_t callingPid, const std::string &sessionId)
{
    ConnectAbilityInfo info;
    ApplyUserTokenResult tokenResult;
    std::vector<uint8_t> token;
    bool isModalSystem = false;
    // Determine if this is a modal system request by checking SessionAbilityConnection
    if (SessionAbilityConnection::GetInstance().GetConnectInfo(callingPid, info)) {
        if (sessionId == info.sessionId) {
            isModalSystem = true;
        }
    }
    // Non-modal system: lookup sessionId -> callingPid -> connectIt chain with lock protection
    if (!isModalSystem) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_sessionIdToPidMap.find(sessionId);
        if (it == g_sessionIdToPidMap.end()) {
            ACCOUNT_LOGI("Fail to pid");
            return ERR_AUTHORIZATION_UPDATE_INFO_ERROR;
        }
        auto connectIt = g_connectbackMap.find(it->second);
        if (connectIt == g_connectbackMap.end()) {
            ACCOUNT_LOGI("Fail to getConnectInfo");
            return ERR_AUTHORIZATION_UPDATE_INFO_ERROR;
        }
        connectIt->second->GetConnectInfo(info);
    }
    auto [errCode, resultCode] = ApplyTaAuthorization(iamToken, accountId, tokenResult, info);
    if (errCode == ERR_OK && resultCode == AuthorizationResultCode::AUTHORIZATION_SUCCESS) {
        token.assign(tokenResult.userToken, tokenResult.userToken + tokenResult.userTokenSize);
    }
    ErrCode ret = ERR_OK;
    if (isModalSystem) {
        ret = SessionAbilityConnection::GetInstance().SaveAuthorizationResult(errCode, resultCode, token,
            tokenResult.remainValidityTime);
    } else {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_connectbackMap.find(info.callingPid);
        // Callback not found is not an error - client may have disconnected, return ERR_OK
        if (it == g_connectbackMap.end()) {
            ACCOUNT_LOGE("Can not find AuthorizationResultCallback.");
            REPORT_OS_ACCOUNT_FAIL(accountId, PRIVILEGE_OPT_ACQUIRE_AUTH, ERR_AUTHORIZATION_GET_PROXY_ERROR,
                "Can not find AuthorizationResultCallback.");
            return ERR_OK;
        }
        it->second->UpdateAuthorizationResult(errCode, resultCode, token, tokenResult.remainValidityTime);
    }
    // Security practice: clear sensitive token data after use
    if (!token.empty()) {
        std::fill(token.begin(), token.end(), 0);
    }
    return ret;
}

bool InnerAuthorizationManager::HasExtensionConnect()
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto it = g_pidToUidMap.begin(); it != g_pidToUidMap.end(); ++it) {
        if (callingUid == it->second) {
            return true;
        }
    }
    return false;
}

ErrCode InnerAuthorizationManager::InitializeConnectAbilityInfo(const PrivilegeBriefDef &pdef,
    const AcquireAuthorizationOptions &options, const OsAccountConfig &config, ConnectAbilityInfo &info)
{
    info.privilege = pdef.privilegeName;
    info.description = pdef.description;
    info.timeout = pdef.timeout;
    info.bundleName = config.authAppBundleName;
    info.challenge = options.challenge;
    info.callingUid = IPCSkeleton::GetCallingUid();
    info.callingPid = IPCSkeleton::GetCallingPid();
    info.sessionId = GenerateSessionId();
    if (info.sessionId.empty()) {
        ACCOUNT_LOGE("Failed to generate sessionId");
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH,
            ERR_AUTHORIZATION_GET_CONTENT_ERROR, "Failed to generate sessionId");
        return ERR_AUTHORIZATION_GET_CONTENT_ERROR;
    }
    return ERR_OK;
}

ErrCode InnerAuthorizationManager::StartUIExtensionConnection(const ConnectAbilityInfo &info,
    const std::string &uiAbilityName, const sptr<IAuthorizationCallback> &callback,
    const AuthorizationResult &result, const sptr<IRemoteObject> &requestRemoteObj)
{
    ErrCode errCode = ValidateUIExtensionParams(info, callback, requestRemoteObj);
    if (errCode != ERR_OK) {
        return errCode;
    }

    ConnectAbilityInfo uiInfo = info;
    uiInfo.abilityName = uiAbilityName;

    auto connectCallback = sptr<ConnectAbilityCallback>::MakeSptr(uiInfo, acquireAuthorizationOnResultfunc(), result);
    return StartUIExtensionTask(uiInfo, connectCallback, callback, requestRemoteObj);
}

ErrCode InnerAuthorizationManager::ValidateUIExtensionParams(const ConnectAbilityInfo &info,
    const sptr<IAuthorizationCallback> &callback, const sptr<IRemoteObject> &requestRemoteObj)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr.");
        REPORT_OS_ACCOUNT_FAIL(info.callingUid / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH,
            ERR_AUTHORIZATION_GET_PROXY_ERROR, "Callback is nullptr.");
        return ERR_AUTHORIZATION_GET_PROXY_ERROR;
    }

    if (requestRemoteObj == nullptr) {
        ACCOUNT_LOGE("Request remote object is nullptr");
        REPORT_OS_ACCOUNT_FAIL(info.callingUid / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH,
            ERR_AUTHORIZATION_GET_PROXY_ERROR, "Request remote object is nullptr");
        return ERR_AUTHORIZATION_GET_PROXY_ERROR;
    }

    auto deathRecipient = new (std::nothrow) AppDeathRecipient();
    if (deathRecipient == nullptr) {
        ACCOUNT_LOGE("DeathRecipient is nullptr");
        REPORT_OS_ACCOUNT_FAIL(info.callingUid / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH,
            ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT, "DeathRecipient is nullptr");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }

    if (callback->AsObject() == nullptr || !callback->AsObject()->AddDeathRecipient(deathRecipient)) {
        ACCOUNT_LOGE("Fail to AddDeathRecipient");
        REPORT_OS_ACCOUNT_FAIL(info.callingUid / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH,
            ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT, "Fail to AddDeathRecipient");
        deathRecipient = nullptr;
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }

    return ERR_OK;
}

ErrCode InnerAuthorizationManager::StartUIExtensionTask(const ConnectAbilityInfo &uiInfo,
    const sptr<ConnectAbilityCallback> &connectCallback, const sptr<IAuthorizationCallback> &callback,
    const sptr<IRemoteObject> &requestRemoteObj)
{
    auto task = [this, uiInfo, connectCallback, callback, requestRemoteObj]() {
        this->ExecuteUIExtensionTask(uiInfo, connectCallback, callback, requestRemoteObj);
    };

#ifdef FUZZ_TEST
    task();
#else
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), "OnConnectAbility");
    taskThread.detach();
#endif
    return ERR_OK;
}

void InnerAuthorizationManager::ExecuteUIExtensionTask(const ConnectAbilityInfo &uiInfo,
    const sptr<ConnectAbilityCallback> &connectCallback, const sptr<IAuthorizationCallback> &callback,
    const sptr<IRemoteObject> &requestRemoteObj)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr in task thread");
        REPORT_OS_ACCOUNT_FAIL(uiInfo.callingUid / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH,
            ERR_ACCOUNT_COMMON_INVALID_PARAMETER, "Callback is null");
        return;
    }

    ErrCode errCode = callback->OnConnectAbility(uiInfo, connectCallback->AsObject());
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("OnConnectAbility failed, errCode:%{public}d", errCode);
        REPORT_OS_ACCOUNT_FAIL(uiInfo.callingUid / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH,
            errCode, "OnConnectAbility failed");
        AuthorizationResult result;
        errCode = callback->OnResult(errCode, result);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("OnResult failed, errCode:%{public}d", errCode);
            REPORT_OS_ACCOUNT_FAIL(uiInfo.callingUid / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH,
                errCode, "ExecuteUIExtensionTask call OnResult failed");
        }
        return;
    }

    if (requestRemoteObj == nullptr) {
        ACCOUNT_LOGE("Request remote object is nullptr");
        REPORT_OS_ACCOUNT_FAIL(uiInfo.callingUid / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH,
            ERR_ACCOUNT_COMMON_INVALID_PARAMETER, "Request remote object");
        return;
    }

    bool ret = StoreCallbackMaps(uiInfo, callback, connectCallback, requestRemoteObj);
    if (!ret) {
        ACCOUNT_LOGE("StoreCallbackMaps failed.");
        AuthorizationResult result;
        errCode = callback->OnResult(ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR, result);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("OnResult failed, errCode:%{public}d", errCode);
            REPORT_OS_ACCOUNT_FAIL(uiInfo.callingUid / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH,
                errCode, "ExecuteUIExtensionTask call OnResult failed");
        }
        return;
    }
}

bool InnerAuthorizationManager::StoreCallbackMaps(const ConnectAbilityInfo &uiInfo,
    const sptr<IAuthorizationCallback> &callback, const sptr<ConnectAbilityCallback> &connectCallback,
    const sptr<IRemoteObject> &requestRemoteObj)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_callbackMap.find(uiInfo.callingPid);
    if (it != g_callbackMap.end()) {
        ACCOUNT_LOGI("Removing old callback for uid:%{public}d", uiInfo.callingPid);
        CleanupAuthorizationSessionMaps(uiInfo.callingPid);
        g_callbackMap.erase(it);
    }
    SmartPidFd fdPtr = nullptr;
    auto ret = OpenSmartPidFd(uiInfo.callingPid, fdPtr);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("OpenSmartPidFd failed, ret = %{public}d", ret);
        REPORT_OS_ACCOUNT_FAIL(uiInfo.callingUid / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH, ret,
            "OpenSmartPidFd failed");
        return false;
    }
    g_pidFdMap[uiInfo.callingPid] = std::move(fdPtr);
    g_pidToUidMap[uiInfo.callingPid] = uiInfo.callingUid;
    g_callbackMap[uiInfo.callingPid] = callback;
    g_connectbackMap[uiInfo.callingPid] = connectCallback;
    g_requestRemoteObjectMap[uiInfo.callingPid] = requestRemoteObj;
    g_sessionIdToPidMap[uiInfo.sessionId] = uiInfo.callingPid;
    ACCOUNT_LOGI("Successfully stored callback maps for uid:%{public}d", uiInfo.callingPid);
    return true;
}

ErrCode InnerAuthorizationManager::StartServiceExtensionConnection(ConnectAbilityInfo &info,
    const std::string &serviceAbilityName, sptr<IAuthorizationCallback> &callback,
    AuthorizationResult &result, const sptr<IRemoteObject> &requestRemoteObj)
{
    ErrCode errCode = BundleManagerAdapter::GetInstance()->GetNameForUid(
        info.callingUid, info.callingBundleName);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to get bundle name");
        REPORT_OS_ACCOUNT_FAIL(info.callingUid / UID_TRANSFORM_DIVISOR, PRIVILEGE_OPT_ACQUIRE_AUTH, errCode,
            "Failed to get bundle name");
        return errCode;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    g_requestRemoteObjectMap[info.callingPid] = requestRemoteObj;
    info.abilityName = serviceAbilityName;
    return SessionAbilityConnection::GetInstance().SessionConnectExtension(info, callback, result);
}

ErrCode InnerAuthorizationManager::CheckAuthorization(
    const uint32_t privilegeId, const int32_t pid, bool &isAuthorized)
{
    AuthenCallerInfo info;
    info.pid = pid;
    info.privilegeIdx = privilegeId;
    int remainTime = -1;
    ErrCode errCode = PrivilegeCacheManager::GetInstance().CheckPrivilege(info, remainTime);
    isAuthorized = errCode == ERR_OK;
    if ((errCode != ERR_OK) && (errCode != ERR_AUTHORIZATION_PRIVILEGE_DENIED)) {
        ACCOUNT_LOGE("Failed to check privilege, errCode: %{public}d", errCode);
        return ERR_ACCOUNT_COMMON_OPERATION_FAIL;
    }
    ACCOUNT_LOGI("CheckAuthorization successed, isAuthorized: %{public}d, privilegeId: %{public}d, pid: %{public}d",
        isAuthorized, privilegeId, pid);
    return ERR_OK;
}

ErrCode InnerAuthorizationManager::VerifyToken(const std::vector<uint8_t> &token, const std::string &privilege,
    const uint32_t pid, std::vector<uint8_t> &challenge, std::vector<uint8_t> &iamToken)
{
    OsAccountTeeAdapter adapter;
    std::vector<uint8_t> outToken(sizeof(VerifyUserTokenResult), 0);
    ErrCode errCode = adapter.VerifyToken(token, privilege, outToken);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to verify token, errCode:%{public}d", errCode);
        REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_VERIFY_TOKEN, errCode, "Failed to verify token");
        return errCode;
    }

    if (outToken.size() != sizeof(VerifyUserTokenResult)) {
        ACCOUNT_LOGI("Invalid outToken size from TEE");
        REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_VERIFY_TOKEN, errCode,
            "Invalid outToken size from TEE");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    VerifyUserTokenResult tokenRet;
    errno_t err = memcpy_s(&tokenRet, sizeof(VerifyUserTokenResult), outToken.data(), sizeof(VerifyUserTokenResult));
    std::fill(outToken.begin(), outToken.end(), 0);
    if (err != 0) {
        ACCOUNT_LOGI("Failed to memcpy outToken, err: %{public}d", err);
        REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_VERIFY_TOKEN, err, "Failed to memcpy_s outToken");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    uint32_t pidFromToken = tokenRet.userTokenPlain.userTokenDataPlain.pid;
    if (pid != pidFromToken) {
        ACCOUNT_LOGI("Failed to compare pid, VerifyToken operation failed");
        return ERR_AUTHORIZATION_PRIVILEGE_DENIED;
    }
    auto &challengeData = tokenRet.userTokenPlain.userTokenDataPlain.challenge;
    challenge = std::vector<uint8_t>(challengeData, challengeData + sizeof(challengeData));
    auto &iamTokenData = tokenRet.userTokenPlain.userTokenDataPlain.authToken;
    size_t iamTokenSize = tokenRet.userTokenPlain.userTokenDataPlain.authTokenSize;
    iamToken = std::vector<uint8_t>(iamTokenData, iamTokenData + iamTokenSize);
    ACCOUNT_LOGI("VerifyToken successed, privilege: %{public}s, pid: %{public}d", privilege.c_str(), pid);
    return ERR_OK;
}

ErrCode InnerAuthorizationManager::AcquireAdminAuthorization(int32_t accountId,
    const std::vector<uint8_t> &challenge, const sptr<IAdminAuthorizationCallback> &callback,
    const std::string &privilege, int32_t callingPid)
{
    ACCOUNT_LOGI("AcquireAdminAuthorization accountId: %{public}d", accountId);

    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    bool isExists = false;
    IInnerOsAccountManager::GetInstance().IsOsAccountExists(accountId, isExists);
    if (!isExists) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    sptr<AuthCallbackDeathRecipient> deathRecipient = new (std::nothrow) AuthCallbackDeathRecipient();
    if ((deathRecipient == nullptr) || (!callback->AsObject()->AddDeathRecipient(deathRecipient))) {
        ACCOUNT_LOGE("Add death recipient failed");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }

    auto callbackWrapper = std::make_shared<AdminAuthCallback>(challenge, callback, accountId, callingPid, privilege);
    callbackWrapper->SetDeathRecipient(deathRecipient);

    UserIam::UserAuth::AuthParam iamAuthParam;
    iamAuthParam.authType = UserIam::UserAuth::AuthType::PIN;
    iamAuthParam.authIntent = UserIam::UserAuth::AuthIntent::DEFAULT;
    iamAuthParam.authTrustLevel = UserIam::UserAuth::AuthTrustLevel::ATL4;
    iamAuthParam.userId = accountId;
    iamAuthParam.challenge = challenge;
    SetFirstCallerTokenID(IPCSkeleton::GetCallingTokenID());
    uint64_t contextId = UserIam::UserAuth::UserAuthClient::GetInstance().BeginAuthentication(iamAuthParam,
        callbackWrapper);
    deathRecipient->SetContextId(contextId);
    return ERR_OK;
}

ErrCode AdminAuthCallback::CallTAForToken(int32_t accountId, const std::vector<uint8_t> &iamToken,
    std::vector<uint8_t> &token)
{
    token.clear();

    OsAccountTeeAdapter teeAdapter;
    ApplyUserTokenParam param;
    param.pid = static_cast<uint32_t>(callingPid_);
    param.grantUserId = accountId;
    param.permissionSize = 0;
    param.grantValidityPeriod = GRANT_VALIDITY_PERIOD;
    if (!privilege_.empty()) {
        errno_t copyRet = memcpy_s(param.permission, sizeof(param.permission), privilege_.data(), privilege_.size());
        if (copyRet != 0) {
            ACCOUNT_LOGE("Failed to copy privilege, err:%{public}d", copyRet);
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }
        param.permissionSize = static_cast<uint8_t>(privilege_.size());
    }
    errno_t err = memcpy_s(param.challenge, sizeof(param.challenge), challenge_.data(), challenge_.size());
    if (err != 0) {
        ACCOUNT_LOGE("Failed to copy challenge, err:%{public}d", err);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (iamToken.size() != 0) {
        err = memcpy_s(param.authToken, sizeof(param.authToken), iamToken.data(), iamToken.size());
        if (err != 0) {
            ACCOUNT_LOGE("Failed to copy iamToken, err:%{public}d", err);
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }
    }
    param.authTokenSize = iamToken.size();

    ApplyUserTokenResult tokenResult;
    ErrCode errCode = teeAdapter.TaAcquireAuthorization(param, tokenResult);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to call TA for token, errCode:%{public}d", errCode);
        return errCode;
    }

    token = std::vector<uint8_t>(tokenResult.userToken, tokenResult.userToken + tokenResult.userTokenSize);
    ACCOUNT_LOGI("CallTAForToken success, token size:%{public}zu", token.size());

    return ERR_OK;
}

AdminAuthCallback::AdminAuthCallback(
    const std::vector<uint8_t> &challenge, const sptr<IAdminAuthorizationCallback> &callback, int32_t userId,
    int32_t callingPid,
    const std::string &privilege)
    : userId_(userId), callingPid_(callingPid), innerCallback_(callback), challenge_(challenge), privilege_(privilege)
{
}

void AdminAuthCallback::SetDeathRecipient(const sptr<AuthCallbackDeathRecipient> &deathRecipient)
{
    deathRecipient_ = deathRecipient;
}

void AdminAuthCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    return;
}

void AdminAuthCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    AdminAuthorizationResult adminAuthResult;
    adminAuthResult.resultCode = result;
    adminAuthResult.token = {};

    if (result != ERR_OK && result != ERR_IAM_NOT_ENROLLED) {
        innerCallback_->OnResult(adminAuthResult);
        ACCOUNT_LOGE("Authentication failed, errCode: %{public}d", result);
        return;
    }

    std::vector<uint8_t> iamToken;
    int32_t accountId;
    if (result == ERR_OK) {
        extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, iamToken);
        extraInfo.GetInt32Value(Attributes::ATTR_USER_ID, accountId);
        if (accountId != userId_) {
            adminAuthResult.resultCode = ERR_AUTHORIZATION_INVALID_ADMIN_ACCOUNT_OR_PASSWORD;
            innerCallback_->OnResult(adminAuthResult);
            ACCOUNT_LOGE("Authentication failed, errCode: %{public}d", result);
            return;
        }
    } else {
        accountId = userId_;
    }
    std::vector<uint8_t> taToken;
    ErrCode errCode = AdminAuthCallback::CallTAForToken(accountId, iamToken, taToken);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to call TA for token, errCode: %{public}d", errCode);
        adminAuthResult.resultCode = errCode;
        innerCallback_->OnResult(adminAuthResult);
        return;
    }
    adminAuthResult.resultCode = ERR_OK;
    adminAuthResult.token = taToken;
    innerCallback_->OnResult(adminAuthResult);
}
}
}

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
#include <map>
#include <mutex>
#include <securec.h>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "account_error_no.h"
#include "account_hisysevent_adapter.h"
#include "account_iam_info.h"
#include "account_log_wrapper.h"
#include "authorization_common.h"
#include "bundle_manager_adapter.h"
#include "iadmin_authorization_callback.h"
#include "iinner_os_account_manager.h"
#include "inner_account_iam_manager.h"
#include "ipc_skeleton.h"
#include "os_account_info.h"
#include "privilege_cache_manager.h"
#include "privilege_hisysevent_utils.h"
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
static std::map<int32_t, std::shared_ptr<ConnectAbilityCallback>> g_connectbackMap;
static std::map<int32_t, int32_t> g_pidToUidMap;
static const std::int32_t GRANT_VALIDITY_PERIOD = 300;
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
        g_callbackMap.erase(it);
        g_connectbackMap.erase(callingPid);
        g_requestRemoteObjectMap.erase(callingPid);
        g_pidToUidMap.erase(callingPid);
        return errCode;
    };
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
    result_.resultCode = static_cast<AuthorizationResultCode>(iamResultCode);
    if (errorCode != ERR_OK) {
        return func_(errorCode, result_, info_.callingPid);
    }
    if (iamResultCode != ERR_OK) {
        return func_(ERR_OK, result_, info_.callingPid);
    }
    ApplyUserTokenResult tokenResult;
    auto [errCode, resultCode] =
        InnerAuthorizationManager::GetInstance().ApplyTaAuthorization(iamToken, accountId, tokenResult, info_);
    result_.resultCode = resultCode;
    if (errCode == ERR_OK && resultCode == AuthorizationResultCode::AUTHORIZATION_SUCCESS) {
        result_.validityPeriod = tokenResult.remainValidityTime;
        result_.token.assign(tokenResult.userToken, tokenResult.userToken + tokenResult.userTokenSize);
    }
    return func_(errCode, result_, info_.callingPid);
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
            it->second = nullptr;
            g_callbackMap.erase(it);
            g_connectbackMap.erase(callingPid);
            g_requestRemoteObjectMap.erase(callingPid);
            g_pidToUidMap.erase(callingPid);
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
    (void)memcpy_s(param.permission, sizeof(param.permission), info.privilege.data(), info.privilege.size());
    param.permissionSize = info.privilege.size();
    (void)memcpy_s(param.authToken, sizeof(param.authToken), iamToken.data(), iamToken.size() * sizeof(uint8_t));
    param.authTokenSize = iamToken.size();
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
        return ret;
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
    InitializeConnectAbilityInfo(pdef, options, config, info);

    if (options.hasContext) {
        return StartUIExtensionConnection(info, config.authAppUIExtensionAbilityName,
            callback, result, requestRemoteObj);
    }
    return StartServiceExtensionConnection(info, config.authAppServiceExtensionAbilityName,
        callback, result, requestRemoteObj);
}

ErrCode InnerAuthorizationManager::UpdateAuthInfo(const std::vector<uint8_t> &iamToken, int32_t accountId,
    int32_t callingPid)
{
    ConnectAbilityInfo info;
    ApplyUserTokenResult tokenResult;
    std::vector<uint8_t> token;
    if (!SessionAbilityConnection::GetInstance().GetConnectInfo(callingPid, info)) {
        ACCOUNT_LOGI("Fail to getConnectInfo");
        return ERR_OK;
    }
    auto [errCode, resultCode] = ApplyTaAuthorization(iamToken, accountId, tokenResult, info);
    if (errCode == ERR_OK && resultCode == AuthorizationResultCode::AUTHORIZATION_SUCCESS) {
        token.assign(tokenResult.userToken, tokenResult.userToken + tokenResult.userTokenSize);
    }
    ErrCode ret = SessionAbilityConnection::GetInstance().SaveAuthorizationResult(errCode, resultCode, token,
        tokenResult.remainValidityTime);
    std::fill(token.begin(), token.end(), 0);
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

void InnerAuthorizationManager::InitializeConnectAbilityInfo(const PrivilegeBriefDef &pdef,
    const AcquireAuthorizationOptions &options, const OsAccountConfig &config, ConnectAbilityInfo &info)
{
    info.privilege = pdef.privilegeName;
    info.description = pdef.description;
    info.timeout = pdef.timeout;
    info.bundleName = config.authAppBundleName;
    info.challenge = options.challenge;
    info.callingUid = IPCSkeleton::GetCallingUid();
    info.callingPid = IPCSkeleton::GetCallingPid();
}

ErrCode InnerAuthorizationManager::StartUIExtensionConnection(const ConnectAbilityInfo &info,
    const std::string &uiAbilityName, const sptr<IAuthorizationCallback> &callback,
    const AuthorizationResult &result, const sptr<IRemoteObject> &requestRemoteObj)
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
    ConnectAbilityInfo uiInfo = info;
    uiInfo.abilityName = uiAbilityName;

    auto connectCallback = std::make_shared<ConnectAbilityCallback>(
        uiInfo, acquireAuthorizationOnResultfunc(), result);

    // Use sptr directly to keep objects alive during async operation
    auto task = [uiInfo, connectCallback, callback, requestRemoteObj]() {
        // Verify callback is still valid before calling
        if (callback == nullptr) {
            ACCOUNT_LOGE("Callback is nullptr in task thread");
            return;
        }

        ErrCode errCode = callback->OnConnectAbility(uiInfo, connectCallback->AsObject());
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("OnConnectAbility failed, errCode:%{public}d", errCode);
            return;
        }

        // Verify requestRemoteObj is still valid before storing
        if (requestRemoteObj == nullptr) {
            ACCOUNT_LOGE("Request remote object is nullptr");
            return;
        }

        // Store in global maps, keeping strong references
        {
            std::lock_guard<std::mutex> lock(g_mutex);

            // Clean up any existing entries for this UID first
            auto it = g_callbackMap.find(uiInfo.callingPid);
            if (it != g_callbackMap.end()) {
                ACCOUNT_LOGI("Removing old callback for uid:%{public}d", uiInfo.callingPid);
                g_callbackMap.erase(it);
                g_connectbackMap.erase(uiInfo.callingPid);
                g_requestRemoteObjectMap.erase(uiInfo.callingPid);
                g_pidToUidMap.erase(uiInfo.callingPid);
            }
            g_pidToUidMap[uiInfo.callingPid] = uiInfo.callingUid;
            g_callbackMap[uiInfo.callingPid] = callback;
            g_connectbackMap[uiInfo.callingPid] = connectCallback;
            g_requestRemoteObjectMap[uiInfo.callingPid] = requestRemoteObj;
            ACCOUNT_LOGI("Successfully stored callback maps for uid:%{public}d", uiInfo.callingPid);
        }
    };

    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), "OnConnectAbility");
    taskThread.detach();
    return ERR_OK;
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
    ErrCode errCode = adapter.VerifyToken(token, outToken);
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
    if (err != 0) {
        ACCOUNT_LOGI("Failed to memcpy outToken, err: %{public}d", err);
        REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_VERIFY_TOKEN, err, "Failed to memcpy_s outToken");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    uint32_t pidFromToken = tokenRet.userTokenPlain.userTokenDataPlain.pid;
    uint32_t privilegeIdFromToken = tokenRet.userTokenPlain.userTokenDataPlain.privilege;
    if (pid != pidFromToken || privilege != TransferCodeToPrivilege(privilegeIdFromToken)) {
        ACCOUNT_LOGI("Failed to compare pid or privilegeId, VerifyToken operation failed");
        return ERR_OK;
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
    const std::vector<uint8_t> &challenge, const sptr<IAdminAuthorizationCallback> &callback)
{
    ACCOUNT_LOGI("AcquireAdminAuthorization accountId: %{public}d", accountId);

    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    ErrCode errCode = CallUserIAMForAuthentication(accountId, challenge, callback);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to call UserIAM for authentication, errCode: %{public}d", errCode);
        return errCode;
    }

    return ERR_OK;
}

void InnerAuthorizationManager::CopyAuthParam(const AuthParam &authParam, UserIam::UserAuth::AuthParam &iamAuthParam)
{
    iamAuthParam.userId = authParam.userId;
    iamAuthParam.challenge = authParam.challenge;
    iamAuthParam.authType = authParam.authType;
    iamAuthParam.authTrustLevel = authParam.authTrustLevel;
    if (static_cast<int32_t>(authParam.authIntent) == AUTHORIZATION_INTENT_NUM) {
        iamAuthParam.authIntent = UserIam::UserAuth::AuthIntent::DEFAULT;
    } else {
        iamAuthParam.authIntent = static_cast<UserIam::UserAuth::AuthIntent>(authParam.authIntent);
    }
    if (authParam.remoteAuthParam != std::nullopt) {
        iamAuthParam.remoteAuthParam = UserIam::UserAuth::RemoteAuthParam();
        if (authParam.remoteAuthParam.value().verifierNetworkId != std::nullopt) {
            iamAuthParam.remoteAuthParam.value().verifierNetworkId =
                authParam.remoteAuthParam.value().verifierNetworkId.value();
        }
        if (authParam.remoteAuthParam.value().collectorNetworkId != std::nullopt) {
            iamAuthParam.remoteAuthParam.value().collectorNetworkId =
                authParam.remoteAuthParam.value().collectorNetworkId.value();
        }
        if (authParam.remoteAuthParam.value().collectorTokenId != std::nullopt) {
            iamAuthParam.remoteAuthParam.value().collectorTokenId =
                authParam.remoteAuthParam.value().collectorTokenId.value();
        }
    }
}

ErrCode InnerAuthorizationManager::CallUserIAMForAuthentication(int32_t accountId,
    const std::vector<uint8_t> &challenge, const sptr<IAdminAuthorizationCallback> &callback)
{
    uint64_t contextId = 0;
    ACCOUNT_LOGI("CallUserIAMForAuthentication accountId: %{public}d", accountId);

    AuthParam authParam;
    authParam.authType = AuthType::PIN;
    authParam.authIntent = AuthIntent::DEFAULT;
    authParam.authTrustLevel = AuthTrustLevel::ATL4;
    authParam.userId = accountId;
    authParam.challenge = challenge;
    
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    OsAccountInfo osAccountInfo;
    if ((authParam.remoteAuthParam == std::nullopt) &&
        (IInnerOsAccountManager::GetInstance().GetRealOsAccountInfoById(authParam.userId,
            osAccountInfo)) != ERR_OK) {
        ACCOUNT_LOGE("Account does not exist");
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    bool isDeactivating = false;
    IInnerOsAccountManager::GetInstance().IsOsAccountDeactivating(authParam.userId, isDeactivating);
    if (isDeactivating) {
        ACCOUNT_LOGE("The target account is deactivating, accountId:%{public}d", authParam.userId);
        return ERR_IAM_BUSY;
    }
#ifdef SUPPORT_LOCK_OS_ACCOUNT
    bool isLocking = false;
    IInnerOsAccountManager::GetInstance().IsOsAccountLocking(authParam.userId, isLocking);
    if (isLocking) {
        ACCOUNT_LOGE("The target account is isLocking, accountId:%{public}d", authParam.userId);
        return ERR_IAM_BUSY;
    }
#endif
    sptr<AuthCallbackDeathRecipient> deathRecipient = new (std::nothrow) AuthCallbackDeathRecipient();
    if ((deathRecipient == nullptr) || (!callback->AsObject()->AddDeathRecipient(deathRecipient))) {
        ACCOUNT_LOGE("failed to add death recipient for auth callback");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }

    auto callbackWrapper = std::make_shared<AdminAuthCallback>(challenge, callback, accountId);
    callbackWrapper->SetDeathRecipient(deathRecipient);

    UserIam::UserAuth::AuthParam iamAuthParam;
    CopyAuthParam(authParam, iamAuthParam);
    ACCOUNT_LOGI("Start to auth user.");
    SetFirstCallerTokenID(IPCSkeleton::GetCallingTokenID());
    contextId = UserIam::UserAuth::UserAuthClient::GetInstance().BeginAuthentication(iamAuthParam, callbackWrapper);
    deathRecipient->SetContextId(contextId);
    return ERR_OK;
}

ErrCode AdminAuthCallback::CallTAForToken(int32_t accountId,
    const std::vector<uint8_t> &challenge, const std::vector<uint8_t> &iamToken, std::vector<uint8_t> &token)
{
    ACCOUNT_LOGI("CallTAForToken accountId: %{public}d", accountId);
    token.clear();

    OsAccountTeeAdapter teeAdapter;
    ApplyUserTokenParam param;
    param.pid = static_cast<uint32_t>(IPCSkeleton::GetCallingPid());
    param.grantUserId = accountId;
    param.permissionSize = 0;
    param.grantValidityPeriod = GRANT_VALIDITY_PERIOD;
    errno_t err = memcpy_s(param.challenge, sizeof(param.challenge), challenge.data(),
        challenge.size());
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
    const std::vector<uint8_t> &challenge, const sptr<IAdminAuthorizationCallback> &callback, int32_t userId)
    : userId_(userId), innerCallback_(callback), challenge_(challenge)
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
    ErrCode errCode = AdminAuthCallback::CallTAForToken(accountId, challenge_, iamToken, taToken);
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

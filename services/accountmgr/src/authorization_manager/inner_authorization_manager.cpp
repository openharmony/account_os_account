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
#include "account_log_wrapper.h"
#include "authorization_common.h"
#include "bundle_manager_adapter.h"
#include "iauthorization_callback.h"
#include "iinner_os_account_manager.h"
#include "ipc_skeleton.h"
#include "os_account_info.h"
#include "privilege_cache_manager.h"
#include "privilege_hisysevent_utils.h"
#include "privileges_map.h"
#include "service_extension_connect.h"
#include "securec.h"

namespace OHOS {
namespace AccountSA {
namespace {
std::mutex g_mutex;
static std::map<int32_t, sptr<IAuthorizationCallback>> g_callbackMap;
static std::map<int32_t, sptr<IRemoteObject>> g_requestRemoteObjectMap;
static std::map<int32_t, std::shared_ptr<ConnectAbilityCallback>> g_connectbackMap;
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
            return ERR_AUTHORIZATION_GET_PROXY_ERROR;
        }
        if (it->second == nullptr) {
            ACCOUNT_LOGE("AuthorizationResultCallback is nullptr");
            return ERR_AUTHORIZATION_GET_PROXY_ERROR;
        }
        ErrCode errCode = it->second->OnResult(errorCode, result);
        g_callbackMap.erase(it);
        g_connectbackMap.erase(callingPid);
        g_requestRemoteObjectMap.erase(callingPid);
        return errCode;
    };
}

ErrCode ConnectAbilityCallback::OnResult(int32_t errorCode, const std::vector<uint8_t> &iamToken, int32_t accountId,
    int32_t iamResultCode)
{
    ACCOUNT_LOGI("ConnectAbilityCallback OnResult errCode:%{public}d,resultCode:%{public}d", errorCode, iamResultCode);
    if (func_ == nullptr) {
        ACCOUNT_LOGE("Get AuthorizationResultCallback proxy is nullptr");
        REPORT_OS_ACCOUNT_FAIL(accountId, Constants::ACQUIRE_AUTH, ERR_AUTHORIZATION_GET_PROXY_ERROR,
            "Get proxy is nullptr");
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
        std::vector<uint8_t> token(tokenResult.userToken, tokenResult.userToken + tokenResult.userTokenSize);
        result_.validityPeriod = tokenResult.remainValidityTime;
        result_.token = token;
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
    ACCOUNT_LOGI("enter");
    if (remote == nullptr) {
        ACCOUNT_LOGE("Remote object is nullptr");
        REPORT_OS_ACCOUNT_FAIL(-1, Constants::ACQUIRE_AUTH, ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
            "Remote object is nullptr");
        return;
    }

    sptr<IRemoteObject> object = remote.promote();
    if (object == nullptr) {
        ACCOUNT_LOGE("Object is nullptr");
        REPORT_OS_ACCOUNT_FAIL(-1, Constants::ACQUIRE_AUTH, ERR_ACCOUNT_COMMON_INVALID_PARAMETER, "Object is nullptr");
        return;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto it = g_callbackMap.begin(); it != g_callbackMap.end(); ++it) {
        if (object == it->second->AsObject()) {
            ACCOUNT_LOGI("remove remote.");
            it->second = nullptr;
            g_callbackMap.erase(it);
            g_connectbackMap.erase(it->first);
            g_requestRemoteObjectMap.erase(it->first);
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
        REPORT_OS_ACCOUNT_FAIL(accountId, Constants::ACQUIRE_AUTH, errCode, "Fail to get OsAccountType");
        return {errCode, AuthorizationResultCode::AUTHORIZATION_SUCCESS};
    }
    if (accountType != OsAccountType::ADMIN) {
        ACCOUNT_LOGE("Fail to check osAccountType, errCode:%{public}d", static_cast<int32_t>(accountType));
        REPORT_OS_ACCOUNT_FAIL(accountId, Constants::ACQUIRE_AUTH,
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
        REPORT_OS_ACCOUNT_FAIL(accountId, Constants::ACQUIRE_AUTH, errCode, "Fail to get authorization from ta");
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
        REPORT_OS_ACCOUNT_FAIL(info.callingUid / UID_TRANSFORM_DIVISOR, Constants::ACQUIRE_AUTH,
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
        REPORT_OS_ACCOUNT_FAIL(info.callingUid / UID_TRANSFORM_DIVISOR, Constants::ACQUIRE_AUTH, errCode,
            "Fail to check privilege approved.");
        ACCOUNT_LOGE("Fail to check privilege=%{public}s approved, errCode:%{public}d",
            info.privilege.c_str(), errCode);
        return ERR_AUTHORIZATION_CACHE_ERROR;
    }
    return ERR_OK;
}

ErrCode InnerAuthorizationManager::AcquireAuthorization(const PrivilegeBriefDef &pdef,
    const AcquireAuthorizationOptions &options, const OsAccountConfig &config,
    const sptr<IRemoteObject> &authorizationCallback, const sptr<IRemoteObject> &requestRemoteObj)
{
    ACCOUNT_LOGI("AcquireAuthorization privilege:%{public}s", pdef.privilegeName);
    auto callback = iface_cast<IAuthorizationCallback>(authorizationCallback);
    if (callback == nullptr) {
        ACCOUNT_LOGE("Get AuthorizationResultCallback proxy is nullptr");
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
    int32_t callingUid)
{
    ConnectAbilityInfo info;
    ApplyUserTokenResult tokenResult;
    std::vector<uint8_t> token;
    SessionAbilityConnection::GetInstance().GetConnectInfo(callingUid, info);
    auto [errCode, resultCode] = ApplyTaAuthorization(iamToken, accountId, tokenResult, info);
    if (errCode == ERR_OK && resultCode == AuthorizationResultCode::AUTHORIZATION_SUCCESS) {
        token.assign(tokenResult.userToken, tokenResult.userToken + tokenResult.userTokenSize);
    }
    ACCOUNT_LOGI("Get auth result, resultCode:%{public}d", static_cast<int32_t>(resultCode));
    return SessionAbilityConnection::GetInstance().SaveAuthorizationResult(errCode, resultCode, token,
        tokenResult.remainValidityTime);
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
        ACCOUNT_LOGE("Authorization callback is nullptr");
        return ERR_AUTHORIZATION_GET_PROXY_ERROR;
    }

    if (requestRemoteObj == nullptr) {
        ACCOUNT_LOGE("Request remote object is nullptr");
        return ERR_AUTHORIZATION_GET_PROXY_ERROR;
    }
    auto deathRecipient = new (std::nothrow) AppDeathRecipient();
    if (deathRecipient == nullptr) {
        ACCOUNT_LOGE("DeathRecipient is nullptr");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }
    if (!callback->AsObject()->AddDeathRecipient(deathRecipient)) {
        ACCOUNT_LOGE("Fail to AddDeathRecipient");
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
            }

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
        REPORT_OS_ACCOUNT_FAIL(info.callingUid / UID_TRANSFORM_DIVISOR, Constants::ACQUIRE_AUTH, errCode,
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
    iamToken = std::vector<uint8_t>(iamTokenData, iamTokenData + sizeof(iamTokenData));
    ACCOUNT_LOGI("VerifyToken successed, privilege: %{public}s, pid: %{public}d", privilege.c_str(), pid);
    return ERR_OK;
}
}
}

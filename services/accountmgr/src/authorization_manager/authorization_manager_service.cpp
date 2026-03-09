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

#include "authorization_manager_service.h"

#include "account_error_no.h"
#include "account_hisysevent_adapter.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "bundle_manager_adapter.h"
#include "iinner_os_account_manager.h"
#include "inner_authorization_manager.h"
#include "ipc_skeleton.h"
#include "os_account_control_file_manager.h"
#include "parameters.h"
#include "privilege_cache_manager.h"
#include "privilege_hisysevent_utils.h"
#include "privileges_map.h"
#include "service_extension_connect.h"

namespace OHOS {
namespace AccountSA {
namespace {
const char PERMISSION_ACQUIRE_AUTHORIZATION[] = "ohos.permission.ACQUIRE_LOCAL_ACCOUNT_AUTHORIZATION";
const char PERMISSION_START_SYSTEM_DIALOG[] = "ohos.permission.START_SYSTEM_DIALOG";
const char PERMISSION_ACCESS_USER_AUTH_INTERNAL[] = "ohos.permission.ACCESS_USER_AUTH_INTERNAL";
constexpr std::int32_t MAX_CHALLENGE_LEN = 32;
}
AuthorizationManagerService::AuthorizationManagerService()
{
    OsAccountControlFileManager &fileController = IInnerOsAccountManager::GetInstance().GetFileController();
    fileController.GetOsAccountConfig(config_);
}

AuthorizationManagerService::~AuthorizationManagerService()
{}

ErrCode AuthorizationManagerService::RegisterAuthAppRemoteObject(const sptr<IRemoteObject> &authAppRemoteObj)
{
    if (!SessionAbilityConnection::GetInstance().HasServiceConnect()) {
        ACCOUNT_LOGI("Do not have serviceConnect");
        return ERR_OK;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t localId = callingUid / UID_TRANSFORM_DIVISOR;
    if (authAppRemoteObj == nullptr) {
        ACCOUNT_LOGE("AuthAppRemoteObj is nullptr.");
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
            "RemoteObj is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, result, "The caller is not system application");
        ACCOUNT_LOGE("The caller is not system application, err = %{public}d.", result);
        return result;
    }
    result = AccountPermissionManager::VerifyPermission(PERMISSION_START_SYSTEM_DIALOG);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to verify dialog permission, result = %{public}d", result);
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, result, "Failed to verify dialog permission");
        return result;
    }
    result = AccountPermissionManager::VerifyPermission(PERMISSION_ACCESS_USER_AUTH_INTERNAL);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to verify auth permission, result = %{public}d", result);
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, result, "Failed to verify auth permission");
        return result;
    }
    std::string bundleName;
    result = BundleManagerAdapter::GetInstance()->GetNameForUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to get bundle name");
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, result, "Failed to get bundle name");
        return result;
    }
    if (bundleName != config_.authAppBundleName) {
        ACCOUNT_LOGE("Failed to get bundle name");
        return ERR_OK;
    }
    return SessionAbilityConnection::GetInstance().RegisterAuthAppRemoteObject(IPCSkeleton::GetCallingPid(),
        authAppRemoteObj);
}

ErrCode AuthorizationManagerService::UnRegisterAuthAppRemoteObject()
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t localId = callingUid / UID_TRANSFORM_DIVISOR;
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, result, "The caller is not system application");
        ACCOUNT_LOGE("The caller is not system application, err = %{public}d.", result);
        return result;
    }
    result = AccountPermissionManager::VerifyPermission(PERMISSION_START_SYSTEM_DIALOG);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to verify dialog permission, result = %{public}d", result);
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, result, "Failed to verify dialog permission");
        return result;
    }
    return SessionAbilityConnection::GetInstance().UnRegisterAuthAppRemoteObject(IPCSkeleton::GetCallingPid());
}

ErrCode AuthorizationManagerService::AcquireAuthorization(const std::string &privilege,
    const AcquireAuthorizationOptions &options, const sptr<IRemoteObject> &authorizationResultCallback,
    const sptr<IRemoteObject> &requestRemoteObj)
{
    int32_t localId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, result, "The caller is not system application");
        ACCOUNT_LOGE("The caller is not system application, err = %{public}d.", result);
        return result;
    }
    result = AccountPermissionManager::VerifyPermission(PERMISSION_ACQUIRE_AUTHORIZATION);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, result, "Failed to verify permission");
        ACCOUNT_LOGE("Failed to verify permission, result = %{public}d", result);
        return result;
    }
    if (options.challenge.size() > MAX_CHALLENGE_LEN || (options.hasContext && !options.isContextValid)) {
        ACCOUNT_LOGE("Challenge size larger than 32 or context valid = %{public}d.", options.isContextValid);
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
            "Challenge size larger than 32 or context is invalid");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    AuthorizationResult authorizationResult;
    authorizationResult.privilege = privilege;
    auto callback = iface_cast<IAuthorizationCallback>(authorizationResultCallback);
    if (callback == nullptr) {
        ACCOUNT_LOGE("Get AuthorizationResultCallback proxy is nullptr");
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, ERR_AUTHORIZATION_GET_PROXY_ERROR,
            "Get proxy is nullptr");
        return ERR_AUTHORIZATION_GET_PROXY_ERROR;
    }
    if (SessionAbilityConnection::GetInstance().HasServiceConnect()) {
        ACCOUNT_LOGI("Failed to hasServiceConnect");
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, static_cast<int32_t>(AUTHORIZATION_SERVICE_BUSY),
            "Failed to hasServiceConnect");
        authorizationResult.resultCode = AuthorizationResultCode::AUTHORIZATION_SERVICE_BUSY;
        callback->OnResult(ERR_OK, authorizationResult);
        return ERR_OK;
    }
    if (options.hasContext && InnerAuthorizationManager::GetInstance().HasExtensionConnect()) {
        ACCOUNT_LOGI("Failed to hasExtensionConnect");
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, static_cast<int32_t>(AUTHORIZATION_SERVICE_BUSY),
            "Failed to hasExtensionConnect");
        authorizationResult.resultCode = AuthorizationResultCode::AUTHORIZATION_SERVICE_BUSY;
        callback->OnResult(ERR_OK, authorizationResult);
        return ERR_OK;
    }
    PrivilegeBriefDef def;
    bool ret = GetPrivilegeBriefDef(privilege, def);
    if (!ret) {
        ACCOUNT_LOGE("Fail to check privilege, privilege:%{public}s", privilege.c_str());
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
            "Fail to check privilege");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (!options.isReuseNeeded && !options.isInteractionAllowed) {
        REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH,
            static_cast<int32_t>(AUTHORIZATION_INTERACTION_NOT_ALLOWED),
            "Check isReuseNeeded = false and isInteractionAllowed = false");
        authorizationResult.resultCode = AuthorizationResultCode::AUTHORIZATION_INTERACTION_NOT_ALLOWED;
        callback->OnResult(ERR_OK, authorizationResult);
        return ERR_OK;
    }
    if (options.isReuseNeeded) {
        uint32_t code;
        ret = TransferPrivilegeToCode(privilege, code);
        if (!ret) {
            REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH, ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
                "Fail to check privilege");
            ACCOUNT_LOGE("Fail to check privilege, privilege:%{public}s", privilege.c_str());
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }
        AuthenCallerInfo info;
        info.privilegeIdx = code;
        int32_t validityPeriod = -1;
        result = PrivilegeCacheManager::GetInstance().CheckPrivilege(info, validityPeriod);
        if (result == ERR_OK) {
            authorizationResult.validityPeriod = validityPeriod;
            authorizationResult.isReused = options.isReuseNeeded;
            callback->OnResult(ERR_OK, authorizationResult);
            return ERR_OK;
        }
        if (!options.isInteractionAllowed) {
            authorizationResult.resultCode = AuthorizationResultCode::AUTHORIZATION_INTERACTION_NOT_ALLOWED;
            REPORT_OS_ACCOUNT_FAIL(localId, PRIVILEGE_OPT_ACQUIRE_AUTH,
                static_cast<int32_t>(AUTHORIZATION_INTERACTION_NOT_ALLOWED), "Fail to check privilege");
            ACCOUNT_LOGE("Fail to check privilege=%{public}s approved, errCode:%{public}d", privilege.c_str(), result);
            callback->OnResult(ERR_OK, authorizationResult);
            return ERR_OK;
        }
    }

    return InnerAuthorizationManager::GetInstance().AcquireAuthorization(def, options,
        config_, authorizationResultCallback, requestRemoteObj);
}

ErrCode AuthorizationManagerService::ReleaseAuthorization(const std::string &privilege)
{
    ErrCode res = AccountPermissionManager::CheckSystemApp();
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Caller is not system application, result = %{public}d.", res);
        return res;
    }
    uint32_t privilegeId = 0;
    if (!TransferPrivilegeToCode(privilege, privilegeId)) {
        ACCOUNT_LOGE("TransferPrivilegeToCode failed, privilege = %{public}s.", privilege.c_str());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    AuthenCallerInfo authenCallerInfo;
    authenCallerInfo.pid = IPCSkeleton::GetCallingPid();
    authenCallerInfo.uid = IPCSkeleton::GetCallingUid();
    authenCallerInfo.privilegeIdx = privilegeId;
    res = PrivilegeCacheManager::GetInstance().RemoveSingle(authenCallerInfo);
    if (res != ERR_OK) {
        ACCOUNT_LOGE("RemoveSingle failed, result = %{public}d.", res);
        return ERR_ACCOUNT_COMMON_OPERATION_FAIL;
    }
    return ERR_OK;
}

static ErrCode CheckAuth(const std::string &privilege, int32_t pid,
    bool &isAuthorized)
{
    ErrCode errCode = AccountPermissionManager::CheckSystemApp();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Caller is not system application, errCode: %{public}d", errCode);
        return errCode;
    }

    uint32_t privilegeId = 0;
    if (!TransferPrivilegeToCode(privilege, privilegeId)) {
        ACCOUNT_LOGE("Failed to get privilegeId from privilege");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    errCode = InnerAuthorizationManager::GetInstance().CheckAuthorization(
        privilegeId, pid, isAuthorized);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to CheckAuthorization with pid, errCode: %{public}d", errCode);
        return errCode;
    }
    ACCOUNT_LOGI("CheckAuthorization successed, privilege: %{public}s, pid: %{public}d",
        privilege.c_str(), pid);
    return ERR_OK;
}

ErrCode AuthorizationManagerService::CheckAuthorization(const std::string &privilege, bool &isAuthorized)
{
    isAuthorized = false;
    int32_t pid = IPCSkeleton::GetCallingPid();
    return CheckAuth(privilege, pid, isAuthorized);
}

ErrCode AuthorizationManagerService::CheckAuthorization(
    const std::string &privilege, int32_t pid, bool &isAuthorized)
{
    isAuthorized = false;
    return CheckAuth(privilege, pid, isAuthorized);
}

ErrCode AuthorizationManagerService::ValidateAdminAuthParams(const std::string &adminName,
    const sptr<IRemoteObject> &callback, sptr<IAdminAuthorizationCallback> &callbackProxy)
{
    if (adminName.empty()) {
        ACCOUNT_LOGE("AdminName is empty");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    callbackProxy = iface_cast<IAdminAuthorizationCallback>(callback);
    if (callbackProxy == nullptr) {
        ACCOUNT_LOGE("Failed to get IAdminAuthorizationCallback proxy");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    return ERR_OK;
}

ErrCode AuthorizationManagerService::VerifyAdminAuthPermission()
{
    ErrCode result = AccountPermissionManager::VerifyPermission(PERMISSION_ACCESS_USER_AUTH_INTERNAL);
    if (result != ERR_OK) {
        result = AccountPermissionManager::VerifyPermission(PERMISSION_ACQUIRE_AUTHORIZATION);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("Failed to verify permission, result: %{public}d", result);
            return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
        }
    }
    return ERR_OK;
}

ErrCode AuthorizationManagerService::FindAccountIdByName(const std::string &adminName, int32_t &accountId)
{
    std::vector<OsAccountInfo> osAccountList;
    ErrCode errCode = IInnerOsAccountManager::GetInstance().QueryAllCreatedOsAccounts(osAccountList);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to get os account list, errCode: %{public}d", errCode);
        return errCode;
    }

    accountId = -1;
    for (const auto &accountInfo : osAccountList) {
        if (accountInfo.GetLocalName() == adminName) {
            accountId = accountInfo.GetLocalId();
            break;
        }
    }

    return ERR_OK;
}

ErrCode AuthorizationManagerService::CheckAuthorizationToken(const std::vector<uint8_t> &token,
    const std::string &privilege, int32_t pid, CheckAuthorizationResult &result)
{
    result.isAuthorized = false;
    result.challenge = {};
    bool isAuthorized = false;
    ErrCode errCode = CheckAuth(privilege, pid, isAuthorized);
    if (errCode != ERR_OK) {
        return errCode;
    }
    if (!isAuthorized) {
        ACCOUNT_LOGE("Failed to check privilege");
        return ERR_OK;
    }
    if (token.empty()) {
        ACCOUNT_LOGE("Failed to get parameter, token is empty");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (pid < 0) {
        ACCOUNT_LOGE("Failed to get parameter, pid < 0");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    const uint32_t newPid = (uint32_t)pid;
    errCode = InnerAuthorizationManager::GetInstance().VerifyToken(
        token, privilege, newPid, result.challenge, result.iamToken);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to verify token, errCode: %{public}d", errCode);
        return errCode;
    }
    result.isAuthorized = isAuthorized;
    ACCOUNT_LOGI("Check authorization successed, privilege: %{public}s, pid: %{public}d",
        privilege.c_str(), pid);
    return ERR_OK;
}

ErrCode AuthorizationManagerService::AcquireAdminAuthorization(const std::string &adminName,
    const std::vector<uint8_t> &challenge, const sptr<IRemoteObject> &callback)
{
#ifdef SUPPORT_AUTHORIZATION
    sptr<IAdminAuthorizationCallback> callbackProxy;
    ErrCode errCode = ValidateAdminAuthParams(adminName, callback, callbackProxy);
    if (errCode != ERR_OK) {
        return errCode;
    }

    errCode = VerifyAdminAuthPermission();
    if (errCode != ERR_OK) {
        return errCode;
    }

    int32_t targetAccountId = -1;
    errCode = FindAccountIdByName(adminName, targetAccountId);
    if (errCode != ERR_OK) {
        return errCode;
    }

    if (targetAccountId == -1) {
        ACCOUNT_LOGE("Admin account not found, adminName: %{public}s", adminName.c_str());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    auto [verifyErrCode, resultCode] = InnerAuthorizationManager::GetInstance().VerifyAdminAccount(targetAccountId);
    if (verifyErrCode != ERR_OK || resultCode != AuthorizationResultCode::AUTHORIZATION_SUCCESS) {
        return ERR_AUTHORIZATION_INVALID_ADMIN_ACCOUNT_OR_PASSWORD;
    }

    errCode = InnerAuthorizationManager::GetInstance().AcquireAdminAuthorization(
        targetAccountId, challenge, callbackProxy);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to acquire admin authorization, errCode: %{public}d", errCode);
        return errCode;
    }

    return ERR_OK;
#else
    return ERR_ACCOUNT_COMMON_NOT_SUPPORT;
#endif // SUPPORT_AUTHORIZATION
}
}
}
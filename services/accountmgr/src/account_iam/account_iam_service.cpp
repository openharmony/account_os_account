/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "account_iam_service.h"

#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "iget_cred_info_callback.h"
#include "iinner_os_account_manager.h"
#include "inner_account_iam_manager.h"
#include "ipc_skeleton.h"
#include "token_setproc.h"

namespace OHOS {
namespace AccountSA {
namespace {
const char PERMISSION_ACCESS_USER_AUTH_INTERNAL[] = "ohos.permission.ACCESS_USER_AUTH_INTERNAL";
const char PERMISSION_MANAGE_USER_IDM[] = "ohos.permission.MANAGE_USER_IDM";
const char PERMISSION_USE_USER_IDM[] = "ohos.permission.USE_USER_IDM";
} // namespace

AccountIAMService::AccountIAMService()
{}

AccountIAMService::~AccountIAMService()
{}

static bool GetCurrentUserId(int32_t &userId)
{
    int32_t callingLocalId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (callingLocalId == 0) {
        int32_t foregroundLocalId = -1;
        ErrCode ret = IInnerOsAccountManager::GetInstance().GetForegroundOsAccountLocalId(
            Constants::DEFAULT_DISPLAY_ID, foregroundLocalId);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("Fail to get foreground os account local id on default display, errCode = %{public}d", ret);
            return false;
        }
        userId = foregroundLocalId;
        return true;
    }
    userId = callingLocalId;
    return true;
}

static bool IsRestrictedAccountId(int32_t accountId)
{
    return (accountId == 0);
}

static int32_t NormalizeAccountId(int32_t &accountId)
{
    if (accountId < -1) {
        ACCOUNT_LOGE("The id = %{public}d is invalid", accountId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    } else if (accountId == -1) {
        if (!GetCurrentUserId(accountId)) {
            return ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR;
        }
    } else {
        bool isOsAccountExits = false;
        IInnerOsAccountManager::GetInstance().IsOsAccountExists(accountId, isOsAccountExits);
        if (!isOsAccountExits) {
            ACCOUNT_LOGE("Account does not exist");
            return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
        }
    }
    return ERR_OK;
}

int32_t AccountIAMService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result = SetFirstCallerTokenID(tokenCaller);
    ACCOUNT_LOGD("SetFirstCallerTokenID code: %{public}d, result: %{public}d", code, result);

    if (static_cast<IAccountIAMIpcCode>(code) == IAccountIAMIpcCode::COMMAND_GET_ACCOUNT_STATE) {
        return ERR_OK;
    }
    result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, code = %{public}d result = %{public}d.", code, result);
    }
    return result;
}

int32_t AccountIAMService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    if (!CheckPermission(PERMISSION_MANAGE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        return ret;
    }
    if (IsRestrictedAccountId(userId)) {
        ACCOUNT_LOGE("The id = %{public}d is restricted", userId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_IS_RESTRICTED;
    }
    InnerAccountIAMManager::GetInstance().OpenSession(userId, challenge);
    return ERR_OK;
}

int32_t AccountIAMService::CloseSession(int32_t userId)
{
    if (!CheckPermission(PERMISSION_MANAGE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        return ret;
    }
    if (IsRestrictedAccountId(userId)) {
        ACCOUNT_LOGE("The id = %{public}d is restricted", userId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_IS_RESTRICTED;
    }
    InnerAccountIAMManager::GetInstance().CloseSession(userId);
    return ERR_OK;
}

int32_t AccountIAMService::AddCredential(
    int32_t userId, const CredentialParametersIam& credInfoIam, const sptr<IIDMCallback> &idmCallback)
{
    if (!CheckPermission(PERMISSION_MANAGE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    Attributes emptyResult;
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        return ret;
    }
    if (IsRestrictedAccountId(userId)) {
        ACCOUNT_LOGE("The id = %{public}d is restricted", userId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_IS_RESTRICTED;
    }
    InnerAccountIAMManager::GetInstance().AddCredential(userId, credInfoIam.credentialParameters, idmCallback);
    auto info = const_cast<CredentialParametersIam*>(&credInfoIam);
    std::fill(info->credentialParameters.token.begin(), info->credentialParameters.token.end(), 0);
    return ERR_OK;
}

int32_t AccountIAMService::UpdateCredential(int32_t userId, const CredentialParametersIam& credInfoIam,
    const sptr<IIDMCallback> &idmCallback)
{
    if (!CheckPermission(PERMISSION_MANAGE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        return ret;
    }
    InnerAccountIAMManager::GetInstance().UpdateCredential(userId, credInfoIam.credentialParameters, idmCallback);
    auto info = const_cast<CredentialParametersIam *>(&credInfoIam);
    std::fill(info->credentialParameters.token.begin(), info->credentialParameters.token.end(), 0);
    return ERR_OK;
}

int32_t AccountIAMService::Cancel(int32_t userId)
{
    if (!CheckPermission(PERMISSION_MANAGE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        return ret;
    }
    return InnerAccountIAMManager::GetInstance().Cancel(userId);
}

int32_t AccountIAMService::DelCred(
    int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &idmCallback)
{
    if (!CheckPermission(PERMISSION_MANAGE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        return ret;
    }
    InnerAccountIAMManager::GetInstance().DelCred(userId, credentialId, authToken, idmCallback);
    auto token = const_cast<std::vector<uint8_t> *>(&authToken);
    std::fill(token->begin(), token->end(), 0);
    return ERR_OK;
}

int32_t AccountIAMService::DelUser(
    int32_t userId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &idmCallback)
{
    if (!CheckPermission(PERMISSION_MANAGE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        return ret;
    }
    InnerAccountIAMManager::GetInstance().DelUser(userId, authToken, idmCallback);
    auto token = const_cast<std::vector<uint8_t> *>(&authToken);
    std::fill(token->begin(), token->end(), 0);
    return ERR_OK;
}

int32_t AccountIAMService::GetCredentialInfo(
    int32_t userId, int32_t authTypeInt, const sptr<IGetCredInfoCallback> &getCredInfoCallback)
{
    if (!CheckPermission(PERMISSION_USE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    AuthType authType = static_cast<AuthType>(authTypeInt);
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        return ret;
    }
    if ((authType < UserIam::UserAuth::ALL) ||
        (static_cast<int32_t>(authType) >= static_cast<int32_t>(IAMAuthType::TYPE_END))) {
        ACCOUNT_LOGE("authType is not in correct range");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    InnerAccountIAMManager::GetInstance().GetCredentialInfo(userId, authType, getCredInfoCallback);
    return ERR_OK;
}

int32_t AccountIAMService::PrepareRemoteAuth(
    const std::string &remoteNetworkId, const sptr<IPreRemoteAuthCallback> &preRemoteAuthCallback)
{
    if (!CheckPermission(PERMISSION_ACCESS_USER_AUTH_INTERNAL)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return InnerAccountIAMManager::GetInstance().PrepareRemoteAuth(remoteNetworkId, preRemoteAuthCallback);
}

int32_t AccountIAMService::AuthUser(
    const AuthParam& authParam, const sptr<IIDMCallback> &idmCallback, uint64_t &contextId)
{
    if (!CheckPermission(PERMISSION_ACCESS_USER_AUTH_INTERNAL)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    auto authParamTemp = authParam;
    if ((authParamTemp.remoteAuthParam == std::nullopt) && (authParamTemp.userId == -1) &&
        (!GetCurrentUserId(authParamTemp.userId))) {
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR;
    }
    return InnerAccountIAMManager::GetInstance().AuthUser(authParamTemp, idmCallback, contextId);
}

int32_t AccountIAMService::CancelAuth(uint64_t contextId)
{
    if (!CheckPermission(PERMISSION_ACCESS_USER_AUTH_INTERNAL)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return InnerAccountIAMManager::GetInstance().CancelAuth(contextId);
}

int32_t AccountIAMService::GetAvailableStatus(int32_t authTypeInt, uint32_t authTrustLevelInt, int32_t &status)
{
    if (!CheckPermission(PERMISSION_ACCESS_USER_AUTH_INTERNAL)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    AuthType authType = static_cast<AuthType>(authTypeInt);
    AuthTrustLevel authTrustLevel = static_cast<AuthTrustLevel>(authTrustLevelInt);
    if (authTrustLevel < UserIam::UserAuth::ATL1 || authTrustLevel > UserIam::UserAuth::ATL4) {
        ACCOUNT_LOGE("authTrustLevel is not in correct range");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (authType < UserIam::UserAuth::ALL) {
        ACCOUNT_LOGE("authType is not in correct range");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return InnerAccountIAMManager::GetInstance().GetAvailableStatus(authType, authTrustLevel, status);
}

int32_t AccountIAMService::GetProperty(
    int32_t userId, const GetPropertyRequestIam &request, const sptr<IGetSetPropCallback> &getSetPropCallback)
{
    if (!CheckPermission(PERMISSION_ACCESS_USER_AUTH_INTERNAL)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        return ret;
    }
    InnerAccountIAMManager::GetInstance().GetProperty(userId, request.getPropertyRequest, getSetPropCallback);
    return ERR_OK;
}

int32_t AccountIAMService::GetPropertyByCredentialId(uint64_t credentialId,
    const std::vector<int32_t>& keysInt, const sptr<IGetSetPropCallback> &getSetPropCallback)
{
    if (!CheckPermission(PERMISSION_ACCESS_USER_AUTH_INTERNAL)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    std::vector<Attributes::AttributeKey> keys;
    for (auto &key : keysInt) {
        keys.push_back(static_cast<Attributes::AttributeKey>(key));
    }
    InnerAccountIAMManager::GetInstance().GetPropertyByCredentialId(credentialId, keys, getSetPropCallback);
    return ERR_OK;
}

int32_t AccountIAMService::SetProperty(
    int32_t userId, const SetPropertyRequestIam &request, const sptr<IGetSetPropCallback> &getSetPropCallback)
{
    if (!CheckPermission(PERMISSION_ACCESS_USER_AUTH_INTERNAL)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        return ret;
    }
    InnerAccountIAMManager::GetInstance().SetProperty(userId, request.setPropertyRequest, getSetPropCallback);
    return ERR_OK;
}

int32_t AccountIAMService::GetAccountState(int32_t userId, int32_t& funcResult)
{
    auto ret = InnerAccountIAMManager::GetInstance().GetState(userId);
    funcResult = static_cast<int32_t>(ret);
    return ERR_OK;
}

int32_t AccountIAMService::GetEnrolledId(
    int32_t accountId, int32_t authTypeInt, const sptr<IGetEnrolledIdCallback> &getEnrolledIdCallback)
{
    if (!CheckPermission(PERMISSION_USE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    AuthType authType = static_cast<AuthType>(authTypeInt);
    int32_t ret = NormalizeAccountId(accountId);
    if (ret != ERR_OK) {
        return ret;
    }
    if ((authType < UserIam::UserAuth::ALL) ||
        (static_cast<int32_t>(authType) >= static_cast<int32_t>(IAMAuthType::TYPE_END))) {
        ACCOUNT_LOGE("AuthType is not in correct range");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    InnerAccountIAMManager::GetInstance().GetEnrolledId(accountId, authType, getEnrolledIdCallback);
    return ERR_OK;
}

bool AccountIAMService::CheckPermission(const std::string &permission)
{
    if (AccountPermissionManager::VerifyPermission(permission) != ERR_OK) {
        ACCOUNT_LOGE("check permission failed, permission name: %{public}s", permission.c_str());
        return false;
    }
    return true;
}
}  // namespace AccountSA
}  // namespace OHOS

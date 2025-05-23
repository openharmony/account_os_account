/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "iaccount_iam_callback.h"
#include "iinner_os_account_manager.h"
#include "inner_account_iam_manager.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
AccountIAMService::AccountIAMService()
{}

AccountIAMService::~AccountIAMService()
{}

static bool GetCurrentUserId(int32_t &userId)
{
    std::vector<int32_t> userIds;
    (void)IInnerOsAccountManager::GetInstance().QueryActiveOsAccountIds(userIds);
    if (userIds.empty()) {
        ACCOUNT_LOGE("Fail to get activated os account ids");
        return false;
    }
    userId = userIds[0];
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

int32_t AccountIAMService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
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

void AccountIAMService::AddCredential(
    int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback)
{
    Attributes emptyResult;
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        callback->OnResult(ret, emptyResult);
        return;
    }
    if (IsRestrictedAccountId(userId)) {
        ACCOUNT_LOGE("The id = %{public}d is restricted", userId);
        callback->OnResult(ERR_ACCOUNT_COMMON_ACCOUNT_IS_RESTRICTED, emptyResult);
        return;
    }
    InnerAccountIAMManager::GetInstance().AddCredential(userId, credInfo, callback);
}

void AccountIAMService::UpdateCredential(int32_t userId, const CredentialParameters &credInfo,
    const sptr<IIDMCallback> &callback)
{
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        Attributes emptyResult;
        callback->OnResult(ret, emptyResult);
        return;
    }
    InnerAccountIAMManager::GetInstance().UpdateCredential(userId, credInfo, callback);
}

int32_t AccountIAMService::Cancel(int32_t userId)
{
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        return ret;
    }
    return InnerAccountIAMManager::GetInstance().Cancel(userId);
}

void AccountIAMService::DelCred(
    int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &callback)
{
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        Attributes emptyResult;
        callback->OnResult(ret, emptyResult);
        return;
    }
    InnerAccountIAMManager::GetInstance().DelCred(userId, credentialId, authToken, callback);
}

void AccountIAMService::DelUser(
    int32_t userId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &callback)
{
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        Attributes emptyResult;
        callback->OnResult(ret, emptyResult);
        return;
    }
    InnerAccountIAMManager::GetInstance().DelUser(userId, authToken, callback);
}

int32_t AccountIAMService::GetCredentialInfo(
    int32_t userId, AuthType authType, const sptr<IGetCredInfoCallback> &callback)
{
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        return ret;
    }
    if ((authType < UserIam::UserAuth::ALL) ||
        (static_cast<int32_t>(authType) >= static_cast<int32_t>(IAMAuthType::TYPE_END))) {
        ACCOUNT_LOGE("authType is not in correct range");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    InnerAccountIAMManager::GetInstance().GetCredentialInfo(userId, authType, callback);
    return ERR_OK;
}

int32_t AccountIAMService::PrepareRemoteAuth(
    const std::string &remoteNetworkId, const sptr<IPreRemoteAuthCallback> &callback)
{
    return InnerAccountIAMManager::GetInstance().PrepareRemoteAuth(remoteNetworkId, callback);
}

int32_t AccountIAMService::AuthUser(
    AuthParam &authParam, const sptr<IIDMCallback> &callback, uint64_t &contextId)
{
    if ((authParam.remoteAuthParam == std::nullopt) && (authParam.userId == -1) &&
        (!GetCurrentUserId(authParam.userId))) {
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR;
    }
    return InnerAccountIAMManager::GetInstance().AuthUser(authParam, callback, contextId);
}

int32_t AccountIAMService::CancelAuth(uint64_t contextId)
{
    return InnerAccountIAMManager::GetInstance().CancelAuth(contextId);
}

int32_t AccountIAMService::GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel, int32_t &status)
{
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

void AccountIAMService::GetProperty(
    int32_t userId, const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
{
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        Attributes emptyResult;
        callback->OnResult(ret, emptyResult);
        return;
    }
    InnerAccountIAMManager::GetInstance().GetProperty(userId, request, callback);
}

void AccountIAMService::GetPropertyByCredentialId(uint64_t credentialId,
    std::vector<Attributes::AttributeKey> &keys, const sptr<IGetSetPropCallback> &callback)
{
    InnerAccountIAMManager::GetInstance().GetPropertyByCredentialId(credentialId, keys, callback);
}

void AccountIAMService::SetProperty(
    int32_t userId, const SetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
{
    int32_t ret = NormalizeAccountId(userId);
    if (ret != ERR_OK) {
        Attributes emptyResult;
        callback->OnResult(ret, emptyResult);
        return;
    }
    InnerAccountIAMManager::GetInstance().SetProperty(userId, request, callback);
}

IAMState AccountIAMService::GetAccountState(int32_t userId)
{
    return InnerAccountIAMManager::GetInstance().GetState(userId);
}

void AccountIAMService::GetEnrolledId(
    int32_t accountId, AuthType authType, const sptr<IGetEnrolledIdCallback> &callback)
{
    uint64_t emptyId = 0;
    int32_t ret = NormalizeAccountId(accountId);
    if (ret != ERR_OK) {
        callback->OnEnrolledId(ret, emptyId);
        return;
    }
    if ((authType < UserIam::UserAuth::ALL) ||
        (static_cast<int32_t>(authType) >= static_cast<int32_t>(IAMAuthType::TYPE_END))) {
        ACCOUNT_LOGE("AuthType is not in correct range");
        callback->OnEnrolledId(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, emptyId);
        return;
    }
    InnerAccountIAMManager::GetInstance().GetEnrolledId(accountId, authType, callback);
}
}  // namespace AccountSA
}  // namespace OHOS

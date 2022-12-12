/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

int32_t AccountIAMService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        return ERR_ACCOUNT_IAM_SERVICE_PARAM_INVALID_ERROR;
    }
    InnerAccountIAMManager::GetInstance().OpenSession(userId, challenge);
    return ERR_OK;
}

int32_t AccountIAMService::CloseSession(int32_t userId)
{
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        return ERR_ACCOUNT_IAM_SERVICE_PARAM_INVALID_ERROR;
    }
    InnerAccountIAMManager::GetInstance().CloseSession(userId);
    return ERR_OK;
}

void AccountIAMService::AddCredential(
    int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback)
{
    Attributes emptyResult;
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        callback->OnResult(ERR_ACCOUNT_IAM_SERVICE_PARAM_INVALID_ERROR, emptyResult);
        return;
    }
    InnerAccountIAMManager::GetInstance().AddCredential(userId, credInfo, callback);
}

void AccountIAMService::UpdateCredential(int32_t userId, const CredentialParameters &credInfo,
    const sptr<IIDMCallback> &callback)
{
    Attributes emptyResult;
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        callback->OnResult(ERR_ACCOUNT_IAM_SERVICE_PARAM_INVALID_ERROR, emptyResult);
        return;
    }
    InnerAccountIAMManager::GetInstance().UpdateCredential(userId, credInfo, callback);
}

int32_t AccountIAMService::Cancel(int32_t userId)
{
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        return ERR_ACCOUNT_IAM_SERVICE_PARAM_INVALID_ERROR;
    }
    return InnerAccountIAMManager::GetInstance().Cancel(userId);
}

void AccountIAMService::DelCred(
    int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &callback)
{
    Attributes emptyResult;
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        callback->OnResult(ERR_ACCOUNT_IAM_SERVICE_PARAM_INVALID_ERROR, emptyResult);
        return;
    }
    InnerAccountIAMManager::GetInstance().DelCred(userId, credentialId, authToken, callback);
}

void AccountIAMService::DelUser(
    int32_t userId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &callback)
{
    Attributes emptyResult;
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        callback->OnResult(ERR_ACCOUNT_IAM_SERVICE_PARAM_INVALID_ERROR, emptyResult);
        return;
    }
    InnerAccountIAMManager::GetInstance().DelUser(userId, authToken, callback);
}

int32_t AccountIAMService::GetCredentialInfo(
    int32_t userId, AuthType authType, const sptr<IGetCredInfoCallback> &callback)
{
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        return ERR_ACCOUNT_IAM_SERVICE_PARAM_INVALID_ERROR;
    }
    InnerAccountIAMManager::GetInstance().GetCredentialInfo(userId, authType, callback);
    return ERR_OK;
}

uint64_t AccountIAMService::AuthUser(int32_t userId, const std::vector<uint8_t> &challenge, AuthType authType,
    AuthTrustLevel authTrustLevel, const sptr<IIDMCallback> &callback)
{
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        return ERR_ACCOUNT_IAM_SERVICE_PARAM_INVALID_ERROR;
    }
    return InnerAccountIAMManager::GetInstance().AuthUser(
        userId, challenge, authType, authTrustLevel, callback);
}

int32_t AccountIAMService::CancelAuth(uint64_t contextId)
{
    return InnerAccountIAMManager::GetInstance().CancelAuth(contextId);
}

int32_t AccountIAMService::GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel, int32_t &status)
{
    if (authTrustLevel < UserIam::UserAuth::ATL1 || authTrustLevel > UserIam::UserAuth::ATL4) {
        ACCOUNT_LOGE("authTrustLevel is not in correct range");
        return ERR_ACCOUNT_IAM_SERVICE_PARAM_INVALID_ERROR;
    }
    if (authType < UserIam::UserAuth::ALL) {
        ACCOUNT_LOGE("authType is not in correct range");
        return ERR_ACCOUNT_IAM_SERVICE_PARAM_INVALID_ERROR;
    }
    return InnerAccountIAMManager::GetInstance().GetAvailableStatus(authType, authTrustLevel, status);
}

void AccountIAMService::GetProperty(
    int32_t userId, const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
{
    Attributes emptyResult;
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        callback->OnResult(ERR_ACCOUNT_IAM_SERVICE_PARAM_INVALID_ERROR, emptyResult);
        return;
    }
    return InnerAccountIAMManager::GetInstance().GetProperty(userId, request, callback);
}

void AccountIAMService::SetProperty(
    int32_t userId, const SetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
{
    Attributes emptyResult;
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        callback->OnResult(ERR_ACCOUNT_IAM_SERVICE_PARAM_INVALID_ERROR, emptyResult);
        return;
    }
    InnerAccountIAMManager::GetInstance().SetProperty(userId, request, callback);
}

IAMState AccountIAMService::GetAccountState(int32_t userId)
{
    return InnerAccountIAMManager::GetInstance().GetState(userId);
}

bool AccountIAMService::GetCurrentUserId(int32_t &userId)
{
    std::vector<int32_t> userIds;
    (void)IInnerOsAccountManager::GetInstance()->QueryActiveOsAccountIds(userIds);
    if (userIds.empty()) {
        ACCOUNT_LOGE("fail to get activated os account ids");
        return false;
    }
    userId = userIds[0];
    return true;
}
}  // namespace AccountSA
}  // namespace OHOS

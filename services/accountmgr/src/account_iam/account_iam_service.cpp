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
#include "inner_account_iam_manager.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"

namespace OHOS {
namespace AccountSA {
AccountIAMService::AccountIAMService()
{}

AccountIAMService::~AccountIAMService()
{}

void AccountIAMService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    if (userId == 0) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        if (OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId) != ERR_OK) {
            return;
        }
    }
    InnerAccountIAMManager::GetInstance().OpenSession(userId, challenge);
}

void AccountIAMService::CloseSession(int32_t userId)
{
    if (userId == 0) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        if (OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId) != ERR_OK) {
            return;
        }
    }
    InnerAccountIAMManager::GetInstance().CloseSession(userId);
}

void AccountIAMService::AddCredential(
    int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback)
{
    if (userId == 0) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        if (OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId) != ERR_OK) {
            return;
        }
    }
    InnerAccountIAMManager::GetInstance().AddCredential(userId, credInfo, callback);
}

void AccountIAMService::UpdateCredential(int32_t userId, const CredentialParameters &credInfo,
    const sptr<IIDMCallback> &callback)
{
    if (userId == 0) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        if (OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId) != ERR_OK) {
            return;
        }
    }
    InnerAccountIAMManager::GetInstance().UpdateCredential(userId, credInfo, callback);
}

int32_t AccountIAMService::Cancel(int32_t userId, uint64_t challenge)
{
    if (userId == 0) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        if (OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId) != ERR_OK) {
            return ResultCode::FAIL;
        }
    }
    return InnerAccountIAMManager::GetInstance().Cancel(userId, challenge);
}

void AccountIAMService::DelCred(
    int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &callback)
{
    if (userId == 0) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        if (OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId) != ERR_OK) {
            return;
        }
    }
    InnerAccountIAMManager::GetInstance().DelCred(userId, credentialId, authToken, callback);
}

void AccountIAMService::DelUser(
    int32_t userId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &callback)
{
    if (userId == 0) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        if (OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId) != ERR_OK) {
            return;
        }
    }
    InnerAccountIAMManager::GetInstance().DelUser(userId, authToken, callback);
}

void AccountIAMService::GetCredentialInfo(
    int32_t userId, AuthType authType, const sptr<IGetCredInfoCallback> &callback)
{
    if (userId == 0) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        if (OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId) != ERR_OK) {
            return;
        }
    }
    InnerAccountIAMManager::GetInstance().GetCredentialInfo(userId, authType, callback);
}

uint64_t AccountIAMService::AuthUser(int32_t userId, const std::vector<uint8_t> &challenge, AuthType authType,
    AuthTrustLevel authTrustLevel, const sptr<IIDMCallback> &callback)
{
    if (userId == 0) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        if (OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId) != ERR_OK) {
            return ResultCode::FAIL;
        }
    }
    return InnerAccountIAMManager::GetInstance().AuthUser(
        userId, challenge, authType, authTrustLevel, callback);
}

int32_t AccountIAMService::CancelAuth(uint64_t contextId)
{
    return InnerAccountIAMManager::GetInstance().CancelAuth(contextId);
}

int32_t AccountIAMService::GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel)
{
    return InnerAccountIAMManager::GetInstance().GetAvailableStatus(authType, authTrustLevel);
}

void AccountIAMService::GetProperty(
    int32_t userId, const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
{
    if (userId == 0) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        if (OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId) != ERR_OK) {
            return;
        }
    }
    return InnerAccountIAMManager::GetInstance().GetProperty(userId, request, callback);
}

void AccountIAMService::SetProperty(
    int32_t userId, const SetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
{
    if (userId == 0) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        if (OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId) != ERR_OK) {
            return;
        }
    }
    InnerAccountIAMManager::GetInstance().SetProperty(userId, request, callback);
}

bool AccountIAMService::RegisterInputer(const sptr<IGetDataCallback> &inputer)
{
    int32_t userId = 0;
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId) != ERR_OK) {
        return false;
    }
    return InnerAccountIAMManager::GetInstance().RegisterInputer(userId, inputer);
}

void AccountIAMService::UnRegisterInputer()
{
    return InnerAccountIAMManager::GetInstance().UnRegisterInputer();
}
}  // namespace AccountSA
}  // namespace OHOS

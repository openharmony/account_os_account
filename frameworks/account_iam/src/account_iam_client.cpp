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

#include "account_iam_client.h"

#include "account_iam_callback.h"
#include "account_log_wrapper.h"
#include "account_proxy.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "pinauth_register.h"
#include "system_ability_definition.h"
#include "user_auth_client.h"
#include "user_auth_client_impl.h"
#include "user_idm_client.h"

namespace OHOS {
namespace AccountSA {
using UserIDMClient = UserIam::UserAuth::UserIdmClient;
using UserAuthClient = UserIam::UserAuth::UserAuthClient;
using PinAuthRegister = UserIam::PinAuth::PinAuthRegister;
using UserAuthClientImpl = UserIam::UserAuth::UserAuthClientImpl;

AccountIAMClient::AccountIAMClient()
{
    userStateMap_[0] = IDLE;
}

ErrCode AccountIAMClient::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    challenge = UserIDMClient::GetInstance().OpenSession(userId);
    std::lock_guard<std::mutex> lock(mutex_);
    userStateMap_[userId] = AFTER_OPEN_SESSION;
    userChallengeMap_[userId] = challenge;
    return ERR_OK;
}

ErrCode AccountIAMClient::CloseSession(int32_t userId)
{
    UserIDMClient::GetInstance().CloseSession(userId);
    std::lock_guard<std::mutex> lock(mutex_);
    if (userId == 0) {
        userStateMap_[0] = IDLE;
    } else {
        userStateMap_.erase(userId);
    }
    userChallengeMap_.erase(userId);
    return ERR_OK;
}

ErrCode AccountIAMClient::AddCredential(const CredentialParameters& credInfo,
    const std::shared_ptr<UserIdmClientCallback>& callback)
{
    ACCOUNT_LOGD("enter");
    if (callback == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    if (credInfo.authType != AuthType::PIN) {
        UserIDMClient::GetInstance().AddCredential(0, credInfo, callback);
        return ERR_OK;
    }
    int32_t userId = 0;
    OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    auto idmCallback = std::make_shared<AddCredCallback>(userId, credInfo, callback);
    UserIDMClient::GetInstance().AddCredential(0, credInfo, idmCallback);
    return ERR_OK;
}

ErrCode AccountIAMClient::UpdateCredential(const CredentialParameters& credInfo,
    const std::shared_ptr<UserIdmClientCallback>& callback)
{
    ACCOUNT_LOGD("enter");
    if (callback == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    if (credInfo.token.empty()) {
        ACCOUNT_LOGD("token is empty");
        Attributes emptyResult;
        callback->OnResult(ResultCode::INVALID_PARAMETERS, emptyResult);
        return ERR_OK;
    }
    if (credInfo.authType != AuthType::PIN) {
        UserIDMClient::GetInstance().UpdateCredential(0, credInfo, callback);
        return ERR_OK;
    }
    int32_t userId = 0;
    OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    auto idmCallback = std::make_shared<UpdateCredCallback>(userId, credInfo, callback);
    UserIDMClient::GetInstance().UpdateCredential(0, credInfo, idmCallback);
    return ERR_OK;
}

ErrCode AccountIAMClient::DelCred(uint64_t credentialId, std::vector<uint8_t> authToken,
    const std::shared_ptr<UserIdmClientCallback>& callback)
{
    ACCOUNT_LOGD("enter");
    if (callback == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    Attributes errResult;
    if (authToken.empty()) {
        ACCOUNT_LOGD("token is empty");
        callback->OnResult(ResultCode::INVALID_PARAMETERS, errResult);
        return ERR_OK;
    }
    int32_t userId = 0;
    OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    std::vector<uint8_t> secret;
    ErrCode result = UpdateUserKey(userId, credentialId, authToken, secret);
    if (result != ERR_OK) {
        callback->OnResult(result, errResult);
        return ERR_OK;
    }
    auto idmCallback = std::make_shared<DelCredCallback>(userId, credentialId, authToken, callback);
    UserIDMClient::GetInstance().DeleteCredential(0, credentialId, authToken, idmCallback);
    return ERR_OK;
}

ErrCode AccountIAMClient::DelUser(std::vector<uint8_t> authToken,
    const std::shared_ptr<UserIdmClientCallback>& callback)
{
    ACCOUNT_LOGD("enter");
    if (callback == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    Attributes errResult;
    if (authToken.empty()) {
        ACCOUNT_LOGD("token is empty");
        callback->OnResult(ResultCode::INVALID_PARAMETERS, errResult);
        return ERR_OK;
    }
    int32_t userId = 0;
    OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    ErrCode result = RemoveUserKey(userId, authToken);
    if (result != ERR_OK) {
        callback->OnResult(result, errResult);
        return ERR_OK;
    }
    auto idmCallback = std::make_shared<DelCredCallback>(userId, 0, authToken, callback);
    UserIDMClient::GetInstance().DeleteUser(userId, authToken, idmCallback);
    return ERR_OK;
}

ErrCode AccountIAMClient::GetAuthInfo(AuthType authType, const std::shared_ptr<GetCredentialInfoCallback>& callback)
{
    UserIDMClient::GetInstance().GetCredentialInfo(0, authType, callback);
    return ERR_OK;
}

ErrCode AccountIAMClient::Cancel(uint64_t challenge, int32_t &resultCode)
{
    resultCode = UserIDMClient::GetInstance().Cancel(challenge);
    return ERR_OK;
}

ErrCode AccountIAMClient::Auth(const std::vector<uint8_t> &challenge, const AuthType authType,
    const AuthTrustLevel authTrustLevel, const std::shared_ptr<AuthenticationCallback> &callback, uint64_t &contextId)
{
    ACCOUNT_LOGD("enter");
    int32_t userId = 0;
    OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    return AuthUser(userId, challenge, authType, authTrustLevel, callback, contextId);
}

ErrCode AccountIAMClient::AuthUser(
    const int32_t userId, const std::vector<uint8_t> &challenge, const AuthType authType,
    const AuthTrustLevel authTrustLevel, const std::shared_ptr<AuthenticationCallback> &callback, uint64_t &contextId)
{
    ACCOUNT_LOGD("enter");
    if (callback == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    if (authType != AuthType::PIN) {
        contextId = UserAuthClient::GetInstance().BeginAuthentication(
            userId, challenge, authType, authTrustLevel, callback);
        return ERR_OK;
    }
    auto userAuthCallback = std::make_shared<AuthCallback>(userId, callback);
    contextId = UserAuthClient::GetInstance().BeginAuthentication(
        userId, challenge, authType, authTrustLevel, userAuthCallback);
    return ERR_OK;
}

ErrCode AccountIAMClient::CancelAuth(const uint64_t contextId, int32_t &resultCode)
{
    resultCode = UserAuthClient::GetInstance().CancelAuthentication(contextId);
    return ERR_OK;
}

ErrCode AccountIAMClient::GetAvailableStatus(
    const AuthType authType, const AuthTrustLevel authTrustLevel, int32_t &status)
{
    status = UserAuthClientImpl::Instance().GetAvailableStatus(authType, authTrustLevel);
    return ERR_OK;
}

ErrCode AccountIAMClient::GetProperty(const GetPropertyRequest &request, std::shared_ptr<GetPropCallback> callback)
{
    UserAuthClient::GetInstance().GetProperty(0, request, callback);
    return ERR_OK;
}

ErrCode AccountIAMClient::SetProperty(const SetPropertyRequest &request, std::shared_ptr<SetPropCallback> callback)
{
    UserAuthClient::GetInstance().SetProperty(0, request, callback);
    return ERR_OK;
}

ErrCode AccountIAMClient::RegisterInputer(const std::shared_ptr<IInputer> inputer, bool &isSucceed)
{
    ACCOUNT_LOGD("enter");
    isSucceed = false;
    int32_t userId = 0;
    OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    auto iamInputer = std::make_shared<IAMInputer>(userId, inputer);
    isSucceed = PinAuthRegister::GetInstance().RegisterInputer(iamInputer);
    return ERR_OK;
}

ErrCode AccountIAMClient::UnRegisterInputer()
{
    ACCOUNT_LOGD("enter");
    PinAuthRegister::GetInstance().UnRegisterInputer();
    return ERR_OK;
}

IAMState AccountIAMClient::GetState(int32_t userId)
{
    ACCOUNT_LOGD("enter");
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = userStateMap_.find(userId);
    if (it != userStateMap_.end()) {
        return it->second;
    }
    return userStateMap_[0];
}

void AccountIAMClient::SetState(int32_t userId, IAMState state)
{
    ACCOUNT_LOGD("enter");
    std::lock_guard<std::mutex> lock(mutex_);
    userStateMap_[userId] = state;
}

void AccountIAMClient::GetChallenge(int32_t userId, std::vector<uint8_t> &challenge)
{
    ACCOUNT_LOGD("enter");
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = userChallengeMap_.find(userId);
    if (it != userChallengeMap_.end()) {
        challenge = it->second;
    } else {
        challenge = userChallengeMap_[0];
    }
}

void AccountIAMClient::GetCredential(int32_t userId, int32_t authSubType, CredentialPair &credPair)
{
    ACCOUNT_LOGD("enter");
    std::string key = std::to_string(userId) + std::to_string(authSubType);
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = credentialMap_.find(key);
    if (it != credentialMap_.end()) {
        credPair = it->second;
    }
}

void AccountIAMClient::SetCredential(int32_t userId, int32_t authSubType, const std::vector<uint8_t> &credential)
{
    ACCOUNT_LOGD("enter");
    std::string key = std::to_string(userId) + std::to_string(authSubType);
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = credentialMap_.find(key);
    if (it != credentialMap_.end()) {
        it->second.oldCredential = it->second.credential;
        it->second.credential = credential;
        return;
    }
    credentialMap_[key] = {
        .credential = credential
    };
}

void AccountIAMClient::ClearCredential(int32_t userId, int32_t authSubType)
{
    std::string key = std::to_string(userId) + std::to_string(authSubType);
    std::lock_guard<std::mutex> lock(mutex_);
    credentialMap_.erase(key);
}

ErrCode AccountIAMClient::ActivateUserKey(
    int32_t userId, const std::vector<uint8_t> &token, const std::vector<uint8_t> &secret)
{
    ACCOUNT_LOGD("enter");
    ErrCode result = GetAccountIAMProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return result;
    }
    return proxy_->ActivateUserKey(userId, token, secret);
}

ErrCode AccountIAMClient::UpdateUserKey(int32_t userId, uint64_t credentialId,
    const std::vector<uint8_t> &token, const std::vector<uint8_t> &newSecret)
{
    ACCOUNT_LOGD("enter");
    ErrCode result = GetAccountIAMProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return result;
    }
    return proxy_->UpdateUserKey(userId, credentialId, token, newSecret);
}

ErrCode AccountIAMClient::RemoveUserKey(int32_t userId, const std::vector<uint8_t> &token)
{
    ACCOUNT_LOGD("enter");
    ErrCode result = GetAccountIAMProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return result;
    }
    return proxy_->RemoveUserKey(userId, token);
}

ErrCode AccountIAMClient::RestoreUserKey(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &token)
{
    ACCOUNT_LOGD("enter");
    ErrCode result = GetAccountIAMProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return result;
    }
    return proxy_->RestoreUserKey(userId, credentialId, token);
}

void AccountIAMClient::ResetAccountIAMProxy(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ == nullptr) {
        ACCOUNT_LOGD("proxy is nullptr");
        return;
    }
    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

void AccountIAMClient::AccountIAMDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    if (remote == nullptr) {
        ACCOUNT_LOGD("remote is nullptr");
        return;
    }
    AccountIAMClient::GetInstance().ResetAccountIAMProxy(remote);
}

ErrCode AccountIAMClient::GetAccountIAMProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return ERR_OK;
    }
    sptr<ISystemAbilityManager> saMgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!saMgr) {
        ACCOUNT_LOGD("failed to get system ability manager");
        return ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER;
    }
    sptr<IRemoteObject> remoteObject = saMgr->GetSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
    if (!remoteObject) {
        ACCOUNT_LOGD("failed to get account system ability");
        return ERR_APPACCOUNT_KIT_GET_ACCOUNT_SYSTEM_ABILITY;
    }
    sptr<IAccount> accountProxy = iface_cast<AccountProxy>(remoteObject);
    if (!accountProxy) {
        ACCOUNT_LOGD("failed to cast account proxy");
        return ERR_APPACCOUNT_KIT_CAST_ACCOUNT_PROXY;
    }
    sptr<IRemoteObject> accountIAMRemoteObject = accountProxy->GetAccountIAMService();
    if (!accountIAMRemoteObject) {
        ACCOUNT_LOGD("failed to get account iam service");
        return ERR_APPACCOUNT_KIT_GET_APP_ACCOUNT_SERVICE;
    }
    proxy_ = iface_cast<IAccountIAM>(accountIAMRemoteObject);
    if ((!proxy_) || (!proxy_->AsObject())) {
        ACCOUNT_LOGD("failed to cast account iam proxy");
        return ERR_APPACCOUNT_KIT_GET_APP_ACCOUNT_PROXY;
    }
    deathRecipient_ = new (std::nothrow) AccountIAMDeathRecipient();
    if (!deathRecipient_) {
        ACCOUNT_LOGD("failed to create account iam death recipient");
        return ERR_APPACCOUNT_KIT_CREATE_APP_ACCOUNT_DEATH_RECIPIENT;
    }
    proxy_->AsObject()->AddDeathRecipient(deathRecipient_);
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

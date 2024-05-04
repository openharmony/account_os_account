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

#include "inner_account_iam_manager.h"

#include "account_iam_callback.h"
#include "account_log_wrapper.h"
#include "domain_account_callback_service.h"
#include "account_hisysevent_adapter.h"
#include "iinner_os_account_manager.h"
#include "inner_domain_account_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "user_auth_client.h"
#include "user_auth_client_impl.h"
#include "user_idm_client.h"

namespace OHOS {
namespace AccountSA {
namespace {
#ifdef HAS_STORAGE_PART
const int32_t ERROR_STORAGE_KEY_NOT_EXIST = -2;
#endif
}
using UserIDMClient = UserIam::UserAuth::UserIdmClient;
using UserAuthClient = UserIam::UserAuth::UserAuthClient;
using UserAuthClientImpl = UserIam::UserAuth::UserAuthClientImpl;

InnerAccountIAMManager::InnerAccountIAMManager()
{
    userStateMap_[0] = IDLE;
}

InnerAccountIAMManager &InnerAccountIAMManager::GetInstance()
{
    static InnerAccountIAMManager *instance = new (std::nothrow) InnerAccountIAMManager();
    return *instance;
}

void InnerAccountIAMManager::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    challenge = UserIDMClient::GetInstance().OpenSession(userId);
    std::lock_guard<std::mutex> lock(mutex_);
    userStateMap_[userId] = AFTER_OPEN_SESSION;
    userChallengeMap_[userId] = challenge;
}

void InnerAccountIAMManager::CloseSession(int32_t userId)
{
    UserIDMClient::GetInstance().CloseSession(userId);
    std::lock_guard<std::mutex> lock(mutex_);
    if (userId == 0) {
        userStateMap_[0] = IDLE;
    } else {
        userStateMap_.erase(userId);
    }
    userChallengeMap_.erase(userId);
}

void InnerAccountIAMManager::AddCredential(
    int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }

    sptr<IDMCallbackDeathRecipient> deathRecipient = new (std::nothrow) IDMCallbackDeathRecipient(userId);
    if ((deathRecipient == nullptr) || (callback->AsObject() == nullptr) ||
        (!callback->AsObject()->AddDeathRecipient(deathRecipient))) {
        ACCOUNT_LOGE("Failed to add death recipient for AddCred");
        return;
    }
    auto idmCallbackWrapper = std::make_shared<AddCredCallback>(userId, credInfo, callback);
    idmCallbackWrapper->SetDeathRecipient(deathRecipient);
    UserIDMClient::GetInstance().AddCredential(userId, credInfo, idmCallbackWrapper);
}

void InnerAccountIAMManager::UpdateCredential(
    int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    Attributes emptyResult;
    if (credInfo.token.empty()) {
        ACCOUNT_LOGE("token is empty");
        callback->OnResult(ResultCode::INVALID_PARAMETERS, emptyResult);
        return;
    }

    sptr<IDMCallbackDeathRecipient> deathRecipient = new (std::nothrow) IDMCallbackDeathRecipient(userId);
    if ((deathRecipient == nullptr) || (callback->AsObject() == nullptr) ||
        (!callback->AsObject()->AddDeathRecipient(deathRecipient))) {
        ACCOUNT_LOGE("Failed to add death recipient for UpdateCred");
        return;
    }

    auto idmCallbackWrapper = std::make_shared<UpdateCredCallback>(userId, credInfo, callback);
    idmCallbackWrapper->SetDeathRecipient(deathRecipient);
    UserIDMClient::GetInstance().UpdateCredential(userId, credInfo, idmCallbackWrapper);
}

void InnerAccountIAMManager::DelCred(
    int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    Attributes emptyResult;
    if (authToken.empty()) {
        ACCOUNT_LOGD("token is empty");
        callback->OnResult(ResultCode::INVALID_PARAMETERS, emptyResult);
        return;
    }
    uint64_t pinCredentialId = 0;
    (void)IInnerOsAccountManager::GetInstance().GetOsAccountCredentialId(userId, pinCredentialId);
    bool isPIN = (pinCredentialId != 0) && (credentialId == pinCredentialId);

    auto idmCallback = std::make_shared<DelCredCallback>(userId, isPIN, authToken, callback);
    UserIDMClient::GetInstance().DeleteCredential(userId, credentialId, authToken, idmCallback);
}

void InnerAccountIAMManager::DelUser(
    int32_t userId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    Attributes errResult;
    if (authToken.empty()) {
        ACCOUNT_LOGE("token is empty");
        callback->OnResult(ResultCode::INVALID_PARAMETERS, errResult);
        return;
    }

    auto idmCallback = std::make_shared<DelCredCallback>(userId, true, authToken, callback);
    UserIDMClient::GetInstance().DeleteUser(userId, authToken, idmCallback);
}

static bool IsNonPINAllowed(int32_t userId)
{
    bool isVerified = false;
    (void) IInnerOsAccountManager::GetInstance().IsOsAccountVerified(userId, isVerified);
    return isVerified;
}

void InnerAccountIAMManager::GetCredentialInfo(
    int32_t userId, AuthType authType, const sptr<IGetCredInfoCallback> &callback)
{
    if (!IsNonPINAllowed(userId)) {
        if ((authType != AuthType::PIN) && (authType != AuthType::ALL)) {
            ACCOUNT_LOGD("unsupported auth type: %{public}d", authType);
            std::vector<CredentialInfo> infoList;
            return callback->OnCredentialInfo(infoList);
        }
        authType = AuthType::PIN;
    }
    if (static_cast<int32_t>(authType) == static_cast<int32_t>(IAMAuthType::DOMAIN)) {
        std::vector<CredentialInfo> infoList;
        if (CheckDomainAuthAvailable(userId)) {
            CredentialInfo info;
            info.authType = static_cast<AuthType>(IAMAuthType::DOMAIN);
            info.pinType = static_cast<PinSubType>(IAMAuthSubType::DOMAIN_MIXED);
            infoList.emplace_back(info);
        }
        return callback->OnCredentialInfo(infoList);
    }
    auto getCallback = std::make_shared<GetCredInfoCallbackWrapper>(userId, static_cast<int32_t>(authType), callback);
    UserIDMClient::GetInstance().GetCredentialInfo(userId, authType, getCallback);
}

int32_t InnerAccountIAMManager::Cancel(int32_t userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = userStateMap_.find(userId);
    if ((it == userStateMap_.end()) || (it->second >= AFTER_ADD_CRED)) {
        return ResultCode::GENERAL_ERROR;
    }
    return UserIDMClient::GetInstance().Cancel(userId);
}

int32_t InnerAccountIAMManager::PrepareRemoteAuth(
    const std::string &remoteNetworkId, const sptr<IPreRemoteAuthCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    ACCOUNT_LOGI("Start IAM PrepareRemoteAuth.");
    auto prepareCallback = std::make_shared<PrepareRemoteAuthCallbackWrapper>(callback);
    return UserAuthClient::GetInstance().PrepareRemoteAuth(remoteNetworkId, prepareCallback);
}

void InnerAccountIAMManager::CopyAuthParam(const AuthParam &authParam, UserIam::UserAuth::AuthParam &iamAuthParam)
{
    iamAuthParam.userId = authParam.userId;
    iamAuthParam.challenge = authParam.challenge;
    iamAuthParam.authType = authParam.authType;
    iamAuthParam.authTrustLevel = authParam.authTrustLevel;
    iamAuthParam.authIntent = static_cast<UserIam::UserAuth::AuthIntent>(authParam.authIntent);
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

int32_t InnerAccountIAMManager::AuthUser(
    AuthParam &authParam, const sptr<IIDMCallback> &callback, uint64_t &contextId)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    if ((authParam.authType != AuthType::PIN) && (!IsNonPINAllowed(authParam.userId))) {
        ACCOUNT_LOGE("unsupported auth type: %{public}d", authParam.authType);
        return ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE;
    }
    OsAccountInfo osAccountInfo;
    if (IInnerOsAccountManager::GetInstance().QueryOsAccountById(authParam.userId, osAccountInfo) != ERR_OK) {
        ACCOUNT_LOGE("Account does not exist");
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    sptr<AuthCallbackDeathRecipient> deathRecipient = new (std::nothrow) AuthCallbackDeathRecipient();
    if ((deathRecipient == nullptr) || (!callback->AsObject()->AddDeathRecipient(deathRecipient))) {
        ACCOUNT_LOGE("failed to add death recipient for auth callback");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }

    auto callbackWrapper =
        std::make_shared<AuthCallback>(authParam.userId, osAccountInfo.GetCredentialId(), authParam.authType, callback);
    callbackWrapper->SetDeathRecipient(deathRecipient);

    UserIam::UserAuth::AuthParam iamAuthParam;
    CopyAuthParam(authParam, iamAuthParam);
    ACCOUNT_LOGI("Start IAM AuthUser.");
    contextId = UserAuthClient::GetInstance().BeginAuthentication(iamAuthParam, callbackWrapper);
    deathRecipient->SetContextId(contextId);
    return ERR_OK;
}

int32_t InnerAccountIAMManager::CancelAuth(uint64_t contextId)
{
    return UserAuthClient::GetInstance().CancelAuthentication(contextId);
}

int32_t InnerAccountIAMManager::GetAvailableStatus(
    AuthType authType, AuthTrustLevel authTrustLevel, int32_t &status)
{
    if (static_cast<int32_t>(authType) != static_cast<int32_t>(IAMAuthType::DOMAIN)) {
        status = UserAuthClientImpl::Instance().GetAvailableStatus(authType, authTrustLevel);
        return ERR_OK;
    }
    bool isPluginAvailable = InnerDomainAccountManager::GetInstance().IsPluginAvailable();
    if (isPluginAvailable) {
        status = ERR_JS_SUCCESS;
    } else {
        status = ERR_JS_AUTH_TYPE_NOT_SUPPORTED;
    }
    return ERR_OK;
}

ErrCode InnerAccountIAMManager::GetDomainAuthStatusInfo(
    int32_t userId, const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
{
    OsAccountInfo osAccountInfo;
    ErrCode result = IInnerOsAccountManager::GetInstance().QueryOsAccountById(userId, osAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info");
        return result;
    }
    DomainAccountInfo domainAccountInfo;
    osAccountInfo.GetDomainInfo(domainAccountInfo);
    if (domainAccountInfo.accountName_.empty()) {
        ACCOUNT_LOGE("the target user is not a domain account");
        return ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE;
    }
    std::shared_ptr<DomainAccountCallback> statusCallback =
        std::make_shared<GetDomainAuthStatusInfoCallback>(request, callback);
    if (statusCallback == nullptr) {
        ACCOUNT_LOGE("failed to create GetDomainAuthStatusInfoCallback");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    return InnerDomainAccountManager::GetInstance().GetAuthStatusInfo(domainAccountInfo, statusCallback);
}

bool InnerAccountIAMManager::CheckDomainAuthAvailable(int32_t userId)
{
    OsAccountInfo osAccountInfo;
    if (IInnerOsAccountManager::GetInstance().QueryOsAccountById(userId, osAccountInfo) != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info");
        return false;
    }
    DomainAccountInfo domainAccountInfo;
    osAccountInfo.GetDomainInfo(domainAccountInfo);
    bool isAvailable = InnerDomainAccountManager::GetInstance().IsPluginAvailable();
    return !domainAccountInfo.accountName_.empty() && isAvailable;
}

void InnerAccountIAMManager::GetProperty(
    int32_t userId, const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    Attributes attributes;
    if ((request.authType != AuthType::PIN) && (!IsNonPINAllowed(userId))) {
        ACCOUNT_LOGE("unsupported auth type: %{public}d", request.authType);
        callback->OnResult(ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE, attributes);
        return;
    }
    if (static_cast<int32_t>(request.authType) != static_cast<int32_t>(IAMAuthType::DOMAIN)) {
        auto getCallback = std::make_shared<GetPropCallbackWrapper>(userId, callback);
        UserAuthClient::GetInstance().GetProperty(userId, request, getCallback);
        return;
    }
    ErrCode result = GetDomainAuthStatusInfo(userId, request, callback);
    if (result != ERR_OK) {
        callback->OnResult(result, attributes);
    }
}

void InnerAccountIAMManager::SetProperty(
    int32_t userId, const SetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
{
    if (static_cast<int32_t>(request.authType) == static_cast<int32_t>(IAMAuthType::DOMAIN)) {
        Attributes result;
        callback->OnResult(ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE, result);
        return;
    }
    auto setCallback = std::make_shared<SetPropCallbackWrapper>(userId, callback);
    UserAuthClient::GetInstance().SetProperty(userId, request, setCallback);
}

void InnerAccountIAMManager::GetEnrolledId(
    int32_t accountId, AuthType authType, const sptr<IGetEnrolledIdCallback> &callback)
{
    if (static_cast<int32_t>(authType) == static_cast<int32_t>(IAMAuthType::DOMAIN)) {
        ACCOUNT_LOGE("Unsupported auth type");
        uint64_t emptyId = 0;
        callback->OnEnrolledId(ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE, emptyId);
        return;
    }
    auto GetSecUserInfoCallback = std::make_shared<GetSecUserInfoCallbackWrapper>(authType, callback);
    UserIDMClient::GetInstance().GetSecUserInfo(accountId, GetSecUserInfoCallback);
}

IAMState InnerAccountIAMManager::GetState(int32_t userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = userStateMap_.find(userId);
    if (it != userStateMap_.end()) {
        return it->second;
    }
    return userStateMap_[0];
}

void InnerAccountIAMManager::SetState(int32_t userId, IAMState state)
{
    std::lock_guard<std::mutex> lock(mutex_);
    userStateMap_[userId] = state;
}

void InnerAccountIAMManager::GetChallenge(int32_t userId, std::vector<uint8_t> &challenge)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = userChallengeMap_.find(userId);
    if (it != userChallengeMap_.end()) {
        challenge = it->second;
    } else {
        challenge = userChallengeMap_[0];
    }
}

ErrCode InnerAccountIAMManager::UpdateStorageKey(
    int32_t userId, uint64_t secureUid, const std::vector<uint8_t> &token,
    const std::vector<uint8_t> &oldSecret, const std::vector<uint8_t> &newSecret)
{
#ifdef HAS_STORAGE_PART
    ErrCode result = GetStorageManagerProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("fail to get storage proxy");
        return result;
    }
    result = storageMgrProxy_->UpdateUserAuth(userId, secureUid, token, oldSecret, newSecret);
    if ((result != ERR_OK) && (result != ERROR_STORAGE_KEY_NOT_EXIST)) {
        ACCOUNT_LOGE("fail to update user auth");
        return result;
    }

    result = storageMgrProxy_->UpdateKeyContext(userId);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Fail to update key context, userId=%{public}d, result=%{public}d", userId, result);
        ReportOsAccountOperationFail(userId, "updateStorageKeyContext", result,
            "Failed to notice storage update key context");
    }
    return result;
#else
    return ERR_OK;
#endif
}

ErrCode InnerAccountIAMManager::UpdateStorageKeyContext(const int32_t userId)
{
    ACCOUNT_LOGI("Enter, userId=%{public}d", userId);
#ifdef HAS_STORAGE_PART
    ErrCode code = GetStorageManagerProxy();
    if (code != ERR_OK) {
        ACCOUNT_LOGE("Fail to get storage proxy");
        return code;
    }
    code = storageMgrProxy_->UpdateKeyContext(userId);
    if (code != ERR_OK) {
        ACCOUNT_LOGE("Fail to update key context, userId=%{public}d, code=%{public}d", userId, code);
        ReportOsAccountOperationFail(userId, "updateStorageKeyContext", code,
            "Failed to notice storage update key context");
        return code;
    }
#endif
    return ERR_OK;
}

ErrCode InnerAccountIAMManager::UpdateStorageUserAuth(int32_t userId, uint64_t secureUid,
    const std::vector<uint8_t> &token, const std::vector<uint8_t> &oldSecret, const std::vector<uint8_t> &newSecret)
{
    ACCOUNT_LOGI("Enter, userId=%{public}d", userId);
#ifdef HAS_STORAGE_PART
    ErrCode code = GetStorageManagerProxy();
    if (code != ERR_OK) {
        ACCOUNT_LOGE("Fail to get storage proxy");
        return code;
    }

    code = storageMgrProxy_->UpdateUserAuth(userId, secureUid, token, oldSecret, newSecret);
    if ((code != ERR_OK) && (code != ERROR_STORAGE_KEY_NOT_EXIST)) {
        ACCOUNT_LOGE("Fail to update user auth, userId=%{public}d, code=%{public}d", userId, code);
        ReportOsAccountOperationFail(userId, "updateStorageUserAuth", code,
            "Failed to notice storage update user auth");
        return code;
    }
#endif
    return ERR_OK;
}

ErrCode InnerAccountIAMManager::GetLockScreenStatus(uint32_t userId, bool &lockScreenStatus)
{
#ifdef HAS_STORAGE_PART
    ErrCode result = GetStorageManagerProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("fail to get storage proxy");
        return result;
    }
    result = storageMgrProxy_->GetLockScreenStatus(userId, lockScreenStatus);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get lock screen status");
        return result;
    }
#endif
    return ERR_OK;
}

ErrCode InnerAccountIAMManager::UnlockUserScreen(int32_t userId)
{
#ifdef HAS_STORAGE_PART
    ErrCode result = GetStorageManagerProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("fail to get storage proxy");
        return result;
    }
    result = storageMgrProxy_->UnlockUserScreen(userId);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("fail to unlock screen");
        return result;
    }
#endif
    return ERR_OK;
}

ErrCode InnerAccountIAMManager::ActivateUserKey(
    int32_t userId, const std::vector<uint8_t> &token, const std::vector<uint8_t> &secret)
{
#ifdef HAS_STORAGE_PART
    ErrCode result = GetStorageManagerProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("fail to get storage proxy");
        return result;
    }
    result = storageMgrProxy_->ActiveUserKey(userId, token, secret);
    if (result != ERR_OK && result != ERROR_STORAGE_KEY_NOT_EXIST) {
        ACCOUNT_LOGE("fail to active user key, error code: %{public}d", result);
        return result;
    }
    storageMgrProxy_->PrepareStartUser(userId);
#endif
    return ERR_OK;
}


ErrCode InnerAccountIAMManager::GetStorageManagerProxy()
{
#ifdef HAS_STORAGE_PART
    if (storageMgrProxy_ != nullptr) {
        return ERR_OK;
    }
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        ACCOUNT_LOGE("failed to get system ability mgr");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto remote = systemAbilityManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (remote == nullptr) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID service");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY;
    }
    storageMgrProxy_ = iface_cast<StorageManager::IStorageManager>(remote);
    if (storageMgrProxy_ == nullptr) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID proxy");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY;
    }
    return ERR_OK;
#else
    return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY;
#endif
}
}  // namespace AccountSA
}  // namespace OHOS

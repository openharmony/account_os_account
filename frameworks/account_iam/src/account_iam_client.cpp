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

#include "accesstoken_kit.h"
#include "account_error_no.h"
#include "account_iam_callback_service.h"
#include "account_log_wrapper.h"
#include "account_proxy.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "pinauth_register.h"
#include "system_ability_definition.h"
#include "token_setproc.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string PERMISSION_MANAGE_USER_IDM = "ohos.permission.MANAGE_USER_IDM";
const std::string PERMISSION_ACCESS_USER_AUTH_INTERNAL = "ohos.permission.ACCESS_USER_AUTH_INTERNAL";
}
AccountIAMClient::AccountIAMClient()
{}

int32_t AccountIAMClient::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        return ERR_ACCOUNT_IAM_KIT_PROXY_ERROR;
    }
    return proxy_->OpenSession(userId, challenge);
}

int32_t AccountIAMClient::CloseSession(int32_t userId)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        return ERR_ACCOUNT_IAM_KIT_PROXY_ERROR;
    }
    return proxy_->CloseSession(userId);
}

void AccountIAMClient::AddCredential(
    int32_t userId, const CredentialParameters& credInfo, const std::shared_ptr<IDMCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    Attributes emptyResult;
    if (GetAccountIAMProxy() != ERR_OK) {
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_PROXY_ERROR, emptyResult);
        return;
    }
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        ACCOUNT_LOGE("fail to add credential for invalid userId");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_PARAM_INVALID_ERROR, emptyResult);
        return;
    }
    if (credInfo.authType == AuthType::PIN) {
        SetAuthSubType(userId, static_cast<int32_t>(credInfo.pinType.value_or(PinSubType::PIN_MAX)));
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(userId, callback);
    proxy_->AddCredential(userId, credInfo, wrapper);
}

void AccountIAMClient::UpdateCredential(
    int32_t userId, const CredentialParameters& credInfo, const std::shared_ptr<IDMCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    Attributes emptyResult;
    if (GetAccountIAMProxy() != ERR_OK) {
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_PROXY_ERROR, emptyResult);
        return;
    }
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        ACCOUNT_LOGE("fail to update credential for invalid userId");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_PARAM_INVALID_ERROR, emptyResult);
        return;
    }
    if (credInfo.authType == AuthType::PIN) {
        SetAuthSubType(userId, static_cast<int32_t>(credInfo.pinType.value_or(PinSubType::PIN_MAX)));
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(userId, callback);
    proxy_->UpdateCredential(userId, credInfo, wrapper);
}

void AccountIAMClient::DelCred(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
    const std::shared_ptr<IDMCallback>& callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    Attributes emptyResult;
    if (GetAccountIAMProxy() != ERR_OK) {
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_PROXY_ERROR, emptyResult);
        return;
    }
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_PARAM_INVALID_ERROR, emptyResult);
        return;
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(userId, callback);
    proxy_->DelCred(userId, credentialId, authToken, wrapper);
}

void AccountIAMClient::DelUser(
    int32_t userId, const std::vector<uint8_t> &authToken, const std::shared_ptr<IDMCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    Attributes emptyResult;
    if (GetAccountIAMProxy() != ERR_OK) {
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_PROXY_ERROR, emptyResult);
        return;
    }
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_PARAM_INVALID_ERROR, emptyResult);
        return;
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(userId, callback);
    proxy_->DelUser(userId, authToken, wrapper);
}

int32_t AccountIAMClient::GetCredentialInfo(
    int32_t userId, AuthType authType, const std::shared_ptr<GetCredInfoCallback> &callback)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        return ERR_ACCOUNT_IAM_KIT_PROXY_ERROR;
    }
    sptr<IGetCredInfoCallback> wrapper = new (std::nothrow) GetCredInfoCallbackService(callback);
    return proxy_->GetCredentialInfo(userId, authType, wrapper);
}

int32_t AccountIAMClient::Cancel(int32_t userId)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        return ERR_ACCOUNT_IAM_KIT_PROXY_ERROR;
    }
    return proxy_->Cancel(userId);
}

uint64_t AccountIAMClient::StartDomainAuth(int32_t userId, const std::shared_ptr<IDMCallback> &callback)
{
    std::lock_guard<std::mutex> lock(domainMutex_);
    Attributes emptyResult;
    if (domainInputer_ == nullptr) {
        ACCOUNT_LOGE("the registered inputer is not found or invalid");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_INPUTER_NOT_REGISTERED, emptyResult);
        return 0;
    }
    auto credentialRecipient = std::make_shared<DomainCredentialRecipient>(userId, callback);
    if (credentialRecipient == nullptr) {
        ACCOUNT_LOGE("failed to create DomainCredentialRecipient");
        callback->OnResult(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, emptyResult);
        return 0;
    }
    domainInputer_->OnGetData(IAMAuthType::DOMAIN, credentialRecipient);
    return 0;
}

uint64_t AccountIAMClient::Auth(const std::vector<uint8_t> &challenge, AuthType authType,
    AuthTrustLevel authTrustLevel, const std::shared_ptr<IDMCallback> &callback)
{
    return AuthUser(0, challenge, authType, authTrustLevel, callback);
}

uint64_t AccountIAMClient::AuthUser(
    int32_t userId, const std::vector<uint8_t> &challenge, AuthType authType,
    AuthTrustLevel authTrustLevel, const std::shared_ptr<IDMCallback> &callback)
{
    uint64_t contextId = 0;
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return contextId;
    }
    if (GetAccountIAMProxy() != ERR_OK) {
        return contextId;
    }
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        return contextId;
    }
    if (static_cast<int32_t>(authType) == static_cast<int32_t>(IAMAuthType::DOMAIN)) {
        return StartDomainAuth(userId, callback);
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(userId, callback);
    return proxy_->AuthUser(userId, challenge, authType, authTrustLevel, wrapper);
}

int32_t AccountIAMClient::CancelAuth(uint64_t contextId)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        return ERR_ACCOUNT_IAM_KIT_PROXY_ERROR;
    }
    return proxy_->CancelAuth(contextId);
}

int32_t AccountIAMClient::GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel, int32_t &status)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        return ERR_ACCOUNT_IAM_KIT_PROXY_ERROR;
    }
    if (authTrustLevel < UserIam::UserAuth::ATL1 || authTrustLevel > UserIam::UserAuth::ATL4) {
        ACCOUNT_LOGE("authTrustLevel is not in correct range");
        return ERR_ACCOUNT_IAM_KIT_PARAM_INVALID_ERROR;
    }
    if (authType < UserIam::UserAuth::ALL) {
        ACCOUNT_LOGE("authType is not in correct range");
        return ERR_ACCOUNT_IAM_KIT_PARAM_INVALID_ERROR;
    }
    return proxy_->GetAvailableStatus(authType, authTrustLevel, status);
}

void AccountIAMClient::GetProperty(
    int32_t userId, const GetPropertyRequest &request, const std::shared_ptr<GetSetPropCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    Attributes emptyResult;
    if (GetAccountIAMProxy() != ERR_OK) {
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_PROXY_ERROR, emptyResult);
        return;
    }
    sptr<IGetSetPropCallback> wrapper = new (std::nothrow) GetSetPropCallbackService(callback);
    proxy_->GetProperty(userId, request, wrapper);
}

void AccountIAMClient::SetProperty(
    int32_t userId, const SetPropertyRequest &request, const std::shared_ptr<GetSetPropCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    Attributes emptyResult;
    if (GetAccountIAMProxy() != ERR_OK) {
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_PROXY_ERROR, emptyResult);
        return;
    }
    sptr<IGetSetPropCallback> wrapper = new (std::nothrow) GetSetPropCallbackService(callback);
    proxy_->SetProperty(userId, request, wrapper);
}

ErrCode AccountIAMClient::RegisterPINInputer(const std::shared_ptr<IInputer> &inputer)
{
    std::lock_guard<std::mutex> lock(pinMutex_);
    if (pinInputer_ != nullptr) {
        ACCOUNT_LOGE("inputer is already registered");
        return ERR_ACCOUNT_IAM_KIT_INPUTER_ALREADY_REGISTERED;
    }
    int32_t userId = 0;
    if (!GetCurrentUserId(userId)) {
        return ERR_ACCOUNT_IAM_KIT_GET_USERID_FAIL;
    }
    auto iamInputer = std::make_shared<IAMInputer>(userId, inputer);
    if (iamInputer == nullptr) {
        ACCOUNT_LOGE("failed to create IAMInputer");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    if (UserIam::PinAuth::PinAuthRegister::GetInstance().RegisterInputer(iamInputer)) {
        pinInputer_ = inputer;
        return ERR_OK;
    }
    return ERR_ACCOUNT_IAM_SERVICE_PERMISSION_DENIED;
}

bool AccountIAMClient::CheckSelfPermission(const std::string &permissionName)
{
    Security::AccessToken::AccessTokenID tokenId = GetSelfTokenID();
    ErrCode result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permissionName);
    return result == Security::AccessToken::TypePermissionState::PERMISSION_GRANTED;
}

ErrCode AccountIAMClient::RegisterDomainInputer(const std::shared_ptr<IInputer> &inputer)
{
    std::lock_guard<std::mutex> lock(domainMutex_);
    if (domainInputer_ != nullptr) {
        ACCOUNT_LOGE("inputer is already registered");
        return ERR_ACCOUNT_IAM_KIT_INPUTER_ALREADY_REGISTERED;
    }
    domainInputer_ = inputer;
    return ERR_OK;
}

ErrCode AccountIAMClient::RegisterInputer(int32_t authType, const std::shared_ptr<IInputer> &inputer)
{
    if ((!CheckSelfPermission(PERMISSION_ACCESS_USER_AUTH_INTERNAL)) &&
        (!CheckSelfPermission(PERMISSION_MANAGE_USER_IDM))) {
        ACCOUNT_LOGE("failed to check permission");
        return ERR_ACCOUNT_IAM_SERVICE_PERMISSION_DENIED;
    }
    if (inputer == nullptr) {
        ACCOUNT_LOGE("inputer is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    }
    switch (authType) {
        case IAMAuthType::DOMAIN:
            return RegisterDomainInputer(inputer);
        default:
            return ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE;
    }
}

ErrCode AccountIAMClient::UnregisterInputer(int32_t authType)
{
    if ((!CheckSelfPermission(PERMISSION_ACCESS_USER_AUTH_INTERNAL)) &&
        (!CheckSelfPermission(PERMISSION_MANAGE_USER_IDM))) {
        ACCOUNT_LOGE("failed to check permission");
        return ERR_ACCOUNT_IAM_SERVICE_PERMISSION_DENIED;
    }
    switch (authType) {
        case IAMAuthType::DOMAIN:
            return UnregisterDomainInputer();
        default:
            return ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE;
    }
    return ERR_OK;
}

void AccountIAMClient::UnregisterPINInputer()
{
    UserIam::PinAuth::PinAuthRegister::GetInstance().UnRegisterInputer();
    std::lock_guard<std::mutex> lock(pinMutex_);
    pinInputer_ = nullptr;
}

ErrCode AccountIAMClient::UnregisterDomainInputer()
{
    std::lock_guard<std::mutex> lock(domainMutex_);
    domainInputer_ = nullptr;
    return ERR_OK;
}

IAMState AccountIAMClient::GetAccountState(int32_t userId)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        return IDLE;
    }
    return proxy_->GetAccountState(userId);
}

void AccountIAMClient::GetCredential(int32_t userId, CredentialItem &credItem)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = credentialMap_.find(userId);
    if (it != credentialMap_.end()) {
        credItem = it->second;
    }
}

void AccountIAMClient::SetCredential(int32_t userId, const std::vector<uint8_t> &credential)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = credentialMap_.find(userId);
    if (it != credentialMap_.end()) {
        it->second.oldCredential = it->second.credential;
        it->second.credential = credential;
        return;
    }
    credentialMap_[userId] = {
        .credential = credential
    };
}

void AccountIAMClient::ClearCredential(int32_t userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    credentialMap_.erase(userId);
}

void AccountIAMClient::SetAuthSubType(int32_t userId, int32_t authSubType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = credentialMap_.find(userId);
    if (it != credentialMap_.end()) {
        return;
    }
    credentialMap_[userId] = {
        .type = authSubType
    };
}

int32_t AccountIAMClient::GetAuthSubType(int32_t userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = credentialMap_.find(userId);
    if (it != credentialMap_.end()) {
        return it->second.type;
    }
    return 0;
}

bool AccountIAMClient::GetCurrentUserId(int32_t &userId)
{
    std::vector<int32_t> userIds;
    if ((OsAccountManager::QueryActiveOsAccountIds(userIds) != ERR_OK) || userIds.empty()) {
        ACCOUNT_LOGE("fail to get activated os account ids");
        return false;
    }
    userId = userIds[0];
    return true;
}

void AccountIAMClient::ResetAccountIAMProxy(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ == nullptr) {
        ACCOUNT_LOGE("proxy is nullptr");
        return;
    }
    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

void AccountIAMClient::AccountIAMDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr");
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
    if (saMgr == nullptr) {
        ACCOUNT_LOGE("failed to get system ability manager");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    sptr<IRemoteObject> remoteObject = saMgr->GetSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
    if (remoteObject == nullptr) {
        ACCOUNT_LOGE("failed to get account system ability");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY;
    }
    sptr<IAccount> accountProxy = iface_cast<AccountProxy>(remoteObject);
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("failed to cast account proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    proxy_ = iface_cast<IAccountIAM>(accountProxy->GetAccountIAMService());
    if ((proxy_ == nullptr) || (proxy_->AsObject() == nullptr)) {
        ACCOUNT_LOGE("failed to cast account iam proxy");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    deathRecipient_ = new (std::nothrow) AccountIAMDeathRecipient();
    if (deathRecipient_ == nullptr) {
        ACCOUNT_LOGE("failed to create account iam death recipient");
        proxy_ = nullptr;
        return ERR_ACCOUNT_COMMON_CREATE_DEATH_RECIPIENT;
    }
    if (!proxy_->AsObject()->AddDeathRecipient(deathRecipient_)) {
        ACCOUNT_LOGE("failed to add account iam death recipient");
        proxy_ = nullptr;
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

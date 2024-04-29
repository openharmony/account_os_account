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

#include "account_iam_client.h"

#include "accesstoken_kit.h"
#include "account_error_no.h"
#include "account_iam_callback_service.h"
#include "account_log_wrapper.h"
#include "account_proxy.h"
#include "account_permission_manager.h"
#include "ipc_skeleton.h"
#include "ohos_account_kits_impl.h"
#include "os_account_manager.h"
#ifdef HAS_PIN_AUTH_PART
#include "pinauth_register.h"
#endif

namespace OHOS {
namespace AccountSA {
namespace {
const std::string PERMISSION_ACCESS_PIN_AUTH = "ohos.permission.ACCESS_PIN_AUTH";
const std::string PERMISSION_MANAGE_USER_IDM = "ohos.permission.MANAGE_USER_IDM";
const std::string PERMISSION_ACCESS_USER_AUTH_INTERNAL = "ohos.permission.ACCESS_USER_AUTH_INTERNAL";
}

AccountIAMClient &AccountIAMClient::GetInstance()
{
    static AccountIAMClient *instance = new (std::nothrow) AccountIAMClient();
    return *instance;
}

int32_t AccountIAMClient::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->OpenSession(userId, challenge);
}

int32_t AccountIAMClient::CloseSession(int32_t userId)
{
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CloseSession(userId);
}

void AccountIAMClient::AddCredential(
    int32_t userId, const CredentialParameters& credInfo, const std::shared_ptr<IDMCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("the callback for adding credential is nullptr");
        return;
    }
    Attributes emptyResult;
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        callback->OnResult(ERR_ACCOUNT_COMMON_GET_PROXY, emptyResult);
        return;
    }
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        ACCOUNT_LOGE("fail to add credential for invalid userId");
        callback->OnResult(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, emptyResult);
        return;
    }
    if (credInfo.authType == AuthType::PIN) {
        SetAuthSubType(userId, static_cast<int32_t>(credInfo.pinType.value_or(PinSubType::PIN_MAX)));
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(userId, callback);
    proxy->AddCredential(userId, credInfo, wrapper);
}

void AccountIAMClient::UpdateCredential(
    int32_t userId, const CredentialParameters& credInfo, const std::shared_ptr<IDMCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("the callback for updating credential is nullptr");
        return;
    }
    Attributes emptyResult;
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        callback->OnResult(ERR_ACCOUNT_COMMON_GET_PROXY, emptyResult);
        return;
    }
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        ACCOUNT_LOGE("fail to update credential for invalid userId");
        callback->OnResult(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, emptyResult);
        return;
    }
    if (credInfo.authType == AuthType::PIN) {
        SetAuthSubType(userId, static_cast<int32_t>(credInfo.pinType.value_or(PinSubType::PIN_MAX)));
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(userId, callback);
    proxy->UpdateCredential(userId, credInfo, wrapper);
}

void AccountIAMClient::DelCred(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
    const std::shared_ptr<IDMCallback>& callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("the callback for deleting credential is nullptr");
        return;
    }
    Attributes emptyResult;
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        callback->OnResult(ERR_ACCOUNT_COMMON_GET_PROXY, emptyResult);
        return;
    }
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        callback->OnResult(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, emptyResult);
        return;
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(userId, callback);
    proxy->DelCred(userId, credentialId, authToken, wrapper);
}

void AccountIAMClient::DelUser(
    int32_t userId, const std::vector<uint8_t> &authToken, const std::shared_ptr<IDMCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("the callback for deleting user is nullptr");
        return;
    }
    Attributes emptyResult;
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        callback->OnResult(ERR_ACCOUNT_COMMON_GET_PROXY, emptyResult);
        return;
    }
    if ((userId == 0) && (!GetCurrentUserId(userId))) {
        callback->OnResult(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, emptyResult);
        return;
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(userId, callback);
    proxy->DelUser(userId, authToken, wrapper);
}

int32_t AccountIAMClient::GetCredentialInfo(
    int32_t userId, AuthType authType, const std::shared_ptr<GetCredInfoCallback> &callback)
{
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    sptr<IGetCredInfoCallback> wrapper = new (std::nothrow) GetCredInfoCallbackService(callback);
    ErrCode result = proxy->GetCredentialInfo(userId, authType, wrapper);
    if ((result != ERR_OK) && (callback != nullptr)) {
        std::vector<CredentialInfo> infoList;
        callback->OnCredentialInfo(result, infoList);
    }
    return result;
}

int32_t AccountIAMClient::Cancel(int32_t userId)
{
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->Cancel(userId);
}

#ifdef HAS_PIN_AUTH_PART
uint64_t AccountIAMClient::StartDomainAuth(int32_t userId, const std::shared_ptr<IDMCallback> &callback)
{
    std::lock_guard<std::mutex> lock(domainMutex_);
    Attributes emptyResult;
    if (domainInputer_ == nullptr) {
        ACCOUNT_LOGE("the registered inputer is not found or invalid");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_INPUTER_NOT_REGISTERED, emptyResult);
        return 0;
    }
    domainInputer_->OnGetData(IAMAuthType::DOMAIN, std::vector<uint8_t>(),
        std::make_shared<DomainCredentialRecipient>(userId, callback));
    return 0;
}
#endif

int32_t AccountIAMClient::PrepareRemoteAuth(
    const std::string &remoteNetworkId, const std::shared_ptr<PreRemoteAuthCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback for PrepareRemoteAuth is nullptr.");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        callback->OnResult(ERR_ACCOUNT_COMMON_GET_PROXY);
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    sptr<IPreRemoteAuthCallback> wrapper = new (std::nothrow) PreRemoteAuthCallbackService(callback);
    return proxy->PrepareRemoteAuth(remoteNetworkId, wrapper);
}

uint64_t AccountIAMClient::Auth(AuthOptions& authOptions, const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel authTrustLevel, const std::shared_ptr<IDMCallback> &callback)
{
    return AuthUser(authOptions, challenge, authType, authTrustLevel, callback);
}

uint64_t AccountIAMClient::AuthUser(
    AuthOptions &authOptions, const std::vector<uint8_t> &challenge, AuthType authType,
    AuthTrustLevel authTrustLevel, const std::shared_ptr<IDMCallback> &callback)
{
    uint64_t contextId = 0;
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return contextId;
    }
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        return contextId;
    }
    if ((authOptions.accountId == 0) && (!GetCurrentUserId(authOptions.accountId))) {
        return contextId;
    }
#ifdef HAS_PIN_AUTH_PART
    if (static_cast<int32_t>(authType) == static_cast<int32_t>(IAMAuthType::DOMAIN)) {
        return StartDomainAuth(authOptions.accountId, callback);
    }
#endif
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(authOptions.accountId, callback);
    AuthParam authParam;
    authParam.challenge = challenge;
    authParam.authType = authType;
    authParam.authTrustLevel = authTrustLevel;
    authParam.userId = authOptions.accountId;
    authParam.authIntent = authOptions.authIntent;
    if (authOptions.hasRemoteAuthOptions) {
        authParam.remoteAuthParam = RemoteAuthParam();
        if (authOptions.remoteAuthOptions.hasVerifierNetworkId) {
            authParam.remoteAuthParam.value().verifierNetworkId = authOptions.remoteAuthOptions.verifierNetworkId;
        }
        if (authOptions.remoteAuthOptions.hasCollectorNetworkId) {
            authParam.remoteAuthParam.value().collectorNetworkId = authOptions.remoteAuthOptions.collectorNetworkId;
        }
        if (authOptions.remoteAuthOptions.hasCollectorTokenId) {
            authParam.remoteAuthParam.value().collectorTokenId = authOptions.remoteAuthOptions.collectorTokenId;
        }
    }
    ErrCode result = proxy->AuthUser(authParam, wrapper, contextId);
    if (result != ERR_OK) {
        Attributes emptyResult;
        callback->OnResult(result, emptyResult);
    }
    return contextId;
}

int32_t AccountIAMClient::CancelAuth(uint64_t contextId)
{
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CancelAuth(contextId);
}

int32_t AccountIAMClient::GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel, int32_t &status)
{
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    if (authTrustLevel < UserIam::UserAuth::ATL1 || authTrustLevel > UserIam::UserAuth::ATL4) {
        ACCOUNT_LOGE("authTrustLevel is not in correct range");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (authType < UserIam::UserAuth::ALL) {
        ACCOUNT_LOGE("authType is not in correct range");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return proxy->GetAvailableStatus(authType, authTrustLevel, status);
}

void AccountIAMClient::GetProperty(
    int32_t userId, const GetPropertyRequest &request, const std::shared_ptr<GetSetPropCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("the callback for getting property is nullptr");
        return;
    }
    Attributes emptyResult;
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        callback->OnResult(ERR_ACCOUNT_COMMON_GET_PROXY, emptyResult);
        return;
    }
    sptr<IGetSetPropCallback> wrapper = new (std::nothrow) GetSetPropCallbackService(callback);
    proxy->GetProperty(userId, request, wrapper);
}

void AccountIAMClient::SetProperty(
    int32_t userId, const SetPropertyRequest &request, const std::shared_ptr<GetSetPropCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("the callback for setting property is nullptr");
        return;
    }
    Attributes emptyResult;
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        callback->OnResult(ERR_ACCOUNT_COMMON_GET_PROXY, emptyResult);
        return;
    }
    sptr<IGetSetPropCallback> wrapper = new (std::nothrow) GetSetPropCallbackService(callback);
    proxy->SetProperty(userId, request, wrapper);
}

void AccountIAMClient::GetEnrolledId(
    int32_t accountId, AuthType authType, const std::shared_ptr<GetEnrolledIdCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("The callback for get enrolled id is nullptr");
        return;
    }
    uint64_t emptyResult = 0;
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        callback->OnEnrolledId(ERR_ACCOUNT_COMMON_GET_PROXY, emptyResult);
        return;
    }
    sptr<IGetEnrolledIdCallback> wrapper = new (std::nothrow) GetEnrolledIdCallbackService(callback);
    if (wrapper == nullptr) {
        callback->OnEnrolledId(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, emptyResult);
        return;
    }
    proxy->GetEnrolledId(accountId, authType, wrapper);
}

bool AccountIAMClient::CheckSelfPermission(const std::string &permissionName)
{
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetSelfTokenID();
    ErrCode result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permissionName);
    return result == Security::AccessToken::TypePermissionState::PERMISSION_GRANTED;
}

#ifdef HAS_PIN_AUTH_PART
ErrCode AccountIAMClient::RegisterPINInputer(const std::shared_ptr<IInputer> &inputer)
{
    std::lock_guard<std::mutex> lock(pinMutex_);
    ErrCode result = AccountPermissionManager::CheckSystemApp(false);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("is not system application, result = %{public}u.", result);
        return result;
    }
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
    return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
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
    ErrCode result = AccountPermissionManager::CheckSystemApp(false);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("is not system application, result = %{public}u.", result);
        return result;
    }
    if ((!CheckSelfPermission(PERMISSION_ACCESS_USER_AUTH_INTERNAL)) &&
        (!CheckSelfPermission(PERMISSION_MANAGE_USER_IDM))) {
        ACCOUNT_LOGE("failed to check permission");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    if (inputer == nullptr) {
        ACCOUNT_LOGE("inputer is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
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
    ErrCode result = AccountPermissionManager::CheckSystemApp(false);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("is not system application, result = %{public}u.", result);
        return result;
    }
    if ((!CheckSelfPermission(PERMISSION_ACCESS_USER_AUTH_INTERNAL)) &&
        (!CheckSelfPermission(PERMISSION_MANAGE_USER_IDM))) {
        ACCOUNT_LOGE("failed to check permission");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    switch (authType) {
        case IAMAuthType::DOMAIN:
            return UnregisterDomainInputer();
        default:
            return ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE;
    }
    return ERR_OK;
}

ErrCode AccountIAMClient::UnregisterPINInputer()
{
    ErrCode result = AccountPermissionManager::CheckSystemApp(false);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("is not system application, result = %{public}u.", result);
        return result;
    }
    if (!CheckSelfPermission(PERMISSION_ACCESS_PIN_AUTH)) {
        ACCOUNT_LOGE("failed to check permission");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    UserIam::PinAuth::PinAuthRegister::GetInstance().UnRegisterInputer();
    std::lock_guard<std::mutex> lock(pinMutex_);
    pinInputer_ = nullptr;
    return ERR_OK;
}

ErrCode AccountIAMClient::UnregisterDomainInputer()
{
    std::lock_guard<std::mutex> lock(domainMutex_);
    domainInputer_ = nullptr;
    return ERR_OK;
}
#endif

IAMState AccountIAMClient::GetAccountState(int32_t userId)
{
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        return IDLE;
    }
    return proxy->GetAccountState(userId);
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

sptr<IAccountIAM> AccountIAMClient::GetAccountIAMProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }
    sptr<IRemoteObject> object = OhosAccountKitsImpl::GetInstance().GetAccountIAMService();
    if (object == nullptr) {
        ACCOUNT_LOGE("failed to get account iam service");
        return nullptr;
    }
    deathRecipient_ = new (std::nothrow) AccountIAMDeathRecipient();
    if (deathRecipient_ == nullptr) {
        ACCOUNT_LOGE("failed to create account iam death recipient");
        return nullptr;
    }
    if (!object->AddDeathRecipient(deathRecipient_)) {
        ACCOUNT_LOGE("failed to add account iam death recipient");
        deathRecipient_ = nullptr;
        return nullptr;
    }
    proxy_ = iface_cast<IAccountIAM>(object);
    if (proxy_ == nullptr) {
        ACCOUNT_LOGE("failed to get account iam proxy");
    }
    return proxy_;
}
}  // namespace AccountSA
}  // namespace OHOS

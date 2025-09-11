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
#ifdef SUPPORT_DOMAIN_ACCOUNTS
#include "domain_account_client.h"
#endif // SUPPORT_DOMAIN_ACCOUNTS
#endif // HAS_PIN_AUTH_PART

namespace OHOS {
namespace AccountSA {
namespace {
const char PERMISSION_ACCESS_PIN_AUTH[] = "ohos.permission.ACCESS_PIN_AUTH";
const char PERMISSION_MANAGE_USER_IDM[] = "ohos.permission.MANAGE_USER_IDM";
const char PERMISSION_ACCESS_USER_AUTH_INTERNAL[] = "ohos.permission.ACCESS_USER_AUTH_INTERNAL";
const int32_t UINT8_SHIFT_LENGTH = 8;
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
    challenge.clear();
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
    if ((userId == -1) && (!GetCurrentUserId(userId))) {
        ACCOUNT_LOGE("fail to add credential for invalid userId");
        callback->OnResult(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, emptyResult);
        return;
    }
    if (credInfo.authType == AuthType::PIN) {
        SetAuthSubType(userId, static_cast<int32_t>(credInfo.pinType.value_or(PinSubType::PIN_MAX)));
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(userId, callback);
    if (wrapper == nullptr) {
        ACCOUNT_LOGE("The wrapper for adding credential is nullptr");
        callback->OnResult(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, emptyResult);
        return;
    }
    CredentialParametersIam credentialParametersIam;
    credentialParametersIam.credentialParameters = credInfo;
    auto ret = proxy->AddCredential(userId, credentialParametersIam, wrapper);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to add credential, error code: %{public}d", ret);
        wrapper->OnResult(ret, emptyResult.Serialize());
    }
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
    if ((userId == -1) && (!GetCurrentUserId(userId))) {
        ACCOUNT_LOGE("fail to update credential for invalid userId");
        callback->OnResult(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, emptyResult);
        return;
    }
    if (credInfo.authType == AuthType::PIN) {
        SetAuthSubType(userId, static_cast<int32_t>(credInfo.pinType.value_or(PinSubType::PIN_MAX)));
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(userId, callback);
    if (wrapper == nullptr) {
        ACCOUNT_LOGE("The wrapper for updating credential is nullptr");
        callback->OnResult(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, emptyResult);
        return;
    }
    CredentialParametersIam credentialParametersIam;
    credentialParametersIam.credentialParameters = credInfo;
    auto ret = proxy->UpdateCredential(userId, credentialParametersIam, wrapper);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to update credential, error code: %{public}d", ret);
        wrapper->OnResult(ret, emptyResult.Serialize());
    }
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
    if ((userId == -1) && (!GetCurrentUserId(userId))) {
        callback->OnResult(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, emptyResult);
        return;
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(userId, callback);
    if (wrapper == nullptr) {
        ACCOUNT_LOGE("The wrapper for deleting credential is nullptr");
        callback->OnResult(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, emptyResult);
        return;
    }
    auto ret = proxy->DelCred(userId, credentialId, authToken, wrapper);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to delete credential, error code: %{public}d", ret);
        wrapper->OnResult(ret, emptyResult.Serialize());
    }
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
    if ((userId == -1) && (!GetCurrentUserId(userId))) {
        callback->OnResult(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, emptyResult);
        return;
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(userId, callback);
    if (wrapper == nullptr) {
        ACCOUNT_LOGE("The wrapper for deleting user is nullptr");
        callback->OnResult(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, emptyResult);
        return;
    }
    auto ret = proxy->DelUser(userId, authToken, wrapper);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to delete user, error code: %{public}d", ret);
        wrapper->OnResult(ret, emptyResult.Serialize());
    }
}

int32_t AccountIAMClient::GetCredentialInfo(
    int32_t userId, AuthType authType, const std::shared_ptr<GetCredInfoCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("The callback for get credential info is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    std::vector<CredentialInfo> infoList;
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        callback->OnCredentialInfo(ERR_ACCOUNT_COMMON_GET_PROXY, infoList);
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    sptr<IGetCredInfoCallback> wrapper = new (std::nothrow) GetCredInfoCallbackService(callback);
    if (wrapper == nullptr) {
        ACCOUNT_LOGE("The wrapper is nullptr");
        callback->OnCredentialInfo(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, infoList);
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    ErrCode result = proxy->GetCredentialInfo(userId, static_cast<int32_t>(authType), wrapper);
    if (result != ERR_OK) {
        auto infoListIam = ConvertToCredentialInfoIamList(infoList);
        wrapper->OnCredentialInfo(result, infoListIam);
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
#ifdef SUPPORT_DOMAIN_ACCOUNTS
uint64_t AccountIAMClient::StartDomainAuth(int32_t userId, const std::shared_ptr<IDMCallback> &callback)
{
    std::lock_guard<std::mutex> lock(domainMutex_);
    Attributes emptyResult;
    if (domainInputer_ == nullptr) {
        ACCOUNT_LOGE("the registered inputer is not found or invalid");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_INPUTER_NOT_REGISTERED, emptyResult);
        return 0;
    }
    uint64_t contextId = 0;
    auto idmCallback = std::make_shared<DomainAuthCallbackAdapter>(callback);

    auto getPwdHooks = [domainInputer = domainInputer_] {
        auto recipient = std::make_shared<DomainCredentialRecipient>();
        domainInputer->OnGetData(IAMAuthType::DOMAIN, std::vector<uint8_t>(), recipient);
        return recipient->WaitToGetData();
    };
    ErrCode errCode = DomainAccountClient::GetInstance().AuthUser(userId, getPwdHooks, idmCallback, contextId);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to begin authenticate user, errCode = %{public}d", errCode);
        callback->OnResult(errCode, emptyResult);
        return 0;
    }
    return contextId;
}
#endif
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
    if (wrapper == nullptr) {
        ACCOUNT_LOGE("The wrapper for prepare remote auth is nullptr");
        callback->OnResult(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR);
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    auto ret = proxy->PrepareRemoteAuth(remoteNetworkId, wrapper);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to prepare remote auth, error code: %{public}d", ret);
        wrapper->OnResult(ret);
    }
    return ret;
}

static std::vector<uint8_t> GenerateContextArray(const uint64_t contextId, const uint8_t authTypeIdx)
{
    std::vector<uint8_t> contextArray(sizeof(uint64_t), 0);
    uint64_t contextIdCopy =  contextId;
    size_t vecSize = contextArray.size();
    for (int i = vecSize - 1; i >= 0; i--) {
        contextArray[i] = contextIdCopy & 0xFF;
        contextIdCopy >>= UINT8_SHIFT_LENGTH;
    }
    contextArray.insert(contextArray.begin(), authTypeIdx);
    return contextArray;
}

static bool ParseContextId(const std::vector<uint8_t> &contextIdArray, uint64_t &contextId, uint8_t &authTypeIdx)
{
    size_t vecSize = contextIdArray.size();
    if ((vecSize != sizeof(uint64_t)) && (vecSize != sizeof(uint64_t) + sizeof(uint8_t))) {
        ACCOUNT_LOGE("Invalid contextId vector size: %{public}zu, expected between: %{public}zu and %{public}zu",
            vecSize, sizeof(uint64_t), sizeof(uint64_t) + sizeof(uint8_t));
        return false;
    }
    int32_t offset = 0;
    if (vecSize == sizeof(uint64_t)) {
        // if size is 8, is iam in default
        authTypeIdx = static_cast<uint8_t>(AuthTypeIndex::ALL);
    } else {
        authTypeIdx = contextIdArray[0];
        offset = 1;
    }
    for (auto each = contextIdArray.begin() + offset; each != contextIdArray.end(); each++) {
        contextId = (contextId << UINT8_SHIFT_LENGTH) | (*each);
    }
    return true;
}

std::vector<uint8_t> AccountIAMClient::Auth(AuthOptions& authOptions, const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel authTrustLevel, const std::shared_ptr<IDMCallback> &callback)
{
    return AuthUser(authOptions, challenge, authType, authTrustLevel, callback);
}

static void CopyAuthOptionsToAuthParam(const AuthOptions &authOptions, AuthParam &authParam)
{
    authParam.userId = authOptions.accountId;
    authParam.authIntent = authOptions.authIntent;
    if (!authOptions.hasRemoteAuthOptions) {
        return;
    }
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

std::vector<uint8_t> AccountIAMClient::AuthUser(
    AuthOptions &authOptions, const std::vector<uint8_t> &challenge, AuthType authType,
    AuthTrustLevel authTrustLevel, const std::shared_ptr<IDMCallback> &callback)
{
    uint64_t contextId = 0;
    std::vector<uint8_t> errorContextId(sizeof(uint64_t), 0);
    auto authTypeIdx = GetAuthTypeIndex(authType);
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return errorContextId;
    }
    Attributes emptyResult;
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        callback->OnResult(ERR_ACCOUNT_COMMON_GET_PROXY, emptyResult);
        return errorContextId;
    }
    if ((!authOptions.hasRemoteAuthOptions) && (authOptions.accountId == -1) &&
        (!GetCurrentUserId(authOptions.accountId))) {
        callback->OnResult(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, emptyResult);
        return errorContextId;
    }
#ifdef HAS_PIN_AUTH_PART
    if (static_cast<int32_t>(authType) == static_cast<int32_t>(IAMAuthType::DOMAIN)) {
#ifdef SUPPORT_DOMAIN_ACCOUNTS
        contextId = StartDomainAuth(authOptions.accountId, callback);
        return GenerateContextArray(contextId, authTypeIdx);
#else
        callback->OnResult(ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE, emptyResult);
        return errorContextId;
#endif // SUPPORT_DOMAIN_ACCOUNTS
    }
#endif
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(authOptions.accountId, callback);
    if (wrapper == nullptr) {
        ACCOUNT_LOGE("The wrapper is nullptr");
        callback->OnResult(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, emptyResult);
        return errorContextId;
    }
    AuthParam authParam;
    authParam.challenge = challenge;
    authParam.authType = authType;
    authParam.authTrustLevel = authTrustLevel;
    CopyAuthOptionsToAuthParam(authOptions, authParam);
    ErrCode result = proxy->AuthUser(authParam, wrapper, contextId);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to auth user, result = %{public}d", result);
        wrapper->OnResult(result, emptyResult.Serialize());
        return errorContextId;
    }
    return GenerateContextArray(contextId, authTypeIdx);
}

int32_t AccountIAMClient::CancelAuth(const std::vector<uint8_t> &contextIdByteArray)
{
    uint8_t authTypeIdx = 0;
    uint64_t contextId = 0;
    if (!ParseContextId(contextIdByteArray, contextId, authTypeIdx)) {
        ACCOUNT_LOGE("Failed to parse contextId");
        return ERR_IAM_INVALID_CONTEXT_ID;
    }

    if (authTypeIdx == static_cast<uint8_t>(AuthTypeIndex::DOMAIN)) {
#ifdef SUPPORT_DOMAIN_ACCOUNTS
        return DomainAccountClient::GetInstance().CancelAuth(contextId);
#else
        return ERR_IAM_INVALID_CONTEXT_ID;
#endif
    }
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CancelAuth(contextId);
}

uint8_t AccountIAMClient::GetAuthTypeIndex(AuthType authType)
{
    switch (static_cast<int32_t>(authType)) {
        case AuthType::ALL:
            return static_cast<uint8_t>(AuthTypeIndex::ALL);
        case AuthType::PIN:
            return static_cast<uint8_t>(AuthTypeIndex::PIN);
        case AuthType::FACE:
            return static_cast<uint8_t>(AuthTypeIndex::FACE);
        case AuthType::FINGERPRINT:
            return static_cast<uint8_t>(AuthTypeIndex::FINGERPRINT);
        case AuthType::RECOVERY_KEY:
            return static_cast<uint8_t>(AuthTypeIndex::RECOVERY_KEY);
        case AuthType::PRIVATE_PIN:
            return static_cast<uint8_t>(AuthTypeIndex::PRIVATE_PIN);
        case AuthType::TUI_PIN:
            return static_cast<uint8_t>(AuthTypeIndex::TUI_PIN);
        case IAMAuthType::DOMAIN:
            return static_cast<uint8_t>(AuthTypeIndex::DOMAIN);
        default:
            return static_cast<uint8_t>(AuthTypeIndex::INVALID);
    }
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
    return proxy->GetAvailableStatus(static_cast<int32_t>(authType), static_cast<uint32_t>(authTrustLevel), status);
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
    if (wrapper == nullptr) {
        ACCOUNT_LOGE("The wrapper for getting property is nullptr");
        callback->OnResult(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, emptyResult);
        return;
    }
    GetPropertyRequestIam getPropertyRequestIam;
    getPropertyRequestIam.getPropertyRequest = request;
    auto ret = proxy->GetProperty(userId, getPropertyRequestIam, wrapper);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to get property, error code: %{public}d", ret);
        wrapper->OnResult(ret, emptyResult.Serialize());
    }
}

void AccountIAMClient::GetPropertyByCredentialId(uint64_t credentialId,
    std::vector<Attributes::AttributeKey> &keys, const std::shared_ptr<GetSetPropCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("The callback for getting property is nullptr");
        return;
    }
    Attributes emptyResult;
    auto proxy = GetAccountIAMProxy();
    if (proxy == nullptr) {
        callback->OnResult(ERR_ACCOUNT_COMMON_GET_PROXY, emptyResult);
        return;
    }
    sptr<IGetSetPropCallback> wrapper = new (std::nothrow) GetSetPropCallbackService(callback);
    if (wrapper == nullptr) {
        ACCOUNT_LOGE("The wrapper for getting property by credentialId is nullptr");
        callback->OnResult(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, emptyResult);
        return;
    }
    std::vector<int32_t> keysInt;
    for (auto &key : keys) {
        keysInt.push_back(static_cast<int32_t>(key));
    }
    auto ret = proxy->GetPropertyByCredentialId(credentialId, keysInt, wrapper);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to get property by credentialId, error code: %{public}d", ret);
        wrapper->OnResult(ret, emptyResult.Serialize());
    }
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
    if (wrapper == nullptr) {
        ACCOUNT_LOGE("The wrapper for setting property is nullptr");
        callback->OnResult(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, emptyResult);
        return;
    }
    Attributes extraInfo(request.attrs.Serialize());
    SetPropertyRequestIam setPropertyRequestIam;
    setPropertyRequestIam.setPropertyRequest.authType = request.authType;
    setPropertyRequestIam.setPropertyRequest.mode = request.mode;
    setPropertyRequestIam.setPropertyRequest.attrs = std::move(extraInfo);
    auto ret = proxy->SetProperty(userId, setPropertyRequestIam, wrapper);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to set property, error code: %{public}d", ret);
        wrapper->OnResult(ret, emptyResult.Serialize());
    }
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
        ACCOUNT_LOGE("The wrapper is nullptr");
        callback->OnEnrolledId(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, emptyResult);
        return;
    }
    auto ret = proxy->GetEnrolledId(accountId, static_cast<int32_t>(authType), wrapper);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to get enrolled id, error code: %{public}d", ret);
        wrapper->OnEnrolledId(ret, emptyResult);
    }
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
    int32_t userId = -1;
    if (!GetCurrentUserId(userId)) {
        return ERR_ACCOUNT_IAM_KIT_GET_USERID_FAIL;
    }
    auto iamInputer = std::make_shared<IAMInputer>(userId, inputer);
    if (UserIam::PinAuth::PinAuthRegister::GetInstance().RegisterInputer(iamInputer)) {
        pinInputer_ = inputer;
        ACCOUNT_LOGI("Register inputer successful!");
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
            ACCOUNT_LOGE("Unsupport auth type = %{public}d", authType);
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
            ACCOUNT_LOGE("Unsupport auth type = %{public}d", authType);
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
    ACCOUNT_LOGI("Unregister PIN inputer successful!");
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
    int32_t state = static_cast<int32_t>(IDLE);
    proxy->GetAccountState(userId, state);
    return static_cast<IAMState>(state);
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
    int32_t currentLocalId = getuid() / UID_TRANSFORM_DIVISOR;
    if (currentLocalId == 0) {
        int32_t foregroundLocalId = -1;
        ErrCode ret = OsAccountManager::GetForegroundOsAccountLocalId(foregroundLocalId);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("Fail to get foreground os account local id, errCode = %{public}d", ret);
            return false;
        }
        userId = foregroundLocalId;
        return true;
    }
    userId = currentLocalId;
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

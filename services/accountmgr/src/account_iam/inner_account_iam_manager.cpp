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

#include <thread>
#include "account_constants.h"
#include "account_iam_callback.h"
#include "account_log_wrapper.h"
#include "domain_account_callback_service.h"
#include "account_hisysevent_adapter.h"
#include "iinner_os_account_manager.h"
#ifdef SUPPORT_DOMAIN_ACCOUNTS
#include "inner_domain_account_manager.h"
#endif // SUPPORT_DOMAIN_ACCOUNTS
#include "iservice_registry.h"
#ifdef HAS_STORAGE_PART
#include "storage_service_errno.h"
#endif
#include "system_ability_definition.h"
#include "user_access_ctrl_client.h"
#include "user_auth_client.h"
#include "user_auth_client_impl.h"
#include "user_idm_client.h"
#include "access_token.h"
#include "ipc_skeleton.h"
#include "token_setproc.h"
#include "os_account_constants.h"
#include "account_file_operator.h"

namespace OHOS {
namespace AccountSA {
namespace {
constexpr int32_t DELAY_FOR_EXCEPTION = 100;
constexpr int32_t MAX_RETRY_TIMES = 20;
constexpr int32_t TIME_WAIT_TIME_OUT = 5;
constexpr uint64_t TOKEN_ALLOWABLE_DURATION = 60 * 1000; // 60s -> 60 * 1000ms

#ifdef _ARM64_
static const std::string RECOVERY_LIB_PATH = "/system/lib64/";
#else
static const std::string RECOVERY_LIB_PATH = "/system/lib/";
#endif
static const std::string RECOVERY_SO_PATH = RECOVERY_LIB_PATH + "librecovery_key_service_client.z.so";
static const char RECOVERY_METHOD_NAME[] = "UpdateUseAuthWithRecoveryKey";
}
using UserIDMClient = UserIam::UserAuth::UserIdmClient;
using UserAuthClient = UserIam::UserAuth::UserAuthClient;
using UserAuthClientImpl = UserIam::UserAuth::UserAuthClientImpl;
using UserAccessCtrlClient = UserIam::UserAuth::UserAccessCtrlClient;

typedef int32_t (*UpdateUserAuthWithRecoveryKeyFunc)(const std::vector<uint8_t> &authToken,
    const std::vector<uint8_t> &newSecret, uint64_t secureUid, uint32_t userId);

InnerAccountIAMManager::InnerAccountIAMManager()
{
    userStateMap_[0] = IDLE;
}

InnerAccountIAMManager &InnerAccountIAMManager::GetInstance()
{
    static InnerAccountIAMManager *instance = new (std::nothrow) InnerAccountIAMManager();
    return *instance;
}

std::shared_ptr<std::mutex> InnerAccountIAMManager::GetOperatingUserLock(int32_t id)
{
    std::lock_guard<std::mutex> lock(operatingMutex_);
    auto it = userLocks_.find(id);
    if (it == userLocks_.end()) {
        auto mutexPtr = std::make_shared<std::mutex>();
        userLocks_.insert(std::make_pair(id, mutexPtr));
        return mutexPtr;
    }
    return it->second;
}

void InnerAccountIAMManager::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    ACCOUNT_LOGI("Start to open session, userId:%{public}d", userId);
    challenge = UserIDMClient::GetInstance().OpenSession(userId);
    if (challenge.empty()) {
        ACCOUNT_LOGE("Failed to open session, userId:%{public}d", userId);
        REPORT_OS_ACCOUNT_FAIL(userId, "openSession", -1, "Failed to open session");
    }
    std::lock_guard<std::mutex> lock(mutex_);
    userStateMap_[userId] = AFTER_OPEN_SESSION;
}

void InnerAccountIAMManager::CloseSession(int32_t userId)
{
    ACCOUNT_LOGI("Start to close session, userId:%{public}d", userId);
    UserIDMClient::GetInstance().CloseSession(userId);
    std::lock_guard<std::mutex> lock(mutex_);
    if (userId == 0) {
        userStateMap_[0] = IDLE;
    } else {
        userStateMap_.erase(userId);
    }
}

void InnerAccountIAMManager::AddCredential(
    int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }

    std::lock_guard<std::mutex> userLock(*GetOperatingUserLock(userId));
    sptr<IDMCallbackDeathRecipient> deathRecipient = new (std::nothrow) IDMCallbackDeathRecipient(userId);
    if ((deathRecipient == nullptr) || (callback->AsObject() == nullptr) ||
        (!callback->AsObject()->AddDeathRecipient(deathRecipient))) {
        ACCOUNT_LOGE("Failed to add death recipient for AddCred");
        return;
    }
    if (credInfo.authType == AuthType::PIN) {
        std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(userId) +
            Constants::PATH_SEPARATOR + Constants::USER_ADD_SECRET_FLAG_FILE_NAME;
        auto accountFileOperator = std::make_shared<AccountFileOperator>();
        ErrCode code = accountFileOperator->InputFileByPathAndContent(path, "");
        if (code != ERR_OK) {
            ReportOsAccountOperationFail(userId, "addCredential", code, "Failed to write add_secret_flag file");
            ACCOUNT_LOGE("Input file fail, path=%{public}s", path.c_str());
        }
    }
    auto idmCallbackWrapper = std::make_shared<AddCredCallback>(userId, credInfo, callback);
    idmCallbackWrapper->SetDeathRecipient(deathRecipient);
    ACCOUNT_LOGI("Start to add credential, userId:%{public}d, authType:%{public}d", userId, credInfo.authType);
    UserIDMClient::GetInstance().AddCredential(userId, credInfo, idmCallbackWrapper);
    std::unique_lock<std::mutex> lock(idmCallbackWrapper->mutex_);
    idmCallbackWrapper->onResultCondition_.wait(lock, [idmCallbackWrapper] {
        return idmCallbackWrapper->isCalled_;
    });
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

    std::lock_guard<std::mutex> userLock(*GetOperatingUserLock(userId));
    sptr<IDMCallbackDeathRecipient> deathRecipient = new (std::nothrow) IDMCallbackDeathRecipient(userId);
    sptr<IRemoteObject> object = callback->AsObject();
    if ((deathRecipient == nullptr) || object == nullptr ||
        ((object->IsProxyObject()) && (!object->AddDeathRecipient(deathRecipient)))) {
        ACCOUNT_LOGE("Failed to add death recipient for UpdateCred");
        return;
    }

    auto idmCallbackWrapper = std::make_shared<UpdateCredCallback>(userId, credInfo, callback);
    idmCallbackWrapper->SetDeathRecipient(deathRecipient);
    ACCOUNT_LOGI("Start to update credential, userId:%{public}d, authType:%{public}d", userId, credInfo.authType);
    UserIDMClient::GetInstance().UpdateCredential(userId, credInfo, idmCallbackWrapper);
    std::unique_lock<std::mutex> lock(idmCallbackWrapper->mutex_);
    idmCallbackWrapper->onResultCondition_.wait(lock, [idmCallbackWrapper] {
        return idmCallbackWrapper->isCalled_;
    });
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
    ACCOUNT_LOGI("Start to delete credential, userId:%{public}d", userId);
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
        callback->OnResult(ResultCode::FAIL, errResult);
        return;
    }
    std::lock_guard<std::mutex> userLock(*GetOperatingUserLock(userId));
    Security::AccessToken::AccessTokenID callerTokenId = IPCSkeleton::GetCallingTokenID();
    auto verifyTokenCallback = std::make_shared<VerifyTokenCallbackWrapper>(userId, authToken, callerTokenId, callback);
    ACCOUNT_LOGI("Start to verify token before delete user's credential, userId:%{public}d", userId);
    UserAccessCtrlClient::GetInstance().VerifyAuthToken(authToken, TOKEN_ALLOWABLE_DURATION, verifyTokenCallback);
    std::unique_lock<std::mutex> lock(verifyTokenCallback->mutex_);
    verifyTokenCallback->onResultCondition_.wait(lock, [verifyTokenCallback] {
        return verifyTokenCallback->isCalled_;
    });
}

void InnerAccountIAMManager::GetCredentialInfo(
    int32_t userId, AuthType authType, const sptr<IGetCredInfoCallback> &callback)
{
    if (static_cast<int32_t>(authType) == static_cast<int32_t>(IAMAuthType::DOMAIN)) {
        std::vector<CredentialInfo> infoList;
        if (CheckDomainAuthAvailable(userId)) {
            ACCOUNT_LOGI("Domain auth is support");
            CredentialInfo info;
            info.authType = static_cast<AuthType>(IAMAuthType::DOMAIN);
            info.pinType = static_cast<PinSubType>(IAMAuthSubType::DOMAIN_MIXED);
            infoList.emplace_back(info);
        }
        return callback->OnCredentialInfo(ERR_OK, infoList);
    }
    auto getCallback = std::make_shared<GetCredInfoCallbackWrapper>(userId, static_cast<int32_t>(authType), callback);
    ACCOUNT_LOGI("Start to get credential info, userId=%{public}d, authType=%{public}d", userId, authType);
    UserIDMClient::GetInstance().GetCredentialInfo(userId, authType, getCallback);
}

int32_t InnerAccountIAMManager::Cancel(int32_t userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = userStateMap_.find(userId);
    if ((it == userStateMap_.end()) || (it->second >= AFTER_ADD_CRED)) {
        ACCOUNT_LOGE("Failed to cancel after 'addCredential' success");
        return ResultCode::GENERAL_ERROR;
    }
    ACCOUNT_LOGI("Start to cancel, userId=%{public}d", userId);
    return UserIDMClient::GetInstance().Cancel(userId);
}

int32_t InnerAccountIAMManager::PrepareRemoteAuth(
    const std::string &remoteNetworkId, const sptr<IPreRemoteAuthCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    ACCOUNT_LOGI("Start to prepare remote auth.");
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
    OsAccountInfo osAccountInfo;
    if ((authParam.remoteAuthParam == std::nullopt) &&
        (IInnerOsAccountManager::GetInstance().GetRealOsAccountInfoById(authParam.userId,
            osAccountInfo)) != ERR_OK) {
        ACCOUNT_LOGE("Account does not exist");
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    bool isDeactivating = false;
    IInnerOsAccountManager::GetInstance().IsOsAccountDeactivating(authParam.userId, isDeactivating);
    if (isDeactivating) {
        ACCOUNT_LOGE("The target account is deactivating, accountId:%{public}d", authParam.userId);
        return ERR_IAM_BUSY;
    }
    sptr<AuthCallbackDeathRecipient> deathRecipient = new (std::nothrow) AuthCallbackDeathRecipient();
    if ((deathRecipient == nullptr) || (!callback->AsObject()->AddDeathRecipient(deathRecipient))) {
        ACCOUNT_LOGE("failed to add death recipient for auth callback");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }

    auto callbackWrapper = std::make_shared<AuthCallback>(authParam.userId,
        authParam.authType, authParam.authIntent, (authParam.remoteAuthParam != std::nullopt), callback);
    callbackWrapper->SetDeathRecipient(deathRecipient);

    UserIam::UserAuth::AuthParam iamAuthParam;
    CopyAuthParam(authParam, iamAuthParam);
    ACCOUNT_LOGI("Start to auth user.");
    contextId = UserAuthClient::GetInstance().BeginAuthentication(iamAuthParam, callbackWrapper);
    deathRecipient->SetContextId(contextId);
    return ERR_OK;
}

int32_t InnerAccountIAMManager::CancelAuth(uint64_t contextId)
{
    ACCOUNT_LOGI("Start to cancel auth");
    return UserAuthClient::GetInstance().CancelAuthentication(contextId);
}

int32_t InnerAccountIAMManager::GetAvailableStatus(
    AuthType authType, AuthTrustLevel authTrustLevel, int32_t &status)
{
    if (static_cast<int32_t>(authType) != static_cast<int32_t>(IAMAuthType::DOMAIN)) {
        status = UserAuthClientImpl::Instance().GetAvailableStatus(authType, authTrustLevel);
        ACCOUNT_LOGI("Get available status ret:%{public}d, authType:%{public}d, authTrustLevel:%{public}d",
            status, authType, authTrustLevel);
        return ERR_OK;
    }
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    bool isPluginAvailable = InnerDomainAccountManager::GetInstance().IsPluginAvailable();
    if (isPluginAvailable) {
        status = ERR_JS_SUCCESS;
    } else {
        ACCOUNT_LOGI("Domain auth is not support");
        status = ERR_JS_AUTH_TYPE_NOT_SUPPORTED;
    }
#else
    ACCOUNT_LOGI("Domain auth is not support");
    status = ERR_JS_AUTH_TYPE_NOT_SUPPORTED;
#endif // SUPPORT_DOMAIN_ACCOUNTS
    return ERR_OK;
}

#ifdef SUPPORT_DOMAIN_ACCOUNTS
ErrCode InnerAccountIAMManager::GetDomainAuthStatusInfo(
    int32_t userId, const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
{
    OsAccountInfo osAccountInfo;
    ErrCode result = IInnerOsAccountManager::GetInstance().GetRealOsAccountInfoById(userId, osAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info");
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
#endif // SUPPORT_DOMAIN_ACCOUNTS

bool InnerAccountIAMManager::CheckDomainAuthAvailable(int32_t userId)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    OsAccountInfo osAccountInfo;
    if (IInnerOsAccountManager::GetInstance().GetRealOsAccountInfoById(userId, osAccountInfo) != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info");
        return false;
    }
    DomainAccountInfo domainAccountInfo;
    osAccountInfo.GetDomainInfo(domainAccountInfo);
    bool isAvailable = InnerDomainAccountManager::GetInstance().IsPluginAvailable();
    return !domainAccountInfo.accountName_.empty() && isAvailable;
#else
    return false;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

void InnerAccountIAMManager::GetProperty(
    int32_t userId, const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    if (static_cast<int32_t>(request.authType) != static_cast<int32_t>(IAMAuthType::DOMAIN)) {
        auto getCallback = std::make_shared<GetPropCallbackWrapper>(userId, callback);
        ACCOUNT_LOGI("Start to get property by authType:%{public}d.", request.authType);
        UserAuthClient::GetInstance().GetProperty(userId, request, getCallback);
        return;
    }
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    ErrCode result = GetDomainAuthStatusInfo(userId, request, callback);
    if (result != ERR_OK) {
        Attributes attributes;
        callback->OnResult(result, attributes);
    }
#else
    Attributes attributes;
    callback->OnResult(ResultCode::NOT_ENROLLED, attributes);
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

void InnerAccountIAMManager::GetPropertyByCredentialId(uint64_t credentialId,
    std::vector<Attributes::AttributeKey> &keys, const sptr<IGetSetPropCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr");
        return;
    }
    auto getPropCallback = std::make_shared<GetPropCallbackWrapper>(-1, callback);
    ACCOUNT_LOGI("Start to get property by credentialId.");
    UserAuthClient::GetInstance().GetPropertyById(credentialId, keys, getPropCallback);
    return;
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
    ACCOUNT_LOGI("Start to set property, userId:%{public}d, authType:%{public}d.", userId, request.authType);
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
    auto GetSecUserInfoCallback = std::make_shared<GetSecUserInfoCallbackWrapper>(accountId, authType, callback);
    ACCOUNT_LOGI("Start to get sec user info, userId:%{public}d, authType:%{public}d", accountId, authType);
    UserIDMClient::GetInstance().GetSecUserInfo(accountId, GetSecUserInfoCallback);
}

void InnerAccountIAMManager::HandleFileKeyException(int32_t userId, const std::vector<uint8_t> &secret,
    const std::vector<uint8_t> &token)
{
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(userId) +
        Constants::PATH_SEPARATOR + Constants::USER_ADD_SECRET_FLAG_FILE_NAME;
    auto accountFileOperator = std::make_shared<AccountFileOperator>();
    bool isExistFile = accountFileOperator->IsExistFile(path);
    ACCOUNT_LOGI("The add_secret_flag file existence status:%{public}d, localId:%{public}d", isExistFile, userId);
    if (!isExistFile) {
        return;
    }
    auto callback = std::make_shared<GetSecureUidCallback>(userId);
    ACCOUNT_LOGI("Start to get sec user info, userId=%{public}d", userId);
    ErrCode code = UserIDMClient::GetInstance().GetSecUserInfo(userId, callback);
    if (code != ERR_OK) {
        ACCOUNT_LOGE("Failed to get secure uid, userId: %{public}d", userId);
        ReportOsAccountOperationFail(userId, "addCredential", code,
            "Failed to get secure uid when restoring key context");
        return;
    }
    std::unique_lock<std::mutex> lck(callback->secureMtx_);
    auto status = callback->secureCv_.wait_for(lck, std::chrono::seconds(TIME_WAIT_TIME_OUT), [callback] {
        return callback->isCalled_;
    });
    if (!status) {
        ACCOUNT_LOGE("GetSecureUidCallback time out");
        ReportOsAccountOperationFail(userId, "addCredential", -1, "Get secure uid timeout when restoring key context");
        return;
    }
    code = UpdateStorageUserAuth(userId, callback->secureUid_, token, {}, secret);
    if (code != ERR_OK) {
        ACCOUNT_LOGE("Restore user auth fail, userId: %{public}d", userId);
        ReportOsAccountOperationFail(userId, "addCredential", code, "Failed to restore user auth");
        return;
    }
    code = UpdateStorageKeyContext(userId);
    if (code != ERR_OK) {
        ACCOUNT_LOGE("Restore key context fail, userId:%{public}d", userId);
        ReportOsAccountOperationFail(userId, "addCredential", code, "Failed to restore key context");
        return;
    }
    ACCOUNT_LOGI("Restore key context successfully, userId:%{public}d", userId);
    code = accountFileOperator->DeleteDirOrFile(path);
    if (code != ERR_OK) {
        ReportOsAccountOperationFail(userId, "addCredential", code,
            "Failed to delete add_secret_flag file after restoring key context");
        ACCOUNT_LOGE("Delete file fail, path=%{public}s", path.c_str());
    }
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

ErrCode InnerAccountIAMManager::UpdateStorageKeyContext(const int32_t userId)
{
    int times = 0;
    ErrCode errCode = ERR_OK;
    while (times < MAX_RETRY_TIMES) {
        errCode = InnerUpdateStorageKeyContext(userId);
        if ((errCode != Constants::E_IPC_ERROR) && (errCode != Constants::E_IPC_SA_DIED)) {
            return errCode;
        }
        ACCOUNT_LOGE("errCode=%{public}d, userId=%{public}d, times=%{public}d", errCode, userId, times);
        times++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    return errCode;
}

ErrCode InnerAccountIAMManager::InnerUpdateStorageKeyContext(const int32_t userId)
{
    ACCOUNT_LOGI("Enter, userId=%{public}d", userId);
#ifdef HAS_STORAGE_PART
    auto storageMgrProxy = GetStorageManagerProxy();
    if (storageMgrProxy == nullptr) {
        ACCOUNT_LOGE("Fail to get storage proxy");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY;
    }
    ErrCode code = storageMgrProxy->UpdateKeyContext(userId);
    if (code != ERR_OK) {
        ACCOUNT_LOGE("Fail to update key context, userId=%{public}d, code=%{public}d", userId, code);
        return code;
    }
#endif
    return ERR_OK;
}

ErrCode InnerAccountIAMManager::UpdateStorageUserAuth(int32_t userId, uint64_t secureUid,
    const std::vector<uint8_t> &token, const std::vector<uint8_t> &oldSecret, const std::vector<uint8_t> &newSecret)
{
    int times = 0;
    ErrCode errCode = ERR_OK;
    while (times < MAX_RETRY_TIMES) {
        errCode = InnerUpdateStorageUserAuth(userId, secureUid, token, oldSecret, newSecret);
        if ((errCode != Constants::E_IPC_ERROR) && (errCode != Constants::E_IPC_SA_DIED)) {
            return errCode;
        }
        ACCOUNT_LOGE("errCode=%{public}d, userId=%{public}d, times=%{public}d", errCode, userId, times);
        times++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    return errCode;
}

ErrCode InnerAccountIAMManager::InnerUpdateStorageUserAuth(int32_t userId, uint64_t secureUid,
    const std::vector<uint8_t> &token, const std::vector<uint8_t> &oldSecret, const std::vector<uint8_t> &newSecret)
{
    ACCOUNT_LOGI("Enter, userId=%{public}d", userId);
#ifdef HAS_STORAGE_PART
    auto storageMgrProxy = GetStorageManagerProxy();
    if (storageMgrProxy == nullptr) {
        ACCOUNT_LOGE("Fail to get storage proxy");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY;
    }

    ErrCode code = storageMgrProxy->UpdateUserAuth(userId, secureUid, token, oldSecret, newSecret);
    if ((code != ERR_OK) && (code != ErrNo::E_PARAMS_NULLPTR_ERR)) {
        ACCOUNT_LOGE("Fail to update user auth, userId=%{public}d, code=%{public}d", userId, code);
        return code;
    }
#endif
    return ERR_OK;
}

ErrCode InnerAccountIAMManager::UpdateUserAuthWithRecoveryKey(const std::vector<uint8_t> &authToken,
    const std::vector<uint8_t> &newSecret, uint64_t secureUid, uint32_t userId)
{
    ACCOUNT_LOGI("Enter, userId=%{public}d", userId);
    void *handle = dlopen(RECOVERY_SO_PATH.c_str(), RTLD_LAZY);
    if (handle == nullptr) {
        ACCOUNT_LOGE("Call dlopen failed, error=%{public}s.", dlerror());
        return ERR_INVALID_VALUE;
    }
    void *updateUserAuthWithRecoveryKey = dlsym(handle, RECOVERY_METHOD_NAME);
    if (updateUserAuthWithRecoveryKey == nullptr) {
        ACCOUNT_LOGE("Call dlsym failed, method=%{public}s error=%{public}s.",
            RECOVERY_METHOD_NAME, dlerror());
        return ERR_INVALID_VALUE;
    }
    ErrCode res = (*reinterpret_cast<UpdateUserAuthWithRecoveryKeyFunc>(updateUserAuthWithRecoveryKey))(
        authToken, newSecret, secureUid, userId);
    dlclose(handle);
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Call updateUserAuthWithRecoveryKey failed, error=%{public}d.", res);
    }
    return res;
}

ErrCode InnerAccountIAMManager::GetLockScreenStatus(uint32_t userId, bool &lockScreenStatus)
{
    int times = 0;
    ErrCode errCode = ERR_OK;
    while (times < MAX_RETRY_TIMES) {
        errCode = InnerGetLockScreenStatus(userId, lockScreenStatus);
        if ((errCode != Constants::E_IPC_ERROR) && (errCode != Constants::E_IPC_SA_DIED)) {
            return errCode;
        }
        ACCOUNT_LOGE("errCode=%{public}d, userId=%{public}d, times=%{public}d", errCode, userId, times);
        times++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    return errCode;
}

ErrCode InnerAccountIAMManager::InnerGetLockScreenStatus(uint32_t userId, bool &lockScreenStatus)
{
#ifdef HAS_STORAGE_PART
    auto storageMgrProxy = GetStorageManagerProxy();
    if (storageMgrProxy == nullptr) {
        ACCOUNT_LOGE("fail to get storage proxy");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY;
    }
    ErrCode result = storageMgrProxy->GetLockScreenStatus(userId, lockScreenStatus);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to get lock screen status, ret:%{public}d, userId:%{public}d", result, userId);
        return result;
    }
#endif
    return ERR_OK;
}

ErrCode InnerAccountIAMManager::UnlockUserScreen(
    int32_t userId, const std::vector<uint8_t> &token, const std::vector<uint8_t> &secret)
{
    int times = 0;
    ErrCode errCode = ERR_OK;
    while (times < MAX_RETRY_TIMES) {
        errCode = InnerUnlockUserScreen(userId, token, secret);
        if ((errCode != Constants::E_IPC_ERROR) && (errCode != Constants::E_IPC_SA_DIED)) {
            return errCode;
        }
        ACCOUNT_LOGE("errCode=%{public}d, userId=%{public}d, times=%{public}d", errCode, userId, times);
        times++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    return errCode;
}

ErrCode InnerAccountIAMManager::InnerUnlockUserScreen(
    int32_t userId, const std::vector<uint8_t> &token, const std::vector<uint8_t> &secret)
{
#ifdef HAS_STORAGE_PART
    auto storageMgrProxy = GetStorageManagerProxy();
    if (storageMgrProxy == nullptr) {
        ACCOUNT_LOGE("fail to get storage proxy");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY;
    }
    ErrCode result = storageMgrProxy->UnlockUserScreen(userId, token, secret);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Fail to unlock screen, ret:%{public}d, userId:%{public}d", result, userId);
        return result;
    }
#endif
    return ERR_OK;
}

ErrCode InnerAccountIAMManager::ActivateUserKey(
    int32_t userId, const std::vector<uint8_t> &token, const std::vector<uint8_t> &secret)
{
    int times = 0;
    ErrCode errCode = ERR_OK;
    while (times < MAX_RETRY_TIMES) {
        errCode = InnerActivateUserKey(userId, token, secret);
        if ((errCode != Constants::E_IPC_ERROR) && (errCode != Constants::E_IPC_SA_DIED) &&
            (errCode != ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY)) {
            return errCode;
        }
        ACCOUNT_LOGE("Fail to activate user key, errCode=%{public}d, userId=%{public}d, times=%{public}d",
            errCode, userId, times);
        times++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    return errCode;
}

ErrCode InnerAccountIAMManager::InnerActivateUserKey(
    int32_t userId, const std::vector<uint8_t> &token, const std::vector<uint8_t> &secret)
{
    ErrCode result = ERR_OK;
#ifdef HAS_STORAGE_PART
    auto storageMgrProxy = GetStorageManagerProxy();
    if (storageMgrProxy == nullptr) {
        ACCOUNT_LOGE("Fail to get storage proxy");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY;
    }
    result = storageMgrProxy->ActiveUserKey(userId, token, secret);
    ACCOUNT_LOGI("ActiveUserKey end, ret: %{public}d", result);
#endif
    return result;
}

ErrCode InnerAccountIAMManager::PrepareStartUser(int32_t userId)
{
    int times = 0;
    ErrCode errCode = ERR_OK;
    while (times < MAX_RETRY_TIMES) {
        errCode = InnerPrepareStartUser(userId);
        if ((errCode != Constants::E_IPC_ERROR) && (errCode != Constants::E_IPC_SA_DIED) &&
            (errCode != ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY)) {
            return errCode;
        }
        ACCOUNT_LOGE("Fail to prepare start user, errCode=%{public}d, userId=%{public}d, times=%{public}d",
            errCode, userId, times);
        times++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    return errCode;
}

ErrCode InnerAccountIAMManager::InnerPrepareStartUser(int32_t userId)
{
    ErrCode result = ERR_OK;
#ifdef HAS_STORAGE_PART
    auto storageMgrProxy = GetStorageManagerProxy();
    if (storageMgrProxy == nullptr) {
        ACCOUNT_LOGE("Fail to get storage proxy");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY;
    }
    result = storageMgrProxy->PrepareStartUser(userId);
    ACCOUNT_LOGI("PrepareStartUser end, ret: %{public}d", result);
#endif
    return result;
}

#ifdef HAS_STORAGE_PART
sptr<StorageManager::IStorageManager> InnerAccountIAMManager::GetStorageManagerProxy()
{
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        ACCOUNT_LOGE("failed to get system ability mgr");
        return nullptr;
    }
    auto remote = systemAbilityManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (remote == nullptr) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID service");
        return nullptr;
    }
    auto storageMgrProxy = iface_cast<StorageManager::IStorageManager>(remote);
    return storageMgrProxy;
}
#endif

ErrCode InnerAccountIAMManager::CheckNeedReactivateUserKey(int32_t userId, bool &needReactivateKey)
{
#ifdef HAS_STORAGE_PART
    int32_t errCode = 0;
    int32_t retryTimes = 0;
    while (retryTimes < MAX_RETRY_TIMES) {
        sptr<StorageManager::IStorageManager> proxy = GetStorageManagerProxy();
        if (proxy == nullptr) {
            ACCOUNT_LOGE("Failed to get STORAGE_MANAGER_MANAGER_ID proxy, retry!");
            errCode = ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
            retryTimes++;
            std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
            continue;
        }
        errCode = proxy->GetUserNeedActiveStatus(userId, needReactivateKey);
        if ((errCode == Constants::E_IPC_ERROR) || (errCode == Constants::E_IPC_SA_DIED)) {
            ACCOUNT_LOGE("Failed to PrepareStartUser, id:%{public}d, errCode:%{public}d, retry!", userId, errCode);
            retryTimes++;
            std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
            continue;
        } else {
            break;
        }
    }
    if (errCode != ERR_OK) {
        needReactivateKey = true;
    }
    ACCOUNT_LOGI("Get user %{public}d need active status, ret = %{public}d, needReactivateKey = %{public}d.",
        userId, errCode, needReactivateKey);
    return errCode;
#else
    needReactivateKey = false;
    return ERR_OK;
#endif // HAS_STORAGE_PART
}
}  // namespace AccountSA
}  // namespace OHOS

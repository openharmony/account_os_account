/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "app_account_manager_service.h"

#include <securec.h>
#include "accesstoken_kit.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "bundle_manager_adapter.h"
#include "account_hisysevent_adapter.h"
#include "inner_app_account_manager.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
namespace {
constexpr int32_t UID_TRANSFORM_DIVISOR = 200000;  // local account id = uid / UID_TRANSFORM_DIVISOR
const char DISTRIBUTED_DATASYNC[] = "ohos.permission.DISTRIBUTED_DATASYNC";
const char GET_ALL_APP_ACCOUNTS[] = "ohos.permission.GET_ALL_APP_ACCOUNTS";
std::mutex g_mapMutex;
std::map<int32_t, std::weak_ptr<std::mutex>> g_uidMutexMap;
}

#define RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(str, funcResult)                   \
    if (CheckSpecialCharacters(str) != ERR_OK) {                           \
        ACCOUNT_LOGE("fail to check special characters");                  \
        funcResult = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;                 \
        return ERR_OK;                                                   \
    }                                                                      \

#define RETURN_IF_STRING_IS_OVERSIZE(str, maxSize, msg, funcResult)                                                    \
    if ((str).size() > (maxSize)) {                                                                             \
        ACCOUNT_LOGE("%{public}s, input size: %{public}zu, max size: %{public}zu", msg, (str).size(), maxSize); \
        funcResult = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;                                                      \
        return ERR_OK;                                                                                        \
    }                                                                                                           \

#define RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(str, maxSize, msg, funcResult)                                           \
    if ((str).empty() || ((str).size() > (maxSize))) {                                                          \
        ACCOUNT_LOGE("%{public}s, input size: %{public}zu, max size: %{public}zu", msg, (str).size(), maxSize); \
        funcResult = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;                                                      \
        return ERR_OK;                                                                                        \
    }                                                                                                           \

static ErrCode CheckSpecialCharacters(const std::string &str)
{
    for (auto specialCharacter : Constants::SPECIAL_CHARACTERS) {
        std::size_t found = str.find(specialCharacter);
        if (found != std::string::npos) {
            ACCOUNT_LOGE("found a special character, specialCharacter = %{public}c", specialCharacter);
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }
    }
    return ERR_OK;
}

AppAccountLock::AppAccountLock(int32_t uid) : uid_(uid)
{
    {
        std::lock_guard<std::mutex> lock(g_mapMutex);
        auto it = g_uidMutexMap.find(uid);
        if (it != g_uidMutexMap.end()) {
            mutexPtr_ = it->second.lock();
        }

        if (mutexPtr_ == nullptr) {
            mutexPtr_ = std::make_shared<std::mutex>();
            g_uidMutexMap[uid] = mutexPtr_;
        }
    }
    lock_ = std::unique_lock<std::mutex>(*mutexPtr_);
}

AppAccountLock::~AppAccountLock()
{
    lock_.unlock();
    if (mutexPtr_.use_count() == 1) {
        std::lock_guard<std::mutex> lock(g_mapMutex);
        g_uidMutexMap.erase(uid_);
    }
}

AppAccountManagerService::AppAccountManagerService()
#ifdef HAS_CES_PART
    : observer_(AppAccountCommonEventObserver::GetInstance())
#endif // HAS_CES_PART
{
    ACCOUNT_LOGI("Constructed");
    innerManager_ = std::make_shared<InnerAppAccountManager>();
}

AppAccountManagerService::~AppAccountManagerService()
{
    ACCOUNT_LOGI("Destroyed");
}

ErrCode AppAccountManagerService::AddAccount(const std::string &name, const std::string &extraInfo, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name, funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(extraInfo, Constants::EXTRA_INFO_MAX_SIZE, "extraInfo is oversize", funcResult);
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(callingUid);
    funcResult = innerManager_->AddAccount(name, extraInfo, callingUid, bundleName, appIndex);
    return ERR_OK;
}

ErrCode AppAccountManagerService::AddAccountImplicitly(const std::string &owner, const std::string &authType,
    const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize", funcResult);
    AuthenticatorSessionRequest request;
    request.callerPid = IPCSkeleton::GetCallingRealPid();
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        return ERR_OK;
    }
    request.owner = owner;
    request.authType = authType;
    request.options = options;
    request.callback = callback;
    request.options.SetParam(Constants::KEY_CALLER_PID, request.callerPid);
    request.options.SetParam(Constants::KEY_CALLER_UID, request.callerUid);
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->AddAccountImplicitly(request);
    return ERR_OK;
}

ErrCode AppAccountManagerService::CreateAccount(
    const std::string &name, const CreateAccountOptions &options, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(
        options.customData, Constants::MAX_CUSTOM_DATA_SIZE, "customData is oversize", funcResult);
    for (const auto &it : options.customData) {
        RETURN_IF_STRING_IS_OVERSIZE(
            it.first, Constants::ASSOCIATED_KEY_MAX_SIZE, "customData key is oversize", funcResult);
        RETURN_IF_STRING_IS_OVERSIZE(
            it.second, Constants::ASSOCIATED_VALUE_MAX_SIZE, "customData value is oversize", funcResult);
    }
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(callingUid);
    funcResult = innerManager_->CreateAccount(name, options, callingUid, bundleName, appIndex);
    return ERR_OK;
}

ErrCode AppAccountManagerService::CreateAccountImplicitly(const std::string &owner,
    const CreateAccountImplicitlyOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback,
    int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(
        options.authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(options.requiredLabels,
        Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "requiredLabels array is oversize", funcResult);
    AuthenticatorSessionRequest request;
    request.callerPid = IPCSkeleton::GetCallingRealPid();
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        return ERR_OK;
    }
    request.owner = owner;
    request.callback = callback;
    request.createOptions = options;
    request.createOptions.parameters.SetParam(Constants::KEY_CALLER_BUNDLE_NAME, request.callerBundleName);
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->CreateAccountImplicitly(request);
    return ERR_OK;
}

ErrCode AppAccountManagerService::DeleteAccount(const std::string &name, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(callingUid);
    funcResult = innerManager_->DeleteAccount(name, callingUid, bundleName, appIndex);
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetAccountExtraInfo(
    const std::string &name, std::string &extraInfo, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name, funcResult);
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(callingUid);
    funcResult = innerManager_->GetAccountExtraInfo(name, extraInfo, callingUid, bundleName, appIndex);
    return ERR_OK;
}

ErrCode AppAccountManagerService::SetAccountExtraInfo(
    const std::string &name, const std::string &extraInfo, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name, funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(extraInfo, Constants::EXTRA_INFO_MAX_SIZE, "extraInfo is oversize", funcResult);
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(callingUid);
    funcResult = innerManager_->SetAccountExtraInfo(name, extraInfo, callingUid, bundleName, appIndex);
    return ERR_OK;
}

ErrCode AppAccountManagerService::EnableAppAccess(
    const std::string &name, const std::string &authorizedApp, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name, funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(authorizedApp, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize", funcResult);
    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode result = GetCallingInfo(
        appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName, appAccountCallingInfo.appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        return ERR_OK;
    }

    if (authorizedApp == appAccountCallingInfo.bundleName) {
        ACCOUNT_LOGE("AuthorizedApp is the same to owner.");
        funcResult = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        return ERR_OK;
    }

    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(appAccountCallingInfo.callingUid);
    funcResult = innerManager_->EnableAppAccess(name, authorizedApp, appAccountCallingInfo);
    return ERR_OK;
}

ErrCode AppAccountManagerService::DisableAppAccess(
    const std::string &name, const std::string &authorizedApp, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name, funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(authorizedApp, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize", funcResult);
    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode ret = GetCallingInfo(
        appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName, appAccountCallingInfo.appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    if (authorizedApp == appAccountCallingInfo.bundleName) {
        ACCOUNT_LOGE("AuthorizedApp is the same to owner.");
        funcResult = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(appAccountCallingInfo.callingUid);
    funcResult = innerManager_->DisableAppAccess(name, authorizedApp, appAccountCallingInfo);
    return ERR_OK;
}

ErrCode AppAccountManagerService::SetAppAccess(
    const std::string &name, const std::string &authorizedApp, bool isAccessible, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(authorizedApp, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize", funcResult);
    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode ret = GetCallingInfo(
        appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName, appAccountCallingInfo.appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }

    if (authorizedApp == appAccountCallingInfo.bundleName) {
        if (isAccessible) {
            ACCOUNT_LOGI("AuthorizedApp name is the self, invalid operate.");
            funcResult = ERR_OK;
            return ERR_OK;
        } else {
            ACCOUNT_LOGE("AuthorizedApp is the same to owner.");
            funcResult = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
            return ERR_OK;
        }
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(appAccountCallingInfo.callingUid);
    if (isAccessible) {
        funcResult = innerManager_->EnableAppAccess(
            name, authorizedApp, appAccountCallingInfo, Constants::API_VERSION9);
        return ERR_OK;
    }

    funcResult = innerManager_->DisableAppAccess(name, authorizedApp, appAccountCallingInfo, Constants::API_VERSION9);
    return ERR_OK;
}

ErrCode AppAccountManagerService::CheckAppAccountSyncEnable(
    const std::string &name, bool &syncEnable, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetBundleNameAndCheckPerm(callingUid, bundleName, DISTRIBUTED_DATASYNC);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    ret = GetCallingTokenInfoAndAppIndex(appIndex);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to get app index");
        funcResult = ret;
        return ERR_OK;
    }

    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(callingUid);
    funcResult = innerManager_->CheckAppAccountSyncEnable(name, syncEnable, callingUid, bundleName, appIndex);
    return ERR_OK;
}

ErrCode AppAccountManagerService::SetAppAccountSyncEnable(
    const std::string &name, bool syncEnable, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetBundleNameAndCheckPerm(callingUid, bundleName, DISTRIBUTED_DATASYNC);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    ret = GetCallingTokenInfoAndAppIndex(appIndex);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to get app index");
        funcResult = ret;
        return ERR_OK;
    }

    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(callingUid);
    funcResult = innerManager_->SetAppAccountSyncEnable(name, syncEnable, callingUid, bundleName, appIndex);
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetAssociatedData(
    const std::string &name, const std::string &key, std::string &value, int32_t &funcResult)
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(callingUid);
    funcResult = innerManager_->GetAssociatedData(name, key, value, callingUid);
    return ERR_OK;
}

ErrCode AppAccountManagerService::SetAssociatedData(
    const std::string &name, const std::string &key, const std::string &value, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(
        key, Constants::ASSOCIATED_KEY_MAX_SIZE, "key is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(value, Constants::ASSOCIATED_VALUE_MAX_SIZE, "value is oversize", funcResult);
    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode ret = GetCallingInfo(appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName,
        appAccountCallingInfo.appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(appAccountCallingInfo.callingUid);
    funcResult = innerManager_->SetAssociatedData(name, key, value, appAccountCallingInfo);
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(credentialType, Constants::CREDENTIAL_TYPE_MAX_SIZE,
        "credentialType is empty or oversize", funcResult);
    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode ret = GetCallingInfo(appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName,
        appAccountCallingInfo.appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(appAccountCallingInfo.callingUid);
    funcResult = innerManager_->GetAccountCredential(name, credentialType, credential, appAccountCallingInfo);
    return ERR_OK;
}

ErrCode AppAccountManagerService::SetAccountCredential(
    const std::string &name, const std::string &credentialType, const std::string &credential, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(credentialType, Constants::CREDENTIAL_TYPE_MAX_SIZE,
        "credentialType is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(credential, Constants::CREDENTIAL_MAX_SIZE, "credential is oversize", funcResult);
    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode ret = GetCallingInfo(appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName,
        appAccountCallingInfo.appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        auto credStr = const_cast<std::string *>(&credential);
        (void)memset_s(credStr->data(), credStr->size(), 0, credStr->size());
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(appAccountCallingInfo.callingUid);
    funcResult = innerManager_->SetAccountCredential(name, credentialType, credential, appAccountCallingInfo);
    auto credStr = const_cast<std::string *>(&credential);
    (void)memset_s(credStr->data(), credStr->size(), 0, credStr->size());
    return ERR_OK;
}

ErrCode AppAccountManagerService::Authenticate(const AppAccountStringInfo &appAccountStringInfo,
    const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(
        appAccountStringInfo.name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(
        appAccountStringInfo.owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(
        appAccountStringInfo.authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize", funcResult);
    AuthenticatorSessionRequest request;
    request.callerPid = IPCSkeleton::GetCallingRealPid();
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        return ERR_OK;
    }
    request.name = appAccountStringInfo.name;
    request.owner = appAccountStringInfo.owner;
    request.authType = appAccountStringInfo.authType;
    request.options = options;
    request.callback = callback;
    request.options.SetParam(Constants::KEY_CALLER_BUNDLE_NAME, request.callerBundleName);
    request.options.SetParam(Constants::KEY_CALLER_UID, request.callerUid);
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->Authenticate(request);
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetOAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token,
    int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize", funcResult);
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name, funcResult);
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        return ERR_OK;
    }
    request.name = name;
    request.owner = owner;
    request.authType = authType;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->GetOAuthToken(request, token);
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token,
    int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize", funcResult);
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        return ERR_OK;
    }
    request.name = name;
    request.owner = owner;
    request.authType = authType;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->GetOAuthToken(request, token, Constants::API_VERSION9);
    return ERR_OK;
}

ErrCode AppAccountManagerService::SetOAuthToken(
    const std::string &name, const std::string &authType, const std::string &token, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(token, Constants::TOKEN_MAX_SIZE, "token is oversize", funcResult);
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        auto tokenStr = const_cast<std::string *>(&token);
        (void)memset_s(tokenStr->data(), tokenStr->size(), 0, tokenStr->size());
        return ERR_OK;
    }
    request.name = name;
    request.owner = request.callerBundleName;
    request.authType = authType;
    request.token = token;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->SetOAuthToken(request);
    auto tokenStr = const_cast<std::string *>(&token);
    (void)memset_s(tokenStr->data(), tokenStr->size(), 0, tokenStr->size());
    return ERR_OK;
}

ErrCode AppAccountManagerService::DeleteOAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, const std::string &token,
    int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(token, Constants::TOKEN_MAX_SIZE, "token is oversize", funcResult);
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name, funcResult);
    AuthenticatorSessionRequest request;
    ErrCode ret = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        auto tokenStr = const_cast<std::string *>(&token);
        (void)memset_s(tokenStr->data(), tokenStr->size(), 0, tokenStr->size());
        return ERR_OK;
    }
    request.name = name;
    request.owner = owner;
    request.authType = authType;
    request.token = token;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->DeleteOAuthToken(request);
    auto tokenStr = const_cast<std::string *>(&token);
    (void)memset_s(tokenStr->data(), tokenStr->size(), 0, tokenStr->size());
    return ERR_OK;
}

ErrCode AppAccountManagerService::DeleteAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, const std::string &token,
    int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(token, Constants::TOKEN_MAX_SIZE, "token is oversize", funcResult);
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        auto tokenStr = const_cast<std::string *>(&token);
        (void)memset_s(tokenStr->data(), tokenStr->size(), 0, tokenStr->size());
        return ERR_OK;
    }
    request.name = name;
    request.owner = owner;
    request.authType = authType;
    request.token = token;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->DeleteOAuthToken(request, Constants::API_VERSION9);
    auto tokenStr = const_cast<std::string *>(&token);
    (void)memset_s(tokenStr->data(), tokenStr->size(), 0, tokenStr->size());
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetTokenVisibilityParam(const std::string &name,
    const std::string &authType, const std::string &bundleName, AuthenticatorSessionRequest &request)
{
    ErrCode ret = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    request.name = name;
    request.owner = request.callerBundleName;
    request.authType = authType;
    request.bundleName = bundleName;
    return ret;
}

ErrCode AppAccountManagerService::SetOAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool isVisible,
    int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize", funcResult);
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name, funcResult);
    AuthenticatorSessionRequest request;
    ErrCode ret = GetTokenVisibilityParam(name, authType, bundleName, request);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    request.isTokenVisible = isVisible;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->SetOAuthTokenVisibility(request);
    return ERR_OK;
}

ErrCode AppAccountManagerService::SetAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool isVisible,
    int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize", funcResult);
    AuthenticatorSessionRequest request;
    ErrCode result = GetTokenVisibilityParam(name, authType, bundleName, request);
    if (result != ERR_OK) {
        funcResult = result;
        return ERR_OK;
    }
    if (request.bundleName == request.owner) {
        if (isVisible) {
            ACCOUNT_LOGI("authorizedApp name is the self, invalid operate.");
            funcResult = ERR_OK;
            return ERR_OK;
        } else {
            ACCOUNT_LOGE("authorizedApp is the same to owner.");
            funcResult = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
            return ERR_OK;
        }
    }
    request.isTokenVisible = isVisible;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->SetOAuthTokenVisibility(request, Constants::API_VERSION9);
    return ERR_OK;
}

ErrCode AppAccountManagerService::CheckOAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool &isVisible,
    int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize", funcResult);
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name, funcResult);
    AuthenticatorSessionRequest request;
    ErrCode ret = GetTokenVisibilityParam(name, authType, bundleName, request);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->CheckOAuthTokenVisibility(request, isVisible);
    return ERR_OK;
}

ErrCode AppAccountManagerService::CheckAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool &isVisible,
    int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize", funcResult);
    AuthenticatorSessionRequest request;
    ErrCode ret = GetTokenVisibilityParam(name, authType, bundleName, request);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->CheckOAuthTokenVisibility(request, isVisible, Constants::API_VERSION9);
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetAuthenticatorInfo(
    const std::string &owner, AuthenticatorInfo &info, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize", funcResult);
    AuthenticatorSessionRequest request;
    request.callerUid = IPCSkeleton::GetCallingUid();
    ErrCode result = GetCallingTokenInfoAndAppIndex(request.appIndex);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get app index");
        funcResult = result;
        return ERR_OK;
    }
    request.owner = owner;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->GetAuthenticatorInfo(request, info);
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetAllOAuthTokens(
    const std::string &name, const std::string &owner, std::vector<OAuthTokenInfo> &tokenInfos, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize", funcResult);
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        return ERR_OK;
    }
    request.name = name;
    request.owner = owner;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->GetAllOAuthTokens(request, tokenInfos);
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetOAuthList(
    const std::string &name, const std::string &authType, std::set<std::string> &oauthList, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::OWNER_MAX_SIZE, "authType is oversize", funcResult);
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name, funcResult);
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        return ERR_OK;
    }
    request.name = name;
    request.authType = authType;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->GetOAuthList(request, oauthList);
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetAuthList(
    const std::string &name, const std::string &authType, std::set<std::string> &oauthList, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::OWNER_MAX_SIZE, "authType is oversize", funcResult);
    AuthenticatorSessionRequest request;
    ErrCode ret = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    request.name = name;
    request.authType = authType;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->GetOAuthList(request, oauthList, Constants::API_VERSION9);
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetAuthenticatorCallback(
    const std::string &sessionId, int32_t &funcResult, sptr<IRemoteObject> &callback)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(sessionId, Constants::SESSION_ID_MAX_SIZE,
        "sessionId is empty or oversize", funcResult);
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        return ERR_OK;
    }
    request.sessionId = sessionId;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->GetAuthenticatorCallback(request, callback);
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetAllAccounts(
    const std::string &owner, std::vector<AppAccountInfo> &appAccounts, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize", funcResult);
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    if ((owner != bundleName) &&
        (AccountPermissionManager::VerifyPermission(GET_ALL_APP_ACCOUNTS) != ERR_OK)) {
        ACCOUNT_LOGE("failed to verify permission for %{public}s", GET_ALL_APP_ACCOUNTS);
        REPORT_PERMISSION_FAIL();
        funcResult = ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
        return ERR_OK;
    }

    AppExecFwk::BundleInfo bundleInfo;
    int32_t userId = callingUid / UID_TRANSFORM_DIVISOR;
    bool result = BundleManagerAdapter::GetInstance()->GetBundleInfo(
        owner, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
    if (!result) {
        funcResult = ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(callingUid);
    funcResult = innerManager_->GetAllAccounts(owner, appAccounts, callingUid, bundleName, appIndex);
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetAllAccessibleAccounts(
    std::vector<AppAccountInfo> &appAccounts, int32_t &funcResult)
{
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetBundleNameAndCheckPerm(callingUid, bundleName, GET_ALL_APP_ACCOUNTS);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    ret = GetCallingTokenInfoAndAppIndex(appIndex);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to get app index");
        funcResult = ret;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(callingUid);
    funcResult = innerManager_->GetAllAccessibleAccounts(appAccounts, callingUid, bundleName, appIndex);
    return ERR_OK;
}

ErrCode AppAccountManagerService::QueryAllAccessibleAccounts(
    const std::string &owner, std::vector<AppAccountInfo> &appAccounts, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is or oversize", funcResult);
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode result = GetCallingInfo(callingUid, bundleName, appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        return ERR_OK;
    }
    if (owner.empty()) {
        funcResult = innerManager_->GetAllAccessibleAccounts(appAccounts, callingUid, bundleName, appIndex);
        return ERR_OK;
    }
    AppExecFwk::BundleInfo bundleInfo;
    int32_t userId = callingUid / UID_TRANSFORM_DIVISOR;
    bool ret = BundleManagerAdapter::GetInstance()->GetBundleInfo(
        owner, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
    if (!ret) {
        funcResult = ERR_OK;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(callingUid);
    funcResult = innerManager_->GetAllAccounts(owner, appAccounts, callingUid, bundleName, appIndex);
    return ERR_OK;
}

ErrCode AppAccountManagerService::CheckAppAccess(
    const std::string &name, const std::string &authorizedApp, bool &isAccessible, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(authorizedApp, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize", funcResult);
    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode result = GetCallingInfo(appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName,
        appAccountCallingInfo.appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        return ERR_OK;
    }
    if (authorizedApp == appAccountCallingInfo.bundleName) {
        isAccessible = true;
        funcResult = ERR_OK;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(appAccountCallingInfo.callingUid);
    funcResult = innerManager_->CheckAppAccess(name, authorizedApp, isAccessible, appAccountCallingInfo);
    return ERR_OK;
}

ErrCode AppAccountManagerService::DeleteAccountCredential(
    const std::string &name, const std::string &credentialType, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(credentialType, Constants::CREDENTIAL_TYPE_MAX_SIZE,
        "credentialType is empty or oversize", funcResult);
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(callingUid);
    funcResult = innerManager_->DeleteAccountCredential(name, credentialType, callingUid, bundleName, appIndex);
    return ERR_OK;
}

ErrCode AppAccountManagerService::SelectAccountsByOptions(
    const SelectAccountsOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_OVERSIZE(options.allowedAccounts,
        Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "allowedAccounts array is oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(options.allowedOwners,
        Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "allowedOwners array is oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(options.requiredLabels,
        Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "requiredLabels array is oversize", funcResult);
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(callingUid);
    funcResult = innerManager_->SelectAccountsByOptions(options, callback, callingUid, bundleName, appIndex);
    return ERR_OK;
}

ErrCode AppAccountManagerService::VerifyCredential(const std::string &name, const std::string &owner,
    const VerifyCredentialOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(
        options.credentialType, Constants::CREDENTIAL_TYPE_MAX_SIZE, "the credential type is oversize", funcResult);
    RETURN_IF_STRING_IS_OVERSIZE(
        options.credential, Constants::CREDENTIAL_MAX_SIZE, "the credential is oversize", funcResult);
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        return ERR_OK;
    }
    request.name = name;
    request.owner = owner;
    request.verifyCredOptions = options;
    request.callback = callback;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->VerifyCredential(request);
    return ERR_OK;
}

ErrCode AppAccountManagerService::CheckAccountLabels(const std::string &name, const std::string &owner,
    const std::vector<std::string> &labels, const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize", funcResult);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(
        labels, Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "labels array is empty or oversize", funcResult);
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        return ERR_OK;
    }
    request.labels = labels;
    request.callback = callback;
    request.name = name;
    request.owner = owner;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->CheckAccountLabels(request);
    return ERR_OK;
}

ErrCode AppAccountManagerService::SetAuthenticatorProperties(const std::string &owner,
    const SetPropertiesOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE,  "owner is empty or oversize", funcResult);
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        funcResult = result;
        return ERR_OK;
    }
    request.owner = owner;
    request.setPropOptions = options;
    request.callback = callback;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(request.callerUid);
    funcResult = innerManager_->SetAuthenticatorProperties(request);
    return ERR_OK;
}

ErrCode AppAccountManagerService::SubscribeAppAccount(
    const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener, int32_t &funcResult)
{
    auto subscribeInfoCopy = subscribeInfo;
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        funcResult = ret;
        return ERR_OK;
    }

    std::vector<std::string> owners;
    subscribeInfoCopy.GetOwners(owners);
    if (owners.size() == 0) {
        ACCOUNT_LOGE("owners size is 0");
        funcResult = ERR_APPACCOUNT_SERVICE_OWNERS_SIZE_IS_ZERO;
        return ERR_OK;
    }

    int32_t userId = callingUid / UID_TRANSFORM_DIVISOR;
    std::vector<std::string> existOwners;
    for (auto owner : owners) {
        AppExecFwk::BundleInfo bundleInfo;
        bool bundleRet = BundleManagerAdapter::GetInstance()->GetBundleInfo(owner,
            AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
        if (!bundleRet) {
            ACCOUNT_LOGE("Failed to get bundle info, name=%{public}s", owner.c_str());
            continue;
        }
        existOwners.push_back(owner);
    }
    if (existOwners.size() == 0) {
        ACCOUNT_LOGI("ExistOwners is empty.");
        funcResult = ERR_OK;
        return ERR_OK;
    }
    subscribeInfoCopy.SetOwners(existOwners);
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(callingUid);
    funcResult = innerManager_->SubscribeAppAccount(subscribeInfoCopy, eventListener, callingUid, bundleName, appIndex);
    return ERR_OK;
}

ErrCode AppAccountManagerService::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener,
    const std::vector<std::string> &owners, int32_t &funcResult)
{
    RETURN_IF_STRING_IS_OVERSIZE(
        owners, Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "owners array is empty or oversize", funcResult);
    std::vector<std::string> ownerList = owners;
    std::unique_ptr<AppAccountLock> lock = std::make_unique<AppAccountLock>(IPCSkeleton::GetCallingUid());
    funcResult = innerManager_->UnsubscribeAppAccount(eventListener, ownerList);
    return ERR_OK;
}

ErrCode AppAccountManagerService::OnPackageRemoved(
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    return innerManager_->OnPackageRemoved(uid, bundleName, appIndex);
}

ErrCode AppAccountManagerService::OnUserRemoved(int32_t userId)
{
    return innerManager_->OnUserRemoved(userId);
}

ErrCode AppAccountManagerService::GetBundleNameAndCheckPerm(int32_t &callingUid,
    std::string &bundleName, const std::string &permName)
{
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        return result;
    }

    result = AccountPermissionManager::VerifyPermission(permName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to verify permission for %{public}s, result = %{public}d",
            permName.c_str(), result);
        ReportPermissionFail(callingUid, IPCSkeleton::GetCallingRealPid(), permName);
        return result;
    }
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetBundleNameAndCallingUid(int32_t &callingUid, std::string &bundleName)
{
    callingUid = IPCSkeleton::GetCallingUid();
    ErrCode bundleRet = BundleManagerAdapter::GetInstance()->GetNameForUid(callingUid, bundleName);
    if (bundleRet != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME;
    }
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetCallingTokenInfoAndAppIndex(uint32_t &appIndex)
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::HapTokenInfo hapTokenInfo;
    int result = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(callingTokenId, hapTokenInfo);
    if (result) {
        ACCOUNT_LOGE("failed to get hap token info, result = %{public}d", result);
        return ERR_APPACCOUNT_SERVICE_GET_APP_INDEX;
    }
    if (hapTokenInfo.instIndex < 0) {
        ACCOUNT_LOGE("get invalid app index from hap token info, index = %{public}d", hapTokenInfo.instIndex);
        return ERR_APPACCOUNT_SERVICE_GET_APP_INDEX;
    }
    appIndex = static_cast<uint32_t>(hapTokenInfo.instIndex);
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetCallingInfo(int32_t &callingUid, std::string &bundleName, uint32_t &appIndex)
{
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to get bundle name");
        return result;
    }
    result = GetCallingTokenInfoAndAppIndex(appIndex);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get app index");
        return result;
    }
    return result;
}
}  // namespace AccountSA
}  // namespace OHOS

/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "account_info.h"
#include "accesstoken_kit.h"
#include "account_log_wrapper.h"
#include "bundle_manager_adapter.h"
#include "hisysevent_adapter.h"
#include "inner_app_account_manager.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
AppAccountManagerService::AppAccountManagerService()
{
    innerManager_ = std::make_shared<InnerAppAccountManager>();
    permissionManagerPtr_ = DelayedSingleton<AccountPermissionManager>::GetInstance();
#ifdef HAS_CES_PART
    CommonEventCallback callback = {
        std::bind(&AppAccountManagerService::OnPackageRemoved,
            this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
        std::bind(&AppAccountManagerService::OnUserRemoved, this, std::placeholders::_1),
    };
    observer_ = std::make_shared<AppAccountCommonEventObserver>(callback);
#endif // HAS_CES_PART
}

AppAccountManagerService::~AppAccountManagerService()
{}

ErrCode AppAccountManagerService::AddAccount(const std::string &name, const std::string &extraInfo)
{
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    return innerManager_->AddAccount(name, extraInfo, callingUid, bundleName, appIndex);
}

ErrCode AppAccountManagerService::AddAccountImplicitly(const std::string &owner, const std::string &authType,
    const AAFwk::Want &options, const sptr<IRemoteObject> &callback)
{
    AuthenticatorSessionRequest request;
    request.callerPid = IPCSkeleton::GetCallingPid();
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    request.owner = owner;
    request.authType = authType;
    request.options = options;
    request.callerAbilityName = options.GetStringParam(Constants::KEY_CALLER_ABILITY_NAME);
    request.callback = iface_cast<IAppAccountAuthenticatorCallback>(callback);
    request.options.RemoveParam(Constants::KEY_CALLER_ABILITY_NAME);
    request.options.SetParam(Constants::KEY_CALLER_PID, request.callerPid);
    request.options.SetParam(Constants::KEY_CALLER_UID, request.callerUid);
    return innerManager_->AddAccountImplicitly(request);
}

ErrCode AppAccountManagerService::CreateAccount(const std::string &name, const CreateAccountOptions &options)
{
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    return innerManager_->CreateAccount(name, options, callingUid, bundleName, appIndex);
}

ErrCode AppAccountManagerService::CreateAccountImplicitly(const std::string &owner,
    const CreateAccountImplicitlyOptions &options, const sptr<IRemoteObject> &callback)
{
    AuthenticatorSessionRequest request;
    request.callerPid = IPCSkeleton::GetCallingPid();
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    request.owner = owner;
    request.callerAbilityName = options.parameters.GetStringParam(Constants::KEY_CALLER_ABILITY_NAME);
    request.callback = iface_cast<IAppAccountAuthenticatorCallback>(callback);
    request.createOptions = options;
    request.createOptions.parameters.RemoveParam(Constants::KEY_CALLER_ABILITY_NAME);
    request.createOptions.parameters.SetParam(Constants::KEY_CALLER_BUNDLE_NAME, request.callerBundleName);
    return innerManager_->CreateAccountImplicitly(request);
}

ErrCode AppAccountManagerService::DeleteAccount(const std::string &name)
{
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    return innerManager_->DeleteAccount(name, callingUid, bundleName, appIndex);
}

ErrCode AppAccountManagerService::GetAccountExtraInfo(const std::string &name, std::string &extraInfo)
{
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    return innerManager_->GetAccountExtraInfo(name, extraInfo, callingUid, bundleName, appIndex);
}

ErrCode AppAccountManagerService::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo)
{
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    return innerManager_->SetAccountExtraInfo(name, extraInfo, callingUid, bundleName, appIndex);
}

ErrCode AppAccountManagerService::EnableAppAccess(
    const std::string &name, const std::string &authorizedApp)
{
    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode result = GetCallingInfo(
        appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName, appAccountCallingInfo.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    AppExecFwk::BundleInfo bundleInfo;
    int32_t userId = appAccountCallingInfo.callingUid / UID_TRANSFORM_DIVISOR;
    bool bundleRet = BundleManagerAdapter::GetInstance()->GetBundleInfo(
        authorizedApp, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
    if (!bundleRet) {
        ACCOUNT_LOGE("failed to get bundle info");
        return ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO;
    }
    if (authorizedApp == appAccountCallingInfo.bundleName) {
        ACCOUNT_LOGE("authorizedApp is the same to owner");
        return ERR_APPACCOUNT_SERVICE_BUNDLE_NAME_IS_THE_SAME;
    }

    return innerManager_->EnableAppAccess(name, authorizedApp, appAccountCallingInfo);
}

ErrCode AppAccountManagerService::DisableAppAccess(
    const std::string &name, const std::string &authorizedApp)
{
    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode ret = GetCallingInfo(
        appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName, appAccountCallingInfo.appIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    AppExecFwk::BundleInfo bundleInfo;

    int32_t userId = appAccountCallingInfo.callingUid / UID_TRANSFORM_DIVISOR;
    bool bundleRet = BundleManagerAdapter::GetInstance()->GetBundleInfo(
        authorizedApp, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
    if (!bundleRet) {
        ACCOUNT_LOGE("failed to get bundle info");
        return ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO;
    }

    if (authorizedApp == appAccountCallingInfo.bundleName) {
        ACCOUNT_LOGE("authorizedApp is the same to owner");
        return ERR_APPACCOUNT_SERVICE_BUNDLE_NAME_IS_THE_SAME;
    }

    return innerManager_->DisableAppAccess(name, authorizedApp, appAccountCallingInfo);
}

ErrCode AppAccountManagerService::SetAppAccess(
    const std::string &name, const std::string &authorizedApp, bool isAccessible)
{
    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode ret = GetCallingInfo(
        appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName, appAccountCallingInfo.appIndex);
    if (ret != ERR_OK) {
        return ret;
    }

    if (authorizedApp == appAccountCallingInfo.bundleName) {
        if (isAccessible) {
            ACCOUNT_LOGI("authorizedApp name is the self, invalid operate.");
            return ERR_OK;
        } else {
            ACCOUNT_LOGE("authorizedApp is the same to owner");
            return ERR_APPACCOUNT_SERVICE_BUNDLE_NAME_IS_THE_SAME;
        }
    }

    if (isAccessible) {
        AppExecFwk::BundleInfo bundleInfo;
        int32_t userId = appAccountCallingInfo.callingUid / UID_TRANSFORM_DIVISOR;
        bool bundleRet = BundleManagerAdapter::GetInstance()->GetBundleInfo(
            authorizedApp, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
        if (!bundleRet) {
            ACCOUNT_LOGE("failed to get bundle info");
            return ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO;
        }
        return innerManager_->EnableAppAccess(name, authorizedApp, appAccountCallingInfo, Constants::API_VERSION9);
    }

    return innerManager_->DisableAppAccess(name, authorizedApp, appAccountCallingInfo, Constants::API_VERSION9);
}

ErrCode AppAccountManagerService::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable)
{
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetBundleNameAndCheckPerm(callingUid, bundleName, AccountPermissionManager::DISTRIBUTED_DATASYNC);
    if (ret != ERR_OK) {
        return ret;
    }
    ret = GetCallingTokenInfoAndAppIndex(appIndex);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to get app index");
        return ret;
    }

    return innerManager_->CheckAppAccountSyncEnable(name, syncEnable, callingUid, bundleName, appIndex);
}

ErrCode AppAccountManagerService::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable)
{
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetBundleNameAndCheckPerm(callingUid, bundleName, AccountPermissionManager::DISTRIBUTED_DATASYNC);
    if (ret != ERR_OK) {
        return ret;
    }
    ret = GetCallingTokenInfoAndAppIndex(appIndex);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to get app index");
        return ret;
    }

    return innerManager_->SetAppAccountSyncEnable(name, syncEnable, callingUid, bundleName, appIndex);
}

ErrCode AppAccountManagerService::GetAssociatedData(
    const std::string &name, const std::string &key, std::string &value)
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return innerManager_->GetAssociatedData(name, key, value, callingUid);
}

ErrCode AppAccountManagerService::SetAssociatedData(
    const std::string &name, const std::string &key, const std::string &value)
{
    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode ret = GetCallingInfo(appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName,
        appAccountCallingInfo.appIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    return innerManager_->SetAssociatedData(name, key, value, appAccountCallingInfo);
}

ErrCode AppAccountManagerService::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential)
{
    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode ret = GetCallingInfo(appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName,
        appAccountCallingInfo.appIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    return innerManager_->GetAccountCredential(name, credentialType, credential, appAccountCallingInfo);
}

ErrCode AppAccountManagerService::SetAccountCredential(
    const std::string &name, const std::string &credentialType, const std::string &credential)
{
    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode ret = GetCallingInfo(appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName,
        appAccountCallingInfo.appIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    return innerManager_->SetAccountCredential(name, credentialType, credential, appAccountCallingInfo);
}

ErrCode AppAccountManagerService::Authenticate(const std::string &name, const std::string &owner,
    const std::string &authType, const AAFwk::Want &options, const sptr<IRemoteObject> &callback)
{
    AuthenticatorSessionRequest request;
    request.callerPid = IPCSkeleton::GetCallingPid();
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    request.name = name;
    request.owner = owner;
    request.authType = authType;
    request.options = options;
    request.callerAbilityName = options.GetStringParam(Constants::KEY_CALLER_ABILITY_NAME);
    request.callback = iface_cast<IAppAccountAuthenticatorCallback>(callback);
    request.options.RemoveParam(Constants::KEY_CALLER_ABILITY_NAME);
    request.options.SetParam(Constants::KEY_CALLER_BUNDLE_NAME, request.callerBundleName);
    request.options.SetParam(Constants::KEY_CALLER_UID, request.callerUid);
    return innerManager_->Authenticate(request);
}

ErrCode AppAccountManagerService::GetOAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    request.name = name;
    request.owner = owner;
    request.authType = authType;
    return innerManager_->GetOAuthToken(request, token);
}

ErrCode AppAccountManagerService::GetAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    request.name = name;
    request.owner = owner;
    request.authType = authType;
    return innerManager_->GetOAuthToken(request, token, Constants::API_VERSION9);
}

ErrCode AppAccountManagerService::SetOAuthToken(
    const std::string &name, const std::string &authType, const std::string &token)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    request.name = name;
    request.owner = request.callerBundleName;
    request.authType = authType;
    request.token = token;
    return innerManager_->SetOAuthToken(request);
}

ErrCode AppAccountManagerService::DeleteOAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, const std::string &token)
{
    AuthenticatorSessionRequest request;
    ErrCode ret = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    request.name = name;
    request.owner = owner;
    request.authType = authType;
    request.token = token;
    return innerManager_->DeleteOAuthToken(request);
}

ErrCode AppAccountManagerService::DeleteAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, const std::string &token)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    request.name = name;
    request.owner = owner;
    request.authType = authType;
    request.token = token;
    return innerManager_->DeleteOAuthToken(request, Constants::API_VERSION9);
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
    const std::string &name, const std::string &authType, const std::string &bundleName, bool isVisible)
{
    AuthenticatorSessionRequest request;
    ErrCode ret = GetTokenVisibilityParam(name, authType, bundleName, request);
    if (ret != ERR_OK) {
        return ret;
    }
    request.isTokenVisible = isVisible;
    return innerManager_->SetOAuthTokenVisibility(request);
}

ErrCode AppAccountManagerService::SetAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool isVisible)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetTokenVisibilityParam(name, authType, bundleName, request);
    if (result != ERR_OK) {
        return result;
    }
    if (request.bundleName == request.owner) {
        if (isVisible) {
            ACCOUNT_LOGI("authorizedApp name is the self, invalid operate.");
            return ERR_OK;
        } else {
            ACCOUNT_LOGE("authorizedApp is the same to owner.");
            return ERR_APPACCOUNT_SERVICE_BUNDLE_NAME_IS_THE_SAME;
        }
    }
    if (isVisible) {
        AppExecFwk::BundleInfo bundleInfo;
        int32_t userId = request.callerUid / UID_TRANSFORM_DIVISOR;
        bool ret = BundleManagerAdapter::GetInstance()->GetBundleInfo(
            bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
        if (!ret) {
            return ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO;
        }
    }
    request.isTokenVisible = isVisible;
    return innerManager_->SetOAuthTokenVisibility(request, Constants::API_VERSION9);
}

ErrCode AppAccountManagerService::CheckOAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool &isVisible)
{
    AuthenticatorSessionRequest request;
    ErrCode ret = GetTokenVisibilityParam(name, authType, bundleName, request);
    if (ret != ERR_OK) {
        return ret;
    }
    return innerManager_->CheckOAuthTokenVisibility(request, isVisible);
}

ErrCode AppAccountManagerService::CheckAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool &isVisible)
{
    AuthenticatorSessionRequest request;
    ErrCode ret = GetTokenVisibilityParam(name, authType, bundleName, request);
    if (ret != ERR_OK) {
        return ret;
    }
    return innerManager_->CheckOAuthTokenVisibility(request, isVisible, Constants::API_VERSION9);
}

ErrCode AppAccountManagerService::GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &info)
{
    AuthenticatorSessionRequest request;
    request.callerUid = IPCSkeleton::GetCallingUid();
    ErrCode result = GetCallingTokenInfoAndAppIndex(request.appIndex);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get app index");
        return result;
    }
    request.owner = owner;
    return innerManager_->GetAuthenticatorInfo(request, info);
}

ErrCode AppAccountManagerService::GetAllOAuthTokens(
    const std::string &name, const std::string &owner, std::vector<OAuthTokenInfo> &tokenInfos)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    request.name = name;
    request.owner = owner;
    return innerManager_->GetAllOAuthTokens(request, tokenInfos);
}

ErrCode AppAccountManagerService::GetOAuthList(
    const std::string &name, const std::string &authType, std::set<std::string> &oauthList)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    request.name = name;
    request.authType = authType;
    return innerManager_->GetOAuthList(request, oauthList);
}

ErrCode AppAccountManagerService::GetAuthList(
    const std::string &name, const std::string &authType, std::set<std::string> &oauthList)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    request.name = name;
    request.authType = authType;
    return innerManager_->GetOAuthList(request, oauthList, Constants::API_VERSION9);
}

ErrCode AppAccountManagerService::GetAuthenticatorCallback(
    const std::string &sessionId, sptr<IRemoteObject> &callback)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    request.sessionId = sessionId;
    result = innerManager_->GetAuthenticatorCallback(request, callback);
    return result;
}

ErrCode AppAccountManagerService::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    if ((owner != bundleName) &&
        (permissionManagerPtr_->VerifyPermission(AccountPermissionManager::GET_ALL_APP_ACCOUNTS) != ERR_OK)) {
        ACCOUNT_LOGE("failed to verify permission for %{public}s",
            AccountPermissionManager::GET_ALL_APP_ACCOUNTS.c_str());
        ReportPermissionFail(callingUid, IPCSkeleton::GetCallingPid(),
            AccountPermissionManager::GET_ALL_APP_ACCOUNTS);
        return ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    AppExecFwk::BundleInfo bundleInfo;
    int32_t userId = callingUid / UID_TRANSFORM_DIVISOR;
    bool result = BundleManagerAdapter::GetInstance()->GetBundleInfo(
        owner, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
    if (!result) {
        return ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO;
    }

    return innerManager_->GetAllAccounts(owner, appAccounts, callingUid, bundleName, appIndex);
}

ErrCode AppAccountManagerService::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts)
{
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetBundleNameAndCheckPerm(callingUid, bundleName, AccountPermissionManager::GET_ALL_APP_ACCOUNTS);
    if (ret != ERR_OK) {
        return ret;
    }
    ret = GetCallingTokenInfoAndAppIndex(appIndex);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to get app index");
        return ret;
    }
    return innerManager_->GetAllAccessibleAccounts(appAccounts, callingUid, bundleName, appIndex);
}

ErrCode AppAccountManagerService::QueryAllAccessibleAccounts(
    const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode result = GetCallingInfo(callingUid, bundleName, appIndex);
    if (result != ERR_OK) {
        return result;
    }
    if (owner.empty()) {
        return innerManager_->GetAllAccessibleAccounts(appAccounts, callingUid, bundleName, appIndex);
    }
    AppExecFwk::BundleInfo bundleInfo;
    int32_t userId = callingUid / UID_TRANSFORM_DIVISOR;
    bool ret = BundleManagerAdapter::GetInstance()->GetBundleInfo(
        owner, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
    if (!ret) {
        return ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO;
    }
    return innerManager_->GetAllAccounts(owner, appAccounts, callingUid, bundleName, appIndex);
}

ErrCode AppAccountManagerService::CheckAppAccess(
    const std::string &name, const std::string &authorizedApp, bool &isAccessible)
{
    AppAccountCallingInfo appAccountCallingInfo;
    ErrCode result = GetCallingInfo(appAccountCallingInfo.callingUid, appAccountCallingInfo.bundleName,
        appAccountCallingInfo.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    if (authorizedApp == appAccountCallingInfo.bundleName) {
        isAccessible = true;
        return ERR_OK;
    }
    return innerManager_->CheckAppAccess(name, authorizedApp, isAccessible, appAccountCallingInfo);
}

ErrCode AppAccountManagerService::DeleteAccountCredential(
    const std::string &name, const std::string &credentialType)
{
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    return innerManager_->DeleteAccountCredential(name, credentialType, callingUid, bundleName, appIndex);
}

ErrCode AppAccountManagerService::SelectAccountsByOptions(
    const SelectAccountsOptions &options, const sptr<IRemoteObject> &callback)
{
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    auto authenticatorCallback = iface_cast<IAppAccountAuthenticatorCallback>(callback);
    return innerManager_->SelectAccountsByOptions(options, authenticatorCallback, callingUid, bundleName, appIndex);
}

ErrCode AppAccountManagerService::VerifyCredential(const std::string &name, const std::string &owner,
    const VerifyCredentialOptions &options, const sptr<IRemoteObject> &callback)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    request.name = name;
    request.owner = owner;
    request.verifyCredOptions = options;
    request.callback = iface_cast<IAppAccountAuthenticatorCallback>(callback);
    return innerManager_->VerifyCredential(request);
}

ErrCode AppAccountManagerService::CheckAccountLabels(const std::string &name, const std::string &owner,
    const std::vector<std::string> &labels, const sptr<IRemoteObject> &callback)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    request.labels = labels;
    request.callback = iface_cast<IAppAccountAuthenticatorCallback>(callback);
    request.name = name;
    request.owner = owner;
    return innerManager_->CheckAccountLabels(request);
}

ErrCode AppAccountManagerService::SetAuthenticatorProperties(
    const std::string &owner, const SetPropertiesOptions &options, const sptr<IRemoteObject> &callback)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetCallingInfo(request.callerUid, request.callerBundleName, request.appIndex);
    if (result != ERR_OK) {
        return result;
    }
    request.owner = owner;
    request.setPropOptions = options;
    request.callback = iface_cast<IAppAccountAuthenticatorCallback>(callback);
    return innerManager_->SetAuthenticatorProperties(request);
}

ErrCode AppAccountManagerService::SubscribeAppAccount(
    const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
    ErrCode ret = GetCallingInfo(callingUid, bundleName, appIndex);
    if (ret != ERR_OK) {
        return ret;
    }

    std::vector<std::string> owners;
    if (subscribeInfo.GetOwners(owners) != ERR_OK) {
        ACCOUNT_LOGE("failed to get owners");
        return ERR_APPACCOUNT_SERVICE_GET_OWNERS;
    }

    if (owners.size() == 0) {
        ACCOUNT_LOGE("owners size is 0");
        return ERR_APPACCOUNT_SERVICE_OWNERS_SIZE_IS_ZERO;
    }

    int32_t userId = callingUid / UID_TRANSFORM_DIVISOR;
    for (auto owner : owners) {
        AppExecFwk::BundleInfo bundleInfo;
        bool bundleRet = BundleManagerAdapter::GetInstance()->GetBundleInfo(owner,
            AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
        if (!bundleRet) {
            ACCOUNT_LOGE("failed to get bundle info");
            return ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO;
        }
    }

    return innerManager_->SubscribeAppAccount(subscribeInfo, eventListener, callingUid, bundleName, appIndex);
}

ErrCode AppAccountManagerService::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    return innerManager_->UnsubscribeAppAccount(eventListener);
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

    result = permissionManagerPtr_->VerifyPermission(permName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to verify permission for %{public}s, result = %{public}d",
            permName.c_str(), result);
        ReportPermissionFail(callingUid, IPCSkeleton::GetCallingPid(), permName);
        return result;
    }
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetBundleNameAndCallingUid(int32_t &callingUid, std::string &bundleName)
{
    callingUid = IPCSkeleton::GetCallingUid();
    bool bundleRet = BundleManagerAdapter::GetInstance()->GetBundleNameForUid(callingUid, bundleName);
    if (!bundleRet) {
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
    appIndex = hapTokenInfo.instIndex;
    return ERR_OK;
}

ErrCode AppAccountManagerService::GetCallingInfo(int32_t &callingUid, std::string &bundleName, uint32_t &appIndex)
{
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGD("failed to get bundle name");
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

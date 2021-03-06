/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "account_log_wrapper.h"
#include "bundle_manager_adapter.h"
#include "hisysevent_adapter.h"
#include "inner_app_account_manager.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
AppAccountManagerService::AppAccountManagerService()
{
    ACCOUNT_LOGD("enter");

    innerManager_ = std::make_shared<InnerAppAccountManager>();
    permissionManagerPtr_ = DelayedSingleton<AccountPermissionManager>::GetInstance();
#ifdef HAS_CES_PART
    CommonEventCallback callback = {
        std::bind(&AppAccountManagerService::OnPackageRemoved, this, std::placeholders::_1, std::placeholders::_2),
        std::bind(&AppAccountManagerService::OnUserRemoved, this, std::placeholders::_1),
    };
    observer_ = std::make_shared<AppAccountCommonEventObserver>(callback);
#endif // HAS_CES_PART
    ACCOUNT_LOGD("end");
}

AppAccountManagerService::~AppAccountManagerService()
{}

ErrCode AppAccountManagerService::AddAccount(const std::string &name, const std::string &extraInfo)
{
    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->AddAccount(name, extraInfo, callingUid, bundleName);
}

ErrCode AppAccountManagerService::AddAccountImplicitly(const std::string &owner, const std::string &authType,
    const AAFwk::Want &options, const sptr<IRemoteObject> &callback)
{
    AuthenticatorSessionRequest request;
    request.callerPid = IPCSkeleton::GetCallingPid();
    ErrCode result = GetBundleNameAndCallingUid(request.callerUid, request.callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
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

ErrCode AppAccountManagerService::DeleteAccount(const std::string &name)
{
    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->DeleteAccount(name, callingUid, bundleName);
}

ErrCode AppAccountManagerService::GetAccountExtraInfo(const std::string &name, std::string &extraInfo)
{
    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->GetAccountExtraInfo(name, extraInfo, callingUid, bundleName);
}

ErrCode AppAccountManagerService::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo)
{
    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->SetAccountExtraInfo(name, extraInfo, callingUid, bundleName);
}

ErrCode AppAccountManagerService::EnableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    AppExecFwk::BundleInfo bundleInfo;
    int32_t userId = callingUid / UID_TRANSFORM_DIVISOR;
    bool bundleRet = BundleManagerAdapter::GetInstance()->GetBundleInfo(
        authorizedApp, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
    if (!bundleRet) {
        ACCOUNT_LOGE("failed to get bundle info");
        return ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO;
    }

    return innerManager_->EnableAppAccess(name, authorizedApp, callingUid, bundleName);
}

ErrCode AppAccountManagerService::DisableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    AppExecFwk::BundleInfo bundleInfo;
    int32_t userId = callingUid / UID_TRANSFORM_DIVISOR;
    bool bundleRet = BundleManagerAdapter::GetInstance()->GetBundleInfo(
        authorizedApp, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
    if (!bundleRet) {
        ACCOUNT_LOGE("failed to get bundle info");
        return ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO;
    }

    return innerManager_->DisableAppAccess(name, authorizedApp, callingUid, bundleName);
}

ErrCode AppAccountManagerService::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable)
{
    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode ret = GetBundleNameAndCheckPerm(callingUid, bundleName, AccountPermissionManager::DISTRIBUTED_DATASYNC);
    if (ret != ERR_OK) {
        return ret;
    }

    return innerManager_->CheckAppAccountSyncEnable(name, syncEnable, callingUid, bundleName);
}

ErrCode AppAccountManagerService::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable)
{
    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode ret = GetBundleNameAndCheckPerm(callingUid, bundleName, AccountPermissionManager::DISTRIBUTED_DATASYNC);
    if (ret != ERR_OK) {
        return ret;
    }

    return innerManager_->SetAppAccountSyncEnable(name, syncEnable, callingUid, bundleName);
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
    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->SetAssociatedData(name, key, value, callingUid, bundleName);
}

ErrCode AppAccountManagerService::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential)
{
    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->GetAccountCredential(name, credentialType, credential, callingUid, bundleName);
}

ErrCode AppAccountManagerService::SetAccountCredential(
    const std::string &name, const std::string &credentialType, const std::string &credential)
{
    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->SetAccountCredential(name, credentialType, credential, callingUid, bundleName);
}

ErrCode AppAccountManagerService::Authenticate(const std::string &name, const std::string &owner,
    const std::string &authType, const AAFwk::Want &options, const sptr<IRemoteObject> &callback)
{
    AuthenticatorSessionRequest request;
    request.callerPid = IPCSkeleton::GetCallingPid();
    ErrCode result = GetBundleNameAndCallingUid(request.callerUid, request.callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    request.name = name;
    request.owner = owner;
    request.authType = authType;
    request.options = options;
    request.callerAbilityName = options.GetStringParam(Constants::KEY_CALLER_ABILITY_NAME);
    request.callback = iface_cast<IAppAccountAuthenticatorCallback>(callback);
    request.options.RemoveParam(Constants::KEY_CALLER_ABILITY_NAME);
    request.options.SetParam(Constants::KEY_CALLER_PID, request.callerPid);
    request.options.SetParam(Constants::KEY_CALLER_UID, request.callerUid);
    return innerManager_->Authenticate(request);
}

ErrCode AppAccountManagerService::GetOAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetBundleNameAndCallingUid(request.callerUid, request.callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    request.name = name;
    request.owner = owner;
    request.authType = authType;
    return innerManager_->GetOAuthToken(request, token);
}

ErrCode AppAccountManagerService::SetOAuthToken(
    const std::string &name, const std::string &authType, const std::string &token)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetBundleNameAndCallingUid(request.callerUid, request.callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
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
    ErrCode result = GetBundleNameAndCallingUid(request.callerUid, request.callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    request.name = name;
    request.owner = owner;
    request.authType = authType;
    request.token = token;
    return innerManager_->DeleteOAuthToken(request);
}

ErrCode AppAccountManagerService::SetOAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool isVisible)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetBundleNameAndCallingUid(request.callerUid, request.callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    request.name = name;
    request.owner = request.callerBundleName;
    request.authType = authType;
    request.bundleName = bundleName;
    request.isTokenVisible = isVisible;
    return innerManager_->SetOAuthTokenVisibility(request);
}

ErrCode AppAccountManagerService::CheckOAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool &isVisible)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetBundleNameAndCallingUid(request.callerUid, request.callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    request.name = name;
    request.owner = request.callerBundleName;
    request.authType = authType;
    request.bundleName = bundleName;
    return innerManager_->CheckOAuthTokenVisibility(request, isVisible);
}

ErrCode AppAccountManagerService::GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &info)
{
    AuthenticatorSessionRequest request;
    request.callerUid = IPCSkeleton::GetCallingUid();
    request.owner = owner;
    return innerManager_->GetAuthenticatorInfo(request, info);
}

ErrCode AppAccountManagerService::GetAllOAuthTokens(
    const std::string &name, const std::string &owner, std::vector<OAuthTokenInfo> &tokenInfos)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetBundleNameAndCallingUid(request.callerUid, request.callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
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
    ErrCode result = GetBundleNameAndCallingUid(request.callerUid, request.callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    request.name = name;
    request.authType = authType;
    return innerManager_->GetOAuthList(request, oauthList);
}

ErrCode AppAccountManagerService::GetAuthenticatorCallback(
    const std::string &sessionId, sptr<IRemoteObject> &callback)
{
    AuthenticatorSessionRequest request;
    ErrCode result = GetBundleNameAndCallingUid(request.callerUid, request.callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
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
    ErrCode ret = GetBundleNameAndCheckPerm(callingUid, bundleName, AccountPermissionManager::GET_ALL_APP_ACCOUNTS);
    if (ret != ERR_OK) {
        return ret;
    }

    AppExecFwk::BundleInfo bundleInfo;
    int32_t userId = callingUid / UID_TRANSFORM_DIVISOR;
    bool result = BundleManagerAdapter::GetInstance()->GetBundleInfo(
        owner, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
    if (!result) {
        ACCOUNT_LOGE("failed to get bundle info");
        return ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO;
    }

    return innerManager_->GetAllAccounts(owner, appAccounts, callingUid, bundleName);
}

ErrCode AppAccountManagerService::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts)
{
    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode ret = GetBundleNameAndCheckPerm(callingUid, bundleName, AccountPermissionManager::GET_ALL_APP_ACCOUNTS);
    if (ret != ERR_OK) {
        return ret;
    }

    return innerManager_->GetAllAccessibleAccounts(appAccounts, callingUid, bundleName);
}

ErrCode AppAccountManagerService::CheckAppAccess(
    const std::string &name, const std::string &authorizedApp, bool &isAccessible)
{
    ACCOUNT_LOGD("enter");
    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    return innerManager_->CheckAppAccess(name, authorizedApp, isAccessible, callingUid, bundleName);
}

ErrCode AppAccountManagerService::DeleteAccountCredential(
    const std::string &name, const std::string &credentialType)
{
    ACCOUNT_LOGD("enter");
    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    return innerManager_->DeleteAccountCredential(name, credentialType, callingUid, bundleName);
}

ErrCode AppAccountManagerService::SelectAccountsByOptions(
    const SelectAccountsOptions &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGD("enter");
    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    auto authenticatorCallback = iface_cast<IAppAccountAuthenticatorCallback>(callback);
    return innerManager_->SelectAccountsByOptions(options, authenticatorCallback, callingUid, bundleName);
}

ErrCode AppAccountManagerService::VerifyCredential(const std::string &name, const std::string &owner,
    const VerifyCredentialOptions &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGD("enter");
    AuthenticatorSessionRequest request;
    ErrCode result = GetBundleNameAndCallingUid(request.callerUid, request.callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
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
    ACCOUNT_LOGD("enter");
    AuthenticatorSessionRequest request;
    ErrCode result = GetBundleNameAndCallingUid(request.callerUid, request.callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    request.name = name;
    request.owner = owner;
    request.labels = labels;
    request.callback = iface_cast<IAppAccountAuthenticatorCallback>(callback);
    return innerManager_->CheckAccountLabels(request);
}

ErrCode AppAccountManagerService::SetAuthenticatorProperties(
    const std::string &owner, const SetPropertiesOptions &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGD("enter");
    AuthenticatorSessionRequest request;
    ErrCode result = GetBundleNameAndCallingUid(request.callerUid, request.callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
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
    ACCOUNT_LOGD("enter");

    int32_t callingUid = -1;
    std::string bundleName;
    ErrCode result = GetBundleNameAndCallingUid(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
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

    return innerManager_->SubscribeAppAccount(subscribeInfo, eventListener, callingUid, bundleName);
}

ErrCode AppAccountManagerService::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    return innerManager_->UnsubscribeAppAccount(eventListener);
}

ErrCode AppAccountManagerService::OnPackageRemoved(const uid_t &uid, const std::string &bundleName)
{
    return innerManager_->OnPackageRemoved(uid, bundleName);
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
}  // namespace AccountSA
}  // namespace OHOS

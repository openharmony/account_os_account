/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "account_log_wrapper.h"
#include "inner_app_account_manager.h"
#include "ipc_skeleton.h"

#include "app_account_manager_service.h"

namespace OHOS {
namespace AccountSA {
AppAccountManagerService::AppAccountManagerService()
{
    ACCOUNT_LOGI("enter");

    innerManager_ = std::make_shared<InnerAppAccountManager>();
    permissionManagerPtr_ = DelayedSingleton<AccountPermissionManager>::GetInstance();
    bundleManagerPtr_ = DelayedSingleton<AccountBundleManager>::GetInstance();

    CommonEventCallback callback = {
        std::bind(&AppAccountManagerService::OnPackageRemoved, this, std::placeholders::_1, std::placeholders::_2),
    };
    oberserver_ = std::make_shared<AppAccountCommonEventOberserver>(callback);

    ACCOUNT_LOGI("end");
}

AppAccountManagerService::~AppAccountManagerService()
{}

ErrCode AppAccountManagerService::AddAccount(const std::string &name, const std::string &extraInfo)
{
    ACCOUNT_LOGI("enter, name = %{public}s, extraInfo = %{public}s.", name.c_str(), extraInfo.c_str());

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName;

    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->AddAccount(name, extraInfo, callingUid, bundleName);
}

ErrCode AppAccountManagerService::AddAccountImplicitly(
    const std::string &owner, const std::string &authType, const AAFwk::WantParams &options,
    const sptr<IRemoteObject> &callback, const std::string &abilityName)
{
    ACCOUNT_LOGI("enter");
    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string callerBundleName;
    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    OAuthRequest request = {
        .owner = owner,
        .authType = authType,
        .callerBundleName = callerBundleName,
        .callerAbilityName = abilityName,
        .callerUid = callingUid,
        .options = options,
        .callback = iface_cast<IAppAccountAuthenticatorCallback>(callback)
    };
    return innerManager_->AddAccountImplicitly(request);
}

ErrCode AppAccountManagerService::DeleteAccount(const std::string &name)
{
    ACCOUNT_LOGI("enter, name = %{public}s", name.c_str());

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName;

    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->DeleteAccount(name, callingUid, bundleName);
}

ErrCode AppAccountManagerService::GetAccountExtraInfo(const std::string &name, std::string &extraInfo)
{
    ACCOUNT_LOGI("enter, name = %{public}s", name.c_str());

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName;

    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->GetAccountExtraInfo(name, extraInfo, callingUid, bundleName);
}

ErrCode AppAccountManagerService::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo)
{
    ACCOUNT_LOGI("enter, name = %{public}s, extraInfo = %{public}s.", name.c_str(), extraInfo.c_str());

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName;

    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->SetAccountExtraInfo(name, extraInfo, callingUid, bundleName);
}

ErrCode AppAccountManagerService::EnableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    ACCOUNT_LOGI("enter, name = %{public}s, authorizedApp = %{public}s", name.c_str(), authorizedApp.c_str());

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName;

    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    AppExecFwk::BundleInfo bundleInfo;
    result = bundleManagerPtr_->GetBundleInfo(authorizedApp, bundleInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle info");
        return result;
    }

    return innerManager_->EnableAppAccess(name, authorizedApp, callingUid, bundleName);
}

ErrCode AppAccountManagerService::DisableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    ACCOUNT_LOGI("enter, name = %{public}s, authorizedApp = %{public}s.", name.c_str(), authorizedApp.c_str());

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName;

    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    AppExecFwk::BundleInfo bundleInfo;
    result = bundleManagerPtr_->GetBundleInfo(authorizedApp, bundleInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle info");
        return result;
    }

    return innerManager_->DisableAppAccess(name, authorizedApp, callingUid, bundleName);
}

ErrCode AppAccountManagerService::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable)
{
    ACCOUNT_LOGI("enter, name = %{public}s, syncEnable = %{public}d", name.c_str(), syncEnable);

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName;

    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    result = permissionManagerPtr_->VerifyPermission(AccountPermissionManager::DISTRIBUTED_DATASYNC);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
        return result;
    }

    return innerManager_->CheckAppAccountSyncEnable(name, syncEnable, callingUid, bundleName);
}

ErrCode AppAccountManagerService::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable)
{
    ACCOUNT_LOGI("enter, name = %{public}s, syncEnable = %{public}d", name.c_str(), syncEnable);

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName;

    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    result = permissionManagerPtr_->VerifyPermission(AccountPermissionManager::DISTRIBUTED_DATASYNC);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
        return result;
    }

    return innerManager_->SetAppAccountSyncEnable(name, syncEnable, callingUid, bundleName);
}

ErrCode AppAccountManagerService::GetAssociatedData(
    const std::string &name, const std::string &key, std::string &value)
{
    ACCOUNT_LOGI("enter, name = %{public}s, key = %{public}s", name.c_str(), key.c_str());

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName;

    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->GetAssociatedData(name, key, value, callingUid, bundleName);
}

ErrCode AppAccountManagerService::SetAssociatedData(
    const std::string &name, const std::string &key, const std::string &value)
{
    ACCOUNT_LOGI("enter, name = %{public}s, key = %{public}s, value = %{public}s",
        name.c_str(), key.c_str(), value.c_str());

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName;

    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->SetAssociatedData(name, key, value, callingUid, bundleName);
}

ErrCode AppAccountManagerService::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential)
{
    ACCOUNT_LOGI("enter, name = %{public}s, credentialType = %{public}s.", name.c_str(), credentialType.c_str());

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName;

    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->GetAccountCredential(name, credentialType, credential, callingUid, bundleName);
}

ErrCode AppAccountManagerService::SetAccountCredential(
    const std::string &name, const std::string &credentialType, const std::string &credential)
{
    ACCOUNT_LOGI("enter, name = %{public}s, credentialType = %{public}s.", name.c_str(), credentialType.c_str());

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName;

    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->SetAccountCredential(name, credentialType, credential, callingUid, bundleName);
}

ErrCode AppAccountManagerService::Authenticate(OAuthRequest &request)
{
    ACCOUNT_LOGI("enter, name=%{public}s, owner=%{public}s, authType=%{public}s",
        request.name.c_str(), request.owner.c_str(), request.authType.c_str());
    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string callerBundleName;
    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    request.callerBundleName = callerBundleName;
    request.callerUid = callingUid;
    return innerManager_->Authenticate(request);
}

ErrCode AppAccountManagerService::GetOAuthToken(const std::string &name, const std::string &owner,
    const std::string &authType, std::string &token)
{
    ACCOUNT_LOGI("enter, name = %{public}s, owner=%{public}s", name.c_str(), owner.c_str());
    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string callerBundleName;
    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    OAuthRequest request = {
        .name = name,
        .owner = owner,
        .authType = authType,
        .callerBundleName = callerBundleName,
        .callerUid = callingUid
    };
    return innerManager_->GetOAuthToken(request, token);
}

ErrCode AppAccountManagerService::SetOAuthToken(
    const std::string &name, const std::string &authType, const std::string &token)
{
    ACCOUNT_LOGI("enter, name=%{public}s, authType=%{public}s", name.c_str(), authType.c_str());
    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string callerBundleName;
    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    OAuthRequest request = {
        .name = name,
        .owner = callerBundleName,
        .authType = authType,
        .token = token,
        .callerBundleName = callerBundleName,
        .callerUid = callingUid
    };
    return innerManager_->SetOAuthToken(request);
}

ErrCode AppAccountManagerService::DeleteOAuthToken(const std::string &name, const std::string &owner,
    const std::string &authType, const std::string &token)
{
    ACCOUNT_LOGI("enter, name=%{public}s, owner=%{public}s, authType=%{public}s",
        name.c_str(), owner.c_str(), authType.c_str());
    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string callerBundleName;
    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    OAuthRequest request = {
        .name = name,
        .owner = owner,
        .authType = authType,
        .token = token,
        .callerBundleName = callerBundleName,
        .callerUid = callingUid
    };
    return innerManager_->DeleteOAuthToken(request);
}

ErrCode AppAccountManagerService::SetOAuthTokenVisibility(const std::string &name, const std::string &authType,
    const std::string &bundleName, bool isVisible)
{
    ACCOUNT_LOGI("enter, name=%{public}s, authType=%{public}s, bundleName=%{public}s, isVisible=%{public}d",
        name.c_str(), authType.c_str(), bundleName.c_str(), isVisible);
    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string callerBundleName;
    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    OAuthRequest request = {
        .name = name,
        .owner = callerBundleName,
        .authType = authType,
        .bundleName = bundleName,
        .callerBundleName = callerBundleName,
        .isTokenVisible = isVisible,
        .callerUid = callingUid
    };
    return innerManager_->SetOAuthTokenVisibility(request);
}

ErrCode AppAccountManagerService::CheckOAuthTokenVisibility(const std::string &name, const std::string &authType,
    const std::string &bundleName, bool &isVisible)
{
    ACCOUNT_LOGI("enter, name=%{public}s, authType=%{public}s, bundleName=%{public}s",
        name.c_str(), authType.c_str(), bundleName.c_str());
    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string callerBundleName;
    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    OAuthRequest request = {
        .name = name,
        .owner = callerBundleName,
        .authType = authType,
        .bundleName = bundleName,
        .callerBundleName = callerBundleName,
        .callerUid = callingUid
    };
    return innerManager_->CheckOAuthTokenVisibility(request, isVisible);
}

ErrCode AppAccountManagerService::GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &info)
{
    ACCOUNT_LOGI("enter, owner=%{public}s", owner.c_str());
    auto callingUid = IPCSkeleton::GetCallingUid();
    OAuthRequest request = {
        .owner = owner,
        .callerUid = callingUid
    };
    return innerManager_->GetAuthenticatorInfo(request, info);
}

ErrCode AppAccountManagerService::GetAllOAuthTokens(
    const std::string &name, const std::string &owner, std::vector<OAuthTokenInfo> &tokenInfos)
{
    ACCOUNT_LOGI("enter, name=%{public}s, owner=%{public}s", name.c_str(), owner.c_str());
    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string callerBundleName;
    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    OAuthRequest request = {
        .name = name,
        .owner = owner,
        .callerBundleName = callerBundleName,
        .callerUid = callingUid
    };
    return innerManager_->GetAllOAuthTokens(request, tokenInfos);
}

ErrCode AppAccountManagerService::GetOAuthList(
    const std::string &name, const std::string &authType, std::set<std::string> &oauthList)
{
    ACCOUNT_LOGI("enter, name=%{public}s, authType=%{public}s", name.c_str(), authType.c_str());
    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string callerBundleName;
    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    OAuthRequest request = {
        .name = name,
        .authType = authType,
        .callerBundleName = callerBundleName,
        .callerUid = callingUid
    };
    return innerManager_->GetOAuthList(request, oauthList);
}

ErrCode AppAccountManagerService::GetAuthenticatorCallback(
    const std::string &sessionId, sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("enter");
    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string callerBundleName;
    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, callerBundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }
    OAuthRequest request = {
        .sessionId = sessionId,
        .callerBundleName = callerBundleName,
        .callerUid = callingUid
    };
    result = innerManager_->GetAuthenticatorCallback(request, callback);
    ACCOUNT_LOGI("end");
    return result;
}

ErrCode AppAccountManagerService::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGI("enter, owner = %{public}s", owner.c_str());

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName;

    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    result = permissionManagerPtr_->VerifyPermission(AccountPermissionManager::GET_ACCOUNTS_PRIVILEGED);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to verify permission for GET_ACCOUNTS_PRIVILEGED, result = %{public}d", result);
        return result;
    }

    AppExecFwk::BundleInfo bundleInfo;
    result = bundleManagerPtr_->GetBundleInfo(owner, bundleInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle info");
        return result;
    }

    return innerManager_->GetAllAccounts(owner, appAccounts, callingUid, bundleName);
}

ErrCode AppAccountManagerService::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGI("enter");

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName;

    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    result = permissionManagerPtr_->VerifyPermission(AccountPermissionManager::GET_ACCOUNTS_PRIVILEGED);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to verify permission for GET_ACCOUNTS_PRIVILEGED, result = %{public}d", result);
        return result;
    }

    return innerManager_->GetAllAccessibleAccounts(appAccounts, callingUid, bundleName);
}

ErrCode AppAccountManagerService::SubscribeAppAccount(
    const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName;

    ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
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

    for (auto owner : owners) {
        AppExecFwk::BundleInfo bundleInfo;
        result = bundleManagerPtr_->GetBundleInfo(owner, bundleInfo);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle info");
            return result;
        }
    }

    return innerManager_->SubscribeAppAccount(subscribeInfo, eventListener, callingUid, bundleName);
}

ErrCode AppAccountManagerService::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");

    return innerManager_->UnsubscribeAppAccount(eventListener);
}

ErrCode AppAccountManagerService::OnPackageRemoved(const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, uid = %{public}d, bundleName = %{public}s.", uid, bundleName.c_str());

    return innerManager_->OnPackageRemoved(uid, bundleName);
}
}  // namespace AccountSA
}  // namespace OHOS

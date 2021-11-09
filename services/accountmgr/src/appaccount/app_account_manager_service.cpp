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
#include "account_permission_manager.h"
#include "app_account_bundle_manager.h"
#include "app_account_stub.h"
#include "bundle_constants.h"
#include "inner_app_account_manager.h"

#include "app_account_manager_service.h"

namespace OHOS {
namespace AccountSA {
AppAccountManagerService::AppAccountManagerService()
{
    ACCOUNT_LOGI("enter");

    innerManager_ = std::make_shared<InnerAppAccountManager>();

    CommonEventCallback callback = {
        std::bind(&AppAccountManagerService::OnPackageRemoved, this, std::placeholders::_1),
    };
    oberserver_ = std::make_shared<AppAccountCommonEventOberserver>(callback);

    ACCOUNT_LOGI("end");
}

AppAccountManagerService::~AppAccountManagerService()
{
    ACCOUNT_LOGI("enter");
}

ErrCode AppAccountManagerService::AddAccount(const std::string &name, const std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("extraInfo = %{public}s", extraInfo.c_str());

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    ErrCode result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->AddAccount(name, extraInfo, bundleName);
}

ErrCode AppAccountManagerService::DeleteAccount(const std::string &name)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    ErrCode result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->DeleteAccount(name, bundleName);
}

ErrCode AppAccountManagerService::GetAccountExtraInfo(const std::string &name, std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("extraInfo = %{public}s", extraInfo.c_str());

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    ErrCode result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->GetAccountExtraInfo(name, extraInfo, bundleName);
}

ErrCode AppAccountManagerService::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("extraInfo = %{public}s", extraInfo.c_str());

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    ErrCode result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->SetAccountExtraInfo(name, extraInfo, bundleName);
}

ErrCode AppAccountManagerService::EnableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("authorizedApp = %{public}s", authorizedApp.c_str());

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    ErrCode result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->EnableAppAccess(name, authorizedApp, bundleName);
}

ErrCode AppAccountManagerService::DisableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("authorizedApp = %{public}s", authorizedApp.c_str());

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    ErrCode result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->DisableAppAccess(name, authorizedApp, bundleName);
}

ErrCode AppAccountManagerService::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("syncEnable = %{public}d", syncEnable);

    auto permissionManagerPtr = DelayedSingleton<AccountPermissionManager>::GetInstance();
    ErrCode result = permissionManagerPtr->VerifyPermission(AccountPermissionManager::DISTRIBUTED_DATASYNC);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
        return result;
    }

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->CheckAppAccountSyncEnable(name, syncEnable, bundleName);
}

ErrCode AppAccountManagerService::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("syncEnable = %{public}d", syncEnable);

    auto permissionManagerPtr = DelayedSingleton<AccountPermissionManager>::GetInstance();
    ErrCode result = permissionManagerPtr->VerifyPermission(AccountPermissionManager::DISTRIBUTED_DATASYNC);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
        return result;
    }

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->SetAppAccountSyncEnable(name, syncEnable, bundleName);
}

ErrCode AppAccountManagerService::GetAssociatedData(const std::string &name, const std::string &key, std::string &value)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("key = %{public}s", key.c_str());

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    ErrCode result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->GetAssociatedData(name, key, value, bundleName);
}

ErrCode AppAccountManagerService::SetAssociatedData(
    const std::string &name, const std::string &key, const std::string &value)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("key = %{public}s, value = %{public}s", key.c_str(), value.c_str());

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    ErrCode result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->SetAssociatedData(name, key, value, bundleName);
}

ErrCode AppAccountManagerService::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("credentialType = %{public}s", credentialType.c_str());

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    ErrCode result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->GetAccountCredential(name, credentialType, credential, bundleName);
}

ErrCode AppAccountManagerService::SetAccountCredential(
    const std::string &name, const std::string &credentialType, const std::string &credential)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("credentialType = %{public}s, credential = %{public}s", credentialType.c_str(), credential.c_str());

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    ErrCode result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->SetAccountCredential(name, credentialType, credential, bundleName);
}

ErrCode AppAccountManagerService::GetOAuthToken(const std::string &name, std::string &token)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("token = %{public}s", token.c_str());

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    ErrCode result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->GetOAuthToken(name, token, bundleName);
}

ErrCode AppAccountManagerService::SetOAuthToken(const std::string &name, const std::string &token)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("token = %{public}s", token.c_str());

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    ErrCode result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->SetOAuthToken(name, token, bundleName);
}

ErrCode AppAccountManagerService::ClearOAuthToken(const std::string &name)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    ErrCode result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->ClearOAuthToken(name, bundleName);
}

ErrCode AppAccountManagerService::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("owner = %{public}s", owner.c_str());

    auto permissionManagerPtr = DelayedSingleton<AccountPermissionManager>::GetInstance();
    ErrCode result = permissionManagerPtr->VerifyPermission(AccountPermissionManager::GET_ACCOUNTS_PRIVILEGED);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to verify permission for GET_ACCOUNTS_PRIVILEGED, result = %{public}d", result);
        return result;
    }

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->GetAllAccounts(owner, appAccounts, bundleName);
}

ErrCode AppAccountManagerService::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGI("enter");

    auto permissionManagerPtr = DelayedSingleton<AccountPermissionManager>::GetInstance();
    ErrCode result = permissionManagerPtr->VerifyPermission(AccountPermissionManager::GET_ACCOUNTS_PRIVILEGED);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to verify permission for GET_ACCOUNTS_PRIVILEGED, result = %{public}d", result);
        return result;
    }

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->GetAllAccessibleAccounts(appAccounts, bundleName);
}

ErrCode AppAccountManagerService::SubscribeAppAccount(
    const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");

    std::string bundleName;
    auto bundleManagerPtr = DelayedSingleton<AppAccountBundleManager>::GetInstance();

    ErrCode result = bundleManagerPtr->GetBundleName(bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get bundle name");
        return result;
    }

    return innerManager_->SubscribeAppAccount(subscribeInfo, eventListener, bundleName);
}

ErrCode AppAccountManagerService::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");

    return innerManager_->UnsubscribeAppAccount(eventListener);
}

ErrCode AppAccountManagerService::OnPackageRemoved(const CommonEventData &data)
{
    ACCOUNT_LOGI("enter");

    auto want = data.GetWant();
    std::string action = want.GetAction();
    auto element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    auto uid = want.GetIntParam(AppExecFwk::Constants::UID, -1);

    ACCOUNT_LOGI("uid = %{public}d", uid);
    ACCOUNT_LOGI("bundleName = %{public}s", bundleName.c_str());

    return innerManager_->OnPackageRemoved(uid, bundleName);
}
}  // namespace AccountSA
}  // namespace OHOS

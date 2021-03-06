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

#include "app_account_control_manager.h"

#include "account_log_wrapper.h"
#include "app_account_app_state_observer.h"
#include "app_account_check_labels_session.h"
#include "app_account_data_storage.h"
#include "app_account_info.h"
#include "app_account_subscribe_manager.h"
#include "bundle_manager_adapter.h"
#include "hitrace_adapter.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "ohos_account_kits.h"
#include "singleton.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
AppAccountControlManager::AppAccountControlManager()
{
    ACCOUNT_LOGD("enter");
}

ErrCode AppAccountControlManager::AddAccount(const std::string &name, const std::string &extraInfo, const uid_t &uid,
    const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(uid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);

        result = appAccountInfo.SetExtraInfo(extraInfo);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to set extra info, result %{public}d.", result);
            return ERR_APPACCOUNT_SERVICE_SET_EXTRA_INFO;
        }

        result = AddAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, uid);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to add account info into data storage, result %{public}d.", result);
            return result;
        }
    } else {
        ACCOUNT_LOGE("add existing account");
        return ERR_APPACCOUNT_SERVICE_ADD_EXISTING_ACCOUNT;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::DeleteAccount(
    const std::string &name, const uid_t &uid, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(uid);
    ErrCode result = DeleteAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to delete account info from data storage, result %{public}d.", result);
        return result;
    }

    std::set<std::string> authorizedApps;
    appAccountInfo.GetAuthorizedApps(authorizedApps);
    for (auto authorizedApp : authorizedApps) {
        // remove authorized account from data storage
        result = RemoveAuthorizedAccount(authorizedApp, appAccountInfo, dataStoragePtr, uid);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to save authorized account into data storage, result %{public}d.", result);
            return result;
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAccountExtraInfo(
    const std::string &name, std::string &extraInfo, const uid_t &uid, const std::string &bundleName)
{
    AppAccountInfo appAccountInfo(name, bundleName);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(uid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }

    result = appAccountInfo.GetExtraInfo(extraInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get extra info, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_GET_EXTRA_INFO;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo,
    const uid_t &uid, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(uid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }

    result = appAccountInfo.SetExtraInfo(extraInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to set extra info, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_SET_EXTRA_INFO;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return result;
    }

    ACCOUNT_LOGD("end, result = %{public}d", result);

    return result;
}

ErrCode AppAccountControlManager::EnableAppAccess(const std::string &name, const std::string &authorizedApp,
    const uid_t &uid, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    if (authorizedApp == bundleName) {
        ACCOUNT_LOGE("authorizedApp is the same to owner");
        return ERR_APPACCOUNT_SERVICE_BUNDLE_NAME_IS_THE_SAME;
    }

    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(uid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }

    result = appAccountInfo.EnableAppAccess(authorizedApp);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to enable app access, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ENABLE_APP_ACCESS_ALREADY_EXISTS;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return result;
    }

    // save authorized account into data storage
    result = SaveAuthorizedAccount(authorizedApp, appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save authorized account into data storage, result %{public}d.", result);
        return result;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::DisableAppAccess(const std::string &name, const std::string &authorizedApp,
    const uid_t &uid, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(uid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }

    result = appAccountInfo.DisableAppAccess(authorizedApp);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to disable app access, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_DISABLE_APP_ACCESS_NOT_EXISTED;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return result;
    }

    // remove authorized account from data storage
    result = RemoveAuthorizedAccount(authorizedApp, appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save authorized account into data storage, result %{public}d.", result);
        return result;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::CheckAppAccess(const std::string &name, const std::string &authorizedApp,
    bool &isAccessible, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");
    isAccessible = false;
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(uid);
    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    return appAccountInfo.CheckAppAccess(authorizedApp, isAccessible);
}

ErrCode AppAccountControlManager::CheckAppAccountSyncEnable(
    const std::string &name, bool &syncEnable, const uid_t &uid, const std::string &bundleName)
{
    AppAccountInfo appAccountInfo(name, bundleName);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(uid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }

    result = appAccountInfo.GetSyncEnable(syncEnable);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get sync enable, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_GET_SYNC_ENABLE;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable,
    const uid_t &uid, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(uid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }

    result = appAccountInfo.SetSyncEnable(syncEnable);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to set sync enable, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_GET_SYNC_ENABLE;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return result;
    }

    return ERR_OK;
}

void AppAccountControlManager::PopDataFromAssociatedDataCache()
{
    auto it = associatedDataCache_.begin();
    auto toPopedIt = it++;
    for (; it != associatedDataCache_.end(); ++it) {
        if (toPopedIt->second.freq > it->second.freq) {
            toPopedIt = it;
        }
        it->second.freq = 0;
    }
    associatedDataCache_.erase(toPopedIt);
}

ErrCode AppAccountControlManager::GetAssociatedDataFromStorage(const std::string &name, const std::string &key,
    std::string &value, const uid_t &uid)
{
    ACCOUNT_LOGD("enter");
    std::string bundleName;
    if (!BundleManagerAdapter::GetInstance()->GetBundleNameForUid(uid, bundleName)) {
        ACCOUNT_LOGD("failed to get bundle name");
        return ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME;
    }
    AppAccountInfo appAccountInfo(name, bundleName);
    std::shared_ptr<AppAccountDataStorage> storePtr = GetDataStorage(uid);
    if (storePtr == nullptr) {
        ACCOUNT_LOGD("failed to get data storage");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, storePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGD("failed to get account info from data storage");
        return result;
    }
    AssociatedDataCacheItem item;
    item.name = name;
    item.freq = 0;
    appAccountInfo.GetAllAssociatedData(item.data);
    auto it = item.data.find(key);
    if (it != item.data.end()) {
        value = it->second;
    } else {
        ACCOUNT_LOGD("key not exists");
        result = ERR_APPACCOUNT_SERVICE_ASSOCIATED_DATA_KEY_NOT_EXIST;
    }
    if ((associatedDataCache_.size() == 0) && (!RegisterApplicationStateObserver())) {
        ACCOUNT_LOGD("failed to register application state observer");
        return result;
    }
    if (associatedDataCache_.size() >= ASSOCIATED_DATA_CACHE_MAX_SIZE) {
        PopDataFromAssociatedDataCache();
    }
    associatedDataCache_.emplace(uid, item);
    return result;
}

ErrCode AppAccountControlManager::GetAssociatedData(const std::string &name, const std::string &key,
    std::string &value, const uid_t &uid)
{
    ACCOUNT_LOGD("enter");
    std::lock_guard<std::mutex> lock(associatedDataMutex_);
    auto it = associatedDataCache_.find(uid);
    if ((it == associatedDataCache_.end()) || (it->second.name != name)) {
        associatedDataCache_.erase(uid);
        return GetAssociatedDataFromStorage(name, key, value, uid);
    }
    it->second.freq++;
    auto dataIt = it->second.data.find(key);
    if (dataIt == it->second.data.end()) {
        return ERR_APPACCOUNT_SERVICE_ASSOCIATED_DATA_KEY_NOT_EXIST;
    }
    value = dataIt->second;
    return ERR_OK;
}

ErrCode AppAccountControlManager::SetAssociatedData(const std::string &name, const std::string &key,
    const std::string &value, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGD("enter");
    std::shared_ptr<AppAccountDataStorage> storePtr = GetDataStorage(uid);
    AppAccountInfo appAccountInfo(name, bundleName);
    std::lock_guard<std::mutex> lock(associatedDataMutex_);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, storePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGD("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }
    result = appAccountInfo.SetAssociatedData(key, value);
    if (result != ERR_OK) {
        ACCOUNT_LOGD("failed to set associated data, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_SET_ASSOCIATED_DATA;
    }
    result = SaveAccountInfoIntoDataStorage(appAccountInfo, storePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGD("failed to save account info into data storage, result %{public}d.", result);
        return result;
    }
    auto it = associatedDataCache_.find(uid);
    if ((it != associatedDataCache_.end()) && (it->second.name == name)) {
        it->second.data[key] = value;
    }
    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAccountCredential(const std::string &name, const std::string &credentialType,
    std::string &credential, const uid_t &uid, const std::string &bundleName)
{
    AppAccountInfo appAccountInfo(name, bundleName);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(uid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }

    result = appAccountInfo.GetAccountCredential(credentialType, credential);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account credential, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_CREDENTIAL;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SetAccountCredential(const std::string &name, const std::string &credentialType,
    const std::string &credential, const uid_t &uid, const std::string &bundleName, bool isDelete)
{
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(uid);
    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }

    result = appAccountInfo.SetAccountCredential(credentialType, credential, isDelete);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to set account credential, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_SET_ACCOUNT_CREDENTIAL;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return result;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetOAuthToken(const AuthenticatorSessionRequest &request, std::string &token)
{
    AppAccountInfo appAccountInfo(request.name, request.owner);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    bool isVisible = false;
    result = appAccountInfo.CheckOAuthTokenVisibility(request.authType, request.callerBundleName, isVisible);
    if ((result != ERR_OK) || (!isVisible)) {
        ACCOUNT_LOGE("failed to get oauth token for permission denied, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED;
    }
    return appAccountInfo.GetOAuthToken(request.authType, token);
}

ErrCode AppAccountControlManager::SetOAuthToken(const AuthenticatorSessionRequest &request)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AppAccountInfo appAccountInfo(request.name, request.callerBundleName);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    result = appAccountInfo.SetOAuthToken(request.authType, request.token);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to set oauth token, result %{public}d.", result);
        return result;
    }
    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_SAVE_ACCOUNT_INFO;
    }
    return ERR_OK;
}

ErrCode AppAccountControlManager::DeleteOAuthToken(const AuthenticatorSessionRequest &request)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AppAccountInfo appAccountInfo(request.name, request.owner);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    bool isVisible = false;
    result = appAccountInfo.CheckOAuthTokenVisibility(request.authType, request.callerBundleName, isVisible);
    if ((!isVisible) || (result != ERR_OK)) {
        ACCOUNT_LOGE("failed to delete oauth token for permission denied, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED;
    }
    result = appAccountInfo.DeleteOAuthToken(request.authType, request.token);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to delete oauth token, result %{public}d.", result);
        return ERR_OK;
    }
    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_SAVE_ACCOUNT_INFO;
    }
    return ERR_OK;
}

ErrCode AppAccountControlManager::SetOAuthTokenVisibility(const AuthenticatorSessionRequest &request)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AppAccountInfo appAccountInfo(request.name, request.callerBundleName);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    result = appAccountInfo.SetOAuthTokenVisibility(request.authType, request.bundleName, request.isTokenVisible);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to set oauth token visibility, result %{public}d.", result);
        return result;
    }
    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_SAVE_ACCOUNT_INFO;
    }
    return ERR_OK;
}

ErrCode AppAccountControlManager::CheckOAuthTokenVisibility(const AuthenticatorSessionRequest &request, bool &isVisible)
{
    isVisible = false;
    AppAccountInfo appAccountInfo(request.name, request.owner);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    return appAccountInfo.CheckOAuthTokenVisibility(request.authType, request.bundleName, isVisible);
}

ErrCode AppAccountControlManager::GetAllOAuthTokens(
    const AuthenticatorSessionRequest &request, std::vector<OAuthTokenInfo> &tokenInfos)
{
    tokenInfos.clear();
    AppAccountInfo appAccountInfo(request.name, request.owner);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    std::vector<OAuthTokenInfo> allTokenInfos;
    result = appAccountInfo.GetAllOAuthTokens(allTokenInfos);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get all oauth token from data storage, result %{public}d.", result);
        return result;
    }
    if (request.callerBundleName == request.owner) {
        tokenInfos = allTokenInfos;
        return ERR_OK;
    }
    for (auto tokenInfo : allTokenInfos) {
        if (tokenInfo.token.empty()) {
            continue;
        }
        auto it = tokenInfo.authList.find(request.callerBundleName);
        if (it != tokenInfo.authList.end()) {
            tokenInfo.authList.clear();
            tokenInfos.push_back(tokenInfo);
        }
    }
    return ERR_OK;
}

ErrCode AppAccountControlManager::GetOAuthList(
    const AuthenticatorSessionRequest &request, std::set<std::string> &oauthList)
{
    AppAccountInfo appAccountInfo(request.name, request.callerBundleName);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    return appAccountInfo.GetOAuthList(request.authType, oauthList);
}

ErrCode AppAccountControlManager::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts,
    const uid_t &uid, const std::string &bundleName)
{
    appAccounts.clear();

    auto dataStoragePtr = GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    ErrCode result = GetAllAccountsFromDataStorage(owner, appAccounts, bundleName, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get all accounts from data storage, result = %{public}d", result);
        return result;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAllAccessibleAccounts(
    std::vector<AppAccountInfo> &appAccounts, const uid_t &uid, const std::string &bundleName)
{
    appAccounts.clear();

    auto dataStoragePtr = GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::vector<std::string> accessibleAccounts;
    ErrCode result = dataStoragePtr->GetAccessibleAccountsFromDataStorage(bundleName, accessibleAccounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get accessible account from data storage, result %{public}d.", result);
        return result;
    }

    for (auto account : accessibleAccounts) {
        AppAccountInfo appAccountInfo;

        result = dataStoragePtr->GetAccountInfoById(account, appAccountInfo);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get account info by id, result %{public}d.", result);
            return ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID;
        }

        appAccounts.emplace_back(appAccountInfo);
    }

    std::vector<AppAccountInfo> currentAppAccounts;

    result = GetAllAccountsFromDataStorage(bundleName, currentAppAccounts, bundleName, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get all accounts from data storage, result = %{public}d", result);
        return result;
    }

    for (auto account : currentAppAccounts) {
        appAccounts.emplace_back(account);
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SelectAccountsByOptions(
    const SelectAccountsOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback,
    const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGD("enter");
    AAFwk::Want result;
    if ((!options.hasAccounts) && (!options.hasOwners) && (!options.hasLabels)) {
        callback->OnResult(ERR_JS_SUCCESS, result);
        return ERR_OK;
    }
    std::set<std::string> allowedAccounts;
    for (auto account : options.allowedAccounts) {
        allowedAccounts.emplace(account.first + "_" + account.second);
    }
    std::set<std::string> allowedOwners(options.allowedOwners.begin(), options.allowedOwners.end());
    std::vector<AppAccountInfo> accessibleAccounts;
    ErrCode errCode = GetAllAccessibleAccounts(accessibleAccounts, uid, bundleName);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGD("failed to get all accessible accounts");
        return errCode;
    }
    std::vector<AppAccountInfo> candidateAccounts;
    for (auto account : accessibleAccounts) {
        std::string owner = account.GetOwner();
        if (options.hasOwners && allowedOwners.count(owner) == 0) {
            continue;
        }
        if (options.hasAccounts && allowedAccounts.count(owner + "_" + account.GetName()) == 0) {
            continue;
        }
        candidateAccounts.push_back(account);
    }
    if (options.requiredLabels.size() == 0) {
        std::vector<std::string> names;
        std::vector<std::string> owners;
        for (auto account : candidateAccounts) {
            names.push_back(account.GetName());
            owners.push_back(account.GetOwner());
        }
        result.SetParam(Constants::KEY_ACCOUNT_NAMES, names);
        result.SetParam(Constants::KEY_ACCOUNT_OWNERS, owners);
        callback->OnResult(ERR_JS_SUCCESS, result);
        return ERR_OK;
    }
    AuthenticatorSessionRequest request;
    request.callback = callback;
    request.callerUid = uid;
    request.labels = options.requiredLabels;
    auto sessionManager = AppAccountAuthenticatorSessionManager::GetInstance();
    if (sessionManager == nullptr) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    return sessionManager->SelectAccountsByOptions(candidateAccounts, request);
}

ErrCode AppAccountControlManager::OnPackageRemoved(const uid_t &uid, const std::string &bundleName)
{
    auto dataStoragePtr = GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    auto dataStorageSyncPtr = GetDataStorage(uid, true);
    if (dataStorageSyncPtr == nullptr) {
        ACCOUNT_LOGE("dataStorageSyncPtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    ErrCode result = dataStoragePtr->LoadDataByLocalFuzzyQuery(bundleName, accounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get accounts by owner, result %{public}d, bundleName = %{public}s",
            result, bundleName.c_str());
        return ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_OWNER;
    }

    AppAccountInfo appAccountInfo;
    for (auto account : accounts) {
        appAccountInfo = *(std::static_pointer_cast<AppAccountInfo>(account.second));

        std::set<std::string> authorizedApps;
        appAccountInfo.GetAuthorizedApps(authorizedApps);
        for (auto authorizedApp : authorizedApps) {
            result = RemoveAuthorizedAccountFromDataStorage(authorizedApp, appAccountInfo, dataStoragePtr);
            ACCOUNT_LOGD("remove authorized account from data storage, result = %{public}d.", result);

            // for sync data storage
            if (NeedSyncDataStorage(appAccountInfo) == true) {
                result = RemoveAuthorizedAccountFromDataStorage(authorizedApp, appAccountInfo, dataStorageSyncPtr);
                ACCOUNT_LOGD("remove authorized account from data storage, result = %{public}d.", result);
            }
        }

        result = dataStoragePtr->DeleteAccountInfoFromDataStorage(appAccountInfo);
        ACCOUNT_LOGD("delete account info from data storage, result = %{public}d.", result);

        // for sync data storage
        if (NeedSyncDataStorage(appAccountInfo) == true) {
            result = dataStorageSyncPtr->DeleteAccountInfoFromDataStorage(appAccountInfo);
            ACCOUNT_LOGD("delete account info from data storage, result = %{public}d.", result);
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::OnUserRemoved(int32_t userId)
{
    std::string storeId = std::to_string(userId);
    std::string syncStoreId = storeId + AppAccountDataStorage::DATA_STORAGE_SUFFIX;
    std::lock_guard<std::mutex> lock(storePtrMutex_);
    storePtrMap_.erase(storeId);
    storePtrMap_.erase(syncStoreId);
    return ERR_OK;
}

bool AppAccountControlManager::RegisterApplicationStateObserver()
{
    ACCOUNT_LOGD("enter");
    if (appStateObserver_ != nullptr) {
        return false;
    }
    appStateObserver_ = new (std::nothrow) AppAccountAppStateObserver();
    if (appStateObserver_ == nullptr) {
        ACCOUNT_LOGE("failed to create AppAccountAppStateObserver instance");
        return false;
    }
    sptr<ISystemAbilityManager> samgrClient = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrClient == nullptr) {
        ACCOUNT_LOGE("failed to system ability manager");
        return false;
    }
    iAppMgr_ = iface_cast<AppExecFwk::IAppMgr>(samgrClient->GetSystemAbility(APP_MGR_SERVICE_ID));
    if (iAppMgr_ == nullptr) {
        appStateObserver_ = nullptr;
        ACCOUNT_LOGE("failed to get ability manager service");
        return false;
    }
    int32_t result = iAppMgr_->RegisterApplicationStateObserver(appStateObserver_);
    if (result != ERR_OK) {
        return false;
    }
    return true;
}

void AppAccountControlManager::UnregisterApplicationStateObserver()
{
    if (iAppMgr_) {
        iAppMgr_->UnregisterApplicationStateObserver(appStateObserver_);
    }
    iAppMgr_ = nullptr;
    appStateObserver_ = nullptr;
}

void AppAccountControlManager::OnAbilityStateChanged(const AppExecFwk::AbilityStateData &abilityStateData)
{
    ACCOUNT_LOGE("enter");
    if (abilityStateData.abilityState != Constants::ABILITY_STATE_TERMINATED) {
        return;
    }
    std::lock_guard<std::mutex> lock(associatedDataMutex_);
    associatedDataCache_.erase(abilityStateData.uid);
    if (associatedDataCache_.size() == 0) {
        UnregisterApplicationStateObserver();
    }
}

ErrCode AppAccountControlManager::GetAllAccountsFromDataStorage(const std::string &owner,
    std::vector<AppAccountInfo> &appAccounts, const std::string &bundleName,
    const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr)
{
    appAccounts.clear();

    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    ErrCode result = dataStoragePtr->LoadDataByLocalFuzzyQuery(owner, accounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get accounts by owner, result = %{public}d, owner = %{public}s",
            result, owner.c_str());
        return ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_OWNER;
    }

    for (auto account : accounts) {
        appAccounts.emplace_back(*(std::static_pointer_cast<AppAccountInfo>(account.second)));
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAllAccessibleAccountsFromDataStorage(std::vector<AppAccountInfo> &appAccounts,
    const std::string &bundleName, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr)
{
    appAccounts.clear();

    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::vector<std::string> accessibleAccounts;
    ErrCode result = dataStoragePtr->GetAccessibleAccountsFromDataStorage(bundleName, accessibleAccounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get accessible account from data storage, result = %{public}d.", result);
        return result;
    }

    for (auto account : accessibleAccounts) {
        AppAccountInfo appAccountInfo;

        result = dataStoragePtr->GetAccountInfoById(account, appAccountInfo);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get account info by id. result %{public}d.", result);
            return ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID;
        }

        appAccounts.emplace_back(appAccountInfo);
    }

    std::vector<AppAccountInfo> currentAppAccounts;

    result = GetAllAccountsFromDataStorage(bundleName, currentAppAccounts, bundleName, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get all accounts from data storage, result = %{public}d", result);
        return result;
    }

    for (auto account : currentAppAccounts) {
        appAccounts.emplace_back(account);
    }

    return ERR_OK;
}

std::shared_ptr<AppAccountDataStorage> AppAccountControlManager::GetDataStorageByUserId(
    int32_t userId, const bool &autoSync)
{
    std::string storeId = std::to_string(userId);
    if (autoSync == true) {
        storeId = storeId + AppAccountDataStorage::DATA_STORAGE_SUFFIX;
    }
    std::lock_guard<std::mutex> lock(storePtrMutex_);
    auto it = storePtrMap_.find(storeId);
    if (it != storePtrMap_.end()) {
        return it->second;
    }
    auto storePtr = std::make_shared<AppAccountDataStorage>(storeId, autoSync);
    storePtrMap_.emplace(storeId, storePtr);
    return storePtr;
}

std::shared_ptr<AppAccountDataStorage> AppAccountControlManager::GetDataStorage(const uid_t &uid, const bool &autoSync)
{
    return GetDataStorageByUserId(uid / UID_TRANSFORM_DIVISOR, autoSync);
}

ErrCode AppAccountControlManager::GetStoreId(const uid_t &uid, std::string &storeId)
{
    std::int32_t uidToGetDeviceAccountId = uid;

    auto deviceAccountId = OhosAccountKits::GetInstance().GetDeviceAccountIdByUID(uidToGetDeviceAccountId);

    storeId = std::to_string(deviceAccountId);

    return ERR_OK;
}

bool AppAccountControlManager::NeedSyncDataStorage(const AppAccountInfo &appAccountInfo)
{
    bool syncEnable = false;
    ErrCode result = appAccountInfo.GetSyncEnable(syncEnable);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get sync enable, result = %{public}d.", result);
        return false;
    }

    if (syncEnable == false) {
        return false;
    }
    return true;
}

ErrCode AppAccountControlManager::GetAccountInfoFromDataStorage(
    AppAccountInfo &appAccountInfo, std::shared_ptr<AppAccountDataStorage> &dataStoragePtr)
{
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    return dataStoragePtr->GetAccountInfoFromDataStorage(appAccountInfo);
}

ErrCode AppAccountControlManager::AddAccountInfoIntoDataStorage(
    AppAccountInfo &appAccountInfo, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid)
{
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::string owner;
    ErrCode result = appAccountInfo.GetOwner(owner);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get owner, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_GET_OWNER;
    }

    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    result = dataStoragePtr->LoadDataByLocalFuzzyQuery(owner, accounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get accounts by owner, result %{public}d, owner = %{public}s",
            result, owner.c_str());
        return ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_OWNER;
    }

    if (accounts.size() >= ACCOUNT_MAX_SIZE) {
        ACCOUNT_LOGE("account exceeds max size");
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_MAX_SIZE;
    }

    result = dataStoragePtr->AddAccountInfoIntoDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to add account info into data storage, result %{public}d.", result);
        return result;
    }

    // for sync data storage
    if (NeedSyncDataStorage(appAccountInfo) == true) {
        auto dataStorageSyncPtr = GetDataStorage(uid, true);
        if (dataStorageSyncPtr == nullptr) {
            ACCOUNT_LOGE("dataStorageSyncPtr is nullptr");
            return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
        }

        result = dataStorageSyncPtr->AddAccountInfoIntoDataStorage(appAccountInfo);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to add account info into data storage, result %{public}d.", result);
            return result;
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SaveAccountInfoIntoDataStorage(
    AppAccountInfo &appAccountInfo, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid)
{
    ACCOUNT_LOGD("enter");

    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    ErrCode result = dataStoragePtr->SaveAccountInfoIntoDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return result;
    }

    // for sync data storage
    if (NeedSyncDataStorage(appAccountInfo) == true) {
        auto dataStorageSyncPtr = GetDataStorage(uid, true);
        if (dataStorageSyncPtr == nullptr) {
            ACCOUNT_LOGE("dataStorageSyncPtr is nullptr");
            return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
        }

        std::string appAccountInfoFromDataStorage;
        result = dataStorageSyncPtr->GetValueFromKvStore(appAccountInfo.GetPrimeKey(), appAccountInfoFromDataStorage);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get config by id from data storage, result %{public}d.", result);

            result = dataStorageSyncPtr->AddAccountInfo(appAccountInfo);
            if (result != ERR_OK) {
                ACCOUNT_LOGE("failed to add account info, result = %{public}d", result);
                return ERR_APPACCOUNT_SERVICE_ADD_ACCOUNT_INFO;
            }
        } else {
            result = dataStorageSyncPtr->SaveAccountInfo(appAccountInfo);
            if (result != ERR_OK) {
                ACCOUNT_LOGE("failed to save account info, result = %{public}d", result);
                return ERR_APPACCOUNT_SERVICE_SAVE_ACCOUNT_INFO;
            }
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::DeleteAccountInfoFromDataStorage(
    AppAccountInfo &appAccountInfo, std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid)
{
    ACCOUNT_LOGD("enter");
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    ErrCode result = dataStoragePtr->GetAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }

    result = dataStoragePtr->DeleteAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to delete account info from data storage, result %{public}d.", result);
        return result;
    }

    // for sync data storage
    if (NeedSyncDataStorage(appAccountInfo) == true) {
        auto dataStorageSyncPtr = GetDataStorage(uid, true);
        if (dataStorageSyncPtr == nullptr) {
            ACCOUNT_LOGE("dataStorageSyncPtr is nullptr");
            return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
        }

        result = dataStorageSyncPtr->DeleteAccountInfoFromDataStorage(appAccountInfo);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to delete account info from data storage, result %{public}d.", result);
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SaveAuthorizedAccount(const std::string &bundleName, AppAccountInfo &appAccountInfo,
    const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid)
{
    ACCOUNT_LOGD("enter");

    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    ErrCode result = SaveAuthorizedAccountIntoDataStorage(bundleName, appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save authorized account, result %{public}d.", result);
        return result;
    }

    // for sync data storage
    if (NeedSyncDataStorage(appAccountInfo) == true) {
        auto dataStorageSyncPtr = GetDataStorage(uid, true);
        if (dataStorageSyncPtr == nullptr) {
            ACCOUNT_LOGE("dataStorageSyncPtr is nullptr");
            return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
        }

        result = SaveAuthorizedAccountIntoDataStorage(bundleName, appAccountInfo, dataStorageSyncPtr);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to save authorized account, result %{public}d.", result);
            return result;
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::RemoveAuthorizedAccount(const std::string &bundleName,
    AppAccountInfo &appAccountInfo, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid)
{
    ACCOUNT_LOGD("enter");

    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    ErrCode result = RemoveAuthorizedAccountFromDataStorage(bundleName, appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save authorized account, result %{public}d.", result);
        return result;
    }

    // for sync data storage
    if (NeedSyncDataStorage(appAccountInfo) == true) {
        auto dataStorageSyncPtr = GetDataStorage(uid, true);
        if (dataStorageSyncPtr == nullptr) {
            ACCOUNT_LOGE("dataStorageSyncPtr is nullptr");
            return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
        }

        result = RemoveAuthorizedAccountFromDataStorage(bundleName, appAccountInfo, dataStorageSyncPtr);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to save authorized account, result %{public}d.", result);
            return result;
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SaveAuthorizedAccountIntoDataStorage(const std::string &authorizedApp,
    AppAccountInfo &appAccountInfo, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr)
{
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::string authorizedAccounts;
    ErrCode result = dataStoragePtr->GetValueFromKvStore(AppAccountDataStorage::AUTHORIZED_ACCOUNTS,
        authorizedAccounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get config by id from data storage, result %{public}d.", result);
    }

    std::vector<std::string> accessibleAccounts;
    auto jsonObject = dataStoragePtr->GetAccessibleAccountsFromAuthorizedAccounts(
        authorizedAccounts, authorizedApp, accessibleAccounts);

    auto accountId = appAccountInfo.GetPrimeKey();

    auto it = std::find(accessibleAccounts.begin(), accessibleAccounts.end(), accountId);
    if (it == accessibleAccounts.end()) {
        ACCOUNT_LOGI("failed to find accountId, accountId = %{public}s", accountId.c_str());
        accessibleAccounts.emplace_back(accountId);
    }

    auto accessibleAccountArray = Json::array();
    ACCOUNT_LOGD("accessibleAccounts.size() = %{public}zu", accessibleAccounts.size());
    for (auto account : accessibleAccounts) {
        accessibleAccountArray.emplace_back(account);
    }

    jsonObject[authorizedApp] = accessibleAccountArray;
    try {
        authorizedAccounts = jsonObject.dump();
    } catch (Json::type_error& err) {
        ACCOUNT_LOGE("failed to dump json object, reason: %{public}s", err.what());
        return ERR_APPACCOUNT_SERVICE_DUMP_JSON;
    }

    result = dataStoragePtr->PutValueToKvStore(AppAccountDataStorage::AUTHORIZED_ACCOUNTS, authorizedAccounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("PutValueToKvStore failed! result %{public}d.", result);
    }
    return result;
}

ErrCode AppAccountControlManager::RemoveAuthorizedAccountFromDataStorage(const std::string &authorizedApp,
    AppAccountInfo &appAccountInfo, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr)
{
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::string authorizedAccounts;
    ErrCode result = dataStoragePtr->GetValueFromKvStore(AppAccountDataStorage::AUTHORIZED_ACCOUNTS,
        authorizedAccounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get config by id from data storage, result %{public}d.", result);
    }

    std::vector<std::string> accessibleAccounts;
    auto jsonObject = dataStoragePtr->GetAccessibleAccountsFromAuthorizedAccounts(
        authorizedAccounts, authorizedApp, accessibleAccounts);

    auto accountId = appAccountInfo.GetPrimeKey();

    auto it = std::find(accessibleAccounts.begin(), accessibleAccounts.end(), accountId);
    if (it != accessibleAccounts.end()) {
        accessibleAccounts.erase(it);
    }

    auto accessibleAccountArray = Json::array();
    for (auto account : accessibleAccounts) {
        accessibleAccountArray.emplace_back(account);
    }

    jsonObject[authorizedApp] = accessibleAccountArray;
    try {
        authorizedAccounts = jsonObject.dump();
    } catch (Json::type_error& err) {
        ACCOUNT_LOGE("failed to dump json object, reason: %{public}s", err.what());
        return ERR_APPACCOUNT_SERVICE_DUMP_JSON;
    }

    result = dataStoragePtr->PutValueToKvStore(AppAccountDataStorage::AUTHORIZED_ACCOUNTS, authorizedAccounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save config info, result %{public}d.", result);
        return result;
    }

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

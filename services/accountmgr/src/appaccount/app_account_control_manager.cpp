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

#include "accesstoken_kit.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "app_account_app_state_observer.h"
#include "app_account_check_labels_session.h"
#include "app_account_data_storage.h"
#include "app_account_info.h"
#include "app_account_subscribe_manager.h"
#include "bundle_manager_adapter.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "ohos_account_kits.h"
#include "singleton.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
AppAccountControlManager::AppAccountControlManager()
{}

ErrCode AppAccountControlManager::AddAccount(const std::string &name, const std::string &extraInfo, const uid_t &uid,
    const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(uid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);

        appAccountInfo.SetExtraInfo(extraInfo);

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

ErrCode AppAccountControlManager::CreateAccount(const std::string &name, const CreateAccountOptions &options,
    const uid_t &uid, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(uid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        result = appAccountInfo.InitCustomData(options.customData);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to set custom data, result %{public}d.", result);
            return ERR_APPACCOUNT_SERVICE_SET_ASSOCIATED_DATA;
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
    RemoveAssociatedDataCacheByAccount(uid, name);

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

ErrCode AppAccountControlManager::GetAccountExtraInfo(const std::string &name, std::string &extraInfo,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    AppAccountInfo appAccountInfo(name, bundleName);
    appAccountInfo.SetAppIndex(appIndex);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(uid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }

    appAccountInfo.GetExtraInfo(extraInfo);

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

    appAccountInfo.SetExtraInfo(extraInfo);

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return result;
    }

    ACCOUNT_LOGD("end, result = %{public}d", result);

    return result;
}

ErrCode AppAccountControlManager::EnableAppAccess(const std::string &name, const std::string &authorizedApp,
    AppAccountCallingInfo &appAccountCallingInfo, AppAccountInfo &appAccountInfo, const uint32_t apiVersion)
{
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(appAccountCallingInfo.callingUid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }

    result = appAccountInfo.EnableAppAccess(authorizedApp, apiVersion);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to enable app access, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ENABLE_APP_ACCESS_ALREADY_EXISTS;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, appAccountCallingInfo.callingUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return result;
    }

    // save authorized account into data storage
    result = SaveAuthorizedAccount(authorizedApp, appAccountInfo, dataStoragePtr, appAccountCallingInfo.callingUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save authorized account into data storage, result %{public}d.", result);
        return result;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::DisableAppAccess(const std::string &name, const std::string &authorizedApp,
    AppAccountCallingInfo &appAccountCallingInfo, AppAccountInfo &appAccountInfo, const uint32_t apiVersion)
{
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(appAccountCallingInfo.callingUid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }

    result = appAccountInfo.DisableAppAccess(authorizedApp, apiVersion);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to disable app access, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_DISABLE_APP_ACCESS_NOT_EXISTED;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, appAccountCallingInfo.callingUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return result;
    }

    // remove authorized account from data storage
    result = RemoveAuthorizedAccount(authorizedApp, appAccountInfo, dataStoragePtr, appAccountCallingInfo.callingUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save authorized account into data storage, result %{public}d.", result);
        return result;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::CheckAppAccess(const std::string &name, const std::string &authorizedApp,
    bool &isAccessible, const AppAccountCallingInfo &appAccountCallingInfo)
{
    isAccessible = false;
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(appAccountCallingInfo.callingUid);
    AppAccountInfo appAccountInfo(name, appAccountCallingInfo.bundleName);
    appAccountInfo.SetAppIndex(appAccountCallingInfo.appIndex);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    return appAccountInfo.CheckAppAccess(authorizedApp, isAccessible);
}

ErrCode AppAccountControlManager::CheckAppAccountSyncEnable(const std::string &name,
    bool &syncEnable, const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    AppAccountInfo appAccountInfo(name, bundleName);
    appAccountInfo.SetAppIndex(appIndex);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(uid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }

    appAccountInfo.GetSyncEnable(syncEnable);

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

    appAccountInfo.SetSyncEnable(syncEnable);

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
    std::string &value, const uid_t &uid, const uint32_t &appIndex)
{
    std::string bundleName;
    if (!BundleManagerAdapter::GetInstance()->GetBundleNameForUid(uid, bundleName)) {
        ACCOUNT_LOGE("failed to get bundle name");
        return ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME;
    }
    AppAccountInfo appAccountInfo(name, bundleName);
    appAccountInfo.SetAppIndex(appIndex);
    std::shared_ptr<AppAccountDataStorage> storePtr = GetDataStorage(uid);
    if (storePtr == nullptr) {
        ACCOUNT_LOGE("failed to get data storage");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, storePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
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
        result = ERR_APPACCOUNT_SERVICE_ASSOCIATED_DATA_KEY_NOT_EXIST;
    }
    if ((associatedDataCache_.size() == 0) && (!RegisterApplicationStateObserver())) {
        ACCOUNT_LOGE("failed to register application state observer");
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
    std::lock_guard<std::mutex> lock(associatedDataMutex_);
    auto it = associatedDataCache_.find(uid);
    if ((it == associatedDataCache_.end()) || (it->second.name != name)) {
        uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
        Security::AccessToken::HapTokenInfo hapTokenInfo;
        int result = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(callingTokenId, hapTokenInfo);
        if ((result != 0) || (hapTokenInfo.instIndex < 0)) {
            ACCOUNT_LOGE("failed to get app index");
            return ERR_APPACCOUNT_SERVICE_GET_APP_INDEX;
        }
        associatedDataCache_.erase(uid);
        return GetAssociatedDataFromStorage(name, key, value, uid, hapTokenInfo.instIndex);
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
    const std::string &value, const AppAccountCallingInfo &appAccountCallingInfo)
{
    std::shared_ptr<AppAccountDataStorage> storePtr = GetDataStorage(appAccountCallingInfo.callingUid);
    AppAccountInfo appAccountInfo(name, appAccountCallingInfo.bundleName);
    appAccountInfo.SetAppIndex(appAccountCallingInfo.appIndex);
    std::lock_guard<std::mutex> lock(associatedDataMutex_);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, storePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }
    result = appAccountInfo.SetAssociatedData(key, value);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to set associated data, result %{public}d.", result);
        return result;
    }
    result = SaveAccountInfoIntoDataStorage(appAccountInfo, storePtr, appAccountCallingInfo.callingUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return result;
    }
    auto it = associatedDataCache_.find(appAccountCallingInfo.callingUid);
    if ((it != associatedDataCache_.end()) && (it->second.name == name)) {
        it->second.data[key] = value;
    }
    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAccountCredential(const std::string &name, const std::string &credentialType,
    std::string &credential, const AppAccountCallingInfo &appAccountCallingInfo)
{
    AppAccountInfo appAccountInfo(name, appAccountCallingInfo.bundleName);
    appAccountInfo.SetAppIndex(appAccountCallingInfo.appIndex);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(appAccountCallingInfo.callingUid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }

    result = appAccountInfo.GetAccountCredential(credentialType, credential);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account credential, result %{public}d.", result);
        return result;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SetAccountCredential(const std::string &name, const std::string &credentialType,
    const std::string &credential, const AppAccountCallingInfo &appAccountCallingInfo, bool isDelete)
{
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(appAccountCallingInfo.callingUid);
    AppAccountInfo appAccountInfo(name, appAccountCallingInfo.bundleName);
    appAccountInfo.SetAppIndex(appAccountCallingInfo.appIndex);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }

    result = appAccountInfo.SetAccountCredential(credentialType, credential, isDelete);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to set account credential, result %{public}d.", result);
        return result;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, appAccountCallingInfo.callingUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return result;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetOAuthToken(
    const AuthenticatorSessionRequest &request, std::string &token, const uint32_t apiVersion)
{
    AppAccountInfo appAccountInfo(request.name, request.owner);
    appAccountInfo.SetAppIndex(request.appIndex);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    bool isVisible = false;
    result = appAccountInfo.CheckOAuthTokenVisibility(
        request.authType, request.callerBundleName, isVisible, apiVersion);
    if ((result != ERR_OK) || (!isVisible)) {
        ACCOUNT_LOGE("failed to get oauth token for permission denied, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED;
    }
    return appAccountInfo.GetOAuthToken(request.authType, token, apiVersion);
}

ErrCode AppAccountControlManager::SetOAuthToken(const AuthenticatorSessionRequest &request)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AppAccountInfo appAccountInfo(request.name, request.callerBundleName);
    appAccountInfo.SetAppIndex(request.appIndex);
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

ErrCode AppAccountControlManager::DeleteOAuthToken(
    const AuthenticatorSessionRequest &request, const uint32_t apiVersion)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AppAccountInfo appAccountInfo(request.name, request.owner);
    appAccountInfo.SetAppIndex(request.appIndex);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid);
    ErrCode ret = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", ret);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    bool isOwnerSelf = false;
    if (request.owner == request.callerBundleName) {
        isOwnerSelf = true;
    }
    bool isVisible = false;
    ret = appAccountInfo.CheckOAuthTokenVisibility(request.authType, request.callerBundleName, isVisible, apiVersion);
    if ((!isVisible) || (ret != ERR_OK)) {
        ACCOUNT_LOGE("failed to delete oauth token for permission denied, result %{public}d.", ret);
        return ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED;
    }
    if (apiVersion >= Constants::API_VERSION9) {
        ret = appAccountInfo.DeleteAuthToken(request.authType, request.token, isOwnerSelf);
        if (ret != ERR_OK) {
            return ret;
        }
    } else {
        ret = appAccountInfo.DeleteOAuthToken(request.authType, request.token);
        if (ret == ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST) {
            return ERR_OK;
        }
    }
    ret = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", ret);
        return ERR_APPACCOUNT_SERVICE_SAVE_ACCOUNT_INFO;
    }
    return ERR_OK;
}

ErrCode AppAccountControlManager::SetOAuthTokenVisibility(
    const AuthenticatorSessionRequest &request, const uint32_t apiVersion)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AppAccountInfo appAccountInfo(request.name, request.callerBundleName);
    appAccountInfo.SetAppIndex(request.appIndex);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid);
    ErrCode ret = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", ret);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    ret = appAccountInfo.SetOAuthTokenVisibility(
        request.authType, request.bundleName, request.isTokenVisible, apiVersion);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to set oauth token visibility, result %{public}d.", ret);
        return ret;
    }
    ret = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", ret);
        return ERR_APPACCOUNT_SERVICE_SAVE_ACCOUNT_INFO;
    }
    return ERR_OK;
}

ErrCode AppAccountControlManager::CheckOAuthTokenVisibility(
    const AuthenticatorSessionRequest &request, bool &isVisible, const uint32_t apiVersion)
{
    isVisible = false;
    AppAccountInfo appAccountInfo(request.name, request.owner);
    appAccountInfo.SetAppIndex(request.appIndex);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    return appAccountInfo.CheckOAuthTokenVisibility(request.authType, request.bundleName, isVisible, apiVersion);
}

ErrCode AppAccountControlManager::GetAllOAuthTokens(
    const AuthenticatorSessionRequest &request, std::vector<OAuthTokenInfo> &tokenInfos)
{
    tokenInfos.clear();
    AppAccountInfo appAccountInfo(request.name, request.owner);
    appAccountInfo.SetAppIndex(request.appIndex);
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
    const AuthenticatorSessionRequest &request, std::set<std::string> &oauthList, const uint32_t apiVersion)
{
    AppAccountInfo appAccountInfo(request.name, request.callerBundleName);
    appAccountInfo.SetAppIndex(request.appIndex);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    return appAccountInfo.GetOAuthList(request.authType, oauthList, apiVersion);
}

ErrCode AppAccountControlManager::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    appAccounts.clear();

    auto dataStoragePtr = GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }
    ErrCode result = AccountPermissionManager::GetInstance()->VerifyPermission(
        AccountPermissionManager::GET_ALL_APP_ACCOUNTS);
    if ((bundleName == owner) || (result == ERR_OK)) {
        std::string key = owner + Constants::HYPHEN + std::to_string(appIndex);
        result = GetAllAccountsFromDataStorage(key, appAccounts, owner, dataStoragePtr);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get all accounts from data storage, result = %{public}d", result);
            return result;
        }
        return ERR_OK;
    }

    std::vector<std::string> accessibleAccounts;
    result = dataStoragePtr->GetAccessibleAccountsFromDataStorage(bundleName, accessibleAccounts);
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
        if (appAccountInfo.GetOwner() == owner) {
            appAccounts.emplace_back(appAccountInfo);
        }
    }
    return ERR_OK;
}

static ErrCode LoadAllAppAccounts(const std::shared_ptr<OHOS::AccountSA::AppAccountDataStorage> &dataStoragePtr,
    std::vector<AppAccountInfo> &appAccounts)
{
    std::map<std::string, std::shared_ptr<IAccountInfo>> infos;
    ErrCode result = dataStoragePtr->LoadAllData(infos);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("LoadAllData failed!");
        return result;
    }
    for (auto it = infos.begin(); it != infos.end(); ++it) {
        if (it->first == AppAccountDataStorage::AUTHORIZED_ACCOUNTS) {
            continue;
        }
        AppAccountInfo curAppInfo = *(std::static_pointer_cast<AppAccountInfo>(it->second));
        appAccounts.emplace_back(curAppInfo);
    }
    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    appAccounts.clear();

    auto dataStoragePtr = GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }
    ErrCode result = AccountPermissionManager::GetInstance()->VerifyPermission(
        AccountPermissionManager::GET_ALL_APP_ACCOUNTS);
    if (result == ERR_OK) {
        return LoadAllAppAccounts(dataStoragePtr, appAccounts);
    }
    std::vector<std::string> accessibleAccounts;
    result = dataStoragePtr->GetAccessibleAccountsFromDataStorage(bundleName, accessibleAccounts);
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
    std::string key = bundleName + Constants::HYPHEN + std::to_string(appIndex);
    result = GetAllAccountsFromDataStorage(key, currentAppAccounts, bundleName, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get all accounts from data storage, result = %{public}d", result);
        return result;
    }

    std::transform(currentAppAccounts.begin(), currentAppAccounts.end(), std::back_inserter(appAccounts),
        [](auto account) { return account; });

    return ERR_OK;
}

ErrCode AppAccountControlManager::SelectAccountsByOptions(
    const SelectAccountsOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback,
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
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
    ErrCode errCode = GetAllAccessibleAccounts(accessibleAccounts, uid, bundleName, appIndex);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to get all accessible accounts");
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

void AppAccountControlManager::RemoveAssociatedDataCacheByUid(const uid_t &uid)
{
    std::lock_guard<std::mutex> lock(associatedDataMutex_);
    associatedDataCache_.erase(uid);
    if (associatedDataCache_.empty()) {
        UnregisterApplicationStateObserver();
    }
}

void AppAccountControlManager::RemoveAssociatedDataCacheByAccount(const uid_t &uid, const std::string &name)
{
    std::lock_guard<std::mutex> lock(associatedDataMutex_);
    auto it = associatedDataCache_.find(uid);
    if ((it == associatedDataCache_.end()) || (it->second.name != name)) {
        return;
    }
    associatedDataCache_.erase(it);
    if (associatedDataCache_.empty()) {
        UnregisterApplicationStateObserver();
    }
}

ErrCode AppAccountControlManager::OnPackageRemoved(
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    RemoveAssociatedDataCacheByUid(uid);
    auto dataStoragePtr = GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }
#ifdef DISTRIBUTED_FEATURE_ENABLED
    auto dataStorageSyncPtr = GetDataStorage(uid, true);
    if (dataStorageSyncPtr == nullptr) {
        ACCOUNT_LOGE("dataStorageSyncPtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }
#endif // DISTRIBUTED_FEATURE_ENABLED
    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    std::string key = bundleName + Constants::HYPHEN + std::to_string(appIndex);
    ErrCode result = dataStoragePtr->LoadDataByLocalFuzzyQuery(key, accounts);
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
        appAccountInfo.SetAppIndex(appIndex);
        for (auto authorizedApp : authorizedApps) {
            RemoveAuthorizedAccountFromDataStorage(authorizedApp, appAccountInfo, dataStoragePtr);
#ifdef DISTRIBUTED_FEATURE_ENABLED
            if (NeedSyncDataStorage(appAccountInfo) == true) {
                RemoveAuthorizedAccountFromDataStorage(authorizedApp, appAccountInfo, dataStorageSyncPtr);
            }
#endif // DISTRIBUTED_FEATURE_ENABLED
        }
        dataStoragePtr->DeleteAccountInfoFromDataStorage(appAccountInfo);
#ifdef DISTRIBUTED_FEATURE_ENABLED
        if (NeedSyncDataStorage(appAccountInfo) == true) {
            dataStorageSyncPtr->DeleteAccountInfoFromDataStorage(appAccountInfo);
        }
#else  // DISTRIBUTED_FEATURE_ENABLED
        ACCOUNT_LOGI("No distributed feature!");
#endif // DISTRIBUTED_FEATURE_ENABLED
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
    if (abilityStateData.abilityState != static_cast<int32_t>(AppExecFwk::AbilityState::ABILITY_STATE_TERMINATED)) {
        return;
    }
    RemoveAssociatedDataCacheByUid(abilityStateData.uid);
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

    std::transform(accounts.begin(), accounts.end(), std::back_inserter(appAccounts),
        [](auto account) { return *(std::static_pointer_cast<AppAccountInfo>(account.second)); });

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAllAccessibleAccountsFromDataStorage(
    std::vector<AppAccountInfo> &appAccounts, const std::string &bundleName,
    const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uint32_t &appIndex)
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
    std::string key = bundleName + Constants::HYPHEN + std::to_string(appIndex);
    result = GetAllAccountsFromDataStorage(key, currentAppAccounts, bundleName, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get all accounts from data storage, result = %{public}d", result);
        return result;
    }

    std::transform(currentAppAccounts.begin(), currentAppAccounts.end(), std::back_inserter(appAccounts),
        [](auto account) { return account; });

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

bool AppAccountControlManager::NeedSyncDataStorage(const AppAccountInfo &appAccountInfo)
{
    bool syncEnable = false;
    appAccountInfo.GetSyncEnable(syncEnable);

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
    appAccountInfo.GetOwner(owner);

    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    std::string key = owner + Constants::HYPHEN + std::to_string(appAccountInfo.GetAppIndex());
    ErrCode result = dataStoragePtr->LoadDataByLocalFuzzyQuery(key, accounts);
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
#ifdef DISTRIBUTED_FEATURE_ENABLED
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
#else  // DISTRIBUTED_FEATURE_ENABLED
    ACCOUNT_LOGI("No distributed feature!");
#endif // DISTRIBUTED_FEATURE_ENABLED

    return ERR_OK;
}

ErrCode AppAccountControlManager::SaveAccountInfoIntoDataStorage(
    AppAccountInfo &appAccountInfo, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid)
{
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
#ifdef DISTRIBUTED_FEATURE_ENABLED
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
#else  // DISTRIBUTED_FEATURE_ENABLED
    ACCOUNT_LOGI("No distributed feature!");
#endif // DISTRIBUTED_FEATURE_ENABLED

    return ERR_OK;
}

ErrCode AppAccountControlManager::DeleteAccountInfoFromDataStorage(
    AppAccountInfo &appAccountInfo, std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid)
{
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
#ifdef DISTRIBUTED_FEATURE_ENABLED
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
#else  // DISTRIBUTED_FEATURE_ENABLED
    ACCOUNT_LOGI("No distributed feature!");
#endif // DISTRIBUTED_FEATURE_ENABLED
    return ERR_OK;
}

ErrCode AppAccountControlManager::SaveAuthorizedAccount(const std::string &bundleName,
    AppAccountInfo &appAccountInfo, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid)
{
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
#ifdef DISTRIBUTED_FEATURE_ENABLED
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
#else  // DISTRIBUTED_FEATURE_ENABLED
    ACCOUNT_LOGI("No distributed feature!");
#endif // DISTRIBUTED_FEATURE_ENABLED

    return ERR_OK;
}

ErrCode AppAccountControlManager::RemoveAuthorizedAccount(const std::string &bundleName,
    AppAccountInfo &appAccountInfo, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid)
{
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
#ifdef DISTRIBUTED_FEATURE_ENABLED
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
#else  // DISTRIBUTED_FEATURE_ENABLED
    ACCOUNT_LOGI("No distributed feature!");
#endif // DISTRIBUTED_FEATURE_ENABLED

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
        accessibleAccounts.emplace_back(accountId);
    }

    auto accessibleAccountArray = Json::array();
    std::transform(accessibleAccounts.begin(), accessibleAccounts.end(), std::back_inserter(accessibleAccountArray),
        [](auto account) { return account; });

    jsonObject[authorizedApp] = accessibleAccountArray;
    try {
        authorizedAccounts = jsonObject.dump();
    } catch (Json::type_error& err) {
        ACCOUNT_LOGE("failed to dump json object, reason: %{public}s", err.what());
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
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
    std::transform(accessibleAccounts.begin(), accessibleAccounts.end(), std::back_inserter(accessibleAccountArray),
        [](auto account) { return account; });

    jsonObject[authorizedApp] = accessibleAccountArray;
    try {
        authorizedAccounts = jsonObject.dump();
    } catch (Json::type_error& err) {
        ACCOUNT_LOGE("failed to dump json object, reason: %{public}s", err.what());
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
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

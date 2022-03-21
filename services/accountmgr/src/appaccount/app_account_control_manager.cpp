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
#include "app_account_data_storage.h"
#include "app_account_info.h"
#include "ipc_skeleton.h"
#include "ohos_account_kits.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
AppAccountControlManager::AppAccountControlManager()
{
    ACCOUNT_LOGI("enter");
}

ErrCode AppAccountControlManager::AddAccount(const std::string &name, const std::string &extraInfo, const uid_t &uid,
    const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter, name = %{public}s, extraInfo = %{public}s.", name.c_str(), extraInfo.c_str());

    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");

        result = appAccountInfo.SetExtraInfo(extraInfo);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to set extra info");
            return ERR_APPACCOUNT_SERVICE_SET_EXTRA_INFO;
        }

        result = AddAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, uid);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to add account info into data storage");
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
    ACCOUNT_LOGI("enter, name = %{public}s", name.c_str());

    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = DeleteAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to delete account info from data storage");
        return result;
    }

    std::set<std::string> authorizedApps;
    appAccountInfo.GetAuthorizedApps(authorizedApps);
    for (auto authorizedApp : authorizedApps) {
        // remove authorized account from data storage
        result = RemoveAuthorizedAccount(authorizedApp, appAccountInfo, dataStoragePtr, uid);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to save authorized account into data storage");
            return result;
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAccountExtraInfo(
    const std::string &name, std::string &extraInfo, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s", name.c_str());

    AppAccountInfo appAccountInfo(name, bundleName);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.GetExtraInfo(extraInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to get extra info");
        return ERR_APPACCOUNT_SERVICE_GET_EXTRA_INFO;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo,
    const uid_t &uid, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter, name = %{public}s, extraInfo = %{public}s.", name.c_str(), extraInfo.c_str());

    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.SetExtraInfo(extraInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to set extra info");
        return ERR_APPACCOUNT_SERVICE_SET_EXTRA_INFO;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
        return result;
    }

    ACCOUNT_LOGI("end, result = %{public}d", result);

    return result;
}

ErrCode AppAccountControlManager::EnableAppAccess(const std::string &name, const std::string &authorizedApp,
    const uid_t &uid, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter, name = %{public}s, authorizedApp = %{public}s, bundleName = %{public}s",
        name.c_str(), authorizedApp.c_str(), bundleName.c_str());

    if (authorizedApp == bundleName) {
        ACCOUNT_LOGE("authorizedApp is the same to owner");
        return ERR_APPACCOUNT_SERVICE_BUNDLE_NAME_IS_THE_SAME;
    }

    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.EnableAppAccess(authorizedApp);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to enable app access");
        return ERR_APPACCOUNT_SERVICE_ENABLE_APP_ACCESS_ALREADY_EXISTS;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
        return result;
    }

    // save authorized account into data storage
    result = SaveAuthorizedAccount(authorizedApp, appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save authorized account into data storage");
        return result;
    }

    ACCOUNT_LOGI("end, result = %{public}d", result);

    return ERR_OK;
}

ErrCode AppAccountControlManager::DisableAppAccess(const std::string &name, const std::string &authorizedApp,
    const uid_t &uid, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter, name = %{public}s, authorizedApp = %{public}s.",
        name.c_str(), authorizedApp.c_str());

    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.DisableAppAccess(authorizedApp);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to disable app access");
        return ERR_APPACCOUNT_SERVICE_DISABLE_APP_ACCESS_NOT_EXISTED;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
        return result;
    }

    // remove authorized account from data storage
    result = RemoveAuthorizedAccount(authorizedApp, appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save authorized account into data storage");
        return result;
    }

    ACCOUNT_LOGI("end, result = %{public}d", result);

    return ERR_OK;
}

ErrCode AppAccountControlManager::CheckAppAccountSyncEnable(
    const std::string &name, bool &syncEnable, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s", name.c_str());

    AppAccountInfo appAccountInfo(name, bundleName);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.GetSyncEnable(syncEnable);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get sync enable");
        return ERR_APPACCOUNT_SERVICE_GET_SYNC_ENABLE;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable,
    const uid_t &uid, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter, name = %{public}s, syncEnable = %{public}d.", name.c_str(), syncEnable);

    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.SetSyncEnable(syncEnable);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to set sync enable");
        return ERR_APPACCOUNT_SERVICE_GET_SYNC_ENABLE;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
        return result;
    }

    ACCOUNT_LOGI("end, result = %{public}d", result);

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAssociatedData(const std::string &name, const std::string &key,
    std::string &value, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s, key = %{public}s, value = %{public}s.",
        name.c_str(), key.c_str(), value.c_str());

    AppAccountInfo appAccountInfo(name, bundleName);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.GetAssociatedData(key, value);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get associated data");
        return ERR_APPACCOUNT_SERVICE_GET_ASSOCIATED_DATA;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SetAssociatedData(const std::string &name, const std::string &key,
    const std::string &value, const uid_t &uid, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter, name = %{public}s, key = %{public}s, value = %{public}s.",
        name.c_str(), key.c_str(), value.c_str());

    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.SetAssociatedData(key, value);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to set associated data");
        return ERR_APPACCOUNT_SERVICE_SET_ASSOCIATED_DATA;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
        return result;
    }

    ACCOUNT_LOGI("end, result = %{public}d", result);

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAccountCredential(const std::string &name, const std::string &credentialType,
    std::string &credential, const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, name = %{public}s, credentialType = %{public}s.", name.c_str(), credentialType.c_str());

    AppAccountInfo appAccountInfo(name, bundleName);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.GetAccountCredential(credentialType, credential);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account credential");
        return ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_CREDENTIAL;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SetAccountCredential(const std::string &name, const std::string &credentialType,
    const std::string &credential, const uid_t &uid, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter, name = %{public}s, credentialType = %{public}s.", name.c_str(), credentialType.c_str());

    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.SetAccountCredential(credentialType, credential);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to set account credential");
        return ERR_APPACCOUNT_SERVICE_SET_ACCOUNT_CREDENTIAL;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
        return result;
    }

    ACCOUNT_LOGI("end, result = %{public}d", result);

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetOAuthToken(const OAuthRequest &request, std::string &token)
{
    AppAccountInfo appAccountInfo(request.name, request.owner);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    bool isVisible = false;
    result = appAccountInfo.CheckOAuthTokenVisibility(request.authType, request.callerBundleName, isVisible);
    if ((result != ERR_OK) || (!isVisible)) {
        ACCOUNT_LOGE("failed to get oauth token for permission denied");
        return ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED;
    }
    return appAccountInfo.GetOAuthToken(request.authType, token);
}

ErrCode AppAccountControlManager::SetOAuthToken(const OAuthRequest &request)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AppAccountInfo appAccountInfo(request.name, request.callerBundleName);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    result = appAccountInfo.SetOAuthToken(request.authType, request.token);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to set oauth token");
        return result;
    }
    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
        return ERR_APPACCOUNT_SERVICE_SAVE_ACCOUNT_INFO;
    }
    return ERR_OK;
}

ErrCode AppAccountControlManager::DeleteOAuthToken(const OAuthRequest &request)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AppAccountInfo appAccountInfo(request.name, request.owner);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    bool isVisible = false;
    result = appAccountInfo.CheckOAuthTokenVisibility(request.authType, request.callerBundleName, isVisible);
    if ((!isVisible) || (result != ERR_OK)) {
        ACCOUNT_LOGI("failed to delete oauth token for permission denied");
        return ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED;
    }
    result = appAccountInfo.DeleteOAuthToken(request.authType, request.token);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to delete oauth token");
        return ERR_OK;
    }
    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
        return ERR_APPACCOUNT_SERVICE_SAVE_ACCOUNT_INFO;
    }
    return ERR_OK;
}

ErrCode AppAccountControlManager::SetOAuthTokenVisibility(const OAuthRequest &request)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AppAccountInfo appAccountInfo(request.name, request.callerBundleName);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    result = appAccountInfo.SetOAuthTokenVisibility(request.authType, request.bundleName, request.isTokenVisible);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to set oauth token visibility");
        return result;
    }
    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
        return ERR_APPACCOUNT_SERVICE_SAVE_ACCOUNT_INFO;
    }
    return ERR_OK;
}

ErrCode AppAccountControlManager::CheckOAuthTokenVisibility(const OAuthRequest &request, bool &isVisible)
{
    ACCOUNT_LOGI("enter, name = %{public}s, owner = %{public}s, authType = %{public}s, bundleName = %{public}s",
        request.name.c_str(), request.owner.c_str(), request.authType.c_str(), request.bundleName.c_str());
    isVisible = false;
    AppAccountInfo appAccountInfo(request.name, request.owner);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to get account info from data storage");
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    return appAccountInfo.CheckOAuthTokenVisibility(request.authType, request.bundleName, isVisible);
}

ErrCode AppAccountControlManager::GetAllOAuthTokens(
    const OAuthRequest &request, std::vector<OAuthTokenInfo> &tokenInfos)
{
    tokenInfos.clear();
    AppAccountInfo appAccountInfo(request.name, request.owner);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    std::vector<OAuthTokenInfo> allTokenInfos;
    result = appAccountInfo.GetAllOAuthTokens(allTokenInfos);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get all oauth token from data storage");
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
    const OAuthRequest &request, std::set<std::string> &oauthList)
{
    AppAccountInfo appAccountInfo(request.name, request.callerBundleName);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr;
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    return appAccountInfo.GetOAuthList(request.authType, oauthList);
}

ErrCode AppAccountControlManager::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts,
    const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, owner = %{public}s", owner.c_str());

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
    ACCOUNT_LOGI("enter");

    appAccounts.clear();

    auto dataStoragePtr = GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::vector<std::string> accessibleAccounts;
    ErrCode result = dataStoragePtr->GetAccessibleAccountsFromDataStorage(bundleName, accessibleAccounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get accessiable account from data storage");
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

ErrCode AppAccountControlManager::OnPackageRemoved(const uid_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter, uid = %{public}d, bundleName = %{public}s", uid, bundleName.c_str());

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
        ACCOUNT_LOGE("failed to get accounts by owner, bundleName = %{public}s", bundleName.c_str());
        return ERR_APPACCOUNT_SERVICE_GET_IACCOUNT_INFO_BY_OWNER;
    }

    AppAccountInfo appAccountInfo;
    for (auto account : accounts) {
        appAccountInfo = *(std::static_pointer_cast<AppAccountInfo>(account.second));

        std::set<std::string> authorizedApps;
        appAccountInfo.GetAuthorizedApps(authorizedApps);
        for (auto authorizedApp : authorizedApps) {
            result = RemoveAuthorizedAccountFromDataStorage(authorizedApp, appAccountInfo, dataStoragePtr);
            ACCOUNT_LOGI("remove authorized account from data storage, result = %{public}d", result);

            // for sync data storage
            if (NeedSyncDataStorage(appAccountInfo) == true) {
                result = RemoveAuthorizedAccountFromDataStorage(authorizedApp, appAccountInfo, dataStorageSyncPtr);
                ACCOUNT_LOGI("remove authorized account from data storage, result = %{public}d", result);
            }
        }

        result = dataStoragePtr->DeleteAccountInfoFromDataStorage(appAccountInfo);
        ACCOUNT_LOGI("delete account info from data storage, result = %{public}d", result);

        // for sync data storage
        if (NeedSyncDataStorage(appAccountInfo) == true) {
            result = dataStorageSyncPtr->DeleteAccountInfoFromDataStorage(appAccountInfo);
            ACCOUNT_LOGI("delete account info from data storage, result = %{public}d", result);
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAllAccountsFromDataStorage(const std::string &owner,
    std::vector<AppAccountInfo> &appAccounts, const std::string &bundleName,
    const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr)
{
    ACCOUNT_LOGI("enter, owner = %{public}s", owner.c_str());

    appAccounts.clear();

    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    ErrCode result = dataStoragePtr->LoadDataByLocalFuzzyQuery(owner, accounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get accounts by owner, owner = %{public}s", owner.c_str());
        return ERR_APPACCOUNT_SERVICE_GET_IACCOUNT_INFO_BY_OWNER;
    }

    for (auto account : accounts) {
        appAccounts.emplace_back(*(std::static_pointer_cast<AppAccountInfo>(account.second)));
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAllAccessibleAccountsFromDataStorage(std::vector<AppAccountInfo> &appAccounts,
    const std::string &bundleName, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr)
{
    ACCOUNT_LOGI("enter");

    appAccounts.clear();

    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::vector<std::string> accessibleAccounts;
    ErrCode result = dataStoragePtr->GetAccessibleAccountsFromDataStorage(bundleName, accessibleAccounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get accessiable account from data storage");
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

std::shared_ptr<AppAccountDataStorage> AppAccountControlManager::GetDataStorage(const uid_t &uid, const bool &autoSync)
{
    ACCOUNT_LOGI("enter");

    std::string storeId;
    ErrCode result = GetStoreId(uid, storeId);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get store id, result = %{public}d", result);
        return nullptr;
    }

    if (autoSync == true) {
        storeId = storeId + AppAccountDataStorage::DATA_STORAGE_SUFFIX;
    }

    ACCOUNT_LOGI("storeId = %{public}s", storeId.c_str());

    return std::make_shared<AppAccountDataStorage>(storeId, autoSync);
}

ErrCode AppAccountControlManager::GetStoreId(const uid_t &uid, std::string &storeId)
{
    ACCOUNT_LOGI("enter, uid = %{public}d", uid);

    std::int32_t uidToGetDeviceAccountId = uid;

    auto deviceAccountId = OhosAccountKits::GetInstance().GetDeviceAccountIdByUID(uidToGetDeviceAccountId);
    ACCOUNT_LOGI("deviceAccountId = %{public}d", deviceAccountId);

    storeId = std::to_string(deviceAccountId);

    ACCOUNT_LOGI("end, storeId = %{public}s", storeId.c_str());

    return ERR_OK;
}

bool AppAccountControlManager::NeedSyncDataStorage(const AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    bool syncEnable = false;
    ErrCode result = appAccountInfo.GetSyncEnable(syncEnable);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get sync enable");
        return false;
    }

    ACCOUNT_LOGI("syncEnable = %{public}d", syncEnable);

    if (syncEnable == false) {
        return false;
    }
    return true;
}

ErrCode AppAccountControlManager::GetAccountInfoFromDataStorage(
    AppAccountInfo &appAccountInfo, std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid)
{
    ACCOUNT_LOGI("enter");

    dataStoragePtr = GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    ErrCode result = dataStoragePtr->GetAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::AddAccountInfoIntoDataStorage(
    AppAccountInfo &appAccountInfo, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid)
{
    ACCOUNT_LOGI("enter");

    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::string owner;
    ErrCode result = appAccountInfo.GetOwner(owner);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get owner");
        return ERR_APPACCOUNT_SERVICE_GET_OWNER;
    }

    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    result = dataStoragePtr->LoadDataByLocalFuzzyQuery(owner, accounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get accounts by owner, owner = %{public}s", owner.c_str());
        return ERR_APPACCOUNT_SERVICE_GET_IACCOUNT_INFO_BY_OWNER;
    }

    if (accounts.size() == ACCOUNT_MAX_SIZE) {
        ACCOUNT_LOGE("account exceeds max size");
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_MAX_SIZE;
    }

    result = dataStoragePtr->AddAccountInfoIntoDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to add account info into data storage");
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
            ACCOUNT_LOGE("failed to add account info into data storage");
            return result;
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SaveAccountInfoIntoDataStorage(
    AppAccountInfo &appAccountInfo, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid)
{
    ACCOUNT_LOGI("enter");

    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    ErrCode result = dataStoragePtr->SaveAccountInfoIntoDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
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
            ACCOUNT_LOGI("failed to get config by id from data storage");

            result = dataStorageSyncPtr->AddAccountInfo(appAccountInfo);
            if (result != ERR_OK) {
                ACCOUNT_LOGI("failed to add account info, result = %{public}d", result);
                return ERR_APPACCOUNT_SERVICE_ADD_ACCOUNT_INFO;
            }
        } else {
            result = dataStorageSyncPtr->SaveAccountInfo(appAccountInfo);
            if (result != ERR_OK) {
                ACCOUNT_LOGI("failed to save account info, result = %{public}d", result);
                return ERR_APPACCOUNT_SERVICE_SAVE_ACCOUNT_INFO;
            }
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::DeleteAccountInfoFromDataStorage(
    AppAccountInfo &appAccountInfo, std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid)
{
    ACCOUNT_LOGI("enter");

    dataStoragePtr = GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    ErrCode result = dataStoragePtr->GetAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = dataStoragePtr->DeleteAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to delete account info from data storage");
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
            ACCOUNT_LOGI("failed to delete account info from data storage");
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SaveAuthorizedAccount(const std::string &bundleName, AppAccountInfo &appAccountInfo,
    const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid)
{
    ACCOUNT_LOGI("enter");

    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    ErrCode result = SaveAuthorizedAccountIntoDataStorage(bundleName, appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save authorized account");
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
            ACCOUNT_LOGE("failed to save authorized account");
            return result;
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::RemoveAuthorizedAccount(const std::string &bundleName,
    AppAccountInfo &appAccountInfo, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid)
{
    ACCOUNT_LOGI("enter");

    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    ErrCode result = RemoveAuthorizedAccountFromDataStorage(bundleName, appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save authorized account");
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
            ACCOUNT_LOGE("failed to save authorized account");
            return result;
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SaveAuthorizedAccountIntoDataStorage(const std::string &authorizedApp,
    AppAccountInfo &appAccountInfo, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr)
{
    ACCOUNT_LOGI("enter, authorizedApp = %{public}s", authorizedApp.c_str());

    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::string authorizedAccounts;
    ErrCode result = dataStoragePtr->GetValueFromKvStore(AppAccountDataStorage::AUTHORIZED_ACCOUNTS,
        authorizedAccounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get config by id from data storage");
    }

    std::vector<std::string> accessibleAccounts;
    auto jsonObject = dataStoragePtr->GetAccessibleAccountsFromAuthorizedAccounts(
        authorizedAccounts, authorizedApp, accessibleAccounts);

    auto accountId = appAccountInfo.GetPrimeKey();
    ACCOUNT_LOGI("accountId = %{public}s", accountId.c_str());

    auto it = std::find(accessibleAccounts.begin(), accessibleAccounts.end(), accountId);
    if (it == accessibleAccounts.end()) {
        ACCOUNT_LOGI("failed to find accountId, accountId = %{public}s", accountId.c_str());
        accessibleAccounts.emplace_back(accountId);
    }

    auto accessibleAccountArray = Json::array();
    ACCOUNT_LOGI("accessibleAccounts.size() = %{public}zu", accessibleAccounts.size());
    for (auto account : accessibleAccounts) {
        ACCOUNT_LOGI("account = %{public}s", account.c_str());
        accessibleAccountArray.emplace_back(account);
    }

    jsonObject[authorizedApp] = accessibleAccountArray;
    try {
        authorizedAccounts = jsonObject.dump();
    } catch (Json::type_error& err) {
        ACCOUNT_LOGE("failed to dump json object, reason: %{public}s", err.what());
        return ERR_APPACCOUNT_SERVICE_DUMP_JSON;
    }

    ACCOUNT_LOGI("authorizedAccounts = %{public}s", authorizedAccounts.c_str());

    result = dataStoragePtr->PutValueToKvStore(AppAccountDataStorage::AUTHORIZED_ACCOUNTS, authorizedAccounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("PutValueToKvStore failed! result %{public}d.", result);
    }
    return result;
}

ErrCode AppAccountControlManager::RemoveAuthorizedAccountFromDataStorage(const std::string &authorizedApp,
    AppAccountInfo &appAccountInfo, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr)
{
    ACCOUNT_LOGI("enter, authorizedApp = %{public}s", authorizedApp.c_str());

    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::string authorizedAccounts;
    ErrCode result = dataStoragePtr->GetValueFromKvStore(AppAccountDataStorage::AUTHORIZED_ACCOUNTS,
        authorizedAccounts);
    ACCOUNT_LOGI("authorizedAccounts = %{public}s", authorizedAccounts.c_str());
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get config by id from data storage");
    }

    std::vector<std::string> accessibleAccounts;
    auto jsonObject = dataStoragePtr->GetAccessibleAccountsFromAuthorizedAccounts(
        authorizedAccounts, authorizedApp, accessibleAccounts);

    auto accountId = appAccountInfo.GetPrimeKey();
    ACCOUNT_LOGI("accountId = %{public}s", accountId.c_str());

    auto it = std::find(accessibleAccounts.begin(), accessibleAccounts.end(), accountId);
    if (it != accessibleAccounts.end()) {
        accessibleAccounts.erase(it);
    }

    auto accessibleAccountArray = Json::array();
    ACCOUNT_LOGI("accessibleAccounts.size() = %{public}zu", accessibleAccounts.size());
    for (auto account : accessibleAccounts) {
        ACCOUNT_LOGI("account = %{public}s", account.c_str());
        accessibleAccountArray.emplace_back(account);
    }

    jsonObject[authorizedApp] = accessibleAccountArray;
    try {
        authorizedAccounts = jsonObject.dump();
    } catch (Json::type_error& err) {
        ACCOUNT_LOGE("failed to dump json object, reason: %{public}s", err.what());
        return ERR_APPACCOUNT_SERVICE_DUMP_JSON;
    }

    ACCOUNT_LOGI("authorizedAccounts = %{public}s", authorizedAccounts.c_str());

    result = dataStoragePtr->PutValueToKvStore(AppAccountDataStorage::AUTHORIZED_ACCOUNTS, authorizedAccounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save config info");
        return result;
    }

    ACCOUNT_LOGI("authorizedAccounts = %{public}s", authorizedAccounts.c_str());

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

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
#include "app_account_data_storage.h"
#include "app_account_info.h"
#include "ipc_skeleton.h"
#include "ohos_account_kits.h"
#include "singleton.h"

#include "app_account_control_manager.h"

namespace OHOS {
namespace AccountSA {
AppAccountControlManager::AppAccountControlManager()
{
    ACCOUNT_LOGI("enter");

    fileOperator_ = std::make_shared<AccountFileOperator>();
    if (fileOperator_->IsExistFile(CONFIG_PATH) == false) {
        ACCOUNT_LOGE("end, config file does not exist");
        return;
    }

    std::string content;
    if (fileOperator_->GetFileContentByPath(CONFIG_PATH, content) != ERR_OK) {
        ACCOUNT_LOGE("end, failed to get file content by path");
        return;
    }

    ACCOUNT_LOGI("content = %{public}s", content.c_str());
    auto jsonObject = Json::parse(content, nullptr, false);
    if (!jsonObject.is_discarded()) {
        auto it = jsonObject.find(ACCOUNT_MAX_SIZE_KEY);
        if (it != jsonObject.end() && jsonObject[ACCOUNT_MAX_SIZE_KEY] <= ACCOUNT_MAX_SIZE) {
            account_max_size = jsonObject[ACCOUNT_MAX_SIZE_KEY];
        } else {
            ACCOUNT_LOGE("failed to update account_max_size");
        }
    } else {
        ACCOUNT_LOGE("jsonObject is discarded");
    }

    ACCOUNT_LOGI("end, account_max_size = %{public}d", account_max_size);
}

AppAccountControlManager::~AppAccountControlManager()
{
    ACCOUNT_LOGI("enter");
}

ErrCode AppAccountControlManager::AddAccount(const std::string &name, const std::string &extraInfo,
    const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("extraInfo = %{public}s", extraInfo.c_str());

    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");

        result = appAccountInfo.SetExtraInfo(extraInfo);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to set extra info");
            return ERR_APPACCOUNT_SERVICE_SET_EXTRA_INFO;
        }

        result = AddAccountInfoIntoDataStorage(appAccountInfo);
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
    const std::string &name, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());

    ErrCode result = DeleteAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to delete account info from data storage");
        return result;
    }

    auto it = dataCache_.find(appAccountInfo.GetPrimeKey());
    if (it == dataCache_.end()) {
        ACCOUNT_LOGE("failed to get account info from data cache");
    } else {
        dataCache_.erase(it);
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAccountExtraInfo(
    const std::string &name, std::string &extraInfo, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("extraInfo = %{public}s", extraInfo.c_str());

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo);
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
    const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("extraInfo = %{public}s", extraInfo.c_str());

    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.SetExtraInfo(extraInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to set extra info");
        return ERR_APPACCOUNT_SERVICE_SET_EXTRA_INFO;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
        return result;
    }

    ACCOUNT_LOGI("end, result = %{public}d", result);

    return result;
}

ErrCode AppAccountControlManager::EnableAppAccess(const std::string &name, const std::string &authorizedApp,
    const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("authorizedApp = %{public}s", authorizedApp.c_str());
    ACCOUNT_LOGI("bundleName = %{public}s", bundleName.c_str());

    if (authorizedApp == bundleName) {
        ACCOUNT_LOGE("authorizedApp is the same to owner");
        return ERR_APPACCOUNT_SERVICE_BUNDLE_NAME_IS_THE_SAME;
    }

    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.EnableAppAccess(authorizedApp);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to enable app access");
        return ERR_APPACCOUNT_SERVICE_ENABLE_APP_ACCESS_ALREADY_EXISTS;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
        return result;
    }

    // save authorized account into data storage
    result = SaveAuthorizedAccount(authorizedApp, appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save authorized account into data storage");
        return result;
    }

    ACCOUNT_LOGI("end, result = %{public}d", result);

    return ERR_OK;
}

ErrCode AppAccountControlManager::DisableAppAccess(const std::string &name, const std::string &authorizedApp,
    const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("authorizedApp = %{public}s", authorizedApp.c_str());

    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.DisableAppAccess(authorizedApp);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to disable app access");
        return ERR_APPACCOUNT_SERVICE_DISABLE_APP_ACCESS_NOT_EXISTED;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
        return result;
    }

    // remove authorized account from data storage
    result = RemoveAuthorizedAccount(authorizedApp, appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save authorized account into data storage");
        return result;
    }

    ACCOUNT_LOGI("end, result = %{public}d", result);

    return ERR_OK;
}

ErrCode AppAccountControlManager::CheckAppAccountSyncEnable(
    const std::string &name, bool &syncEnable, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo);
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

ErrCode AppAccountControlManager::SetAppAccountSyncEnable(
    const std::string &name, const bool &syncEnable, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("syncEnable = %{public}d", syncEnable);

    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.SetSyncEnable(syncEnable);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to set sync enable");
        return ERR_APPACCOUNT_SERVICE_GET_SYNC_ENABLE;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
        return result;
    }

    ACCOUNT_LOGI("end, result = %{public}d", result);

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAssociatedData(
    const std::string &name, const std::string &key, std::string &value, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("key = %{public}s, value = %{public}s", key.c_str(), value.c_str());

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    std::string associatedData;
    result = appAccountInfo.GetAssociatedData(key, value);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get associated data");
        return ERR_APPACCOUNT_SERVICE_GET_ASSOCIATED_DATA;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SetAssociatedData(const std::string &name, const std::string &key,
    const std::string &value, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("key = %{public}s, value = %{public}s", key.c_str(), value.c_str());

    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.SetAssociatedData(key, value);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to set associated data");
        return ERR_APPACCOUNT_SERVICE_SET_ASSOCIATED_DATA;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
        return result;
    }

    ACCOUNT_LOGI("end, result = %{public}d", result);

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("credentialType = %{public}s", credentialType.c_str());

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    std::string accountCredential;
    result = appAccountInfo.GetAccountCredential(credentialType, credential);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account credential");
        return ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_CREDENTIAL;
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SetAccountCredential(const std::string &name, const std::string &credentialType,
    const std::string &credential, const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("credentialType = %{public}s, credential = %{public}s", credentialType.c_str(), credential.c_str());

    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    result = appAccountInfo.SetAccountCredential(credentialType, credential);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to set account credential");
        return ERR_APPACCOUNT_SERVICE_SET_ACCOUNT_CREDENTIAL;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage");
        return result;
    }

    ACCOUNT_LOGI("end, result = %{public}d", result);

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetOAuthToken(
    const std::string &name, std::string &token, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("token = %{public}s", token.c_str());
    ACCOUNT_LOGI("bundleName = %{public}s", bundleName.c_str());

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    auto it = dataCache_.find(appAccountInfo.GetPrimeKey());
    if (it == dataCache_.end()) {
        ACCOUNT_LOGE("failed to get account info from data cache");
        dataCache_.emplace(appAccountInfo.GetPrimeKey(), "");
        it = dataCache_.find(appAccountInfo.GetPrimeKey());
    }

    token = it->second;

    ACCOUNT_LOGI("end, token = %{public}s", token.c_str());

    return ERR_OK;
}

ErrCode AppAccountControlManager::SetOAuthToken(
    const std::string &name, const std::string &token, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("token = %{public}s", token.c_str());
    ACCOUNT_LOGI("bundleName = %{public}s", bundleName.c_str());

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    dataCache_.emplace(appAccountInfo.GetPrimeKey(), token);

    auto it = dataCache_.find(appAccountInfo.GetPrimeKey());
    if (it != dataCache_.end()) {
        ACCOUNT_LOGI("it->second = %{public}s", it->second.c_str());
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::ClearOAuthToken(const std::string &name, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("bundleName = %{public}s", bundleName.c_str());

    AppAccountInfo appAccountInfo(name, bundleName);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage");
        return result;
    }

    auto it = dataCache_.find(appAccountInfo.GetPrimeKey());
    if (it != dataCache_.end()) {
        ACCOUNT_LOGI("it->second = %{public}s", it->second.c_str());
        dataCache_.erase(it);
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAllAccounts(
    const std::string &owner, std::vector<AppAccountInfo> &appAccounts, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("owner = %{public}s", owner.c_str());

    appAccounts.clear();

    auto dataStoragePtr = GetDataStorage();
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    if (owner == bundleName) {
        std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
        ErrCode result = dataStoragePtr->LoadDataByLocalFuzzyQuery(owner, accounts);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get accounts by owner");
            return ERR_APPACCOUNT_SERVICE_GET_IACCOUNT_INFO_BY_OWNER;
        }

        for (auto account : accounts) {
            appAccounts.emplace_back(*(std::static_pointer_cast<AppAccountInfo>(account.second)));
        }
    } else {
        std::vector<std::string> accessibleAccounts;
        ErrCode result = dataStoragePtr->GetAccessibleAccountsFromDataStorage(bundleName, accessibleAccounts);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get accessiable account from data storage");
            return result;
        }

        AppAccountInfo appAccountInfo;
        for (auto account : accessibleAccounts) {
            auto position = account.find(owner);
            ACCOUNT_LOGI("position = %{public}zu", position);
            if (position == 0) {
                result = dataStoragePtr->GetAccountInfoById(account, appAccountInfo);
                if (result != ERR_OK) {
                    ACCOUNT_LOGE("failed to get account info by id");
                    return ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID;
                }

                appAccounts.emplace_back(appAccountInfo);
            }
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::GetAllAccessibleAccounts(
    std::vector<AppAccountInfo> &appAccounts, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    appAccounts.clear();

    auto dataStoragePtr = GetDataStorage();
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
            ACCOUNT_LOGE("failed to get account info by id");
            return ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID;
        }

        appAccounts.emplace_back(appAccountInfo);
    }

    std::vector<AppAccountInfo> currentAppAccounts;

    result = GetAllAccounts(bundleName, currentAppAccounts, bundleName);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get all accounts");
        return result;
    }

    for (auto account : currentAppAccounts) {
        appAccounts.emplace_back(account);
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::OnPackageRemoved(const int32_t &uid, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");
    ACCOUNT_LOGI("uid = %{public}d, bundleName = %{public}s", uid, bundleName.c_str());

    auto dataStoragePtr = GetDataStorage(false, uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    auto dataStorageSyncPtr = GetDataStorage(true, uid);
    if (dataStorageSyncPtr == nullptr) {
        ACCOUNT_LOGE("dataStorageSyncPtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    ErrCode result = dataStoragePtr->LoadDataByLocalFuzzyQuery(bundleName, accounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get accounts by bundleName");
        return ERR_APPACCOUNT_SERVICE_GET_IACCOUNT_INFO_BY_OWNER;
    }

    AppAccountInfo appAccountInfo;
    for (auto account : accounts) {
        appAccountInfo = *(std::static_pointer_cast<AppAccountInfo>(account.second));

        std::set<std::string> apps;
        appAccountInfo.GetAuthorizedApps(apps);
        for (auto app : apps) {
            result = RemoveAuthorizedAccountFromDataStorage(app, appAccountInfo);
            ACCOUNT_LOGI("remove authorized account from data storage, result = %{public}d", result);

            // for sync data storage
            if (NeedSyncDataStorage(appAccountInfo) == true) {
                result = RemoveAuthorizedAccountFromDataStorage(app, appAccountInfo, true);
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

ErrCode AppAccountControlManager::SaveAuthorizedAccount(const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    ErrCode result = SaveAuthorizedAccountIntoDataStorage(bundleName, appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save authorized account");
        return result;
    }

    // for sync data storage
    if (NeedSyncDataStorage(appAccountInfo) == true) {
        result = SaveAuthorizedAccountIntoDataStorage(bundleName, appAccountInfo, true);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to save authorized account");
            return result;
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::RemoveAuthorizedAccount(const std::string &bundleName, AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    ErrCode result = RemoveAuthorizedAccountFromDataStorage(bundleName, appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save authorized account");
        return result;
    }

    // for sync data storage
    if (NeedSyncDataStorage(appAccountInfo) == true) {
        result = RemoveAuthorizedAccountFromDataStorage(bundleName, appAccountInfo, true);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to save authorized account");
            return result;
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SaveAuthorizedAccountIntoDataStorage(
    const std::string &authorizedApp, AppAccountInfo &appAccountInfo, const bool &autoSync)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("authorizedApp = %{public}s", authorizedApp.c_str());
    ACCOUNT_LOGI("autoSync = %{public}d", autoSync);

    auto dataStoragePtr = GetDataStorage(autoSync);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    bool hasAuthorizedAccounts = true;
    std::string authorizedAccounts;
    ErrCode result = dataStoragePtr->GetConfigById(AppAccountDataStorage::AUTHORIZED_ACCOUNTS, authorizedAccounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get config by id from data storage");
        hasAuthorizedAccounts = false;
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
    ACCOUNT_LOGI("accessibleAccountArray.dump() = %{public}s", accessibleAccountArray.dump().c_str());

    jsonObject[authorizedApp] = accessibleAccountArray;
    authorizedAccounts = jsonObject.dump();

    ACCOUNT_LOGI("authorizedAccounts = %{public}s", authorizedAccounts.c_str());

    if (hasAuthorizedAccounts == false) {
        result = dataStoragePtr->AddConfigInfo(AppAccountDataStorage::AUTHORIZED_ACCOUNTS, authorizedAccounts);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to add config info");
            return result;
        }
    } else {
        result = dataStoragePtr->SavConfigInfo(AppAccountDataStorage::AUTHORIZED_ACCOUNTS, authorizedAccounts);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to save config info");
            return result;
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::RemoveAuthorizedAccountFromDataStorage(
    const std::string &authorizedApp, AppAccountInfo &appAccountInfo, const bool &autoSync)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("authorizedApp = %{public}s", authorizedApp.c_str());
    ACCOUNT_LOGI("autoSync = %{public}d", autoSync);

    auto dataStoragePtr = GetDataStorage(autoSync);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }

    std::string authorizedAccounts;
    ErrCode result = dataStoragePtr->GetConfigById(AppAccountDataStorage::AUTHORIZED_ACCOUNTS, authorizedAccounts);
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
    ACCOUNT_LOGI("accessibleAccountArray.dump() = %{public}s", accessibleAccountArray.dump().c_str());

    jsonObject[authorizedApp] = accessibleAccountArray;
    authorizedAccounts = jsonObject.dump();

    ACCOUNT_LOGI("authorizedAccounts = %{public}s", authorizedAccounts.c_str());

    result = dataStoragePtr->SavConfigInfo(AppAccountDataStorage::AUTHORIZED_ACCOUNTS, authorizedAccounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save config info");
        return result;
    }

    ACCOUNT_LOGI("authorizedAccounts = %{public}s", authorizedAccounts.c_str());

    return ERR_OK;
}

std::shared_ptr<AppAccountDataStorage> AppAccountControlManager::GetDataStorage(const bool &autoSync, const int32_t uid)
{
    ACCOUNT_LOGI("enter");

    std::string storeId;
    ErrCode result = GetStoreId(storeId, uid);
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

ErrCode AppAccountControlManager::GetStoreId(std::string &storeId, int32_t uid)
{
    ACCOUNT_LOGI("enter");

    if (uid == AppExecFwk::Constants::INVALID_UID) {
        uid = IPCSkeleton::GetCallingUid();
    }
    ACCOUNT_LOGI("uid = %{public}d", uid);

    auto deviceAccountId = OhosAccountKits::GetInstance().GetDeviceAccountIdByUID(uid);
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

ErrCode AppAccountControlManager::GetAccountInfoFromDataStorage(AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    auto dataStoragePtr = GetDataStorage();
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

ErrCode AppAccountControlManager::AddAccountInfoIntoDataStorage(AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    auto dataStoragePtr = GetDataStorage();
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
        ACCOUNT_LOGE("failed to get accounts by owner");
        return ERR_APPACCOUNT_SERVICE_GET_IACCOUNT_INFO_BY_OWNER;
    }

    if (accounts.size() == account_max_size) {
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
        dataStoragePtr = GetDataStorage(true);
        if (dataStoragePtr == nullptr) {
            ACCOUNT_LOGE("dataStoragePtr is nullptr");
            return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
        }

        result = dataStoragePtr->AddAccountInfoIntoDataStorage(appAccountInfo);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to add account info into data storage");
            return result;
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::SaveAccountInfoIntoDataStorage(AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    auto dataStoragePtr = GetDataStorage();
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
        dataStoragePtr = GetDataStorage(true);
        if (dataStoragePtr == nullptr) {
            ACCOUNT_LOGE("dataStoragePtr is nullptr");
            return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
        }

        std::string appAccountInfoFromDataStorage;
        result = dataStoragePtr->GetConfigById(appAccountInfo.GetPrimeKey(), appAccountInfoFromDataStorage);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to get config by id from data storage");

            result = dataStoragePtr->AddAccountInfo(appAccountInfo);
            if (result != ERR_OK) {
                ACCOUNT_LOGI("failed to add account info, result = %{public}d", result);
                return ERR_APPACCOUNT_SERVICE_ADD_ACCOUNT_INFO;
            }
        } else {
            result = dataStoragePtr->SaveAccountInfo(appAccountInfo);
            if (result != ERR_OK) {
                ACCOUNT_LOGI("failed to save account info, result = %{public}d", result);
                return ERR_APPACCOUNT_SERVICE_SAVE_ACCOUNT_INFO;
            }
        }
    }

    return ERR_OK;
}

ErrCode AppAccountControlManager::DeleteAccountInfoFromDataStorage(AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    auto dataStoragePtr = GetDataStorage();
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
        // for sync data storage
        dataStoragePtr = GetDataStorage(true);
        if (dataStoragePtr == nullptr) {
            ACCOUNT_LOGE("dataStoragePtr is nullptr");
            return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
        }

        result = dataStoragePtr->DeleteAccountInfoFromDataStorage(appAccountInfo);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to delete account info from data storage");
        }
    }

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

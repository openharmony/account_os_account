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

#include "app_account_control_manager.h"

#include "accesstoken_kit.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "app_account_check_labels_session.h"
#include "app_account_data_storage.h"
#include "app_account_info.h"
#include "app_account_subscribe_manager.h"
#ifdef HAS_ASSET_PART
#include "asset_system_api.h"
#endif
#include "bundle_manager_adapter.h"
#ifdef SQLITE_DLCLOSE_ENABLE
#include "database_adapter_loader.h"
#endif // SQLITE_DLCLOSE_ENABLE
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "ohos_account_kits.h"
#include "singleton.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
namespace {
const char GET_ALL_APP_ACCOUNTS[] = "ohos.permission.GET_ALL_APP_ACCOUNTS";
const char DATA_STORAGE_SUFFIX[] = "_sync";
#ifndef SQLITE_DLCLOSE_ENABLE
const char DATA_STORAGE_PREFIX[] = "encrypt_";
#endif // SQLITE_DLCLOSE_ENABLE
const char EL2_DATA_STORE_PREFIX[] = "account_";
const char EL2_DATA_STORAGE_PATH_PREFIX[] = "/data/service/el2/";
const char EL2_DATA_STORAGE_PATH_SUFFIX[] = "/account/app_account/database/";
const char AUTHORIZED_ACCOUNTS[] = "authorizedAccounts";
const std::string HYPHEN = "#";
#ifdef HAS_ASSET_PART
const std::string ALIAS_SUFFIX_CREDENTIAL = "credential";
const std::string ALIAS_SUFFIX_TOKEN = "token";
#endif
}

#ifdef HAS_ASSET_PART
static ErrCode SaveDataToAsset(int32_t localId, const std::string &hapLabel, const std::string &accountLabel,
    const std::string &alias, const std::string &value)
{
    if (value.empty()) {
        return ERR_OK;
    }
    AssetValue hapLabelValue = { .blob = { static_cast<uint32_t>(hapLabel.size()),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(hapLabel.c_str())) } };
    AssetValue accountLabelValue = { .blob = { static_cast<uint32_t>(accountLabel.size()),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(accountLabel.c_str())) } };
    AssetValue aliasValue = { .blob = { static_cast<uint32_t>(alias.size()),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(alias.c_str())) } };
    AssetValue secretValue = { .blob = { static_cast<uint32_t>(value.size()),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(value.c_str())) } };
    AssetValue accessibilityValue;
    if (localId == 0) {
        accessibilityValue.u32 = SEC_ASSET_ACCESSIBILITY_DEVICE_POWERED_ON;
    } else {
        accessibilityValue.u32 = SEC_ASSET_ACCESSIBILITY_DEVICE_UNLOCKED;
    }
    std::vector<AssetAttr> attrs = {
        { .tag = SEC_ASSET_TAG_SECRET, .value = secretValue },
        { .tag = SEC_ASSET_TAG_DATA_LABEL_NORMAL_1, .value = hapLabelValue },
        { .tag = SEC_ASSET_TAG_DATA_LABEL_NORMAL_2, .value = accountLabelValue },
        { .tag = SEC_ASSET_TAG_ACCESSIBILITY, .value = accessibilityValue },
        { .tag = SEC_ASSET_TAG_ALIAS, .value = aliasValue }
    };
    uint32_t queryCnt = 1;
    if (localId != 0) {
        AssetValue localIdValue = { .u32 = localId };
        attrs.push_back({ .tag = SEC_ASSET_TAG_USER_ID, .value = localIdValue });
        queryCnt++;
    }
    const AssetAttr *attrArr = attrs.data();
    ErrCode ret = AssetAdd(attrArr, attrs.size());
    if (ret == SEC_ASSET_DUPLICATED) {
        ret = AssetUpdate(&attrArr[4], queryCnt, attrArr, 1);  // 4 indicates the index four
    }
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("fail to save data to asset, error code: %{public}d", ret);
    }
    return ret;
}

static ErrCode GetDataFromAsset(int32_t localId, const std::string &alias, std::string &value)
{
    AssetValue aliasValue = { .blob = { static_cast<uint32_t>(alias.size()),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(alias.c_str())) } };
    AssetValue u32Value = { .u32 = SEC_ASSET_RETURN_ALL };
    std::vector<AssetAttr> attrs = {
        { .tag = SEC_ASSET_TAG_ALIAS, .value = aliasValue },
        { .tag = SEC_ASSET_TAG_RETURN_TYPE, .value = u32Value }
    };
    if (localId != 0) {
        AssetValue localIdValue = { .u32 = localId };
        attrs.push_back({ .tag = SEC_ASSET_TAG_USER_ID, .value = localIdValue });
    }

    AssetResultSet resultSet = {0};
    ErrCode ret = AssetQuery(attrs.data(), attrs.size(), &resultSet);
    if (ret != SEC_ASSET_SUCCESS) {
        ACCOUNT_LOGE("fail to get data from asset, error code: %{public}d", ret);
    } else {
        AssetAttr *secret = AssetParseAttr(resultSet.results, SEC_ASSET_TAG_SECRET);
        if (secret == nullptr) {
            ACCOUNT_LOGE("secret is nullptr");
            ret = ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
        } else {
            AssetBlob valueBlob = secret->value.blob;
            value = std::string(reinterpret_cast<const char *>(valueBlob.data), valueBlob.size);
        }
    }
    AssetFreeResultSet(&resultSet);
    return ret;
}

static ErrCode RemoveDataFromAsset(int32_t localId, const std::string &alias)
{
    AssetValue aliasValue = { .blob = { static_cast<uint32_t>(alias.size()),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(alias.c_str())) } };
    std::vector<AssetAttr> attrs = {
        { .tag = SEC_ASSET_TAG_ALIAS, .value = aliasValue }
    };
    if (localId != 0) {
        AssetValue localIdValue = { .u32 = localId };
        attrs.push_back({ .tag = SEC_ASSET_TAG_USER_ID, .value = localIdValue });
    }

    ErrCode ret = AssetRemove(attrs.data(), attrs.size());
    if (ret != SEC_ASSET_SUCCESS) {
        ACCOUNT_LOGE("fail to remove data from asset");
    }
    return ret;
}

static ErrCode RemoveDataFromAssetByLabel(int32_t localId, int32_t tag, const std::string &label)
{
    AssetValue labelValue = { .blob = { static_cast<uint32_t>(label.size()),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(label.c_str())) } };
    std::vector<AssetAttr> attrs = { { .tag = tag, .value = labelValue } };
    if (localId != 0) {
        AssetValue localIdValue = { .u32 = localId };
        attrs.push_back({ .tag = SEC_ASSET_TAG_USER_ID, .value = localIdValue });
    }

    ErrCode ret = AssetRemove(attrs.data(), attrs.size());
    if (ret != SEC_ASSET_SUCCESS) {
        ACCOUNT_LOGE("fail to remove data from asset");
    }
    return ret;
}
#endif

#ifndef SQLITE_DLCLOSE_ENABLE
void AppAccountControlManager::MoveData()
{
    DistributedKv::DistributedKvDataManager dataManager;
    DistributedKv::AppId appId = { .appId = Constants::APP_ACCOUNT_APP_ID };
    std::vector<DistributedKv::StoreId> storeIdList;
    std::lock_guard<std::mutex> storeIdLock(storePtrMutex_);
    OHOS::DistributedKv::Status status = dataManager.GetAllKvStoreId(appId, storeIdList);
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("GetAllKvStoreId failed, status=%{public}u", status);
        return;
    }
    std::lock_guard<std::mutex> accountIdLock(migratedAccountMutex_);
    while (!migratedAccounts_.empty()) {
        std::string userId = std::to_string(*(migratedAccounts_.begin()));
        for (std::string &storeId : storeIdList) {
            if (storeId.find(EL2_DATA_STORE_PREFIX) != std::string::npos
                || storeId.find(userId) == std::string::npos) {
                continue;
            }
            AccountDataStorageOptions options;
            if (storeId.find(DATA_STORAGE_PREFIX) != std::string::npos) {
                options.encrypt = true;
            }
            ACCOUNT_LOGI("MoveData start, storeId=%{public}s", storeId.c_str());
            auto oldPtr = std::make_shared<AppAccountDataStorage>(storeId, options);
            options.encrypt = false;
            options.area = DistributedKv::EL2;
            options.baseDir = EL2_DATA_STORAGE_PATH_PREFIX + userId + EL2_DATA_STORAGE_PATH_SUFFIX;
            auto newPtr = std::make_shared<AppAccountDataStorage>(EL2_DATA_STORE_PREFIX + userId, options);
            ErrCode result = newPtr->MoveData(oldPtr);
            if (result != ERR_OK) {
                ACCOUNT_LOGE("MoveData failed, storeId=%{public}s, result=%{public}u",
                    storeId.c_str(), result);
                continue;
            }
            result = oldPtr->DeleteKvStore();
            if (result != ERR_OK) {
                ACCOUNT_LOGE("DeleteKvStore failed, storeId=%{public}s, result=%{public}u", storeId.c_str(), result);
            }
        }
        migratedAccounts_.erase(migratedAccounts_.begin());
    }
    ACCOUNT_LOGI("MoveData complete");
}
#else
void AppAccountControlManager::MoveData()
{
    ACCOUNT_LOGI("MoveData not enabled.");
}
#endif // SQLITE_DLCLOSE_ENABLE

void AppAccountControlManager::AddMigratedAccount(int32_t localId)
{
    {
        std::lock_guard<std::mutex> lock(migratedAccountMutex_);
        migratedAccounts_.insert(localId);
    }
    MoveData();
}

AppAccountControlManager &AppAccountControlManager::GetInstance()
{
    static AppAccountControlManager *instance = new (std::nothrow) AppAccountControlManager();
    return *instance;
}

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
    DatabaseTransaction dbTransaction = nullptr;
    ErrCode result = StartDbTransaction(dataStoragePtr, dbTransaction);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("StartDbTransaction failed, result = %{public}d", result);
        return result;
    }
    result = DeleteAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, uid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to delete account info from data storage, result %{public}d.", result);
        return result;
    }
    RemoveAssociatedDataCacheByAccount(uid, name);
#ifdef HAS_ASSET_PART
    RemoveDataFromAssetByLabel(uid / UID_TRANSFORM_DIVISOR, SEC_ASSET_TAG_DATA_LABEL_NORMAL_2,
        appAccountInfo.GetPrimeKey());
#endif

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
    result = CommitDbTransaction(dataStoragePtr, dbTransaction);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to commit db transaction, result %{public}d.", result);
        return result;
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
        ACCOUNT_LOGE("Failed to enable app access, result=%{public}d.", result);
        return result;
    }
    DatabaseTransaction dbTransaction = nullptr;
    result = StartDbTransaction(dataStoragePtr, dbTransaction);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("StartDbTransaction failed, result = %{public}d", result);
        return result;
    }
    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, appAccountCallingInfo.callingUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return result;
    }

    // save authorized account into data storage
    result = SaveAuthorizedAccount(authorizedApp, appAccountInfo, dataStoragePtr, appAccountCallingInfo.callingUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to save authorized account into data storage, result=%{public}d.", result);
        return result;
    }
    result = CommitDbTransaction(dataStoragePtr, dbTransaction);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to commit db transaction, result %{public}d.", result);
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
    DatabaseTransaction dbTransaction = nullptr;
    result = StartDbTransaction(dataStoragePtr, dbTransaction);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("StartDbTransaction failed, result = %{public}d", result);
        return result;
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
    result = CommitDbTransaction(dataStoragePtr, dbTransaction);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to commit db transaction, result %{public}d.", result);
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
    if (BundleManagerAdapter::GetInstance()->GetNameForUid(uid, bundleName) != ERR_OK) {
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
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(appAccountCallingInfo.callingUid, false);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return result;
    }

    result = appAccountInfo.GetAccountCredential(credentialType, credential);
    if (result != ERR_OK) {
        return result;
    }
#ifdef HAS_ASSET_PART
    std::string alias = credential;
    credential = "";
    GetDataFromAsset(appAccountCallingInfo.callingUid / UID_TRANSFORM_DIVISOR, alias, credential);
#endif
    return result;
}

ErrCode AppAccountControlManager::SetAccountCredential(const std::string &name, const std::string &credentialType,
    const std::string &credential, const AppAccountCallingInfo &appAccountCallingInfo)
{
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(appAccountCallingInfo.callingUid, false);
    AppAccountInfo appAccountInfo(name, appAccountCallingInfo.bundleName);
    appAccountInfo.SetAppIndex(appAccountCallingInfo.appIndex);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    result = appAccountInfo.SetAccountCredential(credentialType, credential);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to set account credential, result %{public}d.", result);
        return result;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, appAccountCallingInfo.callingUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
        return result;
    }
#ifdef HAS_ASSET_PART
    std::string hapLabel = appAccountCallingInfo.bundleName + Constants::HYPHEN +
        std::to_string(appAccountCallingInfo.appIndex);
    std::string credentialAlias;
    appAccountInfo.GetAccountCredential(credentialType, credentialAlias);
    int32_t localId = appAccountCallingInfo.callingUid / UID_TRANSFORM_DIVISOR;
    result = SaveDataToAsset(localId, hapLabel, appAccountInfo.GetAlias(), credentialAlias, credential);
#endif
    return result;
}

ErrCode AppAccountControlManager::DeleteAccountCredential(const std::string &name, const std::string &credentialType,
    const AppAccountCallingInfo &callingInfo)
{
    AppAccountInfo appAccountInfo(name, callingInfo.bundleName);
    appAccountInfo.SetAppIndex(callingInfo.appIndex);
    auto dataStoragePtr = GetDataStorage(callingInfo.callingUid, false);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
#ifdef HAS_ASSET_PART
    std::string alias;
    appAccountInfo.GetAccountCredential(credentialType, alias);
    RemoveDataFromAsset(callingInfo.callingUid / UID_TRANSFORM_DIVISOR, alias);
#endif
    result = appAccountInfo.DeleteAccountCredential(credentialType);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to delete account credential, result %{public}d.", result);
        return result;
    }

    result = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, callingInfo.callingUid);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", result);
    }
    return result;
}

ErrCode AppAccountControlManager::GetOAuthToken(
    const AuthenticatorSessionRequest &request, std::string &token, const uint32_t apiVersion)
{
    AppAccountInfo appAccountInfo(request.name, request.owner);
    appAccountInfo.SetAppIndex(0);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid, false);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    bool isVisible = false;
    result = appAccountInfo.CheckOAuthTokenVisibility(request.authType, request.callerBundleName +
        GetBundleKeySuffix(request.appIndex), isVisible, apiVersion);
    if ((result != ERR_OK) || (!isVisible)) {
        ACCOUNT_LOGE("failed to get oauth token for permission denied, result %{public}d.", result);
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    result = appAccountInfo.GetOAuthToken(request.authType, token, apiVersion);
    if (result != ERR_OK) {
        return result;
    }
#ifdef HAS_ASSET_PART
    std::string alias = token;
    token = "";
    GetDataFromAsset(request.callerUid / UID_TRANSFORM_DIVISOR, alias, token);
    if (token.empty() && (apiVersion < Constants::API_VERSION9)) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST;
    }
#endif
    return ERR_OK;
}

ErrCode AppAccountControlManager::SetOAuthToken(const AuthenticatorSessionRequest &request)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AppAccountInfo appAccountInfo(request.name, request.callerBundleName);
    appAccountInfo.SetAppIndex(request.appIndex);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid, false);
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
        return result;
    }
#ifdef HAS_ASSET_PART
    std::string hapLabel = request.callerBundleName + Constants::HYPHEN + std::to_string(request.appIndex);
    std::string authTypeAlias;
    appAccountInfo.GetOAuthToken(request.authType, authTypeAlias);
    int32_t localId = request.callerUid / UID_TRANSFORM_DIVISOR;
    result = SaveDataToAsset(localId, hapLabel, appAccountInfo.GetAlias(), authTypeAlias, request.token);
#endif
    return result;
}

ErrCode AppAccountControlManager::DeleteOAuthToken(
    const AuthenticatorSessionRequest &request, const uint32_t apiVersion)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AppAccountInfo appAccountInfo(request.name, request.owner);
    appAccountInfo.SetAppIndex(0);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid);
    ErrCode ret = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", ret);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    bool isVisible = false;
    ret = appAccountInfo.CheckOAuthTokenVisibility(request.authType, request.callerBundleName +
        GetBundleKeySuffix(request.appIndex), isVisible, apiVersion);
    if ((!isVisible) || (ret != ERR_OK)) {
        ACCOUNT_LOGE("failed to delete oauth token for permission denied, result %{public}d.", ret);
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    std::string token = request.token;
#ifdef HAS_ASSET_PART
    std::string alias;
    ret = appAccountInfo.GetOAuthToken(request.authType, alias, apiVersion);
    if (ret != ERR_OK) {
        return apiVersion >= Constants::API_VERSION9 ? ret : ERR_OK;
    }
    GetDataFromAsset(request.callerUid / UID_TRANSFORM_DIVISOR, alias, token);
    if (token != request.token) {
        return ERR_OK;
    }
    RemoveDataFromAsset(request.callerUid / UID_TRANSFORM_DIVISOR, alias);
    token = alias;
#endif
    if (apiVersion >= Constants::API_VERSION9) {
        bool isOwnerSelf = request.owner == request.callerBundleName;
        ret = appAccountInfo.DeleteAuthToken(request.authType, token, isOwnerSelf);
        if (ret != ERR_OK) {
            return ret;
        }
    } else {
        ret = appAccountInfo.DeleteOAuthToken(request.authType, token);
        if (ret == ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST) {
            return ERR_OK;
        }
    }
    ret = SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to save account info into data storage, result %{public}d.", ret);
        return ret;
    }
    return ret;
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
        return ret;
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
    appAccountInfo.SetAppIndex(0);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = GetDataStorage(request.callerUid);
    ErrCode result = GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info from data storage, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    std::string bundleKey = request.callerBundleName + GetBundleKeySuffix(request.appIndex);
    std::vector<OAuthTokenInfo> allTokenInfos;
    result = appAccountInfo.GetAllOAuthTokens(allTokenInfos);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get all oauth token from data storage, result %{public}d.", result);
        return result;
    }
    for (auto tokenInfo : allTokenInfos) {
        if ((bundleKey != request.owner) &&
            (tokenInfo.authList.find(bundleKey) == tokenInfo.authList.end())) {
            continue;
        }
#ifdef HAS_ASSET_PART
        std::string alias = tokenInfo.token;
        tokenInfo.token = "";
        GetDataFromAsset(request.callerUid / UID_TRANSFORM_DIVISOR, alias, tokenInfo.token);
#endif
        if (tokenInfo.token.empty() && tokenInfo.authList.empty()) { // for api 8 logic
            continue;
        }
        tokenInfo.authList.clear();
        tokenInfos.push_back(tokenInfo);
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

std::string AppAccountControlManager::GetBundleKeySuffix(const uint32_t &appIndex)
{
    return (appIndex == 0 ? "" : HYPHEN + std::to_string(appIndex));
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
    ErrCode result = AccountPermissionManager::VerifyPermission(GET_ALL_APP_ACCOUNTS);
    std::string bundleKey = bundleName + GetBundleKeySuffix(appIndex);
    if ((bundleKey == owner) || (result == ERR_OK)) {
        std::string key = owner + Constants::HYPHEN + std::to_string(0);
        result = GetAllAccountsFromDataStorage(key, appAccounts, owner, dataStoragePtr);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get all accounts from data storage, result = %{public}d", result);
            return result;
        }
        return ERR_OK;
    }

    std::vector<std::string> accessibleAccounts;
    result = dataStoragePtr->GetAccessibleAccountsFromDataStorage(bundleKey, accessibleAccounts);
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
        if (appAccountInfo.GetOwner() == owner && AppAccountSubscribeManager::CheckAppIsMaster(account)) {
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
        if (it->first == AUTHORIZED_ACCOUNTS) {
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
    ErrCode result = AccountPermissionManager::VerifyPermission(GET_ALL_APP_ACCOUNTS);
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
    return AppAccountAuthenticatorSessionManager::GetInstance().SelectAccountsByOptions(candidateAccounts, request);
}

void AppAccountControlManager::RemoveAssociatedDataCacheByUid(const uid_t &uid)
{
    std::lock_guard<std::mutex> lock(associatedDataMutex_);
    associatedDataCache_.erase(uid);
}

void AppAccountControlManager::RemoveAssociatedDataCacheByAccount(const uid_t &uid, const std::string &name)
{
    std::lock_guard<std::mutex> lock(associatedDataMutex_);
    auto it = associatedDataCache_.find(uid);
    if ((it == associatedDataCache_.end()) || (it->second.name != name)) {
        return;
    }
    associatedDataCache_.erase(it);
}

void AppAccountControlManager::SetOsAccountRemoved(int32_t localId, bool isRemoved)
{
    if (isRemoved) {
        removedOsAccounts_.EnsureInsert(localId, true);
    } else {
        removedOsAccounts_.Erase(localId);
    }
}

bool AppAccountControlManager::IsOsAccountRemoved(int32_t localId)
{
    bool isRemoved = false;
    return removedOsAccounts_.Find(localId, isRemoved);
}

ErrCode AppAccountControlManager::OnPackageRemoved(
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    RemoveAssociatedDataCacheByUid(uid);
    int32_t localId = uid / UID_TRANSFORM_DIVISOR;
    if (IsOsAccountRemoved(localId)) {
        return ERR_OK;
    }
    ErrCode errCode = RemoveAppAccountData(uid, bundleName, appIndex);
    CloseDataStorage();
    return errCode;
}

ErrCode AppAccountControlManager::RemoveAppAccountDataFromDataStorage(
    const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const std::string &key,
    const uint32_t &appIndex, const std::shared_ptr<AppAccountDataStorage> &dataStorageSyncPtr = nullptr)
{
    DatabaseTransaction dbTransaction = nullptr;
    ErrCode result = StartDbTransaction(dataStoragePtr, dbTransaction);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("StartDbTransaction failed, result = %{public}d", result);
        return result;
    }
    std::map<std::string, std::shared_ptr<IAccountInfo>> accounts;
    result = dataStoragePtr->LoadDataByLocalFuzzyQuery(key, accounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to get accounts by owner, result = %{public}d, key = %{public}s", result, key.c_str());
        return result;
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
    result = CommitDbTransaction(dataStoragePtr, dbTransaction);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to commit db transaction, result %{public}d.", result);
        return result;
    }
    return ERR_OK;
}

ErrCode AppAccountControlManager::RemoveAppAccountData(
    const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex)
{
    auto dataStoragePtr = GetDataStorage(uid);
    if (dataStoragePtr == nullptr) {
        ACCOUNT_LOGE("dataStoragePtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }
    std::string key = bundleName + Constants::HYPHEN + std::to_string(appIndex);
#ifdef DISTRIBUTED_FEATURE_ENABLED
    auto dataStorageSyncPtr = GetDataStorage(uid, true);
    if (dataStorageSyncPtr == nullptr) {
        ACCOUNT_LOGE("dataStorageSyncPtr is nullptr");
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }
    ErrCode result = RemoveAppAccountDataFromDataStorage(dataStoragePtr, key, appIndex, dataStorageSyncPtr);
#else
    ErrCode result = RemoveAppAccountDataFromDataStorage(dataStoragePtr, key, appIndex);
#endif // DISTRIBUTED_FEATURE_ENABLED
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to remove accounts from database, result = %{public}d, bundleName = %{public}s",
            result, bundleName.c_str());
        return result;
    }
#ifdef HAS_ASSET_PART
    RemoveDataFromAssetByLabel(uid / UID_TRANSFORM_DIVISOR, SEC_ASSET_TAG_DATA_LABEL_NORMAL_1, key);
#endif
    return ERR_OK;
}

ErrCode AppAccountControlManager::OnUserStopping(int32_t userId)
{
    std::string storeId = std::to_string(userId);
    std::string syncStoreId = storeId + DATA_STORAGE_SUFFIX;
    std::lock_guard<std::mutex> lock(storePtrMutex_);
    storePtrMap_.erase(storeId);
    storePtrMap_.erase(syncStoreId);
    return ERR_OK;
}

ErrCode AppAccountControlManager::OnUserRemoved(int32_t userId)
{
    return OnUserStopping(userId);
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
        return result;
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
        if (!AppAccountSubscribeManager::CheckAppIsMaster(account)) {
            continue;
        }
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

#ifndef SQLITE_DLCLOSE_ENABLE
std::shared_ptr<AppAccountDataStorage> AppAccountControlManager::GetDataStorageByUserId(
    int32_t userId, const bool &autoSync, DistributedKv::SecurityLevel securityLevel)
{
    std::string storeId = std::to_string(userId);
    if (autoSync == true) {
        storeId = storeId + DATA_STORAGE_SUFFIX;
    }
    std::lock_guard<std::mutex> lock(storePtrMutex_);
    auto it = storePtrMap_.find(storeId);
    if ((it != storePtrMap_.end()) && (it->second != nullptr)) {
        return it->second;
    }
    AccountDataStorageOptions options;
    options.area = DistributedKv::EL2;
#else
std::shared_ptr<AppAccountDataStorage> AppAccountControlManager::GetDataStorageByUserId(
    int32_t userId, const bool &autoSync, DbAdapterSecurityLevel securityLevel)
{
    std::string storeId = std::to_string(userId);
    if (autoSync == true) {
        storeId = storeId + DATA_STORAGE_SUFFIX;
    }
    std::lock_guard<std::mutex> lock(storePtrMutex_);
    auto it = storePtrMap_.find(storeId);
    if ((it != storePtrMap_.end()) && (it->second != nullptr)) {
        return it->second;
    }
    DbAdapterOptions options;
    options.area = DbAdapterArea::EL2;
#endif // SQLITE_DLCLOSE_ENABLE
    options.autoSync = autoSync;
    options.securityLevel = securityLevel;
    options.baseDir = EL2_DATA_STORAGE_PATH_PREFIX + std::to_string(userId) + EL2_DATA_STORAGE_PATH_SUFFIX;
    auto storePtr = std::make_shared<AppAccountDataStorage>(EL2_DATA_STORE_PREFIX + storeId, options);
    storePtrMap_[storeId] = storePtr;
    return storePtr;
}

#ifndef SQLITE_DLCLOSE_ENABLE
std::shared_ptr<AppAccountDataStorage> AppAccountControlManager::GetDataStorage(
    const uid_t &uid, const bool &autoSync, DistributedKv::SecurityLevel securityLevel)
#else
std::shared_ptr<AppAccountDataStorage> AppAccountControlManager::GetDataStorage(
    const uid_t &uid, const bool &autoSync, DbAdapterSecurityLevel securityLevel)
#endif // SQLITE_DLCLOSE_ENABLE
{
    return GetDataStorageByUserId(uid / UID_TRANSFORM_DIVISOR, autoSync, securityLevel);
}

void AppAccountControlManager::CloseDataStorage()
{
    if (!storePtrMutex_.try_lock()) {
        return;
    }
    for (auto &item : storePtrMap_) {
        if (item.second == nullptr || item.second.use_count() > 1) {
            continue;
        }
        ErrCode result = item.second->Close();
        if (result == ERR_OK) {
            item.second = nullptr;
        }
        ACCOUNT_LOGI("Close storage, storeId: %{public}s, result: %{public}d", item.first.c_str(), result);
    }
#ifdef SQLITE_DLCLOSE_ENABLE
    for (auto &item : storePtrMap_) {
        if (item.second != nullptr) {
            storePtrMutex_.unlock();
            return;
        }
    }
    bool dlCloseRet = DatabaseAdapterLoader::GetInstance().CheckAndUnload();
    ACCOUNT_LOGI("Close so end, ret: %{public}d", dlCloseRet);
#endif // SQLITE_DLCLOSE_ENABLE
    storePtrMutex_.unlock();
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
        return result;
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
        // Here do not open transaction, as it should be opened before this func is called
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
        // Here do not open transaction, as it should be opened before this func is called
        std::string appAccountInfoFromDataStorage;
        result = dataStorageSyncPtr->GetValueFromKvStore(appAccountInfo.GetPrimeKey(), appAccountInfoFromDataStorage);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get config by id from data storage, result %{public}d.", result);

            result = dataStorageSyncPtr->AddAccountInfo(appAccountInfo);
            if (result != ERR_OK) {
                ACCOUNT_LOGE("failed to add account info, result = %{public}d", result);
                return result;
            }
        } else {
            result = dataStorageSyncPtr->SaveAccountInfo(appAccountInfo);
            if (result != ERR_OK) {
                ACCOUNT_LOGE("failed to save account info, result = %{public}d", result);
                return result;
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
        // Here do not open transaction, as it should be opened before this func is called
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
        // Here do not open transaction, as it should be opened before this func is called
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
        // Here do not open transaction, as it should be opened before this func is called
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
    ErrCode result = dataStoragePtr->GetValueFromKvStore(AUTHORIZED_ACCOUNTS,
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

    AddVectorStringToJson(jsonObject, authorizedApp, accessibleAccounts);
    authorizedAccounts = PackJsonToString(jsonObject);
    if (authorizedAccounts.empty()) {
        ACCOUNT_LOGE("Failed to dump json object.");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }

    result = dataStoragePtr->PutValueToKvStore(AUTHORIZED_ACCOUNTS, authorizedAccounts);
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
    ErrCode result = dataStoragePtr->GetValueFromKvStore(AUTHORIZED_ACCOUNTS,
        authorizedAccounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get authorized accounts from data storage, result %{public}d.", result);
    }

    std::vector<std::string> accessibleAccounts;
    auto jsonObject = dataStoragePtr->GetAccessibleAccountsFromAuthorizedAccounts(
        authorizedAccounts, authorizedApp, accessibleAccounts);

    auto accountId = appAccountInfo.GetPrimeKey();

    auto it = std::find(accessibleAccounts.begin(), accessibleAccounts.end(), accountId);
    if (it != accessibleAccounts.end()) {
        accessibleAccounts.erase(it);
    }

    AddVectorStringToJson(jsonObject, authorizedApp, accessibleAccounts);
    authorizedAccounts = PackJsonToString(jsonObject);
    if (authorizedAccounts.empty()) {
        ACCOUNT_LOGE("Failed to dump json object.");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }

    result = dataStoragePtr->PutValueToKvStore(AUTHORIZED_ACCOUNTS, authorizedAccounts);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to save config info, result %{public}d.", result);
        return result;
    }

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

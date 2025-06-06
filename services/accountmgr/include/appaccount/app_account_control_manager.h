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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CONTROL_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CONTROL_MANAGER_H

#include "app_mgr_interface.h"
#include "app_account_authenticator_manager.h"
#include "app_account_data_storage.h"
#include "iapp_account_authenticator_callback.h"
#include "iremote_object.h"
#include "want_params.h"
#include "safe_map.h"

namespace OHOS {
namespace AccountSA {
struct AssociatedDataCacheItem {
    std::map<std::string, std::string> data;
    std::string name;
    int32_t freq;
};

class AppAccountControlManager {
public:
    static AppAccountControlManager &GetInstance();
    ErrCode AddAccount(const std::string &name, const std::string &extraInfo, const uid_t &uid,
        const std::string &bundleName, AppAccountInfo &appAccountInfo);
    ErrCode CreateAccount(const std::string &name, const CreateAccountOptions &options, const uid_t &uid,
        const std::string &bundleName, AppAccountInfo &appAccountInfo);
    ErrCode DeleteAccount(
        const std::string &name, const uid_t &uid, const std::string &bundleName, AppAccountInfo &appAccountInfo);

    ErrCode GetAccountExtraInfo(const std::string &name, std::string &extraInfo,
        const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);
    ErrCode SetAccountExtraInfo(const std::string &name, const std::string &extraInfo, const uid_t &uid,
        const std::string &bundleName, AppAccountInfo &appAccountInfo);

    ErrCode EnableAppAccess(const std::string &name, const std::string &authorizedApp,
        AppAccountCallingInfo &appAccountCallingInfo, AppAccountInfo &appAccountInfo,
        const uint32_t apiVersion = Constants::API_VERSION7);
    ErrCode DisableAppAccess(const std::string &name, const std::string &authorizedApp,
        AppAccountCallingInfo &appAccountCallingInfo, AppAccountInfo &appAccountInfo,
        const uint32_t apiVersion = Constants::API_VERSION7);
    ErrCode CheckAppAccess(const std::string &name, const std::string &authorizedApp, bool &isAccessible,
        const AppAccountCallingInfo &appAccountCallingInfo);

    ErrCode CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable,
        const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);
    ErrCode SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable, const uid_t &uid,
        const std::string &bundleName, AppAccountInfo &appAccountInfo);
    ErrCode GetAssociatedData(const std::string &name, const std::string &key,
        std::string &value, const uid_t &uid);
    ErrCode SetAssociatedData(const std::string &name, const std::string &key, const std::string &value,
        const AppAccountCallingInfo &appAccountCallingInfo);

    ErrCode GetAccountCredential(const std::string &name, const std::string &credentialType, std::string &credential,
        const AppAccountCallingInfo &appAccountCallingInfo);
    ErrCode SetAccountCredential(const std::string &name, const std::string &credentialType,
        const std::string &credential, const AppAccountCallingInfo &appAccountCallingInfo);
    ErrCode DeleteAccountCredential(const std::string &name, const std::string &credentialType,
        const AppAccountCallingInfo &callingInfo);

    ErrCode GetOAuthToken(const AuthenticatorSessionRequest &request,
        std::string &token, const uint32_t apiVersion = Constants::API_VERSION8);
    ErrCode SetOAuthToken(const AuthenticatorSessionRequest &request);
    ErrCode DeleteOAuthToken(
        const AuthenticatorSessionRequest &request, const uint32_t apiVersion = Constants::API_VERSION8);
    ErrCode SetOAuthTokenVisibility(
        const AuthenticatorSessionRequest &request, const uint32_t apiVersion = Constants::API_VERSION8);
    ErrCode CheckOAuthTokenVisibility(const AuthenticatorSessionRequest &request,
        bool &isVisible, const uint32_t apiVersion = Constants::API_VERSION8);
    ErrCode GetAllOAuthTokens(const AuthenticatorSessionRequest &request, std::vector<OAuthTokenInfo> &tokenInfos);
    ErrCode GetOAuthList(const AuthenticatorSessionRequest &request,
        std::set<std::string> &oauthList, const uint32_t apiVersion = Constants::API_VERSION8);

    ErrCode GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts, const uid_t &uid,
        const std::string &bundleName, const uint32_t &appIndex);
    ErrCode GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts,
        const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);

    ErrCode SelectAccountsByOptions(
        const SelectAccountsOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback,
        const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);

    ErrCode OnPackageRemoved(const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);
    ErrCode OnUserStopping(int32_t userId);
    ErrCode OnUserRemoved(int32_t userId);

    ErrCode GetAllAccountsFromDataStorage(const std::string &owner, std::vector<AppAccountInfo> &appAccounts,
        const std::string &bundleName, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr);
    ErrCode GetAllAccessibleAccountsFromDataStorage(std::vector<AppAccountInfo> &appAccounts,
        const std::string &bundleName, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr,
        const uint32_t &appIndex);
    ErrCode GetAccountInfoFromDataStorage(
        AppAccountInfo &appAccountInfo, std::shared_ptr<AppAccountDataStorage> &dataStoragePtr);
#ifndef SQLITE_DLCLOSE_ENABLE
    std::shared_ptr<AppAccountDataStorage> GetDataStorage(const uid_t &uid, const bool &autoSync = false,
        DistributedKv::SecurityLevel securityLevel = DistributedKv::SecurityLevel::S1);
#else
    std::shared_ptr<AppAccountDataStorage> GetDataStorage(const uid_t &uid, const bool &autoSync = false,
        DbAdapterSecurityLevel securityLevel = DbAdapterSecurityLevel::S1);
#endif // SQLITE_DLCLOSE_ENABLE
    void CloseDataStorage();

    void AddMigratedAccount(int32_t localId);
    void MoveData();
    void SetOsAccountRemoved(int32_t localId, bool isRemoved);

private:
    AppAccountControlManager() = default;
    ~AppAccountControlManager() = default;
    DISALLOW_COPY_AND_MOVE(AppAccountControlManager);
    void PopDataFromAssociatedDataCache();
    void RemoveAssociatedDataCacheByUid(const uid_t &uid);
    void RemoveAssociatedDataCacheByAccount(const uid_t &uid, const std::string &name);
    ErrCode GetAssociatedDataFromStorage(const std::string &name, const std::string &key, std::string &value,
        const uid_t &uid, const uint32_t &appIndex);
#ifndef SQLITE_DLCLOSE_ENABLE
    std::shared_ptr<AppAccountDataStorage> GetDataStorageByUserId(int32_t userId, const bool &autoSync = false,
        DistributedKv::SecurityLevel securityLevel = DistributedKv::SecurityLevel::S1);
#else
    std::shared_ptr<AppAccountDataStorage> GetDataStorageByUserId(int32_t userId, const bool &autoSync = false,
        DbAdapterSecurityLevel securityLevel = DbAdapterSecurityLevel::S1);
#endif // SQLITE_DLCLOSE_ENABLE
    bool NeedSyncDataStorage(const AppAccountInfo &appAccountInfo);
    ErrCode AddAccountInfoIntoDataStorage(AppAccountInfo &appAccountInfo,
        const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid);
    ErrCode SaveAccountInfoIntoDataStorage(AppAccountInfo &appAccountInfo,
        const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid);
    ErrCode DeleteAccountInfoFromDataStorage(
        AppAccountInfo &appAccountInfo, std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid);

    ErrCode SaveAuthorizedAccount(const std::string &authorizedApp, AppAccountInfo &appAccountInfo,
        const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid);
    ErrCode RemoveAuthorizedAccount(const std::string &authorizedApp, AppAccountInfo &appAccountInfo,
        const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid);
    ErrCode SaveAuthorizedAccountIntoDataStorage(const std::string &authorizedApp, AppAccountInfo &appAccountInfo,
        const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr);
    ErrCode RemoveAuthorizedAccountFromDataStorage(const std::string &authorizedApp, AppAccountInfo &appAccountInfo,
        const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr);
    bool IsOsAccountRemoved(int32_t localId);
    ErrCode RemoveAppAccountData(const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);
    std::string GetBundleKeySuffix(const uint32_t &appIndex);
    ErrCode RemoveAppAccountDataFromDataStorage(const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr,
        const std::string &key, const uint32_t &appIndex,
        const std::shared_ptr<AppAccountDataStorage> &dataStorageSyncPtr);

private:
    std::mutex mutex_;
    std::mutex storePtrMutex_;
    std::mutex associatedDataMutex_;
    std::map<uid_t, AssociatedDataCacheItem> associatedDataCache_;
    std::map<std::string, std::shared_ptr<AppAccountDataStorage>> storePtrMap_;
    std::mutex migratedAccountMutex_;
    std::set<int32_t> migratedAccounts_;
    SafeMap<int32_t, bool> removedOsAccounts_;
    std::size_t ACCOUNT_MAX_SIZE = 1000;
    std::size_t ASSOCIATED_DATA_CACHE_MAX_SIZE = 5;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CONTROL_MANAGER_H

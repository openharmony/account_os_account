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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CONTROL_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CONTROL_MANAGER_H

#include "app_account_authenticator_manager.h"
#include "app_account_data_storage.h"
#include "iapp_account_authenticator_callback.h"
#include "iremote_object.h"
#include "singleton.h"
#include "want_params.h"

namespace OHOS {
namespace AccountSA {
class AppAccountControlManager : public DelayedSingleton<AppAccountControlManager> {
public:
    AppAccountControlManager();
    virtual ~AppAccountControlManager() = default;

    ErrCode AddAccount(const std::string &name, const std::string &extraInfo, const uid_t &uid,
        const std::string &bundleName, AppAccountInfo &appAccountInfo);
    ErrCode DeleteAccount(
        const std::string &name, const uid_t &uid, const std::string &bundleName, AppAccountInfo &appAccountInfo);

    ErrCode GetAccountExtraInfo(
        const std::string &name, std::string &extraInfo, const uid_t &uid, const std::string &bundleName);
    ErrCode SetAccountExtraInfo(const std::string &name, const std::string &extraInfo, const uid_t &uid,
        const std::string &bundleName, AppAccountInfo &appAccountInfo);

    ErrCode EnableAppAccess(const std::string &name, const std::string &authorizedApp, const uid_t &uid,
        const std::string &bundleName, AppAccountInfo &appAccountInfo);
    ErrCode DisableAppAccess(const std::string &name, const std::string &authorizedApp, const uid_t &uid,
        const std::string &bundleName, AppAccountInfo &appAccountInfo);

    ErrCode CheckAppAccountSyncEnable(
        const std::string &name, bool &syncEnable, const uid_t &uid, const std::string &bundleName);
    ErrCode SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable, const uid_t &uid,
        const std::string &bundleName, AppAccountInfo &appAccountInfo);

    ErrCode GetAssociatedData(const std::string &name, const std::string &key, std::string &value, const uid_t &uid,
        const std::string &bundleName);
    ErrCode SetAssociatedData(const std::string &name, const std::string &key, const std::string &value,
        const uid_t &uid, const std::string &bundleName, AppAccountInfo &appAccountInfo);

    ErrCode GetAccountCredential(const std::string &name, const std::string &credentialType, std::string &credential,
        const uid_t &uid, const std::string &bundleName);
    ErrCode SetAccountCredential(const std::string &name, const std::string &credentialType,
        const std::string &credential, const uid_t &uid, const std::string &bundleName,
        AppAccountInfo &appAccountInfo);

    ErrCode GetOAuthToken(const OAuthRequest &request, std::string &token);
    ErrCode SetOAuthToken(const OAuthRequest &request);
    ErrCode DeleteOAuthToken(const OAuthRequest &request);
    ErrCode SetOAuthTokenVisibility(const OAuthRequest &request);
    ErrCode CheckOAuthTokenVisibility(const OAuthRequest &request, bool &isVisible);
    ErrCode GetAllOAuthTokens(const OAuthRequest &request, std::vector<OAuthTokenInfo> &tokenInfos);
    ErrCode GetOAuthList(const OAuthRequest &request, std::set<std::string> &oauthList);

    ErrCode GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts, const uid_t &uid,
        const std::string &bundleName);
    ErrCode GetAllAccessibleAccounts(
        std::vector<AppAccountInfo> &appAccounts, const uid_t &uid, const std::string &bundleName);

    ErrCode OnPackageRemoved(const uid_t &uid, const std::string &bundleName);

    ErrCode GetAllAccountsFromDataStorage(const std::string &owner, std::vector<AppAccountInfo> &appAccounts,
        const std::string &bundleName, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr);
    ErrCode GetAllAccessibleAccountsFromDataStorage(std::vector<AppAccountInfo> &appAccounts,
        const std::string &bundleName, const std::shared_ptr<AppAccountDataStorage> &dataStoragePtr);

private:
    std::shared_ptr<AppAccountDataStorage> GetDataStorage(const uid_t &uid, const bool &autoSync = false);
    ErrCode GetStoreId(const uid_t &uid, std::string &storeId);

    bool NeedSyncDataStorage(const AppAccountInfo &appAccountInfo);
    ErrCode GetAccountInfoFromDataStorage(
        AppAccountInfo &appAccountInfo, std::shared_ptr<AppAccountDataStorage> &dataStoragePtr, const uid_t &uid);
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

private:
    std::map<std::string, std::string> dataCache_;

    std::size_t ACCOUNT_MAX_SIZE = 1000;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CONTROL_MANAGER_H

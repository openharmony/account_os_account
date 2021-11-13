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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APP_ACCOUNT_CONTROL_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APP_ACCOUNT_CONTROL_MANAGER_H

#include "account_file_operator.h"
#include "iapp_account_control.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
class AppAccountControlManager : public IAppAccountControl, public DelayedSingleton<AppAccountControlManager> {
public:
    AppAccountControlManager();
    virtual ~AppAccountControlManager();

    virtual ErrCode AddAccount(const std::string &name, const std::string &extraInfo, const std::string &bundleName,
        AppAccountInfo &appAccountInfo) override;
    virtual ErrCode DeleteAccount(
        const std::string &name, const std::string &bundleName, AppAccountInfo &appAccountInfo) override;

    virtual ErrCode GetAccountExtraInfo(
        const std::string &name, std::string &extraInfo, const std::string &bundleName) override;
    virtual ErrCode SetAccountExtraInfo(const std::string &name, const std::string &extraInfo,
        const std::string &bundleName, AppAccountInfo &appAccountInfo) override;

    virtual ErrCode EnableAppAccess(const std::string &name, const std::string &authorizedApp,
        const std::string &bundleName, AppAccountInfo &appAccountInfo) override;
    virtual ErrCode DisableAppAccess(const std::string &name, const std::string &authorizedApp,
        const std::string &bundleName, AppAccountInfo &appAccountInfo) override;

    virtual ErrCode CheckAppAccountSyncEnable(
        const std::string &name, bool &syncEnable, const std::string &bundleName) override;
    virtual ErrCode SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable,
        const std::string &bundleName, AppAccountInfo &appAccountInfo) override;

    virtual ErrCode GetAssociatedData(
        const std::string &name, const std::string &key, std::string &value, const std::string &bundleName) override;
    virtual ErrCode SetAssociatedData(const std::string &name, const std::string &key, const std::string &value,
        const std::string &bundleName, AppAccountInfo &appAccountInfo) override;

    virtual ErrCode GetAccountCredential(const std::string &name, const std::string &credentialType,
        std::string &credential, const std::string &bundleName) override;
    virtual ErrCode SetAccountCredential(const std::string &name, const std::string &credentialType,
        const std::string &credential, const std::string &bundleName, AppAccountInfo &appAccountInfo) override;

    virtual ErrCode GetOAuthToken(const std::string &name, std::string &token, const std::string &bundleName) override;
    virtual ErrCode SetOAuthToken(
        const std::string &name, const std::string &token, const std::string &bundleName) override;
    virtual ErrCode ClearOAuthToken(const std::string &name, const std::string &bundleName) override;

    virtual ErrCode GetAllAccounts(
        const std::string &owner, std::vector<AppAccountInfo> &appAccounts, const std::string &bundleName) override;
    virtual ErrCode GetAllAccessibleAccounts(
        std::vector<AppAccountInfo> &appAccounts, const std::string &bundleName) override;

    virtual ErrCode OnPackageRemoved(const int32_t &uid, const std::string &bundleName) override;

private:
    virtual std::shared_ptr<AppAccountDataStorage> GetDataStorage(
        const bool &autoSync = false, const int32_t uid = AppExecFwk::Constants::INVALID_UID) override;
    virtual ErrCode GetStoreId(std::string &storeId, int32_t uid = AppExecFwk::Constants::INVALID_UID) override;

    virtual bool NeedSyncDataStorage(const AppAccountInfo &appAccountInfo) override;
    virtual ErrCode GetAccountInfoFromDataStorage(AppAccountInfo &appAccountInfo) override;
    virtual ErrCode AddAccountInfoIntoDataStorage(AppAccountInfo &appAccountInfo) override;
    virtual ErrCode SaveAccountInfoIntoDataStorage(AppAccountInfo &appAccountInfo) override;
    virtual ErrCode DeleteAccountInfoFromDataStorage(AppAccountInfo &appAccountInfo) override;

    virtual ErrCode SaveAuthorizedAccount(const std::string &authorizedApp, AppAccountInfo &appAccountInfo);
    virtual ErrCode RemoveAuthorizedAccount(const std::string &authorizedApp, AppAccountInfo &appAccountInfo);
    virtual ErrCode SaveAuthorizedAccountIntoDataStorage(
        const std::string &authorizedApp, AppAccountInfo &appAccountInfo, const bool &autoSync = false);
    virtual ErrCode RemoveAuthorizedAccountFromDataStorage(
        const std::string &authorizedApp, AppAccountInfo &appAccountInfo, const bool &autoSync = false);

private:
    std::map<std::string, std::string> dataCache_;
    std::shared_ptr<AccountFileOperator> fileOperator_;

    const std::string CONFIG_PATH = "/system/etc/account/app_account.json";
    const std::string ACCOUNT_MAX_SIZE_KEY = "account_max_size";
    std::int32_t ACCOUNT_MAX_SIZE = 32;
    std::int32_t account_max_size = 32;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APP_ACCOUNT_CONTROL_MANAGER_H

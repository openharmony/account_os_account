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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_IAPP_ACCOUNT_CONTROL_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_IAPP_ACCOUNT_CONTROL_H

#include "account_error_no.h"
#include "app_account_data_storage.h"
#include "app_account_info.h"
#include "bundle_constants.h"
#include "event_handler.h"

namespace OHOS {
namespace AccountSA {
class IAppAccountControl {
public:
    using EventHandler = OHOS::AppExecFwk::EventHandler;
    using EventRunner = OHOS::AppExecFwk::EventRunner;
    using Callback = OHOS::AppExecFwk::InnerEvent::Callback;

    virtual ErrCode AddAccount(const std::string &name, const std::string &extraInfo, const std::string &bundleName,
        AppAccountInfo &appAccountInfo) = 0;
    virtual ErrCode DeleteAccount(
        const std::string &name, const std::string &bundleName, AppAccountInfo &appAccountInfo) = 0;

    virtual ErrCode GetAccountExtraInfo(
        const std::string &name, std::string &extraInfo, const std::string &bundleName) = 0;
    virtual ErrCode SetAccountExtraInfo(const std::string &name, const std::string &extraInfo,
        const std::string &bundleName, AppAccountInfo &appAccountInfo) = 0;

    virtual ErrCode EnableAppAccess(const std::string &name, const std::string &authorizedApp,
        const std::string &bundleName, AppAccountInfo &appAccountInfo) = 0;
    virtual ErrCode DisableAppAccess(const std::string &name, const std::string &authorizedApp,
        const std::string &bundleName, AppAccountInfo &appAccountInfo) = 0;

    virtual ErrCode CheckAppAccountSyncEnable(
        const std::string &name, bool &syncEnable, const std::string &bundleName) = 0;
    virtual ErrCode SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable,
        const std::string &bundleName, AppAccountInfo &appAccountInfo) = 0;

    virtual ErrCode GetAssociatedData(
        const std::string &name, const std::string &key, std::string &value, const std::string &bundleName) = 0;
    virtual ErrCode SetAssociatedData(const std::string &name, const std::string &key, const std::string &value,
        const std::string &bundleName, AppAccountInfo &appAccountInfo) = 0;

    virtual ErrCode GetAccountCredential(const std::string &name, const std::string &credentialType,
        std::string &credential, const std::string &bundleName) = 0;
    virtual ErrCode SetAccountCredential(const std::string &name, const std::string &credentialType,
        const std::string &credential, const std::string &bundleName, AppAccountInfo &appAccountInfo) = 0;

    virtual ErrCode GetOAuthToken(const std::string &name, std::string &token, const std::string &bundleName) = 0;
    virtual ErrCode SetOAuthToken(const std::string &name, const std::string &token, const std::string &bundleName) = 0;
    virtual ErrCode ClearOAuthToken(const std::string &name, const std::string &bundleName) = 0;

    virtual ErrCode GetAllAccounts(
        const std::string &owner, std::vector<AppAccountInfo> &appAccounts, const std::string &bundleName) = 0;
    virtual ErrCode GetAllAccessibleAccounts(
        std::vector<AppAccountInfo> &appAccounts, const std::string &bundleName) = 0;

    virtual ErrCode OnPackageRemoved(const int32_t &uid, const std::string &bundleName) = 0;

private:
    virtual std::shared_ptr<AppAccountDataStorage> GetDataStorage(
        const bool &autoSync = false, const int32_t uid = AppExecFwk::Constants::INVALID_UID) = 0;
    virtual ErrCode GetStoreId(std::string &storeId, int32_t uid = AppExecFwk::Constants::INVALID_UID) = 0;

    virtual bool NeedSyncDataStorage(const AppAccountInfo &appAccountInfo) = 0;
    virtual ErrCode GetAccountInfoFromDataStorage(AppAccountInfo &appAccountInfo) = 0;
    virtual ErrCode AddAccountInfoIntoDataStorage(AppAccountInfo &appAccountInfo) = 0;
    virtual ErrCode SaveAccountInfoIntoDataStorage(AppAccountInfo &appAccountInfo) = 0;
    virtual ErrCode DeleteAccountInfoFromDataStorage(AppAccountInfo &appAccountInfo) = 0;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_IAPP_ACCOUNT_CONTROL_H

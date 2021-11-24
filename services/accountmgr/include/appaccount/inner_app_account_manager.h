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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_INNER_APP_ACCOUNT_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_INNER_APP_ACCOUNT_MANAGER_H

#include "app_account_control_manager.h"
#include "app_account_subscribe_manager.h"

namespace OHOS {
namespace AccountSA {
class InnerAppAccountManager {
public:
    InnerAppAccountManager();
    virtual ~InnerAppAccountManager();

    ErrCode AddAccount(const std::string &name, const std::string &extraInfo, const std::string &bundleName);
    ErrCode DeleteAccount(const std::string &name, const std::string &bundleName);

    ErrCode GetAccountExtraInfo(const std::string &name, std::string &extraInfo, const std::string &bundleName);
    ErrCode SetAccountExtraInfo(const std::string &name, const std::string &extraInfo, const std::string &bundleName);

    ErrCode EnableAppAccess(const std::string &name, const std::string &authorizedApp, const std::string &bundleName);
    ErrCode DisableAppAccess(const std::string &name, const std::string &authorizedApp, const std::string &bundleName);

    ErrCode CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable, const std::string &bundleName);
    ErrCode SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable, const std::string &bundleName);

    ErrCode GetAssociatedData(
        const std::string &name, const std::string &key, std::string &value, const std::string &bundleName);
    ErrCode SetAssociatedData(
        const std::string &name, const std::string &key, const std::string &value, const std::string &bundleName);

    ErrCode GetAccountCredential(const std::string &name, const std::string &credentialType, std::string &credential,
        const std::string &bundleName);
    ErrCode SetAccountCredential(const std::string &name, const std::string &credentialType,
        const std::string &credential, const std::string &bundleName);

    ErrCode GetOAuthToken(const std::string &name, std::string &token, const std::string &bundleName);
    ErrCode SetOAuthToken(const std::string &name, const std::string &token, const std::string &bundleName);
    ErrCode ClearOAuthToken(const std::string &name, const std::string &bundleName);

    ErrCode GetAllAccounts(
        const std::string &owner, std::vector<AppAccountInfo> &appAccounts, const std::string &bundleName);
    ErrCode GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts, const std::string &bundleName);

    ErrCode SubscribeAppAccount(const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener,
        const std::string &bundleName);
    ErrCode UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener);

    ErrCode OnPackageRemoved(const int32_t &uid, const std::string &bundleName);

private:
    std::shared_ptr<AppAccountControlManager> controlManagerPtr_;
    std::shared_ptr<AppAccountSubscribeManager> subscribeManagerPtr_;

    DISALLOW_COPY_AND_MOVE(InnerAppAccountManager);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_INNER_APP_ACCOUNT_MANAGER_H

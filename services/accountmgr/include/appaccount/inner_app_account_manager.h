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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_INNER_APP_ACCOUNT_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_INNER_APP_ACCOUNT_MANAGER_H

#include "iapp_account_control.h"
#include "iapp_account_subscribe.h"
#include "iinner_app_account.h"

namespace OHOS {
namespace AccountSA {
class InnerAppAccountManager : public IInnerAppAccount {
public:
    InnerAppAccountManager();
    virtual ~InnerAppAccountManager();

    ErrCode AddAccount(const std::string &name, const std::string &extraInfo, const std::string &bundleName) override;
    ErrCode DeleteAccount(const std::string &name, const std::string &bundleName) override;

    ErrCode GetAccountExtraInfo(
        const std::string &name, std::string &extraInfo, const std::string &bundleName) override;
    ErrCode SetAccountExtraInfo(
        const std::string &name, const std::string &extraInfo, const std::string &bundleName) override;

    ErrCode EnableAppAccess(
        const std::string &name, const std::string &authorizedApp, const std::string &bundleName) override;
    ErrCode DisableAppAccess(
        const std::string &name, const std::string &authorizedApp, const std::string &bundleName) override;

    ErrCode CheckAppAccountSyncEnable(
        const std::string &name, bool &syncEnable, const std::string &bundleName) override;
    ErrCode SetAppAccountSyncEnable(
        const std::string &name, const bool &syncEnable, const std::string &bundleName) override;

    ErrCode GetAssociatedData(
        const std::string &name, const std::string &key, std::string &value, const std::string &bundleName) override;
    ErrCode SetAssociatedData(const std::string &name, const std::string &key, const std::string &value,
        const std::string &bundleName) override;

    ErrCode GetAccountCredential(const std::string &name, const std::string &credentialType, std::string &credential,
        const std::string &bundleName) override;
    ErrCode SetAccountCredential(const std::string &name, const std::string &credentialType,
        const std::string &credential, const std::string &bundleName) override;

    ErrCode GetOAuthToken(const std::string &name, std::string &token, const std::string &bundleName) override;
    ErrCode SetOAuthToken(const std::string &name, const std::string &token, const std::string &bundleName) override;
    ErrCode ClearOAuthToken(const std::string &name, const std::string &bundleName) override;

    ErrCode GetAllAccounts(
        const std::string &owner, std::vector<AppAccountInfo> &appAccounts, const std::string &bundleName) override;
    ErrCode GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts, const std::string &bundleName) override;

    ErrCode SubscribeAppAccount(const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener,
        const std::string &bundleName) override;
    ErrCode UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener) override;

    ErrCode OnPackageRemoved(const int32_t &uid, const std::string &bundleName) override;

private:
    std::shared_ptr<IAppAccountControl> controlManagerPtr_;
    std::shared_ptr<IAppAccountSubscribe> subscribeManagerPtr_;

    DISALLOW_COPY_AND_MOVE(InnerAppAccountManager);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_INNER_APP_ACCOUNT_MANAGER_H

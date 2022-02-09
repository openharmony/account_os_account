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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_MANAGER_SERVICE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_MANAGER_SERVICE_H

#include "account_bundle_manager.h"
#include "account_permission_manager.h"
#include "app_account_common_event_oberserver.h"
#include "app_account_stub.h"
#include "inner_app_account_manager.h"

namespace OHOS {
namespace AccountSA {
class AppAccountManagerService : public AppAccountStub {
public:
    AppAccountManagerService();
    virtual ~AppAccountManagerService() override;

    virtual ErrCode AddAccount(const std::string &name, const std::string &extraInfo) override;
    virtual ErrCode AddAccountImplicitly(
        const std::string &owner, const std::string &authType, const AAFwk::WantParams &options,
        const sptr<IRemoteObject> &callback, const std::string &abilityName) override;
    virtual ErrCode DeleteAccount(const std::string &name) override;

    virtual ErrCode GetAccountExtraInfo(const std::string &name, std::string &extraInfo) override;
    virtual ErrCode SetAccountExtraInfo(const std::string &name, const std::string &extraInfo) override;

    virtual ErrCode EnableAppAccess(const std::string &name, const std::string &authorizedApp) override;
    virtual ErrCode DisableAppAccess(const std::string &name, const std::string &authorizedApp) override;

    virtual ErrCode CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable) override;
    virtual ErrCode SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable) override;

    virtual ErrCode GetAssociatedData(const std::string &name, const std::string &key, std::string &value) override;
    virtual ErrCode SetAssociatedData(
        const std::string &name, const std::string &key, const std::string &value) override;

    virtual ErrCode GetAccountCredential(
        const std::string &name, const std::string &credentialType, std::string &credential) override;
    virtual ErrCode SetAccountCredential(
        const std::string &name, const std::string &credentialType, const std::string &credential) override;

    virtual ErrCode Authenticate(OAuthRequest &request) override;
    virtual ErrCode GetOAuthToken(
        const std::string &name, const std::string &owner, const std::string &authType, std::string &token) override;
    virtual ErrCode SetOAuthToken(
        const std::string &name, const std::string &authType, const std::string &token) override;
    virtual ErrCode DeleteOAuthToken(const std::string &name, const std::string &owner,
        const std::string &authType, const std::string &token) override;
    virtual ErrCode SetOAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool isVisible) override;
    virtual ErrCode CheckOAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool &isVisible) override;
    virtual ErrCode GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &authenticator) override;
    virtual ErrCode GetAllOAuthTokens(const std::string &name, const std::string &owner,
        std::vector<OAuthTokenInfo> &tokenInfos) override;
    virtual ErrCode GetOAuthList(const std::string &name, const std::string &authType,
        std::set<std::string> &oauthList) override;
    virtual ErrCode GetAuthenticatorCallback(const std::string &sessionId, sptr<IRemoteObject> &callback) override;

    virtual ErrCode GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts) override;
    virtual ErrCode GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts) override;

    virtual ErrCode SubscribeAppAccount(
        const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener) override;
    virtual ErrCode UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener) override;

    virtual ErrCode OnPackageRemoved(const uid_t &uid, const std::string &bundleName);

private:
    std::shared_ptr<InnerAppAccountManager> innerManager_ = nullptr;
    std::shared_ptr<AccountPermissionManager> permissionManagerPtr_ = nullptr;
    std::shared_ptr<AccountBundleManager> bundleManagerPtr_ = nullptr;
    std::shared_ptr<AppAccountCommonEventOberserver> oberserver_ = nullptr;

    DISALLOW_COPY_AND_MOVE(AppAccountManagerService);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_MANAGER_SERVICE_H

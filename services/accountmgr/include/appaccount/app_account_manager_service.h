/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "account_permission_manager.h"
#include "app_account_common_event_observer.h"
#include "app_account_stub.h"
#include "inner_app_account_manager.h"

namespace OHOS {
namespace AccountSA {
class AppAccountManagerService : public AppAccountStub {
public:
    AppAccountManagerService();
    ~AppAccountManagerService() override;

    ErrCode AddAccount(const std::string &name, const std::string &extraInfo) override;
    ErrCode AddAccountImplicitly(
        const std::string &owner, const std::string &authType, const AAFwk::Want &options,
        const sptr<IRemoteObject> &callback) override;
    ErrCode CreateAccount(const std::string &name, const CreateAccountOptions &options) override;
    ErrCode CreateAccountImplicitly(const std::string &owner, const CreateAccountImplicitlyOptions &options,
        const sptr<IRemoteObject> &callback) override;
    ErrCode DeleteAccount(const std::string &name) override;

    ErrCode GetAccountExtraInfo(const std::string &name, std::string &extraInfo) override;
    ErrCode SetAccountExtraInfo(const std::string &name, const std::string &extraInfo) override;

    ErrCode EnableAppAccess(const std::string &name, const std::string &authorizedApp) override;
    ErrCode DisableAppAccess(const std::string &name, const std::string &authorizedApp) override;
    ErrCode SetAppAccess(const std::string &name, const std::string &authorizedApp, bool isAccessible) override;
    ErrCode CheckAppAccess(const std::string &name, const std::string &authorizedApp, bool &isAccessible) override;

    ErrCode CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable) override;
    ErrCode SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable) override;

    ErrCode GetAssociatedData(const std::string &name, const std::string &key, std::string &value) override;
    ErrCode SetAssociatedData(
        const std::string &name, const std::string &key, const std::string &value) override;

    ErrCode GetAccountCredential(
        const std::string &name, const std::string &credentialType, std::string &credential) override;
    ErrCode SetAccountCredential(
        const std::string &name, const std::string &credentialType, const std::string &credential) override;
    ErrCode DeleteAccountCredential(const std::string &name, const std::string &credentialType) override;

    ErrCode Authenticate(const std::string &name, const std::string &owner, const std::string &authType,
        const AAFwk::Want &options, const sptr<IRemoteObject> &callback) override;
    ErrCode GetOAuthToken(
        const std::string &name, const std::string &owner, const std::string &authType, std::string &token) override;
    ErrCode GetAuthToken(
        const std::string &name, const std::string &owner, const std::string &authType, std::string &token) override;
    ErrCode SetOAuthToken(
        const std::string &name, const std::string &authType, const std::string &token) override;
    ErrCode DeleteOAuthToken(const std::string &name, const std::string &owner,
        const std::string &authType, const std::string &token) override;
    ErrCode DeleteAuthToken(const std::string &name, const std::string &owner,
        const std::string &authType, const std::string &token) override;
    ErrCode SetOAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool isVisible) override;
    ErrCode SetAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool isVisible) override;
    ErrCode CheckOAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool &isVisible) override;
    ErrCode CheckAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool &isVisible) override;
    ErrCode GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &info) override;
    ErrCode GetAllOAuthTokens(const std::string &name, const std::string &owner,
        std::vector<OAuthTokenInfo> &tokenInfos) override;
    ErrCode GetOAuthList(const std::string &name, const std::string &authType,
        std::set<std::string> &oauthList) override;
    ErrCode GetAuthList(const std::string &name, const std::string &authType,
        std::set<std::string> &oauthList) override;
    ErrCode GetAuthenticatorCallback(const std::string &sessionId, sptr<IRemoteObject> &callback) override;

    ErrCode GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts) override;
    ErrCode GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts) override;
    ErrCode QueryAllAccessibleAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts) override;
    ErrCode SelectAccountsByOptions(
        const SelectAccountsOptions &options, const sptr<IRemoteObject> &callback) override;
    ErrCode VerifyCredential(const std::string &name, const std::string &owner,
        const VerifyCredentialOptions &options, const sptr<IRemoteObject> &callback) override;
    ErrCode CheckAccountLabels(const std::string &name, const std::string &owner,
        const std::vector<std::string> &labels, const sptr<IRemoteObject> &callback) override;
    ErrCode SetAuthenticatorProperties(
        const std::string &owner, const SetPropertiesOptions &options, const sptr<IRemoteObject> &callback) override;

    ErrCode SubscribeAppAccount(
        const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener) override;
    ErrCode UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener) override;

    virtual ErrCode OnPackageRemoved(const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);
    virtual ErrCode OnUserRemoved(int32_t userId);

private:
    ErrCode GetBundleNameAndCheckPerm(int32_t &callingUid, std::string &bundleName, const std::string &permName);
    ErrCode GetBundleNameAndCallingUid(int32_t &callingUid, std::string &bundleName);
    ErrCode GetCallingTokenInfoAndAppIndex(uint32_t &appIndex);
    ErrCode GetCallingInfo(int32_t &callingUid, std::string &bundleName, uint32_t &appIndex);
    ErrCode GetTokenVisibilityParam(const std::string &name,
        const std::string &authType, const std::string &bundleName, AuthenticatorSessionRequest &request);

private:
    std::shared_ptr<InnerAppAccountManager> innerManager_ = nullptr;
    std::shared_ptr<AccountPermissionManager> permissionManagerPtr_ = nullptr;
#ifdef HAS_CES_PART
    std::shared_ptr<AppAccountCommonEventObserver> observer_ = nullptr;
#endif // HAS_CES_PART
    DISALLOW_COPY_AND_MOVE(AppAccountManagerService);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_MANAGER_SERVICE_H

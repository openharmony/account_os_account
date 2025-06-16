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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_MANAGER_SERVICE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_MANAGER_SERVICE_H

#ifdef HAS_CES_PART
#include "app_account_common_event_observer.h"
#endif // HAS_CES_PART
#include "app_account_stub.h"
#include "inner_app_account_manager.h"

namespace OHOS {
namespace AccountSA {
class AppAccountManagerService : public AppAccountStub {
public:
    AppAccountManagerService();
    ~AppAccountManagerService() override;

    ErrCode AddAccount(const std::string &name, const std::string &extraInfo, int32_t &funcResult) override;
    ErrCode AddAccountImplicitly(
        const std::string &owner, const std::string &authType, const AAFwk::Want &options,
        const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult) override;
    ErrCode CreateAccount(const std::string &name, const CreateAccountOptions &options, int32_t &funcResult) override;
    ErrCode CreateAccountImplicitly(const std::string &owner, const CreateAccountImplicitlyOptions &options,
        const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult) override;
    ErrCode DeleteAccount(const std::string &name, int32_t &funcResult) override;

    ErrCode GetAccountExtraInfo(const std::string &name, std::string &extraInfo, int32_t &funcResult) override;
    ErrCode SetAccountExtraInfo(const std::string &name, const std::string &extraInfo, int32_t &funcResult) override;

    ErrCode EnableAppAccess(const std::string &name, const std::string &authorizedApp, int32_t &funcResult) override;
    ErrCode DisableAppAccess(const std::string &name, const std::string &authorizedApp, int32_t &funcResult) override;
    ErrCode SetAppAccess(const std::string &name, const std::string &authorizedApp, bool isAccessible,
        int32_t &funcResult) override;
    ErrCode CheckAppAccess(const std::string &name, const std::string &authorizedApp, bool &isAccessible,
        int32_t &funcResult) override;

    ErrCode CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable, int32_t &funcResult) override;
    ErrCode SetAppAccountSyncEnable(const std::string &name, bool syncEnable, int32_t &funcResult) override;

    ErrCode GetAssociatedData(const std::string &name, const std::string &key, std::string &value,
        int32_t &funcResult) override;
    ErrCode SetAssociatedData(
        const std::string &name, const std::string &key, const std::string &value, int32_t &funcResult) override;

    ErrCode GetAccountCredential(
        const std::string &name, const std::string &credentialType, std::string &credential,
        int32_t &funcResult) override;
    ErrCode SetAccountCredential(
        const std::string &name, const std::string &credentialType, const std::string &credential,
        int32_t &funcResult) override;
    ErrCode DeleteAccountCredential(const std::string &name, const std::string &credentialType,
        int32_t &funcResult) override;

    ErrCode Authenticate(const AppAccountStringInfo &appAccountStringInfo, const AAFwk::Want &options,
        const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult) override;
    ErrCode GetOAuthToken(
        const std::string &name, const std::string &owner, const std::string &authType, std::string &token,
        int32_t &funcResult) override;
    ErrCode GetAuthToken(
        const std::string &name, const std::string &owner, const std::string &authType, std::string &token,
        int32_t &funcResult) override;
    ErrCode SetOAuthToken(
        const std::string &name, const std::string &authType, const std::string &token,
        int32_t &funcResult) override;
    ErrCode DeleteOAuthToken(const std::string &name, const std::string &owner,
        const std::string &authType, const std::string &token, int32_t &funcResult) override;
    ErrCode DeleteAuthToken(const std::string &name, const std::string &owner,
        const std::string &authType, const std::string &token, int32_t &funcResult) override;
    ErrCode SetOAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool isVisible, int32_t &funcResult) override;
    ErrCode SetAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool isVisible, int32_t &funcResult) override;
    ErrCode CheckOAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool &isVisible, int32_t &funcResult) override;
    ErrCode CheckAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool &isVisible, int32_t &funcResult) override;
    ErrCode GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &info, int32_t &funcResult) override;
    ErrCode GetAllOAuthTokens(const std::string &name, const std::string &owner,
        std::vector<OAuthTokenInfo> &tokenInfos, int32_t &funcResult) override;
    ErrCode GetOAuthList(const std::string &name, const std::string &authType,
        std::set<std::string> &oauthList, int32_t &funcResult) override;
    ErrCode GetAuthList(const std::string &name, const std::string &authType,
        std::set<std::string> &oauthList, int32_t &funcResult) override;
    ErrCode GetAuthenticatorCallback(const std::string &sessionId, int32_t &funcResult,
        sptr<IRemoteObject> &callback) override;

    ErrCode GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts,
        int32_t &funcResult) override;
    ErrCode GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts, int32_t &funcResult) override;
    ErrCode QueryAllAccessibleAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts,
        int32_t &funcResult) override;
    ErrCode SelectAccountsByOptions(
        const SelectAccountsOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback,
        int32_t &funcResult) override;
    ErrCode VerifyCredential(const std::string &name, const std::string &owner,
        const VerifyCredentialOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback,
        int32_t &funcResult) override;
    ErrCode CheckAccountLabels(const std::string &name, const std::string &owner,
        const std::vector<std::string> &labels, const sptr<IAppAccountAuthenticatorCallback> &callback,
        int32_t &funcResult) override;
    ErrCode SetAuthenticatorProperties(const std::string &owner, const SetPropertiesOptions &options,
        const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult) override;

    ErrCode SubscribeAppAccount(
        const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener,
        int32_t &funcResult) override;
    ErrCode UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener, const std::vector<std::string> &owners,
        int32_t &funcResult) override;

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
#ifdef HAS_CES_PART
    AppAccountCommonEventObserver &observer_;
#endif // HAS_CES_PART
    DISALLOW_COPY_AND_MOVE(AppAccountManagerService);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_MANAGER_SERVICE_H

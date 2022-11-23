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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_INNER_APP_ACCOUNT_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_INNER_APP_ACCOUNT_MANAGER_H

#include "app_account_authenticator_manager.h"
#include "app_account_authenticator_session_manager.h"
#include "app_account_control_manager.h"
#include "app_account_subscribe_manager.h"

namespace OHOS {
namespace AccountSA {
class InnerAppAccountManager {
public:
    InnerAppAccountManager();
    virtual ~InnerAppAccountManager();

    ErrCode AddAccount(const std::string &name, const std::string &extraInfo,
        const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);
    ErrCode AddAccountImplicitly(const AuthenticatorSessionRequest &request);
    ErrCode CreateAccount(const std::string &name, const CreateAccountOptions &options,
        const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);
    ErrCode CreateAccountImplicitly(const AuthenticatorSessionRequest &request);
    ErrCode DeleteAccount(
        const std::string &name, const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);

    ErrCode GetAccountExtraInfo(const std::string &name, std::string &extraInfo,
        const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);
    ErrCode SetAccountExtraInfo(const std::string &name, const std::string &extraInfo,
        const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);

    ErrCode EnableAppAccess(const std::string &name, const std::string &authorizedApp,
        AppAccountCallingInfo &appAccountCallingInfo, const uint32_t apiVersion = Constants::API_VERSION7);
    ErrCode DisableAppAccess(const std::string &name, const std::string &authorizedApp,
        AppAccountCallingInfo &appAccountCallingInfo, const uint32_t apiVersion = Constants::API_VERSION7);
    ErrCode CheckAppAccess(const std::string &name, const std::string &authorizedApp, bool &isAccessible,
        const AppAccountCallingInfo &appAccountCallingInfo);

    ErrCode CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable,
        const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);
    ErrCode SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable,
        const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);

    ErrCode GetAssociatedData(const std::string &name, const std::string &key,
        std::string &value, const uid_t &uid);
    ErrCode SetAssociatedData(const std::string &name, const std::string &key, const std::string &value,
        const AppAccountCallingInfo &appAccountCallingInfo);

    ErrCode GetAccountCredential(const std::string &name, const std::string &credentialType, std::string &credential,
        const AppAccountCallingInfo &appAccountCallingInfo);
    ErrCode SetAccountCredential(const std::string &name, const std::string &credentialType,
        const std::string &credential, const AppAccountCallingInfo &appAccountCallingInfo);
    ErrCode DeleteAccountCredential(const std::string &name, const std::string &credentialType,
        const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);

    ErrCode Authenticate(const AuthenticatorSessionRequest &request);
    ErrCode GetOAuthToken(const AuthenticatorSessionRequest &request,
        std::string &token, const uint32_t apiVersion = Constants::API_VERSION8);
    ErrCode SetOAuthToken(const AuthenticatorSessionRequest &request);
    ErrCode DeleteOAuthToken(
        const AuthenticatorSessionRequest &request, const uint32_t apiVersion = Constants::API_VERSION8);
    ErrCode SetOAuthTokenVisibility(const AuthenticatorSessionRequest &,
        const uint32_t apiVersion = Constants::API_VERSION8);
    ErrCode CheckOAuthTokenVisibility(const AuthenticatorSessionRequest &request,
        bool &isVisible, const uint32_t apiVersion = Constants::API_VERSION8);
    ErrCode GetAllOAuthTokens(const AuthenticatorSessionRequest &request, std::vector<OAuthTokenInfo> &tokenInfos);
    ErrCode GetOAuthList(const AuthenticatorSessionRequest &request,
        std::set<std::string> &oauthList, const uint32_t apiVersion = Constants::API_VERSION8);
    ErrCode GetAuthenticatorCallback(const AuthenticatorSessionRequest &request, sptr<IRemoteObject> &callback);
    ErrCode GetAuthenticatorInfo(const AuthenticatorSessionRequest &request, AuthenticatorInfo &authenticator);

    ErrCode GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts, const uid_t &uid,
        const std::string &bundleName, const uint32_t &appIndex);
    ErrCode GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts,
        const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);

    ErrCode SelectAccountsByOptions(
        const SelectAccountsOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback,
        const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);
    ErrCode VerifyCredential(const AuthenticatorSessionRequest &request);
    ErrCode CheckAccountLabels(const AuthenticatorSessionRequest &request);
    ErrCode SetAuthenticatorProperties(const AuthenticatorSessionRequest &request);

    ErrCode SubscribeAppAccount(const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener,
        const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);
    ErrCode UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener);

    ErrCode OnPackageRemoved(const uid_t &uid, const std::string &bundleName, const uint32_t &appIndex);
    ErrCode OnUserRemoved(int32_t userId);

private:
    std::shared_ptr<AppAccountControlManager> controlManagerPtr_ = nullptr;
    std::shared_ptr<AppAccountSubscribeManager> subscribeManagerPtr_ = nullptr;
    std::shared_ptr<AppAccountAuthenticatorSessionManager> sessionManagerPtr_ = nullptr;
    std::shared_ptr<AppAccountAuthenticatorManager> authenticatorManagerPtr_ = nullptr;

    DISALLOW_COPY_AND_MOVE(InnerAppAccountManager);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_INNER_APP_ACCOUNT_MANAGER_H

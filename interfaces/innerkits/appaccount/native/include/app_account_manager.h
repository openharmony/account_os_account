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

#ifndef APP_ACCOUNT_INTERFACES_INNERKITS_APPACCOUNT_NATIVE_INCLUDE_APP_ACCOUNT_MANAGER_H
#define APP_ACCOUNT_INTERFACES_INNERKITS_APPACCOUNT_NATIVE_INCLUDE_APP_ACCOUNT_MANAGER_H

#include "app_account_subscriber.h"
#include "app_account_common.h"
#include "app_account_info.h"
#include "iapp_account_authenticator_callback.h"
#include "iremote_object.h"

namespace OHOS {
namespace AccountSA {
class AppAccountManager {
public:
    static ErrCode AddAccount(const std::string &name, const std::string &extraInfo = "");
    static ErrCode AddAccountImplicitly(const std::string &owner, const std::string &authType,
        const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback);
    static ErrCode CreateAccount(const std::string &name, const CreateAccountOptions &options);
    static ErrCode CreateAccountImplicitly(const std::string &owner, const CreateAccountImplicitlyOptions &options,
        const sptr<IAppAccountAuthenticatorCallback> &callback);
    static ErrCode DeleteAccount(const std::string &name);

    static ErrCode GetAccountExtraInfo(const std::string &name, std::string &extraInfo);
    static ErrCode SetAccountExtraInfo(const std::string &name, const std::string &extraInfo);

    static ErrCode EnableAppAccess(const std::string &name, const std::string &authorizedApp);
    static ErrCode DisableAppAccess(const std::string &name, const std::string &authorizedApp);
    static ErrCode SetAppAccess(const std::string &name, const std::string &authorizedApp, bool isAccessible);

    static ErrCode CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable);
    static ErrCode SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable);

    static ErrCode GetAssociatedData(const std::string &name, const std::string &key, std::string &value);
    static ErrCode SetAssociatedData(const std::string &name, const std::string &key, const std::string &value);

    static ErrCode GetAccountCredential(
        const std::string &name, const std::string &credentialType, std::string &credential);
    static ErrCode SetAccountCredential(
        const std::string &name, const std::string &credentialType, const std::string &credential);

    static ErrCode Authenticate(const std::string &name, const std::string &owner, const std::string &authType,
        const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback);
    static ErrCode GetOAuthToken(const std::string &name, const std::string &owner, const std::string &authType,
        std::string &token);
    static ErrCode GetAuthToken(const std::string &name, const std::string &owner, const std::string &authType,
        std::string &token);
    static ErrCode SetOAuthToken(
        const std::string &name, const std::string &authType, const std::string &token);
    static ErrCode DeleteOAuthToken(
        const std::string &name, const std::string &owner, const std::string &authType, const std::string &token);
    static ErrCode DeleteAuthToken(
        const std::string &name, const std::string &owner, const std::string &authType, const std::string &token);
    static ErrCode SetOAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool isVisible);
    static ErrCode SetAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool isVisible);
    static ErrCode CheckOAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool &isVisible);
    static ErrCode CheckAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool &isVisible);
    static ErrCode GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &info);
    static ErrCode GetAllOAuthTokens(const std::string &name, const std::string &owner,
        std::vector<OAuthTokenInfo> &tokenInfos);
    static ErrCode GetOAuthList(const std::string &name, const std::string &authType,
        std::set<std::string> &oauthList);
    static ErrCode GetAuthList(const std::string &name, const std::string &authType,
        std::set<std::string> &oauthList);
    static ErrCode GetAuthenticatorCallback(const std::string &sessionId, sptr<IRemoteObject> &callback);

    static ErrCode GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts);
    static ErrCode GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts);
    static ErrCode QueryAllAccessibleAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts);
    static ErrCode CheckAppAccess(const std::string &name, const std::string &authorizedApp, bool &isAccessible);
    static ErrCode DeleteAccountCredential(const std::string &name, const std::string &credentialType);
    static ErrCode SelectAccountsByOptions(
        const SelectAccountsOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback);
    static ErrCode VerifyCredential(const std::string &name, const std::string &owner,
        const VerifyCredentialOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback);
    static ErrCode CheckAccountLabels(const std::string &name, const std::string &owner,
        const std::vector<std::string> &labels, const sptr<IAppAccountAuthenticatorCallback> &callback);
    static ErrCode SetAuthenticatorProperties(const std::string &owner,
        const SetPropertiesOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback);

    static ErrCode SubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber);
    static ErrCode UnsubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // APP_ACCOUNT_INTERFACES_INNERKITS_APPACCOUNT_NATIVE_INCLUDE_APP_ACCOUNT_MANAGER_H

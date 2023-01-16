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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_IAPP_ACCOUNT_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_IAPP_ACCOUNT_H

#include "app_account_common.h"
#include "app_account_info.h"
#include "app_account_subscribe_info.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
class IAppAccount : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IAppAccount");

    virtual ErrCode AddAccount(const std::string &name, const std::string &extraInfo) = 0;
    virtual ErrCode AddAccountImplicitly(const std::string &owner, const std::string &authType,
        const AAFwk::Want &options, const sptr<IRemoteObject> &callback) = 0;
    virtual ErrCode CreateAccount(const std::string &name, const CreateAccountOptions &options) = 0;
    virtual ErrCode CreateAccountImplicitly(const std::string &owner, const CreateAccountImplicitlyOptions &options,
        const sptr<IRemoteObject> &callback) = 0;
    virtual ErrCode DeleteAccount(const std::string &name) = 0;

    virtual ErrCode GetAccountExtraInfo(const std::string &name, std::string &extraInfo) = 0;
    virtual ErrCode SetAccountExtraInfo(const std::string &name, const std::string &extraInfo) = 0;

    virtual ErrCode EnableAppAccess(const std::string &name, const std::string &authorizedApp) = 0;
    virtual ErrCode DisableAppAccess(const std::string &name, const std::string &authorizedApp) = 0;
    virtual ErrCode SetAppAccess(const std::string &name, const std::string &authorizedApp, bool isAccessible) = 0;
    virtual ErrCode CheckAppAccess(const std::string &name, const std::string &authorizedApp, bool &isAccessible) = 0;

    virtual ErrCode CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable) = 0;
    virtual ErrCode SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable) = 0;

    virtual ErrCode GetAssociatedData(const std::string &name, const std::string &key, std::string &value) = 0;
    virtual ErrCode SetAssociatedData(const std::string &name, const std::string &key, const std::string &value) = 0;

    virtual ErrCode GetAccountCredential(
        const std::string &name, const std::string &credentialType, std::string &credential) = 0;
    virtual ErrCode SetAccountCredential(
        const std::string &name, const std::string &credentialType, const std::string &credential) = 0;
    virtual ErrCode DeleteAccountCredential(const std::string &name, const std::string &credentialType) = 0;

    virtual ErrCode Authenticate(const std::string &name, const std::string &owner, const std::string &authType,
        const AAFwk::Want &options, const sptr<IRemoteObject> &callback) = 0;
    virtual ErrCode GetOAuthToken(
        const std::string &name, const std::string &owner, const std::string &authType, std::string &token) = 0;
    virtual ErrCode GetAuthToken(
        const std::string &name, const std::string &owner, const std::string &authType, std::string &token) = 0;
    virtual ErrCode SetOAuthToken(
        const std::string &name, const std::string &authType, const std::string &token) = 0;
    virtual ErrCode DeleteOAuthToken(
        const std::string &name, const std::string &owner, const std::string &authType, const std::string &token) = 0;
    virtual ErrCode DeleteAuthToken(
        const std::string &name, const std::string &owner, const std::string &authType, const std::string &token) = 0;
    virtual ErrCode SetOAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool isVisible) = 0;
    virtual ErrCode SetAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool isVisible) = 0;
    virtual ErrCode CheckOAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool &isVisible) = 0;
    virtual ErrCode CheckAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool &isVisible) = 0;
    virtual ErrCode GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &info) = 0;
    virtual ErrCode GetAllOAuthTokens(const std::string &name, const std::string &owner,
        std::vector<OAuthTokenInfo> &tokenInfos) = 0;
    virtual ErrCode GetOAuthList(const std::string &name, const std::string &authType,
        std::set<std::string> &oauthList) = 0;
    virtual ErrCode GetAuthList(const std::string &name, const std::string &authType,
        std::set<std::string> &oauthList) = 0;
    virtual ErrCode GetAuthenticatorCallback(const std::string &sessionId, sptr<IRemoteObject> &callback) = 0;

    virtual ErrCode GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts) = 0;
    virtual ErrCode GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts) = 0;
    virtual ErrCode QueryAllAccessibleAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts) = 0;
    virtual ErrCode SelectAccountsByOptions(
        const SelectAccountsOptions &options, const sptr<IRemoteObject> &callback) = 0;
    virtual ErrCode VerifyCredential(const std::string &name, const std::string &owner,
        const VerifyCredentialOptions &options, const sptr<IRemoteObject> &callback) = 0;
    virtual ErrCode CheckAccountLabels(const std::string &name, const std::string &owner,
        const std::vector<std::string> &labels, const sptr<IRemoteObject> &callback) = 0;
    virtual ErrCode SetAuthenticatorProperties(
        const std::string &owner, const SetPropertiesOptions &options, const sptr<IRemoteObject> &callback) = 0;

    virtual ErrCode SubscribeAppAccount(
        const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener) = 0;
    virtual ErrCode UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener) = 0;

    enum class Message {
        ADD_ACCOUNT = 0,
        ADD_ACCOUNT_IMPLICITLY,
        DELETE_ACCOUNT,
        GET_ACCOUNT_EXTRA_INFO,
        SET_ACCOUNT_EXTRA_INFO,
        ENABLE_APP_ACCESS,
        DISABLE_APP_ACCESS,
        SET_APP_ACCESS,
        CHECK_APP_ACCOUNT_SYNC_ENABLE,
        SET_APP_ACCOUNT_SYNC_ENABLE,
        GET_ASSOCIATED_DATA,
        SET_ASSOCIATED_DATA,
        GET_ACCOUNT_CREDENTIAL,
        SET_ACCOUNT_CREDENTIAL,
        AUTHENTICATE,
        GET_OAUTH_TOKEN,
        GET_AUTH_TOKEN,
        SET_OAUTH_TOKEN,
        DELETE_OAUTH_TOKEN,
        DELETE_AUTH_TOKEN,
        SET_OAUTH_TOKEN_VISIBILITY,
        SET_AUTH_TOKEN_VISIBILITY,
        CHECK_OAUTH_TOKEN_VISIBILITY,
        CHECK_AUTH_TOKEN_VISIBILITY,
        GET_AUTHENTICATOR_INFO,
        GET_ALL_OAUTH_TOKENS,
        GET_OAUTH_LIST,
        GET_AUTH_LIST,
        GET_AUTHENTICATOR_CALLBACK,
        CLEAR_OAUTH_TOKEN,
        GET_ALL_ACCOUNTS,
        GET_ALL_ACCESSIBLE_ACCOUNTS,
        QUERY_ALL_ACCESSIBLE_ACCOUNTS,
        SUBSCRIBE_ACCOUNT,
        UNSUBSCRIBE_ACCOUNT,
        CHECK_APP_ACCESS,
        DELETE_ACCOUNT_CREDENTIAL,
        SELECT_ACCOUNTS_BY_OPTIONS,
        VERIFY_CREDENTIAL,
        CHECK_ACCOUNT_LABELS,
        SET_AUTHENTICATOR_PROPERTIES,
        CREATE_ACCOUNT,
        CREATE_ACCOUNT_IMPLICITLY
    };
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_IAPP_ACCOUNT_H

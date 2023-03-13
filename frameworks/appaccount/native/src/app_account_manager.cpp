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

#include "app_account_manager.h"

#include "account_log_wrapper.h"
#include "app_account.h"

namespace OHOS {
namespace AccountSA {
ErrCode AppAccountManager::AddAccount(const std::string &name, const std::string &extraInfo)
{
    return AppAccount::GetInstance().AddAccount(name, extraInfo);
}

ErrCode AppAccountManager::AddAccountImplicitly(const std::string &owner, const std::string &authType,
    const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    return AppAccount::GetInstance().AddAccountImplicitly(
        owner, authType, options, callback);
}

ErrCode AppAccountManager::CreateAccount(const std::string &name, const CreateAccountOptions &options)
{
    return AppAccount::GetInstance().CreateAccount(name, options);
}

ErrCode AppAccountManager::CreateAccountImplicitly(const std::string &owner,
    const CreateAccountImplicitlyOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    return AppAccount::GetInstance().CreateAccountImplicitly(owner, options, callback);
}

ErrCode AppAccountManager::DeleteAccount(const std::string &name)
{
    return AppAccount::GetInstance().DeleteAccount(name);
}

ErrCode AppAccountManager::GetAccountExtraInfo(const std::string &name, std::string &extraInfo)
{
    return AppAccount::GetInstance().GetAccountExtraInfo(name, extraInfo);
}

ErrCode AppAccountManager::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo)
{
    return AppAccount::GetInstance().SetAccountExtraInfo(name, extraInfo);
}

ErrCode AppAccountManager::EnableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    return AppAccount::GetInstance().EnableAppAccess(name, authorizedApp);
}

ErrCode AppAccountManager::DisableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    return AppAccount::GetInstance().DisableAppAccess(name, authorizedApp);
}

ErrCode AppAccountManager::SetAppAccess(const std::string &name, const std::string &authorizedApp, bool isAccessible)
{
    return AppAccount::GetInstance().SetAppAccess(name, authorizedApp, isAccessible);
}

ErrCode AppAccountManager::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable)
{
    return AppAccount::GetInstance().CheckAppAccountSyncEnable(name, syncEnable);
}

ErrCode AppAccountManager::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable)
{
    return AppAccount::GetInstance().SetAppAccountSyncEnable(name, syncEnable);
}

ErrCode AppAccountManager::GetAssociatedData(const std::string &name, const std::string &key, std::string &value)
{
    return AppAccount::GetInstance().GetAssociatedData(name, key, value);
}

ErrCode AppAccountManager::SetAssociatedData(const std::string &name, const std::string &key, const std::string &value)
{
    return AppAccount::GetInstance().SetAssociatedData(name, key, value);
}

ErrCode AppAccountManager::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential)
{
    return AppAccount::GetInstance().GetAccountCredential(name, credentialType, credential);
}

ErrCode AppAccountManager::SetAccountCredential(
    const std::string &name, const std::string &credentialType, const std::string &credential)
{
    return AppAccount::GetInstance().SetAccountCredential(name, credentialType, credential);
}

ErrCode AppAccountManager::Authenticate(const std::string &name, const std::string &owner,
    const std::string &authType, const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    return AppAccount::GetInstance().Authenticate(name, owner, authType, options, callback);
}

ErrCode AppAccountManager::GetOAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token)
{
    return AppAccount::GetInstance().GetOAuthToken(name, owner, authType, token);
}

ErrCode AppAccountManager::GetAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token)
{
    return AppAccount::GetInstance().GetAuthToken(name, owner, authType, token);
}

ErrCode AppAccountManager::SetOAuthToken(
    const std::string &name, const std::string &authType, const std::string &token)
{
    return AppAccount::GetInstance().SetOAuthToken(name, authType, token);
}

ErrCode AppAccountManager::DeleteOAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, const std::string &token)
{
    return AppAccount::GetInstance().DeleteOAuthToken(name, owner, authType, token);
}

ErrCode AppAccountManager::DeleteAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, const std::string &token)
{
    return AppAccount::GetInstance().DeleteAuthToken(name, owner, authType, token);
}

ErrCode AppAccountManager::SetOAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool isVisible)
{
    return AppAccount::GetInstance().SetOAuthTokenVisibility(
        name, authType, bundleName, isVisible);
}

ErrCode AppAccountManager::SetAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool isVisible)
{
    return AppAccount::GetInstance().SetAuthTokenVisibility(
        name, authType, bundleName, isVisible);
}

ErrCode AppAccountManager::CheckOAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool &isVisible)
{
    return AppAccount::GetInstance().CheckOAuthTokenVisibility(
        name, authType, bundleName, isVisible);
}

ErrCode AppAccountManager::CheckAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool &isVisible)
{
    return AppAccount::GetInstance().CheckAuthTokenVisibility(
        name, authType, bundleName, isVisible);
}

ErrCode AppAccountManager::GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &info)
{
    return AppAccount::GetInstance().GetAuthenticatorInfo(owner, info);
}

ErrCode AppAccountManager::GetAllOAuthTokens(
    const std::string &name, const std::string &owner, std::vector<OAuthTokenInfo> &tokenInfos)
{
    return AppAccount::GetInstance().GetAllOAuthTokens(name, owner, tokenInfos);
}

ErrCode AppAccountManager::GetOAuthList(
    const std::string &name, const std::string &authType, std::set<std::string> &oauthList)
{
    return AppAccount::GetInstance().GetOAuthList(name, authType, oauthList);
}

ErrCode AppAccountManager::GetAuthList(
    const std::string &name, const std::string &authType, std::set<std::string> &oauthList)
{
    return AppAccount::GetInstance().GetAuthList(name, authType, oauthList);
}

ErrCode AppAccountManager::GetAuthenticatorCallback(const std::string &sessionId, sptr<IRemoteObject> &callback)
{
    return AppAccount::GetInstance().GetAuthenticatorCallback(sessionId, callback);
}

ErrCode AppAccountManager::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    return AppAccount::GetInstance().GetAllAccounts(owner, appAccounts);
}

ErrCode AppAccountManager::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts)
{
    return AppAccount::GetInstance().GetAllAccessibleAccounts(appAccounts);
}

ErrCode AppAccountManager::QueryAllAccessibleAccounts(
    const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    return AppAccount::GetInstance().QueryAllAccessibleAccounts(owner, appAccounts);
}

ErrCode AppAccountManager::CheckAppAccess(const std::string &name, const std::string &authorizedApp, bool &isAccessible)
{
    return AppAccount::GetInstance().CheckAppAccess(name, authorizedApp, isAccessible);
}

ErrCode AppAccountManager::DeleteAccountCredential(const std::string &name, const std::string &credentialType)
{
    return AppAccount::GetInstance().DeleteAccountCredential(name, credentialType);
}

ErrCode AppAccountManager::SelectAccountsByOptions(
    const SelectAccountsOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    return AppAccount::GetInstance().SelectAccountsByOptions(options, callback);
}

ErrCode AppAccountManager::VerifyCredential(const std::string &name, const std::string &owner,
    const VerifyCredentialOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    return AppAccount::GetInstance().VerifyCredential(name, owner, options, callback);
}

ErrCode AppAccountManager::CheckAccountLabels(const std::string &name, const std::string &owner,
    const std::vector<std::string> &labels, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    return AppAccount::GetInstance().CheckAccountLabels(name, owner, labels, callback);
}

ErrCode AppAccountManager::SetAuthenticatorProperties(const std::string &owner,
    const SetPropertiesOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    return AppAccount::GetInstance().SetAuthenticatorProperties(owner, options, callback);
}

ErrCode AppAccountManager::SubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber)
{
    return AppAccount::GetInstance().SubscribeAppAccount(subscriber);
}

ErrCode AppAccountManager::UnsubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber)
{
    return AppAccount::GetInstance().UnsubscribeAppAccount(subscriber);
}
}  // namespace AccountSA
}  // namespace OHOS

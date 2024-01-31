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

#include "app_account.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_proxy.h"
#include "app_account_common.h"
#include "app_account_constants.h"
#include "app_account_death_recipient.h"
#include "ohos_account_kits_impl.h"

namespace OHOS {
namespace AccountSA {
#define RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(str)         \
    if (CheckSpecialCharacters(str) != ERR_OK) {            \
        ACCOUNT_LOGE("failed to check special characters"); \
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;        \
    }                                                       \

#define RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(str, maxSize, msg)                                                \
    if ((str).empty() || ((str).size() > (maxSize))) {                                                            \
        ACCOUNT_LOGE("%{public}s, input size: %{public}zu, max size: %{public}zu", msg, (str).size(), maxSize); \
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;                                                            \
    }

#define RETURN_IF_STRING_IS_OVERSIZE(str, maxSize, msg)                                                         \
    if ((str).size() > (maxSize)) {                                                                             \
        ACCOUNT_LOGE("%{public}s, input size: %{public}zu, max size: %{public}zu", msg, (str).size(), maxSize); \
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;                                                            \
    }                                                                                                           \

AppAccount &AppAccount::GetInstance()
{
    static AppAccount *instance = new (std::nothrow) AppAccount();
    return *instance;
}

ErrCode AppAccount::AddAccount(const std::string &name, const std::string &extraInfo)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_OVERSIZE(extraInfo, Constants::EXTRA_INFO_MAX_SIZE, "extraInfo is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->AddAccount(name, extraInfo);
}

ErrCode AppAccount::AddAccountImplicitly(const std::string &owner, const std::string &authType,
    const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(options.GetStringParam(Constants::KEY_CALLER_ABILITY_NAME),
        Constants::ABILITY_NAME_MAX_SIZE, "abilityName is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->AddAccountImplicitly(owner, authType, options, callback);
}

ErrCode AppAccount::CreateAccount(const std::string &name, const CreateAccountOptions &options)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    if (options.customData.size() > Constants::MAX_CUSTOM_DATA_SIZE) {
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    for (auto it : options.customData) {
        RETURN_IF_STRING_IS_OVERSIZE(it.first, Constants::ASSOCIATED_KEY_MAX_SIZE, "customData key is oversize");
        RETURN_IF_STRING_IS_OVERSIZE(it.second, Constants::ASSOCIATED_VALUE_MAX_SIZE, "customData value is oversize");
    }
    return proxy->CreateAccount(name, options);
}

ErrCode AppAccount::CreateAccountImplicitly(const std::string &owner, const CreateAccountImplicitlyOptions &options,
    const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(options.authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(options.parameters.GetStringParam(Constants::KEY_CALLER_ABILITY_NAME),
        Constants::ABILITY_NAME_MAX_SIZE, "abilityName is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(
        options.requiredLabels, Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "requiredLabels array is oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CreateAccountImplicitly(owner, options, callback);
}

ErrCode AppAccount::DeleteAccount(const std::string &name)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->DeleteAccount(name);
}

ErrCode AppAccount::GetAccountExtraInfo(const std::string &name, std::string &extraInfo)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_OVERSIZE(extraInfo, Constants::EXTRA_INFO_MAX_SIZE, "extraInfo is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAccountExtraInfo(name, extraInfo);
}

ErrCode AppAccount::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_OVERSIZE(extraInfo, Constants::EXTRA_INFO_MAX_SIZE, "extraInfo is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SetAccountExtraInfo(name, extraInfo);
}

ErrCode AppAccount::EnableAppAccess(const std::string &name, const std::string &bundleName)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->EnableAppAccess(name, bundleName);
}

ErrCode AppAccount::DisableAppAccess(const std::string &name, const std::string &bundleName)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->DisableAppAccess(name, bundleName);
}

ErrCode AppAccount::SetAppAccess(const std::string &name, const std::string &authorizedApp, bool isAccessible)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(authorizedApp, Constants::BUNDLE_NAME_MAX_SIZE,
        "authorizedApp name is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SetAppAccess(name, authorizedApp, isAccessible);
}

ErrCode AppAccount::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CheckAppAccountSyncEnable(name, syncEnable);
}

ErrCode AppAccount::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SetAppAccountSyncEnable(name, syncEnable);
}

ErrCode AppAccount::GetAssociatedData(const std::string &name, const std::string &key, std::string &value)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(key, Constants::ASSOCIATED_KEY_MAX_SIZE, "key is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAssociatedData(name, key, value);
}

ErrCode AppAccount::SetAssociatedData(const std::string &name, const std::string &key, const std::string &value)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(key, Constants::ASSOCIATED_KEY_MAX_SIZE, "key is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(value, Constants::ASSOCIATED_VALUE_MAX_SIZE, "value is oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SetAssociatedData(name, key, value);
}

ErrCode AppAccount::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(credentialType, Constants::CREDENTIAL_TYPE_MAX_SIZE,
        "credentialType is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAccountCredential(name, credentialType, credential);
}

ErrCode AppAccount::SetAccountCredential(
    const std::string &name, const std::string &credentialType, const std::string &credential)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(credentialType, Constants::CREDENTIAL_TYPE_MAX_SIZE,
        "credentialType is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(credential, Constants::CREDENTIAL_MAX_SIZE, "credential is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SetAccountCredential(name, credentialType, credential);
}

ErrCode AppAccount::Authenticate(const std::string &name, const std::string &owner, const std::string &authType,
    const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    RETURN_IF_STRING_IS_OVERSIZE(options.GetStringParam(Constants::KEY_CALLER_ABILITY_NAME),
        Constants::ABILITY_NAME_MAX_SIZE, "abilityName is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->Authenticate(name, owner, authType, options, callback);
}

ErrCode AppAccount::GetOAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetOAuthToken(name, owner, authType, token);
}

ErrCode AppAccount::GetAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAuthToken(name, owner, authType, token);
}

ErrCode AppAccount::SetOAuthToken(const std::string &name, const std::string &authType, const std::string &token)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    RETURN_IF_STRING_IS_OVERSIZE(token, Constants::TOKEN_MAX_SIZE, "token is oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SetOAuthToken(name, authType, token);
}

ErrCode AppAccount::DeleteOAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, const std::string &token)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    RETURN_IF_STRING_IS_OVERSIZE(token, Constants::TOKEN_MAX_SIZE, "token is oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->DeleteOAuthToken(name, owner, authType, token);
}

ErrCode AppAccount::DeleteAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, const std::string &token)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    RETURN_IF_STRING_IS_OVERSIZE(token, Constants::TOKEN_MAX_SIZE, "token is oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->DeleteAuthToken(name, owner, authType, token);
}

ErrCode AppAccount::CheckTokenVisibilityParam(
    const std::string &name, const std::string &authType, const std::string &bundleName)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize");
    return ERR_OK;
}

ErrCode AppAccount::SetAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool isVisible)
{
    ErrCode ret = CheckTokenVisibilityParam(name, authType, bundleName);
    if (ret != ERR_OK) {
        return ret;
    }
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SetAuthTokenVisibility(name, authType, bundleName, isVisible);
}

ErrCode AppAccount::SetOAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool isVisible)
{
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    ErrCode ret = CheckTokenVisibilityParam(name, authType, bundleName);
    if (ret != ERR_OK) {
        return ret;
    }
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SetOAuthTokenVisibility(name, authType, bundleName, isVisible);
}

ErrCode AppAccount::CheckAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool &isVisible)
{
    ErrCode ret = CheckTokenVisibilityParam(name, authType, bundleName);
    if (ret != ERR_OK) {
        return ret;
    }
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CheckAuthTokenVisibility(name, authType, bundleName, isVisible);
}

ErrCode AppAccount::CheckOAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool &isVisible)
{
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    ErrCode ret = CheckTokenVisibilityParam(name, authType, bundleName);
    if (ret != ERR_OK) {
        return ret;
    }
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CheckOAuthTokenVisibility(name, authType, bundleName, isVisible);
}

ErrCode AppAccount::GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &info)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAuthenticatorInfo(owner, info);
}

ErrCode AppAccount::GetAllOAuthTokens(
    const std::string &name, const std::string &owner, std::vector<OAuthTokenInfo> &tokenInfos)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAllOAuthTokens(name, owner, tokenInfos);
}

ErrCode AppAccount::GetOAuthList(
    const std::string &name, const std::string &authType, std::set<std::string> &oauthList)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetOAuthList(name, authType, oauthList);
}

ErrCode AppAccount::GetAuthList(
    const std::string &name, const std::string &authType, std::set<std::string> &oauthList)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAuthList(name, authType, oauthList);
}

ErrCode AppAccount::GetAuthenticatorCallback(const std::string &sessionId, sptr<IRemoteObject> &callback)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(sessionId, Constants::SESSION_ID_MAX_SIZE,
        "session id is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAuthenticatorCallback(sessionId, callback);
}

ErrCode AppAccount::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAllAccounts(owner, appAccounts);
}

ErrCode AppAccount::CheckAppAccess(const std::string &name, const std::string &authorizedApp, bool &isAccessible)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(authorizedApp, Constants::BUNDLE_NAME_MAX_SIZE,
        "authorizedApp is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CheckAppAccess(name, authorizedApp, isAccessible);
}

ErrCode AppAccount::DeleteAccountCredential(const std::string &name, const std::string &credentialType)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(credentialType, Constants::CREDENTIAL_TYPE_MAX_SIZE,
        "credential type is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->DeleteAccountCredential(name, credentialType);
}

ErrCode AppAccount::SelectAccountsByOptions(
    const SelectAccountsOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    RETURN_IF_STRING_IS_OVERSIZE(
        options.allowedAccounts, Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "allowedAccounts array is oversize");
    RETURN_IF_STRING_IS_OVERSIZE(
        options.allowedOwners, Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "allowedOwners array is oversize");
    RETURN_IF_STRING_IS_OVERSIZE(
        options.requiredLabels, Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "requiredLabels array is oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SelectAccountsByOptions(options, callback);
}

ErrCode AppAccount::VerifyCredential(const std::string &name, const std::string &owner,
    const VerifyCredentialOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_STRING_IS_OVERSIZE(
        options.credentialType, Constants::CREDENTIAL_TYPE_MAX_SIZE, "the credential type is oversize");
    RETURN_IF_STRING_IS_OVERSIZE(options.credential, Constants::CREDENTIAL_MAX_SIZE, "the credential is oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->VerifyCredential(name, owner, options, callback);
}

ErrCode AppAccount::CheckAccountLabels(const std::string &name, const std::string &owner,
    const std::vector<std::string> &labels, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(
        labels, Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "labels array is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CheckAccountLabels(name, owner, labels, callback);
}

ErrCode AppAccount::SetAuthenticatorProperties(const std::string &owner,
    const SetPropertiesOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SetAuthenticatorProperties(owner, options, callback);
}

ErrCode AppAccount::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts)
{
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetAllAccessibleAccounts(appAccounts);
}

ErrCode AppAccount::QueryAllAccessibleAccounts(
    const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    RETURN_IF_STRING_IS_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is oversize");
    return proxy->QueryAllAccessibleAccounts(owner, appAccounts);
}

ErrCode AppAccount::SubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber)
{
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return ERR_APPACCOUNT_KIT_SUBSCRIBER_IS_NULLPTR;
    }

    AppAccountSubscribeInfo subscribeInfo;
    if (subscriber->GetSubscribeInfo(subscribeInfo) != ERR_OK) {
        ACCOUNT_LOGE("get subscribeInfo failed");
        return ERR_APPACCOUNT_KIT_GET_SUBSCRIBE_INFO;
    }

    std::vector<std::string> owners;
    if (subscribeInfo.GetOwners(owners) != ERR_OK) {
        ACCOUNT_LOGE("failed to get owners");
        return ERR_APPACCOUNT_KIT_GET_OWNERS;
    }

    if (owners.size() == 0) {
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    // remove duplicate ones
    std::sort(owners.begin(), owners.end());
    owners.erase(std::unique(owners.begin(), owners.end()), owners.end());
    if (subscribeInfo.SetOwners(owners) != ERR_OK) {
        ACCOUNT_LOGE("failed to set owners");
        return ERR_APPACCOUNT_KIT_SET_OWNERS;
    }

    for (auto owner : owners) {
        if (owner.size() > Constants::OWNER_MAX_SIZE) {
            ACCOUNT_LOGE("owner is out of range, owner.size() = %{public}zu", owner.size());
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }
    }

    sptr<IRemoteObject> appAccountEventListener = nullptr;
    ErrCode subscribeState = CreateAppAccountEventListener(subscriber, appAccountEventListener);
    if (subscribeState == INITIAL_SUBSCRIPTION) {
        subscribeState = proxy->SubscribeAppAccount(subscribeInfo, appAccountEventListener);
        if (subscribeState != ERR_OK) {
            std::lock_guard<std::mutex> lock(eventListenersMutex_);
            eventListeners_.erase(subscriber);
        }
        return subscribeState;
    } else if (subscribeState == ALREADY_SUBSCRIBED) {
        return ERR_APPACCOUNT_SUBSCRIBER_ALREADY_REGISTERED;
    } else {
        return ERR_APPACCOUNT_KIT_SUBSCRIBE;
    }
}

ErrCode AppAccount::UnsubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber)
{
    auto proxy = GetAppAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return ERR_APPACCOUNT_KIT_SUBSCRIBER_IS_NULLPTR;
    }

    std::lock_guard<std::mutex> lock(eventListenersMutex_);

    auto eventListener = eventListeners_.find(subscriber);
    if (eventListener != eventListeners_.end()) {
        ErrCode result = proxy->UnsubscribeAppAccount(eventListener->second->AsObject());
        if (result == ERR_OK) {
            eventListener->second->Stop();
            eventListeners_.erase(eventListener);
        }

        return result;
    } else {
        ACCOUNT_LOGE("no specified subscriber has been registered");
        return ERR_APPACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED;
    }
}

ErrCode AppAccount::ResetAppAccountProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if ((proxy_ != nullptr) && (proxy_->AsObject() != nullptr)) {
        proxy_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
    proxy_ = nullptr;
    return ERR_OK;
}

ErrCode AppAccount::CheckSpecialCharacters(const std::string &name)
{
    for (auto specialCharacter : Constants::SPECIAL_CHARACTERS) {
        std::size_t found = name.find(specialCharacter);
        if (found != std::string::npos) {
            ACCOUNT_LOGE("found a special character, specialCharacter = %{public}c", specialCharacter);
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }
    }

    return ERR_OK;
}

sptr<IAppAccount> AppAccount::GetAppAccountProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }
    sptr<IRemoteObject> object = OhosAccountKitsImpl::GetInstance().GetAppAccountService();
    if (object == nullptr) {
        ACCOUNT_LOGE("failed to get app account service");
        return nullptr;
    }
    deathRecipient_ = new (std::nothrow) AppAccountDeathRecipient();
    if (deathRecipient_ == nullptr) {
        ACCOUNT_LOGE("failed to create app account death recipient");
        return nullptr;
    }
    if (!object->AddDeathRecipient(deathRecipient_)) {
        ACCOUNT_LOGE("failed to add app account death recipient");
        deathRecipient_ = nullptr;
        return nullptr;
    }
    proxy_ = iface_cast<IAppAccount>(object);
    return proxy_;
}

ErrCode AppAccount::CreateAppAccountEventListener(
    const std::shared_ptr<AppAccountSubscriber> &subscriber, sptr<IRemoteObject> &appAccountEventListener)
{
    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return SUBSCRIBE_FAILED;
    }

    std::lock_guard<std::mutex> lock(eventListenersMutex_);

    auto eventListener = eventListeners_.find(subscriber);
    if (eventListener != eventListeners_.end()) {
        appAccountEventListener = eventListener->second->AsObject();
        ACCOUNT_LOGI("subscriber already has app account event listener");
        return ALREADY_SUBSCRIBED;
    } else {
        if (eventListeners_.size() == Constants::APP_ACCOUNT_SUBSCRIBER_MAX_SIZE) {
            ACCOUNT_LOGE("the maximum number of subscribers has been reached");
            return SUBSCRIBE_FAILED;
        }

        sptr<AppAccountEventListener> listener = new (std::nothrow) AppAccountEventListener(subscriber);
        if (!listener) {
            ACCOUNT_LOGE("the app account event listener is null");
            return SUBSCRIBE_FAILED;
        }
        appAccountEventListener = listener->AsObject();
        eventListeners_[subscriber] = listener;
    }

    return INITIAL_SUBSCRIPTION;
}
}  // namespace AccountSA
}  // namespace OHOS

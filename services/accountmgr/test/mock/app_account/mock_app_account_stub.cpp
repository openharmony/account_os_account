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

#include "mock_app_account_stub.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string STRING_EMPTY = "";
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_NAME_EMPTY = STRING_EMPTY;
const std::string STRING_EXTRA_INFO_EMPTY = STRING_EMPTY;
const std::string STRING_OWNER = "com.example.owner";

constexpr std::int32_t NAME_MAX_SIZE = 512;
constexpr std::int32_t EXTRA_INFO_MAX_SIZE = 1024;
}  // namespace

ErrCode MockAppAccountStub::AddAccount(const std::string &name, const std::string &extraInfo, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");
    ACCOUNT_LOGI("mock name.size() = %{public}zu", name.size());
    ACCOUNT_LOGI("mock extraInfo.size() = %{public}zu", extraInfo.size());

    if (name.size() == 0) {
        ACCOUNT_LOGE("mock name is empty");
        funcResult = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        return funcResult;
    }

    if (name.size() > NAME_MAX_SIZE) {
        ACCOUNT_LOGE("mock name is out of range, name.size() = %{public}zu", name.size());
        funcResult = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        return funcResult;
    }

    if (extraInfo.size() > EXTRA_INFO_MAX_SIZE) {
        ACCOUNT_LOGE("mock extra info is out of range, extraInfo.size() = %{public}zu", extraInfo.size());
        funcResult = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        return funcResult;
    }

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::AddAccountImplicitly(const std::string &owner, const std::string &authType,
    const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");
    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::CreateAccount(const std::string &name, const CreateAccountOptions &options,
    int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");
    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::CreateAccountImplicitly(const std::string &owner,
    const CreateAccountImplicitlyOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback,
    int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");
    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::DeleteAccount(const std::string &name, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");
    ACCOUNT_LOGI("mock name.size() = %{public}zu", name.size());

    if (name.size() == 0) {
        ACCOUNT_LOGE("mock name is empty");
        funcResult = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        return funcResult;
    }

    if (name.size() > NAME_MAX_SIZE) {
        ACCOUNT_LOGE("mock name is out of range, name.size() = %{public}zu", name.size());
        funcResult = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        return funcResult;
    }

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::GetAccountExtraInfo(const std::string &name, std::string &extraInfo, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo,
    int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::EnableAppAccess(const std::string &name, const std::string &authorizedApp,
    int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::DisableAppAccess(const std::string &name, const std::string &authorizedApp,
    int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::SetAppAccess(const std::string &name, const std::string &authorizedApp, bool isAccessible,
    int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::SetAppAccountSyncEnable(const std::string &name, bool syncEnable, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::GetAssociatedData(const std::string &name, const std::string &key, std::string &value,
    int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::SetAssociatedData(
    const std::string &name, const std::string &key, const std::string &value, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::SetAccountCredential(
    const std::string &name, const std::string &credentialType, const std::string &credential, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::Authenticate(const AppAccountStringInfo &appAccountStringInfo, const AAFwk::Want &options,
    const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::GetOAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token,
    int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::GetAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token,
    int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::SetOAuthToken(
    const std::string &name, const std::string &authType, const std::string &token, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::DeleteOAuthToken(const std::string &name, const std::string &owner,
    const std::string &authType, const std::string &token, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::DeleteAuthToken(const std::string &name, const std::string &owner,
    const std::string &authType, const std::string &token, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::SetOAuthTokenVisibility(const std::string &name, const std::string &authType,
    const std::string &bundleName, bool isVisible, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::SetAuthTokenVisibility(const std::string &name, const std::string &authType,
    const std::string &bundleName, bool isVisible, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::CheckOAuthTokenVisibility(const std::string &name, const std::string &authType,
    const std::string &bundleName, bool &isVisible, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::CheckAuthTokenVisibility(const std::string &name, const std::string &authType,
    const std::string &bundleName, bool &isVisible, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}


ErrCode MockAppAccountStub::GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &authenticator,
    int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::GetAllOAuthTokens(const std::string &name, const std::string &owner,
    std::vector<OAuthTokenInfo> &tokenInfos, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::GetOAuthList(const std::string &name, const std::string &authType,
    std::set<std::string> &oauthList, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::GetAuthList(const std::string &name, const std::string &authType,
    std::set<std::string> &oauthList, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::GetAuthenticatorCallback(const std::string &sessionId, int32_t &funcResult,
    sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts,
    int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::QueryAllAccessibleAccounts(
    const std::string &owner, std::vector<AppAccountInfo> &appAccounts, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");
    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::CheckAppAccess(
    const std::string &name, const std::string &authorizedApp, bool &isAccessible, int32_t &funcResult)
{
    ACCOUNT_LOGD("mock enter");
    (void) name;
    (void) authorizedApp;
    (void) isAccessible;
    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::DeleteAccountCredential(const std::string &name, const std::string &credentialType,
    int32_t &funcResult)
{
    ACCOUNT_LOGD("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::SelectAccountsByOptions(
    const SelectAccountsOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult)
{
    ACCOUNT_LOGD("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::VerifyCredential(const std::string &name, const std::string &owner,
    const VerifyCredentialOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult)
{
    ACCOUNT_LOGD("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::CheckAccountLabels(const std::string &name, const std::string &owner,
    const std::vector<std::string> &labels, const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult)
{
    ACCOUNT_LOGD("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::SetAuthenticatorProperties(const std::string &owner,
    const SetPropertiesOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback, int32_t &funcResult)
{
    ACCOUNT_LOGD("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::SubscribeAppAccount(
    const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    std::vector<std::string> owners;
    subscribeInfo.GetOwners(owners);

    ACCOUNT_LOGI("mock owners.size() = %{public}zu", owners.size());
    if (owners.size() == 0) {
        ACCOUNT_LOGE("mock owners are empty");
        funcResult = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        return funcResult;
    }

    funcResult = ERR_OK;
    return funcResult;
}

ErrCode MockAppAccountStub::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener,
    const std::vector<std::string> &owners, int32_t &funcResult)
{
    ACCOUNT_LOGI("mock enter");

    funcResult = ERR_OK;
    return funcResult;
}
}  // namespace AccountSA
}  // namespace OHOS

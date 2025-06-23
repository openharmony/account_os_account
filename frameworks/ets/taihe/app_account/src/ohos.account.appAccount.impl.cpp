/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ani_common_want.h"
#include "app_account_authenticator_callback_stub.h"
#include "app_account_common.h"
#include "app_account_manager.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "ohos.account.appAccount.proj.hpp"
#include "ohos.account.appAccount.impl.hpp"
#include "taihe_appAccount_info.h"
#include "ohos_account_kits.h"
#include "stdexcept"
#include "taihe/runtime.hpp"

using namespace taihe;
using namespace OHOS;
using namespace ohos::account::appAccount;

namespace {
using OHOS::AccountSA::ACCOUNT_LABEL;

std::map<OHOS::AccountSA::AppAccountManager *,
    std::vector<AccountSA::AsyncContextForSubscribe *>> g_AppAccountSubscribers;
std::mutex g_lockForAppAccountSubscribers;

AccountSA::SelectAccountsOptions ConvertAccountsOptionsInfo(SelectAccountsOptions const& options)
{
    AccountSA::SelectAccountsOptions tempOptions;
    if(options.allowedAccounts){
        for (const auto& accountsOptionsInfo : options.allowedAccounts.value()){
            std::pair<std::string, std::string> tmepPair;
            tmepPair.first = accountsOptionsInfo.owner.c_str();
            tmepPair.second = accountsOptionsInfo.name.c_str();
            tempOptions.allowedAccounts.push_back(tmepPair);
        }
    }

    if(options.allowedOwners){
        std::vector<std::string> tempAllowedOwners(options.allowedOwners.value().data(),
            options.allowedOwners.value().data() + options.allowedOwners.value().size());
        tempOptions.allowedOwners = tempAllowedOwners;
    }

    if(options.requiredLabels){
        std::vector<std::string> tempRequiredLabels(options.requiredLabels.value().data(),
            options.requiredLabels.value().data() + options.requiredLabels.value().size());
        tempOptions.requiredLabels = tempRequiredLabels;
    }
    return tempOptions;
}

AppAccountInfo ConvertAppAccountInfo(AccountSA::AppAccountInfo& innerInfo)
{
    return AppAccountInfo{
        .owner = taihe::string(innerInfo.GetOwner().c_str()),
        .name = taihe::string(innerInfo.GetName().c_str()),
    };
}

AccountSA::SelectAccountsOptions ConvertAccountsOptionsInfo(
    ::ohos::account::appAccount::SelectAccountsOptions const& options)
{
    AccountSA::SelectAccountsOptions tempOptions;
    if (options.allowedAccounts) {
        for (const auto& accountsOptionsInfo : options.allowedAccounts.value()) {
            std::pair<std::string, std::string> tempPair;
            tempPair.first = accountsOptionsInfo.owner.c_str();
            tempPair.second = accountsOptionsInfo.name.c_str();
            tempOptions.allowedAccounts.push_back(tempPair);
        }
    }
    
    if (options.allowedOwners) {
        std::vector<std::string> tempAllowedOwners(options.allowedOwners.value().data(),
            options.allowedOwners.value().data() + options.allowedOwners.value().size());
        tempOptions.allowedOwners = tempAllowedOwners;
    }

    if (options.requiredLabels) {
        std::vector<std::string> tempRequiredLabels(options.requiredLabels.value().data(),
            options.requiredLabels.value().data() + options.requiredLabels.value().size());
        tempOptions.requiredLabels = tempRequiredLabels;
    }
    return tempOptions;
}

class AppAccountManagerImpl {
public:
    AppAccountManagerImpl() {}

    void CreateAccountSync(string_view name)
    {
        AccountSA::CreateAccountOptions options{};
        std::string innerName(name.data(), name.size());
        int32_t errorCode = AccountSA::AppAccountManager::CreateAccount(innerName, options);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    void CreateAccountWithOpt(string_view name, CreateAccountOptions const& options)
    {
        std::string innerName(name.data(), name.size());
        AccountSA::CreateAccountOptions optionsInner;
        if (options.customData.has_value()) {
            for (const auto& [key, value] : options.customData.value()) {
                std::string tempKey(key.data(), key.size());
                std::string tempValue(value.data(), value.size());
                optionsInner.customData.emplace(tempKey, tempValue);
            }
        }
        int32_t errorCode = AccountSA::AppAccountManager::CreateAccount(innerName, optionsInner);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    void RemoveAccountSync(string_view name)
    {
        std::string innerName(name.data(), name.size());
        int32_t errorCode = AccountSA::AppAccountManager::DeleteAccount(innerName);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    void SetAppAccessSync(string_view name, string_view bundleName, bool isAccessible)
    {
        std::string innerName(name.data(), name.size());
        std::string innerBundleName(bundleName.data(), bundleName.size());
        ErrCode errorCode = AccountSA::AppAccountManager::SetAppAccess(innerName, innerBundleName, isAccessible);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    bool CheckAppAccessSync(string_view name, string_view bundleName)
    {
        std::string innerName(name.data(), name.size());
        std::string innerBundleName(bundleName.data(), bundleName.size());
        bool isAccessible = false;
        int32_t errorCode = AccountSA::AppAccountManager::CheckAppAccess(innerName, innerBundleName, isAccessible);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        return isAccessible;
    }

    bool CheckDataSyncEnabledSync(string_view name)
    {
        std::string innerName(name.data(), name.size());
        bool result = false;
        int32_t errorCode = AccountSA::AppAccountManager::CheckAppAccountSyncEnable(innerName, result);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        return result;
    }

    void SetCredentialSync(string_view name, string_view credentialType, string_view credential)
    {
        std::string innerName(name.data(), name.size());
        std::string innerCredentialType(credentialType.data(), credentialType.size());
        std::string innerCredential(credential.data(), credential.size());
        int32_t errorCode = AccountSA::AppAccountManager::SetAccountCredential(innerName,
            innerCredentialType, innerCredential);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    void SetDataSyncEnabledSync(string_view name, bool isEnabled)
    {
        std::string innerName(name.data(), name.size());
        int32_t errorCode = AccountSA::AppAccountManager::SetAppAccountSyncEnable(innerName, isEnabled);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    void SetCustomDataSync(string_view name, string_view key, string_view value)
    {
        std::string innerName(name.data(), name.size());
        std::string innerkey(key.data(), key.size());
        std::string innerValue(value.data(), value.size());
        int32_t errorCode = AccountSA::AppAccountManager::SetAssociatedData(innerName, innerkey, innerValue);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    array<AppAccountInfo> GetAllAccountsSync()
    {
        std::string innerOwner = "";
        std::vector<AccountSA::AppAccountInfo> appAccounts;
        int32_t errorCode = AccountSA::AppAccountManager::QueryAllAccessibleAccounts(innerOwner, appAccounts);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        std::vector<AppAccountInfo> appAccountsInfos;
        appAccountsInfos.reserve(appAccounts.size());
        for (auto &info : appAccounts) {
            appAccountsInfos.push_back(ConvertAppAccountInfo(info));
        }
        return taihe::array<AppAccountInfo>(taihe::copy_data_t{}, appAccountsInfos.data(), appAccountsInfos.size());
    }

    array<AppAccountInfo> GetAccountsByOwnerSync(string_view owner)
    {
        std::string innerOwner(owner.data(), owner.size());
        std::vector<AccountSA::AppAccountInfo> appAccounts;
        int32_t errorCode = AccountSA::AppAccountManager::QueryAllAccessibleAccounts(innerOwner, appAccounts);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        std::vector<AppAccountInfo> appAccountsInfos;
        appAccountsInfos.reserve(appAccounts.size());
        for (auto &info : appAccounts) {
            appAccountsInfos.push_back(ConvertAppAccountInfo(info));
        }
        return taihe::array<AppAccountInfo>(taihe::copy_data_t{}, appAccountsInfos.data(), appAccountsInfos.size());
    }

    string GetCredentialSync(string_view name, string_view credentialType)
    {
        std::string innerName(name.data(), name.size());
        std::string innerCredentialType(credentialType.data(), credentialType.size());
        std::string credential = "";
        int32_t errorCode = AccountSA::AppAccountManager::GetAccountCredential(innerName,
            innerCredentialType, credential);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        return taihe::string(credential.c_str());
    }

    string GetCustomDataWithTypeSync(string_view name, string_view credentialType)
    {
        std::string innerName(name.data(), name.size());
        std::string innerKey(credentialType.data(), credentialType.size());
        std::string value = "";
        int32_t errorCode = AccountSA::AppAccountManager::GetAssociatedData(innerName, innerKey, value);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        return taihe::string(value.c_str());
    }

    string GetCustomDataSyncTaihe(string_view name, string_view key)
    {
        std::string innerName(name.data(), name.size());
        std::string innerKey(key.data(), key.size());
        std::string value = "";
        int32_t errorCode = AccountSA::AppAccountManager::GetAssociatedData(innerName, innerKey, value);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        return taihe::string(value.c_str());
    }

    string GetAuthTokenSync(string_view name, string_view owner, string_view authType)
    {
        std::string innerName(name.data(), name.size());
        std::string innerOwner(owner.data(), owner.size());
        std::string innerAuthType(authType.data(), authType.size());
        std::string token = "";
        int32_t errorCode = AccountSA::AppAccountManager::GetOAuthToken(innerName, innerOwner, innerAuthType, token);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        return taihe::string(token.c_str());
    }

    void SetAuthTokenSync(string_view name, string_view authType, string_view token)
    {
        std::string innerName(name.data(), name.size());
        std::string innerAuthType(authType.data(), authType.size());
        std::string innerToken(token.data(), token.size());
        int32_t errorCode = AccountSA::AppAccountManager::SetOAuthToken(innerName, innerAuthType, innerToken);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    bool CheckAccountLabelsSync(string_view name, string_view owner, array_view<string> labels)
    {
        std::string innerName(name.data(), name.size());
        std::string innerOwner(owner.data(), owner.size());
        std::vector<std::string> innerLabels(labels.data(), labels.data() + labels.size());
        sptr<AccountSA::THauthenticatorAsyncCallback> callback =
            new (std::nothrow) AccountSA::THauthenticatorAsyncCallback();
        if (callback == nullptr) {
            ACCOUNT_LOGE("Insufficient memory for callback!");
            return false;
        }
        int32_t errorCode = AccountSA::AppAccountManager::CheckAccountLabels(innerName,
            innerOwner, innerLabels, callback);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        std::unique_lock<std::mutex> lock(callback->mutex);
        callback->cv.wait(lock, [callback] { return callback->isDone; });
        return callback->param->result.GetBoolParam(AccountSA::Constants::KEY_BOOLEAN_RESULT, false);
    }

    array<AppAccountInfo> SelectAccountsByOptionsSync(SelectAccountsOptions const& options)
    {
        AccountSA::SelectAccountsOptions innerOptions = ConvertAccountsOptionsInfo(options);
        std::vector<AppAccountInfo> accountInfos;
        sptr<AccountSA::THauthenticatorAsyncCallback> callback =
            new (std::nothrow) AccountSA::THauthenticatorAsyncCallback();
        if (callback == nullptr) {
            ACCOUNT_LOGE("Insufficient memory for callback!");
            return taihe::array<AppAccountInfo>(taihe::copy_data_t{}, accountInfos.data(), accountInfos.size());
        }
        int32_t errorCode = AccountSA::AppAccountManager::SelectAccountsByOptions(innerOptions, callback);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        std::unique_lock<std::mutex> lock(callback->mutex);
        callback->cv.wait(lock, [callback] { return callback->isDone; });
        std::vector<std::string> names =
			callback->param->result.GetStringArrayParam(AccountSA::Constants::KEY_ACCOUNT_NAMES);
        std::vector<std::string> owners =
			callback->param->result.GetStringArrayParam(AccountSA::Constants::KEY_ACCOUNT_OWNERS);
        for (size_t i = 0; i < names.size(); ++i) {
            AppAccountInfo tempInfo{
                .owner = owners[i],
                .name = names[i],
            };
            accountInfos.push_back(tempInfo);
        }
        return taihe::array<AppAccountInfo>(taihe::copy_data_t{}, accountInfos.data(), accountInfos.size());
    }

    void DeleteAuthTokenSync(string_view name, string_view owner, string_view authType, string_view token)
    {
        std::string innerName(name.data(), name.size());
        std::string innerOwner(owner.data(), owner.size());
        std::string innerAuthType(authType.data(), authType.size());
        std::string innerToken(token.data(), token.size());
        int32_t errorCode = AccountSA::AppAccountManager::DeleteAuthToken(innerName,
            innerOwner, innerAuthType, innerToken);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    void SetAuthTokenVisibilitySync(string_view name, string_view authType, string_view bundleName, bool isVisible)
    {
        std::string innerName(name.data(), name.size());
        std::string innerAuthType(authType.data(), authType.size());
        std::string innerBundleName(bundleName.data(), bundleName.size());
        int32_t errorCode = AccountSA::AppAccountManager::SetAuthTokenVisibility(innerName, innerAuthType,
            innerBundleName, isVisible);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    bool CheckAuthTokenVisibilitySync(string_view name, string_view authType, string_view bundleName)
    {
        std::string innerName(name.data(), name.size());
        std::string innerAuthType(authType.data(), authType.size());
        std::string innerBundleName(bundleName.data(), bundleName.size());
        bool isVisible = false;
        int32_t errorCode = AccountSA::AppAccountManager::CheckAuthTokenVisibility(innerName, innerAuthType,
            innerBundleName, isVisible);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        return isVisible;
    }
    
    array<AuthTokenInfo> GetAllAuthTokensSync(string_view name, string_view owner)
    {
        std::string innerName(name.data(), name.size());
        std::string innerOwner(owner.data(), owner.size());
        std::vector<AccountSA::OAuthTokenInfo> innerAuthTokenInfos;

        int32_t errorCode = AccountSA::AppAccountManager::GetAllOAuthTokens(innerName,
            innerOwner, innerAuthTokenInfos);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        AppAccountInfo appAccountInfo = {owner, name};
        std::vector<AuthTokenInfo> authTokenInfoArray;
        authTokenInfoArray.reserve(innerAuthTokenInfos.size());
        AuthTokenInfo authTokenInfo = {};
        for (const auto& info : innerAuthTokenInfos) {
            authTokenInfo = AuthTokenInfo{
                .authType = info.authType,
                .token = info.token,
                .account = optional<AppAccountInfo>(std::in_place_t{}, appAccountInfo),
            };
            authTokenInfoArray.push_back(authTokenInfo);
        }
        return array<AuthTokenInfo>(taihe::copy_data_t{}, authTokenInfoArray.data(), authTokenInfoArray.size());
    }
    
    array<string> GetAuthListSync(string_view name, string_view authType)
    {
        std::string innerName(name.data(), name.size());
        std::string innerAuthType(authType.data(), authType.size());
        std::set<std::string> innerAuthList;
        int32_t errorCode = AccountSA::AppAccountManager::GetAuthList(innerName,
            innerAuthType, innerAuthList);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        std::vector<std::string> innerAuthListVector(
            innerAuthList.begin(),
            innerAuthList.end()
        );
        return array<string>(taihe::copy_data_t{}, innerAuthListVector.data(), innerAuthListVector.size());
    }

    AuthenticatorInfo QueryAuthenticatorInfoSync(string_view owner)
    {
        std::string innerOwner(owner.data(), owner.size());
        AccountSA::AuthenticatorInfo innerAuthenticatorInfo;

        int32_t errorCode = AccountSA::AppAccountManager::GetAuthenticatorInfo(innerOwner,
            innerAuthenticatorInfo);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }

        AuthenticatorInfo authenticatorInfo = AuthenticatorInfo{
            .owner = innerAuthenticatorInfo.owner,
            .iconId = innerAuthenticatorInfo.iconId,
            .labelId = innerAuthenticatorInfo.labelId
        };
        return authenticatorInfo;
    }

    void DeleteCredentialSync(string_view name, string_view credentialType)
    {
        std::string innerName(name.data(), name.size());
        std::string innerCredentialType(credentialType.data(), credentialType.size());
        int32_t errorCode = AccountSA::AppAccountManager::DeleteAccountCredential(innerName,
            innerCredentialType);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    array<AppAccountInfo> SelectAccountsByOptionsSync(SelectAccountsOptions const& options)
    {
        AccountSA::SelectAccountsOptions innerOptions = ConvertAccountsOptionsInfo(options);
        sptr<AccountSA::THauthenticatorAsyncCallback> callback = new
            (std::nothrow) AccountSA::THauthenticatorAsyncCallback();
        int errorCode = AccountSA::AppAccountManager::SelectAccountsByOptions(innerOptions, callback);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        std::unique_lock<std::mutex> lock(callback->mutex);
        callback->cv.wait(lock, [callback] { return callback->isDone; });
        std::vector<AppAccountInfo> accountInfos;
        std::vector<std::string> names = callback->param->result.GetStringArrayParam(
            AccountSA::Constants::KEY_ACCOUNT_NAMES);
        std::vector<std::string> owners = callback->param->result.GetStringArrayParam(
            AccountSA::Constants::KEY_ACCOUNT_OWNERS);
        for (size_t i = 0; i < names.size(); ++i) {
            accountInfos.push_back(ConvertAccountInfo(names[i], owners[i]));
        }
        return taihe::array<AppAccountInfo>(taihe::copy_data_t{}, accountInfos.data(), accountInfos.size());
    }

    void CreateAccountImplicitly(string_view owner, AuthCallback const& Callback)
    {
        std::string innerOwner(owner.data(), owner.size());
        AccountSA::CreateAccountImplicitlyOptions options;
        sptr<AccountSA::AppAccountManagerCallback> callback = new AccountSA::AppAccountManagerCallback(Callback);
        ErrCode errCode = AccountSA::AppAccountManager::CreateAccountImplicitly(innerOwner, options, callback);
        std::unique_lock<std::mutex> lock(callback->mutex_);
        callback->cv.wait(lock, [callback] {return callback->isDone;});
        AAFwk::Want errResult;
        if ((errCode != 0) && (callback != nullptr)) {
            callback->OnResult(errCode, errResult);
        }
        if (errCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        if (callback != nullptr) {
            delete callback;
        }
    }

    void CreateAccountImplicitlyWithOpt(string_view owner,
        CreateAccountImplicitlyOptions const& options, AuthCallback const& Callback)
    {
        std::string innerOwner(owner.data(), owner.size());
        AccountSA::CreateAccountImplicitlyOptions inneroptions;
        if (options.authType.has_value()) {
            inneroptions.authType = std::string(options.authType.value().data(), options.authType.value().size());
        }
        if(options.requiredLabels.has_value()){
            inneroptions.requiredLabels.assign(options.requiredLabels.value().data(),
                options.requiredLabels.value().data() + options.requiredLabels.value().size());
        }
        if (options.parameters.has_value()) {
            for (const auto& [key, value] : options.parameters.value()) {
                int* ptr = reinterpret_cast<int*>(value);
                std::string tempKey(key.data(), key.size());
                inneroptions.parameters.SetParam(tempKey,*ptr);
            }
        }
        sptr<AccountSA::AppAccountManagerCallback> callback = new AccountSA::AppAccountManagerCallback(Callback);
        ErrCode errCode = AccountSA::AppAccountManager::CreateAccountImplicitly(innerOwner, inneroptions, callback);
        std::unique_lock<std::mutex> lock(callback->mutex_);
        callback->cv.wait(lock, [callback] {return callback->isDone;});
        AAFwk::Want errResult;
        if ((errCode != 0) && (callback != nullptr)) {
            callback->OnResult(errCode, errResult);
        }
        if (errCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        if (callback != nullptr) {
            delete callback;
        }
    }

    void OnSync(string_view type, array_view<string> owners, callback_view<void(array_view<AppAccountInfo>)> Callback)
    {
        if (type.size() == 0 || type != "accountChange") {
            ACCOUNT_LOGE("Subscriber type size %{public}zu is invalid.", type.size());
            std::string errMsg =
                "Parameter error. The content of \"type\" must be \"accountChange\"";
            taihe::set_business_error(ERR_JS_INVALID_PARAMETER, errMsg);
            return;
        }
        std::vector<std::string> innerOwners(owners.data(), owners.data() + owners.size());

        auto context = std::make_unique<AccountSA::AsyncContextForSubscribe>();
        AccountSA::AppAccountSubscribeInfo subscribeInfo(innerOwners);
        context->subscriber = std::make_shared<AccountSA::SubscriberPtr>(subscribeInfo, Callback);
        if (context->subscriber == nullptr) {
            ACCOUNT_LOGE("fail to create subscriber");
            return;
        }
        std::lock_guard<std::mutex> lock(g_lockForAppAccountSubscribers);
        ErrCode errorCode = AccountSA::AppAccountManager::SubscribeAppAccount(context->subscriber);
        if ((errorCode != ERR_OK) && (context->type != AccountSA::TYPE_CHANGE)) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        g_AppAccountSubscribers[context->appAccountManager].emplace_back(context.get());
        context.release();
    }

    void GetSubscriberByUnsubscribe(std::vector<std::shared_ptr<AccountSA::SubscriberPtr>> &subscribers,
    AccountSA::AsyncContextForUnsubscribe *asyncContextForOff, bool &isFind)
    {
        std::lock_guard<std::mutex> lock(g_lockForAppAccountSubscribers);
        for (auto subscriberInstance : g_AppAccountSubscribers) {
            if (subscriberInstance.first == asyncContextForOff->appAccountManager) {
                for (auto item : subscriberInstance.second) {
                    subscribers.emplace_back(item->subscriber);
                }
                isFind = true;
                break;
            }
        }
    }

    void OffSync(string_view type)
    {
        if (type.size() == 0 || type != "accountChange") {
            ACCOUNT_LOGE("Subscriber type size %{public}zu is invalid.", type.size());
            std::string errMsg =
                "Parameter error. The content of \"type\" must be \"accountChange\"";
            taihe::set_business_error(ERR_JS_INVALID_PARAMETER, errMsg);
            return;
        }

        AccountSA::AsyncContextForUnsubscribe *context = new (std::nothrow) AccountSA::AsyncContextForUnsubscribe();
        std::lock_guard<std::mutex> lock(g_lockForAppAccountSubscribers);
        auto subscribe = g_AppAccountSubscribers.find(context->appAccountManager);
        if (subscribe == g_AppAccountSubscribers.end()) {
            return;
        }

        bool isFind = false;
        std::vector<std::shared_ptr<AccountSA::SubscriberPtr>> subscribers = {nullptr};
        GetSubscriberByUnsubscribe(subscribers, context, isFind);
        if (!isFind) {
            ACCOUNT_LOGE("Unsubscribe failed. The current subscriber does not exist");
            delete context;
            return;
        }

        context->subscribers = subscribers;

        for (auto offSubscriber : context->subscribers) {
            int errCode = AccountSA::AppAccountManager::UnsubscribeAppAccount(offSubscriber);
            ACCOUNT_LOGD("Unsubscribe errcode parameter is %{public}d", errCode);
        }

        subscribe = g_AppAccountSubscribers.find(context->appAccountManager);
        if (subscribe != g_AppAccountSubscribers.end()) {
            for (auto offCBInfo : subscribe->second) {
                delete offCBInfo;
            }
            g_AppAccountSubscribers.erase(subscribe);
        }
    }

    void OffSyncTaihe(string_view type, callback_view<void(array_view<AppAccountInfo>)> Callback)
    {
        if (type.size() == 0 || type != "accountChange") {
            ACCOUNT_LOGE("Subscriber type size %{public}zu is invalid.", type.size());
            std::string errMsg =
                "Parameter error. The content of \"type\" must be \"accountChange\"";
            taihe::set_business_error(ERR_JS_INVALID_PARAMETER, errMsg);
            return;
        }
        AccountSA::AsyncContextForUnsubscribe *context = new (std::nothrow) AccountSA::AsyncContextForUnsubscribe();
        std::lock_guard<std::mutex> lock(g_lockForAppAccountSubscribers);
        auto subscribe = g_AppAccountSubscribers.find(context->appAccountManager);
        if (subscribe == g_AppAccountSubscribers.end()) {
            return;
        }

        bool isFind = false;
        std::vector<std::shared_ptr<AccountSA::SubscriberPtr>> subscribers = {nullptr};
        GetSubscriberByUnsubscribe(subscribers, context, isFind);
        if (!isFind) {
            ACCOUNT_LOGE("Unsubscribe failed. The current subscriber does not exist");
            delete context;
            return;
        }

        context->subscribers = subscribers;

        for (auto offSubscriber : context->subscribers) {
            int errCode = AccountSA::AppAccountManager::UnsubscribeAppAccount(offSubscriber);
            ACCOUNT_LOGD("Unsubscribe errcode parameter is %{public}d", errCode);
        }

        subscribe = g_AppAccountSubscribers.find(context->appAccountManager);
        if (subscribe != g_AppAccountSubscribers.end()) {
            for (auto offCBInfo : subscribe->second) {
                delete offCBInfo;
            }
            g_AppAccountSubscribers.erase(subscribe);
        }
    }

    void AuthSync(string_view name, string_view owner, string_view authType, AuthCallback const& Callback)
    {
        std::string innerName(name.data(), name.size());
        std::string innerOwner(owner.data(), owner.size());
        std::string innerAuthType(authType.data(), authType.size());
        AAFwk::Want options;
        sptr<AccountSA::AppAccountManagerCallback> callback = new AccountSA::AppAccountManagerCallback(Callback);
        ErrCode errCode = AccountSA::AppAccountManager::Authenticate(innerName, innerOwner,
            innerAuthType, options, callback);
        std::unique_lock<std::mutex> lock(callback->mutex_);
        callback->cv.wait(lock, [callback] {return callback->isDone;});
        AAFwk::Want errResult;
        if ((errCode != 0) && (callback != nullptr)) {
            callback->OnResult(errCode, errResult);
        }
        if (errCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        if (callback != nullptr) {
            delete callback;
        }
    }

    void AuthWithMap(string_view name, string_view owner, string_view authType,
        map_view<string, uintptr_t> options, AuthCallback const& Callback)
    {
        std::string innerName(name.data(), name.size());
        std::string innerOwner(owner.data(), owner.size());
        std::string innerAuthType(authType.data(), authType.size());
        AAFwk::Want innerOptions;
        for (const auto& [key, value] : options) {
            int* ptr = reinterpret_cast<int*>(value);
            std::string tempKey(key.data(), key.size());
            innerOptions.SetParam(tempKey,*ptr);
        }
        sptr<AccountSA::AppAccountManagerCallback> callback = new AccountSA::AppAccountManagerCallback(Callback);
        ErrCode errCode = AccountSA::AppAccountManager::Authenticate(innerName, innerOwner,
            innerAuthType, innerOptions, callback);
        std::unique_lock<std::mutex> lock(callback->mutex_);
        callback->cv.wait(lock, [callback] {return callback->isDone;});
        AAFwk::Want errResult;
        if ((errCode != 0) && (callback != nullptr)) {
            callback->OnResult(errCode, errResult);
        }
        if (errCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        if (callback != nullptr) {
            delete callback;
        }
    }
};

AppAccountManager createAppAccountManager()
{
    return make_holder<AppAccountManagerImpl, AppAccountManager>();
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_createAppAccountManager(createAppAccountManager);
// NOLINTEND

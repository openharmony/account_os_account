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
#include "ani_remote_object.h"

using namespace taihe;
using namespace OHOS;
using namespace ohos::account::appAccount;


namespace OHOS::AccountSA {
std::map<uint64_t,
    std::vector<AsyncContextForSubscribe *>> g_ThAppAccountSubscribers;
std::mutex g_thLockForAppAccountSubscribers;
}

namespace {
using OHOS::AccountSA::ACCOUNT_LABEL;

AppAccountInfo ConvertAppAccountInfo(AccountSA::AppAccountInfo& innerInfo)
{
    return AppAccountInfo {
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

class THAppAccountManagerCallback : public AccountSA::AppAccountAuthenticatorCallbackStub {
public:
    explicit THAppAccountManagerCallback(const ohos::account::appAccount::AuthCallback &taiheCallback)
        : taiheCallback_(taiheCallback) {}

    ~THAppAccountManagerCallback() override = default;
    ErrCode OnResult(int32_t resultCode, const AAFwk::Want &result) override
    {
        AppAccountInfo appAccountInfo = AppAccountInfo {
            .owner = taihe::string(result.GetStringParam(AccountSA::Constants::KEY_ACCOUNT_OWNERS)),
            .name = taihe::string(result.GetStringParam(AccountSA::Constants::KEY_ACCOUNT_NAMES))
        };
        AuthTokenInfo authTokenInfo = AuthTokenInfo {
            .authType = taihe::string(result.GetStringParam(AccountSA::Constants::KEY_AUTH_TYPE)),
            .token = taihe::string(result.GetStringParam(AccountSA::Constants::KEY_TOKEN))
        };
        AuthResult authResult = AuthResult {
            .account = optional<AppAccountInfo>(std::in_place_t{}, appAccountInfo),
            .tokenInfo = optional<AuthTokenInfo>(std::in_place_t{}, authTokenInfo),
        };
        taiheCallback_.onResult(resultCode, optional<AuthResult>(std::in_place_t{}, authResult));
        return ERR_OK;
    }

    ErrCode OnRequestRedirected(const AAFwk::Want &request) override
    {
        ani_env *env = get_env();
        auto requestObj = AppExecFwk::WrapWant(env, request);
        auto requestPtr = reinterpret_cast<uintptr_t>(requestObj);
        taiheCallback_.onRequestRedirected(requestPtr);
        return ERR_OK;
    }

    ErrCode OnRequestContinued() override
    {
        if (taiheCallback_.onRequestContinued.has_value()) {
            taiheCallback_.onRequestContinued.value()();
        }
        return ERR_OK;
    }
private:
    ohos::account::appAccount::AuthCallback taiheCallback_;
};

class OnResultCallbackImpl {
public:
    explicit OnResultCallbackImpl(sptr<AccountSA::IAppAccountAuthenticatorCallback> callback)
        : callback_(callback) {}

    void operator()(int32_t result, const optional_view<AuthResult> authResult)
    {
        if (callback_ == nullptr) {
            ACCOUNT_LOGE("Native callback is nullptr");
            return;
        }
        AAFwk::Want wantResult;
        if (authResult.has_value()) {
            if (authResult.value().account.has_value()) {
                std::string name(authResult.value().account.value().name.data(),
                    authResult.value().account.value().name.size());
                std::string owner(authResult.value().account.value().owner.data(),
                    authResult.value().account.value().owner.size());
                wantResult.SetParam(AccountSA::Constants::KEY_ACCOUNT_NAMES, name);
                wantResult.SetParam(AccountSA::Constants::KEY_ACCOUNT_OWNERS, owner);
            }
            if (authResult.value().tokenInfo.has_value()) {
                std::string authType(authResult.value().tokenInfo.value().authType.data(),
                    authResult.value().tokenInfo.value().authType.size());
                std::string token(authResult.value().tokenInfo.value().token.data(),
                    authResult.value().tokenInfo.value().token.size());
                wantResult.SetParam(AccountSA::Constants::KEY_AUTH_TYPE, authType);
                wantResult.SetParam(AccountSA::Constants::KEY_TOKEN, token);
            }
        }
        callback_->OnResult(result, wantResult);
    }

private:
    sptr<AccountSA::IAppAccountAuthenticatorCallback> callback_;
};

class OnRequestRedirectedCallbackImpl {
public:
    explicit OnRequestRedirectedCallbackImpl(sptr<AccountSA::IAppAccountAuthenticatorCallback> callback)
        : callback_(callback) {}

    void operator()(uintptr_t request)
    {
        if (callback_ == nullptr) {
            ACCOUNT_LOGE("Native callback is nullptr");
            return;
        }
        AAFwk::Want wantResult;
        AAFwk::WantParams wantParamsResult;
        ani_env *env = get_env();
        ani_ref requestRef = reinterpret_cast<ani_ref>(request);
        auto status = AppExecFwk::UnwrapWantParams(env, requestRef, wantParamsResult);
        if (status == false) {
            ACCOUNT_LOGE("Failed to UnwrapWantParams status = %{public}d", status);
            return;
        }
        wantResult = wantResult.SetParams(wantParamsResult);
        callback_->OnRequestRedirected(wantResult);
    }

private:
    sptr<AccountSA::IAppAccountAuthenticatorCallback> callback_;
};

class OnRequestContinuedCallbackImpl {
public:
    explicit OnRequestContinuedCallbackImpl(sptr<AccountSA::IAppAccountAuthenticatorCallback> callback)
        : callback_(callback) {}

    void operator()()
    {
        if (callback_ == nullptr) {
            ACCOUNT_LOGE("Native callback is nullptr");
            return;
        }
        callback_->OnRequestContinued();
    }

private:
    sptr<AccountSA::IAppAccountAuthenticatorCallback> callback_;
};

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

    void CreateAccountImplicitly(string_view owner, AuthCallback const& callback)
    {
        std::string innerOwner(owner.data(), owner.size());
        AccountSA::CreateAccountImplicitlyOptions options;
        sptr<THAppAccountManagerCallback> appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
        if (appAccountMgrCb == nullptr) {
            ACCOUNT_LOGE("failed to create AppAccountManagerCallback for insufficient memory");
            return;
        }
        ErrCode errCode = AccountSA::AppAccountManager::CreateAccountImplicitly(innerOwner,
            options, appAccountMgrCb);
        AAFwk::Want errResult;
        if (errCode != ERR_OK) {
            appAccountMgrCb->OnResult(errCode, errResult);
        }
    }

    void CreateAccountImplicitlyWithOpt(string_view owner,
        ohos::account::appAccount::CreateAccountImplicitlyOptions const& options,
        AuthCallback const& callback)
    {
        std::string innerOwner(owner.data(), owner.size());
        AccountSA::CreateAccountImplicitlyOptions innerOptions;
        if (options.authType.has_value()) {
            innerOptions.authType = std::string(options.authType.value().data(), options.authType.value().size());
        }
        if (options.requiredLabels.has_value()) {
            innerOptions.requiredLabels.assign(options.requiredLabels.value().data(),
                options.requiredLabels.value().data() + options.requiredLabels.value().size());
        }

        AAFwk::WantParams params;
        ani_env *env = get_env();
        ani_ref parametersRef = reinterpret_cast<ani_ref>(options.parameters.value());
        auto status = AppExecFwk::UnwrapWantParams(env, parametersRef, params);
        if (status == false) {
            ACCOUNT_LOGE("Failed to UnwrapWant options status = %{public}d", status);
            return;
        }
        innerOptions.parameters.SetParams(params);

        sptr<THAppAccountManagerCallback> appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
        if (appAccountMgrCb == nullptr) {
            ACCOUNT_LOGE("failed to create AppAccountManagerCallback for insufficient memory");
            return;
        }

        ErrCode errCode = AccountSA::AppAccountManager::CreateAccountImplicitly(innerOwner,
            innerOptions, appAccountMgrCb);
        AAFwk::Want errResult;
        if (errCode != ERR_OK) {
            appAccountMgrCb->OnResult(errCode, errResult);
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
            return false;
        }
        std::unique_lock<std::mutex> lock(callback->mutex_);
        callback->cv_.wait(lock, [callback] { return callback->isDone_; });
        if (callback->param_ == nullptr) {
            ACCOUNT_LOGE("Insufficient memory for AuthenticatorCallbackParam!");
            return false;
        }
        if (callback->param_->resultCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(callback->param_->resultCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return false;
        }
        return callback->param_->result.GetBoolParam(AccountSA::Constants::KEY_BOOLEAN_RESULT, false);
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
            return taihe::array<AppAccountInfo>(taihe::copy_data_t{}, accountInfos.data(), accountInfos.size());
        }
        std::unique_lock<std::mutex> lock(callback->mutex_);
        callback->cv_.wait(lock, [callback] { return callback->isDone_; });
        if (callback->param_ == nullptr) {
            ACCOUNT_LOGE("Insufficient memory for AuthenticatorCallbackParam!");
            return taihe::array<AppAccountInfo>(taihe::copy_data_t{}, accountInfos.data(), accountInfos.size());
        }
        if (callback->param_->resultCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(callback->param_->resultCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return taihe::array<AppAccountInfo>(taihe::copy_data_t{}, accountInfos.data(), accountInfos.size());
        }
        std::vector<std::string> names =
			callback->param_->result.GetStringArrayParam(AccountSA::Constants::KEY_ACCOUNT_NAMES);
        std::vector<std::string> owners =
			callback->param_->result.GetStringArrayParam(AccountSA::Constants::KEY_ACCOUNT_OWNERS);
        if (names.size() != owners.size()) {
            int32_t jsErrCode = GenerateBusinessErrorCode(JSErrorCode::ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return taihe::array<AppAccountInfo>(taihe::copy_data_t{}, accountInfos.data(), accountInfos.size());
        }
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

    AuthCallback GetAuthCallbackSync(string_view sessionId)
    {
        std::string innerSessionId(sessionId.data(), sessionId.size());
        sptr<IRemoteObject> remoteCallback;
        int errorCode = AccountSA::AppAccountManager::GetAuthenticatorCallback(
            innerSessionId, remoteCallback);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        sptr<AccountSA::IAppAccountAuthenticatorCallback> authenticatorCallback =
            iface_cast<OHOS::AccountSA::IAppAccountAuthenticatorCallback>(remoteCallback);
        ::taihe::callback<void(int32_t, optional_view<AuthResult>)> onResult =
            ::taihe::make_holder<OnResultCallbackImpl,
                ::taihe::callback<void(int32_t, optional_view<AuthResult>)>>(authenticatorCallback);
        ::taihe::callback<void(uintptr_t)> onRequestRedirected =
            ::taihe::make_holder<OnRequestRedirectedCallbackImpl,
                ::taihe::callback<void(uintptr_t)>>(authenticatorCallback);
        ::taihe::callback<void()> onRequestContinued =
            ::taihe::make_holder<OnRequestContinuedCallbackImpl,
                ::taihe::callback<void()>>(authenticatorCallback);
        AuthCallback authCallback{
            .onResult = onResult,
            .onRequestRedirected = onRequestRedirected,
            .onRequestContinued = optional<taihe::callback<void ()>>(std::in_place_t{}, onRequestContinued),
        };
        return authCallback;
    }

    void VerifyCredentialSync(string_view name, string_view owner, AuthCallback const& callback)
    {
        std::string innerName(name.data(), name.size());
        std::string innerOwner(owner.data(), owner.size());
        AccountSA::VerifyCredentialOptions options;
        sptr<THAppAccountManagerCallback> appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
        if (appAccountMgrCb == nullptr) {
            ACCOUNT_LOGE("Failed to create AppAccountManagerCallback for insufficient memory");
            int32_t jsErrCode = GenerateBusinessErrorCode(JSErrorCode::ERR_JS_SYSTEM_SERVICE_EXCEPTION);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        }
        ErrCode errorCode = AccountSA::AppAccountManager::VerifyCredential(
            innerName, innerOwner, options, appAccountMgrCb);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    void RetrieveStringFromAni(ani_env *env, ani_string str, std::string &res)
    {
        ani_size sz {};
        ani_status status = ANI_ERROR;
        if ((status = env->String_GetUTF8Size(str, &sz)) != ANI_OK) {
            ACCOUNT_LOGE("String_GetUTF8Size Fail! status: %{public}d", status);
            return;
        }
        res.resize(sz + 1);
        if ((status = env->String_GetUTF8SubString(str, 0, sz, res.data(), res.size(), &sz)) != ANI_OK) {
            ACCOUNT_LOGE("String_GetUTF8SubString Fail! status: %{public}d", status);
            return;
        }
        res.resize(sz);
    }

    bool ParseVerifyCredentialOptions(ani_env *env,
        uintptr_t options, AccountSA::VerifyCredentialOptions &innerOptions)
    {
        ani_object optionsObj = reinterpret_cast<ani_object>(options);
        ani_boolean isUndefined;
        ani_ref credentialRef;
        if (env->Object_GetPropertyByName_Ref(optionsObj, "credential", &credentialRef) != ANI_OK) {
            ACCOUNT_LOGE("Failed to get options's credential property");
            return false;
        }
        if (env->Reference_IsUndefined(credentialRef, &isUndefined) != ANI_OK) {
            ACCOUNT_LOGE("Failed to check undefined for credentialRef");
            return false;
        }
        if (!isUndefined) {
            std::string innerCredential;
            ani_string credentialRefString = static_cast<ani_string>(credentialRef);
            RetrieveStringFromAni(env, credentialRefString, innerCredential);
            innerOptions.credential = innerCredential;
        }
        ani_ref credentialTypeRef;
        if (env->Object_GetPropertyByName_Ref(optionsObj, "credentialType", &credentialTypeRef) != ANI_OK) {
            ACCOUNT_LOGE("Failed to get options's credentialType property");
            return false;
        }
        if (env->Reference_IsUndefined(credentialTypeRef, &isUndefined) != ANI_OK) {
            ACCOUNT_LOGE("Failed to check undefined for credentialTypeRef");
            return false;
        }
        if (!isUndefined) {
            std::string innerCredentialType;
            ani_string credentialTypeRefString = static_cast<ani_string>(credentialTypeRef);
            RetrieveStringFromAni(env, credentialTypeRefString, innerCredentialType);
            innerOptions.credentialType = innerCredentialType;
        }
        return ParseParameters(env, options, innerOptions);
    }

    bool ParseParameters(ani_env *env, uintptr_t options, AccountSA::VerifyCredentialOptions &innerOptions)
    {
        ani_object optionsObj = reinterpret_cast<ani_object>(options);
        ani_boolean isUndefined;
        ani_ref parametersRef;
        if (env->Object_GetPropertyByName_Ref(optionsObj, "parameters", &parametersRef) != ANI_OK) {
            ACCOUNT_LOGE("Failed to get options's parameters property");
            return false;
        }
        if (env->Reference_IsUndefined(parametersRef, &isUndefined) != ANI_OK) {
            ACCOUNT_LOGE("Failed to check undefined for parametersRef");
            return false;
        }
        if (!isUndefined) {
            auto status = AppExecFwk::UnwrapWantParams(env, parametersRef, innerOptions.parameters);
            if (status == false) {
                ACCOUNT_LOGE("Failed to UnwrapWantParams parameters status = %{public}d", status);
                return false;
            }
        }
        return true;
    }

    void VerifyCredentialWithOpt(string_view name, string_view owner, uintptr_t options, AuthCallback const& callback)
    {
        std::string innerName(name.data(), name.size());
        std::string innerOwner(owner.data(), owner.size());
        AccountSA::VerifyCredentialOptions innerOptions;
        ani_env *env = get_env();
        if (!ParseVerifyCredentialOptions(env, options, innerOptions)) {
            ACCOUNT_LOGE("Failed to parse verifyCredentialOptions");
            int32_t jsErrCode = GenerateBusinessErrorCode(JSErrorCode::ERR_JS_PARAMETER_ERROR);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        }
        sptr<THAppAccountManagerCallback> appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
        if (appAccountMgrCb == nullptr) {
            ACCOUNT_LOGE("Failed to create AppAccountManagerCallback for insufficient memory");
            int32_t jsErrCode = GenerateBusinessErrorCode(JSErrorCode::ERR_JS_SYSTEM_SERVICE_EXCEPTION);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        }
        ErrCode errorCode = AccountSA::AppAccountManager::VerifyCredential(
            innerName, innerOwner, innerOptions, appAccountMgrCb);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    void SetAuthenticatorPropertiesSync(string_view owner, AuthCallback const& callback)
    {
        std::string innerOwner(owner.data(), owner.size());
        AccountSA::SetPropertiesOptions options;
        sptr<THAppAccountManagerCallback> appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
        if (appAccountMgrCb == nullptr) {
            ACCOUNT_LOGE("Failed to create AppAccountManagerCallback for insufficient memory");
            int32_t jsErrCode = GenerateBusinessErrorCode(JSErrorCode::ERR_JS_SYSTEM_SERVICE_EXCEPTION);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        }
        ErrCode errCode = AccountSA::AppAccountManager::SetAuthenticatorProperties(
            innerOwner, options, appAccountMgrCb);
        if (errCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    bool ParseSetPropertiesOptions(ani_env *env, uintptr_t options, AccountSA::SetPropertiesOptions &innerOptions)
    {
        ani_object optionsObj = reinterpret_cast<ani_object>(options);
        ani_boolean isUndefined;
        ani_ref propertiesRef;
        if (env->Object_GetPropertyByName_Ref(optionsObj, "properties", &propertiesRef) != ANI_OK) {
            ACCOUNT_LOGE("Failed to get options's properties property");
            return false;
        }
        if (env->Reference_IsUndefined(propertiesRef, &isUndefined) != ANI_OK) {
            ACCOUNT_LOGE("Failed to check undefined for propertiesRef");
            return false;
        }
        if (!isUndefined) {
            auto status = AppExecFwk::UnwrapWantParams(env, propertiesRef, innerOptions.properties);
            if (status == false) {
                ACCOUNT_LOGE("Failed to UnwrapWantParams properties status = %{public}d", status);
                return false;
            }
        }
        ani_ref parametersRef;
        if (env->Object_GetPropertyByName_Ref(optionsObj, "parameters", &parametersRef) != ANI_OK) {
            ACCOUNT_LOGE("Failed to get options's parameters property");
            return false;
        }
        if (env->Reference_IsUndefined(parametersRef, &isUndefined) != ANI_OK) {
            ACCOUNT_LOGE("Failed to check undefined for parametersRef");
            return false;
        }
        if (!isUndefined) {
            auto status = AppExecFwk::UnwrapWantParams(env, parametersRef, innerOptions.parameters);
            if (status == false) {
                ACCOUNT_LOGE("Failed to UnwrapWantParams parameters status = %{public}d", status);
                return false;
            }
        }
        return true;
    }

    void SetAuthenticatorPropertiesWithOpt(string_view owner, uintptr_t options, AuthCallback const& callback)
    {
        std::string innerOwner(owner.data(), owner.size());
        AccountSA::SetPropertiesOptions innerOptions;
        ani_env *env = get_env();
        if (!ParseSetPropertiesOptions(env, options, innerOptions)) {
            ACCOUNT_LOGE("Failed to parse setPropertiesOptions");
            int32_t jsErrCode = GenerateBusinessErrorCode(JSErrorCode::ERR_JS_PARAMETER_ERROR);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        }
        sptr<THAppAccountManagerCallback> appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
        if (appAccountMgrCb == nullptr) {
            ACCOUNT_LOGE("Failed to create AppAccountManagerCallback for insufficient memory");
            int32_t jsErrCode = GenerateBusinessErrorCode(JSErrorCode::ERR_JS_SYSTEM_SERVICE_EXCEPTION);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        }
        ErrCode errCode = AccountSA::AppAccountManager::SetAuthenticatorProperties(
            innerOwner, innerOptions, appAccountMgrCb);
        if (errCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
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

    static bool CheckSpecialCharacters(const std::string &name)
    {
        for (const auto &specialCharacter : AccountSA::Constants::SPECIAL_CHARACTERS) {
            std::size_t index = name.find(specialCharacter);
            if (index != std::string::npos) {
                ACCOUNT_LOGE("found a special character, specialCharacter = %{public}c", specialCharacter);
                NativeErrMsg() = "Invalid name. The name cannot contain space characters";
                return false;
            }
        }
        return true;
    }

    void AuthSync(string_view name, string_view owner, string_view authType, AuthCallback const& callback)
    {
        std::string innerName(name.data(), name.size());
        if (!CheckSpecialCharacters(innerName)) {
            int32_t jsErrCode = GenerateBusinessErrorCode(ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        }
        std::string innerOwner(owner.data(), owner.size());
        std::string innerAuthType(authType.data(), authType.size());
        AAFwk::Want options;
        sptr<THAppAccountManagerCallback> appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
        if (appAccountMgrCb == nullptr) {
            ACCOUNT_LOGE("failed to create AppAccountManagerCallback for insufficient memory");
            return;
        }
        ErrCode errCode = AccountSA::AppAccountManager::Authenticate(
            innerName, innerOwner, innerAuthType, options, appAccountMgrCb);
        AAFwk::Want errResult;
        if (errCode != 0) {
            appAccountMgrCb->OnResult(errCode, errResult);
        }
    }

    void AuthWithMap(string_view name, string_view owner, string_view authType,
        uintptr_t options, AuthCallback const& callback)
    {
        std::string innerName(name.data(), name.size());
        if (!CheckSpecialCharacters(innerName)) {
            int32_t jsErrCode = GenerateBusinessErrorCode(ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        }
        std::string innerOwner(owner.data(), owner.size());
        std::string innerAuthType(authType.data(), authType.size());
        AAFwk::WantParams params;
        ani_env *env = get_env();
        ani_ref parametersRef = reinterpret_cast<ani_ref>(options);
        auto status = AppExecFwk::UnwrapWantParams(env, parametersRef, params);
        if (status == false) {
            ACCOUNT_LOGE("Failed to UnwrapWant options status = %{public}d", status);
            return;
        }
        AAFwk::Want innerOptions;
        innerOptions.SetParams(params);
        sptr<THAppAccountManagerCallback> appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
        if (appAccountMgrCb == nullptr) {
            ACCOUNT_LOGE("failed to create AppAccountManagerCallback for insufficient memory");
            return;
        }
        ErrCode errCode = AccountSA::AppAccountManager::Authenticate(innerName, innerOwner,
            innerAuthType, innerOptions, appAccountMgrCb);
        AAFwk::Want errResult;
        if (errCode != 0) {
            appAccountMgrCb->OnResult(errCode, errResult);
        }
    }

    static bool IsExitSubscribe(AccountSA::AsyncContextForSubscribe* context)
    {
        auto subscribe = AccountSA::g_ThAppAccountSubscribers.find(context->appAccountManager);
        if (subscribe == AccountSA::g_ThAppAccountSubscribers.end()) {
            return false;
        }

        for (size_t index = 0; index < subscribe->second.size(); index++) {
        if (subscribe->second[index]->callbackRef == context->callbackRef) {
            return true;
        }
    }

        return false;
    }

    bool CheckType(string_view type)
    {
        if (type.empty() || type != "accountChange") {
            ACCOUNT_LOGE("Subscriber type size %{public}zu is invalid.", type.size());
            std::string errMsg =
                "Parameter error. The content of \"type\" must be \"accountChange\"";
            taihe::set_business_error(ERR_JS_INVALID_PARAMETER, errMsg);
            return false;
        }
        return true;
    }

    void OnSync(string_view type, array_view<string> owners, callback_view<void(array_view<AppAccountInfo>)> callback)
    {
        if (!CheckType(type)) {
            return;
        }
        std::vector<std::string> innerOwners(owners.data(), owners.data() + owners.size());

        auto context = std::make_unique<AccountSA::AsyncContextForSubscribe>(callback);
        context->appAccountManager = GetInner();
        AccountSA::AppAccountSubscribeInfo subscribeInfo(innerOwners);
        context->subscriber = std::make_shared<AccountSA::SubscriberPtr>(subscribeInfo, callback);
        if (context->subscriber == nullptr) {
            ACCOUNT_LOGE("fail to create subscriber");
            return;
        }
        std::lock_guard<std::mutex> lock(AccountSA::g_thLockForAppAccountSubscribers);
        if (IsExitSubscribe(context.get())) {
            return;
        }
        ErrCode errorCode = AccountSA::AppAccountManager::SubscribeAppAccount(context->subscriber);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        }
        AccountSA::g_ThAppAccountSubscribers[context->appAccountManager].emplace_back(context.get());
        context.release();
    }

    bool GetSubscriberByUnsubscribe(std::vector<std::shared_ptr<AccountSA::SubscriberPtr>> &subscribers,
    AccountSA::AsyncContextForUnsubscribe *asyncContextForOff)
    {
        for (auto subscriberInstance : AccountSA::g_ThAppAccountSubscribers) {
            if (subscriberInstance.first == asyncContextForOff->appAccountManager) {
                for (auto item : subscriberInstance.second) {
                    subscribers.emplace_back(item->subscriber);
                }
                return true;
            }
        }
        return false;
    }

    void Unsubscribe(std::shared_ptr<AccountSA::AsyncContextForUnsubscribe> context,
        optional_view<callback<void(array_view<AppAccountInfo> data)>> callback)
    {
        std::lock_guard<std::mutex> lock(AccountSA::g_thLockForAppAccountSubscribers);
        auto subscribe = AccountSA::g_ThAppAccountSubscribers.find(context->appAccountManager);
        if (subscribe == AccountSA::g_ThAppAccountSubscribers.end()) {
            return;
        }
        std::vector<std::shared_ptr<AccountSA::SubscriberPtr>> subscribers = {nullptr};
        if (!GetSubscriberByUnsubscribe(subscribers, context.get())) {
            ACCOUNT_LOGE("Unsubscribe failed. The current subscriber does not exist");
            return;
        }
        if (callback == nullptr) {
            context->subscribers = subscribers;
            for (auto offSubscriber : context->subscribers) {
                int errCode = AccountSA::AppAccountManager::UnsubscribeAppAccount(offSubscriber);
                ACCOUNT_LOGD("Unsubscribe errcode parameter is %{public}d", errCode);
            }
            subscribe = AccountSA::g_ThAppAccountSubscribers.find(context->appAccountManager);
            if (subscribe != AccountSA::g_ThAppAccountSubscribers.end()) {
                for (auto offCBInfo : subscribe->second) {
                    delete offCBInfo;
                }
                AccountSA::g_ThAppAccountSubscribers.erase(subscribe);
            }
        } else {
            std::shared_ptr<subscribe_callback> currentCallback = nullptr;
            std::shared_ptr<subscribe_callback> needRemoveCallback = nullptr;
            subscribe_callback call = callback.value();
            needRemoveCallback = std::make_shared<subscribe_callback>(call);
            for (size_t index = 0; index < subscribe->second.size(); ++index) {
                subscribe_callback tempCall = subscribe->second[index]->subscriber->callback_;
                currentCallback = std::make_shared<subscribe_callback>(tempCall);
                if ((needRemoveCallback != nullptr) && (!(call == tempCall))) {
                    continue;
                }
                int errCode = AccountSA::AppAccountManager::UnsubscribeAppAccount(subscribe->second[index]->subscriber);
                if (errCode != ERR_OK) {
                    int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
                    taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
                    return;
                }
                delete subscribe->second[index];
                subscribe->second.erase(subscribe->second.begin() + index);
                break;
            }
            if ((needRemoveCallback.get() == nullptr) || (subscribe->second.empty())) {
                AccountSA::g_ThAppAccountSubscribers.erase(subscribe);
            }
        }
    }

    void OffSync(string_view type, optional_view<callback<void(array_view<AppAccountInfo> data)>> callback)
    {
        if (!CheckType(type)) {
            return;
        }
        std::shared_ptr<AccountSA::AsyncContextForUnsubscribe> context(
            new (std::nothrow) AccountSA::AsyncContextForUnsubscribe());
        if (context == nullptr) {
            ACCOUNT_LOGE("fail to create subscriber");
            return;
        }
        context->appAccountManager = GetInner();
        if (callback.has_value()) {
            Unsubscribe(context, callback);
        } else {
            Unsubscribe(context, nullptr);
        }
    }

private:
    uint64_t GetInner()
    {
        return reinterpret_cast<uint64_t>(this);
    }
};

class TaiheAppAccountAuthenticator : public AccountSA::AppAccountAuthenticatorStub {
public:
    TaiheAppAccountAuthenticator() = default;
    ~TaiheAppAccountAuthenticator() override = default;
    
    bool CheckObjectLegality() const override
    {
        return true;
    }
    
    int GetObjectType() const override
    {
        return OBJECT_TYPE_NATIVE;
    }
    
    ErrCode AddAccountImplicitly(const std::string& authType,
        const std::string& callerBundleName,
        const WantParams& options,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override
    {
        return ERR_OK;
    }
    
    ErrCode Authenticate(
        const AppAccountAuthenticatorStringInfo& appAccountAuthenticatorStringInfo,
        const WantParams& options,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override
    {
        return ERR_OK;
    }
    
    ErrCode CreateAccountImplicitly(
        const AccountSA::CreateAccountImplicitlyOptions& options,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override
    {
        return ERR_OK;
    }
    
    ErrCode Auth(
        const std::string& name,
        const std::string& authType,
        const WantParams& options,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override
    {
        return ERR_OK;
    }
    
    ErrCode VerifyCredential(
        const std::string& name,
        const AccountSA::VerifyCredentialOptions& options,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override
    {
        return ERR_OK;
    }
    
    ErrCode CheckAccountLabels(
        const std::string& name,
        const std::vector<std::string>& labels,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override
    {
        return ERR_OK;
    }
    
    ErrCode SetProperties(
        const AccountSA::SetPropertiesOptions& options,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override
    {
        return ERR_OK;
    }
    
    ErrCode IsAccountRemovable(
        const std::string& name,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override
    {
        return ERR_OK;
    }
};

class AuthenticatorImpl {
public:
    AuthenticatorImpl()
    {
        auto authenticator = new (std::nothrow) TaiheAppAccountAuthenticator();
        if (authenticator == nullptr) {
            remoteObject_ = 0;
            return;
        }
        
        ani_env* env = get_env();
        if (env == nullptr) {
            remoteObject_ = 0;
            return;
        }

        ani_ref aniRemoteObj = ANI_ohos_rpc_CreateJsRemoteObject(env, authenticator->AsObject());
        if (aniRemoteObj == nullptr) {
            remoteObject_ = 0;
            return;
        }
        remoteObject_ = reinterpret_cast<uintptr_t>(aniRemoteObj);
    }

    ~AuthenticatorImpl()
    {
        if (remoteObject_ != 0) {
            remoteObject_ = 0;
        }
    }

    uintptr_t GetRemoteObject()
    {
        if (remoteObject_ == 0) {
            ACCOUNT_LOGE("Remote object not initialized");
        }
        return remoteObject_;
    }

public:
    uintptr_t remoteObject_;
};

AppAccountManager createAppAccountManager()
{
    return make_holder<AppAccountManagerImpl, AppAccountManager>();
}
}  // namespace

TH_EXPORT_CPP_API_createAppAccountManager(createAppAccountManager);

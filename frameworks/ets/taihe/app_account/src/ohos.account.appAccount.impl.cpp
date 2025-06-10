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
#include "napi_account_error.h"
#include "ohos.account.appAccount.proj.hpp"
#include "ohos.account.appAccount.impl.hpp"
#include "ohos_account_kits.h"
#include "stdexcept"
#include "taihe/runtime.hpp"

using namespace taihe;
using namespace OHOS;
using namespace ohos::account::appAccount;

namespace {
using OHOS::AccountSA::ACCOUNT_LABEL;

AppAccountInfo ConvertAppAccountInfo(const AccountSA::AppAccountInfo innerInfo)
{
    return AppAccountInfo{
        .owner = taihe::string(const_cast<AccountSA::AppAccountInfo&>(innerInfo).GetOwner().c_str()),
        .name = taihe::string(const_cast<AccountSA::AppAccountInfo&>(innerInfo).GetName().c_str()),
    };
}

AppAccountInfo ConvertAccountInfo(const std::string name, const std::string owner)
{
    return AppAccountInfo{
        .owner = owner,
        .name = name,
    };
}

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
        std::vector<std::string> tempAllowedOwners(options.allowedOwners.value().data(), options.allowedOwners.value().data() 
            + options.allowedOwners.value().size());
        tempOptions.allowedOwners = tempAllowedOwners;
    }

    if(options.requiredLabels){
        std::vector<std::string> tempRequiredLabels(options.requiredLabels.value().data(), options.requiredLabels.value().data() 
            + options.requiredLabels.value().size());
        tempOptions.requiredLabels = tempRequiredLabels;
    }
    return tempOptions;
}

// class AppAccountManagerCallback : public AccountSA::AppAccountAuthenticatorCallbackStub {
//     public:
//         explicit AppAccountManagerCallback(ohos::account::appAccount::AuthCallback callback): callback_(callback){}
//         void OnResult(int32_t resultCode, const AAFwk::Want &result) override
//         {
//             {
//                 std::lock_guard<std::mutex> lock(mutex_);
//                 if (isDone) {
//                     return;
//                 }
//                 isDone = true;
//             }
//             cv.notify_one();
    
//             ACCOUNT_LOGI("Post task finish");
//         }
//         void OnRequestRedirected(AAFwk::Want &request) override
//         {}
//         void OnRequestContinued() override
//         {}
    
//         std::mutex mutex_;
//         bool isDone = false;
//         AuthCallback callback_;
//         std::condition_variable cv;
//     };

struct AuthenticatorCallbackParam 
{
    int32_t resultCode = -1;
    AAFwk::Want result;
};

class AuthenticatorAsyncCallback : public AccountSA::AppAccountAuthenticatorCallbackStub {
public:
    void OnResult(int32_t resultCode, const AAFwk::Want &result) override
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (isDone) {
                return;
            }
            isDone = true;
        }
        cv.notify_one();

        param = std::make_shared<AuthenticatorCallbackParam>();
        param->resultCode = resultCode;
        param->result = result;

    }
    void OnRequestRedirected(AAFwk::Want &request) override{};
    void OnRequestContinued() override{};
    std::shared_ptr<AuthenticatorCallbackParam> param;
    std::mutex mutex;
    bool isDone = false;
    std::condition_variable cv;
};

// class THAppAccountManagerCallback : public AccountSA::AppAccountAuthenticatorCallbackStub {
//     public:
//         explicit THAppAccountManagerCallback(const ohos::account::appAccount::AuthCallback &taiheCallback)
//             : taiheCallback_(taiheCallback) {}
//         // explicit AppAccountManagerCallback(ohos::account::appAccount::AuthCallback callback): callback_(callback){}

//         // ~THAppAccountManagerCallback() override = default;

//         // void OnResult(int32_t resultCode, const AAFwk::Want &result) override
//         void OnResult(int32_t resultCode, const AAFwk::Want &result) override
//         {
//             if (taiheCallback_.onResult.data_ptr != nullptr) {
//                 ani_env *env = get_env();
//                 auto resultParams =  AppExecFwk::WrapWantParams(env, result.GetParams());
//                 AuthResult* authResult = reinterpret_cast<AuthResult*>(resultParams);
//                 taiheCallback_.onResult(resultCode, optional<AuthResult>(std::in_place_t{}, *authResult));
//             }
//         }

//         // void OnRequestRedirected(AAFwk::Want &request) override
//         void OnRequestRedirected(AAFwk::Want &request) override
//         {
//             if (taiheCallback_.onRequestRedirected.data_ptr != nullptr) {
//                 ani_env *env = get_env();
//                 taiheCallback_.onRequestRedirected(reinterpret_cast<uintptr_t>(AppExecFwk::WrapWant(env, request)));
//             }
//         }

//         // void OnRequestContinued() override
//         void OnRequestContinued() override
//         {
//             if (taiheCallback_.onRequestContinued.has_value()) {
//                 taiheCallback_.onRequestContinued.value()();
//             }
//         }
//     private:
//         ohos::account::appAccount::AuthCallback taiheCallback_;
//     };

class AppAccountManagerImpl {
public:
    AppAccountManagerImpl() {}

    void CreateAccountSync(string_view name)
    {
        AccountSA::CreateAccountOptions options{};
        std::string innerName(name.data(), name.size());
        int errorCode = AccountSA::AppAccountManager::CreateAccount(innerName, options);
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
        int errorCode = AccountSA::AppAccountManager::CreateAccount(innerName, optionsInner);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }
    void RemoveAccountSync(string_view name)
    {
        std::string innerName(name.data(), name.size());
        int errorCode = AccountSA::AppAccountManager::DeleteAccount(innerName);
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
        int errorCode = AccountSA::AppAccountManager::CheckAppAccess(innerName, innerBundleName, isAccessible);
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
        int errorCode = AccountSA::AppAccountManager::CheckAppAccountSyncEnable(innerName, result);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        if (result != ERR_OK) {
            ACCOUNT_LOGE("CheckDataSyncEnabled failed with errCode: %{public}d", result);
        }
        return result;
    }

    void SetCredentialSync(string_view name, string_view credentialType, string_view credential)
    {
        std::string innerName(name.data(), name.size());
        std::string innerCredentialType(credentialType.data(), credentialType.size());
        std::string innerCredential(credential.data(), credential.size());
        int errorCode = AccountSA::AppAccountManager::SetAccountCredential(innerName,
            innerCredentialType, innerCredential);
        if (errorCode != ERR_OK) {
             int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
             taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    void SetDataSyncEnabledSync(string_view name, bool isEnabled)
    {
        std::string innerName(name.data(), name.size());
        int errorCode = AccountSA::AppAccountManager::SetAppAccountSyncEnable(innerName, isEnabled);
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
        int errorCode = AccountSA::AppAccountManager::SetAssociatedData(innerName, innerkey, innerValue);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    array<AppAccountInfo> GetAllAccountsSync()
    {
        std::string innerOwner = "";
        std::vector<AccountSA::AppAccountInfo> appAccounts;
        int errorCode = AccountSA::AppAccountManager::QueryAllAccessibleAccounts(innerOwner, appAccounts);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        std::vector<AppAccountInfo> appAccountsInfos;
        appAccountsInfos.reserve(appAccounts.size());
        for (const auto &info : appAccounts) {
            appAccountsInfos.push_back(ConvertAppAccountInfo(info));
        }
        return taihe::array<AppAccountInfo>(taihe::copy_data_t{}, appAccountsInfos.data(), appAccountsInfos.size());
    }

    array<AppAccountInfo> GetAccountsByOwnerSync(string_view owner)
    {
        std::string innerOwner(owner.data(), owner.size());
        std::vector<AccountSA::AppAccountInfo> appAccounts;
        int errorCode = AccountSA::AppAccountManager::QueryAllAccessibleAccounts(innerOwner, appAccounts);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        std::vector<AppAccountInfo> appAccountsInfos;
        appAccountsInfos.reserve(appAccounts.size());
        for (const auto &info : appAccounts) {
            appAccountsInfos.push_back(ConvertAppAccountInfo(info));
        }
        return taihe::array<AppAccountInfo>(taihe::copy_data_t{}, appAccountsInfos.data(), appAccountsInfos.size());
    }

    string GetCredentialSync(string_view name, string_view credentialType)
    {
        std::string innerName(name.data(), name.size());
        std::string innerCredentialType(credentialType.data(), credentialType.size());
        std::string credential = "";
        int errorCode = AccountSA::AppAccountManager::GetAccountCredential(innerName, innerCredentialType, credential);
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
        int errorCode = AccountSA::AppAccountManager::GetAssociatedData(innerName, innerKey, value);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        return taihe::string(value.c_str());
    }

    string GetCustomDataSyncSync(string_view name, string_view key)
    {
        std::string innerName(name.data(), name.size());
        std::string innerKey(key.data(), key.size());
        std::string value = "";
        int errorCode = AccountSA::AppAccountManager::GetAssociatedData(innerName, innerKey, value);
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
        int errorCode = AccountSA::AppAccountManager::GetOAuthToken(innerName, innerOwner, innerAuthType, token);
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
        int errorCode = AccountSA::AppAccountManager::SetOAuthToken(innerName, innerAuthType, innerToken);
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
        sptr<AuthenticatorAsyncCallback> callback = new (std::nothrow) AuthenticatorAsyncCallback();
        int errorCode = AccountSA::AppAccountManager::CheckAccountLabels(innerName, innerOwner, innerLabels, callback);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        std::unique_lock<std::mutex> lock(callback->mutex);
        callback->cv.wait(lock, [callback] { return callback->isDone; });
        return callback->isDone;
    }

    array<AppAccountInfo> SelectAccountsByOptionsSync(SelectAccountsOptions const& options)
    {
        AccountSA::SelectAccountsOptions innerOptions = ConvertAccountsOptionsInfo(options);
        sptr<AuthenticatorAsyncCallback> callback = new (std::nothrow) AuthenticatorAsyncCallback();
        int errorCode = AccountSA::AppAccountManager::SelectAccountsByOptions(innerOptions, callback);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        std::unique_lock<std::mutex> lock(callback->mutex);
        callback->cv.wait(lock, [callback] { return callback->isDone; });
        std::vector<AppAccountInfo> accountInfos;
        std::vector<std::string> names = callback->param->result.GetStringArrayParam(AccountSA::Constants::KEY_ACCOUNT_NAMES);
        std::vector<std::string> owners = callback->param->result.GetStringArrayParam(AccountSA::Constants::KEY_ACCOUNT_OWNERS);
        for (size_t i = 0; i < names.size(); ++i) {
            accountInfos.push_back(ConvertAccountInfo(names[i], owners[i]));
        }
        return taihe::array<AppAccountInfo>(taihe::copy_data_t{}, accountInfos.data(), accountInfos.size());
    }

    void DeleteAuthTokenSync(string_view name, string_view owner, string_view authType, string_view token)
    {
        std::string innerName(name.data(), name.size());
        std::string innerOwner(owner.data(), owner.size());
        std::string innerAuthType(authType.data(), authType.size());
        std::string innerToken(token.data(), token.size());
        int errorCode = AccountSA::AppAccountManager::DeleteAuthToken(innerName, innerOwner, innerAuthType, innerToken);
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
        int errorCode = AccountSA::AppAccountManager::SetAuthTokenVisibility(innerName, innerAuthType,
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
        bool isVisible;
        int errorCode = AccountSA::AppAccountManager::CheckAuthTokenVisibility(innerName, innerAuthType,
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

        int errorCode = AccountSA::AppAccountManager::GetAllOAuthTokens(innerName,
            innerOwner, innerAuthTokenInfos);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        AppAccountInfo appAccountInfo = {owner, name};
        std::vector<AuthTokenInfo> authTokenInfosArray;
        authTokenInfosArray.reserve(innerAuthTokenInfos.size());
        AuthTokenInfo authTokenInfo = {};
        for (const auto& info : innerAuthTokenInfos) {
            authTokenInfo = AuthTokenInfo{
                .authType = info.authType,
                .token = info.token,
                .account = optional<AppAccountInfo>(std::in_place_t{}, appAccountInfo),
            };
            authTokenInfosArray.push_back(authTokenInfo);
        }
        return array<AuthTokenInfo>(taihe::copy_data_t{}, authTokenInfosArray.data(), authTokenInfosArray.size());
    }
    
    array<string> GetAuthListSync(string_view name, string_view authType)
    {
        std::string innerName(name.data(), name.size());
        std::string innerAuthType(authType.data(), authType.size());
        std::set<std::string> innerAuthList;
        int errorCode = AccountSA::AppAccountManager::GetAuthList(innerName,
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

    // AuthCallback GetAuthCallbackSync(string_view sessionId) {
    //     AuthCallback authCallback = {};
    //     std::string innerSessionId(sessionId.data(), sessionId.size());
    //     sptr<IRemoteObject> authenticatorCb = nullptr;
    //     int errorCode = AccountSA::AppAccountManager::GetAuthenticatorCallback(
    //         innerSessionId, authenticatorCb);
    //         reinterpret_cast<int64_t>(authenticatorCb.GetRefPtr());
    //     if (errorCode != ERR_OK) {
    //         int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
    //         taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
    //     }
    //     return authCallback;
    // }
    void VerifyCredentialSync(string_view name, string_view owner, AuthCallback const& callback)
    {
        std::string innerName(name.data(), name.size());
        std::string innerOwner(owner.data(), owner.size());
        AccountSA::VerifyCredentialOptions options;
        // std::shared_ptr<AccountSA::AppAccountAuthenticatorCallbackStub> authCallback = std::make_shared<THAppAccountManagerCallback>(callback);
        // auto appAccountMgrCb = new THAppAccountManagerCallback(callback);
        // ErrCode errorCode = AccountSA::AppAccountManager::VerifyCredential(
        //     innerName, innerOwner, options, appAccountMgrCb);
        // if (errorCode != ERR_OK) {
        //     int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
        //     taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        // }
    }
    void VerifyCredentialWithOpt(string_view name, string_view owner, VerifyCredentialOptions const& options, ::ohos::account::appAccount::AuthCallback const& callback) {
        TH_THROW(std::runtime_error, "VerifyCredentialWithOpt not implemented");
    }

    AuthenticatorInfo QueryAuthenticatorInfoSync(string_view owner)
    {
        std::string innerOwner(owner.data(), owner.size());
        AccountSA::AuthenticatorInfo innerAuthenticatorInfo;

        int errorCode = AccountSA::AppAccountManager::GetAuthenticatorInfo(innerOwner,
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
        int errorCode = AccountSA::AppAccountManager::DeleteAccountCredential(innerName,
            innerCredentialType);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
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

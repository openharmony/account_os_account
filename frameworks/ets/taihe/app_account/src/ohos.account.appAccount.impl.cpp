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

class THAppAccountManagerCallback : public AccountSA::AppAccountAuthenticatorCallbackStub {
public:
    explicit THAppAccountManagerCallback(const ohos::account::appAccount::AuthCallback &taiheCallback)
        : taiheCallback_(taiheCallback) {}

    ~THAppAccountManagerCallback() override = default;
    ErrCode OnResult(int32_t resultCode, const AAFwk::Want &result) override
    {
        AppAccountInfo appAccountInfo = AppAccountInfo {
            .owner = result.GetStringArrayParam(AccountSA::Constants::KEY_ACCOUNT_OWNERS)[0],
            .name = result.GetStringArrayParam(AccountSA::Constants::KEY_ACCOUNT_NAMES)[0],
        };
        AuthTokenInfo authTokenInfo = AuthTokenInfo {
            .authType = result.GetStringArrayParam(AccountSA::Constants::KEY_AUTH_TYPE)[0],
            .token = result.GetStringArrayParam(AccountSA::Constants::KEY_TOKEN)[0]
        };
        AuthResult authResult = AuthResult {
            .account = optional<AppAccountInfo>(std::in_place_t{}, appAccountInfo),
            .tokenInfo = optional<AuthTokenInfo>(std::in_place_t{}, authTokenInfo),
        };
        taiheCallback_.onResult(resultCode, optional<AuthResult>(std::in_place_t{}, authResult));
        return true;
    }
    ErrCode OnRequestRedirected(const AAFwk::Want &request) override
    {
        ani_env *env = get_env();
        auto requestObj = AppExecFwk::WrapWant(env, request);
        auto requestPtr = reinterpret_cast<uintptr_t>(requestObj);
        taiheCallback_.onRequestRedirected(requestPtr);
        return true;
    }

    ErrCode OnRequestContinued() override
    {
        taiheCallback_.onRequestContinued.value()();
        return true;
    }
private:
    ohos::account::appAccount::AuthCallback taiheCallback_;
};

class OnResultCallbackImpl {
public:
    explicit OnResultCallbackImpl(sptr<AccountSA::IAppAccountAuthenticatorCallback> callback) 
        : callback_(callback) {}

    void operator()(int32_t result, const optional_view<AuthResult> authResult) {
        if (callback_ == nullptr) {
            ACCOUNT_LOGE("Native callback is nullptr");
            return;
        }
        AAFwk::Want wantResult;
        callback_->OnResult(result, wantResult);
    }

private:
    sptr<AccountSA::IAppAccountAuthenticatorCallback> callback_;
};

class OnRequestRedirectedCallbackImpl {
public:
    explicit OnRequestRedirectedCallbackImpl(sptr<AccountSA::IAppAccountAuthenticatorCallback> callback) 
        : callback_(callback) {}

    void operator()(uintptr_t request) {
        if (callback_ == nullptr) {
            ACCOUNT_LOGE("Native callback is nullptr");
            return;
        }
        AAFwk::Want wantResult;
        callback_->OnRequestRedirected(wantResult);
    }

private:
    sptr<AccountSA::IAppAccountAuthenticatorCallback> callback_;
};

class OnRequestContinuedCallbackImpl {
public:
    explicit OnRequestContinuedCallbackImpl(sptr<AccountSA::IAppAccountAuthenticatorCallback> callback) 
        : callback_(callback) {}

    void operator()() {
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

    void CreateAccountImplicitly(string_view owner, AuthCallback const& callback)
    {
        std::string innerOwner(owner.data(), owner.size());
        AccountSA::CreateAccountImplicitlyOptions options;
        auto appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
        if (appAccountMgrCb == nullptr) {
            ACCOUNT_LOGE("failed to create AppAccountManagerCallback for insufficient memory");
            AAFwk::Want result;
            appAccountMgrCb->OnResult(JSErrorCode::ERR_JS_SYSTEM_SERVICE_EXCEPTION, result);
        }
        ErrCode errCode = AccountSA::AppAccountManager::CreateAccountImplicitly(innerOwner, options, appAccountMgrCb);
        AAFwk::Want errResult;
        if ((errCode != 0) && (appAccountMgrCb != nullptr)) {
            appAccountMgrCb->OnResult(errCode, errResult);
        }
        if (errCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        if (appAccountMgrCb != nullptr) {
            delete appAccountMgrCb;
        }
    }

    void CreateAccountImplicitlyWithOpt(string_view owner, ohos::account::appAccount::CreateAccountImplicitlyOptions const& options,
        AuthCallback const& callback)
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
        auto appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
        if (appAccountMgrCb == nullptr) {
            ACCOUNT_LOGE("failed to create AppAccountManagerCallback for insufficient memory");
            AAFwk::Want result;
            appAccountMgrCb->OnResult(JSErrorCode::ERR_JS_SYSTEM_SERVICE_EXCEPTION, result);
        }

        ErrCode errCode = AccountSA::AppAccountManager::CreateAccountImplicitly(innerOwner,
            inneroptions, appAccountMgrCb);
        AAFwk::Want errResult;
        if ((errCode != 0) && (appAccountMgrCb != nullptr)) {
            appAccountMgrCb->OnResult(errCode, errResult);
        }
        if (errCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        if (appAccountMgrCb != nullptr) {
            delete appAccountMgrCb;
        }
    }

    void AuthSync(string_view name, string_view owner, string_view authType, AuthCallback const& callback)
    {
        std::string innerName(name.data(), name.size());
        std::string innerOwner(owner.data(), owner.size());
        std::string innerAuthType(authType.data(), authType.size());
        AAFwk::Want options;
        auto appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
        if (appAccountMgrCb == nullptr) {
            ACCOUNT_LOGE("failed to create AppAccountManagerCallback for insufficient memory");
            AAFwk::Want result;
            appAccountMgrCb->OnResult(JSErrorCode::ERR_JS_SYSTEM_SERVICE_EXCEPTION, result);
        }
        ErrCode errCode = AccountSA::AppAccountManager::Authenticate(
            innerName, innerOwner, innerAuthType, options, appAccountMgrCb);
        AAFwk::Want errResult;
        if ((errCode != 0) && (appAccountMgrCb != nullptr)) {
            appAccountMgrCb->OnResult(errCode, errResult);
        }
        if (errCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        if (appAccountMgrCb != nullptr) {
            delete appAccountMgrCb;
        }
    }

    void AuthWithMap(string_view name, string_view owner, string_view authType,
        map_view<string, uintptr_t> options, AuthCallback const& callback)
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
        auto appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
        if (appAccountMgrCb == nullptr) {
            ACCOUNT_LOGE("failed to create AppAccountManagerCallback for insufficient memory");
            AAFwk::Want result;
            appAccountMgrCb->OnResult(JSErrorCode::ERR_JS_SYSTEM_SERVICE_EXCEPTION, result);
        }
        ErrCode errCode = AccountSA::AppAccountManager::Authenticate(innerName, innerOwner,
            innerAuthType, innerOptions, appAccountMgrCb);
        AAFwk::Want errResult;
        if ((errCode != 0) && (appAccountMgrCb != nullptr)) {
            appAccountMgrCb->OnResult(errCode, errResult);
        }
        if (errCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        if (appAccountMgrCb != nullptr) {
            delete appAccountMgrCb;
        }
    }

    static bool IsExitSubscribe(AccountSA::AsyncContextForSubscribe* context)
    {
        auto subscribe = AccountSA::g_ThAppAccountSubscribers.find(context->appAccountManager);
        if (subscribe == AccountSA::g_ThAppAccountSubscribers.end()) {
            return false;
        }

        for (const auto& existingContext : subscribe->second) {
            if (context->subscriber && existingContext->subscriber &&
                context->subscriber.get() == existingContext->subscriber.get()) {
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

        auto context = std::make_unique<AccountSA::AsyncContextForSubscribe>();
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
                break;
            }
        }
        return false;
    }

    void OffAllSync(string_view type)
    {
        if (!CheckType(type)) {
            return;
        }

        AccountSA::AsyncContextForUnsubscribe *context = new (std::nothrow) AccountSA::AsyncContextForUnsubscribe();
        if (context == nullptr) {
            ACCOUNT_LOGE("fail to create subscriber");
            return;
        }
        context->appAccountManager = GetInner();
        std::lock_guard<std::mutex> lock(AccountSA::g_thLockForAppAccountSubscribers);
        auto subscribe = AccountSA::g_ThAppAccountSubscribers.find(context->appAccountManager);
        if (subscribe == AccountSA::g_ThAppAccountSubscribers.end()) {
            delete context;
            return;
        }

        std::vector<std::shared_ptr<AccountSA::SubscriberPtr>> subscribers = {nullptr};
        if (!GetSubscriberByUnsubscribe(subscribers, context)) {
            ACCOUNT_LOGE("Unsubscribe failed. The current subscriber does not exist");
            delete context;
            return;
        }

        context->subscribers = subscribers;

        for (auto offSubscriber : context->subscribers) {
            int errCode = AccountSA::AppAccountManager::UnsubscribeAppAccount(offSubscriber);
            if (errCode != ERR_OK) {
                int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
                taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
                delete context;
                return;
            }
        }

        subscribe = AccountSA::g_ThAppAccountSubscribers.find(context->appAccountManager);
        if (subscribe != AccountSA::g_ThAppAccountSubscribers.end()) {
            for (auto offCBInfo : subscribe->second) {
                delete offCBInfo;
            }
            AccountSA::g_ThAppAccountSubscribers.erase(subscribe);
        }
        delete context;
    }

    void OffSyncTaihe(string_view type, callback_view<void(array_view<AppAccountInfo>)> callback)
    {
        if (!CheckType(type)) {
            return;
        }
        AccountSA::AsyncContextForUnsubscribe *context = new (std::nothrow) AccountSA::AsyncContextForUnsubscribe();
        if (context == nullptr) {
            ACCOUNT_LOGE("fail to create subscriber");
            return;
        }
        context->appAccountManager = GetInner();
        std::lock_guard<std::mutex> lock(AccountSA::g_thLockForAppAccountSubscribers);
        auto subscribe = AccountSA::g_ThAppAccountSubscribers.find(context->appAccountManager);
        if (subscribe == AccountSA::g_ThAppAccountSubscribers.end()) {
            delete context;
            return;
        }
        std::vector<std::shared_ptr<AccountSA::SubscriberPtr>> subscribers = {nullptr};
        if (!GetSubscriberByUnsubscribe(subscribers, context)) {
            ACCOUNT_LOGE("Unsubscribe failed. The current subscriber does not exist");
            delete context;
            return;
        }
        std::shared_ptr<active_callback> currentCallback = nullptr;
        std::shared_ptr<active_callback> needRemoveCallback = nullptr;
        active_callback call = callback;
        needRemoveCallback = std::make_shared<active_callback>(call);
        for (size_t index = 0; index < subscribe->second.size(); ++index) {
            active_callback tempCall = subscribe->second[index]->subscriber->callback_;
            currentCallback = std::make_shared<active_callback>(tempCall);
            if ((needRemoveCallback != nullptr) && (currentCallback.get() != needRemoveCallback.get())) {
                continue;
            }
            int errCode = AccountSA::AppAccountManager::UnsubscribeAppAccount(subscribe->second[index]->subscriber);
            if (errCode != ERR_OK) {
                int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
                taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
                delete context;
                return;
            }
            delete subscribe->second[index];
            if (needRemoveCallback.get() != nullptr) {
                subscribe->second.erase(subscribe->second.begin() + index);
                break;
            }
        }
        if ((needRemoveCallback.get() == nullptr) || (subscribe->second.empty())) {
            AccountSA::g_ThAppAccountSubscribers.erase(subscribe);
        }
        delete context;
    }

    AuthCallback GetAuthCallbackSync(string_view sessionId) {
        std::string innerSessionId(sessionId.data(), sessionId.size());
        sptr<IRemoteObject> remoteCallback;
        int errorCode = AccountSA::AppAccountManager::GetAuthenticatorCallback(
            innerSessionId, remoteCallback);
        sptr<AccountSA::IAppAccountAuthenticatorCallback> authenticatorCallback =
            iface_cast<OHOS::AccountSA::IAppAccountAuthenticatorCallback>(remoteCallback);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }

        ::taihe::callback<void(int32_t, optional_view<AuthResult>)> onResult =
            ::taihe::make_holder<OnResultCallbackImpl, ::taihe::callback<void(int32_t, optional_view<AuthResult>)>>(authenticatorCallback);

        ::taihe::callback<void(uintptr_t)> onRequestRedirected =
            ::taihe::make_holder<OnRequestRedirectedCallbackImpl, ::taihe::callback<void(uintptr_t)>>(authenticatorCallback);
        
        ::taihe::callback<void()> onRequestContinued =
            ::taihe::make_holder<OnRequestContinuedCallbackImpl, ::taihe::callback<void()>>(authenticatorCallback);

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
        auto appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
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

    bool ParseVerifyCredentialOptions(ani_env *env, uintptr_t options, AccountSA::VerifyCredentialOptions &innerOptions)
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

    void VerifyCredentialWithOpt(string_view name, string_view owner, uintptr_t options, AuthCallback const& callback) {
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
        auto appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
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
    
    void SetAuthenticatorPropertiesSync(string_view owner, AuthCallback const& callback) {
        std::string innerOwner(owner.data(), owner.size());
        AccountSA::SetPropertiesOptions options;
        auto appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
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

    void SetAuthenticatorPropertiesWithOpt(string_view owner, uintptr_t options, AuthCallback const& callback) {
        std::string innerOwner(owner.data(), owner.size());
        AccountSA::SetPropertiesOptions innerOptions;
        ani_env *env = get_env();
        if (!ParseSetPropertiesOptions(env, options, innerOptions)) {
            ACCOUNT_LOGE("Failed to parse setPropertiesOptions");
            int32_t jsErrCode = GenerateBusinessErrorCode(JSErrorCode::ERR_JS_PARAMETER_ERROR);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        }
        auto appAccountMgrCb = new (std::nothrow) THAppAccountManagerCallback(callback);
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
    
    bool CheckObjectLegality() const override {
        return true;
    }
    
    int GetObjectType() const override {
        return OBJECT_TYPE_NATIVE;
    }
    
    ErrCode AddAccountImplicitly(const std::string& authType,
        const std::string& callerBundleName,
        const WantParams& options,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override {
        return ERR_OK;
    }
    
    ErrCode Authenticate(
        const AppAccountAuthenticatorStringInfo& appAccountAuthenticatorStringInfo,
        const WantParams& options,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override {
        return ERR_OK;
    }
    
    ErrCode CreateAccountImplicitly(
        const AccountSA::CreateAccountImplicitlyOptions& options,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override {
        return ERR_OK;
    }
    
    ErrCode Auth(
        const std::string& name,
        const std::string& authType,
        const WantParams& options,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override {
        return ERR_OK;
    }
    
    ErrCode VerifyCredential(
        const std::string& name,
        const AccountSA::VerifyCredentialOptions& options,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override {
        return ERR_OK;
    }
    
    ErrCode CheckAccountLabels(
        const std::string& name,
        const std::vector<std::string>& labels,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override {
        return ERR_OK;
    }
    
    ErrCode SetProperties(
        const AccountSA::SetPropertiesOptions& options,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override {
        return ERR_OK;
    }
    
    ErrCode IsAccountRemovable(
        const std::string& name,
        const sptr<IRemoteObject>& remoteObjCallback,
        int32_t& funcResult) override {
        return ERR_OK;
    }
};

class AuthenticatorImpl {
public:
    AuthenticatorImpl() {
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

    ~AuthenticatorImpl() {
        if (remoteObject_ != 0) {
            remoteObject_ = 0;
        }
    }

    uintptr_t GetRemoteObject() {
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

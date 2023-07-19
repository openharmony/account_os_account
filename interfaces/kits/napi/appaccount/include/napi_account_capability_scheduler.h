/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_ACCOUNT_CAPABILITY_SCHEDULER_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_ACCOUNT_CAPABILITY_SCHEDULER_H

#include <cstring>
#include <mutex>
#include <string>
#include <uv.h>

#include "ability_context.h"
#include "ability.h"
#include "account_error_no.h"
#include "app_account_authorization_extension_callback_stub.h"
#include "app_account_common.h"
#include "iremote_object.h"
#include "napi/native_api.h"
#include "napi_account_common.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;

struct AuthorizationProviderInfo {
    std::string bundleName;
    std::string abilityName;
};

struct ExecuteRequestAsyncContext : public CommonAsyncContext {
    explicit ExecuteRequestAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    ~ExecuteRequestAsyncContext();
    AccountCapabilityRequest accountRequest;
    AsyncCallbackError businessError;
    AAFwk::WantParams parameters;
    napi_ref requestRef = nullptr;
    napi_value thisVar = nullptr;
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext = nullptr;
};

class NapiAccountCapabilityProvider {
public:
    NapiAccountCapabilityProvider(napi_env env, AccountCapabilityType type);
public:
    napi_env env_;
    AccountCapabilityType type_ = CAPABILITY_TYPE_END;
};

class NapiAccountCapabilityRequest {
public:
    NapiAccountCapabilityRequest(napi_env env);
    ~NapiAccountCapabilityRequest();
public:
    NapiAccountCapabilityProvider *baseProvider_ = nullptr;
    napi_env env_;
    int32_t requestType_ = -1;
    napi_ref providerRef_ = nullptr;
};

class NapiAccountCapabilityResponse {
public:
    NapiAccountCapabilityResponse(napi_env env);
    ~NapiAccountCapabilityResponse();
public:
    NapiAccountCapabilityRequest *request_ = nullptr;
    napi_env env_;
    napi_ref requestRef_ = nullptr;
};

class NapiAuthorizationProvider : public NapiAccountCapabilityProvider {
public:
    NapiAuthorizationProvider(napi_env env, const AuthorizationProviderInfo &providerInfo);
public:
    AuthorizationProviderInfo providerInfo_;
};

class NapiAppAccountCapability {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value ProviderConstructor(napi_env env, napi_callback_info info);
    static napi_value RequestConstructor(napi_env env, napi_callback_info info);
    static napi_value ResponseConstructor(napi_env env, napi_callback_info info);
    static napi_value AuthorizationProviderConstructor(napi_env env, napi_callback_info info);
    static void DefineNapiProviderBaseClass(napi_env env, napi_value exports);
    static void DefineNapiRequestBaseClass(napi_env env, napi_value exports);
    static void DefineNapiResponseBaseClass(napi_env env, napi_value exports);
    static void DefineNapiAuthorizationProviderClass(napi_env env, napi_value exports);
};

class NapiAccountCapabilityScheduler {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value JsConstructor(napi_env env, napi_callback_info cbInfo);
    static napi_value ExecuteRequest(napi_env env, napi_callback_info cbInfo);
    static napi_value SetPresentationContext(napi_env env, napi_callback_info cbInfo);
};

class AccountCapabilityScheduler {
public:
    AccountCapabilityScheduler(napi_env env);

public:
    napi_env env_;
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext_ = nullptr;
};

struct JsAbilityResult : public CommonAsyncContext {
    JsAbilityResult(){};
    JsAbilityResult(napi_env napiEnv);
    int resultCode = -1;
    AAFwk::Want want;
    bool isInner = false;
};

class NapiExecuteRequestCallback : public AppAccountAuthorizationExtensionCallbackStub {
public:
    NapiExecuteRequestCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred, napi_ref requestRef,
        std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext);
    ~NapiExecuteRequestCallback();
    void OnResult(const AsyncCallbackError &businessError, const AAFwk::WantParams &parameters) override;
    void OnRequestRedirected(const AAFwk::Want &request) override;

private:
    Ability *GetJsAbility(napi_env env);

private:
    AccountJsKit::ThreadLockInfo lockInfo_;
    napi_env env_;
    napi_ref callbackRef_ = nullptr;
    napi_deferred deferred_ = nullptr;
    napi_ref requestRef_ = nullptr;
    napi_value jsScheduler_;
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext_;
};
}  // namespace AccountJsKit
}  // namespace OHOS

#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_ACCOUNT_CAPABILITY_SCHEDULER_H
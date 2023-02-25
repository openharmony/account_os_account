/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "napi_app_account_authenticator.h"

#include <uv.h>

#include "account_log_wrapper.h"
#include "app_account_constants.h"
#include "iapp_account_authenticator_callback.h"
#include "ipc_object_stub.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_account_common.h"
#include "napi_app_account_authenticator_callback.h"
#include "napi_app_account_common.h"
#include "napi_common.h"
#include "napi_remote_object.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;

NapiAppAccountAuthenticator::NapiAppAccountAuthenticator(napi_env env, JsAuthenticator &jsAuthenticator)
    : env_(env), jsAuthenticator_(jsAuthenticator)
{}

NapiAppAccountAuthenticator::~NapiAppAccountAuthenticator()
{
    if (jsAuthenticator_.addAccountImplicitly != nullptr) {
        napi_delete_reference(env_, jsAuthenticator_.addAccountImplicitly);
    }
    if (jsAuthenticator_.authenticate != nullptr) {
        napi_delete_reference(env_, jsAuthenticator_.authenticate);
    }
    if (jsAuthenticator_.verifyCredential != nullptr) {
        napi_delete_reference(env_, jsAuthenticator_.verifyCredential);
    }
    if (jsAuthenticator_.checkAccountLabels != nullptr) {
        napi_delete_reference(env_, jsAuthenticator_.checkAccountLabels);
    }
    if (jsAuthenticator_.setProperties != nullptr) {
        napi_delete_reference(env_, jsAuthenticator_.setProperties);
    }
    if (jsAuthenticator_.isAccountRemovable != nullptr) {
        napi_delete_reference(env_, jsAuthenticator_.isAccountRemovable);
    }
}

bool NapiAppAccountAuthenticator::CheckObjectLegality() const
{
    return true;
}

int NapiAppAccountAuthenticator::GetObjectType() const
{
    return OBJECT_TYPE_JAVASCRIPT;
}

ErrCode NapiAppAccountAuthenticator::InitWorkEnv(uv_loop_s **loop, uv_work_t **work, JsAuthenticatorParam **param)
{
    napi_get_uv_event_loop(env_, loop);
    if (*loop == nullptr) {
        ACCOUNT_LOGE("failed to get uv event loop");
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    *work = new (std::nothrow) uv_work_t;
    if (*work == nullptr) {
        ACCOUNT_LOGE("failed to allocate memory");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    *param = new (std::nothrow) JsAuthenticatorParam();
    if (*param == nullptr) {
        ACCOUNT_LOGE("failed to allocate memory");
        delete *work;
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    (*param)->env = env_;
    (*param)->jsAuthenticator = jsAuthenticator_;
    return ERR_OK;
}

ErrCode NapiAppAccountAuthenticator::AddAccountImplicitly(
    const std::string &authType, const std::string &callerBundleName,
    const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback)
{
    if (jsAuthenticator_.addAccountImplicitly == nullptr) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsAuthenticatorParam *param = nullptr;
    ErrCode result = InitWorkEnv(&loop, &work, &param);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to InitWorkEnv");
        return result;
    }
    param->authType = authType;
    param->callerBundleName = callerBundleName;
    param->options = options;
    param->callback = callback;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, AddAccountImplicitlyWork);
    return ERR_OK;
}

ErrCode NapiAppAccountAuthenticator::Authenticate(const std::string &name, const std::string &authType,
    const std::string &callerBundleName, const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback)
{
    if (jsAuthenticator_.authenticate == nullptr) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsAuthenticatorParam *param = nullptr;
    ErrCode result = InitWorkEnv(&loop, &work, &param);
    if (result != ERR_OK) {
        return result;
    }
    param->authType = authType;
    param->name = name;
    param->callerBundleName = callerBundleName;
    param->options = options;
    param->callback = callback;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, AuthenticateWork);
    return ERR_OK;
}
ErrCode NapiAppAccountAuthenticator::CreateAccountImplicitly(
    const CreateAccountImplicitlyOptions &options, const sptr<IRemoteObject> &callback)
{
    if (jsAuthenticator_.createAccountImplicitly == nullptr) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsAuthenticatorParam *param = nullptr;
    ErrCode result = InitWorkEnv(&loop, &work, &param);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to InitWorkEnv");
        return result;
    }
    param->createOptions = options;
    param->callback = callback;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, CreateAccountImplicitlyWork);
    return ERR_OK;
}

ErrCode NapiAppAccountAuthenticator::Auth(const std::string &name, const std::string &authType,
    const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback)
{
    if (jsAuthenticator_.auth == nullptr) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsAuthenticatorParam *param = nullptr;
    ErrCode result = InitWorkEnv(&loop, &work, &param);
    if (result != ERR_OK) {
        return result;
    }
    param->authType = authType;
    param->name = name;
    param->options = options;
    param->callback = callback;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, AuthWork);
    return ERR_OK;
}

ErrCode NapiAppAccountAuthenticator::VerifyCredential(
    const std::string &name, const VerifyCredentialOptions &options, const sptr<IRemoteObject> &callback)
{
    if (jsAuthenticator_.verifyCredential == nullptr) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsAuthenticatorParam *param = nullptr;
    ErrCode result = InitWorkEnv(&loop, &work, &param);
    if (result != ERR_OK) {
        return result;
    }
    param->verifyCredOptions = options;
    param->name = name;
    param->callback = callback;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, VerifyCredentialWork);
    return ERR_OK;
}

ErrCode NapiAppAccountAuthenticator::SetProperties(
    const SetPropertiesOptions &options, const sptr<IRemoteObject> &callback)
{
    if (jsAuthenticator_.setProperties == nullptr) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsAuthenticatorParam *param = nullptr;
    ErrCode result = InitWorkEnv(&loop, &work, &param);
    if (result != ERR_OK) {
        return result;
    }
    param->setPropOptions = options;
    param->callback = callback;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, SetPropertiesWork);
    return ERR_OK;
}

ErrCode NapiAppAccountAuthenticator::CheckAccountLabels(
    const std::string &name, const std::vector<std::string> &labels, const sptr<IRemoteObject> &callback)
{
    if (jsAuthenticator_.checkAccountLabels == nullptr) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsAuthenticatorParam *param = nullptr;
    ErrCode result = InitWorkEnv(&loop, &work, &param);
    if (result != ERR_OK) {
        return result;
    }
    param->labels = labels;
    param->name = name;
    param->callback = callback;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, CheckAccountLabelsWork);
    return ERR_OK;
}

ErrCode NapiAppAccountAuthenticator::IsAccountRemovable(const std::string &name, const sptr<IRemoteObject> &callback)
{
    if (jsAuthenticator_.isAccountRemovable == nullptr) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsAuthenticatorParam *param = nullptr;
    ErrCode result = InitWorkEnv(&loop, &work, &param);
    if (result != ERR_OK) {
        return result;
    }
    param->name = name;
    param->callback = callback;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, IsAccountRemovableWork);
    return ERR_OK;
}

napi_value NapiAppAccountAuthenticator::CreateAuthenticatorCallback(
    napi_env env, sptr<IRemoteObject> nativeCallback)
{
    napi_value global = nullptr;
    napi_get_global(env, &global);
    if (global == nullptr) {
        ACCOUNT_LOGE("failed to get napi global");
        return nullptr;
    }
    napi_value jsAuthCallbackConstructor = nullptr;
    napi_get_named_property(env, global, "AuthCallbackConstructor_", &jsAuthCallbackConstructor);
    if (jsAuthCallbackConstructor == nullptr) {
        ACCOUNT_LOGE("jsAuthCallbackConstructor is null");
        return nullptr;
    }
    napi_value jsCallback = nullptr;
    NAPI_CALL(env, napi_new_instance(env, jsAuthCallbackConstructor, 0, nullptr, &jsCallback));
    auto callback = new (std::nothrow) NapiAppAccountAuthenticatorCallback(nativeCallback);
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to create NapiAppAccountAuthenticatorCallback");
        return nullptr;
    }
    napi_status status = napi_wrap(
        env, jsCallback, callback,
        [](napi_env env, void *data, void *hint) {
            ACCOUNT_LOGI("js AuthCallback instance garbage collection");
            delete (reinterpret_cast<NapiAppAccountAuthenticatorCallback *>(data));
        },
        nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "wrap js AuthenticatorStub and native callback failed");
    return jsCallback;
}

void NapiAppAccountAuthenticator::CreateJsVerifyCredentialOptions(
    napi_env env, VerifyCredentialOptions &options, napi_value *jsOptions)
{
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, jsOptions));
    napi_value strVal;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, options.credentialType.c_str(), NAPI_AUTO_LENGTH, &strVal));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, *jsOptions, "credentialType", strVal));
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, options.credential.c_str(), NAPI_AUTO_LENGTH, &strVal));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, *jsOptions, "credential", strVal));
    napi_value jsParam = AppExecFwk::WrapWantParams(env, options.parameters);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, *jsOptions, "parameters", jsParam));
}

void NapiAppAccountAuthenticator::CreateJsSetPropertiesOptions(
    napi_env env, SetPropertiesOptions &options, napi_value *jsOptions)
{
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, jsOptions));
    napi_value jsProperties = AppExecFwk::WrapWantParams(env, options.properties);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, *jsOptions, "properties", jsProperties));
    napi_value jsParam = AppExecFwk::WrapWantParams(env, options.parameters);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, *jsOptions, "parameters", jsParam));
}

void NapiAppAccountAuthenticator::CallJsFunction(
    napi_env env, napi_ref funcRef, napi_value *argv, size_t argc)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);
    napi_value returnVal;
    napi_value function = nullptr;
    napi_get_reference_value(env, funcRef, &function);
    napi_call_function(env, undefined, function, argc, argv, &returnVal);
}

void NapiAppAccountAuthenticator::AddAccountImplicitlyWork(uv_work_t *work, int status)
{
    JsAuthenticatorParam *param = reinterpret_cast<JsAuthenticatorParam *>(work->data);
    napi_value jsAuthType;
    napi_create_string_utf8(param->env, param->authType.c_str(), NAPI_AUTO_LENGTH, &jsAuthType);
    napi_value jsCallerBundleName;
    napi_create_string_utf8(param->env, param->callerBundleName.c_str(), NAPI_AUTO_LENGTH, &jsCallerBundleName);
    napi_value jsOptions = AppExecFwk::WrapWantParams(param->env, param->options);
    napi_value jsCallback = CreateAuthenticatorCallback(param->env, param->callback);
    napi_value argv[] = { jsAuthType, jsCallerBundleName, jsOptions, jsCallback};
    CallJsFunction(param->env, param->jsAuthenticator.addAccountImplicitly, argv, ARGS_SIZE_FOUR);
}

void NapiAppAccountAuthenticator::AuthenticateWork(uv_work_t *work, int status)
{
    JsAuthenticatorParam *param = reinterpret_cast<JsAuthenticatorParam *>(work->data);
    napi_value jsName;
    napi_create_string_utf8(param->env, param->name.c_str(), NAPI_AUTO_LENGTH, &jsName);
    napi_value jsAuthType;
    napi_create_string_utf8(param->env, param->authType.c_str(), NAPI_AUTO_LENGTH, &jsAuthType);
    napi_value jsCallerBundleName;
    napi_create_string_utf8(param->env, param->callerBundleName.c_str(), NAPI_AUTO_LENGTH, &jsCallerBundleName);
    napi_value jsOptions = AppExecFwk::WrapWantParams(param->env, param->options);
    napi_value jsCallback = CreateAuthenticatorCallback(param->env, param->callback);
    napi_value argv[] = { jsName, jsAuthType, jsCallerBundleName, jsOptions, jsCallback};
    CallJsFunction(param->env, param->jsAuthenticator.authenticate, argv, ARGS_SIZE_FIVE);
}

void NapiAppAccountAuthenticator::CreateAccountImplicitlyWork(uv_work_t *work, int status)
{
    JsAuthenticatorParam *param = reinterpret_cast<JsAuthenticatorParam *>(work->data);
    napi_value jsObject = nullptr;
    napi_create_object(param->env, &jsObject);
    if (param->createOptions.hasAuthType) {
        napi_value jsAuthType;
        napi_create_string_utf8(param->env, param->createOptions.authType.c_str(), NAPI_AUTO_LENGTH, &jsAuthType);
        napi_set_named_property(param->env, jsObject, "authType", jsAuthType);
    }
    if (param->createOptions.hasRequiredLabels) {
        napi_value jsRequiredLabels = CreateStringArray(param->env, param->createOptions.requiredLabels);
        napi_set_named_property(param->env, jsObject, "requiredLabels", jsRequiredLabels);
    }
    napi_value jsParams = AppExecFwk::WrapWantParams(param->env, param->createOptions.parameters.GetParams());
    napi_set_named_property(param->env, jsObject, "parameters", jsParams);
    napi_value jsCallback = CreateAuthenticatorCallback(param->env, param->callback);
    napi_value argv[] = {jsObject, jsCallback};
    CallJsFunction(param->env, param->jsAuthenticator.createAccountImplicitly, argv, ARGS_SIZE_TWO);
}

void NapiAppAccountAuthenticator::AuthWork(uv_work_t *work, int status)
{
    JsAuthenticatorParam *param = reinterpret_cast<JsAuthenticatorParam *>(work->data);
    napi_value jsName;
    napi_create_string_utf8(param->env, param->name.c_str(), NAPI_AUTO_LENGTH, &jsName);
    napi_value jsAuthType;
    napi_create_string_utf8(param->env, param->authType.c_str(), NAPI_AUTO_LENGTH, &jsAuthType);
    napi_value jsOptions = AppExecFwk::WrapWantParams(param->env, param->options);
    napi_value jsCallback = CreateAuthenticatorCallback(param->env, param->callback);
    napi_value argv[] = { jsName, jsAuthType, jsOptions, jsCallback};
    CallJsFunction(param->env, param->jsAuthenticator.auth, argv, ARGS_SIZE_FOUR);
}

void NapiAppAccountAuthenticator::VerifyCredentialWork(uv_work_t *work, int status)
{
    JsAuthenticatorParam *param = reinterpret_cast<JsAuthenticatorParam *>(work->data);
    napi_value jsName;
    napi_create_string_utf8(param->env, param->name.c_str(), NAPI_AUTO_LENGTH, &jsName);
    napi_value jsOptions;
    CreateJsVerifyCredentialOptions(param->env, param->verifyCredOptions, &jsOptions);
    napi_value jsCallback = CreateAuthenticatorCallback(param->env, param->callback);
    napi_value argv[] = { jsName, jsOptions, jsCallback};
    CallJsFunction(param->env, param->jsAuthenticator.verifyCredential, argv, ARGS_SIZE_THREE);
}

void NapiAppAccountAuthenticator::SetPropertiesWork(uv_work_t *work, int status)
{
    JsAuthenticatorParam *param = reinterpret_cast<JsAuthenticatorParam *>(work->data);
    napi_value jsOptions;
    CreateJsSetPropertiesOptions(param->env, param->setPropOptions, &jsOptions);
    napi_value jsCallback = CreateAuthenticatorCallback(param->env, param->callback);
    napi_value argv[] = {jsOptions, jsCallback};
    CallJsFunction(param->env, param->jsAuthenticator.setProperties, argv, ARGS_SIZE_TWO);
}

void NapiAppAccountAuthenticator::CheckAccountLabelsWork(uv_work_t *work, int status)
{
    JsAuthenticatorParam *param = reinterpret_cast<JsAuthenticatorParam *>(work->data);
    napi_value jsName;
    napi_create_string_utf8(param->env, param->name.c_str(), NAPI_AUTO_LENGTH, &jsName);
    napi_value jsLabels = nullptr;
    napi_create_array(param->env, &jsLabels);
    for (size_t i = 0; i < param->labels.size(); ++i) {
        napi_value value = nullptr;
        napi_create_string_utf8(param->env, param->labels[i].c_str(), NAPI_AUTO_LENGTH, &value);
        napi_set_element(param->env, jsLabels, i, value);
    }
    napi_value jsCallback = CreateAuthenticatorCallback(param->env, param->callback);
    napi_value argv[] = {jsName, jsLabels, jsCallback};
    CallJsFunction(param->env, param->jsAuthenticator.checkAccountLabels, argv, ARGS_SIZE_THREE);
}

void NapiAppAccountAuthenticator::IsAccountRemovableWork(uv_work_t *work, int status)
{
    JsAuthenticatorParam *param = reinterpret_cast<JsAuthenticatorParam *>(work->data);
    napi_value jsName;
    napi_create_string_utf8(param->env, param->name.c_str(), NAPI_AUTO_LENGTH, &jsName);
    napi_value jsCallback = CreateAuthenticatorCallback(param->env, param->callback);
    napi_value argv[] = {jsName, jsCallback};
    CallJsFunction(param->env, param->jsAuthenticator.isAccountRemovable, argv, ARGS_SIZE_TWO);
}

napi_value NapiAppAccountAuthenticator::GetJsRemoteObject()
{
    return remoteObject_;
}

void NapiAppAccountAuthenticator::SetJsRemoteObject(napi_value remoteObject)
{
    remoteObject_ = remoteObject;
}

napi_value NapiAppAccountAuthenticator::GetRemoteObject(napi_env env, napi_callback_info cbInfo)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbInfo, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiAppAccountAuthenticator::Init(napi_env env, napi_value exports)
{
    const std::string className = "Authenticator";
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), className.length(), JsConstructor, nullptr,
        0, nullptr, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "define js class Authenticator failed");
    napi_status status = napi_set_named_property(env, exports, className.c_str(), constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property Authenticator to exports failed");
    return exports;
}

napi_status NapiAppAccountAuthenticator::GetNamedFunction(
    napi_env env, napi_value value, const std::string &name, napi_ref *result)
{
    napi_value jsFunc = nullptr;
    napi_get_named_property(env, value, name.c_str(), &jsFunc);
    return napi_create_reference(env, jsFunc, 1, result);
}

napi_value NapiAppAccountAuthenticator::JsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "get callback info failed");
    JsAuthenticator jsAuthenticator;
    GetNamedFunction(env, thisVar, "addAccountImplicitly", &jsAuthenticator.addAccountImplicitly);
    GetNamedFunction(env, thisVar, "authenticate", &jsAuthenticator.authenticate);
    GetNamedFunction(env, thisVar, "verifyCredential", &jsAuthenticator.verifyCredential);
    GetNamedFunction(env, thisVar, "checkAccountLabels", &jsAuthenticator.checkAccountLabels);
    GetNamedFunction(env, thisVar, "isAccountRemovable", &jsAuthenticator.isAccountRemovable);
    GetNamedFunction(env, thisVar, "checkAccountRemovable", &jsAuthenticator.isAccountRemovable);
    GetNamedFunction(env, thisVar, "setProperties", &jsAuthenticator.setProperties);
    GetNamedFunction(env, thisVar, "createAccountImplicitly", &jsAuthenticator.createAccountImplicitly);
    GetNamedFunction(env, thisVar, "auth", &jsAuthenticator.auth);
    napi_value object = nullptr;
    napi_create_object(env, &object);
    NAPIRemoteObjectExport(env, object);
    sptr<NapiAppAccountAuthenticator> authenticator =
        new (std::nothrow) NapiAppAccountAuthenticator(env, jsAuthenticator);
    if (authenticator == nullptr) {
        ACCOUNT_LOGE("failed to construct NapiAppAccountAuthenticator");
        return nullptr;
    }
    napi_value napiRemoteObj = NAPI_ohos_rpc_CreateJsRemoteObject(env, authenticator->AsObject());
    napi_value func = nullptr;
    napi_create_function(env, "getRemoteObject", 0, GetRemoteObject, nullptr, &func);
    NAPI_ASSERT(env, func != nullptr, "create function getRemoteObject failed");
    status = napi_set_named_property(env, napiRemoteObj, "getRemoteObject", func);
    NAPI_ASSERT(env, status == napi_ok, "set property getRemoteObject failed");
    return napiRemoteObj;
}
}  // namespace AccountJsKit
}  // namespace OHOS
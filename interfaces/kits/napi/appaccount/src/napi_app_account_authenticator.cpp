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
    ACCOUNT_LOGD("enter");
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
    ACCOUNT_LOGD("enter");
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
    ACCOUNT_LOGD("enter");
    if (jsAuthenticator_.addAccountImplicitly == nullptr) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsAuthenticatorParam *param = nullptr;
    ErrCode result = InitWorkEnv(&loop, &work, &param);
    if (result != ERR_OK) {
        ACCOUNT_LOGD("failed to InitWorkEnv");
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
    ACCOUNT_LOGD("enter");
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
    param->name = name;
    param->authType = authType;
    param->callerBundleName = callerBundleName;
    param->options = options;
    param->callback = callback;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, AuthenticateWork);
    return ERR_OK;
}

ErrCode NapiAppAccountAuthenticator::VerifyCredential(
    const std::string &name, const VerifyCredentialOptions &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGD("enter");
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
    param->name = name;
    param->verifyCredOptions = options;
    param->callback = callback;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, VerifyCredentialWork);
    return ERR_OK;
}

ErrCode NapiAppAccountAuthenticator::SetProperties(
    const SetPropertiesOptions &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGD("enter");
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
    ACCOUNT_LOGD("enter");
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
    param->name = name;
    param->labels = labels;
    param->callback = callback;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, CheckAccountLabelsWork);
    return ERR_OK;
}

ErrCode NapiAppAccountAuthenticator::IsAccountRemovable(const std::string &name, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGD("enter");
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

void NapiAppAccountAuthenticator::CreateAuthenticatorCallback(
    napi_env env, sptr<IRemoteObject> nativeCallback, napi_value *jsCallback)
{
    ACCOUNT_LOGD("enter");
    napi_value global = nullptr;
    napi_get_global(env, &global);
    if (global == nullptr) {
        ACCOUNT_LOGD("failed to get napi global");
        return;
    }
    napi_value jsAuthCallbackConstructor = nullptr;
    napi_get_named_property(env, global, "AuthCallbackConstructor_", &jsAuthCallbackConstructor);
    if (jsAuthCallbackConstructor == nullptr) {
        ACCOUNT_LOGD("jsAuthCallbackConstructor is null");
        return;
    }
    napi_value callbackAddr;
    napi_create_int64(env, reinterpret_cast<int64_t>((IRemoteObject *) nativeCallback), &callbackAddr);
    napi_value argv[] = { callbackAddr };
    napi_new_instance(env, jsAuthCallbackConstructor, ARGS_SIZE_ONE, argv, jsCallback);
}

void NapiAppAccountAuthenticator::CreateJsVerifyCredentialOptions(
    napi_env env, VerifyCredentialOptions &options, napi_value *jsOptions)
{
    ACCOUNT_LOGD("enter");
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, jsOptions));
    napi_value string;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, options.credentialType.c_str(), NAPI_AUTO_LENGTH, &string));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, *jsOptions, "credentialType", string));
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, options.credential.c_str(), NAPI_AUTO_LENGTH, &string));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, *jsOptions, "credentialType", string));
    napi_value jsParam = AppExecFwk::WrapWantParams(env, options.parameters);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, *jsOptions, "parameters", jsParam));
}

void NapiAppAccountAuthenticator::CreateJsSetPropertiesOptions(
    napi_env env, SetPropertiesOptions &options, napi_value *jsOptions)
{
    ACCOUNT_LOGD("enter");
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, jsOptions));
    napi_value jsProperties = AppExecFwk::WrapWantParams(env, options.properties);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, *jsOptions, "properties", jsProperties));
    napi_value jsParam = AppExecFwk::WrapWantParams(env, options.parameters);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, *jsOptions, "parameters", jsParam));
}

void NapiAppAccountAuthenticator::CallJsFunction(
    napi_env env, napi_ref funcRef, napi_value *argv, size_t argc)
{
    ACCOUNT_LOGD("enter");
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);
    napi_value returnVal;
    napi_value function = nullptr;
    napi_get_reference_value(env, funcRef, &function);
    napi_call_function(env, undefined, function, argc, argv, &returnVal);
}

void NapiAppAccountAuthenticator::AddAccountImplicitlyWork(uv_work_t *work, int status)
{
    ACCOUNT_LOGD("enter");
    JsAuthenticatorParam *param = reinterpret_cast<JsAuthenticatorParam *>(work->data);
    napi_value jsAuthType;
    napi_create_string_utf8(param->env, param->authType.c_str(), NAPI_AUTO_LENGTH, &jsAuthType);
    napi_value jsCallerBundleName;
    napi_create_string_utf8(param->env, param->callerBundleName.c_str(), NAPI_AUTO_LENGTH, &jsCallerBundleName);
    napi_value jsOptions = AppExecFwk::WrapWantParams(param->env, param->options);
    napi_value jsCallback;
    CreateAuthenticatorCallback(param->env, param->callback, &jsCallback);
    napi_value argv[] = { jsAuthType, jsCallerBundleName, jsOptions, jsCallback};
    CallJsFunction(param->env, param->jsAuthenticator.addAccountImplicitly, argv, ARGS_SIZE_FOUR);
}

void NapiAppAccountAuthenticator::AuthenticateWork(uv_work_t *work, int status)
{
    ACCOUNT_LOGD("enter");
    JsAuthenticatorParam *param = reinterpret_cast<JsAuthenticatorParam *>(work->data);
    napi_value jsName;
    napi_create_string_utf8(param->env, param->name.c_str(), NAPI_AUTO_LENGTH, &jsName);
    napi_value jsAuthType;
    napi_create_string_utf8(param->env, param->authType.c_str(), NAPI_AUTO_LENGTH, &jsAuthType);
    napi_value jsCallerBundleName;
    napi_create_string_utf8(param->env, param->callerBundleName.c_str(), NAPI_AUTO_LENGTH, &jsCallerBundleName);
    napi_value jsOptions = AppExecFwk::WrapWantParams(param->env, param->options);
    napi_value jsCallback;
    CreateAuthenticatorCallback(param->env, param->callback, &jsCallback);
    napi_value argv[] = { jsName, jsAuthType, jsCallerBundleName, jsOptions, jsCallback};
    CallJsFunction(param->env, param->jsAuthenticator.authenticate, argv, ARGS_SIZE_FIVE);
}

void NapiAppAccountAuthenticator::VerifyCredentialWork(uv_work_t *work, int status)
{
    ACCOUNT_LOGD("enter");
    JsAuthenticatorParam *param = reinterpret_cast<JsAuthenticatorParam *>(work->data);
    napi_value jsName;
    napi_create_string_utf8(param->env, param->name.c_str(), NAPI_AUTO_LENGTH, &jsName);
    napi_value jsOptions;
    CreateJsVerifyCredentialOptions(param->env, param->verifyCredOptions, &jsOptions);
    napi_value jsCallback;
    CreateAuthenticatorCallback(param->env, param->callback, &jsCallback);
    napi_value argv[] = { jsName, jsOptions, jsCallback};
    CallJsFunction(param->env, param->jsAuthenticator.verifyCredential, argv, ARGS_SIZE_THREE);
}

void NapiAppAccountAuthenticator::SetPropertiesWork(uv_work_t *work, int status)
{
    ACCOUNT_LOGD("enter");
    JsAuthenticatorParam *param = reinterpret_cast<JsAuthenticatorParam *>(work->data);
    napi_value jsOptions;
    CreateJsSetPropertiesOptions(param->env, param->setPropOptions, &jsOptions);
    napi_value jsCallback;
    CreateAuthenticatorCallback(param->env, param->callback, &jsCallback);
    napi_value argv[] = {jsOptions, jsCallback};
    CallJsFunction(param->env, param->jsAuthenticator.setProperties, argv, ARGS_SIZE_TWO);
}

void NapiAppAccountAuthenticator::CheckAccountLabelsWork(uv_work_t *work, int status)
{
    ACCOUNT_LOGD("enter");
    JsAuthenticatorParam *param = reinterpret_cast<JsAuthenticatorParam *>(work->data);
    napi_value jsName;
    napi_create_string_utf8(param->env, param->name.c_str(), NAPI_AUTO_LENGTH, &jsName);
    napi_value jsLabels = nullptr;
    napi_value jsCallback;
    CreateAuthenticatorCallback(param->env, param->callback, &jsCallback);
    napi_value argv[] = {jsName, jsLabels, jsCallback};
    CallJsFunction(param->env, param->jsAuthenticator.checkAccountLabels, argv, ARGS_SIZE_THREE);
}

void NapiAppAccountAuthenticator::IsAccountRemovableWork(uv_work_t *work, int status)
{
    ACCOUNT_LOGD("enter");
    JsAuthenticatorParam *param = reinterpret_cast<JsAuthenticatorParam *>(work->data);
    napi_value jsName;
    napi_create_string_utf8(param->env, param->name.c_str(), NAPI_AUTO_LENGTH, &jsName);
    napi_value jsCallback;
    CreateAuthenticatorCallback(param->env, param->callback, &jsCallback);
    napi_value argv[] = {jsName, jsCallback};
    CallJsFunction(param->env, param->jsAuthenticator.isAccountRemovable, argv, ARGS_SIZE_TWO);
}

napi_value NapiAppAccountAuthenticator::GetRemoteObject(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbInfo, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiAppAccountAuthenticator::Init(napi_env env, napi_value exports)
{
    ACCOUNT_LOGD("enter");
    const std::string className = "Authenticator";
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getRemoteObject", GetRemoteObject),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), className.length(), JsConstructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "define js class Authenticator failed");
    napi_status status = napi_set_named_property(env, exports, className.c_str(), constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property Authenticator to exports failed");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    status = napi_set_named_property(env, global, "AuthenticatorConstructor_", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set stub constructor failed");
    return exports;
}

napi_value NapiAppAccountAuthenticator::JsConstructor(napi_env env, napi_callback_info info)
{
    ACCOUNT_LOGD("enter");
    napi_value thisVar = nullptr;
    napi_value jsFunc = nullptr;
    JsAuthenticator jsAuthenticator;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_get_named_property(env, thisVar, "addAccountImplicitly", &jsFunc);
    napi_create_reference(env, jsFunc, 1, &jsAuthenticator.addAccountImplicitly);
    napi_get_named_property(env, thisVar, "authenticate", &jsFunc);
    napi_create_reference(env, jsFunc, 1, &jsAuthenticator.authenticate);
    napi_get_named_property(env, thisVar, "verifyCredential", &jsFunc);
    napi_create_reference(env, jsFunc, 1, &jsAuthenticator.verifyCredential);
    napi_get_named_property(env, thisVar, "checkAccountLabels", &jsFunc);
    napi_create_reference(env, jsFunc, 1, &jsAuthenticator.checkAccountLabels);
    napi_get_named_property(env, thisVar, "isAccountRemovable", &jsFunc);
    napi_create_reference(env, jsFunc, 1, &jsAuthenticator.isAccountRemovable);
    napi_get_named_property(env, thisVar, "setProperties", &jsFunc);
    napi_create_reference(env, jsFunc, 1, &jsAuthenticator.setProperties);
    sptr<NapiAppAccountAuthenticator> authenticator =
        new (std::nothrow) NapiAppAccountAuthenticator(env, jsAuthenticator);
    if (authenticator == nullptr) {
        ACCOUNT_LOGD("failed to construct NapiAppAccountAuthenticator");
        return nullptr;
    }
    return NAPI_ohos_rpc_CreateJsRemoteObject(env, authenticator->AsObject());
}
}  // namespace AccountJsKit
}  // namespace OHOS

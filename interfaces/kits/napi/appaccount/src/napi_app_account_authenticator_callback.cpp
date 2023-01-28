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

#include "napi_app_account_authenticator_callback.h"

#include <uv.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "iapp_account_authenticator_callback.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_app_account_common.h"
#include "napi_common.h"

namespace OHOS {
namespace AccountJsKit {
NapiAppAccountAuthenticatorCallback::NapiAppAccountAuthenticatorCallback(const sptr<IRemoteObject> &object)
    : object_(object)
{}

NapiAppAccountAuthenticatorCallback::~NapiAppAccountAuthenticatorCallback()
{
    object_ = nullptr;
}

sptr<IRemoteObject> NapiAppAccountAuthenticatorCallback::GetRemoteObject()
{
    return object_;
}

napi_value NapiAppAccountAuthenticatorCallback::Init(napi_env env, napi_value exports)
{
    const std::string className = "AuthenticatorCallback";
    const std::string classNameNew = "AuthCallback";
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("onResult", JsOnResult),
        DECLARE_NAPI_FUNCTION("onRequestRedirected", JsOnRequestRedirected),
        DECLARE_NAPI_FUNCTION("onRequestContinued", JsOnRequestContinued),
    };
    napi_value constructor = nullptr;
    NAPI_CALL(env, napi_define_class(env, className.c_str(), className.length(), JsConstructor, nullptr,
        sizeof(properties) / sizeof(napi_property_descriptor), properties, &constructor));
    NAPI_CALL(env, napi_define_class(env, classNameNew.c_str(), classNameNew.length(), JsConstructor, nullptr,
        sizeof(properties) / sizeof(napi_property_descriptor), properties, &constructor));
    NAPI_ASSERT(env, constructor != nullptr, "define js class Authenticator failed");
    napi_status status = napi_set_named_property(env, exports, className.c_str(), constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property Authenticator to exports failed");
    status = napi_set_named_property(env, exports, classNameNew.c_str(), constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property Authenticator to exports failed");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    status = napi_set_named_property(env, global, "AuthCallbackConstructor_", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set stub constructor failed");
    return exports;
}

static void ParseContextForOnResult(napi_env env, napi_callback_info cbInfo, CallbackParam *param)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr);
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&(param->callback)));
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &(param->resultCode));
        } else if (i == 1 && valueType == napi_object) {
            if (!AppExecFwk::UnwrapWantParams(env, argv[i], param->result)) {
                ACCOUNT_LOGE("UnwrapWantParams failed");
                return;
            }
        } else {
            ACCOUNT_LOGE("Type matching failed");
        }
    }
}

static void ParseContextForRequestRedirected(napi_env env, napi_callback_info cbInfo, CallbackParam *param)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr);
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&(param->callback)));
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType == napi_object) {
        if (!AppExecFwk::UnwrapWant(env, argv[0], param->request)) {
            return;
        }
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }
}

static void OnAuthenticatorWorkComplete(napi_env env, napi_status status, void *data)
{
    (void)status;
    CallbackParam *param = reinterpret_cast<CallbackParam *>(data);
    napi_delete_async_work(env, param->work);
    delete param;
    param = nullptr;
}

napi_value NapiAppAccountAuthenticatorCallback::JsOnResult(napi_env env, napi_callback_info cbInfo)
{
    auto *param = new (std::nothrow) CallbackParam();
    if (param == nullptr) {
        ACCOUNT_LOGE("insufficient memory for param!");
        return NapiGetNull(env);
    }
    param->env = env;
    ParseContextForOnResult(env, cbInfo, param);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "JsOnResult", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
            [](napi_env env, void *data) {
                CallbackParam *param = reinterpret_cast<CallbackParam *>(data);
                if ((param == nullptr) || (param->callback == nullptr)) {
                    ACCOUNT_LOGE("invalid parameters");
                    return;
                }
                auto callbackProxy = iface_cast<IAppAccountAuthenticatorCallback>(param->callback->GetRemoteObject());
                if ((callbackProxy != nullptr) && (callbackProxy->AsObject() != nullptr)) {
                    AAFwk::Want result;
                    result.SetParams(param->result);
                    callbackProxy->OnResult(param->resultCode, result);
                }
            },
            OnAuthenticatorWorkComplete,
            reinterpret_cast<void *>(param), &param->work));
    NAPI_CALL(env, napi_queue_async_work(env, param->work));
    return NapiGetNull(env);
}

napi_value NapiAppAccountAuthenticatorCallback::JsOnRequestRedirected(napi_env env, napi_callback_info cbInfo)
{
    auto *param = new (std::nothrow) CallbackParam();
    if (param == nullptr) {
        ACCOUNT_LOGE("insufficient memory for param!");
        return NapiGetNull(env);
    }
    param->env = env;
    ParseContextForRequestRedirected(env, cbInfo, param);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "JsOnRequestRedirected", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
            [](napi_env env, void *data) {
                CallbackParam *param = reinterpret_cast<CallbackParam *>(data);
                if ((param == nullptr) || (param->callback == nullptr)) {
                    ACCOUNT_LOGE("invalid parameters");
                    return;
                }
                auto callbackProxy = iface_cast<IAppAccountAuthenticatorCallback>(param->callback->GetRemoteObject());
                if ((callbackProxy != nullptr) && (callbackProxy->AsObject() != nullptr)) {
                    callbackProxy->OnRequestRedirected(param->request);
                }
            },
            OnAuthenticatorWorkComplete,
            reinterpret_cast<void *>(param), &param->work));
    NAPI_CALL(env, napi_queue_async_work(env, param->work));
    return NapiGetNull(env);
}

napi_value NapiAppAccountAuthenticatorCallback::JsOnRequestContinued(napi_env env, napi_callback_info cbInfo)
{
    auto *param = new (std::nothrow) CallbackParam();
    if (param == nullptr) {
        ACCOUNT_LOGE("insufficient memory for param!");
        return NapiGetNull(env);
    }
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbInfo, nullptr, nullptr, &thisVar, nullptr);
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&(param->callback)));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "JsOnRequestContinued", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
            [](napi_env env, void *data) {
                CallbackParam *param = reinterpret_cast<CallbackParam *>(data);
                if ((param == nullptr) || (param->callback == nullptr)) {
                    ACCOUNT_LOGE("invalid parameters");
                    return;
                }
                auto callbackProxy = iface_cast<IAppAccountAuthenticatorCallback>(param->callback->GetRemoteObject());
                if ((callbackProxy != nullptr) && (callbackProxy->AsObject() != nullptr)) {
                    callbackProxy->OnRequestContinued();
                }
            },
            OnAuthenticatorWorkComplete,
            reinterpret_cast<void *>(param),
            &param->work));
    NAPI_CALL(env, napi_queue_async_work(env, param->work));
    return NapiGetNull(env);
}

napi_value NapiAppAccountAuthenticatorCallback::JsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}
}  // namespace AccountJsKit
}  // namespace OHOS

/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
{
    ACCOUNT_LOGI("enter");
}

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
    ACCOUNT_LOGI("Enter");
    const std::string className = "AuthenticatorCallback";
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("onResult", JsOnResult),
        DECLARE_NAPI_FUNCTION("onRequestRedirected", JsOnRequestRedirected),
    };
    napi_value constructor = nullptr;
    NAPI_CALL(env, napi_define_class(env, className.c_str(), className.length(), JsConstructor, nullptr,
        sizeof(properties) / sizeof(napi_property_descriptor), properties, &constructor));
    NAPI_ASSERT(env, constructor != nullptr, "define js class Authenticator failed");
    napi_status status = napi_set_named_property(env, exports, className.c_str(), constructor);
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
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr);
    napi_unwrap(env, thisVar, (void **)&(param->callback));
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
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr);
    napi_unwrap(env, thisVar, (void **)&(param->callback));
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

napi_value NapiAppAccountAuthenticatorCallback::JsOnResult(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("JsOnResult start");
    auto *param = new (std::nothrow) CallbackParam();
    if (param == nullptr) {
        ACCOUNT_LOGE("insufficient memory for param!");
        return NapiGetNull(env);
    }
    param->env = env;
    ParseContextForOnResult(env, cbInfo, param);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "JsOnResult", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("JsOnResult, napi_create_async_work running.");
                CallbackParam *param = (CallbackParam *)data;
                auto callbackProxy = iface_cast<IAppAccountAuthenticatorCallback>(param->callback->GetRemoteObject());
                if ((callbackProxy != nullptr) && (callbackProxy->AsObject() != nullptr)) {
                    AAFwk::Want result;
                    result.SetParams(param->result);
                    callbackProxy->OnResult(param->resultCode, result);
                }
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("JsOnResult, napi_create_async_work complete.");
                CallbackParam *param = (CallbackParam *)data;
                napi_delete_async_work(env, param->work);
                delete param;
                param = nullptr;
            },
            (void *)param,
            &param->work));
    NAPI_CALL(env, napi_queue_async_work(env, param->work));
    return NapiGetNull(env);
}

napi_value NapiAppAccountAuthenticatorCallback::JsOnRequestRedirected(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("JsOnRequestRedirected start");
    auto *param = new (std::nothrow) CallbackParam();
    if (param == nullptr) {
        ACCOUNT_LOGE("insufficient memory for param!");
        return NapiGetNull(env);
    }
    param->env = env;
    ParseContextForRequestRedirected(env, cbInfo, param);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "JsOnRequestRedirected", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("JsOnRequestRedirected, napi_create_async_work running.");
                CallbackParam *param = (CallbackParam *)data;
                auto callbackProxy = iface_cast<IAppAccountAuthenticatorCallback>(param->callback->GetRemoteObject());
                if ((callbackProxy != nullptr) && (callbackProxy->AsObject() != nullptr)) {
                    callbackProxy->OnRequestRedirected(param->request);
                }
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("JsOnRequestRedirected, napi_create_async_work complete.");
                CallbackParam *param = (CallbackParam *)data;
                napi_delete_async_work(env, param->work);
                delete param;
                param = nullptr;
            },
            (void *)param,
            &param->work));
    NAPI_CALL(env, napi_queue_async_work(env, param->work));
    return NapiGetNull(env);
}

napi_value NapiAppAccountAuthenticatorCallback::JsConstructor(napi_env env, napi_callback_info info)
{
    ACCOUNT_LOGI("Enter");
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "napi get callback info failed");
    sptr<IRemoteObject> remote = nullptr;
    if (argv[0] != nullptr) {
        int64_t tmp = 0;
        napi_get_value_int64(env, argv[0], &tmp);
        remote = reinterpret_cast<IRemoteObject *>(tmp);
        NAPI_ASSERT(env, remote != nullptr, "remote is null");
    }
    auto callback = new (std::nothrow) NapiAppAccountAuthenticatorCallback(remote);
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to create NapiAppAccountAuthenticatorCallback");
        return nullptr;
    }
    status = napi_wrap(
        env, thisVar, callback,
        [](napi_env env, void *data, void *hint) {
            ACCOUNT_LOGI("NapiAppAccountAuthenticatorCallback destructed by js callback");
            delete (reinterpret_cast<NapiAppAccountAuthenticatorCallback *>(data));
        },
        nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "wrap js AuthenticatorStub and native callback failed");
    return thisVar;
}
}  // namespace AccountSA
}  // namespace OHOS

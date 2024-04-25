/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "napi_domain_server_manager.h"

#include <uv.h>
#include "account_log_wrapper.h"
#include "domain_account_client.h"
#include "napi_account_common.h"
#include "napi_account_error.h"
#include "napi_common.h"
#include "napi_domain_account_common.h"
#include "string_wrapper.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;
namespace {
const size_t ARG_SIZE_ONE = 1;
}

napi_value NapiDomainServerConfigManager::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_STATIC_FUNCTION("addServerConfig", AddServerConfig),
        DECLARE_NAPI_STATIC_FUNCTION("removeServerConfig", RemoveServerConfig),
        DECLARE_NAPI_STATIC_FUNCTION("getAccountServerConfig", GetAccountServerConfig),
        DECLARE_NAPI_FUNCTION("addServerConfig", AddServerConfig),
        DECLARE_NAPI_FUNCTION("removeServerConfig", RemoveServerConfig),
        DECLARE_NAPI_FUNCTION("getAccountServerConfig", GetAccountServerConfig),
    };
    napi_value cons;
    NAPI_CALL(env, napi_define_class(env, "DomainServerConfigManager", NAPI_AUTO_LENGTH, JsConstructor,
        nullptr, sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    NAPI_CALL(env, napi_set_named_property(env, exports, "DomainServerConfigManager", cons));
    return exports;
}

napi_value NapiDomainServerConfigManager::JsConstructor(napi_env env, napi_callback_info info)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

static bool ParseContextFoAddServerConfig(
    napi_env env, napi_callback_info info, AddServerConfigAsyncContext *context)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("The parameter of number should be at least one.");
        return false;
    }
    if (!JsObjectToNativeString(env, argv[0], context->parameters)) {
        ACCOUNT_LOGE("Get parameters failed.");
        return false;
    }
    return true;
}

static void AddServerConfigExecuteCB(napi_env env, void *data)
{
    AddServerConfigAsyncContext *asyncContext = reinterpret_cast<AddServerConfigAsyncContext *>(data);
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("In AddServerConfigExecuteCB asyncContext is nullptr.");
        return;
    }
    asyncContext->errCode = DomainAccountClient::GetInstance().AddServerConfig(
        asyncContext->parameters, asyncContext->domainServerConfig);
}

static void ServerConfigToJs(napi_env env, const DomainServerConfig& config, napi_value &configJs)
{
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &configJs));
    napi_value idJs;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, config.id_.c_str(), NAPI_AUTO_LENGTH, &idJs));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, configJs, "id", idJs));
    napi_value parametersJs = NativeStringToJsObject(env, config.parameters_);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, configJs, "parameters", parametersJs));
    napi_value domainJs;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, config.domain_.c_str(), NAPI_AUTO_LENGTH, &domainJs));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, configJs, "domain", domainJs));
}

static void AddServerConfigCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    AddServerConfigAsyncContext *asyncContext = reinterpret_cast<AddServerConfigAsyncContext *>(data);
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("In AddServerConfigCompletedCB asyncContext is nullptr.");
        return;
    }
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == 0) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        ServerConfigToJs(env, asyncContext->domainServerConfig, dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode);
        napi_get_null(env, &dataJs);
    }
    ReturnCallbackOrPromise(env, asyncContext, errJs, dataJs);
    delete asyncContext;
}

napi_value NapiDomainServerConfigManager::AddServerConfig(napi_env env, napi_callback_info info)
{
    auto context = std::make_unique<AddServerConfigAsyncContext>(env);

    if (!ParseContextFoAddServerConfig(env, info, context.get())) {
        std::string errMsg = "The type of parameter is error.";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "AddServerConfig", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, AddServerConfigExecuteCB, AddServerConfigCompletedCB,
        reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return result;
}

static bool ParseContextFoRemoveServerConfig(
    napi_env env, napi_callback_info info, RemoveServerConfigAsyncContext *context)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("The parameter of number should be at least one.");
        return false;
    }
    if (!GetStringProperty(env, argv[0], context->configId)) {
        ACCOUNT_LOGE("Get removeServerconfig's configId failed");
        return false;
    }
    return true;
}

static void RemoveServerConfigExecuteCB(napi_env env, void *data)
{
    RemoveServerConfigAsyncContext *asyncContext = reinterpret_cast<RemoveServerConfigAsyncContext *>(data);
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("In RemoveServerConfigExecuteCB asyncContext is nullptr.");
        return;
    }
    asyncContext->errCode = DomainAccountClient::GetInstance().RemoveServerConfig(asyncContext->configId);
}

static void RemoveServerConfigCompletedCB(napi_env env, napi_status status, void *data)
{
    RemoveServerConfigAsyncContext *asyncContext = reinterpret_cast<RemoveServerConfigAsyncContext *>(data);
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("AsyncContext is nullptr.");
        return;
    }
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == 0) {
        napi_get_null(env, &errJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode);
    }
    napi_get_null(env, &dataJs);
    ReturnCallbackOrPromise(env, asyncContext, errJs, dataJs);
    delete asyncContext;
}

napi_value NapiDomainServerConfigManager::RemoveServerConfig(napi_env env, napi_callback_info info)
{
    auto context = std::make_unique<RemoveServerConfigAsyncContext>(env);
    if (!ParseContextFoRemoveServerConfig(env, info, context.get())) {
        std::string errMsg = "The type of parameter is error.";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "RemoveServerConfig", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, RemoveServerConfigExecuteCB,
        RemoveServerConfigCompletedCB, reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return result;
}

static bool ParseContextFoGetAccountServerConfig(
    napi_env env, napi_callback_info info, GetAccountServerConfigAsyncContext *context)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("The parameter of number should be at least one.");
        return false;
    }
    if (!ParseDomainAccountInfo(env, argv[0], context->domainAccountInfo)) {
        ACCOUNT_LOGE("Get domainInfo failed");
        return false;
    }
    return true;
}

static void GetAccountServerConfigExecuteCB(napi_env env, void *data)
{
    GetAccountServerConfigAsyncContext *asyncContext = reinterpret_cast<GetAccountServerConfigAsyncContext *>(data);
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("In GetAccountServerConfigExecuteCB asyncContext is nullptr.");
        return;
    }
    asyncContext->errCode = DomainAccountClient::GetInstance().GetAccountServerConfig(asyncContext->domainAccountInfo,
        asyncContext->domainServerConfig);
}


static void GetAccountServerConfigCompletedCB(napi_env env, napi_status status, void *data)
{
    GetAccountServerConfigAsyncContext *asyncContext = reinterpret_cast<GetAccountServerConfigAsyncContext *>(data);
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("AsyncContext is nullptr.");
        return;
    }
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == 0) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        ServerConfigToJs(env, asyncContext->domainServerConfig, dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode);
        napi_get_null(env, &dataJs);
    }
    ReturnCallbackOrPromise(env, asyncContext, errJs, dataJs);
    delete asyncContext;
}

napi_value NapiDomainServerConfigManager::GetAccountServerConfig(napi_env env, napi_callback_info info)
{
    auto context = std::make_unique<GetAccountServerConfigAsyncContext>(env);
    if (!ParseContextFoGetAccountServerConfig(env, info, context.get())) {
        std::string errMsg = "The type of parameter is error.";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetAccountServerConfig", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, GetAccountServerConfigExecuteCB,
        GetAccountServerConfigCompletedCB, reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return result;
}

}  // namespace AccountJsKit
}  // namespace OHOS

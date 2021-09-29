/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "napi_distributed_account.h"
#include <map>
#include <string>
#include <unistd.h>
#include "account_log_wrapper.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "ohos_account_kits.h"

using namespace OHOS::AccountSA;

namespace OHOS {
namespace AccountJsKit {
namespace {
constexpr std::int32_t MAX_VALUE_LEN = 4096;
constexpr std::int32_t QUERY_ARGC = 1;
constexpr std::int32_t UPDATE_ARGC = 2;
constexpr int RESULT_COUNT = 2;
const std::string DISTRIBUTED_ACCOUNT_CLASS_NAME = "DistributedAccountAbility";
const std::string PROPERTY_KEY_NAME = "name";
const std::string PROPERTY_KEY_ID = "id";
const std::string PROPERTY_KEY_EVENT = "event";
const std::string PROPERTY_KEY_SCALABLE = "scalableData";

struct DistributedAccountAsyncContext {
    napi_env env;
    napi_async_work work;

    std::string name;
    std::string id;
    std::string event;
    std::map<std::string, std::string> scalableData;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

std::string GetNamedProperty(napi_env env, napi_value obj, const std::string &keyStr)
{
    napi_value value = nullptr;
    napi_get_named_property(env, obj, keyStr.c_str(), &value);
    char propValue[MAX_VALUE_LEN] = {0};
    size_t propLen;
    napi_get_value_string_utf8(env, value, propValue, MAX_VALUE_LEN, &propLen);
    return std::string(propValue);
}

void ParseAsyncContextFromArgs(napi_env env, napi_callback_info cbInfo, DistributedAccountAsyncContext *asyncContext,
    bool isUpdate)
{
    ACCOUNT_LOGI("enter");
    size_t argc = isUpdate ? UPDATE_ARGC : QUERY_ARGC;
    napi_value argv[UPDATE_ARGC] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_object) {
            asyncContext->name = GetNamedProperty(env, argv[i], PROPERTY_KEY_NAME);
            asyncContext->id = GetNamedProperty(env, argv[i], PROPERTY_KEY_ID);
            asyncContext->event = GetNamedProperty(env, argv[i], PROPERTY_KEY_EVENT);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("type mismatch");
        }
    }
}

void ProcessCallbackOrPromise(napi_env env, DistributedAccountAsyncContext *asyncContext, napi_value err,
    napi_value data)
{
    napi_value args[RESULT_COUNT] = { err, data };
    if (asyncContext->deferred) {
        ACCOUNT_LOGI("Promise");
        if (asyncContext->status == napi_ok) {
            napi_resolve_deferred(env, asyncContext->deferred, args[1]);
        } else {
            napi_reject_deferred(env, asyncContext->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, args, &returnVal);
        napi_delete_reference(env, asyncContext->callbackRef);
    }
}

void ProcessSetNamedProperty(napi_env env, DistributedAccountAsyncContext *asyncContext)
{
    napi_value result[RESULT_COUNT] = {0};
    if (asyncContext->status == napi_ok) {
        napi_get_undefined(env, &result[0]);
        napi_create_object(env, &result[1]);
        napi_value value = nullptr;
        napi_create_string_utf8(env, asyncContext->name.c_str(), asyncContext->name.size(), &value);
        napi_set_named_property(env, result[1], PROPERTY_KEY_NAME.c_str(), value);
        napi_create_string_utf8(env, asyncContext->id.c_str(), asyncContext->id.size(), &value);
        napi_set_named_property(env, result[1], PROPERTY_KEY_ID.c_str(), value);
        napi_create_string_utf8(env, asyncContext->event.c_str(), asyncContext->event.size(), &value);
        napi_set_named_property(env, result[1], PROPERTY_KEY_EVENT.c_str(), value);
        napi_value scalable = nullptr;
        napi_create_object(env, &scalable);
        for (const auto &[key, value]:asyncContext->scalableData) {
            napi_value jsValue = nullptr;
            napi_create_string_utf8(env, value.c_str(), value.size(), &jsValue);
            napi_set_named_property(env, scalable, key.c_str(), jsValue);
        }
        napi_set_named_property(env, result[1], PROPERTY_KEY_SCALABLE.c_str(), scalable);
    } else {
        napi_value message = nullptr;
        napi_create_string_utf8(env, "query ohos account info failed", NAPI_AUTO_LENGTH, &message);
        napi_create_error(env, nullptr, message, &result[0]);
        napi_get_undefined(env, &result[1]);
    }
    ProcessCallbackOrPromise(env, asyncContext, result[0], result[1]);
}
}

napi_ref NapiDistributedAccount::constructorRef_;

napi_value NapiDistributedAccount::Init(napi_env env, napi_value exports)
{
    ACCOUNT_LOGI("enter");
    napi_property_descriptor descriptor[] = {
        DECLARE_NAPI_FUNCTION("getDistributedAccountAbility", GetDistributedAccountAbility),
    };
    napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor);

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("queryOsAccountDistributedInfo", QueryOhosAccountInfo),
        DECLARE_NAPI_FUNCTION("updateOsAccountDistributedInfo", UpdateOsAccountDistributedInfo),
    };
    napi_value cons = nullptr;
    napi_define_class(env, DISTRIBUTED_ACCOUNT_CLASS_NAME.c_str(), DISTRIBUTED_ACCOUNT_CLASS_NAME.size(),
        JsConstructor, nullptr, sizeof(properties) / sizeof(napi_property_descriptor), properties, &cons);
    napi_create_reference(env, cons, 1, &constructorRef_);
    napi_set_named_property(env, exports, DISTRIBUTED_ACCOUNT_CLASS_NAME.c_str(), cons);

    return exports;
}

napi_value NapiDistributedAccount::JsConstructor(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiDistributedAccount::GetDistributedAccountAbility(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    napi_value instance = nullptr;
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, constructorRef_, &cons) != napi_ok) {
        return nullptr;
    }

    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        return nullptr;
    }

    return instance;
}

napi_value NapiDistributedAccount::QueryOhosAccountInfo(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    auto *asyncContext = new DistributedAccountAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseAsyncContextFromArgs(env, cbInfo, asyncContext, false);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "QueryOhosAccountInfo", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            DistributedAccountAsyncContext *asyncContext = (DistributedAccountAsyncContext*)data;
            std::pair<bool, OhosAccountInfo> accountInfo = OhosAccountKits::GetInstance().QueryOhosAccountInfo();
            if (accountInfo.first) {
                asyncContext->name = accountInfo.second.name_;
                asyncContext->id = accountInfo.second.uid_;
                asyncContext->event = "";
                asyncContext->scalableData = {};
                asyncContext->status = napi_ok;
            } else {
                asyncContext->status = napi_generic_failure;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            DistributedAccountAsyncContext *asyncContext = (DistributedAccountAsyncContext*)data;
            ProcessSetNamedProperty(env, asyncContext);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
        },
        (void*)asyncContext, &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);

    return result;
}

napi_value NapiDistributedAccount::UpdateOsAccountDistributedInfo(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    auto *asyncContext = new DistributedAccountAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseAsyncContextFromArgs(env, cbInfo, asyncContext, true);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "UpdateOsAccountDistributedInfo", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            DistributedAccountAsyncContext *asyncContext = (DistributedAccountAsyncContext*)data;
            asyncContext->status = OhosAccountKits::GetInstance().UpdateOhosAccountInfo(asyncContext->name,
                asyncContext->id, asyncContext->event) ? napi_ok : napi_generic_failure;
        },
        [](napi_env env, napi_status status, void *data) {
            DistributedAccountAsyncContext *asyncContext = (DistributedAccountAsyncContext*)data;
            napi_value result[RESULT_COUNT] = {0};
            if (asyncContext->status == napi_ok) {
                napi_get_undefined(env, &result[0]);
                napi_get_undefined(env, &result[1]);
            } else {
                napi_value message = nullptr;
                napi_create_string_utf8(env, "Update os account distributedInfo failed", NAPI_AUTO_LENGTH, &message);
                napi_create_error(env, nullptr, message, &result[0]);
                napi_get_undefined(env, &result[1]);
            }
            ProcessCallbackOrPromise(env, asyncContext, result[0], result[1]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
        },
        (void*)asyncContext, &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);

    return result;
}
} // namespace AccountJsKit
} // namespace OHOS

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports)
{
    return OHOS::AccountJsKit::NapiDistributedAccount::Init(env, exports);
}
EXTERN_C_END

/*
 * module define
 */
static napi_module _module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "account.distributedAccount",
    .nm_priv = ((void*)0),
    .reserved = {0}
};
/*
 * module register
 */
extern "C" __attribute__((constructor)) void Register()
{
    napi_module_register(&_module);
}
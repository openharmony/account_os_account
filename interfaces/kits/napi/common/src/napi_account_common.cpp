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
#include "ipc_skeleton.h"
#include "napi_account_common.h"

#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi_account_error.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AccountJsKit {
namespace {
constexpr int32_t BUSINESS_ERROR_ARG_SIZE = 2;
}

void ProcessCallbackOrPromise(napi_env env, const CommonAsyncContext *asyncContext, napi_value err, napi_value data)
{
    napi_value args[BUSINESS_ERROR_ARG_SIZE] = {0};
    if (asyncContext->errCode == ERR_OK) {
        napi_get_null(env, &args[0]);
        args[1] = data;
    } else {
        napi_get_null(env, &args[1]);
        args[0] = err;
    }
    if (asyncContext->deferred) {
        if (asyncContext->errCode == ERR_OK) {
            napi_resolve_deferred(env, asyncContext->deferred, args[1]);
        } else {
            napi_reject_deferred(env, asyncContext->deferred, args[0]);
        }
    } else {
        napi_value callback = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, BUSINESS_ERROR_ARG_SIZE, &args[0], &returnVal);
        if (asyncContext->callbackRef != nullptr) {
            napi_delete_reference(env, asyncContext->callbackRef);
        }
    }
}

bool GetIntProperty(napi_env env, napi_value obj, int32_t &property)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, obj, &valueType), false);
    if (valueType != napi_number) {
        return false;
    }

    NAPI_CALL_BASE(env, napi_get_value_int32(env, obj, &property), false);
    return true;
}

bool GetLongIntProperty(napi_env env, napi_value obj, int64_t &property)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, obj, &valueType), false);
    if (valueType != napi_number) {
        return false;
    }

    NAPI_CALL_BASE(env, napi_get_value_int64(env, obj, &property), false);
    return true;
}

bool GetBoolProperty(napi_env env, napi_value obj, bool &property)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, obj, &valueType), false);
    if (valueType != napi_boolean) {
        return false;
    }
    NAPI_CALL_BASE(env, napi_get_value_bool(env, obj, &property), false);
    return true;
}

bool GetStringProperty(napi_env env, napi_value obj, std::string &property)
{
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, obj, &valuetype), false);
    if (valuetype != napi_string) {
        return false;
    }

    size_t propLen;
    NAPI_CALL_BASE(env, napi_get_value_string_utf8(env, obj, nullptr, 0, &propLen), false);
    property.reserve(propLen + 1);
    property.resize(propLen);
    NAPI_CALL_BASE(env, napi_get_value_string_utf8(env, obj, property.data(), propLen + 1, &propLen), false);
    return true;
}

bool GetStringArrayProperty(napi_env env, napi_value obj, std::vector<std::string> &property, bool allowEmpty)
{
    bool isArray = false;
    NAPI_CALL_BASE(env, napi_is_array(env, obj, &isArray), false);
    if (!isArray) {
        return false;
    }
    uint32_t length = 0;
    NAPI_CALL_BASE(env, napi_get_array_length(env, obj, &length), false);
    if (!allowEmpty && (length == 0)) {
        return false;
    }

    for (size_t i = 0; i < length; i++) {
        napi_value strJs = nullptr;
        NAPI_CALL_BASE(env, napi_get_element(env, obj, i, &strJs), false);
        std::string str;
        if (!GetStringProperty(env, strJs, str)) {
            return false;
        }
        property.emplace_back(str);
    }
    return true;
}

bool GetCallbackProperty(napi_env env, napi_value obj, napi_ref &property, int argNum)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, obj, &valueType), false);
    if (valueType != napi_function) {
        return false;
    }
    NAPI_CALL_BASE(env, napi_create_reference(env, obj, argNum, &property), false);
    return true;
}

bool GetStringPropertyByKey(napi_env env, napi_value obj, const std::string &propertyName, std::string &property)
{
    napi_value value = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, obj, propertyName.c_str(), &value), false);

    return GetStringProperty(env, value, property);
}

bool GetOptionalStringPropertyByKey(napi_env env, napi_value obj, const std::string &propertyName,
    std::string &property)
{
    bool hasProp = false;
    napi_has_named_property(env, obj, propertyName.c_str(), &hasProp);
    if (!hasProp) {
        return true;
    }

    return GetStringPropertyByKey(env, obj, propertyName, property);
}

bool IsSystemApp(napi_env env)
{
    uint64_t tokenId = IPCSkeleton::GetSelfTokenID();
    bool isSystemApp = Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
    if (!isSystemApp) {
        std::string errMsg = ConvertToJsErrMsg(ERR_JS_IS_NOT_SYSTEM_APP);
        AccountNapiThrow(env, ERR_JS_IS_NOT_SYSTEM_APP, errMsg, true);
        return false;
    }
    return true;
}

napi_value CreateStringArray(napi_env env, const std::vector<std::string> &strVec)
{
    napi_value result = nullptr;
    napi_create_array(env, &result);
    for (size_t i = 0; i < strVec.size(); ++i) {
        napi_value value = nullptr;
        napi_create_string_utf8(env, strVec[i].c_str(), NAPI_AUTO_LENGTH, &value);
        napi_set_element(env, result, i, value);
    }
    return result;
}
} // namespace AccountJsKit
} // namespace OHOS
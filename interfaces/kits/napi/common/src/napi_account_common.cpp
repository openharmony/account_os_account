/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "account_log_wrapper.h"
#include "bundle_mgr_proxy.h"
#include "iservice_registry.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi_account_error.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "securec.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AccountJsKit {
namespace {
constexpr int32_t BUSINESS_ERROR_ARG_SIZE = 2;
const char BUSINESS_ERROR_CODE_NAME[] = "code";
const char BUSINESS_ERROR_DATA_NAME[] = "data";
}

using namespace AccountSA;

CommonAsyncContext::~CommonAsyncContext()
{
    if (env == nullptr) {
        return;
    }
    if (callbackRef != nullptr) {
        napi_delete_reference(env, callbackRef);
        callbackRef = nullptr;
    }
    if (work != nullptr) {
        napi_delete_async_work(env, work);
        work = nullptr;
    }
}

void ProcessCallbackOrPromise(napi_env env, const CommonAsyncContext *asyncContext, napi_value err, napi_value data)
{
    napi_value args[BUSINESS_ERROR_ARG_SIZE] = {0};
    if (asyncContext->errCode == ERR_OK) {
        napi_get_null(env, &args[0]);
        args[1] = data;
    } else {
        napi_get_null(env, &args[1]);
        if (!asyncContext->nativeErrMsg.empty()) {
            napi_value errMsgJs = nullptr;
            napi_create_string_utf8(env, asyncContext->nativeErrMsg.c_str(), NAPI_AUTO_LENGTH, &errMsgJs);
            napi_set_named_property(env, err, "message", errMsgJs);
        }
        args[0] = err;
    }
    if (asyncContext->deferred) {
        if (asyncContext->errCode == ERR_OK) {
            napi_resolve_deferred(env, asyncContext->deferred, args[1]);
        } else {
            napi_reject_deferred(env, asyncContext->deferred, args[0]);
        }
    } else {
        NapiCallVoidFunction(env, args, BUSINESS_ERROR_ARG_SIZE, asyncContext->callbackRef);
    }
}

void ProcessCallbackOrPromise(napi_env env, const NapiAsyncContext *asyncContext, napi_value err, napi_value data)
{
    CommonAsyncContext tempAsyncContext;
    tempAsyncContext.errCode = asyncContext->errCode;
    tempAsyncContext.nativeErrMsg = asyncContext->nativeErrMsg;
    tempAsyncContext.deferred = asyncContext->deferred;

    if (asyncContext->callbackRef != nullptr) {
        tempAsyncContext.callbackRef = asyncContext->callbackRef->callbackRef;
    }
    ProcessCallbackOrPromise(env, &tempAsyncContext, err, data);
    // callbackRef should not released, which is controlled by asyncContext.
    tempAsyncContext.callbackRef = nullptr;
}

void ReturnCallbackOrPromise(napi_env env, const CommonAsyncContext *asyncContext, napi_value err, napi_value data)
{
    napi_value args[BUSINESS_ERROR_ARG_SIZE] = {err, data};
    if (asyncContext->errCode == ERR_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &args[0]));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &args[1]));
    }
    if (asyncContext->deferred != nullptr) {
        if (asyncContext->errCode == ERR_OK) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred, args[1]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncContext->deferred, args[0]));
        }
        return;
    }
    if (asyncContext->callbackRef != nullptr) {
        NapiCallVoidFunction(env, args, BUSINESS_ERROR_ARG_SIZE, asyncContext->callbackRef);
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

bool GetOptionIntProperty(napi_env env, napi_value obj, int32_t &property, bool &hasProperty)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, obj, &valueType), false);
    if ((valueType == napi_undefined) || (valueType == napi_null)) {
        ACCOUNT_LOGI("This value is undefined or null");
        return true;
    }
    if (valueType != napi_number) {
        return false;
    }
    NAPI_CALL_BASE(env, napi_get_value_int32(env, obj, &property), false);
    hasProperty = true;
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

bool GetStringArrayPropertyByKey(napi_env env, napi_value obj, const std::string &propertyName,
    std::vector<std::string> &property, bool allowEmpty)
{
    napi_value value = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, obj, propertyName.c_str(), &value), false);
    return GetStringArrayProperty(env, value, property, allowEmpty);
}

bool GetCallbackProperty(napi_env env, napi_value obj, napi_ref &property, int argNum)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, obj, &valueType), false);
    if ((valueType == napi_undefined) || (valueType == napi_null)) {
        ACCOUNT_LOGI("the callback is undefined or null");
        return true;
    } else if (valueType == napi_function) {
        NAPI_CALL_BASE(env, napi_create_reference(env, obj, argNum, &property), false);
        return true;
    }
    ACCOUNT_LOGE("the callback is not a napi_function");
    return false;
}

bool GetStringPropertyByKey(napi_env env, napi_value obj, const std::string &propertyName, std::string &property)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, obj, &valueType);
    if (valueType != napi_object) {
        ACCOUNT_LOGE("Obj is not an object");
        return false;
    }
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
    napi_value value = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, obj, propertyName.c_str(), &value), false);
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valuetype), false);
    if ((valuetype == napi_undefined) || (valuetype == napi_null)) {
        ACCOUNT_LOGI("this key's value is undefined or null");
        return true;
    }
    return GetStringProperty(env, value, property);
}

bool GetOptionalStringPropertyByKey(napi_env env, napi_value obj, const std::string &propertyName,
    std::string &property, bool &hasProperty)
{
    bool hasProp = false;
    napi_has_named_property(env, obj, propertyName.c_str(), &hasProp);
    if (!hasProp) {
        return true;
    }
    napi_value value = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, obj, propertyName.c_str(), &value), false);
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valuetype), false);
    if ((valuetype == napi_undefined) || (valuetype == napi_null)) {
        ACCOUNT_LOGI("this key's value is undefined or null");
        return true;
    }
    if (!GetStringProperty(env, value, property)) {
        return false;
    }
    hasProperty = true;
    return true;
}

bool IsOptionalPropertyExist(napi_env env, napi_value obj, const std::string &propertyName)
{
    bool hasProp = false;
    napi_has_named_property(env, obj, propertyName.c_str(), &hasProp);
    if (!hasProp) {
        return false;
    }
    napi_value value = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, obj, propertyName.c_str(), &value), false);
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valuetype), false);
    if ((valuetype == napi_undefined) || (valuetype == napi_null)) {
        ACCOUNT_LOGI("This key's value is undefined or null");
        return false;
    }
    return true;
}

bool GetOptionalNumberPropertyByKey(napi_env env, napi_value obj, const std::string &propertyName,
    int32_t &numberProperty, bool &hasProperty)
{
    bool hasProp = false;
    napi_has_named_property(env, obj, propertyName.c_str(), &hasProp);
    if (!hasProp) {
        ACCOUNT_LOGI("This property has no '%{public}s' key", propertyName.c_str());
        return true;
    }
    napi_value value = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, obj, propertyName.c_str(), &value), false);
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valuetype), false);
    if ((valuetype == napi_undefined) || (valuetype == napi_null)) {
        ACCOUNT_LOGI("This key's value is undefined or null");
        return true;
    }
    if (!GetIntProperty(env, value, numberProperty)) {
        return false;
    }
    hasProperty = true;
    return true;
}

bool CompareOnAndOffRef(const napi_env env, napi_ref subscriberRef, napi_ref unsubscriberRef)
{
    napi_value subscriberCallback;
    napi_get_reference_value(env, subscriberRef, &subscriberCallback);
    napi_value unsubscriberCallback;
    napi_get_reference_value(env, unsubscriberRef, &unsubscriberCallback);
    bool result = false;
    napi_strict_equals(env, subscriberCallback, unsubscriberCallback, &result);
    return result;
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
napi_value CreateUint8Array(napi_env env, const uint8_t *srcData, size_t length)
{
    napi_value result = nullptr;
    void* dstData = nullptr;
    napi_value napiArr = nullptr;
    NAPI_CALL(env, napi_create_arraybuffer(env, length, &dstData, &napiArr));
    if ((length > 0) && (memcpy_s(dstData, length, srcData, length) != EOK)) {
        ACCOUNT_LOGE("Memcpy_s failed");
        return result;
    }
    NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, length, napiArr, 0, &result));
    return result;
}

napi_status ParseUint8TypedArray(napi_env env, napi_value value, uint8_t **data, size_t *length)
{
    *data = nullptr;
    *length = 0;
    bool isTypedArray = false;
    napi_is_typedarray(env, value, &isTypedArray);
    if (!isTypedArray) {
        ACCOUNT_LOGE("invalid uint8 array");
        return napi_ok;
    }
    napi_typedarray_type arrayType = static_cast<napi_typedarray_type>(-1);  // -1 indicates invalid type
    napi_value buffer = nullptr;
    size_t offset = 0;
    napi_get_typedarray_info(env, value, &arrayType, length, reinterpret_cast<void **>(data), &buffer, &offset);
    if (arrayType != napi_uint8_array) {
        ACCOUNT_LOGE("invalid uint8 array");
        *data = nullptr;
        *length = 0;
    }
    return napi_ok;
}

napi_status ParseUint8TypedArrayToVector(napi_env env, napi_value value, std::vector<uint8_t> &vec)
{
    uint8_t *data = nullptr;
    size_t length = 0;
    napi_status status = ParseUint8TypedArray(env, value, &data, &length);
    if (status != napi_ok) {
        ACCOUNT_LOGE("failed to ParseUint8TypedArray");
        return status;
    }
    vec.assign(data, data + length);
    return napi_ok;
}

napi_status ParseUint8TypedArrayToUint64(napi_env env, napi_value value, uint64_t &result)
{
    uint8_t *data = nullptr;
    size_t length = 0;
    napi_status status = ParseUint8TypedArray(env, value, &data, &length);
    if (status != napi_ok) {
        ACCOUNT_LOGE("failed to ParseUint8TypedArray");
        return status;
    }
    if (data == nullptr) {
        result = 0;
        return napi_invalid_arg;
    }
    if (length != sizeof(uint64_t)) {
        ACCOUNT_LOGE("failed to convert to uint64_t value");
        return napi_invalid_arg;
    }
    result = *(reinterpret_cast<uint64_t *>(data));
    return napi_ok;
}

napi_status ParseUint8ArrayToNativeUint8Array(napi_env env, napi_value value, uint8_t **data, size_t *length)
{
    *data = nullptr;
    *length = 0;
    bool isTypedArray = false;
    napi_is_typedarray(env, value, &isTypedArray);
    if (!isTypedArray) {
        ACCOUNT_LOGE("Invalid uint8 array");
        return napi_invalid_arg;
    }
    napi_typedarray_type arrayType = static_cast<napi_typedarray_type>(-1);  // -1 indicates invalid type
    napi_value buffer = nullptr;
    size_t offset = 0;
    napi_get_typedarray_info(env, value, &arrayType, length, reinterpret_cast<void **>(data), &buffer, &offset);
    if (arrayType != napi_uint8_array) {
        ACCOUNT_LOGE("Invalid uint8 array");
        *data = nullptr;
        *length = 0;
        return napi_invalid_arg;
    }
    return napi_ok;
}

bool ParseBusinessError(napi_env env, napi_value value, BusinessError &error)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valueType), false);
    if (valueType == napi_null || (valueType == napi_undefined)) {
        error.code = 0;
        return true;
    }
    napi_value napiCode = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, BUSINESS_ERROR_CODE_NAME, &napiCode), false);
    if (napiCode == nullptr) {
        ACCOUNT_LOGE("code is undefined");
        return false;
    }
    NAPI_CALL_BASE(env, napi_get_value_int32(env, napiCode, &error.code), false);
    bool hasData = false;
    napi_has_named_property(env, value, BUSINESS_ERROR_DATA_NAME, &hasData);
    if (hasData) {
        napi_value napiData = nullptr;
        napi_get_named_property(env, value, BUSINESS_ERROR_DATA_NAME, &napiData);
        return GetStringProperty(env, napiData, error.data);
    }
    return true;
}

bool GetNamedJsFunction(napi_env env, napi_value object, const std::string &name, napi_ref &callback)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, object, &valueType), false);
    if (valueType != napi_object) {
        ACCOUNT_LOGE("invalid object");
        return false;
    }
    napi_value result = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, object, name.c_str(), &result), false);
    return GetCallbackProperty(env, result, callback, 1);
}

void NapiCallVoidFunction(napi_env env, napi_value *argv, size_t argc, napi_ref funcRef)
{
    napi_value undefined = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    napi_value returnVal;
    napi_value func = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, funcRef, &func));
    napi_status status = napi_call_function(env, undefined, func, argc, argv, &returnVal);
    ACCOUNT_LOGI("call js function finish, status: %{public}d", status);
}

void SetInt32ToJsProperty(napi_env env, int32_t number, const std::string &propertyName, napi_value &dataJs)
{
    napi_value napiNum = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, number, &napiNum));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, dataJs, propertyName.c_str(), napiNum));
}

napi_value CreateAuthResult(
    napi_env env, const std::vector<uint8_t> &token, int32_t remainTimes, int32_t freezingTime)
{
    napi_value object = nullptr;
    NAPI_CALL(env, napi_create_object(env, &object));
    if (remainTimes >= 0) {
        napi_value napiRemainTimes = 0;
        NAPI_CALL(env, napi_create_uint32(env, remainTimes, &napiRemainTimes));
        NAPI_CALL(env, napi_set_named_property(env, object, "remainTimes", napiRemainTimes));
    }
    if (freezingTime >= 0) {
        napi_value napiFreezingTimes = 0;
        NAPI_CALL(env, napi_create_uint32(env, freezingTime, &napiFreezingTimes));
        NAPI_CALL(env, napi_set_named_property(env, object, "freezingTime", napiFreezingTimes));
    }
    if (token.size() > 0) {
        napi_value napiToken = CreateUint8Array(env, token.data(), token.size());
        NAPI_CALL(env, napi_set_named_property(env, object, "token", napiToken));
    }
    return object;
}

void ReleaseNapiRefAsync(napi_env env, napi_ref napiRef)
{
    ReleaseNapiRefArray(env, {napiRef});
}

void ReleaseNapiRefArray(napi_env env, const std::vector<napi_ref> &napiRefVec)
{
    if (env == nullptr) {
        ACCOUNT_LOGE("invalid env");
        return;
    }
    std::shared_ptr<NapiRefArrayContext> context = std::make_shared<NapiRefArrayContext>();
    context->env = env;
    context->napiRefVec = napiRefVec;
    NAPI_CALL_RETURN_VOID(env, napi_send_event(env,
        [context = std::move(context)] () {
            if (context == nullptr) {
                ACCOUNT_LOGE("context is nullptr");
                return;
            }
            for (auto &napiRef : context->napiRefVec) {
                if (napiRef != nullptr) {
                    napi_delete_reference(context->env, napiRef);
                }
            }
        }, napi_eprio_vip));
}

NapiCallbackRef::~NapiCallbackRef()
{
    if (callbackRef == nullptr) {
        return;
    }
    ReleaseNapiRefArray(env, {callbackRef});
    callbackRef = nullptr;
}

bool JsObjectToNativeString(napi_env env, napi_value jsData, std::string &nativeData)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, jsData, &valueType);
    if (valueType != napi_object) {
        ACCOUNT_LOGI("The parameters is not object");
        return false;
    }
    napi_value globalValue = nullptr;
    napi_get_global(env, &globalValue);
    napi_value jsonValue;
    napi_get_named_property(env, globalValue, "JSON", &jsonValue);

    napi_value stringifyValue = nullptr;
    napi_get_named_property(env, jsonValue, "stringify", &stringifyValue);
    napi_value funcArgv[1] = { jsData };
    napi_value transValue = nullptr;
    napi_status status = napi_call_function(env, jsonValue, stringifyValue, 1, funcArgv, &transValue);
    if (status != napi_ok) {
        ACCOUNT_LOGE("Fail to call function, %{public}d", status);
        return false;
    }

    if (!GetStringProperty(env, transValue, nativeData)) {
        ACCOUNT_LOGE("Get native data failed");
        std::string errMsg = "The type of arg 2 must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, false);
        return false;
    }
    return true;
}

napi_value NativeStringToJsObject(napi_env env, const std::string &nativeData)
{
    napi_value jsObjData = nullptr;
    if (nativeData.empty()) {
        napi_create_object(env, &jsObjData);
        return jsObjData;
    }
    napi_value globalValue = nullptr;
    napi_get_global(env, &globalValue);
    napi_value jsonValue;
    napi_get_named_property(env, globalValue, "JSON", &jsonValue);
    napi_value parseValue = nullptr;
    napi_get_named_property(env, jsonValue, "parse", &parseValue);
    napi_value jsStringDate = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, nativeData.c_str(), NAPI_AUTO_LENGTH, &jsStringDate));
    napi_value funcArgv[1] = { jsStringDate };
    napi_status status = napi_call_function(env, jsonValue, parseValue, 1, funcArgv, &jsObjData);
    if (status != napi_ok) {
        ACCOUNT_LOGE("Fail to call function, status: %{public}d", status);
    }
    return jsObjData;
}

bool GetSelfTargetVersion(uint32_t &targetVersion)
{
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        ACCOUNT_LOGE("Samgr error");
        return false;
    }
    auto bundleObj = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleObj == nullptr) {
        ACCOUNT_LOGE("BundleObj error");
        return false;
    }
    auto bundleMgrProxy = iface_cast<AppExecFwk::IBundleMgr>(bundleObj);
    if (bundleMgrProxy == nullptr) {
        ACCOUNT_LOGE("BundleMgrProxy error");
        return false;
    }
    AppExecFwk::BundleInfo bundleInfo;
    ErrCode ret = bundleMgrProxy->GetBundleInfoForSelf(OHOS::AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("GetBundleInfoForSelf error");
        return false;
    }
    ACCOUNT_LOGI("Bundle targetVersion is %{public}d", bundleInfo.targetVersion);
    targetVersion = bundleInfo.targetVersion;
    return true;
}
} // namespace AccountJsKit
} // namespace OHOS
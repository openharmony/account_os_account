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

#include "napi_account_iam_common.h"

#include <map>

#include <uv.h>
#include "account_error_no.h"
#include "account_iam_info.h"
#include "account_log_wrapper.h"
#include "napi_account_error.h"
#include "napi_account_common.h"
#include "napi_account_iam_constant.h"
#include "securec.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;

static int32_t AccountIAMConvertOtherToJSErrCode(int32_t errCode)
{
    switch (errCode) {
        case ERR_IAM_SUCCESS:
            return ERR_JS_SUCCESS;
        case ERR_IAM_FAIL:
        case ERR_IAM_TOKEN_TIMEOUT:
        case ERR_IAM_TOKEN_AUTH_FAILED:
            return ERR_JS_AUTH_CREDENTIAL_WRONG_ERROR;
        case ERR_IAM_TRUST_LEVEL_NOT_SUPPORT:
            return ERR_JS_TRUST_LEVEL_NOT_SUPPORTED;
        case ERR_IAM_TYPE_NOT_SUPPORT:
            return ERR_JS_AUTH_TYPE_NOT_SUPPORTED;
        case ERR_IAM_TIMEOUT:
            return ERR_JS_AUTH_TIMEOUT;
        case ERR_IAM_CANCELED:
            return ERR_JS_AUTH_CANCELLED;
        case ERR_IAM_BUSY:
            return ERR_JS_AUTH_SERVICE_BUSY;
        case ERR_IAM_LOCKED:
            return ERR_JS_AUTH_SERVICE_LOCKED;
        case ERR_IAM_NOT_ENROLLED:
            return ERR_JS_CREDENTIAL_NOT_EXIST;
        case ERR_IAM_PIN_IS_EXPIRED:
            return ERR_JS_PIN_IS_EXPIRED;
        case ERR_IAM_COMPLEXITY_CHECK_FAILED:
            return ERR_JS_COMPLEXITY_CHECK_FAILED;
        case ERR_IAM_INVALID_CONTEXT_ID:
            return ERR_JS_INVALID_CONTEXT_ID;
        case ERR_ACCOUNT_COMMON_INVALID_PARAMETER:
        case ERR_IAM_INVALID_PARAMETERS:
            return ERR_JS_INVALID_PARAMETER;
        case ERR_ACCOUNT_IAM_KIT_INPUTER_ALREADY_REGISTERED:
            return ERR_JS_CREDENTIAL_INPUTER_ALREADY_EXIST;
        case ERR_ACCOUNT_IAM_KIT_INPUTER_NOT_REGISTERED:
            return ERR_JS_CREDENTIAL_INPUTER_NOT_EXIST;
        case ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE:
        case ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT:
            return ERR_JS_AUTH_TYPE_NOT_SUPPORTED;
        case ERR_IAM_CREDENTIAL_NUMBER_REACH_LIMIT:
            return ERR_JS_CREDENTIAL_NUMBER_REACH_LIMIT;
        case ERR_IAM_SESSION_TIMEOUT:
            return ERR_JS_SESSION_TIMEOUT;
        default:
            return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
    }
}

int32_t AccountIAMConvertToJSErrCode(int32_t errCode)
{
    if (CheckJsErrorCode(errCode)) {
        return errCode;
    }
    if (errCode == ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR) {
        return ERR_JS_IS_NOT_SYSTEM_APP;
    } else if (errCode == ERR_ACCOUNT_COMMON_PERMISSION_DENIED || errCode == ERR_IAM_CHECK_PERMISSION_FAILED) {
        return ERR_JS_PERMISSION_DENIED;
    } else if (errCode == ERR_ACCOUNT_COMMON_INVALID_PARAMETER) {
        return ERR_JS_INVALID_PARAMETER;
    } else if (errCode == ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR) {
        return ERR_JS_ACCOUNT_NOT_FOUND;
    }
    return AccountIAMConvertOtherToJSErrCode(errCode);
}

#ifdef HAS_USER_AUTH_PART
NapiIDMCallback::NapiIDMCallback(napi_env env, const std::shared_ptr<JsIAMCallback> &callback)
    : env_(env), callback_(callback)
{}

NapiIDMCallback::~NapiIDMCallback()
{}

static void OnIDMResultWork(uv_work_t* work, int status)
{
    ACCOUNT_LOGI("enter");
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<IDMCallbackParam> param(reinterpret_cast<IDMCallbackParam *>(work->data));
    napi_value argv[ARG_SIZE_TWO] = {0};
    napi_create_int32(param->env, AccountIAMConvertToJSErrCode(param->result), &argv[PARAM_ZERO]);
    napi_create_object(param->env, &argv[PARAM_ONE]);
    napi_value credentialId = CreateUint8Array(
        param->env, reinterpret_cast<uint8_t *>(&param->credentialId), sizeof(uint64_t));
    napi_set_named_property(param->env, argv[PARAM_ONE], "credentialId", credentialId);
    NapiCallVoidFunction(param->env, argv, ARG_SIZE_TWO, param->callback->onResult);
    napi_close_handle_scope(param->env, scope);
}

void NapiIDMCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callback_->onResultCalled) {
        ACCOUNT_LOGE("call twice is not allowed");
        return;
    }
    callback_->onResultCalled = true;
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<IDMCallbackParam> param = std::make_unique<IDMCallbackParam>(env_);
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr || work == nullptr || param == nullptr) {
        ACCOUNT_LOGE("fail for nullptr");
        return;
    }
    param->result = result;
    extraInfo.GetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, param->credentialId);
    param->callback = callback_;
    work->data = reinterpret_cast<void *>(param.get());
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work_with_qos(
        loop, work.get(), [] (uv_work_t *work) {}, OnIDMResultWork, uv_qos_user_initiated));
    ACCOUNT_LOGI("create idm result work finish");
    work.release();
    param.release();
}

static void OnAcquireInfoWork(uv_work_t* work, int status)
{
    ACCOUNT_LOGI("enter");
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<IDMCallbackParam> param(reinterpret_cast<IDMCallbackParam *>(work->data));
    napi_value argv[ARG_SIZE_THREE] = {0};
    napi_env env = param->env;
    napi_create_int32(env, param->module, &argv[PARAM_ZERO]);
    napi_create_int32(env, param->acquire, &argv[PARAM_ONE]);
    argv[PARAM_TWO] = CreateUint8Array(env, param->extraInfo.data(), param->extraInfo.size());
    NapiCallVoidFunction(env, argv, ARG_SIZE_THREE, param->callback->onAcquireInfo);
    napi_close_handle_scope(env, scope);
}

void NapiIDMCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!callback_->hasOnAcquireInfo) {
        ACCOUNT_LOGE("no 'OnAcquireInfo' callback need return");
        return;
    }
    if (callback_->onResultCalled) {
        ACCOUNT_LOGE("call after OnResult is not allowed");
        return;
    }
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<IDMCallbackParam> param = std::make_unique<IDMCallbackParam>(env_);
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr || work == nullptr || param == nullptr) {
        ACCOUNT_LOGE("fail for nullptr");
        return;
    }
    param->callback = callback_;
    param->module = module;
    param->acquire = acquireInfo;
    extraInfo.GetUint8ArrayValue(Attributes::AttributeKey::ATTR_EXTRA_INFO, param->extraInfo);
    work->data = reinterpret_cast<void *>(param.get());
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work_with_qos(
        loop, work.get(), [] (uv_work_t *work) { }, OnAcquireInfoWork, uv_qos_user_initiated));
    ACCOUNT_LOGI("create acquire info work finish");
    work.release();
    param.release();
}

napi_status ParseAddCredInfo(napi_env env, napi_value value, IDMContext &context)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    if (valueType != napi_object) {
        ACCOUNT_LOGE("value is not an object");
        return napi_invalid_arg;
    }
    napi_value result = nullptr;
    napi_get_named_property(env, value, "credType", &result);
    int32_t credType = -1;
    napi_get_value_int32(env, result, &credType);
    context.addCredInfo.authType = static_cast<AuthType>(credType);
    napi_get_named_property(env, value, "credSubType", &result);
    int32_t credSubType = -1;
    napi_get_value_int32(env, result, &credSubType);
    context.addCredInfo.pinType = static_cast<PinSubType>(credSubType);
    napi_get_named_property(env, value, "token", &result);
    if (ParseUint8TypedArrayToVector(env, result, context.addCredInfo.token) != napi_ok) {
        ACCOUNT_LOGE("Get Uint8Array data failed");
        return napi_invalid_arg;
    }
    if (!GetOptionalNumberPropertyByKey(env, value, "accountId", context.accountId, context.parseHasAccountId)) {
        ACCOUNT_LOGE("Get accountId data failed");
        return napi_invalid_arg;
    }
    return napi_ok;
}

napi_status ParseIAMCallback(napi_env env, napi_value object, std::shared_ptr<JsIAMCallback> &callback)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        ACCOUNT_LOGE("invalid object");
        return napi_invalid_arg;
    }
    napi_value result = nullptr;
    napi_get_named_property(env, object, "onResult", &result);
    napi_typeof(env, result, &valueType);
    if (valueType == napi_function) {
        NAPI_CALL_BASE(env, napi_create_reference(env, result, 1, &callback->onResult), napi_generic_failure);
    } else {
        ACCOUNT_LOGE("onResult is not a function");
        return napi_invalid_arg;
    }
    napi_has_named_property(env, object, "onAcquireInfo", &callback->hasOnAcquireInfo);
    if (!callback->hasOnAcquireInfo) {
        return napi_ok;
    }
    napi_get_named_property(env, object, "onAcquireInfo", &result);
    napi_typeof(env, result, &valueType);
    if (valueType == napi_function) {
        NAPI_CALL_BASE(env, napi_create_reference(env, result, 1, &callback->onAcquireInfo), napi_generic_failure);
    } else if ((valueType == napi_undefined) || (valueType == napi_null)) {
        ACCOUNT_LOGI("onAcquireInfo is undefined or null");
    } else {
        ACCOUNT_LOGE("onAcquireInfo is not a function");
        return napi_invalid_arg;
    }
    return napi_ok;
}

napi_value CreateCredInfoArray(napi_env env, const std::vector<CredentialInfo> &info)
{
    napi_value arr = nullptr;
    napi_create_array_with_length(env, info.size(), &arr);
    uint32_t index = 0;
    for (auto item : info) {
        napi_value obj;
        NAPI_CALL(env, napi_create_object(env, &obj));
        napi_value credentialId = CreateUint8Array(
            env, reinterpret_cast<uint8_t *>(&item.credentialId), sizeof(uint64_t));
        napi_value authType;
        NAPI_CALL(env, napi_create_uint32(env, item.authType, &authType));
        napi_value napiPinType;
        PinSubType pinType = item.pinType.value_or(PinSubType::PIN_MAX);
        NAPI_CALL(env, napi_create_uint32(env, pinType, &napiPinType));
        napi_value templateId = CreateUint8Array(
            env, reinterpret_cast<uint8_t *>(&item.templateId), sizeof(uint64_t));
        NAPI_CALL(env, napi_set_named_property(env, obj, "credentialId", credentialId));
        NAPI_CALL(env, napi_set_named_property(env, obj, "authType", authType));
        NAPI_CALL(env, napi_set_named_property(env, obj, "authSubType", napiPinType));
        NAPI_CALL(env, napi_set_named_property(env, obj, "templateId", templateId));
        NAPI_CALL(env, napi_set_element(env, arr, index, obj));
        index++;
    }
    return arr;
}

napi_status ConvertGetPropertyTypeToAttributeKey(GetPropertyType in,
    Attributes::AttributeKey &out)
{
    static const std::map<GetPropertyType, Attributes::AttributeKey> type2Key = {
        { AUTH_SUB_TYPE, Attributes::AttributeKey::ATTR_PIN_SUB_TYPE },
        { REMAIN_TIMES, Attributes::AttributeKey::ATTR_REMAIN_TIMES },
        { FREEZING_TIME, Attributes::AttributeKey::ATTR_FREEZING_TIME },
        { ENROLLMENT_PROGRESS, Attributes::AttributeKey::ATTR_ENROLL_PROGRESS },
        { SENSOR_INFO, Attributes::AttributeKey::ATTR_SENSOR_INFO },
        { NEXT_PHASE_FREEZING_TIME, Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION },
    };

    auto iter = type2Key.find(in);
    if (iter == type2Key.end()) {
        ACCOUNT_LOGE("GetPropertyType %{public}d is invalid", in);
        return napi_invalid_arg;
    } else {
        out = iter->second;
    }
    return napi_ok;
}

napi_status ParseGetPropRequest(napi_env env, napi_value object, GetPropertyContext &context)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        ACCOUNT_LOGE("invalid object");
        return napi_invalid_arg;
    }
    napi_value napiAuthType = nullptr;
    napi_get_named_property(env, object, "authType", &napiAuthType);
    int32_t authType = -1;
    napi_get_value_int32(env, napiAuthType, &authType);
    context.request.authType = static_cast<AuthType>(authType);
    napi_value napiKeys = nullptr;
    napi_get_named_property(env, object, "keys", &napiKeys);
    std::vector<uint32_t> keys;
    ParseUInt32Array(env, napiKeys, keys);
    for (const auto &item : keys) {
        Attributes::AttributeKey key;
        napi_status status = ConvertGetPropertyTypeToAttributeKey(static_cast<GetPropertyType>(item), key);
        if (status != napi_ok) {
            ACCOUNT_LOGE("failed to convert get property type");
            return status;
        }
        context.request.keys.push_back(key);
    }
    if (!GetOptionalNumberPropertyByKey(env, object, "accountId", context.accountId, context.parseHasAccountId)) {
        ACCOUNT_LOGE("Get getPropRequest's accountId failed");
        return napi_invalid_arg;
    }
    return napi_ok;
}

napi_status ParseSetPropRequest(napi_env env, napi_value object, SetPropertyRequest &request)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        ACCOUNT_LOGE("invalid object");
        return napi_invalid_arg;
    }
    napi_value napiKey = nullptr;
    napi_get_named_property(env, object, "key", &napiKey);
    int32_t key = -1;
    napi_get_value_int32(env, napiKey, &key);
    request.mode = static_cast<PropertyMode>(key);
    napi_value napiAuthType = nullptr;
    napi_get_named_property(env, object, "authType", &napiAuthType);
    int32_t authType = -1;
    napi_get_value_int32(env, napiAuthType, &authType);
    request.authType = static_cast<AuthType>(authType);
    napi_value napiSetInfo = nullptr;
    napi_get_named_property(env, object, "setInfo", &napiSetInfo);
    std::vector<uint8_t> setInfo;
    ParseUint8TypedArrayToVector(env, napiSetInfo, setInfo);
    request.attrs.SetUint8ArrayValue(Attributes::AttributeKey(key), setInfo);
    return napi_ok;
}

static void GeneratePropertyJs(napi_env env, const GetPropertyContext &prop, napi_value &dataJs)
{
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &dataJs));
    napi_value napiResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, prop.result, &napiResult));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, dataJs, "result", napiResult));
    for (const auto &key : prop.request.keys) {
        switch (key) {
            case Attributes::AttributeKey::ATTR_PIN_SUB_TYPE: {
                SetInt32ToJsProperty(env, prop.authSubType, "authSubType", dataJs);
                break;
            }
            case Attributes::AttributeKey::ATTR_REMAIN_TIMES: {
                SetInt32ToJsProperty(env, prop.remainTimes, "remainTimes", dataJs);
                break;
            }
            case Attributes::AttributeKey::ATTR_FREEZING_TIME: {
                SetInt32ToJsProperty(env, prop.freezingTime, "freezingTime", dataJs);
                break;
            }
            case Attributes::AttributeKey::ATTR_ENROLL_PROGRESS: {
                napi_value napiEnrollmentProgress = nullptr;
                NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(
                    env, prop.enrollmentProgress.c_str(), NAPI_AUTO_LENGTH, &napiEnrollmentProgress));
                NAPI_CALL_RETURN_VOID(
                    env, napi_set_named_property(env, dataJs, "enrollmentProgress", napiEnrollmentProgress));
                break;
            }
            case Attributes::AttributeKey::ATTR_SENSOR_INFO: {
                napi_value napiSensorInfo = nullptr;
                NAPI_CALL_RETURN_VOID(env,
                    napi_create_string_utf8(env, prop.sensorInfo.c_str(), NAPI_AUTO_LENGTH, &napiSensorInfo));
                NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, dataJs, "sensorInfo", napiSensorInfo));
                break;
            }
            case Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION: {
                SetInt32ToJsProperty(env, prop.nextPhaseFreezingTime, "nextPhaseFreezingTime", dataJs);
                break;
            }
            default:
                break;
        }
    }
}

static void CreateExecutorProperty(napi_env env, GetPropertyContext &prop, napi_value &errJs, napi_value &dataJs)
{
    if (prop.result != ERR_OK && prop.result != ERR_IAM_NOT_ENROLLED) {
        prop.errCode = prop.result;
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(prop.result);
        errJs = GenerateBusinessError(env, jsErrCode, ConvertToJsErrMsg(jsErrCode));
        napi_get_null(env, &dataJs);
    } else {
        prop.errCode = 0;
        napi_get_null(env, &errJs);
        GeneratePropertyJs(env, prop, dataJs);
    }
}

static napi_value GenerateAuthResult(napi_env env, AuthCallbackParam *param)
{
    napi_value object = CreateAuthResult(param->env, param->token, param->remainTimes, param->freezingTime);
    if (param->hasNextPhaseFreezingTime) {
        SetInt32ToJsProperty(env, param->nextPhaseFreezingTime, "nextPhaseFreezingTime", object);
    }
    if (param->hasCredentialId) {
        napi_value napiCredentialId =
            CreateUint8Array(env, reinterpret_cast<uint8_t *>(&param->credentialId), sizeof(uint64_t));
        NAPI_CALL(env, napi_set_named_property(env, object, "credentialId", napiCredentialId));
    }
    if (param->hasAccountId) {
        SetInt32ToJsProperty(env, param->accountId, "accountId", object);
    }
    if (param->hasPinValidityPeriod) {
        napi_value napiPinValidityPeriod = nullptr;
        NAPI_CALL(env, napi_create_int64(env, param->pinValidityPeriod, &napiPinValidityPeriod));
        NAPI_CALL(env, napi_set_named_property(env, object, "pinValidityPeriod", napiPinValidityPeriod));
    }
    return object;
}

static void OnUserAuthResultWork(uv_work_t *work, int status)
{
    ACCOUNT_LOGI("enter");
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<AuthCallbackParam> param(reinterpret_cast<AuthCallbackParam *>(work->data));
    napi_value argv[ARG_SIZE_TWO] = {nullptr};
    napi_create_int32(param->env, AccountIAMConvertToJSErrCode(param->resultCode), &argv[PARAM_ZERO]);
    argv[PARAM_ONE] = GenerateAuthResult(param->env, param.get());
    NapiCallVoidFunction(param->env, argv, ARG_SIZE_TWO, param->callback->onResult);
    napi_close_handle_scope(param->env, scope);
}

static void OnUserAuthAcquireInfoWork(uv_work_t *work, int status)
{
    ACCOUNT_LOGI("enter");
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<AuthCallbackParam> param(reinterpret_cast<AuthCallbackParam *>(work->data));
    napi_value argv[ARG_SIZE_THREE] = {nullptr};
    napi_create_int32(param->env, param->module, &argv[PARAM_ZERO]);
    napi_create_uint32(param->env, param->acquireInfo, &argv[PARAM_ONE]);
    argv[PARAM_TWO] = CreateUint8Array(param->env, param->extraInfo.data(), param->extraInfo.size());
    NapiCallVoidFunction(param->env, argv, ARG_SIZE_THREE, param->callback->onAcquireInfo);
    napi_close_handle_scope(param->env, scope);
}

NapiUserAuthCallback::NapiUserAuthCallback(napi_env env, const std::shared_ptr<JsIAMCallback> &callback)
    : env_(env), callback_(callback)
{}

NapiUserAuthCallback::~NapiUserAuthCallback()
{}

void NapiUserAuthCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callback_->onResultCalled) {
        ACCOUNT_LOGE("call twice is not allowed");
        return;
    }
    callback_->onResultCalled = true;
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<AuthCallbackParam> param = std::make_unique<AuthCallbackParam>(env_);
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr || work == nullptr || param == nullptr) {
        ACCOUNT_LOGE("fail for nullptr");
        return;
    }
    param->resultCode = result;
    extraInfo.GetUint8ArrayValue(Attributes::AttributeKey::ATTR_SIGNATURE, param->token);
    extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_REMAIN_TIMES, param->remainTimes);
    extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_FREEZING_TIME, param->freezingTime);
    if (extraInfo.GetInt32Value(
        Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION, param->nextPhaseFreezingTime)) {
        param->hasNextPhaseFreezingTime = true;
    }
    if (extraInfo.GetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, param->credentialId)) {
        param->hasCredentialId = true;
    }
    if (extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_USER_ID, param->accountId)) {
        param->hasAccountId = true;
    }
    if (extraInfo.GetInt64Value(Attributes::AttributeKey::ATTR_PIN_EXPIRED_INFO, param->pinValidityPeriod)) {
        param->hasPinValidityPeriod = true;
    }
    param->callback = callback_;
    work->data = reinterpret_cast<void *>(param.get());
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work_with_qos(
        loop, work.get(), [] (uv_work_t *work) {}, OnUserAuthResultWork, uv_qos_user_initiated));
    ACCOUNT_LOGI("create user auth result work finish");
    work.release();
    param.release();
}

void NapiUserAuthCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!callback_->hasOnAcquireInfo) {
        ACCOUNT_LOGE("no 'OnAcquireInfo' callback need return");
        return;
    }
    if (callback_->onResultCalled) {
        ACCOUNT_LOGE("call after OnResult is not allowed");
        return;
    }
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<AuthCallbackParam> param = std::make_unique<AuthCallbackParam>(env_);
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr || work == nullptr || param == nullptr) {
        ACCOUNT_LOGE("fail for nullptr");
        return;
    }
    param->module = module;
    param->acquireInfo = acquireInfo;
    extraInfo.GetUint8ArrayValue(Attributes::AttributeKey::ATTR_EXTRA_INFO, param->extraInfo);
    param->callback = callback_;
    work->data = reinterpret_cast<void *>(param.get());
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work_with_qos(
        loop, work.get(), [] (uv_work_t *work) {}, OnUserAuthAcquireInfoWork, uv_qos_user_initiated));
    ACCOUNT_LOGI("create user auth acquire info work finish");
    work.release();
    param.release();
}

NapiGetInfoCallback::NapiGetInfoCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred)
    : env_(env), callbackRef_(callbackRef), deferred_(deferred)
{}

NapiGetInfoCallback::~NapiGetInfoCallback()
{}

static void OnGetInfoWork(uv_work_t *work, int status)
{
    ACCOUNT_LOGI("enter");
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<GetAuthInfoContext> context(reinterpret_cast<GetAuthInfoContext *>(work->data));
    napi_env env = context->env;
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (context->errCode != ERR_OK) {
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(context->errCode);
        errJs = GenerateBusinessError(env, jsErrCode, ConvertToJsErrMsg(jsErrCode));
        napi_get_null(env, &dataJs);
    } else {
        napi_get_null(env, &errJs);
        dataJs = CreateCredInfoArray(env, context->credInfo);
    }
    CallbackAsyncOrPromise(env, context.get(), errJs, dataJs);
    napi_close_handle_scope(env, scope);
}

void NapiGetInfoCallback::OnCredentialInfo(int32_t result, const std::vector<AccountSA::CredentialInfo> &infoList)
{
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<GetAuthInfoContext> context = std::make_unique<GetAuthInfoContext>(env_);
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr || work == nullptr || context == nullptr) {
        ACCOUNT_LOGE("fail for nullptr");
        return;
    }
    context->callbackRef = callbackRef_;
    context->deferred = deferred_;
    context->errCode = result;
    context->credInfo = infoList;
    work->data = reinterpret_cast<void *>(context.get());
    ErrCode ret = uv_queue_work_with_qos(
        loop, work.get(), [] (uv_work_t *work) {}, OnGetInfoWork, uv_qos_user_initiated);
    if (ret != ERR_OK) {
        ReleaseNapiRefAsync(env_, callbackRef_);
        return;
    }
    ACCOUNT_LOGI("create get credential info work finish");
    work.release();
    context.release();
}

NapiGetEnrolledIdCallback::NapiGetEnrolledIdCallback(napi_env env, napi_deferred deferred)
    : env_(env), deferred_(deferred)
{}

NapiGetEnrolledIdCallback::~NapiGetEnrolledIdCallback()
{}

static void OnGetEnrolledIdWork(uv_work_t *work, int status)
{
    ACCOUNT_LOGI("enter");
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        ACCOUNT_LOGI("enter");
        return;
    }
    std::unique_ptr<GetEnrolledIdContext> context(reinterpret_cast<GetEnrolledIdContext *>(work->data));
    napi_env env = context->env;
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (context->errCode != ERR_OK) {
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(context->errCode);
        errJs = GenerateBusinessError(env, jsErrCode, ConvertToJsErrMsg(jsErrCode));
        napi_get_null(env, &dataJs);
    } else {
        napi_get_null(env, &errJs);
        dataJs = CreateUint8Array(env, reinterpret_cast<uint8_t *>(&context->enrolledId), sizeof(uint64_t));
    }
    CallbackAsyncOrPromise(env, context.get(), errJs, dataJs);
    napi_close_handle_scope(env, scope);
}

void NapiGetEnrolledIdCallback::OnEnrolledId(int32_t result, uint64_t enrolledId)
{
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<GetEnrolledIdContext> context = std::make_unique<GetEnrolledIdContext>(env_);
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr || work == nullptr || context == nullptr) {
        ACCOUNT_LOGE("Failed for nullptr");
        return;
    }
    context->deferred = deferred_;
    context->errCode = result;
    context->enrolledId = enrolledId;
    work->data = reinterpret_cast<void *>(context.get());
    ErrCode ret = uv_queue_work_with_qos(
        loop, work.get(), [] (uv_work_t *work) {}, OnGetEnrolledIdWork, uv_qos_user_initiated);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Create get enrolled id work failed");
        return;
    }
    ACCOUNT_LOGI("Create get enrolled id work finish");
    work.release();
    context.release();
}

NapiGetPropCallback::NapiGetPropCallback(
    napi_env env, napi_ref callbackRef, napi_deferred deferred, const AccountSA::GetPropertyRequest &request)
    : env_(env), callbackRef_(callbackRef), deferred_(deferred), request_(request)
{}

NapiGetPropCallback::~NapiGetPropCallback()
{
    if (callbackRef_ != nullptr) {
        ReleaseNapiRefAsync(env_, callbackRef_);
        callbackRef_ = nullptr;
    }
    deferred_ = nullptr;
}

static void OnGetPropertyWork(uv_work_t* work, int status)
{
    ACCOUNT_LOGI("enter");
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<GetPropertyContext> context(reinterpret_cast<GetPropertyContext *>(work->data));
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    CreateExecutorProperty(context->env, *context, errJs, dataJs);
    CallbackAsyncOrPromise(context->env, context.get(), errJs, dataJs);
    napi_close_handle_scope(context->env, scope);
}

void NapiGetPropCallback::GetContextParams(
    const UserIam::UserAuth::Attributes &extraInfo, GetPropertyContext &context)
{
    for (const auto &key : request_.keys) {
        switch (key) {
            case Attributes::AttributeKey::ATTR_PIN_SUB_TYPE: {
                if (!extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_PIN_SUB_TYPE, context.authSubType)) {
                    ACCOUNT_LOGE("get authSubType failed");
                }
                break;
            }
            case Attributes::AttributeKey::ATTR_REMAIN_TIMES: {
                if (!extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_REMAIN_TIMES, context.remainTimes)) {
                    ACCOUNT_LOGE("get remainTimes failed");
                }
                break;
            }
            case Attributes::AttributeKey::ATTR_FREEZING_TIME: {
                if (!extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_FREEZING_TIME, context.freezingTime)) {
                    ACCOUNT_LOGE("get freezingTime failed");
                }
                break;
            }
            case Attributes::AttributeKey::ATTR_ENROLL_PROGRESS: {
                if (!extraInfo.GetStringValue(
                    Attributes::AttributeKey::ATTR_ENROLL_PROGRESS, context.enrollmentProgress)) {
                    ACCOUNT_LOGE("get enrollmentProgress failed");
                }
                break;
            }
            case Attributes::AttributeKey::ATTR_SENSOR_INFO: {
                if (!extraInfo.GetStringValue(Attributes::AttributeKey::ATTR_SENSOR_INFO, context.sensorInfo)) {
                    ACCOUNT_LOGE("get sensorInfo failed");
                }
                break;
            }
            case Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION: {
                if (!extraInfo.GetInt32Value(
                    Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION, context.nextPhaseFreezingTime)) {
                    ACCOUNT_LOGE("get nextPhaseFreezingTime failed");
                }
                break;
            }
            default:
                ACCOUNT_LOGE("get invalid key");
                break;
        }
    }
    return;
}

void NapiGetPropCallback::OnResult(int32_t result, const UserIam::UserAuth::Attributes &extraInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if ((callbackRef_ == nullptr) && (deferred_ == nullptr)) {
        return;
    }
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<GetPropertyContext> context = std::make_unique<GetPropertyContext>(env_);
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr || work == nullptr || context == nullptr) {
        ACCOUNT_LOGE("fail for nullptr");
        return;
    }
    // create context data
    GetContextParams(extraInfo, *context);
    context->callbackRef = callbackRef_;
    context->deferred = deferred_;
    context->errCode = ERR_OK;
    context->result = result;
    context->request = request_;
    work->data = reinterpret_cast<void *>(context.get());
    ErrCode ret = uv_queue_work_with_qos(
        loop, work.get(), [] (uv_work_t *work) {}, OnGetPropertyWork, uv_qos_user_initiated);
    ACCOUNT_LOGI("create get property work finish");
    if (ret != ERR_OK) {
        context->callbackRef = nullptr;
        ACCOUNT_LOGE("create uv work failed");
        return;
    }
    callbackRef_ = nullptr;
    deferred_ = nullptr;
    work.release();
    context.release();
}

NapiSetPropCallback::NapiSetPropCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred)
    : env_(env), callbackRef_(callbackRef), deferred_(deferred)
{}

NapiSetPropCallback::~NapiSetPropCallback()
{
    if (callbackRef_ != nullptr) {
        ReleaseNapiRefAsync(env_, callbackRef_);
        callbackRef_ = nullptr;
    }
    deferred_ = nullptr;
}

NapiPrepareRemoteAuthCallback::NapiPrepareRemoteAuthCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred)
    : env_(env), callbackRef_(callbackRef), deferred_(deferred)
{}

NapiPrepareRemoteAuthCallback::~NapiPrepareRemoteAuthCallback()
{
    if (callbackRef_ != nullptr) {
        ReleaseNapiRefAsync(env_, callbackRef_);
        callbackRef_ = nullptr;
    }
    deferred_ = nullptr;
}

static void OnPrepareRemoteAuthWork(uv_work_t* work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<PrepareRemoteAuthContext> context(reinterpret_cast<PrepareRemoteAuthContext *>(work->data));
    napi_env env = context->env;
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    context->errCode = context->result;
    if (context->result != ERR_OK) {
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(context->result);
        errJs = GenerateBusinessError(env, jsErrCode, ConvertToJsErrMsg(jsErrCode));
        napi_get_null(env, &dataJs);
    } else {
        napi_get_null(env, &errJs);
        napi_get_null(env, &dataJs);
    }
    CallbackAsyncOrPromise(env, context.get(), errJs, dataJs);
    napi_close_handle_scope(env, scope);
}

void NapiPrepareRemoteAuthCallback::OnResult(int32_t result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if ((callbackRef_ == nullptr) && (deferred_ == nullptr)) {
        return;
    }
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<PrepareRemoteAuthContext> context = std::make_unique<PrepareRemoteAuthContext>(env_);
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr || work == nullptr || context == nullptr) {
        ACCOUNT_LOGE("Nullptr fail.");
        return;
    }
    context->deferred = deferred_;
    context->errCode = ERR_OK;
    context->result = result;
    work->data = reinterpret_cast<void *>(context.get());
    ErrCode ret = uv_queue_work_with_qos(
        loop, work.get(), [] (uv_work_t *work) {}, OnPrepareRemoteAuthWork, uv_qos_user_initiated);
    if (ret != ERR_OK) {
        context->callbackRef = nullptr;
        ACCOUNT_LOGE("Create uv work failed.");
        return;
    }
    ACCOUNT_LOGI("Create prepare remote auth work finish.");
    deferred_ = nullptr;
    work.release();
    context.release();
}

static void OnSetPropertyWork(uv_work_t* work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<SetPropertyContext> context(reinterpret_cast<SetPropertyContext *>(work->data));
    napi_env env = context->env;
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    context->errCode = context->result;
    if (context->result != ERR_OK) {
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(context->result);
        errJs = GenerateBusinessError(env, jsErrCode, ConvertToJsErrMsg(jsErrCode));
        napi_get_null(env, &dataJs);
    } else {
        napi_get_null(env, &errJs);
        napi_get_null(env, &dataJs);
    }
    CallbackAsyncOrPromise(env, context.get(), errJs, dataJs);
    napi_close_handle_scope(env, scope);
}

void NapiSetPropCallback::OnResult(int32_t result, const UserIam::UserAuth::Attributes &extraInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if ((callbackRef_ == nullptr) && (deferred_ == nullptr)) {
        return;
    }
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<SetPropertyContext> context = std::make_unique<SetPropertyContext>(env_);
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr || work == nullptr || context == nullptr) {
        ACCOUNT_LOGE("fail for nullptr");
        return;
    }
    context->callbackRef = callbackRef_;
    context->deferred = deferred_;
    context->errCode = ERR_OK;
    context->result = result;
    work->data = reinterpret_cast<void *>(context.get());
    ErrCode ret = uv_queue_work_with_qos(
        loop, work.get(), [] (uv_work_t *work) {}, OnSetPropertyWork, uv_qos_user_initiated);
    ACCOUNT_LOGI("create set property work finish");
    if (ret != ERR_OK) {
        context->callbackRef = nullptr;
        ACCOUNT_LOGE("create uv work failed");
        return;
    }
    callbackRef_ = nullptr;
    deferred_ = nullptr;
    work.release();
    context.release();
}
#endif  // HAS_USER_AUTH_PART

#ifdef HAS_PIN_AUTH_PART
napi_value InputDataConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar;
    void *data;
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    InputerContext *context = static_cast<InputerContext *>(data);
    if (thisVar == nullptr) {
        ACCOUNT_LOGE("thisVar is nullptr");
        return nullptr;
    }
    if (context == nullptr) {
        ACCOUNT_LOGE("inputerData is nullptr");
        return nullptr;
    }
    NAPI_CALL(env, napi_wrap(env, thisVar, context,
        [](napi_env env, void *data, void *hint) {
            InputerContext *context = static_cast<InputerContext *>(data);
            if (context != nullptr) {
                delete context;
            }
        },
        nullptr, nullptr));
    return thisVar;
}

napi_value OnSetData(napi_env env, napi_callback_info info)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    size_t argc = ARG_SIZE_TWO;
    napi_value thisVar = nullptr;
    napi_value argv[ARG_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    if (argc != ARG_SIZE_TWO) {
        ACCOUNT_LOGE("failed to parse parameters, expect three parameters, but got %{public}zu", argc);
        std::string errMsg = "Parameter error. The number of parameters should be 2";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    InputerContext *context = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&context));
    if (context == nullptr || context->inputerData == nullptr) {
        ACCOUNT_LOGE("context or inputerData is nullptr");
        return nullptr;
    }
    int32_t authSubType;
    if (!GetIntProperty(env, argv[PARAM_ZERO], authSubType)) {
        ACCOUNT_LOGE("Get authSubType failed");
        std::string errMsg = "Parameter error. The type of \"authSubType\" must be AuthSubType";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    std::vector<uint8_t> data;
    if (ParseUint8TypedArrayToVector(env, argv[PARAM_ONE], data) != napi_ok) {
        ACCOUNT_LOGE("Get data failed");
        std::string errMsg = "Parameter error. The type of \"data\" must be Uint8Array";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    context->inputerData->OnSetData(authSubType, data);
    context->inputerData = nullptr;
    return nullptr;
}

napi_value GetCtorIInputerData(napi_env env, const std::shared_ptr<AccountSA::IInputerData> &inputerData)
{
    if (inputerData == nullptr) {
        ACCOUNT_LOGE("inputerData nullptr");
        return nullptr;
    }
    InputerContext *context = new (std::nothrow) InputerContext();
    if (context == nullptr) {
        ACCOUNT_LOGE("inputer context is nullptr");
        return nullptr;
    }
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("onSetData", OnSetData),
    };
    context->inputerData = inputerData;
    napi_value cons;
    NAPI_CALL(env, napi_define_class(env, "InputerData", NAPI_AUTO_LENGTH,
        InputDataConstructor, reinterpret_cast<void *>(context),
        sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    return cons;
}

static napi_status GetInputerInstance(InputerContext *context, napi_value *inputerDataVarCtor)
{
    napi_value cons = GetCtorIInputerData(context->env, context->inputerData);
    if (cons == nullptr) {
        ACCOUNT_LOGD("failed to GetCtorIInputerData");
        return napi_generic_failure;
    }
    return napi_new_instance(context->env, cons, 0, nullptr, inputerDataVarCtor);
}

static void OnGetDataWork(uv_work_t* work, int status)
{
    ACCOUNT_LOGI("enter");
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<InputerContext> context(reinterpret_cast<InputerContext *>(work->data));
    napi_value argv[ARG_SIZE_THREE] = {0};
    napi_create_int32(context->env, context->authSubType, &argv[PARAM_ZERO]);
    GetInputerInstance(context.get(), &argv[PARAM_ONE]);

    napi_create_object(context->env, &argv[PARAM_TWO]);
    if (!(context->challenge.empty())) {
        napi_value dataJs = nullptr;
        dataJs = CreateUint8Array(context->env, context->challenge.data(), context->challenge.size());
        napi_set_named_property(context->env, argv[PARAM_TWO], "challenge", dataJs);
    }

    NapiCallVoidFunction(context->env, argv, ARG_SIZE_THREE, context->callback->callbackRef);
}

NapiGetDataCallback::NapiGetDataCallback(napi_env env, const std::shared_ptr<NapiCallbackRef> &callback)
    : env_(env), callback_(callback)
{}

NapiGetDataCallback::~NapiGetDataCallback()
{}

void NapiGetDataCallback::OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
    const std::shared_ptr<AccountSA::IInputerData> inputerData)
{
    if (callback_ == nullptr) {
        ACCOUNT_LOGE("the onGetData function is undefined");
        return;
    }
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<InputerContext> context = std::make_unique<InputerContext>();
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr || work == nullptr || context == nullptr) {
        ACCOUNT_LOGE("fail for nullptr");
        return;
    }
    context->env = env_;
    context->callback = callback_;
    context->authSubType = authSubType;
    context->challenge = challenge;
    context->inputerData = inputerData;
    work->data = reinterpret_cast<void *>(context.get());
    int errCode = uv_queue_work_with_qos(
        loop, work.get(), [] (uv_work_t *work) {}, OnGetDataWork, uv_qos_user_initiated);
    ACCOUNT_LOGI("create get data work finish");
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work_with_qos, errCode: %{public}d", errCode);
        return;
    }
    work.release();
    context.release();
}
#endif  // HAS_PIN_AUTH_PART

void CallbackAsyncOrPromise(napi_env env, CommonAsyncContext *context, napi_value errJs, napi_value dataJs)
{
    if (context->callbackRef) {
        napi_value argv[ARG_SIZE_TWO] = {errJs, dataJs};
        ACCOUNT_LOGI("call js function");
        NapiCallVoidFunction(env, argv, ARG_SIZE_TWO, context->callbackRef);
    } else {
        if (context->errCode == ERR_OK) {
            napi_resolve_deferred(env, context->deferred, dataJs);
        } else {
            napi_reject_deferred(env, context->deferred, errJs);
        }
    }
}

napi_status ParseUInt32Array(napi_env env, napi_value value, std::vector<uint32_t> &data)
{
    data.clear();
    bool isArray = false;
    napi_is_array(env, value, &isArray);
    if (!isArray) {
        ACCOUNT_LOGE("value is not an array");
        return napi_invalid_arg;
    }
    uint32_t arrLen = 0;
    napi_get_array_length(env, value, &arrLen);
    for (uint32_t i = 0; i < arrLen; ++i) {
        napi_value item = nullptr;
        napi_get_element(env, value, i, &item);
        uint32_t num = 0;
        if (napi_get_value_uint32(env, item, &num) != napi_ok) {
            data.clear();
            return napi_number_expected;
        }
        data.push_back(num);
    }
    return napi_ok;
}

napi_value CreateErrorObject(napi_env env, int32_t code)
{
    napi_value errObj = nullptr;
    NAPI_CALL(env, napi_create_object(env, &errObj));
    napi_value number = 0;
    NAPI_CALL(env, napi_create_int32(env, code, &number));
    NAPI_CALL(env, napi_set_named_property(env, errObj, "code", number));
    return errObj;
}

bool IsRestrictedAccountId(int32_t accountId)
{
    if ((accountId >= RESTRICTED_ACCOUNT_ID_BEGINNING) && (accountId < RESTRICTED_ACCOUNT_ID_ENDDING)) {
        ACCOUNT_LOGI("The account id is restricted");
        return true;
    }
    return false;
}
}  // namespace AccountJsKit
}  // namespace OHOS

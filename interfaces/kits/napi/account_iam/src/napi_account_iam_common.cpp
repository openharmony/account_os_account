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

#include "napi_account_iam_common.h"

#include <uv.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "napi_account_error.h"
#include "napi_account_common.h"
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
            return ERR_JS_AUTH_CREDENTIAL_WRONG_ERROR;
        case ERR_IAM_TRUST_LEVEL_NOT_SUPPORT:
            return ERR_JS_TRUST_LEVEL_NOT_SUPPORTED;
        case ERR_IAM_TYPE_NOT_SUPPORT:
            return ERR_JS_AUTH_TYPE_NOT_SUPPORTED;
        case ERR_IAM_TIMEOUT:
            return ERR_JS_AUTH_TIMEOUT;
        case ERR_IAM_BUSY:
            return ERR_JS_AUTH_SERVICE_BUSY;
        case ERR_IAM_LOCKED:
            return ERR_JS_AUTH_SERVICE_LOCKED;
        case ERR_IAM_NOT_ENROLLED:
            return ERR_JS_CREDENTIAL_NOT_EXIST;
        case ERR_IAM_INVALID_CONTEXT_ID:
            return ERR_JS_INVALID_CONTEXT_ID;
        case ERR_ACCOUNT_COMMON_INVALID_PARAMTER:
        case ERR_IAM_INVALID_PARAMETERS:
            return ERR_JS_INVALID_PARAMETER;
        case ERR_ACCOUNT_IAM_KIT_INPUTER_ALREADY_REGISTERED:
            return ERR_JS_CREDENTIAL_INPUTER_ALREADY_EXIST;
        case ERR_ACCOUNT_IAM_KIT_INPUTER_NOT_REGISTERED:
            return ERR_JS_CREDENTIAL_INPUTER_NOT_EXIST;
        case ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE:
            return ERR_JS_AUTH_TYPE_NOT_SUPPORTED;
        default:
            return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
    }
}

int32_t AccountIAMConvertToJSErrCode(int32_t errCode)
{
    if ((errCode >= ERR_ACCOUNT_IAM_KIT_SEND_REQUEST && errCode <= ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL) ||
        (errCode >= ERR_ACCOUNT_IAM_SERVICE_GET_STORAGE_SYSTEM_ABILITY &&
        errCode <= ERR_ACCOUNT_IAM_SERVICE_READ_PARCEL_FAIL)) {
        return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
    } else if (errCode == ERR_ACCOUNT_IAM_SERVICE_PERMISSION_DENIED || errCode == ERR_IAM_CHECK_PERMISSION_FAILED) {
        return ERR_JS_PERMISSION_DENIED;
    } else if (errCode == ERR_ACCOUNT_IAM_SERVICE_PARAM_INVALID_ERROR ||
        errCode == ERR_ACCOUNT_IAM_KIT_PARAM_INVALID_ERROR) {
        return ERR_JS_INVALID_PARAMETER;
    }
    return AccountIAMConvertOtherToJSErrCode(errCode);
}

static void ReleaseWorkAndCallback(napi_env env, napi_async_work work, napi_ref callbackRef)
{
    if (env == nullptr) {
        return;
    }
    if (work != nullptr) {
        napi_delete_async_work(env, work);
    }
    if (callbackRef != nullptr) {
        napi_delete_reference(env, callbackRef);
    }
}

IAMAsyncContext::IAMAsyncContext(napi_env napiEnv) : CommonAsyncContext(napiEnv)
{}

IAMAsyncContext::~IAMAsyncContext()
{
    ReleaseWorkAndCallback(env, work, callbackRef);
    work = nullptr;
    callbackRef = nullptr;
}

GetPropertyContext::~GetPropertyContext()
{
    ReleaseWorkAndCallback(env, work, callbackRef);
    work = nullptr;
    callbackRef = nullptr;
}

SetPropertyContext::~SetPropertyContext()
{
    ReleaseWorkAndCallback(env, work, callbackRef);
    work = nullptr;
    callbackRef = nullptr;
}

#ifdef HAS_USER_AUTH_PART
NapiIDMCallback::NapiIDMCallback(napi_env env, const JsIAMCallback &callback) : env_(env), callback_(callback)
{}

NapiIDMCallback::~NapiIDMCallback()
{
    ReleaseNapiRefArray(env_, { callback_.onResult, callback_.onAcquireInfo });
}

static void OnIDMResultWork(uv_work_t* work, int status)
{
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
    NapiCallVoidFunction(param->env, argv, ARG_SIZE_TWO, param->callback.onResult);
    napi_close_handle_scope(param->env, scope);
}

void NapiIDMCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
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
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work(loop, work.get(), [] (uv_work_t *work) {}, OnIDMResultWork));
    work.release();
    param.release();
}

static void OnAcquireInfoWork(uv_work_t* work, int status)
{
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
    napi_value credentialId = CreateUint8Array(
        env, reinterpret_cast<uint8_t *>(&param->credentialId), sizeof(uint64_t));
    napi_create_object(env, &argv[PARAM_TWO]);
    napi_set_named_property(env, argv[PARAM_TWO], "credentialId", credentialId);
    NapiCallVoidFunction(env, argv, ARG_SIZE_THREE, param->callback.onAcquireInfo);
    napi_close_handle_scope(env, scope);
}

void NapiIDMCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
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
    extraInfo.GetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, param->credentialId);
    work->data = reinterpret_cast<void *>(param.get());
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work(loop, work.get(), [] (uv_work_t *work) { }, OnAcquireInfoWork));
    work.release();
    param.release();
}

napi_status ParseAddCredInfo(napi_env env, napi_value value, CredentialParameters &addCredInfo)
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
    addCredInfo.authType = static_cast<AuthType>(credType);
    napi_get_named_property(env, value, "credSubType", &result);
    int32_t credSubType = -1;
    napi_get_value_int32(env, result, &credSubType);
    addCredInfo.pinType = static_cast<PinSubType>(credSubType);
    napi_get_named_property(env, value, "token", &result);
    return ParseUint8TypedArrayToVector(env, result, addCredInfo.token);
}

napi_status ParseIAMCallback(napi_env env, napi_value object, JsIAMCallback &callback)
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
        NAPI_CALL_BASE(env, napi_create_reference(env, result, 1, &callback.onResult), napi_generic_failure);
    } else {
        ACCOUNT_LOGE("onResult is not a function");
        return napi_invalid_arg;
    }
    bool hasOnAcquireInfo = false;
    napi_has_named_property(env, object, "onAcquireInfo", &hasOnAcquireInfo);
    if (!hasOnAcquireInfo) {
        return napi_ok;
    }
    napi_get_named_property(env, object, "onAcquireInfo", &result);
    napi_typeof(env, result, &valueType);
    if (valueType == napi_function) {
        NAPI_CALL_BASE(env, napi_create_reference(env, result, 1, &callback.onAcquireInfo), napi_generic_failure);
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

napi_status ParseGetPropRequest(napi_env env, napi_value object, GetPropertyRequest &request)
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
    request.authType = static_cast<AuthType>(authType);
    napi_value napiKeys = nullptr;
    napi_get_named_property(env, object, "keys", &napiKeys);
    std::vector<uint32_t> keys;
    ParseUInt32Array(env, napiKeys, keys);
    for (const auto &item : keys) {
        request.keys.push_back(static_cast<Attributes::AttributeKey>(item));
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
    napi_value napiResult = 0;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, prop.result, &napiResult));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, dataJs, "result", napiResult));
    napi_value napiAuthSubType = 0;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, prop.authSubType, &napiAuthSubType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, dataJs, "authSubType", napiAuthSubType));
    napi_value napiRemainTimes = 0;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, prop.remainTimes, &napiRemainTimes));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, dataJs, "remainTimes", napiRemainTimes));
    napi_value napiFreezingTimes = 0;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, prop.freezingTime, &napiFreezingTimes));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, dataJs, "freezingTime", napiFreezingTimes));
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

napi_value CreateAuthResult(napi_env env, const std::vector<uint8_t> &token, int32_t remainTimes, int32_t freezingTime)
{
    napi_value object = nullptr;
    NAPI_CALL(env, napi_create_object(env, &object));
    if (remainTimes >= 0) {
        napi_value napiRemainTimes = 0;
        napi_create_uint32(env, remainTimes, &napiRemainTimes);
        napi_set_named_property(env, object, "remainTimes", napiRemainTimes);
    }
    if (remainTimes >= 0) {
        napi_value napiFreezingTimes = 0;
        napi_create_uint32(env, freezingTime, &napiFreezingTimes);
        napi_set_named_property(env, object, "freezingTime", napiFreezingTimes);
    }
    if (token.size() > 0) {
        napi_value napiToken = CreateUint8Array(env, token.data(), token.size());
        napi_set_named_property(env, object, "token", napiToken);
    }
    return object;
}

static void OnUserAuthResultWork(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<AuthCallbackParam> param(reinterpret_cast<AuthCallbackParam *>(work->data));
    napi_value argv[ARG_SIZE_TWO] = {nullptr};
    napi_create_int32(param->env, AccountIAMConvertToJSErrCode(param->resultCode), &argv[PARAM_ZERO]);
    argv[PARAM_ONE] = CreateAuthResult(param->env, param->token, param->remainTimes, param->freezingTime);
    NapiCallVoidFunction(param->env, argv, ARG_SIZE_TWO, param->callback.onResult);
    napi_close_handle_scope(param->env, scope);
}

static void OnUserAuthAcquireInfoWork(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<AuthCallbackParam> param(reinterpret_cast<AuthCallbackParam *>(work->data));
    napi_value argv[ARG_SIZE_THREE] = {nullptr};
    napi_create_int32(param->env, param->module, &argv[PARAM_ZERO]);
    napi_create_uint32(param->env, param->acquireInfo, &argv[PARAM_ONE]);
    napi_create_int32(param->env, param->extraInfo, &argv[PARAM_TWO]);
    NapiCallVoidFunction(param->env, argv, ARG_SIZE_THREE, param->callback.onAcquireInfo);
    napi_close_handle_scope(param->env, scope);
}

NapiUserAuthCallback::NapiUserAuthCallback(napi_env env, JsIAMCallback callback)
    : env_(env), callback_(callback)
{}

NapiUserAuthCallback::~NapiUserAuthCallback()
{
    ReleaseNapiRefArray(env_, { callback_.onResult, callback_.onAcquireInfo });
}

void NapiUserAuthCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
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
    param->callback = callback_;
    work->data = reinterpret_cast<void *>(param.get());
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work(loop, work.get(), [] (uv_work_t *work) {}, OnUserAuthResultWork));
    work.release();
    param.release();
}

void NapiUserAuthCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
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
    param->extraInfo = 0;
    param->callback = callback_;
    work->data = reinterpret_cast<void *>(param.get());
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work(loop, work.get(), [] (uv_work_t *work) {}, OnUserAuthAcquireInfoWork));
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
    ErrCode ret = uv_queue_work(loop, work.get(), [](uv_work_t *work) {}, OnGetInfoWork);
    if (ret != ERR_OK) {
      ReleaseNapiRefAsync(env_, callbackRef_);
      return;
    }
    work.release();
    context.release();
}

NapiGetPropCallback::NapiGetPropCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred)
    : env_(env), callbackRef_(callbackRef), deferred_(deferred)
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
    extraInfo.GetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, context->authSubType);
    extraInfo.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, context->remainTimes);
    extraInfo.GetInt32Value(Attributes::ATTR_FREEZING_TIME, context->freezingTime);
    context->callbackRef = callbackRef_;
    context->deferred = deferred_;
    context->errCode = ERR_OK;
    context->result = result;
    work->data = reinterpret_cast<void *>(context.get());
    ErrCode ret = uv_queue_work(loop, work.get(), [] (uv_work_t *work) {}, OnGetPropertyWork);
    if (ret != ERR_OK) {
        context->callbackRef = nullptr;
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
    ErrCode ret = uv_queue_work(loop, work.get(), [] (uv_work_t *work) {}, OnSetPropertyWork);
    if (ret != ERR_OK) {
        context->callbackRef = nullptr;
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
    size_t argc = ARG_SIZE_TWO;
    napi_value thisVar = nullptr;
    napi_value argv[ARG_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    if (argc != ARG_SIZE_TWO) {
        ACCOUNT_LOGE("failed to parse parameters, expect three parameters, but got %{public}zu", argc);
        std::string errMsg = "The arg number must be at least 2 characters";
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
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    std::vector<uint8_t> data;
    if (ParseUint8TypedArrayToVector(env, argv[PARAM_ONE], data) != napi_ok) {
        ACCOUNT_LOGE("Get data failed");
        std::string errMsg = "The type of arg 2 must be int array";
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
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<InputerContext> context(reinterpret_cast<InputerContext *>(work->data));
    napi_value argv[ARG_SIZE_TWO] = {0};
    NAPI_CALL_RETURN_VOID(context->env, napi_create_int32(context->env, context->authSubType, &argv[PARAM_ZERO]));
    NAPI_CALL_RETURN_VOID(context->env, GetInputerInstance(context.get(), &argv[PARAM_ONE]));
    NapiCallVoidFunction(context->env, argv, ARG_SIZE_TWO, context->callbackRef);
    std::unique_lock<std::mutex> lock(context->lockInfo->mutex);
    context->lockInfo->count--;
    context->lockInfo->condition.notify_all();
}

NapiGetDataCallback::NapiGetDataCallback(napi_env env, napi_ref callback) : env_(env), callback_(callback)
{}

NapiGetDataCallback::~NapiGetDataCallback()
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    lockInfo_.condition.wait(lock, [this] { return this->lockInfo_.count == 0; });
    lockInfo_.count--;
    ReleaseNapiRefAsync(env_, callback_);
    callback_ = nullptr;
}

void NapiGetDataCallback::OnGetData(int32_t authSubType, const std::shared_ptr<AccountSA::IInputerData> inputerData)
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if (lockInfo_.count < 0) {
        ACCOUNT_LOGE("the inputer has been released");
        return;
    }
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
    context->callbackRef = callback_;
    context->authSubType = authSubType;
    context->inputerData = inputerData;
    context->lockInfo = &lockInfo_;
    work->data = reinterpret_cast<void *>(context.get());
    int errCode = uv_queue_work(loop, work.get(), [] (uv_work_t *work) {}, OnGetDataWork);
    ACCOUNT_LOGI("create get data work finish");
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        return;
    }
    lockInfo_.count++;
    work.release();
    context.release();
}
#endif  // HAS_PIN_AUTH_PART

void CallbackAsyncOrPromise(napi_env env, CommonAsyncContext *context, napi_value errJs, napi_value dataJs)
{
    if (context->callbackRef) {
        napi_value argv[ARG_SIZE_TWO] = {errJs, dataJs};
        NapiCallVoidFunction(env, argv, ARG_SIZE_TWO, context->callbackRef);
        napi_delete_reference(env, context->callbackRef);
        context->callbackRef = nullptr;
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
}  // namespace AccountJsKit
}  // namespace OHOS

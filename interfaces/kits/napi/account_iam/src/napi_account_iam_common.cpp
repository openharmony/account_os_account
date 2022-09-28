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
#include "securec.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;

IAMAsyncContext::IAMAsyncContext(napi_env napiEnv)
    : env(napiEnv)
{}

IAMAsyncContext::~IAMAsyncContext()
{
    if (env == nullptr) {
        return;
    }
    if (work != nullptr) {
        napi_delete_async_work(env, work);
        work = nullptr;
    }
    if (callbackRef != nullptr) {
        napi_delete_reference(env, callbackRef);
        callbackRef = nullptr;
    }
}

#ifdef HAS_USER_AUTH_PART
NapiIDMCallback::NapiIDMCallback(napi_env env, const JsIAMCallback &callback) : env_(env), callback_(callback)
{}

NapiIDMCallback::~NapiIDMCallback()
{}

static void OnIDMResultWork(uv_work_t* work, int status)
{
    IDMCallbackParam *param = reinterpret_cast<IDMCallbackParam *>(work->data);
    if (param == nullptr) {
        ACCOUNT_LOGE("param is null");
        delete work;
        return;
    }
    std::unique_ptr<IDMCallbackParam> paramPtr(param);
    napi_value global;
    napi_value credentialId;
    napi_value callbackRef;
    napi_value callResult = nullptr;
    napi_value argv[ARG_SIZE_TWO] = {0};
    NAPI_CALL_RETURN_VOID(param->env, napi_get_global(param->env, &global));
    NAPI_CALL_RETURN_VOID(param->env, napi_create_int32(param->env, param->result, &argv[0]));
    NAPI_CALL_RETURN_VOID(param->env, napi_create_object(param->env, &argv[PARAM_ONE]));
    credentialId = CreateUint8Array(
        param->env, reinterpret_cast<uint8_t *>(&param->credentialId), sizeof(uint64_t));
    NAPI_CALL_RETURN_VOID(param->env, napi_set_named_property(param->env, argv[PARAM_ONE],
        "credentialId", credentialId));
    NAPI_CALL_RETURN_VOID(param->env, napi_get_reference_value(param->env, param->callback.onResult, &callbackRef));
    NAPI_CALL_RETURN_VOID(param->env, napi_call_function(param->env, global, callbackRef,
        ARG_SIZE_TWO, argv, &callResult));
}

void NapiIDMCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (isCalled_) {
            return;
        }
        isCalled_ = true;
    }
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<IDMCallbackParam> param = std::make_unique<IDMCallbackParam>();
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr || work == nullptr || param == nullptr) {
        ACCOUNT_LOGE("fail for nullptr");
        return;
    }
    param->env = env_;
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
    if (work == nullptr || work->data == nullptr) {
        ACCOUNT_LOGE("param is null");
        return;
    }
    IDMCallbackParam *param = reinterpret_cast<IDMCallbackParam *>(work->data);
    std::unique_ptr<IDMCallbackParam> paramPtr(param);
    napi_value global = nullptr;
    napi_value credentialId;
    napi_value callbackRef;
    napi_value callResult;
    napi_value argv[ARG_SIZE_THREE] = {0};
    napi_env env = param->env;
    napi_get_global(env, &global);
    if (global == nullptr) {
        ACCOUNT_LOGE("napi_get_global failed");
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, param->module, &argv[PARAM_ZERO]));
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, param->acquire, &argv[PARAM_ONE]));
    credentialId = CreateUint8Array(
        env, reinterpret_cast<uint8_t *>(&param->credentialId), sizeof(uint64_t));
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &argv[PARAM_TWO]));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, argv[PARAM_TWO], "credentialId", credentialId));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, param->callback.onAcquireInfo, &callbackRef));
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, global, callbackRef, ARG_SIZE_THREE, argv, &callResult));
}

void NapiIDMCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<IDMCallbackParam> param = std::make_unique<IDMCallbackParam>();
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr || work == nullptr || param == nullptr) {
        ACCOUNT_LOGE("fail for nullptr");
        return;
    }
    param->env = env_;
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

napi_value CreateExecutorProperty(napi_env env, const GetPropertyContext &prop)
{
    napi_value object = nullptr;
    NAPI_CALL(env, napi_create_object(env, &object));
    napi_value napiResult = 0;
    NAPI_CALL(env, napi_create_int32(env, prop.result, &napiResult));
    NAPI_CALL(env, napi_set_named_property(env, object, "result", napiResult));
    napi_value napiAuthSubType = 0;
    NAPI_CALL(env, napi_create_uint32(env, prop.authSubType, &napiAuthSubType));
    NAPI_CALL(env, napi_set_named_property(env, object, "authSubType", napiAuthSubType));
    napi_value napiRemainTimes = 0;
    NAPI_CALL(env, napi_create_uint32(env, prop.remainTimes, &napiRemainTimes));
    NAPI_CALL(env, napi_set_named_property(env, object, "remainTimes", napiRemainTimes));
    napi_value napiFreezingTimes = 0;
    NAPI_CALL(env, napi_create_uint32(env, prop.freezingTime, &napiFreezingTimes));
    NAPI_CALL(env, napi_set_named_property(env, object, "freezingTime", napiFreezingTimes));
    return object;
}

napi_value CreateAuthResult(napi_env env, const std::vector<uint8_t> &token, int32_t remainTimes, int32_t freezingTime)
{
    napi_value object = nullptr;
    NAPI_CALL(env, napi_create_object(env, &object));
    napi_value napiRemainTimes = 0;
    napi_create_uint32(env, remainTimes, &napiRemainTimes);
    napi_set_named_property(env, object, "remainTimes", napiRemainTimes);
    napi_value napiFreezingTimes = 0;
    napi_create_uint32(env, freezingTime, &napiFreezingTimes);
    napi_set_named_property(env, object, "freezingTime", napiFreezingTimes);
    napi_value napiToken = CreateUint8Array(env, token.data(), token.size());
    napi_set_named_property(env, object, "token", napiToken);
    return object;
}

static void OnUserAuthResultWork(uv_work_t *work, int status)
{
    AuthCallbackParam *param = reinterpret_cast<AuthCallbackParam *>(work->data);
    if (param == nullptr) {
        ACCOUNT_LOGE("param is null");
        delete work;
        return;
    }
    napi_value callback = nullptr;
    napi_value argv[ARG_SIZE_TWO] = {nullptr};
    napi_value return_val = nullptr;
    napi_get_reference_value(param->env, param->callback.onResult, &callback);
    napi_create_int32(param->env, param->resultCode, &argv[PARAM_ZERO]);
    argv[PARAM_ONE] = CreateAuthResult(param->env, param->token, param->remainTimes, param->freezingTime);
    napi_call_function(param->env, nullptr, callback, ARG_SIZE_TWO, argv, &return_val);
    napi_delete_reference(param->env, param->callback.onResult);
    delete param;
    delete work;
}

static void OnUserAuthAcquireInfoWork(uv_work_t *work, int status)
{
    AuthCallbackParam *param = reinterpret_cast<AuthCallbackParam *>(work->data);
    if (param == nullptr) {
        ACCOUNT_LOGE("param is null");
        delete work;
        return;
    }
    napi_value return_val = nullptr;
    napi_value argv[ARG_SIZE_THREE] = {nullptr};
    napi_value callback = nullptr;
    napi_get_reference_value(param->env, param->callback.onAcquireInfo, &callback);
    napi_create_int32(param->env, param->module, &argv[PARAM_ZERO]);
    napi_create_uint32(param->env, param->acquireInfo, &argv[PARAM_ONE]);
    napi_create_int32(param->env, param->extraInfo, &argv[PARAM_TWO]);
    if (napi_call_function(param->env, nullptr, callback, ARG_SIZE_THREE, argv, &return_val) != napi_ok) {
        ACCOUNT_LOGE("napi_call_function failed");
    }
    delete param;
    delete work;
}

NapiUserAuthCallback::NapiUserAuthCallback(napi_env env, JsIAMCallback callback)
    : env_(env), callback_(callback)
{}

NapiUserAuthCallback::~NapiUserAuthCallback()
{}

void NapiUserAuthCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<AuthCallbackParam> param = std::make_unique<AuthCallbackParam>();
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
    param->env = env_;
    param->callback = callback_;
    work->data = reinterpret_cast<void *>(param.get());
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work(loop, work.get(), [] (uv_work_t *work) {}, OnUserAuthResultWork));
    work.release();
    param.release();
}

void NapiUserAuthCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<AuthCallbackParam> param = std::make_unique<AuthCallbackParam>();
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr || work == nullptr || param == nullptr) {
        ACCOUNT_LOGE("fail for nullptr");
        return;
    }
    param->module = module;
    param->acquireInfo = acquireInfo;
    param->extraInfo = 0;
    param->env = env_;
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
    GetAuthInfoContext *context = reinterpret_cast<GetAuthInfoContext *>(work->data);
    if (context == nullptr) {
        ACCOUNT_LOGE("context is null");
        delete work;
        return;
    }
    napi_env env = context->env;
    napi_value credInfoArr = CreateCredInfoArray(env, context->credInfo);
    CallbackAsyncOrPromise(env, context, credInfoArr);
    delete context;
    delete work;
}

void NapiGetInfoCallback::OnCredentialInfo(const std::vector<AccountSA::CredentialInfo> &infoList)
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
    context->credInfo = infoList;
    work->data = reinterpret_cast<void *>(context.get());
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work(loop, work.get(), [] (uv_work_t *work) {}, OnGetInfoWork));
    work.release();
    context.release();
}

NapiGetPropCallback::NapiGetPropCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred)
    : env_(env), callbackRef_(callbackRef), deferred_(deferred)
{}

NapiGetPropCallback::~NapiGetPropCallback()
{}

static void OnGetPropertyWork(uv_work_t* work, int status)
{
    GetPropertyContext *context = reinterpret_cast<GetPropertyContext *>(work->data);
    if (context == nullptr) {
        ACCOUNT_LOGE("context is null");
        delete work;
        return;
    }
    napi_value result = CreateExecutorProperty(context->env, *context);
    CallbackAsyncOrPromise(context->env, context, result);
    delete context;
    delete work;
}

void NapiGetPropCallback::OnResult(int32_t result, const UserIam::UserAuth::Attributes &extraInfo)
{
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
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work(loop, work.get(), [] (uv_work_t *work) {}, OnGetPropertyWork));
    work.release();
    context.release();
}

NapiSetPropCallback::NapiSetPropCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred)
    : env_(env), callbackRef_(callbackRef), deferred_(deferred)
{}

NapiSetPropCallback::~NapiSetPropCallback()
{}

static void OnSetPropertyWork(uv_work_t* work, int status)
{
    SetPropertyContext *context = reinterpret_cast<SetPropertyContext *>(work->data);
    if (context == nullptr) {
        ACCOUNT_LOGE("context is null");
        delete work;
        return;
    }
    napi_value result = nullptr;
    napi_create_int32(context->env, context->result, &result);
    CallbackAsyncOrPromise(context->env, context, result);
    delete context;
    delete work;
}

void NapiSetPropCallback::OnResult(int32_t result, const UserIam::UserAuth::Attributes &extraInfo)
{
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
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work(loop, work.get(), [] (uv_work_t *work) {}, OnSetPropertyWork));
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
        return nullptr;
    }
    InputerContext *context = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&context));
    if (context == nullptr || context->inputerData == nullptr) {
        ACCOUNT_LOGE("context or inputerData is nullptr");
        return nullptr;
    }
    int32_t authSubType;
    NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM_ZERO], &authSubType));
    std::vector<uint8_t> data;
    NAPI_CALL(env, ParseUint8TypedArrayToVector(env, argv[PARAM_ONE], data));
    context->inputerData->OnSetData(authSubType, data);
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
        InputDataConstructor, (void*)context,
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
    InputerContext *context = reinterpret_cast<InputerContext *>(work->data);
    if (context == nullptr) {
        ACCOUNT_LOGE("context is null");
        delete work;
        return;
    }
    std::unique_ptr<uv_work_t> workPtr(work);
    std::unique_ptr<InputerContext> contextPtr(context);
    napi_value argv[ARG_SIZE_TWO] = {0};
    napi_value return_val;
    napi_value callback;
    NAPI_CALL_RETURN_VOID(context->env, napi_create_int32(context->env, context->authSubType, &argv[PARAM_ZERO]));
    NAPI_CALL_RETURN_VOID(context->env, GetInputerInstance(context, &argv[PARAM_ONE]));
    NAPI_CALL_RETURN_VOID(context->env, napi_get_reference_value(context->env, context->callback, &callback));
    NAPI_CALL_RETURN_VOID(context->env,
        napi_call_function(context->env, nullptr, callback, ARG_SIZE_TWO, argv, &return_val));
}

NapiGetDataCallback::NapiGetDataCallback(napi_env env, napi_ref callback) : env_(env), callback_(callback)
{}

NapiGetDataCallback::~NapiGetDataCallback()
{}

void NapiGetDataCallback::OnGetData(int32_t authSubType, const std::shared_ptr<AccountSA::IInputerData> inputerData)
{
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
    context->inputerData = inputerData;
    work->data = reinterpret_cast<void *>(context.get());
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work(loop, work.get(), [] (uv_work_t *work) {}, OnGetDataWork));
    work.release();
    context.release();
}
#endif  // HAS_PIN_AUTH_PART

void CallbackAsyncOrPromise(napi_env env, IAMAsyncContext *context, napi_value data)
{
    napi_value err = nullptr;
    if (context->errCode == ERR_OK) {
        napi_get_null(env, &err);
    } else {
        err = CreateErrorObject(env, context->errCode);
        napi_get_null(env, &data);
    }
    if (context->callbackRef) {
        napi_value argv[ARG_SIZE_TWO] = {err, data};
        napi_value result = nullptr;
        napi_value callback = nullptr;
        napi_get_reference_value(env, context->callbackRef, &callback);
        napi_call_function(env, nullptr, callback, ARG_SIZE_TWO, argv, &result);
        napi_delete_reference(env, context->callbackRef);
        context->callbackRef = nullptr;
    } else if (context->errCode == ERR_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, context->deferred, data));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, context->deferred, err));
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
    napi_typedarray_type arrayType;
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
        return napi_ok;
    }
    if (length != sizeof(uint64_t)) {
        ACCOUNT_LOGE("failed to convert to uint64_t value");
        return napi_invalid_arg;
    }
    result = *(reinterpret_cast<uint64_t *>(data));
    return napi_ok;
}

napi_value CreateUint8Array(napi_env env, const uint8_t *srcData, size_t length)
{
    napi_value result = nullptr;
    void* dstData = nullptr;
    napi_value napiArr = nullptr;
    NAPI_CALL(env, napi_create_arraybuffer(env, length, &dstData, &napiArr));
    if (memcpy_s(dstData, length, srcData, length) != EOK) {
        return result;
    }
    NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, length, napiArr, 0, &result));
    return result;
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

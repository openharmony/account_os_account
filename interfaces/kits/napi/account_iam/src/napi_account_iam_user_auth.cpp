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

#include "napi_account_iam_user_auth.h"

#include "account_iam_client.h"
#include "account_log_wrapper.h"
#include "napi_account_iam_common.h"
#include "napi_account_common.h"
#include "napi_account_error.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;

napi_value NapiAccountIAMUserAuth::Init(napi_env env, napi_value exports)
{
    napi_value cons;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("getVersion", GetVersion),
        DECLARE_NAPI_FUNCTION("getAvailableStatus", GetAvailableStatus),
        DECLARE_NAPI_FUNCTION("getProperty", GetProperty),
        DECLARE_NAPI_FUNCTION("setProperty", SetProperty),
        DECLARE_NAPI_FUNCTION("auth", Auth),
        DECLARE_NAPI_FUNCTION("authUser", AuthUser),
        DECLARE_NAPI_FUNCTION("cancelAuth", CancelAuth),
    };
    NAPI_CALL(env, napi_define_class(env, "UserAuth", NAPI_AUTO_LENGTH, JsConstructor,
        nullptr, sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    NAPI_CALL(env, napi_set_named_property(env, exports, "UserAuth", cons));
    return exports;
}

napi_value NapiAccountIAMUserAuth::JsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

napi_value NapiAccountIAMUserAuth::GetVersion(napi_env env, napi_callback_info info)
{
    int32_t result = 0;
    napi_value version = 0;
    NAPI_CALL(env, napi_create_int32(env, result, &version));
    return version;
}

napi_value NapiAccountIAMUserAuth::GetAvailableStatus(napi_env env, napi_callback_info info)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {0};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != ARG_SIZE_TWO) {
        ACCOUNT_LOGE("expect 2 parameters, but got %{public}zu", argc);
        std::string errMsg = "The arg number must be 2 characters";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    napi_valuetype valType = napi_undefined;
    napi_typeof(env, argv[PARAM_ZERO], &valType);
    if (valType != napi_number) {
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    int32_t authType = -1;
    napi_get_value_int32(env, argv[PARAM_ZERO], &authType);
    napi_typeof(env, argv[PARAM_ONE], &valType);
    if (valType != napi_number) {
        std::string errMsg = "The type of arg 2 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    int32_t authSubType = -1;
    napi_get_value_int32(env, argv[PARAM_ONE], &authSubType);
    int32_t status;
    napi_value result = nullptr;
    int32_t errCode = AccountIAMClient::GetInstance().GetAvailableStatus(
        static_cast<AuthType>(authType), static_cast<AuthTrustLevel>(authSubType), status);
    if (errCode == ERR_OK) {
        if ((status != ERR_IAM_SUCCESS) && (status != ERR_IAM_TYPE_NOT_SUPPORT) &&
            (status != ERR_IAM_TRUST_LEVEL_NOT_SUPPORT) && (status != ERR_IAM_NOT_ENROLLED)) {
            AccountIAMNapiThrow(env, AccountIAMConvertToJSErrCode(status), true);
        } else {
            napi_create_int32(env, status, &result);
        }
    } else {
        AccountIAMNapiThrow(env, AccountIAMConvertToJSErrCode(errCode), true);
    }
    return result;
}

static napi_status ParseContextForGetSetProperty(
    napi_env env, napi_callback_info info, CommonAsyncContext *context, napi_value *result, bool isGet = true)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), napi_generic_failure);
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("expect at least 1 parameter, but got zero");
        std::string errMsg = "The arg number must be at least 1 character";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_generic_failure;
    }
    napi_valuetype valueType = napi_undefined;
    if (argc == ARG_SIZE_TWO) {
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PARAM_ONE], &valueType), napi_generic_failure);
    }
    if (valueType == napi_function) {
        NAPI_CALL_BASE(env, napi_create_reference(env, argv[PARAM_ONE], 1, &context->callbackRef),
            napi_generic_failure);
    } else {
        NAPI_CALL_BASE(env, napi_create_promise(env, &context->deferred, result), napi_generic_failure);
    }
    if (isGet) {
        if (ParseGetPropRequest(env, argv[PARAM_ZERO], static_cast<GetPropertyContext *>(context)->request) !=
            napi_ok) {
            std::string errMsg = "Arg 1 must be a valid GetPropertyRequest";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return napi_generic_failure;
        }
    } else {
        if (ParseSetPropRequest(env, argv[PARAM_ZERO], static_cast<SetPropertyContext *>(context)->request) !=
            napi_ok) {
            std::string errMsg = "Arg 1 must be a valid SetPropertyRequest";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return napi_generic_failure;
        }
    }
    return napi_ok;
}

napi_value NapiAccountIAMUserAuth::GetProperty(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    GetPropertyContext *context = new (std::nothrow) GetPropertyContext(env);
    if (context == nullptr) {
        ACCOUNT_LOGE("failed to create GetPropertyContext");
        return result;
    }
    std::unique_ptr<GetPropertyContext> contextPtr(context);
    if (ParseContextForGetSetProperty(env, info, context, &result) != napi_ok) {
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetProperty", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            GetPropertyContext *context = reinterpret_cast<GetPropertyContext *>(data);
            auto getPropCallback = std::make_shared<NapiGetPropCallback>(
                context->env, context->callbackRef, context->deferred);
            AccountIAMClient::GetInstance().GetProperty(0, context->request, getPropCallback);
            context->callbackRef = nullptr;
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<GetPropertyContext *>(data);
        },
        reinterpret_cast<void *>(context), &context->work));
    NAPI_CALL(env, napi_queue_async_work(env, context->work));
    contextPtr.release();
    return result;
}

napi_value NapiAccountIAMUserAuth::SetProperty(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    SetPropertyContext *context = new (std::nothrow) SetPropertyContext(env);
    if (context == nullptr) {
        ACCOUNT_LOGE("failed to create SetPropertyContext");
        return result;
    }
    std::unique_ptr<SetPropertyContext> contextPtr(context);
    if (ParseContextForGetSetProperty(env, info, context, &result, false) != napi_ok) {
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetProperty", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            SetPropertyContext *context = reinterpret_cast<SetPropertyContext *>(data);
            auto setPropCallback = std::make_shared<NapiSetPropCallback>(
                context->env, context->callbackRef, context->deferred);
            AccountIAMClient::GetInstance().SetProperty(0, context->request, setPropCallback);
            context->callbackRef = nullptr;
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<SetPropertyContext *>(data);
        },
        reinterpret_cast<void *>(context), &context->work));
    NAPI_CALL(env, napi_queue_async_work(env, context->work));
    contextPtr.release();
    return result;
}

static napi_status ParseContextForAuth(
    napi_env env, napi_callback_info info, AuthContext &context, bool needUser = false)
{
    size_t expectedSize = needUser ? ARG_SIZE_FIVE : ARG_SIZE_FOUR;
    size_t argc = ARG_SIZE_FIVE;
    napi_value argv[ARG_SIZE_FIVE] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != expectedSize) {
        ACCOUNT_LOGE("failed to parse parameters, expect %{public}zu parameters, but got %{public}zu",
            expectedSize, argc);
        std::string errMsg = "The arg number must be at least " + std::to_string(expectedSize) + " characters";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, context.throwErr);
        return napi_invalid_arg;
    }
    int32_t index = 0;
    if (needUser && !GetIntProperty(env, argv[index++], context.userId)) {
        ACCOUNT_LOGE("Get userId failed");
        std::string errMsg = "The type of arg " + std::to_string(index) + " must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, context.throwErr);
        return napi_invalid_arg;
    }
    if (ParseUint8TypedArrayToVector(env, argv[index++], context.challenge)!= napi_ok) {
        ACCOUNT_LOGE("Get challenge failed");
        std::string errMsg = "The type of arg " + std::to_string(index) + " must be valid int array";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, context.throwErr);
        return napi_invalid_arg;
    }
    if (!GetIntProperty(env, argv[index++], context.authType)) {
        ACCOUNT_LOGE("Get authType failed");
        std::string errMsg = "The type of arg " + std::to_string(index) + " must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, context.throwErr);
        return napi_invalid_arg;
    }
    if (!GetIntProperty(env, argv[index++], context.trustLevel)) {
        ACCOUNT_LOGE("Get trustLevel failed");
        std::string errMsg = "The type of arg " + std::to_string(index) + " must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, context.throwErr);
        return napi_invalid_arg;
    }
    JsIAMCallback jsCallback;
    if (ParseIAMCallback(env, argv[index++], jsCallback) != napi_ok) {
        ACCOUNT_LOGE("Get callback failed");
        std::string errMsg = "The type of arg " + std::to_string(index) + " must be function";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, context.throwErr);
        return napi_invalid_arg;
    }
    NapiUserAuthCallback *object = new (std::nothrow) NapiUserAuthCallback(env, jsCallback);
    if (object == nullptr) {
        ACCOUNT_LOGE("failed to create NapiUserAuthCallback");
        return napi_generic_failure;
    }
    context.callback.reset(object);
    return napi_ok;
}

napi_value NapiAccountIAMUserAuth::Auth(napi_env env, napi_callback_info info)
{
    AuthContext context;
    NAPI_CALL(env, ParseContextForAuth(env, info, context));
    uint64_t contextId = AccountIAMClient::GetInstance().Auth(context.challenge,
        static_cast<AuthType>(context.authType), static_cast<AuthTrustLevel>(context.trustLevel), context.callback);
    return CreateUint8Array(env, reinterpret_cast<uint8_t *>(&contextId), sizeof(uint64_t));
}

napi_value NapiAccountIAMUserAuth::AuthUser(napi_env env, napi_callback_info info)
{
    AuthContext context;
    NAPI_CALL(env, ParseContextForAuth(env, info, context, true));
    uint64_t contextId;
    AccountIAMClient::GetInstance().AuthUser(context.userId, context.challenge,
        static_cast<AuthType>(context.authType), static_cast<AuthTrustLevel>(context.trustLevel), context.callback);
    return CreateUint8Array(env, reinterpret_cast<uint8_t *>(&contextId), sizeof(uint64_t));
}

napi_value NapiAccountIAMUserAuth::CancelAuth(napi_env env, napi_callback_info info)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != ARG_SIZE_ONE) {
        ACCOUNT_LOGE("failed to parse parameters, expect at least one parameter, but got %zu", argc);
        std::string errMsg = "The arg number must be at least " + std::to_string(ARG_SIZE_ONE) + " characters";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    uint64_t contextId = 0;
    if (ParseUint8TypedArrayToUint64(env, argv[0], contextId) != napi_ok) {
        ACCOUNT_LOGE("failed to parse contextId");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    int32_t result = AccountIAMClient::GetInstance().CancelAuth(contextId);
    napi_value napiResult = nullptr;
    if (result == ERR_OK) {
        NAPI_CALL(env, napi_create_int32(env, result, &napiResult));
        return napiResult;
    }
    AccountIAMNapiThrow(env, AccountIAMConvertToJSErrCode(result), true);
    return nullptr;
}
}  // namespace AccountJsKit
}  // namespace OHOS

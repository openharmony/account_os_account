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

#include "napi_account_iam_identity_manager.h"

#include <memory>
#include "account_log_wrapper.h"
#include "account_iam_client.h"
#include "napi_account_iam_common.h"
#include "napi_account_common.h"
#include "napi_account_error.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;

napi_value NapiAccountIAMIdentityManager::Init(napi_env env, napi_value exports)
{
    napi_value cons;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("openSession", OpenSession),
        DECLARE_NAPI_FUNCTION("addCredential", AddCredential),
        DECLARE_NAPI_FUNCTION("updateCredential", UpdateCredential),
        DECLARE_NAPI_FUNCTION("closeSession", CloseSession),
        DECLARE_NAPI_FUNCTION("cancel", Cancel),
        DECLARE_NAPI_FUNCTION("delUser", DelUser),
        DECLARE_NAPI_FUNCTION("delCred", DelCred),
        DECLARE_NAPI_FUNCTION("getAuthInfo", GetAuthInfo),
    };
    NAPI_CALL(env, napi_define_class(env, "UserIdentityManager", NAPI_AUTO_LENGTH, JsConstructor,
        nullptr, sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    NAPI_CALL(env, napi_set_named_property(env, exports, "UserIdentityManager", cons));
    return exports;
}

napi_value NapiAccountIAMIdentityManager::JsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

static bool ParseContextForOpenSession(
    napi_env env, napi_callback_info info, IDMContext *context)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (argc > 0) {
        if (!GetCallbackProperty(env, argv[0], context->callbackRef, 1)) {
            std::string errMsg = "The type of arg 1 must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return false;
        }
    }
    return true;
}

napi_value NapiAccountIAMIdentityManager::OpenSession(napi_env env, napi_callback_info info)
{
    IDMContext *context = new (std::nothrow) IDMContext(env);
    if (context == nullptr) {
        ACCOUNT_LOGE("failed to create IDMContext for insufficient memory");
        return nullptr;
    }
    std::unique_ptr<IDMContext> contextPtr(context);
    if (!ParseContextForOpenSession(env, info, context)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (context->callbackRef == nullptr) {
        napi_create_promise(env, &context->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "OpenSession", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            IDMContext *context = reinterpret_cast<IDMContext *>(data);
            context->errCode = AccountIAMClient::GetInstance().OpenSession(0, context->challenge);
        },
        [](napi_env env, napi_status status, void *data) {
            IDMContext *context = reinterpret_cast<IDMContext *>(data);
            napi_value errJs = nullptr;
            napi_value dataJs = nullptr;
            if (context->errCode != 0) {
                int32_t jsErrCode = AccountIAMConvertToJSErrCode(context->errCode);
                errJs = GenerateBusinessError(env, jsErrCode, ConvertToJsErrMsg(jsErrCode));
                napi_get_null(env, &dataJs);
            } else {
                napi_get_null(env, &errJs);
                dataJs = CreateUint8Array(env, context->challenge.data(), context->challenge.size());
            }
            CallbackAsyncOrPromise(env, context, errJs, dataJs);
            delete context;
        },
        reinterpret_cast<void *>(context), &context->work));
    NAPI_CALL(env, napi_queue_async_work(env, context->work));
    contextPtr.release();
    return result;
}

static bool ParseContextForUpdateCredential(napi_env env, napi_callback_info info, IDMContext *context)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);
    if (argc < ARG_SIZE_TWO) {
        std::string errMsg = "The arg number must be at least 2 characters";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (ParseAddCredInfo(env, argv[PARAM_ZERO], context->addCredInfo) != napi_ok) {
        std::string errMsg = "The type of arg 1 must be valid CredentialInfo";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (ParseIAMCallback(env, argv[PARAM_ONE], context->callback) != napi_ok) {
        std::string errMsg = "The type of arg 2 must be valid IIdmCallback";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    return true;
}

napi_value NapiAccountIAMIdentityManager::AddCredential(napi_env env, napi_callback_info info)
{
    IDMContext *context = new (std::nothrow) IDMContext(env);
    if (context == nullptr) {
        ACCOUNT_LOGE("failed to create IDMContext");
        return nullptr;
    }
    std::unique_ptr<IDMContext> contextPtr(context);
    if (!ParseContextForUpdateCredential(env, info, context)) {
        return nullptr;
    }

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "AddCredential", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            IDMContext *context = reinterpret_cast<IDMContext *>(data);
            auto idmCallback = std::make_shared<NapiIDMCallback>(context->env, context->callback);
            AccountIAMClient::GetInstance().AddCredential(0, context->addCredInfo, idmCallback);
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<IDMContext *>(data);
        },
        reinterpret_cast<void *>(context), &context->work));
    NAPI_CALL(env, napi_queue_async_work(env, context->work));
    contextPtr.release();
    return nullptr;
}

napi_value NapiAccountIAMIdentityManager::UpdateCredential(napi_env env, napi_callback_info info)
{
    IDMContext *context = new (std::nothrow) IDMContext(env);
    if (context == nullptr) {
        ACCOUNT_LOGE("failed to create IDMContext");
        return nullptr;
    }
    std::unique_ptr<IDMContext> contextPtr(context);
    if (!ParseContextForUpdateCredential(env, info, context)) {
        return nullptr;
    }

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "UpdateCredential", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            IDMContext *context = reinterpret_cast<IDMContext *>(data);
            auto idmCallback = std::make_shared<NapiIDMCallback>(context->env, context->callback);
            AccountIAMClient::GetInstance().UpdateCredential(0, context->addCredInfo, idmCallback);
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<IDMContext *>(data);
        },
        reinterpret_cast<void *>(context), &context->work));
    NAPI_CALL(env, napi_queue_async_work(env, context->work));
    contextPtr.release();
    return nullptr;
}

napi_value NapiAccountIAMIdentityManager::CloseSession(napi_env env, napi_callback_info info)
{
    AccountIAMClient::GetInstance().CloseSession(0);
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

napi_value NapiAccountIAMIdentityManager::Cancel(napi_env env, napi_callback_info info)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("failed to parse parameters, expect one parameter, but got %{public}zu", argc);
        std::string errMsg = "The arg number must be at least 1 characters";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    uint8_t *data = nullptr;
    size_t length = 0;
    napi_status status = ParseUint8TypedArray(env, argv[0], &data, &length);
    if ((status != napi_ok) || (length < sizeof(uint64_t))) {
        std::string errMsg = "The type of arg 1 must be a uint8_t array";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    int32_t ret = AccountIAMClient::GetInstance().Cancel(0);
    napi_value napiResult = nullptr;
    if (ret == ERR_OK) {
        napi_create_int32(env, ret, &napiResult);
        return napiResult;
    }
    ACCOUNT_LOGE("Failed to cancel account, ret = %d", ret);
    AccountIAMNapiThrow(env, AccountIAMConvertToJSErrCode(ret), true);
    return nullptr;
}

static napi_status ParseContextForDelUser(napi_env env, napi_callback_info info, IDMContext *context)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != ARG_SIZE_TWO) {
        ACCOUNT_LOGE("failed to parse parameters, expect two parameters, but got one");
        std::string errMsg = "The arg number must be at least 2 characters";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    if (ParseUint8TypedArrayToVector(env, argv[0], context->token) != napi_ok) {
        std::string errMsg = "The type of arg 1 must be a uint8_t array";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    if (ParseIAMCallback(env, argv[PARAM_ONE], context->callback) != napi_ok) {
        std::string errMsg = "The type of arg 2 must be valid IIdmCallback";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    return napi_ok;
}

napi_value NapiAccountIAMIdentityManager::DelUser(napi_env env, napi_callback_info info)
{
    IDMContext *context = new (std::nothrow) IDMContext(env);
    if (context == nullptr) {
        ACCOUNT_LOGE("failed to create IDMContext");
        return nullptr;
    }
    std::unique_ptr<IDMContext> contextPtr(context);
    NAPI_CALL(env, ParseContextForDelUser(env, info, context));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "DelUser", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            IDMContext *context = reinterpret_cast<IDMContext *>(data);
            auto idmCallback = std::make_shared<NapiIDMCallback>(context->env, context->callback);
            AccountIAMClient::GetInstance().DelUser(0, context->token, idmCallback);
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<IDMContext *>(data);
        },
        reinterpret_cast<void *>(context), &context->work));
    NAPI_CALL(env, napi_queue_async_work(env, context->work));
    contextPtr.release();
    return nullptr;
}

static napi_status ParseContextForDelCred(napi_env env, napi_callback_info info, IDMContext *context)
{
    size_t argc = ARG_SIZE_THREE;
    napi_value argv[ARG_SIZE_THREE] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != ARG_SIZE_THREE) {
        ACCOUNT_LOGE("failed to parse parameters, expect three parameters, but got %zu", argc);
        std::string errMsg = "The arg number must be at least 3 characters";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    if (ParseUint8TypedArrayToUint64(env, argv[0], context->credentialId) != napi_ok) {
        std::string errMsg = "The type of arg 1 must be a uint8_t array";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    if (ParseUint8TypedArrayToVector(env, argv[PARAM_ONE], context->token) != napi_ok) {
        std::string errMsg = "The type of arg 2 must be a uint8_t array";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    if (ParseIAMCallback(env, argv[PARAM_TWO], context->callback) != napi_ok) {
        std::string errMsg = "The type of arg 3 must be valid IIdmCallback";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    return napi_ok;
}

napi_value NapiAccountIAMIdentityManager::DelCred(napi_env env, napi_callback_info info)
{
    IDMContext *context = new (std::nothrow) IDMContext(env);
    if (context == nullptr) {
        ACCOUNT_LOGE("failed to create IDMContext");
        return nullptr;
    }
    std::unique_ptr<IDMContext> contextPtr(context);
    NAPI_CALL(env, ParseContextForDelCred(env, info, context));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "DelCred", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            IDMContext *context = reinterpret_cast<IDMContext *>(data);
            auto idmCallback = std::make_shared<NapiIDMCallback>(context->env, context->callback);
            AccountIAMClient::GetInstance().DelCred(0, context->credentialId, context->token, idmCallback);
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<IDMContext *>(data);
        },
        reinterpret_cast<void *>(context), &context->work));
    NAPI_CALL(env, napi_queue_async_work(env, context->work));
    contextPtr.release();
    return nullptr;
}

static napi_status ParseOneParamForGetAuthInfo(napi_env env, GetAuthInfoContext *context,
    napi_value *result, napi_value argv, int32_t &authType)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, argv, &valueType), napi_generic_failure);
    if (valueType == napi_function) {
        if (!GetCallbackProperty(env, argv, context->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg 1 must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return napi_invalid_arg;
        }
    } else if (valueType == napi_number) {
        if (!GetIntProperty(env, argv, authType)) {
            ACCOUNT_LOGE("Get authType failed");
            std::string errMsg = "The type of arg 1 must be number";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return napi_invalid_arg;
        }
        NAPI_CALL_BASE(env, napi_create_promise(env, &context->deferred, result), napi_generic_failure);
    } else {
        ACCOUNT_LOGE("Get arg 1 failed");
        std::string errMsg = "The type of arg 1 must be number or function";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    return napi_ok;
}

static napi_status ParseContextForGetAuthInfo(
    napi_env env, napi_callback_info info, GetAuthInfoContext *context, napi_value *result)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), napi_generic_failure);
    int32_t authType = 0;
    if (argc == 0) {
        NAPI_CALL_BASE(env, napi_create_promise(env, &context->deferred, result), napi_generic_failure);
        return napi_ok;
    }
    if (argc == ARG_SIZE_ONE) {
        if (ParseOneParamForGetAuthInfo(env, context, result, argv[PARAM_ZERO], authType) != napi_ok) {
            return napi_invalid_arg;
        }
    }
    if (argc == ARG_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[PARAM_ONE], context->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg 2 must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return napi_invalid_arg;
        }
        if (!GetIntProperty(env, argv[PARAM_ZERO], authType)) {
            ACCOUNT_LOGE("Get authType failed");
            std::string errMsg = "The type of arg 1 must be number";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return napi_invalid_arg;
        }
    }

    context->authType = static_cast<AuthType>(authType);
    return napi_ok;
}

napi_value NapiAccountIAMIdentityManager::GetAuthInfo(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    GetAuthInfoContext *context = new (std::nothrow) GetAuthInfoContext(env);
    if (context == nullptr) {
        ACCOUNT_LOGE("failed to create GetAuthInfoContext");
        return result;
    }
    std::unique_ptr<GetAuthInfoContext> contextPtr(context);
    NAPI_CALL(env, ParseContextForGetAuthInfo(env, info, context, &result));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetAuthInfo", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            GetAuthInfoContext *context = reinterpret_cast<GetAuthInfoContext *>(data);
            auto idmCallback = std::make_shared<NapiGetInfoCallback>(
                context->env, context->callbackRef, context->deferred);
            AccountIAMClient::GetInstance().GetCredentialInfo(0, context->authType, idmCallback);
            context->callbackRef = nullptr;
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<GetAuthInfoContext *>(data);
        },
        reinterpret_cast<void *>(context), &context->work));
    NAPI_CALL(env, napi_queue_async_work(env, context->work));
    contextPtr.release();
    return result;
}
}  // namespace AccountJsKit
}  // namespace OHOS

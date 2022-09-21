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

static napi_status ParseContextForOpenSession(
    napi_env env, napi_callback_info info, IDMContext *context, napi_value *result)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), napi_generic_failure);
    napi_valuetype valueType = napi_undefined;
    if (argc > 0) {
        NAPI_CALL_BASE(env, napi_typeof(env, argv[0], &valueType), napi_generic_failure);
    }
    if (valueType == napi_function) {
        NAPI_CALL_BASE(env, napi_create_reference(env, argv[0], 1, &context->callbackRef), napi_generic_failure);
    } else {
        NAPI_CALL_BASE(env, napi_create_promise(env, &context->deferred, result), napi_generic_failure);
    }
    return napi_ok;
}

napi_value NapiAccountIAMIdentityManager::OpenSession(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    IDMContext *context = new (std::nothrow) IDMContext(env);
    if (context == nullptr) {
        ACCOUNT_LOGD("failed to create IDMContext for insufficient memory");
        return result;
    }
    std::unique_ptr<IDMContext> contextPtr(context);
    NAPI_CALL(env, ParseContextForOpenSession(env, info, context, &result));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "OpenSession", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            IDMContext *context = reinterpret_cast<IDMContext *>(data);
            AccountIAMClient::GetInstance().OpenSession(0, context->challenge);
        },
        [](napi_env env, napi_status status, void *data) {
            IDMContext *context = reinterpret_cast<IDMContext *>(data);
            napi_value napiChallenge = CreateUint8Array(
                env, context->challenge.data(), context->challenge.size());
            CallbackAsyncOrPromise(env, context, napiChallenge);
            delete context;
        },
        reinterpret_cast<void *>(context), &context->work));
    NAPI_CALL(env, napi_queue_async_work(env, context->work));
    contextPtr.release();
    return result;
}

static napi_status ParseContextForUpdateCredential(napi_env env, napi_callback_info info, IDMContext *context)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), napi_generic_failure);
    if (argc != ARG_SIZE_TWO) {
        ACCOUNT_LOGD("failed to parse parameters, expect 2 parameters, but got %{public}zu", argc);
        return napi_generic_failure;
    }
    ParseAddCredInfo(env, argv[PARAM_ZERO], context->addCredInfo);
    NAPI_CALL_BASE(env, ParseIAMCallback(env, argv[PARAM_ONE], context->callback), napi_generic_failure);
    return napi_ok;
}

napi_value NapiAccountIAMIdentityManager::AddCredential(napi_env env, napi_callback_info info)
{
    IDMContext *context = new (std::nothrow) IDMContext(env);
    if (context == nullptr) {
        ACCOUNT_LOGD("failed to create IDMContext");
        return nullptr;
    }
    std::unique_ptr<IDMContext> contextPtr(context);
    NAPI_CALL(env, ParseContextForUpdateCredential(env, info, context));
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
        ACCOUNT_LOGD("failed to create IDMContext");
        return nullptr;
    }
    std::unique_ptr<IDMContext> contextPtr(context);
    NAPI_CALL(env, ParseContextForUpdateCredential(env, info, context));
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
    if (argc != ARG_SIZE_ONE) {
        ACCOUNT_LOGD("failed to parse parameters, expect one parameter, but got %{public}zu", argc);
        return nullptr;
    }
    uint8_t *data = nullptr;
    size_t length = 0;
    napi_status status = ParseUint8TypedArray(env, argv[0], &data, &length);
    if ((status != napi_ok) || (length < sizeof(uint64_t))) {
        return nullptr;
    }
    uint64_t *challenge = reinterpret_cast<uint64_t *>(reinterpret_cast<void *>(data));
    int32_t ret = AccountIAMClient::GetInstance().Cancel(0, *challenge);
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, ret, &result));
    return result;
}

static napi_status ParseContextForDelUser(napi_env env, napi_callback_info info, IDMContext *context)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != ARG_SIZE_TWO) {
        ACCOUNT_LOGD("failed to parse parameters, expect two parameters, but got one");
        return napi_invalid_arg;
    }
    NAPI_CALL_BASE(env, ParseUint8TypedArrayToVector(env, argv[0], context->token), napi_invalid_arg);
    return ParseIAMCallback(env, argv[PARAM_ONE], context->callback);
}

napi_value NapiAccountIAMIdentityManager::DelUser(napi_env env, napi_callback_info info)
{
    IDMContext *context = new (std::nothrow) IDMContext(env);
    if (context == nullptr) {
        ACCOUNT_LOGD("failed to create IDMContext");
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
        ACCOUNT_LOGD("failed to parse parameters, expect three parameters, but got %zu", argc);
        return napi_invalid_arg;
    }
    ParseUint8TypedArrayToUint64(env, argv[0], context->credentialId);
    ParseUint8TypedArrayToVector(env, argv[PARAM_ONE], context->token);
    return ParseIAMCallback(env, argv[PARAM_TWO], context->callback);
}

napi_value NapiAccountIAMIdentityManager::DelCred(napi_env env, napi_callback_info info)
{
    IDMContext *context = new (std::nothrow) IDMContext(env);
    if (context == nullptr) {
        ACCOUNT_LOGD("failed to create IDMContext");
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

static napi_status ParseContextForGetAuthInfo(
    napi_env env, napi_callback_info info, GetAuthInfoContext *context, napi_value *result)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), napi_generic_failure);
    int32_t authType = 0;
    napi_valuetype valueType = napi_undefined;
    napi_value callback = nullptr;
    if (argc == 0) {
        NAPI_CALL_BASE(env, napi_create_promise(env, &context->deferred, result), napi_generic_failure);
        return napi_ok;
    }
    callback = argv[argc - 1];
    NAPI_CALL_BASE(env, napi_typeof(env, callback, &valueType), napi_generic_failure);
    if (valueType == napi_function) {
        NAPI_CALL_BASE(env, napi_create_reference(env, callback, 1, &context->callbackRef), napi_generic_failure);
        if (argc == ARG_SIZE_TWO) {
            napi_get_value_int32(env, argv[PARAM_ZERO], &authType);
        }
    } else {
        NAPI_CALL_BASE(env, napi_create_promise(env, &context->deferred, result), napi_generic_failure);
        if (argc == ARG_SIZE_ONE) {
            napi_get_value_int32(env, argv[PARAM_ZERO], &authType);
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
        ACCOUNT_LOGD("failed to create GetAuthInfoContext");
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

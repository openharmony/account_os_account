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
        DECLARE_NAPI_FUNCTION("prepareRemoteAuth", PrepareRemoteAuth),
    };
    NAPI_CALL(env, napi_define_class(env, "UserAuth", NAPI_AUTO_LENGTH, JsConstructor,
        nullptr, sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    NAPI_CALL(env, napi_set_named_property(env, exports, "UserAuth", cons));
    return exports;
}

napi_value NapiAccountIAMUserAuth::JsConstructor(napi_env env, napi_callback_info info)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

napi_value NapiAccountIAMUserAuth::GetVersion(napi_env env, napi_callback_info info)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
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
        std::string errMsg = "Parameter error. The number of parameters should be at least 2";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    napi_valuetype valType = napi_undefined;
    napi_typeof(env, argv[PARAM_ZERO], &valType);
    if (valType != napi_number) {
        std::string errMsg = "Parameter error. The type of \"authType\" must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    int32_t authType = -1;
    napi_get_value_int32(env, argv[PARAM_ZERO], &authType);
    napi_typeof(env, argv[PARAM_ONE], &valType);
    if (valType != napi_number) {
        std::string errMsg = "Parameter error. The type of \"authTrustLevel\" must be number";
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
        std::string errMsg = "Parameter error. The number of parameters should be at least 1";
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
        if (ParseGetPropRequest(env, argv[PARAM_ZERO], *(reinterpret_cast<GetPropertyContext *>(context))) != napi_ok) {
            std::string errMsg = "Parameter error. The type of \"request\" must be GetPropertyRequest";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return napi_generic_failure;
        }
    } else {
        if (ParseSetPropRequest(env, argv[PARAM_ZERO], reinterpret_cast<SetPropertyContext *>(context)->request) !=
            napi_ok) {
            std::string errMsg = "Parameter error. The type of \"request\" must be SetPropertyRequest";
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
                context->env, context->callbackRef, context->deferred, context->request);
            if ((context->parseHasAccountId) && (IsRestrictedAccountId(context->accountId))) {
                AccountSA::Attributes emptyInfo;
                getPropCallback->OnResult(ERR_JS_CREDENTIAL_NOT_EXIST, emptyInfo);
                return;
            }
            context->callbackRef = nullptr;
            AccountIAMClient::GetInstance().GetProperty(context->accountId, context->request, getPropCallback);
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<GetPropertyContext *>(data);
        },
        reinterpret_cast<void *>(context), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_user_initiated));
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
            context->callbackRef = nullptr;
            AccountIAMClient::GetInstance().SetProperty(0, context->request, setPropCallback);
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<SetPropertyContext *>(data);
        },
        reinterpret_cast<void *>(context), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_user_initiated));
    contextPtr.release();
    return result;
}

static bool ParseContextForRemoteAuthOptions(napi_env env, napi_value jsOptions, RemoteAuthOptions &remoteAuthOptions)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, jsOptions, &valueType);
    if (valueType == napi_undefined || valueType == napi_null) {
        ACCOUNT_LOGI("RemoteAuthOptions is undefined or null");
        return true;
    }
    if (valueType != napi_object) {
        ACCOUNT_LOGE("Invalid object.");
        std::string errMsg = "Parameter error. The type of \"remoteAuthOptions\" must be object";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!GetOptionalStringPropertyByKey(env, jsOptions, "verifierNetworkId",
        remoteAuthOptions.verifierNetworkId, remoteAuthOptions.hasVerifierNetworkId)) {
        ACCOUNT_LOGE("Get remoteAuthOptions's verifierNetworkId failed.");
        std::string errMsg = "Parameter error. The type of \"verifierNetworkId\" must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!GetOptionalStringPropertyByKey(env, jsOptions, "collectorNetworkId",
        remoteAuthOptions.collectorNetworkId, remoteAuthOptions.hasCollectorNetworkId)) {
        ACCOUNT_LOGE("Get remoteAuthOptions's collectorNetworkId failed.");
        std::string errMsg = "Parameter error. The type of \"collectorNetworkId\" must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    int32_t tokenId = 0;
    if (!GetOptionalNumberPropertyByKey(
        env, jsOptions, "collectorTokenId", tokenId, remoteAuthOptions.hasCollectorTokenId)) {
        ACCOUNT_LOGE("Get remoteAuthOptions's collectorTokenId failed.");
        std::string errMsg = "Parameter error. The type of \"collectorTokenId\" must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    remoteAuthOptions.collectorTokenId = static_cast<uint32_t>(tokenId);
    return true;
}

static bool ParseContextForAuthOptions(napi_env env, napi_value jsOptions, AuthOptions &authOptions)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, jsOptions, &valueType);
    if (valueType == napi_undefined || valueType == napi_null) {
        ACCOUNT_LOGI("AuthOption is undefined or null");
        return true;
    }
    if (valueType != napi_object) {
        ACCOUNT_LOGE("Invalid object.");
        std::string errMsg = "Parameter error. The type of \"authOptions\" must be object";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!GetOptionalNumberPropertyByKey(
        env, jsOptions, "accountId", authOptions.accountId, authOptions.hasAccountId)) {
        ACCOUNT_LOGE("Get authOptions's accountId failed.");
        std::string errMsg = "Parameter error. The type of \"accountId\" must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    int32_t authIntent = 0;
    bool hasProp = false;
    if (!GetOptionalNumberPropertyByKey(env, jsOptions, "authIntent", authIntent, hasProp)) {
        ACCOUNT_LOGE("Get authOptions's authIntent failed.");
        std::string errMsg = "Parameter error. The type of \"authIntent\" must be AuthIntent";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    authOptions.authIntent = static_cast<AuthIntent>(authIntent);
    if (IsOptionalPropertyExist(env, jsOptions, "remoteAuthOptions")) {
        napi_value value = nullptr;
        NAPI_CALL_BASE(env, napi_get_named_property(env, jsOptions, "remoteAuthOptions", &value), false);
        if (!ParseContextForRemoteAuthOptions(env, value, authOptions.remoteAuthOptions)) {
            ACCOUNT_LOGE("Parse remoteAuthOptions failed.");
            return false;
        }
        authOptions.hasRemoteAuthOptions = true;
    }
    return true;
}

static napi_status ParseContextForAuth(napi_env env, napi_value *argv, size_t argc, AuthContext &context)
{
    if (argc != ARG_SIZE_FOUR && argc != ARG_SIZE_FIVE) {
        ACCOUNT_LOGE("the number of parameter is incorrect, expect 4 or 5, but got %{public}zu", argc);
        return napi_invalid_arg;
    }
    size_t index = 0;
    if (ParseUint8TypedArrayToVector(env, argv[index++], context.challenge) != napi_ok) {
        ACCOUNT_LOGE("fail to parse challenge");
        std::string errMsg = "Parameter error. The type of \"challenge\" must be Uint8Array";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    if (!GetIntProperty(env, argv[index++], context.authType)) {
        ACCOUNT_LOGE("fail to parse authType");
        std::string errMsg = "Parameter error. The type of \"authType\" must be AuthType";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    if (!GetIntProperty(env, argv[index++], context.trustLevel)) {
        ACCOUNT_LOGE("fail to parse trustLevel");
        std::string errMsg = "Parameter error. The type of \"authTrustLevel\" must be AuthTrustLevel";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    if (argc == PARAM_FIVE) {
        if (!ParseContextForAuthOptions(env, argv[index++], context.authOptions)) {
            ACCOUNT_LOGE("fail to parse authOptions");
            return napi_invalid_arg;
        }
    }
    std::shared_ptr<JsIAMCallback> jsCallback = std::make_shared<JsIAMCallback>(env);
    if (ParseIAMCallback(env, argv[index++], jsCallback) != napi_ok) {
        ACCOUNT_LOGE("fail to parse callback");
        std::string errMsg = "Parameter error. The type of \"callback\" must be function";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    context.callback = std::make_shared<NapiUserAuthCallback>(env, jsCallback);
    return napi_ok;
}

static napi_status ParseContextForAuthUser(napi_env env, napi_value *argv, size_t argc, AuthContext &context)
{
    if (argc != ARG_SIZE_FIVE) {
        ACCOUNT_LOGE("the number of parameter is incorrect, expect 5, but got %{public}zu", argc);
        std::string errMsg = "Parameter error. The number of parameters should be at least 5";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    if (!GetIntProperty(env, argv[0], context.userId)) {
        ACCOUNT_LOGE("Get userId failed");
        std::string errMsg = "Parameter error. The type of \"userId\" must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    return ParseContextForAuth(env, &argv[1], ARG_SIZE_FOUR, context);
}

napi_value NapiAccountIAMUserAuth::Auth(napi_env env, napi_callback_info info)
{
    size_t argc = ARG_SIZE_FIVE;
    napi_value argv[ARG_SIZE_FIVE] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < ARG_SIZE_FOUR) {
        ACCOUNT_LOGE("the number of parameter is incorrect, expect 4, but got %{public}zu", argc);
        std::string errMsg = "Parameter error. The number of parameters should be at least 4";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    AuthContext context;
    if (ParseContextForAuth(env, argv, argc, context) == napi_invalid_arg) {
        return nullptr;
    }
    if ((context.authOptions.hasAccountId) && (IsRestrictedAccountId(context.authOptions.accountId))) {
        AccountSA::Attributes emptyInfo;
        context.callback->OnResult(ERR_JS_CREDENTIAL_NOT_EXIST, emptyInfo);
        return nullptr;
    }
    uint64_t contextId = AccountIAMClient::GetInstance().Auth(context.authOptions, context.challenge,
        static_cast<AuthType>(context.authType), static_cast<AuthTrustLevel>(context.trustLevel), context.callback);
    return CreateUint8Array(env, reinterpret_cast<uint8_t *>(&contextId), sizeof(uint64_t));
}

napi_value NapiAccountIAMUserAuth::AuthUser(napi_env env, napi_callback_info info)
{
    size_t argc = ARG_SIZE_FIVE;
    napi_value argv[ARG_SIZE_FIVE] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    AuthContext context;
    if (ParseContextForAuthUser(env, argv, argc, context) == napi_invalid_arg) {
        return nullptr;
    }
    if (IsRestrictedAccountId(context.userId)) {
        AccountSA::Attributes emptyInfo;
        context.callback->OnResult(ERR_JS_CREDENTIAL_NOT_EXIST, emptyInfo);
        return nullptr;
    }
    context.authOptions.accountId = context.userId;
    uint64_t contextId = AccountIAMClient::GetInstance().AuthUser(context.authOptions, context.challenge,
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
        std::string errMsg = "Parameter error. The number of parameters should be at least 1";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    uint64_t contextId = 0;
    if (ParseUint8TypedArrayToUint64(env, argv[0], contextId) != napi_ok) {
        ACCOUNT_LOGE("failed to parse contextId");
        std::string errMsg = "Parameter error. The type of \"contextID\" must be Uint8Array";
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

static napi_status ParseContextForPrepareRemoteAuth(
    napi_env env, napi_callback_info info, PrepareRemoteAuthContext *context, napi_value *result)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), napi_generic_failure);
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("Parse parameters failed, expect at least one parameter, but got %zu.", argc);
        std::string errMsg = "Parameter error. The arg number must be at least 1 characters";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_generic_failure;
    }
    if (!GetStringProperty(env, argv[0], context->remoteNetworkId)) {
        ACCOUNT_LOGE("Get remoteNetworkId failed");
        std::string errMsg = "Parameter error. The type of remoteNetworkId must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_generic_failure;
    }
    NAPI_CALL_BASE(env, napi_create_promise(env, &context->deferred, result), napi_generic_failure);

    return napi_ok;
}

napi_value NapiAccountIAMUserAuth::PrepareRemoteAuth(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    PrepareRemoteAuthContext *context = new (std::nothrow) PrepareRemoteAuthContext(env);
    if (context == nullptr) {
        ACCOUNT_LOGE("Create PrepareRemoteAuthContext failed.");
        return result;
    }
    std::unique_ptr<PrepareRemoteAuthContext> contextPtr(context);

    if (ParseContextForPrepareRemoteAuth(env, info, context, &result) != napi_ok) {
        return nullptr;
    }

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "PrepareRemoteAuth", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            if (data == nullptr) {
                ACCOUNT_LOGE("PrepareRemoteAuth work data is nullptr.");
                return;
            }
            PrepareRemoteAuthContext *context = reinterpret_cast<PrepareRemoteAuthContext *>(data);
            auto prepareRemoteAuthCallback = std::make_shared<NapiPrepareRemoteAuthCallback>(
                context->env, context->callbackRef, context->deferred);
            context->callbackRef = nullptr;
            context->result = AccountIAMClient::GetInstance().PrepareRemoteAuth(
                context->remoteNetworkId, prepareRemoteAuthCallback);
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<PrepareRemoteAuthContext *>(data);
        },
        reinterpret_cast<void *>(context), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_user_initiated));
    contextPtr.release();
    return result;
}
}  // namespace AccountJsKit
}  // namespace OHOS

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

#include "napi_account_iam_identity_manager.h"

#include <memory>
#include <mutex>
#include <unordered_set>

#include "account_log_wrapper.h"
#include "account_iam_client.h"
#include "napi_account_common.h"
#include "napi_account_error.h"
#include "napi_account_iam_common.h"
#include "user_idm_client.h"
#include "user_idm_client_callback.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;

const int32_t UINT8_SHIFT_LENGTH = 8;
const std::set<int32_t> TARGET_TYPES = {
    static_cast<int32_t>(AuthType::PIN),
    static_cast<int32_t>(AuthType::FINGERPRINT),
    static_cast<int32_t>(AuthType::FACE),
    static_cast<int32_t>(AuthType::PRIVATE_PIN),
    static_cast<int32_t>(AuthType::COMPANION_DEVICE)
};
const std::set<int32_t> UNSUPPORTED_TYPES = {
    static_cast<int32_t>(AuthType::RECOVERY_KEY),
    static_cast<int32_t>(IAMAuthType::DOMAIN)
};

static std::unordered_set<napi_env> g_registeredEnvs;
static std::mutex g_envRegistrationLock;
std::mutex g_lockForCredChangeSubscribers;
std::vector<std::shared_ptr<CredSubscriberPtr>> g_credChangeSubscribers;


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
        DECLARE_NAPI_FUNCTION("getEnrolledId", GetEnrolledId),
        DECLARE_NAPI_FUNCTION("onCredentialChanged", OnCredentialChanged),
        DECLARE_NAPI_FUNCTION("offCredentialChanged", OffCredentialChanged),
    };
    NAPI_CALL(env, napi_define_class(env, "UserIdentityManager", NAPI_AUTO_LENGTH, JsConstructor,
        nullptr, sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    NAPI_CALL(env, napi_set_named_property(env, exports, "UserIdentityManager", cons));
    return exports;
}

napi_value NapiAccountIAMIdentityManager::JsConstructor(napi_env env, napi_callback_info info)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
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
        if ((!GetCallbackProperty(env, argv[0], context->callbackRef, 1)) &&
            (!GetOptionIntProperty(env, argv[0], context->accountId, context->parseHasAccountId))) {
            std::string errMsg = "Parameter error. The type of arg 1 must be function or number";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return false;
        }
    }
    return true;
}

static bool ParseContextForCloseSession(
    napi_env env, napi_callback_info info, IDMContext *context)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);
    if (argc > 0) {
        if (!GetOptionIntProperty(env, argv[0], context->accountId, context->parseHasAccountId)) {
            std::string errMsg = "Parameter error. The type of \"accountId\" must be number";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return false;
        }
    }
    return true;
}

napi_value NapiAccountIAMIdentityManager::OpenSession(napi_env env, napi_callback_info info)
{
    auto context = std::make_unique<IDMContext>(env);
    if (!ParseContextForOpenSession(env, info, context.get())) {
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
            if ((context->parseHasAccountId) && (!IsAccountIdValid(context->accountId))) {
                context->errCode = ERR_JS_ACCOUNT_NOT_FOUND;
                return;
            }
            context->errCode = AccountIAMClient::GetInstance().OpenSession(context->accountId, context->challenge);
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
        reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_user_initiated));
    context.release();
    return result;
}

static bool ParseContextForUpdateCredential(napi_env env, napi_callback_info info, IDMContext *context)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);
    if (argc < ARG_SIZE_TWO) {
        std::string errMsg = "Parameter error. The number of parameters should be 2";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (ParseAddCredInfo(env, argv[PARAM_ZERO], *context) != napi_ok) {
        std::string errMsg = "Parameter error. The type of \"credentialInfo\" must be CredentialInfo";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    context->callback = std::make_shared<JsIAMCallback>(env);
    if (ParseIAMCallback(env, argv[PARAM_ONE], context->callback) != napi_ok) {
        std::string errMsg = "Parameter error. The type of \"callback\" must be function";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    return true;
}

napi_value NapiAccountIAMIdentityManager::AddCredential(napi_env env, napi_callback_info info)
{
    auto context = std::make_unique<IDMContext>(env);
    if (!ParseContextForUpdateCredential(env, info, context.get())) {
        return nullptr;
    }

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "AddCredential", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            IDMContext *context = reinterpret_cast<IDMContext *>(data);
            auto idmCallback = std::make_shared<NapiIDMCallback>(context->env, context->callback);
            if ((context->parseHasAccountId) && (!IsAccountIdValid(context->accountId))) {
                Attributes emptyResult;
                idmCallback->OnResult(ERR_JS_ACCOUNT_NOT_FOUND, emptyResult);
                return;
            }
            AccountIAMClient::GetInstance().AddCredential(context->accountId, context->addCredInfo, idmCallback);
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<IDMContext *>(data);
        },
        reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_user_initiated));
    context.release();
    return nullptr;
}

napi_value NapiAccountIAMIdentityManager::UpdateCredential(napi_env env, napi_callback_info info)
{
    auto context = std::make_unique<IDMContext>(env);
    if (!ParseContextForUpdateCredential(env, info, context.get())) {
        return nullptr;
    }

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "UpdateCredential", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            IDMContext *context = reinterpret_cast<IDMContext *>(data);
            auto idmCallback = std::make_shared<NapiIDMCallback>(context->env, context->callback);
           if ((context->parseHasAccountId) && (!IsAccountIdValid(context->accountId))) {
                Attributes emptyResult;
                idmCallback->OnResult(ERR_JS_ACCOUNT_NOT_FOUND, emptyResult);
                return;
            }
            AccountIAMClient::GetInstance().UpdateCredential(context->accountId, context->addCredInfo, idmCallback);
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<IDMContext *>(data);
        },
        reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_user_initiated));
    context.release();
    return nullptr;
}

napi_value NapiAccountIAMIdentityManager::CloseSession(napi_env env, napi_callback_info info)
{
    auto context = std::make_unique<IDMContext>(env);
    if (!ParseContextForCloseSession(env, info, context.get())) {
        return nullptr;
    }
    if ((context->parseHasAccountId) && (!IsAccountIdValid(context->accountId))) {
        AccountIAMNapiThrow(env, AccountIAMConvertToJSErrCode(ERR_JS_ACCOUNT_NOT_FOUND), true);
        return nullptr;
    }
    ErrCode errCode = AccountIAMClient::GetInstance().CloseSession(context->accountId);
    if (errCode != ERR_OK) {
        AccountIAMNapiThrow(env, AccountIAMConvertToJSErrCode(errCode), true);
    }
    return nullptr;
}

napi_value NapiAccountIAMIdentityManager::Cancel(napi_env env, napi_callback_info info)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {0};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("failed to parse parameters, expect one parameter, but got %{public}zu", argc);
        std::string errMsg = "Parameter error. The number of parameters should be 1";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    uint8_t *data = nullptr;
    size_t length = 0;
    napi_status status = ParseUint8TypedArray(env, argv[0], &data, &length);
    if ((status != napi_ok) || (length < sizeof(uint64_t))) {
        std::string errMsg = "Parameter error. The type of \"challenge\" must be Uint8Array";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    int32_t ret = AccountIAMClient::GetInstance().Cancel(-1); // -1 indicates the current user
    napi_value napiResult = nullptr;
    if (ret == ERR_OK) {
        napi_create_int32(env, ret, &napiResult);
        return napiResult;
    }
    ACCOUNT_LOGE("Failed to cancel account, ret = %{public}d", ret);
    AccountIAMNapiThrow(env, AccountIAMConvertToJSErrCode(ret), true);
    return nullptr;
}

static napi_status ParseContextForDelUser(napi_env env, napi_callback_info info, IDMContext *context)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), napi_generic_failure);
    if (argc != ARG_SIZE_TWO) {
        ACCOUNT_LOGE("failed to parse parameters, expect two parameters, but got one");
        std::string errMsg = "Parameter error. The number of parameters should be 2";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    if (ParseUint8TypedArrayToVector(env, argv[0], context->token) != napi_ok) {
        std::string errMsg = "Parameter error. The type of \"token\" must be Uint8Array";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    context->callback = std::make_shared<JsIAMCallback>(env);
    if (ParseIAMCallback(env, argv[PARAM_ONE], context->callback) != napi_ok) {
        std::string errMsg = "Parameter error. The type of \"callback\" must be function";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    return napi_ok;
}

napi_value NapiAccountIAMIdentityManager::DelUser(napi_env env, napi_callback_info info)
{
    auto context = std::make_unique<IDMContext>(env);
    NAPI_CALL(env, ParseContextForDelUser(env, info, context.get()));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "DelUser", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            IDMContext *context = reinterpret_cast<IDMContext *>(data);
            auto idmCallback = std::make_shared<NapiIDMCallback>(context->env, context->callback);
            AccountIAMClient::GetInstance().DelUser(context->accountId, context->token, idmCallback);
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<IDMContext *>(data);
        },
        reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_user_initiated));
    context.release();
    return nullptr;
}

static napi_status ParseContextForDelCred(napi_env env, napi_callback_info info, IDMContext *context)
{
    size_t argc = ARG_SIZE_THREE;
    napi_value argv[ARG_SIZE_THREE] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), napi_generic_failure);
    if (argc < ARG_SIZE_THREE) {
        ACCOUNT_LOGE("failed to parse parameters, expect three parameters, but got %zu", argc);
        std::string errMsg = "Parameter error. The number of parameters should be 3";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    if (ParseUint8TypedArrayToUint64(env, argv[0], context->credentialId) != napi_ok) {
        std::string errMsg = "Parameter error. The type of \"credentialId\" must be Uint8Array";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    if (ParseUint8TypedArrayToVector(env, argv[PARAM_ONE], context->token) != napi_ok) {
        std::string errMsg = "Parameter error. The type of \"token\" must be Uint8Array";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    context->callback = std::make_shared<JsIAMCallback>(env);
    if (ParseIAMCallback(env, argv[PARAM_TWO], context->callback) != napi_ok) {
        std::string errMsg = "Parameter error. The type of \"callback\" must be function";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return napi_invalid_arg;
    }
    return napi_ok;
}

napi_value NapiAccountIAMIdentityManager::DelCred(napi_env env, napi_callback_info info)
{
    auto context = std::make_unique<IDMContext>(env);
    NAPI_CALL(env, ParseContextForDelCred(env, info, context.get()));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "DelCred", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            IDMContext *context = reinterpret_cast<IDMContext *>(data);
            auto idmCallback = std::make_shared<NapiIDMCallback>(context->env, context->callback);
            AccountIAMClient::GetInstance().DelCred(
                context->accountId, context->credentialId, context->token, idmCallback);
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<IDMContext *>(data);
        },
        reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_user_initiated));
    context.release();
    return nullptr;
}

static bool ParseGetAuthInfoOptions(napi_env env, napi_value jsOptions, GetAuthInfoContext *context, int32_t &authType)
{
    bool hasAuthType;
    if (!GetOptionalNumberPropertyByKey(env, jsOptions, "authType", authType, hasAuthType)) {
        ACCOUNT_LOGE("Get authOptions's authType failed");
        return false;
    }
    if (!GetOptionalNumberPropertyByKey(env, jsOptions, "accountId", context->accountId, context->parseHasAccountId)) {
        ACCOUNT_LOGE("Get authOptions's accountId failed");
        return false;
    }
    return true;
}

static napi_status ParseOneParamForGetAuthInfo(napi_env env, GetAuthInfoContext *context,
    napi_value *result, napi_value argv, int32_t &authType)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, argv, &valueType), napi_generic_failure);
    if (valueType == napi_function) {
        if (!GetCallbackProperty(env, argv, context->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "Parameter error. The type of \"callback\" must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return napi_invalid_arg;
        }
    } else if (valueType == napi_number) {
        if (!GetIntProperty(env, argv, authType)) {
            ACCOUNT_LOGE("Get authType failed");
            std::string errMsg = "Parameter error. The type of \"authType\" must be AuthType";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return napi_invalid_arg;
        }
        NAPI_CALL_BASE(env, napi_create_promise(env, &context->deferred, result), napi_generic_failure);
    } else if (valueType == napi_object) {
        if (!ParseGetAuthInfoOptions(env, argv, context, authType)) {
            ACCOUNT_LOGE("Parse GetAuthInfoOptions failed");
            std::string errMsg = "Parameter error. The type of \"options\" must be object";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return napi_invalid_arg;
        }
        NAPI_CALL_BASE(env, napi_create_promise(env, &context->deferred, result), napi_generic_failure);
    } else if ((valueType == napi_undefined) || (valueType == napi_null)) {
        ACCOUNT_LOGI("the arg 1 is undefined or null");
        NAPI_CALL_BASE(env, napi_create_promise(env, &context->deferred, result), napi_generic_failure);
    } else {
        ACCOUNT_LOGE("Get arg 1 failed");
        std::string errMsg = "Parameter error. The type of arg 1 must be AuthType, function or object";
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
            std::string errMsg = "Parameter error. The type of \"callback\" must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return napi_invalid_arg;
        }
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[PARAM_ZERO], &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("the authType is undefined or null");
        } else {
            if (!GetIntProperty(env, argv[PARAM_ZERO], authType)) {
                ACCOUNT_LOGE("Get authType failed");
                std::string errMsg = "Parameter error. The type of \"authType\" must be AuthType";
                AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
                return napi_invalid_arg;
            }
        }
    }

    context->authType = static_cast<AuthType>(authType);
    return napi_ok;
}

napi_value NapiAccountIAMIdentityManager::GetAuthInfo(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    auto context = std::make_unique<GetAuthInfoContext>(env);
    NAPI_CALL(env, ParseContextForGetAuthInfo(env, info, context.get(), &result));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetAuthInfo", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            GetAuthInfoContext *context = reinterpret_cast<GetAuthInfoContext *>(data);
            auto idmCallback = std::make_shared<NapiGetInfoCallback>(
                context->env, context->callbackRef, context->deferred);
            if (idmCallback == nullptr) {
                ACCOUNT_LOGE("Failed for nullptr");
                return;
            }
            context->callbackRef = nullptr;
            if ((context->parseHasAccountId) && (!IsAccountIdValid(context->accountId))) {
                std::vector<AccountSA::CredentialInfo> emptyInfoList;
                idmCallback->OnCredentialInfo(ERR_JS_ACCOUNT_NOT_FOUND, emptyInfoList);
                return;
            }
            AccountIAMClient::GetInstance().GetCredentialInfo(context->accountId, context->authType, idmCallback);
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<GetAuthInfoContext *>(data);
        },
        reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_user_initiated));
    context.release();
    return result;
}

static bool ParseContextForGetEnrolledId(
    napi_env env, napi_callback_info info, GetEnrolledIdContext *context, std::string &errMsg)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {0};

    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);
    if (argc < ARG_SIZE_ONE) {
        errMsg = "Parameter error. the parameter of number should be at least one";
        return false;
    }
    if (argc == ARG_SIZE_TWO) {
        if (!GetOptionIntProperty(env, argv[argc - 1], context->accountId, context->parseHasAccountId)) {
            errMsg = "Parameter error. the type of \"accountId\" must be number";
            return false;
        }
    }
    int32_t authType = 0;
    if (!GetIntProperty(env, argv[0], authType)) {
        errMsg = "Parameter error. the type of \"authType\" must be AuthType";
        return false;
    }
    context->authType = static_cast<AuthType>(authType);
    return true;
}

napi_value NapiAccountIAMIdentityManager::GetEnrolledId(napi_env env, napi_callback_info info)
{
    auto context = std::make_unique<GetEnrolledIdContext>(env);
    std::string errMsg;
    if (!ParseContextForGetEnrolledId(env, info, context.get(), errMsg)) {
        ACCOUNT_LOGE("Parse context failed, %{public}s", errMsg.c_str());
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetEnrolledId", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            if (data == nullptr) {
                ACCOUNT_LOGE("Data is nullptr");
                return;
            }
            GetEnrolledIdContext *context = reinterpret_cast<GetEnrolledIdContext *>(data);
            auto getEnrolledIdCallback = std::make_shared<NapiGetEnrolledIdCallback>(
                context->env, context->deferred);
            if ((context->parseHasAccountId) && (!IsAccountIdValid(context->accountId))) {
                uint64_t enrolledId = 0;
                getEnrolledIdCallback->OnEnrolledId(ERR_JS_ACCOUNT_NOT_FOUND, enrolledId);
                return;
            }
            AccountIAMClient::GetInstance().GetEnrolledId(context->accountId, context->authType, getEnrolledIdCallback);
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<GetEnrolledIdContext *>(data);
        },
        reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_user_initiated));
    context.release();
    return result;
}

static void OnEnvCleanup(void* data)
{
    ACCOUNT_LOGI("Start.");
    napi_env cleanupEnv = static_cast<napi_env>(data);
    {
        std::lock_guard<std::mutex> lock(g_lockForCredChangeSubscribers);
        auto it = g_credChangeSubscribers.begin();
        while (it != g_credChangeSubscribers.end()) {
            if (((*it) != nullptr) && ((*it)->env == cleanupEnv)) {
                ACCOUNT_LOGW("Removing subscriber for destroyed environment");
                UserIam::UserAuth::UserIdmClient::GetInstance().UnRegistCredChangeEventListener((*it));
                it = g_credChangeSubscribers.erase(it);
            } else {
                ++it;
            }
        }
    }
    std::lock_guard<std::mutex> lock(g_envRegistrationLock);
    g_registeredEnvs.erase(cleanupEnv);
}

static bool RegisterEnvCleanupHook(napi_env env)
{
    std::lock_guard<std::mutex> lock(g_envRegistrationLock);
    if (g_registeredEnvs.find(env) != g_registeredEnvs.end()) {
        return true;
    }
    napi_status status = napi_add_env_cleanup_hook(env, OnEnvCleanup, env);
    if (status == napi_ok) {
        g_registeredEnvs.insert(env);
        return true;
    }
    return false;
}

static bool CheckAndGetAuthTypes(napi_env env, std::vector<int32_t> inputTypes,
    std::vector<UserIam::UserAuth::AuthType> &credentialTypes)
{
    if (inputTypes.empty()) {
        ACCOUNT_LOGE("The authtype list should not be empty.");
        std::string errMsg = "The authtype list should not be empty.";
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, errMsg, true);
        return false;
    }
    bool invalidFlag = false;
    bool unsupportFlag = false;
    std::string invalids;
    std::string unsupports;
    for (int32_t inputType : inputTypes) {
        if (TARGET_TYPES.find(inputType) == TARGET_TYPES.end()) {
            if (UNSUPPORTED_TYPES.find(inputType) == UNSUPPORTED_TYPES.end()) {
                invalidFlag = true;
                invalids += std::to_string(inputType) + ",";
            } else {
                unsupportFlag = true;
                unsupports += std::to_string(inputType) + ",";
            }
        } else {
            credentialTypes.push_back(static_cast<UserIam::UserAuth::AuthType>(inputType));
            }
        }
    if ((!invalidFlag) && (!unsupportFlag)) {
        return true;
    }
    if (invalidFlag) {
        ACCOUNT_LOGE("One or more auth types are invalid");
        std::string errMsg = "One or more auth types are invalid: " + invalids;
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, errMsg, true);
        return false;
    }
    if (unsupportFlag) {
        ACCOUNT_LOGE("One or more auth types are not supported");
        std::string errMsg = "One or more auth types are not supported: " + unsupports;
        AccountNapiThrow(env, ERR_JS_AUTH_TYPE_NOT_SUPPORTED, errMsg, true);
    }
    return false;
}

std::pair<bool, std::shared_ptr<CredSubscriberPtr>> FindAndGetSubscriber(
    const std::shared_ptr<CredSubscriberPtr> &targetSubscriber)
{
    for (const auto& each : g_credChangeSubscribers) {
        if ((each->env == targetSubscriber->env) &&
            CompareOnAndOffRef(each->env, each->callback->callbackRef, targetSubscriber->callback->callbackRef)) {
                std::shared_ptr<CredSubscriberPtr> findTarget = each;
                return std::make_pair(true, findTarget);
        }
    }
    return std::make_pair(false, targetSubscriber);
}

napi_value NapiAccountIAMIdentityManager::OnCredentialChanged(napi_env env, napi_callback_info cbInfo)
{
    if (!CheckSelfPermission("ohos.permission.USE_USER_IDM")) {
        ACCOUNT_LOGE("Failed to check permission");
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
        AccountNapiThrow(env, jsErrCode, true);
        return nullptr;
    }
    if (!RegisterEnvCleanupHook(env)) {
        ACCOUNT_LOGE("Failed to register env cleanup hook");
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    napi_ref tempRef = nullptr;
    std::vector<int32_t> inputTypes;
    std::vector<UserIam::UserAuth::AuthType> credentialTypes;
    if (!ParseParaOnCredChange(env, cbInfo, tempRef, inputTypes)) {
        ACCOUNT_LOGE("Parse credential Change subscription failed");
        return nullptr;
    }
    if (!CheckAndGetAuthTypes(env, inputTypes, credentialTypes)) {
        return nullptr;
    }
    auto subscriber = std::make_shared<CredSubscriberPtr>(env, tempRef);
    if (subscriber == nullptr) {
        ACCOUNT_LOGE("Failed to create subscriber");
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    tempRef = nullptr;
    std::lock_guard<std::mutex> lock(g_lockForCredChangeSubscribers);
    auto subscriberWithFindRet = FindAndGetSubscriber(subscriber);
    ErrCode errCode = UserIam::UserAuth::UserIdmClient::GetInstance().RegistCredChangeEventListener(credentialTypes,
        subscriberWithFindRet.second);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SubscribeCredentialChange failed with errCode=%{public}d", errCode);
        AccountNapiThrow(env, AccountIAMConvertToJSErrCode(errCode), true);
        return nullptr;
    }
    if (!subscriberWithFindRet.first) {
        g_credChangeSubscribers.emplace_back(subscriberWithFindRet.second);
    }
    return nullptr;
}

void OffCredChangedSync(napi_env env, std::shared_ptr<CredSubscriberPtr> subscriber)
{
    std::lock_guard<std::mutex> lock(g_lockForCredChangeSubscribers);
    auto it = g_credChangeSubscribers.begin();
    while (it != g_credChangeSubscribers.end()) {
        if ((*it)->env != env) {
            ACCOUNT_LOGW("Current subscriber env is not equal to the input env, continue.");
            it++;
            continue;
        }
        if ((subscriber->callback->callbackRef != nullptr) &&
            !CompareOnAndOffRef(env, (*it)->callback->callbackRef, subscriber->callback->callbackRef)) {
                it++;
                continue;
        }
        ErrCode errCode = UserIam::UserAuth::UserIdmClient::GetInstance()
            .UnRegistCredChangeEventListener((*it));
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Unsubscribe CredChangeEventListener failed with errCode=%{public}d", errCode);
            AccountNapiThrow(env, AccountIAMConvertToJSErrCode(errCode), true);
            return;
        }
        it = g_credChangeSubscribers.erase(it);
        if (subscriber->callback->callbackRef != nullptr) {
            return;
        }
    }
}

napi_value NapiAccountIAMIdentityManager::OffCredentialChanged(napi_env env, napi_callback_info cbInfo)
{
    if (!CheckSelfPermission("ohos.permission.USE_USER_IDM")) {
        ACCOUNT_LOGE("Failed to check permission");
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
        AccountNapiThrow(env, jsErrCode, true);
        return nullptr;
    }
    napi_ref tempRef = nullptr;
    if (!ParseParaOffCredChange(env, cbInfo, tempRef)) {
        ACCOUNT_LOGE("Parse unsubscribe failed");
        return nullptr;
    }
    auto subscriber = std::make_shared<CredSubscriberPtr>(env, tempRef);
    if (subscriber == nullptr) {
        ACCOUNT_LOGE("Failed to create subscriber");
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    tempRef = nullptr;
    OffCredChangedSync(env, subscriber);
    return nullptr;
}

static std::vector<uint8_t> GenerateUint8ArrayFromUint64(const uint64_t data)
{
    std::vector<uint8_t> targetArray(sizeof(uint64_t), 0);
    uint64_t dataCopy =  data;
    size_t vecSize = targetArray.size();
    for (size_t i = vecSize; i >= 1; i--) {
        targetArray[i - 1] = dataCopy & 0xFF;
        dataCopy >>= UINT8_SHIFT_LENGTH;
    }
    std::reverse(targetArray.begin(), targetArray.end());
    return targetArray;
}

static napi_value CreateSubEventData(const std::shared_ptr<CredentialChangeWorker> &credChangeWorker)
{
    napi_env env = credChangeWorker->env;
    napi_value objInfo = nullptr;
    NAPI_CALL(env, napi_create_object(env, &objInfo));
    napi_value userIdJS;
    NAPI_CALL(env, napi_create_int32(env, credChangeWorker->userId, &userIdJS));
    NAPI_CALL(env, napi_set_named_property(env, objInfo, "accountId", userIdJS));
    napi_value authTypeJS;
    NAPI_CALL(env, napi_create_int32(env, credChangeWorker->authType, &authTypeJS));
    NAPI_CALL(env, napi_set_named_property(env, objInfo, "credentialType", authTypeJS));
    napi_value eventTypeJS;
    NAPI_CALL(env, napi_create_int32(env, credChangeWorker->eventType, &eventTypeJS));
    NAPI_CALL(env, napi_set_named_property(env, objInfo, "changeType", eventTypeJS));
    napi_value isSilentJS;
    NAPI_CALL(env, napi_get_boolean(env, credChangeWorker->isSilent, &isSilentJS));
    NAPI_CALL(env, napi_set_named_property(env, objInfo, "isSilent", isSilentJS));
    if (credChangeWorker->addedCredentialId != 0) {
        std::vector<uint8_t> addedCredentialId = GenerateUint8ArrayFromUint64(credChangeWorker->addedCredentialId);
        napi_value addedCredentialIdJS = CreateUint8Array(env, addedCredentialId.data(),
            addedCredentialId.size());
        NAPI_CALL(env, napi_set_named_property(env, objInfo, "addedCredentialId", addedCredentialIdJS));
    }
    if (credChangeWorker->deletedCredentialId != 0) {
        std::vector<uint8_t> deletedCredentialId = GenerateUint8ArrayFromUint64(credChangeWorker->deletedCredentialId);
        napi_value deletedCredentialIdJS = CreateUint8Array(env, deletedCredentialId.data(),
            deletedCredentialId.size());
        NAPI_CALL(env, napi_set_named_property(env, objInfo, "deletedCredentialId", deletedCredentialIdJS));
    }
    return objInfo;
}
std::function<void()> CredChangeNotifyTask(const std::shared_ptr<CredentialChangeWorker> &credChangeWorker)
{
    return [credChangeWorker] {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(credChangeWorker->env, &scope);
        if (scope == nullptr) {
            ACCOUNT_LOGE("Fail to open scope");
            return;
        }
        bool isFound = false;
        {
            std::lock_guard<std::mutex> lock(g_lockForCredChangeSubscribers);
            for (const auto& item : g_credChangeSubscribers) {
                if (item == credChangeWorker->subscriber) {
                    isFound = true;
                    break;
                }
            }
        }
        if (isFound) {
            napi_value eventObj = CreateSubEventData(credChangeWorker);
            NapiCallVoidFunction(credChangeWorker->env, &eventObj, ARG_SIZE_ONE,
                credChangeWorker->callback->callbackRef);
        }
        napi_close_handle_scope(credChangeWorker->env, scope);
    };
}

CredSubscriberPtr::CredSubscriberPtr(napi_env env, napi_ref ref)
{
    this->env = env;
    callback = std::make_shared<NapiCallbackRef>(env, ref);
}

CredSubscriberPtr::~CredSubscriberPtr() {};

void CredSubscriberPtr::OnNotifyCredChangeEvent(int32_t userId, AuthType authType,
    UserIam::UserAuth::CredChangeEventType eventType, const UserIam::UserAuth::CredChangeEventInfo &changeInfo)
{
    std::shared_ptr<CredentialChangeWorker> credChangeWorker = std::make_shared<CredentialChangeWorker>();
    if (credChangeWorker == nullptr) {
        ACCOUNT_LOGE("Failed to create credChangeWorker");
        return;
    }
    if ((eventType == UserIam::UserAuth::CredChangeEventType::DEL_USER) ||
        (eventType == UserIam::UserAuth::CredChangeEventType::ENFORCE_DEL_USER)) {
        credChangeWorker->eventType = UserIam::UserAuth::CredChangeEventType::DEL_CRED;
    } else {
        credChangeWorker->eventType = eventType;
    }
    credChangeWorker->userId = userId;
    credChangeWorker->authType = authType;
    credChangeWorker->isSilent = changeInfo.isSilentCredChange;
    credChangeWorker->addedCredentialId = changeInfo.credentialId;
    credChangeWorker->deletedCredentialId = changeInfo.lastCredentialId;
    credChangeWorker->env = env;
    credChangeWorker->callback = callback;
    credChangeWorker->subscriber = shared_from_this();
    auto task = CredChangeNotifyTask(credChangeWorker);
    if (napi_ok != napi_send_event(env, task, napi_eprio_vip, "OnNotifyCredChangeEvent")) {
        ACCOUNT_LOGE("Post task failed");
        return;
    }
    ACCOUNT_LOGI("Post task finish");
}
}  // namespace AccountJsKit
}  // namespace OHOS

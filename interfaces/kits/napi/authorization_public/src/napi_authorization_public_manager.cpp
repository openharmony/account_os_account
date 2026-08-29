/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "napi_authorization_public_manager.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "authorization_callback.h"
#include "authorization_client.h"
#include "authorization_common.h"
#include "authorization_privilege.h"
#include "napi_account_error.h"
#include "napi_authorization_callback_base.h"
#include "ui_extension_context.h"

using namespace OHOS::AccountSA;

namespace OHOS {
namespace AccountJsKit {
static thread_local napi_ref g_authorizationPublicRef = nullptr;
static napi_property_descriptor g_properties[] = {
    DECLARE_NAPI_FUNCTION("requestAuthorization", &NapiAuthorizationPublicManager::AcquireAuthorization),
    DECLARE_NAPI_FUNCTION("hasAuthorization", &NapiAuthorizationPublicManager::HasAuthorization),
};

namespace {
const size_t ARG_SIZE_ONE = 1;
const size_t ARG_SIZE_TWO = 2;
const size_t PARAM_ONE = 1;
const size_t PARAM_ZERO = 0;

void SetNamedPropertyByStr(napi_env env, napi_value dstObj, const std::string &objName, const char *propName)
{
    napi_value prop = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, objName.c_str(), NAPI_AUTO_LENGTH, &prop));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, dstObj, propName, prop));
}

static napi_value BuildResultJs(napi_env env, const AccountSA::AuthorizationResult &result, napi_value &resultJs)
{
    napi_create_object(env, &resultJs);
    napi_value resultCodeVal = nullptr;
    napi_create_int32(env, static_cast<int32_t>(result.resultCode), &resultCodeVal);
    napi_set_named_property(env, resultJs, "resultCode", resultCodeVal);
    napi_value privilegeVal = nullptr;
    napi_create_string_utf8(env, result.privilege.c_str(), result.privilege.length(), &privilegeVal);
    napi_set_named_property(env, resultJs, "privilege", privilegeVal);
    return resultJs;
}

static bool ParsePrivilegeString(napi_env env, napi_value value, std::string &privilege, bool throwErr)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valueType), false);
    if (valueType != napi_string) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, "The type of \"privilege\" must be Privilege", throwErr);
        return false;
    }
    size_t len = 0;
    NAPI_CALL_BASE(env, napi_get_value_string_utf8(env, value, nullptr, 0, &len), false);
    privilege.resize(len);
    NAPI_CALL_BASE(env, napi_get_value_string_utf8(env, value, privilege.data(), len + 1, &len), false);
    for (const auto &item : AccountSA::PRIVILEGE_MAP) {
        if (privilege == item.second) {
            return true;
        }
    }
    ACCOUNT_LOGE("Invalid privilege: %{public}s", privilege.c_str());
    AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR,
        "Parameter error. The value of \"privilege\" must be a valid Privilege", throwErr);
    return false;
}

static bool ValidateContext(napi_env env, napi_value value, AcquireAuthorizationContext *asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valueType), false);
    if (valueType == napi_undefined || valueType == napi_null) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, "Parameter error. The type of \"context\" must be Context object",
            asyncContext->throwErr);
        return false;
    }
    if (valueType != napi_object) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, "Parameter error. The type of \"context\" must be Context object",
            asyncContext->throwErr);
        return false;
    }
    asyncContext->hasOptions = true;
    asyncContext->options.hasContext = true;
    asyncContext->options.isContextValid = false;
    ConvertContextObject(env, value, asyncContext);
    return true;
}

static bool ParseContextForAcquireAuthorizationPublic(napi_env env, napi_callback_info cbInfo,
    AcquireAuthorizationContext *asyncContext)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {nullptr};
    asyncContext->env = env;
    if (napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr) != napi_ok) {
        ACCOUNT_LOGE("Napi_get_cb_info failed");
        return false;
    }
    if (argc < ARG_SIZE_TWO) {
        ACCOUNT_LOGE("Need input two parameters, but got %{public}zu", argc);
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, "Parameter error. The number of parameters should be 2",
            asyncContext->throwErr);
        return false;
    }
    if (!ParsePrivilegeString(env, argv[PARAM_ZERO], asyncContext->privilege, asyncContext->throwErr)) {
        return false;
    }
    if (!ValidateContext(env, argv[PARAM_ONE], asyncContext)) {
        return false;
    }
    return true;
}

static void AcquireAuthorizationPublicExecuteCB(napi_env env, void *data)
{
    AcquireAuthorizationContext *asyncContext = reinterpret_cast<AcquireAuthorizationContext *>(data);
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("AsyncContext is nullptr.");
        return;
    }
    auto callback = std::make_shared<NapiAuthorizationResultCallback>(asyncContext,
        [](napi_env env, const AuthorizationResult& result, napi_value& resultJs) {
            BuildResultJs(env, result, resultJs);
        });
    asyncContext->errCode = AccountSA::AuthorizationClient::GetInstance().AcquireAuthorizationForPublic(
        asyncContext->privilege, asyncContext->options.isContextValid, callback);
    if (asyncContext->errCode != ERR_OK) {
        AccountSA::AuthorizationResult result;
        result.privilege = asyncContext->privilege;
        callback->OnResult(asyncContext->errCode, result);
    }
}

static void AcquireAuthorizationPublicCompletedCB(napi_env env, napi_status status, void *data)
{
    delete reinterpret_cast<AcquireAuthorizationContext *>(data);
}

static bool ParseContextForHasAuthorizationPublic(napi_env env, napi_callback_info cbInfo,
    HasAuthPublicContext *asyncContext)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {nullptr};
    asyncContext->env = env;
    napi_value thisVar = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr), false);
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("Need input at least one parameter, but got %{public}zu", argc);
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, "Parameter error. The number of parameters should be at least 1",
            asyncContext->throwErr);
        return false;
    }
    return ParsePrivilegeString(env, argv[PARAM_ZERO], asyncContext->privilege, asyncContext->throwErr);
}

static void HasAuthorizationPublicExecuteCB(napi_env env, void *data)
{
    HasAuthPublicContext *asyncContext = reinterpret_cast<HasAuthPublicContext *>(data);
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("AsyncContext is nullptr.");
        return;
    }
    asyncContext->errCode = AccountSA::AuthorizationClient::GetInstance().HasAuthorizationForPublic(
        asyncContext->privilege, asyncContext->isAuthorized);
    ACCOUNT_LOGD("errCode is %{public}d, isAuthorized is %{public}d",
        asyncContext->errCode, asyncContext->isAuthorized);
}

static void HasAuthorizationPublicCompletedCB(napi_env env, napi_status status, void *data)
{
    HasAuthPublicContext *asyncContext = reinterpret_cast<HasAuthPublicContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJS = nullptr;
    if (asyncContext->errCode == ERR_OK) {
        errJs = GenerateBusinessSuccess(env, true);
        napi_get_boolean(env, asyncContext->isAuthorized, &dataJS);
    } else {
        errJs = GenerateAuthorizationBusinessError(env, asyncContext->errCode);
        napi_get_null(env, &dataJS);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJS);
    delete asyncContext;
}
} // namespace

napi_value NapiAuthorizationPublicManager::JsConstructor(napi_env env, napi_callback_info cbInfo)
{
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

napi_value NapiAuthorizationPublicManager::AuthorizationResultCodeConstructor(napi_env env)
{
    napi_value resultCode = nullptr;
    napi_value success = nullptr;
    napi_value canceled = nullptr;
    napi_value notAllowed = nullptr;
    napi_value denied = nullptr;
    napi_value systemBusy = nullptr;
    napi_value notSupported = nullptr;
    NAPI_CALL(env, napi_create_object(env, &resultCode));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AccountSA::AuthorizationResultCode::AUTHORIZATION_SUCCESS), &success));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AccountSA::AuthorizationResultCode::AUTHORIZATION_CANCELED), &canceled));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AccountSA::AuthorizationResultCode::AUTHORIZATION_INTERACTION_NOT_ALLOWED), &notAllowed));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AccountSA::AuthorizationResultCode::AUTHORIZATION_DENIED), &denied));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AccountSA::AuthorizationResultCode::AUTHORIZATION_SERVICE_BUSY), &systemBusy));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AccountSA::AuthorizationResultCode::AUTHORIZATION_PRIVILEGE_NOT_SUPPORTED),
        &notSupported));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_SUCCESS", success));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_CANCELED", canceled));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_INTERACTION_NOT_ALLOWED", notAllowed));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_DENIED", denied));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_SERVICE_BUSY", systemBusy));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_PRIVILEGE_NOT_SUPPORTED", notSupported));
    return resultCode;
}

napi_value NapiAuthorizationPublicManager::PrivilegeConstructor(napi_env env)
{
    napi_value privilege = nullptr;
    NAPI_CALL(env, napi_create_object(env, &privilege));
    for (const auto &item : AccountSA::PRIVILEGE_MAP) {
        SetNamedPropertyByStr(env, privilege, item.second, item.first.c_str());
    }
    return privilege;
}

napi_value NapiAuthorizationPublicManager::GetAuthorizationManager(napi_env env, napi_callback_info cbInfo)
{
    napi_value instance = nullptr;
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, g_authorizationPublicRef, &cons) != napi_ok) {
        ACCOUNT_LOGE("Failed to get authorization manager reference");
        return nullptr;
    }
    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        ACCOUNT_LOGE("Failed to create authorization manager instance");
        return nullptr;
    }
    return instance;
}

napi_value NapiAuthorizationPublicManager::AcquireAuthorization(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<AcquireAuthorizationContext>(env, true);
    if (!ParseContextForAcquireAuthorizationPublic(env, cbInfo, context.get())) {
        ACCOUNT_LOGE("Failed to parse parameter for AcquireAuthorizationContext");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "AcquireAuthorizationForPublic", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, AcquireAuthorizationPublicExecuteCB,
        AcquireAuthorizationPublicCompletedCB, reinterpret_cast<void *>(context.get()), &(context->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_user_initiated));
    context.release();
    return result;
}

napi_value NapiAuthorizationPublicManager::HasAuthorization(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<HasAuthPublicContext>();
    context->env = env;
    context->throwErr = true;
    if (!ParseContextForHasAuthorizationPublic(env, cbInfo, context.get())) {
        ACCOUNT_LOGE("Failed to parse parameter for HasAuthPublicContext");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "HasAuthorizationForPublic", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, HasAuthorizationPublicExecuteCB,
        HasAuthorizationPublicCompletedCB, reinterpret_cast<void *>(context.get()), &(context->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_user_initiated));
    context.release();
    return result;
}

napi_value NapiAuthorizationPublicManager::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptor[] = {
        DECLARE_NAPI_FUNCTION("getAuthorizationManager", GetAuthorizationManager),
        DECLARE_NAPI_PROPERTY("Privilege", PrivilegeConstructor(env)),
        DECLARE_NAPI_PROPERTY("AuthorizationResultCode", AuthorizationResultCodeConstructor(env)),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor),
        descriptor));

    std::string className = "AuthorizationManager";
    napi_value cons = nullptr;
    NAPI_CALL(env, napi_define_class(env, className.c_str(), className.size(),
        JsConstructor, nullptr, sizeof(g_properties) / sizeof(napi_property_descriptor), g_properties, &cons));
    NAPI_CALL(env, napi_create_reference(env, cons, 1, &g_authorizationPublicRef));
    NAPI_CALL(env, napi_set_named_property(env, exports, className.c_str(), cons));
    return exports;
}
}  // namespace AccountJsKit
}  // namespace OHOS

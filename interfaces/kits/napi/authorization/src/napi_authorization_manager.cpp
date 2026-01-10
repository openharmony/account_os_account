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

#include "napi_authorization_manager.h"

#include <uv.h>
#include <memory>
#include <mutex>
#include "account_log_wrapper.h"
#include "authorization_client.h"
#include "iconnect_ability_callback.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_account_common.h"
#include "napi_account_error.h"
#include "napi_base_context.h"
#include "napi_common.h"

using namespace OHOS::AccountSA;

namespace OHOS {
namespace AccountJsKit {
namespace {
const size_t ARG_SIZE_ONE = 1;
const size_t ARG_SIZE_TWO = 2;
const size_t PARAM_ONE = 1;
const size_t PARAM_ZERO = 0;
static thread_local napi_ref authorizationRef_ = nullptr;
std::mutex g_mutex;
static std::shared_ptr<NapiAuthorizationResultCallback> g_authorizationCallback = nullptr;
}

using namespace OHOS::AccountSA;
static ErrCode CreateUIExtension()
{
    return ERR_OK;
}

static ErrCode CloseUIExtension()
{
    return ERR_OK;
}

static ErrCode CreateServiceExtension()
{
    return ERR_OK;
}

static ErrCode CloseServiceExtension()
{
    return ERR_OK;
}

UIExtensionCallback::UIExtensionCallback(std::shared_ptr<AcquireAuthorizationContext> &context)
{
    context_ = context;
    isOnResult_.exchange(false);
}

void UIExtensionCallback::SetSessionId(int32_t sessionId)
{
    sessionId_ = sessionId;
}

void UIExtensionCallback::SetCallBack(sptr<IRemoteObject> &callback)
{
    callback_ = callback;
}

void UIExtensionCallback::OnRelease(int32_t releaseCode)
{
    ACCOUNT_LOGI("enter OnRelease releaseCode:%{public}d", releaseCode);
}

void UIExtensionCallback::OnResult(int32_t resultCode, const OHOS::AAFwk::Want &result)
{
    ACCOUNT_LOGI("enter OnRelease errCode:%{public}d", resultCode);
}

void UIExtensionCallback::OnReceive(const OHOS::AAFwk::WantParams &request)
{
    ACCOUNT_LOGI("enter OnReceive");
}

void UIExtensionCallback::OnError(int32_t code, const std::string &name, const std::string &message)
{
    ACCOUNT_LOGI("enter OnError errCode:%{public}d", code);
}

void UIExtensionCallback::OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy)
{
    ACCOUNT_LOGI("enter OnRemoteReady");
}

void UIExtensionCallback::OnDestroy()
{
    ACCOUNT_LOGI("enter OnDestroy");
}

void UIExtensionCallback::ReleaseHandler(int32_t code)
{
    ACCOUNT_LOGI("enter OnRelease errCode:%{public}d", code);
    if (context_ == nullptr) {
        return;
    }
    if (code == ERR_OK && callback_ != nullptr) {
        auto callbackProxy = iface_cast<IConnectAbilityCallback>(callback_);
        if (callbackProxy == nullptr) {
            ACCOUNT_LOGE("ConnectAbilityCallback proxy is nullptr");
            context_->errCode = ERR_JS_SYSTEM_SERVICE_EXCEPTION;
            return;
        }
        callbackProxy->OnResult(context_->errCode, token_);
    }
}

static void AuthorizationResultToJs(napi_env env, const AuthorizationResult& result, napi_value &resultJs)
{
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &resultJs));
    napi_value privilegeJs;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, result.privilege.c_str(),
        NAPI_AUTO_LENGTH, &privilegeJs));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, resultJs, "privilege", privilegeJs));
    napi_value number = 0;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, result.resultCode, &number));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, resultJs, "resultCode", number));
    if (result.resultCode != AuthorizationResultCode::AUTHORIZATION_SUCCESS) {
        return;
    }
    napi_value isReusedJS;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, result.isReused, &isReusedJS));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, resultJs, "isReused", isReusedJS));
    napi_value validityPeriodJs;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, result.validityPeriod, &validityPeriodJs));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, resultJs, "validityPeriod", validityPeriodJs));
    napi_value tokenJS =
        CreateUint8Array(env, result.token.data(), result.token.size());
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, resultJs, "token", tokenJS));
}

std::function<void()> OnAuthorizationResultTask(int32_t errCode,
    const std::shared_ptr<AcquireAuthorizationContext> &asyncContextPtr)
{
    return [errCode, asyncContextPtr] {
        napi_value errJs = nullptr;
        napi_value resultJs = nullptr;
        if (asyncContextPtr->hasOptions && asyncContextPtr->options.hasContext) {
            CloseUIExtension();
        } else {
            CloseServiceExtension();
        }
        if (errCode == ERR_OK) {
            errJs = GenerateBusinessSuccess(asyncContextPtr->env, asyncContextPtr->throwErr);
            AuthorizationResultToJs(asyncContextPtr->env, asyncContextPtr->authorizationResult, resultJs);
        } else {
            errJs = GenerateBusinessError(asyncContextPtr->env, asyncContextPtr->errCode);
        }
        ReturnCallbackOrPromise(asyncContextPtr->env, asyncContextPtr.get(), errJs, resultJs);
    };
}

ErrCode NapiAuthorizationResultCallback::OnResult(int32_t errCode, const AuthorizationResult& result)
{
    ACCOUNT_LOGI("NapiAuthorizationResultCallback OnResult errCode:%{public}d", errCode);
    asyncContextPtr_->authorizationResult = result;
    auto task = OnAuthorizationResultTask(errCode, asyncContextPtr_);
    if (napi_ok != napi_send_event(asyncContextPtr_->env, task, napi_eprio_vip, "AuthorizationCallback OnResult")) {
        ACCOUNT_LOGE("Post AuthorizationCallback OnResult failed.");
    }
    return ERR_OK;
}

std::function<void()> OnConnectAbilityTask(const std::shared_ptr<AcquireAuthorizationContext> &context,
    const std::string &bundleName, const std::string &abilityName, const sptr<IRemoteObject> &callback)
{
    return [context, bundleName, abilityName, callback] {
        ErrCode errCode = ERR_OK;
        if (context->hasOptions && context->options.hasContext) {
            errCode = CreateUIExtension();
        } else {
            errCode = CreateServiceExtension();
        }
        auto connectCallback = iface_cast<IConnectAbilityCallback>(callback);
        std::vector<uint8_t> iamToken;
        connectCallback->OnResult(errCode, iamToken);
    };
}

ErrCode NapiAuthorizationResultCallback::OnConnectAbility(const ConnectAbilityInfo &info,
    const sptr<IRemoteObject> &callback)
{
    auto task = OnConnectAbilityTask(asyncContextPtr_, info.bundleName, info.abilityName, callback);
    if (napi_ok != napi_send_event(asyncContextPtr_->env, task, napi_eprio_vip,
        "AuthorizationCallback OnConnectAbility")) {
        ACCOUNT_LOGE("Post authorizationCallback onConnectAbility failed.");
    }
    ACCOUNT_LOGI("Post authorizationCallback onConnectAbilit success");
    return ERR_OK;
}

static bool GetContext(
    const napi_env &env, const napi_value &object, AcquireAuthorizationContext *asyncContext)
{
    NAPI_CALL_BASE(env, napi_has_named_property(env, object, "interactionContext",
        &asyncContext->options.hasContext), false);
    if (!asyncContext->options.hasContext) {
        return true;
    }
    napi_value value = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, object, "interactionContext", &value), false);
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valueType), false);
    if ((valueType == napi_undefined) || (valueType == napi_null)) {
        ACCOUNT_LOGI("The interactionContext of AcquireAuthorizationOptions is undefined or null");
        return true;
    }
    if (valueType != napi_object) {
        ACCOUNT_LOGE("InteractionContext type is not object");
        return false;
    }

    bool stageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, value, stageMode);
    if (status != napi_ok || !stageMode) {
        ACCOUNT_LOGE("It is not a stage mode");
        return false;
    } else {
        auto context = AbilityRuntime::GetStageModeContext(env, value);
        if (context == nullptr) {
            ACCOUNT_LOGE("Get context failed");
            return false;
        }
        asyncContext->abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
        if ((asyncContext->abilityContext != nullptr) &&
            (asyncContext->abilityContext->GetApplicationInfo() != nullptr)) {
            asyncContext->uiAbilityFlag = true;
        } else {
            ACCOUNT_LOGI("Convert to ability context failed");
            asyncContext->uiExtensionContext =
                AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIExtensionContext>(context);
            if ((asyncContext->uiExtensionContext == nullptr) ||
                (asyncContext->uiExtensionContext->GetApplicationInfo() == nullptr)) {
                ACCOUNT_LOGE("Convert to ui extension context failed");
                return false;
            }
        }
        return true;
    }
}

static bool ParseContextForAcquireAuthorizationOptions(napi_env env, napi_value value,
    AcquireAuthorizationContext *asyncContext)
{
    if (!GetContext(env, value, asyncContext)) {
        ACCOUNT_LOGE("Get options's context failed.");
        std::string errMsg = "Parameter error. The type of \"context\" must be ConText";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!GetOptionalUint8TypedArrayToVector(env, value, "challenge", asyncContext->options.challenge)) {
        ACCOUNT_LOGE("Get options's challenge failed");
        std::string errMsg = "Parameter error. The type of \"challenge\" must be Uint8Array";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!GetOptionBoolProperty(env, value, "isReuseNeeded", asyncContext->options.isReuseNeeded)) {
        ACCOUNT_LOGE("Get options's isReuseNeeded failed");
        std::string errMsg = "Parameter error. The type of \"isReuseNeeded\" must be bool";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!GetOptionBoolProperty(env, value, "isInteractionAllowed", asyncContext->options.isInteractionAllowed)) {
        ACCOUNT_LOGE("Get options's isInteractionAllowed failed");
        std::string errMsg = "Parameter error. The type of \"isInteractionAllowed\" must be bool";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    return true;
}

static bool ParseContextForAcquireAuthorization(napi_env env, napi_callback_info cbInfo,
    AcquireAuthorizationContext *asyncContext)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {nullptr};
    asyncContext->env = env;
    if (napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr) != napi_ok) {
        ACCOUNT_LOGE("Napi_get_cb_info failed");
        return false;
    }
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("Need input at least one parameter, but got %{public}zu", argc);
        std::string errMsg = "Parameter error. The number of parameters should be at least 1";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (!GetStringProperty(env, argv[PARAM_ZERO], asyncContext->privilege)) {
        ACCOUNT_LOGE("Get name failed");
        std::string errMsg = "The type of arg 1 must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (argc == ARG_SIZE_TWO) {
        asyncContext->hasOptions = true;
        return ParseContextForAcquireAuthorizationOptions(env, argv[PARAM_ONE], asyncContext);
    }
    return true;
}

static void AcquireAuthorizationCompletedCB(napi_env env, napi_status status, void *data)
{
    delete reinterpret_cast<RequestAsyncContextHandle *>(data);
}

static void AcquireAuthorizationExecuteCB(napi_env env, void *data)
{
    RequestAsyncContextHandle *asyncContext = reinterpret_cast<RequestAsyncContextHandle *>(data);
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("AsyncContext is nullptr.");
        return;
    }
    g_authorizationCallback = std::make_shared<NapiAuthorizationResultCallback>(asyncContext->asyncContextPtr);
    asyncContext->asyncContextPtr->errCode = AuthorizationClient::GetInstance().AcquireAuthorization(
        asyncContext->asyncContextPtr->privilege, asyncContext->asyncContextPtr->options, g_authorizationCallback);
}

napi_value NapiAuthorizationManager::AcquireAuthorization(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_shared<AcquireAuthorizationContext>(env);

    if (!ParseContextForAcquireAuthorization(env, cbInfo, context.get())) {
        std::string errMsg = "The type of parameter is error.";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    auto asyncContextHandle = std::make_unique<RequestAsyncContextHandle>(context);
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "AcquireAuthorization", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, AcquireAuthorizationExecuteCB,
        AcquireAuthorizationCompletedCB, reinterpret_cast<void*>(asyncContextHandle.get()),
        &(asyncContextHandle->asyncContextPtr->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContextHandle->asyncContextPtr->work,
        napi_qos_user_initiated));
    asyncContextHandle.release();
    return result;
}

napi_value NapiAuthorizationManager::GetAuthorizationManager(napi_env env, napi_callback_info cbInfo)
{
    napi_value instance = nullptr;
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, authorizationRef_, &cons) != napi_ok) {
        return nullptr;
    }

    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        return nullptr;
    }

    return instance;
}

napi_value NapiAuthorizationManager::AuthorizationResultCodeConstructor(napi_env env)
{
    napi_value resultCode = nullptr;
    napi_value success = nullptr;
    napi_value canceled = nullptr;
    napi_value notAllowed = nullptr;
    napi_value denied = nullptr;
    napi_value systemBusy = nullptr;
    NAPI_CALL(env, napi_create_object(env, &resultCode));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AuthorizationResultCode::AUTHORIZATION_SUCCESS), &success));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AuthorizationResultCode::AUTHORIZATION_CANCELED), &canceled));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AuthorizationResultCode::AUTHORIZATION_INTERACTION_NOT_ALLOWED), &notAllowed));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AuthorizationResultCode::AUTHORIZATION_DENIED), &denied));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AuthorizationResultCode::AUTHORIZATION_SYSTEM_BUSY), &systemBusy));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_SUCCESS", success));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_CANCELED", canceled));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_INTERACTION_NOT_ALLOWED", notAllowed));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_DENIED", denied));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_SYSTEM_BUSY", systemBusy));
    return resultCode;
}

napi_value NapiAuthorizationManager::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptor[] = {
        DECLARE_NAPI_FUNCTION("getAuthorizationManager", GetAuthorizationManager),
        DECLARE_NAPI_PROPERTY("AuthorizationResultCode", AuthorizationResultCodeConstructor(env)),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor),
        descriptor));

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("acquireAuthorization", AcquireAuthorization),
    };
    std::string className = "AuthorizationManager";
    napi_value cons = nullptr;
    NAPI_CALL(env, napi_define_class(env, className.c_str(), className.size(),
        JsConstructor, nullptr, sizeof(properties) / sizeof(napi_property_descriptor), properties, &cons));
    NAPI_CALL(env, napi_create_reference(env, cons, 1, &authorizationRef_));
    NAPI_CALL(env, napi_set_named_property(env, exports, className.c_str(), cons));

    return exports;
}

napi_value NapiAuthorizationManager::JsConstructor(napi_env env, napi_callback_info cbInfo)
{
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}
}  // namespace AccountJsKit
}  // namespace OHOS

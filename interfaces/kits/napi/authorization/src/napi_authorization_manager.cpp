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
#include <thread>
#include "account_constants.h"
#include "account_log_wrapper.h"
#include "authorization_client.h"
#include "authorization_ui_extension_callback.h"
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

static ErrCode NotifyAuthorizationResultWithRetry(const sptr<IRemoteObject>& callback, int32_t errCode,
    const std::vector<uint8_t>& iamToken = std::vector<uint8_t>(), int32_t accountId = -1,
    int32_t resultCode = -1)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr");
        return ERR_JS_INVALID_PARAMETER;
    }
    auto callbackProxy = iface_cast<AccountSA::IConnectAbilityCallback>(callback);
    if (callbackProxy == nullptr) {
        ACCOUNT_LOGE("ConnectAbilityCallback proxy is nullptr");
        return ERR_JS_INVALID_PARAMETER;
    }
    int retryTimes = 0;
    ErrCode ret = ERR_OK;
    while (retryTimes < AccountSA::AuthorizationConstants::MAX_RETRY_TIME) {
        ret = callbackProxy->OnResult(errCode, iamToken, accountId, resultCode);
        if (ret == ERR_OK || (ret != Constants::E_IPC_ERROR && ret != Constants::E_IPC_SA_DIED)) {
            break;
        }
        retryTimes++;
        ACCOUNT_LOGE("UIExtensionCallback send result failed, code=%{public}d, retryTimes=%{public}d", ret, retryTimes);
        std::this_thread::sleep_for(std::chrono::milliseconds(Constants::DELAY_FOR_EXCEPTION));
    }
    return ret;
}

static Ace::UIContent* GetUIContent(const std::shared_ptr<AcquireAuthorizationContext> &context)
{
    if (context == nullptr) {
        return nullptr;
    }
    Ace::UIContent* uiContent = nullptr;
    if (context->uiAbilityFlag) {
        uiContent = context->abilityContext->GetUIContent();
    } else if ((context->uiExtensionContext == nullptr) ||
        (context->uiExtensionContext->GetApplicationInfo() == nullptr)) {
        return uiContent;
    } else {
        uiContent = context->uiExtensionContext->GetUIContent();
    }

    return uiContent;
}
} // namespace

UIExtensionCallback::UIExtensionCallback(const std::shared_ptr<AcquireAuthorizationContext>& context)
    : context_(context)
{
    isOnResult_.exchange(false);
    isReleased_.exchange(false);
}

void UIExtensionCallback::ReleaseHandler(int32_t errCode, AuthorizationResultCode resultCode,
    const std::vector<uint8_t> &iamToken, int32_t accountId)
{
    ACCOUNT_LOGI("enter ReleaseHandler code:%{public}d, resultCode:%{public}d", errCode,
        static_cast<int32_t>(resultCode));
    int32_t resultCodeInt = static_cast<int32_t>(resultCode);
    NotifyAuthorizationResultWithRetry(callback_, errCode, iamToken, accountId, resultCodeInt);
    CloseUIExtension();
    context_ = nullptr;
}

OHOS::Ace::UIContent* UIExtensionCallback::GetUIContent()
{
    if (context_ == nullptr) {
        ACCOUNT_LOGE("Context is nullptr");
        return nullptr;
    }

    OHOS::Ace::UIContent* uiContent = nullptr;
    if (context_->uiAbilityFlag) {
        if (context_->abilityContext != nullptr) {
            uiContent = context_->abilityContext->GetUIContent();
        }
    } else if (context_->uiExtensionContext != nullptr) {
        uiContent = context_->uiExtensionContext->GetUIContent();
    }

    return uiContent;
}

void UIExtensionCallback::CloseUIExtension()
{
    OHOS::Ace::UIContent* uiContent = GetUIContent();
    if (uiContent == nullptr) {
        ACCOUNT_LOGE("Get ui content failed!");
        return;
    }

    uiContent->CloseModalUIExtension(sessionId_);
    ACCOUNT_LOGI("Close end, sessionId: %{public}d", sessionId_);
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

std::function<void()> OnAuthorizationResultTask(const std::shared_ptr<AcquireAuthorizationContext> &asyncContextPtr)
{
    return [asyncContextPtr] {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(asyncContextPtr->env, &scope);
        napi_value errJs = nullptr;
        napi_value resultJs = nullptr;
        if (asyncContextPtr->errCode == ERR_OK) {
            errJs = GenerateBusinessSuccess(asyncContextPtr->env, asyncContextPtr->throwErr);
            AuthorizationResultToJs(asyncContextPtr->env, asyncContextPtr->authorizationResult, resultJs);
        } else {
            errJs = GenerateAuthorizationBusinessError(asyncContextPtr->env, asyncContextPtr->errCode);
        }
        ReturnPromise(asyncContextPtr->env, asyncContextPtr.get(), errJs, resultJs);
        napi_close_handle_scope(asyncContextPtr->env, scope);
    };
}

ErrCode NapiAuthorizationResultCallback::OnResult(int32_t errCode, const AuthorizationResult& result)
{
    ACCOUNT_LOGI("NapiAuthorizationResultCallback OnResult errCode:%{public}d", errCode);
    auto asyncContextPtr = std::make_shared<AcquireAuthorizationContext>(env_, true);
    asyncContextPtr->errCode = errCode;
    asyncContextPtr->deferred = deferred_;
    asyncContextPtr->authorizationResult = result;
    if (context_ != nullptr && context_->hasOptions && context_->options.hasContext) {
        UIExtensionCallbackBase::CloseUIExtension(GetUIContent(context_), context_->sessionId);
    }
    auto task = OnAuthorizationResultTask(asyncContextPtr);
    if (napi_ok != napi_send_event(asyncContextPtr->env, task, napi_eprio_vip, "AuthorizationCallback OnResult")) {
        ACCOUNT_LOGE("Post AuthorizationCallback OnResult failed.");
    }
    asyncContextPtr.reset();
    deferred_ = nullptr;
    return ERR_OK;
}

std::function<void()> OnConnectAbilityTask(const std::shared_ptr<AcquireAuthorizationContext> &context,
    const ConnectAbilityInfo &info, const sptr<IRemoteObject> &callback)
{
    return [context, info = std::move(info), callback] {
        if (context == nullptr) {
            ACCOUNT_LOGE("Context is nullptr");
            return;
        }

        auto uiExtCallback = std::make_shared<UIExtensionCallback>(context);
        AAFwk::Want want = UIExtensionCallbackBase::BuildWantFromConnectInfo(info);
        Ace::ModalUIExtensionCallbacks uiExtensionCallbacks =
            UIExtensionCallbackBase::CreateUIExtensionCallbacks(uiExtCallback);

        uiExtCallback->SetCallBack(callback);

        OHOS::Ace::UIContent* uiContent = uiExtCallback->GetUIContent();
        if (uiContent == nullptr) {
            ACCOUNT_LOGE("Get ui content failed!");
            auto connectCallback = iface_cast<AccountSA::IConnectAbilityCallback>(callback);
            if (connectCallback != nullptr) {
                std::vector<uint8_t> iamToken;
                connectCallback->OnResult(ERR_AUTHORIZATION_GET_CONTENT_ERROR, iamToken, -1, -1);
            }
            return;
        }

        Ace::ModalUIExtensionConfig config;
        int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
        if (sessionId == 0) {
            ACCOUNT_LOGE("Create component failed, sessionId is 0");
            NotifyAuthorizationResultWithRetry(callback, ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR);
            return;
        }

        uiExtCallback->SetSessionId(sessionId);
        context->sessionId = sessionId;
        ACCOUNT_LOGI("CreateUIExtension success, sessionId: %{public}d", sessionId);
    };
}

ErrCode NapiAuthorizationResultCallback::OnConnectAbility(const ConnectAbilityInfo &info,
    const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("NapiAuthorizationResultCallback OnConnectAbility");
    if (context_ == nullptr) {
        ACCOUNT_LOGI("CreateUIExtension has not context.");
        return ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR;
    }
    if (!context_->hasOptions || !context_->options.hasContext) {
        ACCOUNT_LOGI("CreateUIExtension has not context.");
        return ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR;
    }
    auto task = OnConnectAbilityTask(context_, info, callback);
    if (napi_ok != napi_send_event(env_, task, napi_eprio_vip, "AuthorizationCallback OnConnectAbility")) {
        ACCOUNT_LOGE("Post authorizationCallback OnConnectAbility failed.");
        return ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR;
    }
    ACCOUNT_LOGI("Post authorizationCallback OnConnectAbility finish.");
    return ERR_OK;
}

/**
 * @brief Get interactionContext property value from object.
 * @param env The napi environment
 * @param object The input object containing interactionContext property
 * @param contextValue Output the interactionContext napi value
 * @param hasContext Output whether the interactionContext property exists
 * @return true if successful, false otherwise
 */
static bool GetInteractionContextObject(const napi_env &env, const napi_value &object,
    napi_value &contextValue, bool &hasContext)
{
    NAPI_CALL_BASE(env, napi_has_named_property(env, object, "interactionContext", &hasContext), false);
    if (!hasContext) {
        return true;
    }

    NAPI_CALL_BASE(env, napi_get_named_property(env, object, "interactionContext", &contextValue), false);

    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, contextValue, &valueType), false);

    if ((valueType == napi_undefined) || (valueType == napi_null)) {
        ACCOUNT_LOGI("The interactionContext of AcquireAuthorizationOptions is undefined or null");
        hasContext = false;
        return true;
    }

    if (valueType != napi_object) {
        ACCOUNT_LOGE("InteractionContext type is not object");
        return false;
    }

    return true;
}

/**
 * @brief Convert context object to ability context or ui extension context.
 * @param env The napi environment
 * @param contextValue The context napi value to convert
 * @param asyncContext The authorization context to store converted result
 * @return true if successful, false otherwise
 */
static bool ConvertContextObject(const napi_env &env, const napi_value &contextValue,
    AcquireAuthorizationContext *asyncContext)
{
    bool stageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, contextValue, stageMode);
    if (status != napi_ok || !stageMode) {
        ACCOUNT_LOGE("It is not a stage mode");
        return false;
    }

    auto context = AbilityRuntime::GetStageModeContext(env, contextValue);
    if (context == nullptr) {
        ACCOUNT_LOGE("Get context is nullptr");
        return false;
    }

    // Try to convert to AbilityContext first
    asyncContext->abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
    if ((asyncContext->abilityContext != nullptr) &&
        (asyncContext->abilityContext->GetApplicationInfo() != nullptr)) {
        ACCOUNT_LOGI("Convert to ability context success");
        asyncContext->uiAbilityFlag = true;
        asyncContext->options.isContextValid = true;
        return true;
    }

    // If AbilityContext conversion fails, try UIExtensionContext
    ACCOUNT_LOGI("Convert to ability context failed, try ui extension context");
    asyncContext->uiExtensionContext =
        AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIExtensionContext>(context);
    if ((asyncContext->uiExtensionContext == nullptr) ||
        (asyncContext->uiExtensionContext->GetApplicationInfo() == nullptr)) {
        ACCOUNT_LOGE("Convert to ui extension context failed");
        return false;
    }
    asyncContext->options.isContextValid = true;
    return true;
}

/**
 * @brief Get and convert interaction context from options object.
 * @param env The napi environment
 * @param object The input object containing interactionContext property
 * @param asyncContext The authorization context to store converted result
 * @return true if successful, false otherwise
 */
static bool GetContext(
    const napi_env &env, const napi_value &object, AcquireAuthorizationContext *asyncContext)
{
    napi_value contextValue = nullptr;
    if (!GetInteractionContextObject(env, object, contextValue, asyncContext->options.hasContext)) {
        // When interaction is required, throw parameter error exception
        ACCOUNT_LOGE("Failed to get interactionContext object when interaction is required");
        std::string errMsg = "Parameter error. The type of \"interactionContext\" must be Context object";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }

    if (!asyncContext->options.hasContext) {
        return true;
    }

    ConvertContextObject(env, contextValue, asyncContext);
    return true;
}

static bool ParseContextForAcquireAuthorizationOptions(napi_env env, napi_value value,
    AcquireAuthorizationContext *asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valueType), false);
    if ((valueType == napi_undefined) || (valueType == napi_null)) {
        ACCOUNT_LOGI("the callback is undefined or null");
        return true;
    }
    if (valueType != napi_object) {
        ACCOUNT_LOGE("Obj is not an object");
        std::string errMsg = "Parameter error. The type of \"acquireAuthorizationOptions\" must be object";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    asyncContext->hasOptions = true;
    if (!GetOptionBoolProperty(env, value, "isInteractionAllowed", asyncContext->options.isInteractionAllowed)) {
        ACCOUNT_LOGE("Get options's isInteractionAllowed failed");
        std::string errMsg = "Parameter error. The type of \"isInteractionAllowed\" must be bool";
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

    // GetContext will handle error internally and throw exception if needed
    // When isInteractionAllowed is true and context retrieval fails, exception is thrown inside
    // When isInteractionAllowed is false, context errors are ignored
    if (!GetContext(env, value, asyncContext)) {
        // GetContext returns false only when exception was already thrown
        ACCOUNT_LOGE("Get options's context failed.");
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
    if (argc < ARG_SIZE_ONE || argc > ARG_SIZE_TWO) {
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
        return ParseContextForAcquireAuthorizationOptions(env, argv[PARAM_ONE], asyncContext);
    }
    return true;
}

static bool ParseContextForReleaseAuthorization(napi_env env, napi_callback_info cbInfo,
    std::unique_ptr<ReleaseAuthorizationAsyncContext> &asyncContext)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL), false);
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("The number of parameters should be at least 1");
        std::string errMsg = "Parameter error. The number of parameters should be at least 1";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!GetStringProperty(env, argv[PARAM_ZERO], asyncContext->privilege)) {
        ACCOUNT_LOGE("Get privilege failed");
        std::string errMsg = "The type of \"privilege\" must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    return true;
}

static void AcquireAuthorizationCompletedCB(napi_env env, napi_status status, void *data)
{
    delete reinterpret_cast<AcquireAuthorizationContext *>(data);
}

static void AcquireAuthorizationExecuteCB(napi_env env, void *data)
{
    AcquireAuthorizationContext *asyncContext = reinterpret_cast<AcquireAuthorizationContext *>(data);
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("AsyncContext is nullptr.");
        return;
    }

    auto callback = std::make_shared<NapiAuthorizationResultCallback>(asyncContext);

    asyncContext->errCode = AuthorizationClient::GetInstance().AcquireAuthorization(
        asyncContext->privilege, asyncContext->options, callback);
    if (asyncContext->errCode != ERR_OK) {
        AuthorizationResult result;
        result.privilege = asyncContext->privilege;
        callback->OnResult(asyncContext->errCode, result);
    }
}

static void ReleaseAuthorizationExecuteCB(napi_env env, void *data)
{
    ReleaseAuthorizationAsyncContext *asyncContext = reinterpret_cast<ReleaseAuthorizationAsyncContext *>(data);
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("AsyncContext is nullptr.");
        return;
    }
    asyncContext->errCode = AuthorizationClient::GetInstance().ReleaseAuthorization(asyncContext->privilege);
    ACCOUNT_LOGI("ReleaseAuthorizationExecuteCB, errCode: %{public}d", asyncContext->errCode);
}

static void ReleaseAuthorizationCompletedCB(napi_env env, napi_status status, void *data)
{
    ReleaseAuthorizationAsyncContext *asyncContext = reinterpret_cast<ReleaseAuthorizationAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == ERR_OK) {
        napi_get_null(env, &errJs);
        napi_get_null(env, &dataJs);
    } else {
        errJs = GenerateAuthorizationBusinessError(env, asyncContext->errCode);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    delete asyncContext;
}

napi_value NapiAuthorizationManager::AcquireAuthorization(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<AcquireAuthorizationContext>(env, true);
    if (!ParseContextForAcquireAuthorization(env, cbInfo, context.get())) {
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "AcquireAuthorization", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, AcquireAuthorizationExecuteCB,
        AcquireAuthorizationCompletedCB, reinterpret_cast<void*>(context.get()), &(context->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_user_initiated));
    context.release();
    return result;
}

napi_value NapiAuthorizationManager::ReleaseAuthorization(napi_env env, napi_callback_info cbInfo)
{
    auto releaseAuthorizationAsyncContext = std::make_unique<ReleaseAuthorizationAsyncContext>();
    releaseAuthorizationAsyncContext->env = env;
    if (!ParseContextForReleaseAuthorization(env, cbInfo, releaseAuthorizationAsyncContext)) {
        ACCOUNT_LOGE("Parse parameters for ReleaseAuthorization failed");
        return nullptr;
    }
    napi_value result = nullptr;
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &releaseAuthorizationAsyncContext->deferred, &result));
    NAPI_CALL(env, napi_create_string_utf8(env, "ReleaseAuthorization", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        ReleaseAuthorizationExecuteCB,
        ReleaseAuthorizationCompletedCB,
        reinterpret_cast<void *>(releaseAuthorizationAsyncContext.get()),
        &releaseAuthorizationAsyncContext->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, releaseAuthorizationAsyncContext->work, napi_qos_default));
    releaseAuthorizationAsyncContext.release();
    return result;
}

static bool ParseContextForHasAuthorization(napi_env env, napi_callback_info cbInfo,
    HasAuthorizationContext *asyncContext)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {nullptr};
    asyncContext->env = env;
    napi_value thisVar = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL), false);
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("Need input at least one parameter, but got %{public}zu", argc);
        std::string errMsg = "Parameter error. The number of parameters should be at least 1";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (!GetStringProperty(env, argv[PARAM_ZERO], asyncContext->privilege)) {
        ACCOUNT_LOGE("Get privilege failed");
        std::string errMsg = "The type of privilege must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    return true;
}

static void HasAuthorizationCompletedCB(napi_env env, napi_status status, void *data)
{
    HasAuthorizationContext *asyncContext = reinterpret_cast<HasAuthorizationContext *>(data);
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

static void HasAuthorizationExecuteCB(napi_env env, void *data)
{
    HasAuthorizationContext *asyncContext = reinterpret_cast<HasAuthorizationContext *>(data);
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("AsyncContext is nullptr.");
        return;
    }
    asyncContext->errCode = AuthorizationClient::GetInstance().CheckAuthorization(
        asyncContext->privilege, asyncContext->isAuthorized);
    ACCOUNT_LOGD("errCode is %{public}d, isAuthorized is %{public}d",
        asyncContext->errCode, asyncContext->isAuthorized);
}

napi_value NapiAuthorizationManager::HasAuthorization(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<HasAuthorizationContext>();
    context->env = env;
    if (!ParseContextForHasAuthorization(env, cbInfo, context.get())) {
        ACCOUNT_LOGE("Failed to parse parameter for HasAuthorizationContext");
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "HasAuthorization", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, HasAuthorizationExecuteCB,
        HasAuthorizationCompletedCB, reinterpret_cast<void*>(context.get()),
        &(context->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_user_initiated));
    context.release();
    return result;
}

napi_value NapiAuthorizationManager::GetAuthorizationManager(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        std::string errMsg = "Not system application.";
        AccountNapiThrow(env, ERR_JS_IS_NOT_SYSTEM_APP, errMsg, true);
        return nullptr;
    }
    napi_value instance = nullptr;
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, authorizationRef_, &cons) != napi_ok) {
        ACCOUNT_LOGE("Failed to get authorization manager reference");
        return nullptr;
    }

    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        ACCOUNT_LOGE("Failed to create authorization manager instance");
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
        static_cast<int32_t>(AuthorizationResultCode::AUTHORIZATION_SERVICE_BUSY), &systemBusy));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_SUCCESS", success));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_CANCELED", canceled));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_INTERACTION_NOT_ALLOWED", notAllowed));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_DENIED", denied));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTHORIZATION_SERVICE_BUSY", systemBusy));
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
        DECLARE_NAPI_FUNCTION("releaseAuthorization", ReleaseAuthorization),
        DECLARE_NAPI_FUNCTION("hasAuthorization", HasAuthorization),
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

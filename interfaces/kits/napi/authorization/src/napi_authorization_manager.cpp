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
const int32_t CANCEL_ERROR = 1;
const int32_t DENIED_ERROR = 2;
const size_t ARG_SIZE_ONE = 1;
const size_t ARG_SIZE_TWO = 2;
const size_t PARAM_ONE = 1;
const size_t PARAM_ZERO = 0;
static thread_local napi_ref authorizationRef_ = nullptr;
const std::string EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
const std::string UI_EXTENSION_TYPE = "sys/commonUI";
const std::string TOKEN_KEY = "authResultToken";
const std::string ACCOUNTID_KEY = "authResultAccountID";
const std::string CODE_KEY = "authResultCode";
constexpr std::int32_t MAX_CHALLENGE_LEN = 32;
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

static ErrCode CreateUIExtensionMainThread(const std::shared_ptr<AcquireAuthorizationContext> &context,
    const AAFwk::Want& want, const Ace::ModalUIExtensionCallbacks& uiExtensionCallbacks,
    const std::shared_ptr<UIExtensionCallback>& uiExtCallback)
{
    Ace::UIContent* uiContent = GetUIContent(context);
    if (uiContent == nullptr) {
        ACCOUNT_LOGE("Get ui content failed!");
        return ERR_AUTHORIZATION_GET_CONTENT_ERROR;
    }

    Ace::ModalUIExtensionConfig config;
    int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
    if (sessionId == 0) {
        ACCOUNT_LOGE("Create component failed, sessionId is 0");
        return ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR;
    }
    uiExtCallback->SetSessionId(sessionId);
    context->sessionId = sessionId;
    return ERR_OK;
}

static ErrCode CreateUIExtension(const std::shared_ptr<AcquireAuthorizationContext> &context,
    const ConnectAbilityInfo &info, const sptr<IRemoteObject> &callback)
{
    if (context == nullptr) {
        ACCOUNT_LOGE("Context is nullptr");
        return ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR;
    }
    AAFwk::Want want;
    want.SetElementName(info.bundleName, info.abilityName);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);
    std::string challengeStr;
    TransVectorU8ToString(info.challenge, challengeStr);
    want.SetParam("challenge", challengeStr);
    want.SetParam("privilege", info.privilege);
    want.SetParam("description", info.description);
    auto uiExtCallback = std::make_shared<UIExtensionCallback>(context);
    Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
        [uiExtCallback](int32_t releaseCode) {
            uiExtCallback->OnRelease(releaseCode);
        },
        [uiExtCallback](int32_t resultCode, const AAFwk::Want &result) {
            uiExtCallback->OnResult(resultCode, result);
        },
        [uiExtCallback](const AAFwk::WantParams &receive) {
            uiExtCallback->OnReceive(receive);
        },
        [uiExtCallback](int32_t code, const std::string &name, const std::string &message) {
            uiExtCallback->OnError(code, name, message);
        },
        [uiExtCallback](const std::shared_ptr<Ace::ModalUIExtensionProxy> &uiProxy) {
            uiExtCallback->OnRemoteReady(uiProxy);
        },
        [uiExtCallback]() {
            uiExtCallback->OnDestroy();
        },
    };
    uiExtCallback->SetCallBack(callback);
    return CreateUIExtensionMainThread(context, want, uiExtensionCallbacks, uiExtCallback);
}


static ErrCode CloseUIExtension(const std::shared_ptr<AcquireAuthorizationContext> &asyncContext, int32_t sessionId)
{
    Ace::UIContent* uiContent = GetUIContent(asyncContext);
    if (uiContent == nullptr) {
        ACCOUNT_LOGE("Get ui content failed!");
        return ERR_OK;
    }
    uiContent->CloseModalUIExtension(sessionId);
    ACCOUNT_LOGI("Close end, sessionId: %{public}d", sessionId);
    return ERR_OK;
}

UIExtensionCallback::UIExtensionCallback(const std::shared_ptr<AcquireAuthorizationContext> &context)
{
    context_ = context;
    isOnResult_.exchange(false);
}

void UIExtensionCallback::SetSessionId(int32_t sessionId)
{
    sessionId_ = sessionId;
}

void UIExtensionCallback::SetCallBack(const sptr<IRemoteObject> &callback)
{
    callback_ = callback;
}

/*
 * when UIExtensionAbility disconnect or use terminate or process die
 * releaseCode is 0 when process normal exit
 */
void UIExtensionCallback::OnRelease(int32_t releaseCode)
{
    ACCOUNT_LOGI("enter OnRelease releaseCode:%{public}d", releaseCode);
    if (!isOnResult_.load()) {
        ReleaseHandler(ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR);
    }
}

/*
 * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
 */
void UIExtensionCallback::OnError(int32_t code, const std::string &name, const std::string &message)
{
    ACCOUNT_LOGI("enter OnError errCode:%{public}d, name:%{public}s, message:%{public}s", code, name.c_str(),
        message.c_str());
    if (!isOnResult_.load()) {
        ReleaseHandler(ERR_OK, AUTHORIZATION_INTERACTION_NOT_ALLOWED);
    }
}

/*
 * when UIExtensionAbility use terminateSelfWithResult
 */
void UIExtensionCallback::OnResult(int32_t resultCode, const OHOS::AAFwk::Want &result)
{
    ACCOUNT_LOGI("enter OnResult resultCode:%{public}d", resultCode);
    if (this->context_ == nullptr) {
        ACCOUNT_LOGE("Request context is null.");
        return;
    }
    isOnResult_.exchange(true);
    // terminal when error or cancel
    if (resultCode == CANCEL_ERROR) {
        return ReleaseHandler(ERR_OK, AUTHORIZATION_CANCELED);
    }
    if (resultCode == DENIED_ERROR) {
        return ReleaseHandler(ERR_OK, AUTHORIZATION_DENIED);
    }
    if (resultCode != ERR_OK) {
        return ReleaseHandler(ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR);
    }
    ACCOUNT_LOGI("ResultCode is %{public}d", resultCode);
    std::vector<int> iamToken = result.GetIntArrayParam(TOKEN_KEY);
    std::vector<uint8_t> tokenVec(iamToken.begin(), iamToken.end());
    int32_t accountId = result.GetIntParam(ACCOUNTID_KEY, -1);
    if (accountId == -1) {
        ACCOUNT_LOGI("AccountId is %{public}d", accountId);
        return ReleaseHandler(ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR);
    }
    return ReleaseHandler(ERR_OK, AUTHORIZATION_SUCCESS, tokenVec, accountId);
}

/*
 * when UIExtensionAbility send message to UIExtensionComponent
 */
void UIExtensionCallback::OnReceive(const OHOS::AAFwk::WantParams &request)
{
    ACCOUNT_LOGI("enter OnReceive");
}

/*
 * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
 * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
 */
void UIExtensionCallback::OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy)
{
    ACCOUNT_LOGI("enter OnRemoteReady");
}

/*
 * when UIExtensionComponent destructed
 */
void UIExtensionCallback::OnDestroy()
{
    ACCOUNT_LOGI("enter OnDestroy");
    if (!isOnResult_.load()) {
        ReleaseHandler(ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR);
    }
}

void UIExtensionCallback::ReleaseHandler(int32_t errCode, AuthorizationResultCode resultCode,
    const std::vector<uint8_t> &iamToken, int32_t accountId)
{
    ACCOUNT_LOGI("enter ReleaseHandler code:%{public}d, resultCode:%{public}d", errCode,
        static_cast<int32_t>(resultCode));
    if (callback_ == nullptr) {
        CloseUIExtension(context_, sessionId_);
        ACCOUNT_LOGE("Context or callback is nullptr");
        return;
    }
    auto callbackProxy = iface_cast<IConnectAbilityCallback>(callback_);
    if (callbackProxy == nullptr) {
        CloseUIExtension(context_, sessionId_);
        ACCOUNT_LOGE("ConnectAbilityCallback proxy is nullptr");
        return;
    }
    int32_t resultCodeInt = static_cast<int32_t>(resultCode);
    ErrCode ret = callbackProxy->OnResult(errCode, iamToken, accountId, resultCodeInt);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to call iConnectAbilityCallback onResult, errCode:%{public}d", ret);
    }
    CloseUIExtension(context_, sessionId_);
    context_ = nullptr;
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
        CloseUIExtension(context_, context_->sessionId);
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
        ErrCode errCode = CreateUIExtension(context, info, callback);
        if (errCode == ERR_OK) {
            return;
        }
        auto connectCallback = iface_cast<IConnectAbilityCallback>(callback);
        if (connectCallback == nullptr) {
            ACCOUNT_LOGE("ConnectAbilityCallback proxy is nullptr");
            std::string errMsg = "ConnectAbilityCallback proxy is nullptr.";
            AccountNapiThrow(context->env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, errMsg, context->throwErr);
            return;
        }
        std::vector<uint8_t> iamToken;
        connectCallback->OnResult(errCode, iamToken, -1, -1);
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
        if (asyncContext->options.isInteractionAllowed) {
            ACCOUNT_LOGE("Failed to get interactionContext object when interaction is required");
            std::string errMsg = "Parameter error. The type of \"interactionContext\" must be Context object";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return false;
        }
        // When interaction is not required, ignore the error and return true
        ACCOUNT_LOGI("Interaction is not allowed, ignore context retrieval error");
        return true;
    }

    if (!asyncContext->options.hasContext) {
        return true;
    }

    if (!ConvertContextObject(env, contextValue, asyncContext)) {
        // When interaction is required, set result code to INTERACTION_NOT_ALLOWED
        if (asyncContext->options.isInteractionAllowed) {
            ACCOUNT_LOGE("Failed to convert context object when interaction is required");
            asyncContext->authorizationResult.resultCode =
                AccountSA::AuthorizationResultCode::AUTHORIZATION_INTERACTION_NOT_ALLOWED;
            asyncContext->errCode = ERR_OK;
            asyncContext->skipAuthorization = true;
            return true;
        }
        // When interaction is not required, ignore the error and return true
        ACCOUNT_LOGI("Interaction is not allowed, ignore context conversion error");
        return true;
    }

    return true;
}

static bool ParseContextForAcquireAuthorizationOptions(napi_env env, napi_value value,
    AcquireAuthorizationContext *asyncContext)
{
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
    if (asyncContext->options.challenge.size() > MAX_CHALLENGE_LEN) {
        ACCOUNT_LOGE("Get options's challenge failed");
        std::string errMsg = "Parameter error. The size of \"challenge\" must not exceed 32 bytes";
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, errMsg, true);
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
        asyncContext->hasOptions = true;
        return ParseContextForAcquireAuthorizationOptions(env, argv[PARAM_ONE], asyncContext);
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

    // Check if authorization should be skipped (e.g., when context conversion fails)
    if (asyncContext->skipAuthorization) {
        ACCOUNT_LOGI("Authorization skipped due to context conversion failure");
        auto callback = std::make_shared<NapiAuthorizationResultCallback>(asyncContext);
        callback->OnResult(asyncContext->errCode, asyncContext->authorizationResult);
        return;
    }

    auto callback = std::make_shared<NapiAuthorizationResultCallback>(asyncContext);
    asyncContext->errCode = AuthorizationClient::GetInstance().AcquireAuthorization(
        asyncContext->privilege, asyncContext->options, callback);
    if (asyncContext->errCode != ERR_OK) {
        AuthorizationResult result;
        callback->OnResult(asyncContext->errCode, result);
    }
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

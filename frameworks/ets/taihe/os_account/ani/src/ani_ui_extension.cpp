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

#include "ani_ui_extension.h"
#include "ability_context.h"
#include "ani_base_context.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "iconnect_ability_callback.h"
#include "ui_content.h"
#include "ui_extension_base/ui_extension_context.h"

namespace OHOS {
namespace AccountSA {
namespace {
const int32_t EXTENSION_ERROR = -1;
std::mutex g_mutex;
const std::string EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
const std::string UI_EXTENSION_TYPE = "sys/commonUI";
const std::string TOKEN_KEY = "authResultToken";
const std::string ACCOUNTID_KEY = "authResultAccountID";
const std::string CODE_KEY = "authResultCode";
const int32_t CANCEL_ERROR = 1;
const int32_t DENIED_ERROR = 2;
const int32_t BACKGROUNT_ERROR = 1011;
}

/**
 * @brief Constructor for UIExtensionCallback.
 * @param context The shared authorization context
 */
UIExtensionCallback::UIExtensionCallback(const std::shared_ptr<TaiheAcquireAuthorizationContext> &context)
{
    context_ = context;
    isOnResult_.exchange(false);
}

/**
 * @brief Set the session ID for this callback.
 * @param sessionId The session ID to set
 */
void UIExtensionCallback::SetSessionId(int32_t sessionId)
{
    sessionId_ = sessionId;
}

/**
 * @brief Set the callback object.
 * @param callback The callback remote object
 */
void UIExtensionCallback::SetCallBack(const sptr<IRemoteObject> &callback)
{
    callback_ = callback;
}

/**
 * @brief Handle UIExtension release event.
 *
 * Called when UIExtensionAbility disconnects, uses terminate, or process dies.
 * releaseCode is 0 when process exits normally.
 *
 * @param releaseCode The release code
 */
void UIExtensionCallback::OnRelease(int32_t releaseCode)
{
    ACCOUNT_LOGI("enter OnRelease releaseCode:%{public}d", releaseCode);
    if (!isOnResult_.load()) {
        ReleaseHandler(ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR);
    }
}

/**
 * @brief Handle UIExtension error event.
 *
 * Called when UIExtensionComponent init fails, turns to background,
 * or UIExtensionAbility encounters an error.
 *
 * @param code Error code
 * @param name Error name
 * @param message Error message
 */
void UIExtensionCallback::OnError(int32_t code, const std::string &name, const std::string &message)
{
    ACCOUNT_LOGI("enter OnError errCode:%{public}d, name:%{public}s, message:%{public}s", code, name.c_str(),
        message.c_str());
    if (isOnResult_.load()) {
        return;
    }
    if (code == BACKGROUNT_ERROR) {
        ReleaseHandler(ERR_OK, AUTHORIZATION_INTERACTION_NOT_ALLOWED);
    } else {
        ReleaseHandler(ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR);
    }
}

/**
 * @brief Handle UIExtension result event.
 *
 * Called when UIExtensionAbility uses terminateSelfWithResult.
 *
 * @param resultCode The result code from UIExtension
 * @param result The result data containing token and account ID
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
        ACCOUNT_LOGI("AccountId is %{public}d, return error", accountId);
        return ReleaseHandler(ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR);
    }
    return ReleaseHandler(ERR_OK, AUTHORIZATION_SUCCESS, tokenVec, accountId);
}

/**
 * @brief Handle UIExtension receive event.
 *
 * Called when UIExtensionAbility sends message to UIExtensionComponent.
 *
 * @param request The received request parameters
 */
void UIExtensionCallback::OnReceive(const OHOS::AAFwk::WantParams &request)
{
    ACCOUNT_LOGI("enter OnReceive");
}

/**
 * @brief Handle UIExtension remote ready event.
 *
 * Called when UIExtensionComponent connects to UIExtensionAbility.
 * ModalUIExtensionProxy will be initialized, allowing UIExtensionComponent
 * to send messages to UIExtensionAbility.
 *
 * @param uiProxy The UI Extension proxy
 */
void UIExtensionCallback::OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy)
{
    ACCOUNT_LOGI("enter OnRemoteReady");
}

/**
 * @brief Handle UIExtension destroy event.
 *
 * Called when UIExtensionComponent is destroyed.
 */
void UIExtensionCallback::OnDestroy()
{
    ACCOUNT_LOGI("enter OnDestroy");
    if (!isOnResult_.load()) {
        ReleaseHandler(EXTENSION_ERROR, AUTHORIZATION_SYSTEM_BUSY);
    }
}

/**
 * @brief Release handler with authorization result.
 *
 * Notifies the authorization service of the result and closes the UI extension.
 *
 * @param code Release code
 * @param resultCode Authorization result code
 * @param iamToken IAM token
 * @param accountId Account ID
 */
void UIExtensionCallback::ReleaseHandler(int32_t errCode, AuthorizationResultCode resultCode,
    const std::vector<uint8_t> &iamToken, int32_t accountId)
{
    ACCOUNT_LOGI("enter ReleaseHandler code:%{public}d, resultCode:%{public}d", errCode, resultCode);
    if (context_ == nullptr || callback_ == nullptr) {
        ACCOUNT_LOGE("Context or callback is nullptr");
        return;
    }
    auto callbackProxy = iface_cast<IConnectAbilityCallback>(callback_);
    if (callbackProxy == nullptr) {
        CloseUIExtension(context_);
        ACCOUNT_LOGE("ConnectAbilityCallback proxy is nullptr");
        return;
    }
    int32_t resultCodeInt = static_cast<int32_t>(resultCode);
    ErrCode ret = callbackProxy->OnResult(errCode, iamToken, accountId, resultCodeInt);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to call iConnectAbilityCallback onResult, errCode:%{public}d", ret);
    }
    CloseUIExtension(context_);
    context_ = nullptr;
}

/**
 * @brief Fill information from ANI context.
 *
 * Extracts the stage context from the ANI context object.
 *
 * @param aniContext The ANI context object
 * @return true if successful, false otherwise
 */
bool TaiheAcquireAuthorizationContext::FillInfoFromContext(const ani_object& aniContext)
{
    if (env_ == nullptr) {
        ACCOUNT_LOGE("env_ is nullptr.");
        return false;
    }
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env_, aniContext);
    if (context == nullptr) {
        ACCOUNT_LOGE("GetStageModeContext failed");
        return false;
    }
    stageContext_ = context;
    return true;
}

/**
 * @brief Get UIContent from stage context.
 *
 * Attempts to get UIContent from either AbilityContext or UIExtensionContext.
 *
 * @param stageContext The stage context
 * @return UIContent pointer, or nullptr if failed
 */
static OHOS::Ace::UIContent* GetUIContent(const std::shared_ptr<OHOS::AbilityRuntime::Context> stageContext)
{
    OHOS::Ace::UIContent* uiContent = nullptr;
    auto abilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(
        stageContext);
    if (abilityContext != nullptr) {
        ACCOUNT_LOGI("Get UIContent from AbilityContext");
        uiContent = abilityContext->GetUIContent();
    } else {
        auto uiExtensionContext =
            OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::UIExtensionContext>(stageContext);
        if (uiExtensionContext == nullptr) {
            ACCOUNT_LOGE("Failed to ConvertTo UIExtensionContext.");
            return nullptr;
        }
        uiContent = uiExtensionContext->GetUIContent();
    }
    return uiContent;
}

/**
 * @brief Create UI extension on main thread.
 *
 * Creates a modal UI extension with the specified want and callbacks.
 *
 * @param asyncContext The authorization context
 * @param want The want object for the extension
 * @param uiExtensionCallbacks The UI extension callbacks
 * @param uiExtCallback The UI extension callback object
 * @return ERR_OK on success, error code on failure
 */
static ErrCode CreateUIExtensionMainThread(std::shared_ptr<TaiheAcquireAuthorizationContext> &asyncContext,
    const OHOS::AAFwk::Want& want, const OHOS::Ace::ModalUIExtensionCallbacks &uiExtensionCallbacks,
    const std::shared_ptr<UIExtensionCallback> &uiExtCallback)
{
    if (asyncContext == nullptr || uiExtCallback == nullptr) {
        ACCOUNT_LOGE("asyncContext or uiExtCallback is nullptr");
        return ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR;
    }
    OHOS::Ace::UIContent* uiContent = GetUIContent(asyncContext->stageContext_);
    if (uiContent == nullptr) {
        ACCOUNT_LOGE("Get ui content failed!");
        asyncContext->errCode = ERR_AUTHORIZATION_GET_CONTENT_ERROR;
        asyncContext->uiExtensionFlag = false;
        return ERR_AUTHORIZATION_GET_CONTENT_ERROR;
    }

    OHOS::Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
    ACCOUNT_LOGI("Create end, sessionId: %{public}d", sessionId);
    if (sessionId <= 0) {
        ACCOUNT_LOGE("Create component failed, sessionId is 0");
        asyncContext->errCode = ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR;
        asyncContext->uiExtensionFlag = false;
        return ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR;
    }
    uiExtCallback->SetSessionId(sessionId);
    asyncContext->sessionId = sessionId;
    ACCOUNT_LOGI("CreateUIExtensionMainThread end");
    return ERR_OK;
}

/**
 * @brief Create a UI Extension for authorization.
 *
 * Creates a modal UI extension with the specified connection information.
 *
 * @param asyncContext The authorization context
 * @param info Connection ability information
 * @param callback The callback object for authorization results
 * @return ERR_OK on success, error code on failure
 */
ErrCode CreateUIExtension(std::shared_ptr<TaiheAcquireAuthorizationContext> &asyncContext,
    const ConnectAbilityInfo &info, const sptr<IRemoteObject> &callback)
{
    AAFwk::Want want;
    want.SetElementName(info.bundleName, info.abilityName);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);
    std::string challengeStr;
    TransVectorU8ToString(info.challenge, challengeStr);
    want.SetParam("challenge", challengeStr);
    want.SetParam("privilege", info.privilege);
    want.SetParam("description", info.description);

    auto uiExtCallback = std::make_shared<UIExtensionCallback>(asyncContext);
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
        [uiExtCallback](int32_t code, const std::string &name, [[maybe_unused]] const std::string &message) {
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
    return CreateUIExtensionMainThread(asyncContext, want, uiExtensionCallbacks, uiExtCallback);
}

/**
 * @brief Close the UI Extension and release resources.
 *
 * Closes the modal UI extension associated with the given context.
 *
 * @param asyncContext The authorization context to close
 */
void CloseUIExtension(std::shared_ptr<TaiheAcquireAuthorizationContext> &asyncContext)
{
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("asyncContext is nullptr");
        return;
    }

    Ace::UIContent* uiContent = GetUIContent(asyncContext->stageContext_);
    if (uiContent == nullptr) {
        ACCOUNT_LOGE("Get ui content failed!");
        return;
    }

    uiContent->CloseModalUIExtension(asyncContext->sessionId);
    ACCOUNT_LOGI("Close end, sessionId: %{public}d", asyncContext->sessionId);
}

} // namespace AccountSA
} // namespace OHOS

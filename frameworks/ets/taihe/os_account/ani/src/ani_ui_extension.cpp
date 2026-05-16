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
#include <thread>
#include "account_constants.h"
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
std::mutex g_mutex;
}

/**
 * @brief Constructor for UIExtensionCallback.
 * @param context The shared authorization context
 */
UIExtensionCallback::UIExtensionCallback(const std::shared_ptr<TaiheAcquireAuthorizationContext>& context)
    : context_(context)
{
    isOnResult_.exchange(false);
    isReleased_.exchange(false);
}

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
        CloseUIExtension();
        ACCOUNT_LOGE("ConnectAbilityCallback proxy is nullptr");
        return;
    }
    int32_t resultCodeInt = static_cast<int32_t>(resultCode);
    ErrCode ret = ERR_OK;
    int retryTimes = 0;
    while (retryTimes < AuthorizationConstants::MAX_RETRY_TIME) {
        ret = callbackProxy->OnResult(errCode, iamToken, accountId, resultCodeInt);
        if (ret == ERR_OK || (ret != Constants::E_IPC_ERROR &&
            ret != Constants::E_IPC_SA_DIED)) {
            break;
        }
        retryTimes++;
        ACCOUNT_LOGE("UIExtensionCallback send result failed, code=%{public}d, retryTimes=%{public}d",
            ret, retryTimes);
        std::this_thread::sleep_for(std::chrono::milliseconds(Constants::DELAY_FOR_EXCEPTION));
    }
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to call iConnectAbilityCallback onResult, errCode:%{public}d", ret);
    }
    CloseUIExtension();
    context_ = nullptr;
}

OHOS::Ace::UIContent* UIExtensionCallback::GetUIContent()
{
    if (context_ == nullptr || context_->stageContext_ == nullptr) {
        ACCOUNT_LOGE("context or stageContext is nullptr");
        return nullptr;
    }

    OHOS::Ace::UIContent* uiContent = nullptr;
    auto abilityContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context_->stageContext_);
    if (abilityContext != nullptr) {
        ACCOUNT_LOGI("Get UIContent from AbilityContext");
        uiContent = abilityContext->GetUIContent();
    } else {
        auto uiExtensionContext =
            OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::UIExtensionContext>(context_->stageContext_);
        if (uiExtensionContext == nullptr) {
            ACCOUNT_LOGE("Failed to ConvertTo UIExtensionContext.");
            return nullptr;
        }
        uiContent = uiExtensionContext->GetUIContent();
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

ErrCode CreateUIExtension(std::shared_ptr<TaiheAcquireAuthorizationContext> &asyncContext,
    const ConnectAbilityInfo &info, const sptr<IRemoteObject> &callback)
{
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("asyncContext is nullptr");
        return ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR;
    }

    auto uiExtCallback = std::make_shared<UIExtensionCallback>(asyncContext);
    AAFwk::Want want = UIExtensionCallbackBase::BuildWantFromConnectInfo(info);
    Ace::ModalUIExtensionCallbacks uiExtensionCallbacks =
        UIExtensionCallbackBase::CreateUIExtensionCallbacks(uiExtCallback);

    uiExtCallback->SetCallBack(callback);

    OHOS::Ace::UIContent* uiContent = uiExtCallback->GetUIContent();
    if (uiContent == nullptr) {
        ACCOUNT_LOGE("Get ui content failed!");
        asyncContext->errCode = ERR_AUTHORIZATION_GET_CONTENT_ERROR;
        asyncContext->uiExtensionFlag = false;
        return ERR_AUTHORIZATION_GET_CONTENT_ERROR;
    }

    OHOS::Ace::ModalUIExtensionConfig config;
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
    ACCOUNT_LOGI("CreateUIExtension end");
    return ERR_OK;
}

void CloseUIExtension(std::shared_ptr<TaiheAcquireAuthorizationContext> &asyncContext)
{
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("asyncContext is nullptr");
        return;
    }

    auto uiExtCallback = std::make_shared<UIExtensionCallback>(asyncContext);
    uiExtCallback->SetSessionId(asyncContext->sessionId);
    uiExtCallback->CloseUIExtension();
}

} // namespace AccountSA
} // namespace OHOS

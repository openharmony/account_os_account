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

#include "authorization_ui_extension_callback.h"
#include "account_constants.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {

void UIExtensionCallbackBase::SetSessionId(int32_t sessionId) { sessionId_ = sessionId; }

void UIExtensionCallbackBase::SetCallBack(const sptr<IRemoteObject>& callback) { callback_ = callback; }

void UIExtensionCallbackBase::OnRelease(int32_t releaseCode)
{
    ACCOUNT_LOGI("enter OnRelease releaseCode:%{public}d", releaseCode);
    if (isOnResult_.load()) {
        return;
    }
    if (isReleased_.exchange(true)) {
        return;
    }
    ReleaseHandler(ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR);
}

void UIExtensionCallbackBase::OnError(int32_t code, const std::string& name, const std::string& message)
{
    ACCOUNT_LOGI(
        "enter OnError errCode:%{public}d, name:%{public}s, message:%{public}s", code, name.c_str(), message.c_str());
    if (isOnResult_.load()) {
        return;
    }
    if (isReleased_.exchange(true)) {
        return;
    }
    if (code == AuthorizationConstants::BACKGROUNT_ERROR) {
        ReleaseHandler(ERR_OK, AUTHORIZATION_INTERACTION_NOT_ALLOWED);
    } else {
        ReleaseHandler(ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR);
    }
}

void UIExtensionCallbackBase::OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result)
{
    ACCOUNT_LOGI("enter OnResult resultCode:%{public}d", resultCode);
    if (isReleased_.load() || isOnResult_.exchange(true)) {
        ACCOUNT_LOGI("Already released or result received, ignore OnResult");
        return;
    }

    if (resultCode == AuthorizationConstants::CANCEL_ERROR) {
        return ReleaseHandler(ERR_OK, AUTHORIZATION_CANCELED);
    }
    if (resultCode == AuthorizationConstants::DENIED_ERROR) {
        return ReleaseHandler(ERR_OK, AUTHORIZATION_DENIED);
    }
    if (resultCode != ERR_OK) {
        return ReleaseHandler(ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR);
    }

    ACCOUNT_LOGI("ResultCode is %{public}d", resultCode);
    std::vector<int> iamToken = result.GetIntArrayParam(AuthorizationConstants::TOKEN_KEY);
    std::vector<uint8_t> tokenVec(iamToken.begin(), iamToken.end());
    std::fill(iamToken.begin(), iamToken.end(), 0);

    int32_t accountId = result.GetIntParam(AuthorizationConstants::ACCOUNTID_KEY, -1);
    if (accountId == -1) {
        ACCOUNT_LOGI("AccountId is %{public}d", accountId);
        std::fill(tokenVec.begin(), tokenVec.end(), 0);
        return ReleaseHandler(ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR);
    }

    ReleaseHandler(ERR_OK, AUTHORIZATION_SUCCESS, tokenVec, accountId);
    std::fill(tokenVec.begin(), tokenVec.end(), 0);
}

void UIExtensionCallbackBase::OnReceive(const OHOS::AAFwk::WantParams& request) { ACCOUNT_LOGI("enter OnReceive"); }

void UIExtensionCallbackBase::OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy)
{
    ACCOUNT_LOGI("enter OnRemoteReady");
}

void UIExtensionCallbackBase::OnDestroy()
{
    ACCOUNT_LOGI("enter OnDestroy");
    if (isOnResult_.load()) {
        return;
    }
    if (isReleased_.exchange(true)) {
        return;
    }
    ReleaseHandler(AuthorizationConstants::EXTENSION_ERROR, AUTHORIZATION_SERVICE_BUSY);
}

AAFwk::Want UIExtensionCallbackBase::BuildWantFromConnectInfo(const ConnectAbilityInfo& info)
{
    AAFwk::Want want;
    want.SetElementName(info.bundleName, info.abilityName);
    want.SetParam(AuthorizationConstants::EXTENSION_TYPE_KEY, AuthorizationConstants::UI_EXTENSION_TYPE);

    std::string challengeStr;
    TransVectorU8ToString(info.challenge, challengeStr);
    want.SetParam("challenge", challengeStr);
    std::fill(challengeStr.begin(), challengeStr.end(), '\0');

    want.SetParam("privilege", info.privilege);
    want.SetParam("description", info.description);

    return want;
}

Ace::ModalUIExtensionCallbacks UIExtensionCallbackBase::CreateUIExtensionCallbacks(
    const std::shared_ptr<UIExtensionCallbackBase>& uiExtCallback)
{
    return {
        [uiExtCallback](int32_t releaseCode) { uiExtCallback->OnRelease(releaseCode); },
        [uiExtCallback](int32_t resultCode, const AAFwk::Want& result) { uiExtCallback->OnResult(resultCode, result); },
        [uiExtCallback](const AAFwk::WantParams& receive) { uiExtCallback->OnReceive(receive); },
        [uiExtCallback](int32_t code, const std::string& name, const std::string& message) {
            uiExtCallback->OnError(code, name, message);
        },
        [uiExtCallback](
            const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy) { uiExtCallback->OnRemoteReady(uiProxy); },
        [uiExtCallback]() { uiExtCallback->OnDestroy(); },
    };
}

void UIExtensionCallbackBase::CloseUIExtension(OHOS::Ace::UIContent* uiContent, int32_t sessionId)
{
    if (uiContent == nullptr) {
        ACCOUNT_LOGE("uiContent is nullptr");
        return;
    }
    uiContent->CloseModalUIExtension(sessionId);
    ACCOUNT_LOGI("Close end, sessionId: %{public}d", sessionId);
}

} // namespace AccountSA
} // namespace OHOS
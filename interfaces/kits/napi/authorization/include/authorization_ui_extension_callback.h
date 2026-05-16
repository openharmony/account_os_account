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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_AUTHORIZATION_AUTHORIZATION_UI_EXTENSION_CALLBACK_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_AUTHORIZATION_AUTHORIZATION_UI_EXTENSION_CALLBACK_H

#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include "authorization_common.h"
#include "iremote_object.h"
#include "iconnect_ability_callback.h"
#include "ui_content.h"
#include "ui_extension_base/ui_extension_context.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {

/**
 * @brief Constants used in authorization UI Extension process.
 */
namespace AuthorizationConstants {
/** User canceled the authorization */
constexpr int32_t CANCEL_ERROR = 1;
/** User denied the authorization */
constexpr int32_t DENIED_ERROR = 2;
/** Authorization UI Extension turned to background */
constexpr int32_t BACKGROUNT_ERROR = 1011;
/** UI Extension error occurred */
constexpr int32_t EXTENSION_ERROR = -1;
/** Maximum retry times for IPC calls */
constexpr int32_t MAX_RETRY_TIME = 3;
/** Key for UI Extension type in Want parameters */
const std::string EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
/** Value for common UI Extension type */
const std::string UI_EXTENSION_TYPE = "sys/commonUI";
/** Key for authorization result token in Want parameters */
const std::string TOKEN_KEY = "authResultToken";
/** Key for account ID in Want parameters */
const std::string ACCOUNTID_KEY = "authResultAccountID";
/** Key for authorization result code in Want parameters */
const std::string CODE_KEY = "authResultCode";
} // namespace AuthorizationConstants

/**
 * @brief Base class for UI Extension callback in authorization process.
 *
 * This class provides common callback methods for UI Extension lifecycle events
 * and handles authorization result processing. Subclasses should implement the
 * virtual methods for platform-specific logic.
 */
class UIExtensionCallbackBase {
public:
    virtual ~UIExtensionCallbackBase() = default;

    /**
     * @brief Sets the session ID for the UI Extension.
     * @param sessionId The session ID returned from CreateModalUIExtension.
     */
    void SetSessionId(int32_t sessionId);

    /**
     * @brief Sets the callback remote object for IPC communication.
     * @param callback The IConnectAbilityCallback remote object.
     */
    void SetCallBack(const sptr<IRemoteObject>& callback);

    /**
     * @brief Handles UI Extension release event.
     *
     * Called when UIExtensionAbility disconnects, terminates, or process dies.
     * @param releaseCode The release code (0 for normal exit).
     */
    void OnRelease(int32_t releaseCode);

    /**
     * @brief Handles UI Extension error event.
     *
     * Called when UIExtensionComponent initialization fails, turns to background,
     * or UIExtensionAbility encounters an error.
     * @param code The error code.
     * @param name The error name.
     * @param message The error message.
     */
    void OnError(int32_t code, const std::string& name, const std::string& message);

    /**
     * @brief Handles UI Extension result event.
     *
     * Called when UIExtensionAbility uses terminateSelfWithResult.
     * @param resultCode The result code from UI Extension.
     * @param result The result Want containing token and account ID.
     */
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result);

    /**
     * @brief Handles UI Extension receive event.
     *
     * Called when UIExtensionAbility sends message to UIExtensionComponent.
     * @param request The received WantParams.
     */
    void OnReceive(const OHOS::AAFwk::WantParams& request);

    /**
     * @brief Handles UI Extension remote ready event.
     *
     * Called when UIExtensionComponent connects to UIExtensionAbility,
     * ModalUIExtensionProxy will be initialized.
     * @param uiProxy The UI Extension proxy for communication.
     */
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy);

    /**
     * @brief Handles UI Extension destroy event.
     *
     * Called when UIExtensionComponent is destroyed.
     */
    void OnDestroy();

    /**
     * @brief Builds a Want object from ConnectAbilityInfo.
     * @param info The connection ability information containing bundle name, ability name, etc.
     * @return The Want object for creating UI Extension.
     */
    static AAFwk::Want BuildWantFromConnectInfo(const ConnectAbilityInfo& info);

    /**
     * @brief Creates ModalUIExtensionCallbacks structure.
     * @param uiExtCallback The UI Extension callback object.
     * @return The callback structure for CreateModalUIExtension.
     */
    static Ace::ModalUIExtensionCallbacks CreateUIExtensionCallbacks(
        const std::shared_ptr<UIExtensionCallbackBase>& uiExtCallback);

    /**
     * @brief Closes UI Extension by session ID.
     * @param uiContent The UIContent pointer for closing UI Extension.
     * @param sessionId The session ID to close.
     */
    static void CloseUIExtension(OHOS::Ace::UIContent* uiContent, int32_t sessionId);

    /**
     * @brief Gets the UIContent for creating/closing UI Extension.
     * @return The UIContent pointer, nullptr if failed.
     */
    virtual OHOS::Ace::UIContent* GetUIContent() = 0;

    /**
     * @brief Closes the UI Extension.
     */
    virtual void CloseUIExtension() = 0;

protected:
    UIExtensionCallbackBase() = default;

    /**
     * @brief Handles authorization result release.
     *
     * Subclasses should implement IPC call to IConnectAbilityCallback::OnResult.
     * @param errCode The error code.
     * @param resultCode The authorization result code.
     * @param iamToken The IAM token for authentication.
     * @param accountId The account ID.
     */
    virtual void ReleaseHandler(int32_t errCode,
        AccountSA::AuthorizationResultCode resultCode = AccountSA::AuthorizationResultCode::AUTHORIZATION_SUCCESS,
        const std::vector<uint8_t> &iamToken = std::vector<uint8_t>(),
        int32_t accountId = -1) = 0;

protected:
    /** Flag indicating whether OnResult has been called */
    std::atomic<bool> isOnResult_{false};
    /** Flag indicating whether the callback has been released */
    std::atomic<bool> isReleased_{false};
    /** Session ID for the UI Extension */
    int32_t sessionId_{0};
    /** Remote callback object for IPC communication */
    sptr<IRemoteObject> callback_ = nullptr;
};

} // namespace AccountSA
} // namespace OHOS

#endif // OS_ACCOUNT_INTERFACES_KITS_NAPI_AUTHORIZATION_AUTHORIZATION_UI_EXTENSION_CALLBACK_H
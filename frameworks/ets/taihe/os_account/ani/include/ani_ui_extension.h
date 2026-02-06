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

#ifndef ANI_OS_ACCOUNT_UI_EXTENSION_H
#define ANI_OS_ACCOUNT_UI_EXTENSION_H

#include <atomic>
#include <memory>
#include <vector>
#include "ani_base_context.h"
#include "ability_context.h"
#include "ani.h"
#include "authorization_callback.h"
#include "authorization_common.h"
#include "refbase.h"
#include "ui_content.h"
#include "ui_extension_context.h"
#include "want.h"
#include "window.h"

namespace OHOS {
namespace AccountSA {

/**
 * @brief Context structure for ANI-based UI authorization acquisition.
 *
 * This structure contains all necessary information for the authorization
 * acquisition process through Ark Native Interface UI Extension.
 */
struct TaiheAcquireAuthorizationContext {
    /**
     * @brief Constructor with ANI environment.
     * @param env The ANI environment pointer
     */
    explicit TaiheAcquireAuthorizationContext(ani_env* env) : env_(env)
    {}

    /**
     * @brief Fill information from ANI context object.
     * @param aniContext The ANI context object
     * @return true if successful, false otherwise
     */
    bool FillInfoFromContext(const ani_object& aniContext);

    // Authorization options
    AcquireAuthorizationOptions options{};
    bool hasOptions = false;

    // Session information
    int32_t sessionId = -1;
    bool uiAbilityFlag = false;
    bool uiExtensionFlag = false;

    // Result
    ErrCode errCode = ERR_OK;

    // Runtime context
    std::shared_ptr<OHOS::AbilityRuntime::Context> stageContext_ = nullptr;
    ani_env* env_ = nullptr;
};

/**
 * @brief Callback class for UI Extension authorization flow.
 *
 * This class handles callbacks from the UI Extension during the
 * authorization process, managing lifecycle events and result handling.
 */
class UIExtensionCallback {
public:
    /**
     * @brief Constructor with authorization context.
     * @param context The shared authorization context
     */
    explicit UIExtensionCallback(const std::shared_ptr<TaiheAcquireAuthorizationContext> &context);

    /**
     * @brief Destructor
     */
    ~UIExtensionCallback() = default;

    // Disable copy and move
    UIExtensionCallback(const UIExtensionCallback&) = delete;
    UIExtensionCallback(UIExtensionCallback&&) = delete;
    UIExtensionCallback& operator=(const UIExtensionCallback&) = delete;
    UIExtensionCallback& operator=(UIExtensionCallback&&) = delete;

    /**
     * @brief Set the session ID.
     * @param sessionId The session ID to set
     */
    void SetSessionId(int32_t sessionId);

    /**
     * @brief Set the callback object.
     * @param callback The callback remote object
     */
    void SetCallBack(const sptr<IRemoteObject> &callback);

    /**
     * @brief Handle release event.
     * @param releaseCode The release code
     */
    void OnRelease(int32_t releaseCode);

    /**
     * @brief Handle result event.
     * @param resultCode The result code
     * @param result The result data
     */
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want &result);

    /**
     * @brief Handle receive event.
     * @param request The received request parameters
     */
    void OnReceive(const OHOS::AAFwk::WantParams &request);

    /**
     * @brief Handle error event.
     * @param code Error code
     * @param name Error name
     * @param message Error message
     */
    void OnError(int32_t code, const std::string &name, const std::string &message);

    /**
     * @brief Handle remote ready event.
     * @param uiProxy The UI Extension proxy
     */
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy);

    /**
     * @brief Handle destroy event.
     */
    void OnDestroy();

    /**
     * @brief Release handler with authorization result.
     * @param code Release code
     * @param resultCode Authorization result code
     * @param iamToken IAM token
     * @param accountId Account ID
     */
    void ReleaseHandler(int32_t code,
        AccountSA::AuthorizationResultCode resultCode = AccountSA::AuthorizationResultCode::AUTHORIZATION_SUCCESS,
        const std::vector<uint8_t> &iamToken = std::vector<uint8_t>(),
        int32_t accountId = -1);

private:
    int32_t sessionId_ = 0;
    std::atomic<bool> isOnResult_{false};
    std::vector<uint8_t> token_;
    std::shared_ptr<TaiheAcquireAuthorizationContext> context_ = nullptr;
    sptr<IRemoteObject> callback_ = nullptr;
};

/**
 * @brief Close the UI Extension and release resources.
 * @param asyncContext The authorization context to close
 */
void CloseUIExtension(std::shared_ptr<TaiheAcquireAuthorizationContext> &asyncContext);

/**
 * @brief Create a UI Extension for authorization.
 * @param asyncContext The authorization context
 * @param info Connection ability information
 * @param callback The callback object for authorization results
 * @return ERR_OK on success, error code on failure
 */
ErrCode CreateUIExtension(std::shared_ptr<TaiheAcquireAuthorizationContext> &asyncContext,
    const ConnectAbilityInfo &info, const sptr<IRemoteObject> &callback);

} // namespace AccountSA
} // namespace OHOS

#endif // ANI_OS_ACCOUNT_UI_EXTENSION_H

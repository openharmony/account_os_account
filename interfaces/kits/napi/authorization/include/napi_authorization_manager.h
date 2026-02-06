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

#ifndef AUTHORIZATION_KITS_NAPI_AUTHORIZATION_INCLUDE_AUTHORIZATION_MANAGER_H
#define AUTHORIZATION_KITS_NAPI_AUTHORIZATION_INCLUDE_AUTHORIZATION_MANAGER_H

#include <atomic>
#include <vector>
#include "authorization_callback.h"
#include "authorization_common.h"
#include "napi/native_api.h"
#include "napi_account_common.h"
#include "ui_content.h"
#include "ui_extension_context.h"
#include "want.h"

namespace OHOS {
namespace AccountJsKit {
struct AcquireAuthorizationContext : public CommonAsyncContext {
    AcquireAuthorizationContext(napi_env napiEnv, bool isThrowable) : CommonAsyncContext(napiEnv, isThrowable) {};
    AccountSA::AcquireAuthorizationOptions options;
    AccountSA::AuthorizationResult authorizationResult;
    std::string privilege;
    bool hasOptions = false;
    bool uiAbilityFlag = false;
    bool skipAuthorization = false;  // Flag to skip authorization flow (e.g., when context conversion fails)
    int32_t sessionId = -1;
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext;
    std::shared_ptr<AbilityRuntime::UIExtensionContext> uiExtensionContext;
};

class UIExtensionCallback {
public:
    explicit UIExtensionCallback(const std::shared_ptr<AcquireAuthorizationContext> &context);
    ~UIExtensionCallback() = default;
    void SetSessionId(int32_t sessionId);
    void SetCallBack(const sptr<IRemoteObject> &callback);
    void OnRelease(int32_t releaseCode);
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want &result);
    void OnReceive(const OHOS::AAFwk::WantParams &request);
    void OnError(int32_t code, const std::string &name, const std::string &message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy);
    void OnDestroy();
    void ReleaseHandler(int32_t code,
        AccountSA::AuthorizationResultCode resultCode = AccountSA::AuthorizationResultCode::AUTHORIZATION_SUCCESS,
        const std::vector<uint8_t> &iamToken = std::vector<uint8_t>(), int32_t accountId = -1);

private:
    int32_t sessionId_ = 0;
    std::atomic<bool> isOnResult_;
    std::vector<uint8_t> token_;
    std::shared_ptr<AcquireAuthorizationContext> context_ = nullptr;
    sptr<IRemoteObject> callback_ = nullptr;
};

class NapiAuthorizationResultCallback final : public AccountSA::AuthorizationCallback {
public:
    NapiAuthorizationResultCallback(AcquireAuthorizationContext *asyncContextPtr)
    {
        env_ = asyncContextPtr->env;
        deferred_ = asyncContextPtr->deferred;
        if (asyncContextPtr->hasOptions) {
            context_ = std::make_shared<AcquireAuthorizationContext>(env_, true);
            context_->hasOptions = asyncContextPtr->hasOptions;
            context_->uiAbilityFlag = asyncContextPtr->uiAbilityFlag;
            context_->sessionId = asyncContextPtr->sessionId;
            context_->abilityContext = asyncContextPtr->abilityContext;
            context_->uiExtensionContext = asyncContextPtr->uiExtensionContext;
            context_->options.hasContext = asyncContextPtr->options.hasContext;
        }
    }
    ErrCode OnResult(int32_t resultCode, const AccountSA::AuthorizationResult& result) override;
    ErrCode OnConnectAbility(const AccountSA::ConnectAbilityInfo &info,
        const sptr<IRemoteObject> &callback) override;
private:
    napi_env env_;
    napi_deferred deferred_ = nullptr;
    std::shared_ptr<AcquireAuthorizationContext> context_ = nullptr;
};

class NapiAuthorizationManager {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value JsConstructor(napi_env env, napi_callback_info cbInfo);
    static napi_value AuthorizationResultCodeConstructor(napi_env env);
    static napi_value AcquireAuthorization(napi_env env, napi_callback_info cbInfo);
    static napi_value GetAuthorizationManager(napi_env env, napi_callback_info cbInfo);
};
}
}
#endif // AUTHORIZATION_KITS_NAPI_AUTHORIZATION_INCLUDE_AUTHORIZATION_MANAGER_H
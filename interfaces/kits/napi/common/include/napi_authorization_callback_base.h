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

#ifndef NAPI_AUTHORIZATION_CALLBACK_BASE_H
#define NAPI_AUTHORIZATION_CALLBACK_BASE_H

#include <memory>
#include <functional>
#include "account_error_no.h"
#include "authorization_callback.h"
#include "authorization_ui_extension_callback.h"
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
    bool isPublicApi = false;
    int32_t sessionId = -1;
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext;
    std::shared_ptr<AbilityRuntime::UIExtensionContext> uiExtensionContext;
};

class UIExtensionCallback : public AccountSA::UIExtensionCallbackBase {
public:
    explicit UIExtensionCallback(const std::shared_ptr<AcquireAuthorizationContext> &context);
    ~UIExtensionCallback() = default;
    OHOS::Ace::UIContent* GetUIContent() override;
    void CloseUIExtension() override;

protected:
    void ReleaseHandler(int32_t errCode,
        AccountSA::AuthorizationResultCode resultCode = AccountSA::AuthorizationResultCode::AUTHORIZATION_SUCCESS,
        const std::vector<uint8_t> &iamToken = std::vector<uint8_t>(),
        int32_t accountId = -1) override;

private:
    std::shared_ptr<AcquireAuthorizationContext> context_ = nullptr;
};

class NapiAuthorizationResultCallback final : public AccountSA::AuthorizationCallback {
public:
    using ResultToJsFunc = std::function<void(napi_env, const AccountSA::AuthorizationResult&, napi_value&)>;

    NapiAuthorizationResultCallback(AcquireAuthorizationContext *asyncContextPtr, ResultToJsFunc resultToJsFunc,
        bool isPublicApi = false)
        : resultToJsFunc_(resultToJsFunc), isPublicApi_(isPublicApi)
    {
        env_ = asyncContextPtr->env;
        deferred_ = asyncContextPtr->deferred;
        if (asyncContextPtr->hasOptions) {
            context_ = std::make_shared<AcquireAuthorizationContext>(env_, true);
            context_->hasOptions = asyncContextPtr->hasOptions;
            context_->privilege = asyncContextPtr->privilege;
            context_->uiAbilityFlag = asyncContextPtr->uiAbilityFlag;
            context_->isPublicApi = asyncContextPtr->isPublicApi;
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
    ResultToJsFunc resultToJsFunc_;
    bool isPublicApi_ = false;
};

bool ConvertContextObject(napi_env env, napi_value contextValue,
    AcquireAuthorizationContext *asyncContext);

} // namespace AccountJsKit
} // namespace OHOS

#endif // NAPI_AUTHORIZATION_CALLBACK_BASE_H

/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_ABILITYRUNTIME_OHOS_JS_AUTHENTICATION_EXTENSION_H
#define FOUNDATION_ABILITYRUNTIME_OHOS_JS_AUTHENTICATION_EXTENSION_H

#include "app_account_authentication_extension_callback_client.h"
#include "app_account_common.h"
#include "authentication_extension.h"
#include "js_runtime.h"
#include "napi_account_common.h"
#include "native_engine/native_value.h"

namespace OHOS {
namespace AccountJsKit {

using namespace OHOS::AbilityRuntime;
/**
 * @brief Basic authentication components.
 */
class JsAuthenticationExtension : public AuthenticationExtension {
public:
    JsAuthenticationExtension(JsRuntime &jsRuntime);
    ~JsAuthenticationExtension() override;
    /**
     * @brief Create JsAuthenticationExtension.
     *
     * @param runtime The runtime.
     * @return The JsAuthenticationExtension instance.
     */
    static JsAuthenticationExtension *Create(const std::unique_ptr<Runtime> &runtime);

    /**
     * @brief Init the extension.
     *
     * @param record the extension record.
     * @param application the application info.
     * @param handler the extension handler.
     * @param token the remote token.
     */
    void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
        const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
        std::shared_ptr<AppExecFwk::AbilityHandler> &handler, const sptr<IRemoteObject> &token) override;

    /**
     * @brief Called when this extension is started. You must override this function if you want to perform some
     *        initialization operations during extension startup.
     *
     * This function can be called only once in the entire lifecycle of an extension.
     * @param Want Indicates the {@link Want} structure containing startup information about the extension.
     */
    void OnStart(const AAFwk::Want &want) override;

    void StartAuthentication(const AccountSA::AuthenticationRequest &request,
        const std::shared_ptr<AccountSA::AppAccountAuthenticationExtensionCallbackClient> &callbackPtr,
        const std::shared_ptr<JsAuthenticationExtension> &extension);

    sptr<IRemoteObject> OnConnect(const OHOS::AAFwk::Want &want) override;

    NativeValue *CallObjectMethod(const std::string &name, NativeValue *const *argv = nullptr, size_t argc = 0);
private:

    void GetSrcPath(std::string &srcPath);

    JsRuntime &jsRuntime_;
    std::unique_ptr<NativeReference> jsObj_ = nullptr;
    sptr<IRemoteObject> providerRemoteObject_ = nullptr;
    AccountJsKit::ThreadLockInfo lockInfo_;
};

struct JsAppAAuthenticationExtensionParam : public AccountJsKit::CommonAsyncContext {
    JsAppAAuthenticationExtensionParam(){};
    JsAppAAuthenticationExtensionParam(napi_env napiEnv);
    std::shared_ptr<AccountSA::AppAccountAuthenticationExtensionCallbackClient> callback = nullptr;
    AccountSA::AuthenticationRequest request;
    std::shared_ptr<JsAuthenticationExtension> authenticationExtension = nullptr;
    ThreadLockInfo *lockInfo = nullptr;
};
} // namespace AccountJsKit
} // namespace OHOS
#endif // FOUNDATION_ABILITYRUNTIME_OHOS_JS_AUTHENTICATION_EXTENSION_H
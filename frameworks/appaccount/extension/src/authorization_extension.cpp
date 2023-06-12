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

#include "authorization_extension.h"

#include "ability_loader.h"
#include "account_log_wrapper.h"
#include "authorization_extension_context.h"
#include "connection_manager.h"
#include "napi_app_account_authorization_extension.h"
#include "runtime.h"

using namespace OHOS::AccountSA;

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
AuthorizationExtension *AuthorizationExtension::Create(const std::unique_ptr<Runtime> &runtime)
{
    if (runtime == nullptr) {
        return new AuthorizationExtension();
    }
    switch (runtime->GetLanguage()) {
        case Runtime::Language::JS:
            return AccountJsKit::JsAuthorizationExtension::Create(runtime);
        default:
            return new AuthorizationExtension();
    }
}

void AuthorizationExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    ExtensionBase<AuthorizationExtensionContext>::Init(record, application, handler, token);
}

std::shared_ptr<AuthorizationExtensionContext> AuthorizationExtension::CreateAndInitContext(
    const std::shared_ptr<AbilityLocalRecord> &record, const std::shared_ptr<OHOSApplication> &application,
    std::shared_ptr<AbilityHandler> &handler, const sptr<IRemoteObject> &token)
{
    std::shared_ptr<AuthorizationExtensionContext> context =
        ExtensionBase<AuthorizationExtensionContext>::CreateAndInitContext(record, application, handler, token);
    return context;
}
} // namespace AbilityRuntime
} // namespace OHOS
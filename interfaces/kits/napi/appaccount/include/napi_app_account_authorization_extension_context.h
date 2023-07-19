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

#ifndef ABILITY_RUNTIME_JS_AUTHORIZATION_EXTENSION_CONTEXT_H
#define ABILITY_RUNTIME_JS_AUTHORIZATION_EXTENSION_CONTEXT_H

#include <memory>

#include "ability_connect_callback.h"
#include "event_handler.h"
#include "authorization_extension_context.h"
#include "native_engine/native_engine.h"
#include "native_engine/native_value.h"
#include "js_service_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
NativeValue *CreateJsAuthorizationExtensionContext(
    NativeEngine &engine, std::shared_ptr<AuthorizationExtensionContext> context);

class JSAuthorizationExtensionConnection : public AbilityConnectCallback {
public:
    explicit JSAuthorizationExtensionConnection(NativeEngine &engine);
    ~JSAuthorizationExtensionConnection();
    void CallJsFailed(int32_t errorCode);

private:
    NativeEngine &engine_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // ABILITY_RUNTIME_JS_AUTHENTICATION_EXTENSION_CONTEXT_H

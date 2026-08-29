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

#ifndef AUTHORIZATION_PUBLIC_KITS_NAPI_INCLUDE_NAPI_AUTHORIZATION_PUBLIC_MANAGER_H
#define AUTHORIZATION_PUBLIC_KITS_NAPI_INCLUDE_NAPI_AUTHORIZATION_PUBLIC_MANAGER_H

#include "napi/native_api.h"
#include "napi_account_common.h"

namespace OHOS {
namespace AccountJsKit {
struct HasAuthPublicContext : public CommonAsyncContext {
    HasAuthPublicContext() = default;
    HasAuthPublicContext(napi_env napiEnv, bool isThrowable) : CommonAsyncContext(napiEnv, isThrowable) {};
    std::string privilege;
    bool isAuthorized = false;
};

class NapiAuthorizationPublicManager {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value AcquireAuthorization(napi_env env, napi_callback_info cbInfo);
    static napi_value HasAuthorization(napi_env env, napi_callback_info cbInfo);

private:
    static napi_value JsConstructor(napi_env env, napi_callback_info cbInfo);
    static napi_value PrivilegeConstructor(napi_env env);
    static napi_value AuthorizationResultCodeConstructor(napi_env env);
    static napi_value GetAuthorizationManager(napi_env env, napi_callback_info cbInfo);
};
}  // namespace AccountJsKit
}  // namespace OHOS

#endif  // AUTHORIZATION_PUBLIC_KITS_NAPI_INCLUDE_NAPI_AUTHORIZATION_PUBLIC_MANAGER_H

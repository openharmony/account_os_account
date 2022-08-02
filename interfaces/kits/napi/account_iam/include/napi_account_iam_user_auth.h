/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_USER_AUTH_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_USER_AUTH_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AccountJsKit {
class NapiAccountIAMUserAuth {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value JsConstructor(napi_env env, napi_callback_info info);
    static napi_value GetVersion(napi_env env, napi_callback_info info);
    static napi_value GetAvailableStatus(napi_env env, napi_callback_info info);
    static napi_value GetProperty(napi_env env, napi_callback_info info);
    static napi_value SetProperty(napi_env env, napi_callback_info info);
    static napi_value Auth(napi_env env, napi_callback_info info);
    static napi_value AuthUser(napi_env env, napi_callback_info info);
    static napi_value CancelAuth(napi_env env, napi_callback_info info);
};
}  // namespace AccountJsKit
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_USER_AUTH_H
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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_IDENTITY_MANAGER_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_IDENTITY_MANAGER_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AccountJsKit {
class NapiAccountIAMIdentityManager {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value JsConstructor(napi_env env, napi_callback_info info);
    static napi_value OpenSession(napi_env env, napi_callback_info info);
    static napi_value AddCredential(napi_env env, napi_callback_info info);
    static napi_value UpdateCredential(napi_env env, napi_callback_info info);
    static napi_value CloseSession(napi_env env, napi_callback_info info);
    static napi_value Cancel(napi_env env, napi_callback_info info);
    static napi_value DelUser(napi_env env, napi_callback_info info);
    static napi_value DelCred(napi_env env, napi_callback_info info);
    static napi_value GetAuthInfo(napi_env env, napi_callback_info info);
};
}  // namespace AccountJsKit
}  // OHOS
#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_IDENTITY_MANAGER_H
/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "napi_os_account.h"
#ifdef HAS_USER_IDM_PART
#include "authface_userIDM_helper.h"
#endif // HAS_USER_IDM_PART
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#ifdef HAS_PIN_AUTH_PART
#include "pin_auth_helper.h"
#endif // HAS_PIN_AUTH_PART
#ifdef HAS_USER_AUTH_PART
#include "user_auth_helper.h"
#endif // HAS_USER_AUTH_PART

namespace OHOS {
namespace AccountJsKit {
EXTERN_C_START

/*
 * Module export function
 */
static napi_value Init(napi_env env, napi_value exports)
{
    /*
     * Propertise define
     */
    OsAccountInit(env, exports);
#ifdef HAS_PIN_AUTH_PART
    PinAuth::Init(env, exports);
    PinAuth::EnumExport(env, exports);
#endif // HAS_PIN_AUTH_PART
#ifdef HAS_USER_AUTH_PART
    UserIAM::UserAuth::UserAuthInit(env, exports);
    UserIAM::UserAuth::EnumExport(env, exports);
#endif // HAS_USER_AUTH_PART
#ifdef HAS_USER_IDM_PART
    UserIAM::UserIDM::AuthFaceInit(env, exports);
    UserIAM::UserIDM::EnumExport(env, exports);
#endif // HAS_USER_IDM_PART
    return exports;
}
EXTERN_C_END

/*
 * Module define
 */
static napi_module _module = {

    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "account.osAccount",
    .nm_priv = ((void *)0),
    .reserved = {0}

};

/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&_module);
}
}  // namespace AccountJsKit
}  // namespace OHOS
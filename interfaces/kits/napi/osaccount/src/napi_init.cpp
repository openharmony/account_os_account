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
#if defined(HAS_USER_AUTH_PART) && defined(HAS_PIN_AUTH_PART)
#include "napi_account_iam_module.h"
#endif
#include "napi_domain_account_module.h"

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
#if defined(HAS_USER_AUTH_PART) && defined(HAS_PIN_AUTH_PART)
    AccountIAMInit(env, exports);
#endif
    DomainAccountInit(env, exports);
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

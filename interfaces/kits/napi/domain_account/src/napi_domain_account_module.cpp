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

#include "napi_domain_account_module.h"

#include "napi_domain_account_manager.h"
#include "napi_domain_auth_callback.h"

namespace OHOS {
namespace AccountJsKit {
using namespace AccountSA;

napi_value DomainAccountInit(napi_env env, napi_value exports)
{
    NapiDomainAccountManager::Init(env, exports);
    NapiDomainAuthCallback::Init(env, exports);
    return exports;
}
}  // namespace AccountJsKit
}  // namespace OHOS

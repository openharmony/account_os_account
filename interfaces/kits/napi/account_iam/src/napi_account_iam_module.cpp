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

#include "napi_account_iam_module.h"

#include "account_log_wrapper.h"
#if defined(HAS_USER_AUTH_PART) || defined(HAS_PIN_AUTH_PART)
#include "napi_account_iam_constant.h"
#endif
#ifdef HAS_USER_AUTH_PART
#include "napi_account_iam_identity_manager.h"
#include "napi_account_iam_user_auth.h"
#endif
#ifdef HAS_PIN_AUTH_PART
#include "napi_account_iam_pin_auth.h"
#endif
#include "napi_account_iam_inputer_manager.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;

napi_value AccountIAMInit(napi_env env, napi_value exports)
{
#ifdef HAS_PIN_AUTH_PART
    NapiAccountIAMPINAuth::Init(env, exports);
#endif
#ifdef HAS_USER_AUTH_PART
    NapiAccountIAMIdentityManager::Init(env, exports);
    NapiAccountIAMUserAuth::Init(env, exports);
#endif
#if defined(HAS_PIN_AUTH_PART) || defined(HAS_USER_AUTH_PART)
    NapiAccountIAMConstant::Init(env, exports);
#endif
    NapiAccountIAMInputerManager::Init(env, exports);
    return exports;
}
}  // namespace AccountJsKit
}  // namespace OHOS

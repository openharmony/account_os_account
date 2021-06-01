/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef NAPI_DISTRIBUTED_ACCOUNT_H
#define NAPI_DISTRIBUTED_ACCOUNT_H

#include "napi/native_api.h"

namespace OHOS {
namespace AccountJsKit {
class NapiDistributedAccount {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value GetDistributedAccountAbility(napi_env env, napi_callback_info cbInfo);
    static napi_value QueryOhosAccountInfo(napi_env env, napi_callback_info cbInfo);
    static napi_value UpdateOsAccountDistributedInfo(napi_env env, napi_callback_info cbInfo);
    static napi_value JsConstructor(napi_env env, napi_callback_info cbinfo);

    static napi_ref constructorRef_;
};
} // namespace AccountJsKit
} // namespace OHOS

#endif // NAPI_DISTRIBUTED_ACCOUNT_H

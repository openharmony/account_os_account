/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_DISTRIBUTEDACCOUNT_INCLUDE_NAPI_DISTRIBUTED_ACCOUNT_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_DISTRIBUTEDACCOUNT_INCLUDE_NAPI_DISTRIBUTED_ACCOUNT_H

#include <string>
#include "account_info.h"
#include "napi/native_api.h"

namespace OHOS {
namespace AccountJsKit {
struct DistributedAccountAsyncContext {
    DistributedAccountAsyncContext(napi_env napiEnv);
    ~DistributedAccountAsyncContext();
    napi_env env = nullptr;
    napi_async_work work = nullptr;

    bool throwErr = false;
    bool withLocalId = false;
    int32_t errCode = 0;
    int32_t localId = -1;  // invalid local id

    std::string event;
    AccountSA::OhosAccountInfo ohosAccountInfo;

    napi_deferred deferred = nullptr;
    napi_ref callbackRef = nullptr;
    napi_status status = napi_generic_failure;
};

class NapiDistributedAccount {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value GetDistributedAccountAbility(napi_env env, napi_callback_info cbInfo);

    static napi_value QueryOsAccountDistributedInfo(napi_env env, napi_callback_info cbInfo);
    static napi_value GetOsAccountDistributedInfo(napi_env env, napi_callback_info cbInfo);
    static napi_value QueryOhosAccountInfo(napi_env env, napi_callback_info cbInfo, bool throwErr);

    static napi_value UpdateOsAccountDistributedInfo(napi_env env, napi_callback_info cbInfo);
    static napi_value SetOsAccountDistributedInfo(napi_env env, napi_callback_info cbInfo);
    static napi_value SetOhosAccountInfo(napi_env env, DistributedAccountAsyncContext *asyncContext);
    static napi_value SetOsAccountDistributedInfoByLocalId(napi_env env, napi_callback_info cbInfo);
    static napi_value UpdateOhosAccountInfo(napi_env env, napi_callback_info cbInfo, bool throwErr);
    static napi_value SetCurrentOsAccountDistributedInfo(napi_env env, napi_callback_info cbInfo);

    static napi_value JsConstructor(napi_env env, napi_callback_info cbinfo);
};
} // namespace AccountJsKit
} // namespace OHOS

#endif // OS_ACCOUNT_INTERFACES_KITS_NAPI_DISTRIBUTEDACCOUNT_INCLUDE_NAPI_DISTRIBUTED_ACCOUNT_H

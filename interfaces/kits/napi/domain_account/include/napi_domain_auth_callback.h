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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_DOMAIN_AUTH_CALLBACK_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_DOMAIN_AUTH_CALLBACK_H

#include "domain_account_common.h"
#include "domain_auth_callback.h"
#include "napi/native_api.h"

namespace OHOS {
namespace AccountJsKit {
class NapiDomainAuthCallback {
public:
    explicit NapiDomainAuthCallback(const std::shared_ptr<AccountSA::DomainAuthCallback> &callback);
    ~NapiDomainAuthCallback();
    std::shared_ptr<AccountSA::DomainAuthCallback> GetDomainAuthCallback();
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value JsOnResult(napi_env env, napi_callback_info cbinfo);
    static napi_value JsConstructor(napi_env env, napi_callback_info cbinfo);
private:
    std::shared_ptr<AccountSA::DomainAuthCallback> callback_;
};

struct CallbackParam {
    CallbackParam(napi_env napiEnv);
    ~CallbackParam();
    napi_env env;
    napi_async_work work = nullptr;
    std::shared_ptr<AccountSA::DomainAuthCallback> callback = nullptr;
    int32_t resultCode = 0;
    AccountSA::DomainAuthResult authResult;
};
}  // namespace AccountJsKit
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_DOMAIN_AUTH_CALLBACK_H

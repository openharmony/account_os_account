/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_DOMAIN_ACCOUNT_INCLUDE_NAPI_DOMAIN_SERVER_MANAGER_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_DOMAIN_ACCOUNT_INCLUDE_NAPI_DOMAIN_SERVER_MANAGER_H

#include "domain_account_common.h"
#include "napi/native_api.h"
#include "napi_account_common.h"

namespace OHOS {
namespace AccountJsKit {
struct AddServerConfigAsyncContext : public CommonAsyncContext {
    AddServerConfigAsyncContext(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    AccountSA::DomainServerConfig domainServerConfig;
    std::string parameters;
};

struct GetAccountServerConfigAsyncContext : public CommonAsyncContext {
    GetAccountServerConfigAsyncContext(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    AccountSA::DomainAccountInfo domainAccountInfo;
    AccountSA::DomainServerConfig domainServerConfig;
};

struct RemoveServerConfigAsyncContext : public CommonAsyncContext {
    RemoveServerConfigAsyncContext(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    std::string configId;
};

class NapiDomainServerConfigManager {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value JsConstructor(napi_env env, napi_callback_info cbInfo);
    static napi_value AddServerConfig(napi_env env, napi_callback_info cbInfo);
    static napi_value RemoveServerConfig(napi_env env, napi_callback_info cbInfo);
    static napi_value GetAccountServerConfig(napi_env env, napi_callback_info cbInfo);
};
}  // namespace AccountJsKit
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_DOMAIN_ACCOUNT_INCLUDE_NAPI_DOMAIN_SERVER_MANAGER_H
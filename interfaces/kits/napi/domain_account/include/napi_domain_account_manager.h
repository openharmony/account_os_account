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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_DOMAIN_ACCOUNT_INCLUDE_NAPI_DOMAIN_ACCOUNT_MANAGER_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_DOMAIN_ACCOUNT_INCLUDE_NAPI_DOMAIN_ACCOUNT_MANAGER_H

#include "domain_account_plugin.h"
#include "domain_auth_callback.h"
#include "napi/native_api.h"
#include "os_account_manager.h"

namespace OHOS {
namespace AccountJsKit {
struct JsDomainPlugin {
    napi_ref auth = nullptr;
};

struct JsDomainPluginParam {
    napi_env env;
    AccountSA::DomainAccountInfo domainAccountInfo;
    std::vector<uint8_t> credential;
    std::shared_ptr<AccountSA::DomainAuthCallback> callback;
    JsDomainPlugin jsPlugin;
};

class NapiDomainAccountPlugin final: public AccountSA::DomainAccountPlugin {
public:
    NapiDomainAccountPlugin(napi_env env, const JsDomainPlugin &jsPlugin);
    void Auth(const AccountSA::DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const std::shared_ptr<AccountSA::DomainAuthCallback> &callback) override;
    int32_t GetAuthProperty(
        const AccountSA::DomainAccountInfo &info, AccountSA::DomainAuthProperty &property) override;

private:
    napi_env env_;
    JsDomainPlugin jsPlugin_;
};

class NapiDomainAccountManager {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value JsConstructor(napi_env env, napi_callback_info info);
    static napi_value RegisterPlugin(napi_env env, napi_callback_info info);
    static napi_value UnregisterPlugin(napi_env env, napi_callback_info info);
};
}  // namespace AccountJsKit
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_DOMAIN_ACCOUNT_INCLUDE_NAPI_DOMAIN_ACCOUNT_MANAGER_H
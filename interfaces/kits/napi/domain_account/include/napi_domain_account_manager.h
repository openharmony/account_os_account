/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "domain_account_callback.h"
#include "domain_account_common.h"
#include "domain_account_plugin.h"
#include "domain_auth_callback.h"
#include "napi/native_api.h"
#include "napi_account_common.h"
#include "os_account_manager.h"

namespace OHOS {
namespace AccountJsKit {
namespace {
const int32_t INVALID_PARAMETER = -1;
}

struct JsDomainPlugin {
    napi_ref auth = nullptr;
    napi_ref authWithPopup = nullptr;
    napi_ref authWithToken = nullptr;
    napi_ref getAuthStatusInfo = nullptr;
    napi_ref getDomainAccountInfo = nullptr;
    napi_ref onAccountBound = nullptr;
    napi_ref onAccountUnbound = nullptr;
};

struct HasDomainAccountAsyncContext : public CommonAsyncContext {
    AccountSA::DomainAccountInfo domainInfo;
    bool isHasDomainAccount = false;
    ThreadLockInfo *lockInfo = nullptr;
};

struct JsDomainPluginParam {
    JsDomainPluginParam(napi_env napiEnv) : env(napiEnv) {}
    napi_env env = nullptr;
    napi_ref func = nullptr;
    napi_async_work work = nullptr;
    AccountSA::DomainAccountInfo domainAccountInfo;
    std::shared_ptr<AccountSA::DomainAuthCallback> authCallback = nullptr;
    std::shared_ptr<AccountSA::DomainAccountCallback> callback = nullptr;
    ThreadLockInfo *lockInfo = nullptr;
    int32_t userId = 0;
    napi_ref callbackRef = nullptr;
    AccountSA::AuthMode authMode;
    std::vector<uint8_t> authData;
    int32_t resultCode = 0;
    int32_t remainingTimes = INVALID_PARAMETER;
    int32_t freezingTime = INVALID_PARAMETER;
};

class NapiDomainAccountPlugin final: public AccountSA::DomainAccountPlugin {
public:
    NapiDomainAccountPlugin(napi_env env, const JsDomainPlugin &jsPlugin);
    ~NapiDomainAccountPlugin();
    void Auth(const AccountSA::DomainAccountInfo &info, const std::vector<uint8_t> &credential,
        const std::shared_ptr<AccountSA::DomainAuthCallback> &callback) override;
    void AuthWithPopup(const AccountSA::DomainAccountInfo &info,
        const std::shared_ptr<AccountSA::DomainAuthCallback> &callback) override;
    void AuthWithToken(const AccountSA::DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const std::shared_ptr<AccountSA::DomainAuthCallback> &callback) override;
    void GetAuthStatusInfo(const AccountSA::DomainAccountInfo &info,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback) override;
    void GetDomainAccountInfo(const std::string &domain, const std::string &accountName,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback) override;
    void OnAccountBound(const AccountSA::DomainAccountInfo &info, const int32_t localId,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback) override;
    void OnAccountUnBound(const AccountSA::DomainAccountInfo &info,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback) override;

private:
    void AuthCommon(AccountSA::AuthMode authMode, const AccountSA::DomainAccountInfo &info,
        const std::vector<uint8_t> &authData, const std::shared_ptr<AccountSA::DomainAuthCallback> &callback);

private:
    napi_env env_;
    JsDomainPlugin jsPlugin_;
    ThreadLockInfo lockInfo_;
};

class NapiHasDomainInfoCallback final : public AccountSA::DomainAccountCallback {
public:
    NapiHasDomainInfoCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred);
    ~NapiHasDomainInfoCallback();
    void OnResult(const int32_t errCode, Parcel &parcel) override;

private:
    AccountJsKit::ThreadLockInfo lockInfo_;
    napi_env env_;
    napi_ref callbackRef_ = nullptr;
    napi_deferred deferred_ = nullptr;
};

class NapiDomainAccountManager {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value JsConstructor(napi_env env, napi_callback_info cbInfo);
    static napi_value RegisterPlugin(napi_env env, napi_callback_info cbInfo);
    static napi_value UnregisterPlugin(napi_env env, napi_callback_info cbInfo);
    static napi_value Auth(napi_env env, napi_callback_info cbInfo);
    static napi_value AuthWithPopup(napi_env env, napi_callback_info cbInfo);
    static napi_value HasDomainAccount(napi_env env, napi_callback_info cbInfo);
};
}  // namespace AccountJsKit
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_DOMAIN_ACCOUNT_INCLUDE_NAPI_DOMAIN_ACCOUNT_MANAGER_H
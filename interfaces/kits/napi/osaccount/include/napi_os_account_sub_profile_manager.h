/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_OSACCOUNT_INCLUDE_NAPI_OS_ACCOUNT_SUB_PROFILE_MANAGER_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_OSACCOUNT_INCLUDE_NAPI_OS_ACCOUNT_SUB_PROFILE_MANAGER_H

#include <set>
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "distributed_account_subscribe_callback.h"
#include "napi_account_common.h"

namespace OHOS {
namespace AccountJsKit {

class SubspaceSubscriber final : public AccountSA::DistributedAccountSubscribeCallback,
                            public std::enable_shared_from_this<SubspaceSubscriber> {
public:
    explicit SubspaceSubscriber(napi_env &env, napi_ref &ref);
    ~SubspaceSubscriber();
    void OnSpaceAccountsChanged(const AccountSA::DistributedAccountSubProfileEventData &eventData) override;
    std::shared_ptr<NapiCallbackRef> callback = nullptr;
    napi_env env = nullptr;
};

struct SubspaceEventWorker : public CommonAsyncContext {
    AccountSA::DistributedAccountSubProfileEventData eventData;
    std::shared_ptr<NapiCallbackRef> callback = nullptr;
    std::shared_ptr<SubspaceSubscriber> subscriber = nullptr;
};

class NapiOsAccountSubProfileManager {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value JsConstructor(napi_env env, napi_callback_info cbInfo);
    static napi_value GetOsAccountSubProfileManager(napi_env env, napi_callback_info cbInfo);
    static napi_value CreateOsAccountSubProfile(napi_env env, napi_callback_info cbInfo);
    static napi_value DeleteOsAccountSubProfile(napi_env env, napi_callback_info cbInfo);
    static napi_value SwitchOsAccountSubProfile(napi_env env, napi_callback_info cbInfo);
    static napi_value onOsAccountSubProfileEvent(napi_env env, napi_callback_info cbInfo);
    static napi_value offOsAccountSubProfileEvent(napi_env env, napi_callback_info cbInfo);
    static napi_value GetOsAccountForegroundSubProfileId(napi_env env, napi_callback_info cbInfo);
    static napi_value GetOsAccountSubProfileIds(napi_env env, napi_callback_info cbInfo);
    static napi_value GetOsAccountLocalIdForSubProfile(napi_env env, napi_callback_info cbInfo);
    static napi_value GetOsAccountSubProfile(napi_env env, napi_callback_info cbInfo);
};

}  // namespace AccountJsKit
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_OSACCOUNT_INCLUDE_NAPI_OS_ACCOUNT_SUB_PROFILE_MANAGER_H

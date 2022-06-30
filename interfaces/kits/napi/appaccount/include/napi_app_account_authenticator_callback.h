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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_APP_ACCOUNT_AUTHENTICATOR_CALLBACK_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_APP_ACCOUNT_AUTHENTICATOR_CALLBACK_H

#include "iapp_account_authenticator_callback.h"
#include "iremote_proxy.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AccountJsKit {
class NapiAppAccountAuthenticatorCallback {
public:
    explicit NapiAppAccountAuthenticatorCallback(const sptr<IRemoteObject> &object);
    ~NapiAppAccountAuthenticatorCallback();
    sptr<IRemoteObject> GetRemoteObject();
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value JsOnResult(napi_env env, napi_callback_info cbinfo);
    static napi_value JsOnRequestRedirected(napi_env env, napi_callback_info cbinfo);
    static napi_value JsOnRequestContinued(napi_env env, napi_callback_info cbinfo);
    static napi_value JsConstructor(napi_env env, napi_callback_info cbinfo);
private:
    sptr<IRemoteObject> object_;
};

struct CallbackParam {
    napi_env env;
    napi_async_work work;
    int32_t resultCode;
    AAFwk::WantParams result;
    AAFwk::Want request;
    napi_ref callbackRef;
    NapiAppAccountAuthenticatorCallback *callback;
};
}  // namespace AccountJsKit
}  // namespace OHOS

#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_APP_ACCOUNT_AUTHENTICATOR_CALLBACK_H

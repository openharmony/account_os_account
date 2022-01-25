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

#ifndef NAPI_APP_ACCOUNT_ACCOUNT_AUTHENTICATOR_STUB_H
#define NAPI_APP_ACCOUNT_ACCOUNT_AUTHENTICATOR_STUB_H

#include <mutex>
#include "app_account_authenticator_stub.h"
#include "iapp_account_authenticator_callback.h"
#include "iremote_object.h"
#include "napi/native_api.h"
#include "napi_app_account_common.h"
#include "refbase.h"

namespace OHOS {
namespace AccountJsKit {
struct AuthParam {
    napi_env env;
    napi_ref addAccountImplicitlyRef;
    napi_ref authenticateRef;
    std::string funcName;
    std::string name;
    std::string authType;
    std::string callerBundleName;
    AAFwk::WantParams options;
    sptr<IRemoteObject> remote;
    ThreadLockInfo *lockInfo;
    IAppAccountAuthenticator *authenticatorPtr;
};

class NapiAppAccountAuthenticator : public AccountSA::AppAccountAuthenticatorStub {
public:
    NapiAppAccountAuthenticator(const napi_env &env,
        const napi_ref &addAccountImplicitlyRef, const napi_ref &authenticateRef);
    virtual ~NapiAppAccountAuthenticator() override;
    bool CheckObjectLegality() const override;
    int GetObjectType() const override;
    static napi_value Init(napi_env env, napi_value exports);
    virtual ErrCode AddAccountImplicitly(const std::string &authType, const std::string &callerBundleName,
        const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback) override;
    virtual ErrCode Authenticate(
        const std::string &name, const std::string &authType, const std::string &callerBundleName,
        const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback) override;

private:
    void CallJsFunction(AuthParam *param);
    static napi_value JsConstructor(napi_env env, napi_callback_info cbinfo);
private:
    napi_env env_ = nullptr;
    napi_ref addAccountImplicitlyRef_ = nullptr;
    napi_ref authenticateRef_ = nullptr;
};
}  // namespace AccountJsKit
}  // namespace OHOS

#endif  // NAPI_APP_ACCOUNT_ACCOUNT_AUTHENTICATOR_H
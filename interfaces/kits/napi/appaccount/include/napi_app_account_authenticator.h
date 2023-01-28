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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_APP_ACCOUNT_AUTHENTICATOR_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_APP_ACCOUNT_AUTHENTICATOR_H

#include <mutex>
#include <uv.h>

#include "account_error_no.h"
#include "app_account_authenticator_stub.h"
#include "iapp_account_authenticator_callback.h"
#include "iremote_object.h"
#include "napi/native_api.h"
#include "napi_app_account_common.h"
#include "refbase.h"

namespace OHOS {
namespace AccountJsKit {
struct JsAuthenticator {
    napi_ref addAccountImplicitly = nullptr;
    napi_ref authenticate = nullptr;
    napi_ref verifyCredential = nullptr;
    napi_ref checkAccountLabels = nullptr;
    napi_ref setProperties = nullptr;
    napi_ref isAccountRemovable = nullptr;
    napi_ref createAccountImplicitly = nullptr;
    napi_ref auth = nullptr;
};

struct JsAuthenticatorParam {
    napi_env env;
    JsAuthenticator jsAuthenticator;
    std::string name;
    std::string authType;
    std::string callerBundleName;
    AAFwk::WantParams options;
    std::vector<std::string> labels;
    VerifyCredentialOptions verifyCredOptions;
    SetPropertiesOptions setPropOptions;
    CreateAccountImplicitlyOptions createOptions;
    sptr<IRemoteObject> callback;
};

class NapiAppAccountAuthenticator : public AccountSA::AppAccountAuthenticatorStub {
public:
    NapiAppAccountAuthenticator(napi_env env, JsAuthenticator &jsAuthenticator);
    ~NapiAppAccountAuthenticator() override;
    bool CheckObjectLegality() const override;
    int GetObjectType() const override;
    static napi_value Init(napi_env env, napi_value exports);
    ErrCode AddAccountImplicitly(const std::string &authType, const std::string &callerBundleName,
        const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback) override;
    ErrCode Authenticate(
        const std::string &name, const std::string &authType, const std::string &callerBundleName,
        const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback) override;
    ErrCode CreateAccountImplicitly(
        const CreateAccountImplicitlyOptions &options, const sptr<IRemoteObject> &callback) override;
    ErrCode Auth(
        const std::string &name, const std::string &authType, const AAFwk::WantParams &options,
        const sptr<IRemoteObject> &callback) override;
    ErrCode VerifyCredential(
        const std::string &name, const VerifyCredentialOptions &options, const sptr<IRemoteObject> &callback) override;
    ErrCode CheckAccountLabels(
        const std::string &name, const std::vector<std::string> &labels, const sptr<IRemoteObject> &callback) override;
    ErrCode SetProperties(const SetPropertiesOptions &options, const sptr<IRemoteObject> &callback) override;
    ErrCode IsAccountRemovable(const std::string &name, const sptr<IRemoteObject> &callback) override;
    ErrCode InitWorkEnv(uv_loop_s **loop, uv_work_t **work, JsAuthenticatorParam **param);
    napi_value GetJsRemoteObject();
    void SetJsRemoteObject(napi_value remoteObject);

private:
    static napi_value JsConstructor(napi_env env, napi_callback_info cbinfo);
    static napi_value GetRemoteObject(napi_env env, napi_callback_info cbInfo);
    static napi_value CreateAuthenticatorCallback(napi_env env, sptr<IRemoteObject> nativeCallback);
    static napi_status GetNamedFunction(napi_env env, napi_value value, const std::string &name, napi_ref *result);
    static void CallJsFunction(napi_env env, napi_ref funcRef, napi_value *argv, size_t argc);
    static void CreateJsVerifyCredentialOptions(napi_env env, VerifyCredentialOptions &options, napi_value *jsOptions);
    static void CreateJsSetPropertiesOptions(napi_env env, SetPropertiesOptions &options, napi_value *jsOptions);
    static void AddAccountImplicitlyWork(uv_work_t *work, int status);
    static void AuthenticateWork(uv_work_t *work, int status);
    static void VerifyCredentialWork(uv_work_t *work, int status);
    static void CheckAccountLabelsWork(uv_work_t *work, int status);
    static void SetPropertiesWork(uv_work_t *work, int status);
    static void IsAccountRemovableWork(uv_work_t *work, int status);
    static void CreateAccountImplicitlyWork(uv_work_t *work, int status);
    static void AuthWork(uv_work_t *work, int status);

private:
    napi_env env_ = nullptr;
    JsAuthenticator jsAuthenticator_;
    napi_value remoteObject_ = nullptr;
};
}  // namespace AccountJsKit
}  // namespace OHOS

#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_APP_ACCOUNT_AUTHENTICATOR_H
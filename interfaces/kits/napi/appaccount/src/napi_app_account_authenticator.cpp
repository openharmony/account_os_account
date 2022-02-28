/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "napi_app_account_authenticator.h"

#include <uv.h>

#include "account_log_wrapper.h"
#include "app_account_constants.h"
#include "iapp_account_authenticator_callback.h"
#include "ipc_object_stub.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_app_account_authenticator_callback.h"
#include "napi_app_account_common.h"
#include "napi_common.h"
#include "napi_remote_object.h"

using namespace OHOS::AccountSA;
namespace OHOS {
namespace AccountJsKit {
NapiAppAccountAuthenticator::NapiAppAccountAuthenticator(const napi_env &env,
    const napi_ref &addAccountImplicitlyRef, const napi_ref &authenticateRef)
{
    ACCOUNT_LOGI("Enter");
    env_ = env;
    addAccountImplicitlyRef_ = addAccountImplicitlyRef;
    authenticateRef_ = authenticateRef;
}

NapiAppAccountAuthenticator::~NapiAppAccountAuthenticator()
{
    ACCOUNT_LOGI("Enter");
    if (addAccountImplicitlyRef_ != nullptr) {
        napi_status status = napi_delete_reference(env_, addAccountImplicitlyRef_);
        NAPI_ASSERT_RETURN_VOID(env_, status == napi_ok, "failed to delete addAccountImplicitlyRef to js RemoteObject");
        addAccountImplicitlyRef_ = nullptr;
    }
    if (authenticateRef_ != nullptr) {
        napi_status status = napi_delete_reference(env_, authenticateRef_);
        NAPI_ASSERT_RETURN_VOID(env_, status == napi_ok, "failed to delete authenticateRef_ to js RemoteObject");
        authenticateRef_ = nullptr;
    }
}

bool NapiAppAccountAuthenticator::CheckObjectLegality() const
{
    return true;
}

int NapiAppAccountAuthenticator::GetObjectType() const
{
    return OBJECT_TYPE_JAVASCRIPT;
}

ErrCode NapiAppAccountAuthenticator::AddAccountImplicitly(
    const std::string &authType, const std::string &callerBundleName,
    const AAFwk::WantParams &options, const sptr<IRemoteObject> &remoteObject)
{
    ACCOUNT_LOGI("Enter");
    std::shared_ptr<struct ThreadLockInfo> lockInfo = std::make_shared<struct ThreadLockInfo>();
    AuthParam *authParam = new (std::nothrow) AuthParam {
        .env = env_,
        .addAccountImplicitlyRef = addAccountImplicitlyRef_,
        .authenticateRef = nullptr,
        .funcName = Constants::OAUTH_ACTION_ADD_ACCOUNT_IMPLICITLY,
        .authType = authType,
        .callerBundleName = callerBundleName,
        .options = options,
        .remote = remoteObject,
        .lockInfo = lockInfo.get(),
    };
    ErrCode result = CallJsFunction(authParam);
    delete authParam;
    return result;
}

ErrCode NapiAppAccountAuthenticator::Authenticate(const std::string &name, const std::string &authType,
    const std::string &callerBundleName, const AAFwk::WantParams &options, const sptr<IRemoteObject> &remoteObject)
{
    ACCOUNT_LOGI("Enter");
    std::shared_ptr<struct ThreadLockInfo> lockInfo = std::make_shared<struct ThreadLockInfo>();
    AuthParam *authParam = new AuthParam {
        .env = env_,
        .addAccountImplicitlyRef = nullptr,
        .authenticateRef = authenticateRef_,
        .funcName = Constants::OAUTH_ACTION_AUTHENTICATE,
        .name = name,
        .authType = authType,
        .callerBundleName = callerBundleName,
        .options = options,
        .remote = remoteObject,
        .lockInfo = lockInfo.get(),
    };
    ErrCode result = CallJsFunction(authParam);
    delete authParam;
    return result;
}

napi_value NapiAppAccountAuthenticator::Init(napi_env env, napi_value exports)
{
    ACCOUNT_LOGI("Enter");
    const std::string className = "Authenticator";
    napi_property_descriptor properties[] = {};
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), className.length(), JsConstructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "define js class Authenticator failed");
    napi_status status = napi_set_named_property(env, exports, className.c_str(), constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property Authenticator to exports failed");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    status = napi_set_named_property(env, global, "AuthenticatorConstructor_", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set stub constructor failed");
    return exports;
}

void NotifyWorkDone(const AuthParam *param)
{
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->ready = true;
    param->lockInfo->condition.notify_all();
}

void UvQueueWorkCallJsFunction(uv_work_t *work, int status)
{
    AuthParam *param = reinterpret_cast<AuthParam *>(work->data);
    napi_value global = nullptr;
    napi_get_global(param->env, &global);
    if (global == nullptr) {
        ACCOUNT_LOGE("failed to get napi global");
        param->errCode = ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
        return NotifyWorkDone(param);
    }
    napi_value jsAuthCallbackConstructor = nullptr;
    napi_get_named_property(param->env, global, "AuthCallbackConstructor_", &jsAuthCallbackConstructor);
    if (jsAuthCallbackConstructor == nullptr) {
        ACCOUNT_LOGE("jsAuthCallbackConstructor is null");
        param->errCode = ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
        return NotifyWorkDone(param);
    }
    napi_value remote;
    napi_create_int64(param->env, reinterpret_cast<int64_t>((IRemoteObject *)param->remote), &remote);
    napi_value argv1[] = { remote };
    napi_value jsAuthCallback = nullptr;
    napi_new_instance(param->env, jsAuthCallbackConstructor, ARGS_SIZE_ONE, argv1, &jsAuthCallback);
    if (jsAuthCallback == nullptr) {
        ACCOUNT_LOGE("failed to create js AuthenticatorCallback");
        param->errCode = ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
        return NotifyWorkDone(param);
    }
    napi_value jsName;
    napi_create_string_utf8(param->env, param->name.c_str(), NAPI_AUTO_LENGTH, &jsName);
    napi_value jsAuthType;
    napi_create_string_utf8(param->env, param->authType.c_str(), NAPI_AUTO_LENGTH, &jsAuthType);
    napi_value jsCallerBundleName;
    napi_create_string_utf8(param->env, param->callerBundleName.c_str(), NAPI_AUTO_LENGTH, &jsCallerBundleName);
    napi_value jsOptions = AppExecFwk::WrapWantParams(param->env, param->options);
    napi_value argv2[] = { jsName, jsAuthType, jsCallerBundleName, jsOptions, jsAuthCallback};
    napi_value undefined = nullptr;
    napi_get_undefined(param->env, &undefined);
    napi_value returnVal;
    napi_status ret = napi_ok;
    napi_value jsFunction = nullptr;
    if (param->funcName == Constants::OAUTH_ACTION_ADD_ACCOUNT_IMPLICITLY) {
        napi_get_reference_value(param->env, param->addAccountImplicitlyRef, &jsFunction);
        ret = napi_call_function(param->env, undefined, jsFunction, ARGS_SIZE_FOUR, &argv2[1], &returnVal);
    } else if (param->funcName == Constants::OAUTH_ACTION_AUTHENTICATE) {
        napi_get_reference_value(param->env, param->authenticateRef, &jsFunction);
        ret = napi_call_function(param->env, undefined, jsFunction, ARGS_SIZE_FIVE, argv2, &returnVal);
    }
    if (ret != napi_ok) {
        ACCOUNT_LOGE("failed to call js function");
        param->errCode = ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    NotifyWorkDone(param);
}

ErrCode NapiAppAccountAuthenticator::CallJsFunction(AuthParam *param)
{
    ACCOUNT_LOGI("Enter");
    if (param == nullptr) {
        ACCOUNT_LOGE("param is nullptr!");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        ACCOUNT_LOGE("failed to new uv_work_t");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    work->data = reinterpret_cast<void *>(param);
    ACCOUNT_LOGI("start nv queue work loop");
    uv_queue_work(loop, work, [](uv_work_t *work) {}, UvQueueWorkCallJsFunction);
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->condition.wait(lock, [&param] { return param->lockInfo->ready; });
    delete work;
    return param->errCode;
}

napi_value NapiAppAccountAuthenticator::JsConstructor(napi_env env, napi_callback_info info)
{
    ACCOUNT_LOGI("Enter");
    napi_value thisVar = nullptr;
    napi_value jsFunc = nullptr;
    napi_ref addAccountImplicitlyRef = nullptr;
    napi_ref authenticateRef = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_get_named_property(env, thisVar, "addAccountImplicitly", &jsFunc);
    napi_create_reference(env, jsFunc, 1, &addAccountImplicitlyRef);
    napi_get_named_property(env, thisVar, "authenticate", &jsFunc);
    napi_create_reference(env, jsFunc, 1, &authenticateRef);
    sptr<NapiAppAccountAuthenticator> authenticator =
        new (std::nothrow) NapiAppAccountAuthenticator(env, addAccountImplicitlyRef, authenticateRef);
    if (authenticator == nullptr) {
        ACCOUNT_LOGE("failed to construct NapiAppAccountAuthenticator");
        return nullptr;
    }
    return NAPI_ohos_rpc_CreateJsRemoteObject(env, authenticator->AsObject());
}
}  // namespace AccountJsKit
}  // namespace OHOS

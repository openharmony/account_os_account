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

#include "napi_domain_auth_callback.h"

#include <uv.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_account_common.h"
#include "napi_account_error.h"

namespace OHOS {
namespace AccountJsKit {
namespace {
const size_t ARGS_SIZE_TWO = 2;
}
using namespace AccountSA;

CallbackParam::CallbackParam(napi_env napiEnv) : env(napiEnv)
{}

CallbackParam::~CallbackParam()
{
    if (env == nullptr) {
        return;
    }
    if (work != nullptr) {
        napi_delete_async_work(env, work);
    }
}

NapiDomainAuthCallback::NapiDomainAuthCallback(const std::shared_ptr<DomainAuthCallback> &callback)
    : callback_(callback)
{}

NapiDomainAuthCallback::~NapiDomainAuthCallback()
{}

std::shared_ptr<DomainAuthCallback> NapiDomainAuthCallback::GetDomainAuthCallback()
{
    return callback_;
}

napi_value NapiDomainAuthCallback::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("onResult", JsOnResult),
    };
    const std::string className = "DomainAuthCallback";
    napi_value constructor = nullptr;
    NAPI_CALL(env, napi_define_class(env, className.c_str(), className.length(), JsConstructor, nullptr,
        sizeof(properties) / sizeof(napi_property_descriptor), properties, &constructor));
    NAPI_ASSERT(env, constructor != nullptr, "define js class DomainAuthCallback failed");
    napi_status status = napi_set_named_property(env, exports, className.c_str(), constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property DomainAuthCallback to exports failed");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    status = napi_set_named_property(env, global, className.c_str(), constructor);
    NAPI_ASSERT(env, status == napi_ok, "set constructor to global failed");
    return exports;
}

static bool ParseDoaminAuthResult(napi_env env, napi_value value, DomainAuthResult &authResult)
{
    bool hasProp = false;
    napi_has_named_property(env, value, "token", &hasProp);
    if (hasProp) {
        napi_value napiToken = nullptr;
        napi_get_named_property(env, value, "token", &napiToken);
        if (ParseUint8TypedArrayToVector(env, napiToken, authResult.token) != napi_ok) {
            ACCOUNT_LOGE("failed to parse token");
            return false;
        }
    }
    hasProp = false;
    napi_has_named_property(env, value, "remainTimes", &hasProp);
    if (hasProp) {
        napi_value napiRemainTimes = nullptr;
        napi_get_named_property(env, value, "remainTimes", &napiRemainTimes);
        if (!GetIntProperty(env, napiRemainTimes, authResult.authStatusInfo.remainingTimes)) {
            ACCOUNT_LOGE("failed to parse remainTimes");
            return false;
        }
    } else {
        authResult.authStatusInfo.remainingTimes = -1;
    }
    hasProp = false;
    napi_has_named_property(env, value, "freezingTime", &hasProp);
    if (hasProp) {
        napi_value napiFreezingTime = nullptr;
        napi_get_named_property(env, value, "freezingTime", &napiFreezingTime);
        if (!GetIntProperty(env, napiFreezingTime, authResult.authStatusInfo.freezingTime)) {
            ACCOUNT_LOGE("failed to parse freezingTime");
            return false;
        }
    } else {
        authResult.authStatusInfo.freezingTime = -1;
    }
    return true;
}

static bool ParseContextForOnResult(napi_env env, napi_callback_info cbInfo, CallbackParam *param)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr);
    if (argc != ARGS_SIZE_TWO) {
        ACCOUNT_LOGE("the number of parameter should be two");
        return false;
    }
    NapiDomainAuthCallback *napiCallback = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCallback));
    if (napiCallback == nullptr) {
        ACCOUNT_LOGE("the napi callback is nullptr");
        return false;
    }
    param->callback = napiCallback->GetDomainAuthCallback();
    NAPI_CALL_BASE(env, napi_get_value_int32(env, argv[0], &(param->resultCode)), false);
    return ParseDoaminAuthResult(env, argv[1], param->authResult);
}

napi_value NapiDomainAuthCallback::JsOnResult(napi_env env, napi_callback_info cbInfo)
{
    auto *param = new (std::nothrow) CallbackParam(env);
    if (param == nullptr) {
        ACCOUNT_LOGE("insufficient memory for param!");
        return nullptr;
    }
    std::unique_ptr<CallbackParam> paramPtr(param);
    if (!ParseContextForOnResult(env, cbInfo, param)) {
        std::string errMsg = "fail to parse onResult parameters";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "JsOnResult", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            if (data == nullptr) {
                ACCOUNT_LOGE("data is nullptr");
                return;
            }
            CallbackParam *param = reinterpret_cast<CallbackParam *>(data);
            if (param->callback == nullptr) {
                ACCOUNT_LOGE("callback is nullptr");
                return;
            }
            param->callback->OnResult(param->resultCode, param->authResult);
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<CallbackParam *>(data);
        },
        reinterpret_cast<void *>(param), &param->work));
    NAPI_CALL(env, napi_queue_async_work(env, param->work));
    paramPtr.release();
    return nullptr;
}

napi_value NapiDomainAuthCallback::JsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "napi get callback info failed");
    return thisVar;
}

NapiDomainAccountCallback::NapiDomainAccountCallback(napi_env env, napi_ref callback)
    : env_(env), callbackRef_(callback)
{}

NapiDomainAccountCallback::~NapiDomainAccountCallback()
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    lockInfo_.condition.wait(lock, [this] { return this->lockInfo_.count == 0; });
    lockInfo_.count--;
    ReleaseNapiRefAsync(env_, callbackRef_);
    callbackRef_ = nullptr;
}

static void DomainAuthResultWork(uv_work_t *work, int status)
{
    if (work == nullptr) {
        ACCOUNT_LOGE("work is nullptr");
        return;
    }
    if (work->data == nullptr) {
        ACCOUNT_LOGE("data is nullptr");
        delete work;
        return;
    }
    CallbackParam *param = reinterpret_cast<CallbackParam *>(work->data);
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_create_int32(param->env, param->resultCode, &argv[0]);
    argv[1] = CreateAuthResult(param->env, param->authResult.token,
        param->authResult.authStatusInfo.remainingTimes, param->authResult.authStatusInfo.freezingTime);
    NapiCallVoidFunction(param->env, argv, ARGS_SIZE_TWO, param->callbackRef);
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->count--;
    param->lockInfo->condition.notify_all();
    delete param;
    delete work;
}

void NapiDomainAccountCallback::OnResult(int32_t resultCode, const AccountSA::DomainAuthResult &result)
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if (lockInfo_.count < 0) {
        ACCOUNT_LOGE("the callback has been released");
        return;
    }
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<CallbackParam> param = std::make_unique<CallbackParam>(env_);
    uv_loop_s *loop = nullptr;
    NAPI_CALL_RETURN_VOID(env_, napi_get_uv_event_loop(env_, &loop));
    if (loop == nullptr || work == nullptr || param == nullptr) {
        ACCOUNT_LOGE("fail for nullptr");
        return;
    }
    param->lockInfo = &lockInfo_;
    param->resultCode = resultCode;
    param->authResult = result;
    param->callbackRef = callbackRef_;
    work->data = reinterpret_cast<void *>(param.get());
    NAPI_CALL_RETURN_VOID(env_, uv_queue_work(loop, work.get(), [] (uv_work_t *work) {}, DomainAuthResultWork));
    work.release();
    param.release();
    lockInfo_.count++;
}
}  // namespace AccountJsKit
}  // namespace OHOS

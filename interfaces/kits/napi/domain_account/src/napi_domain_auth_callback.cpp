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

NapiDomainAuthCallback::NapiDomainAuthCallback(const std::shared_ptr<DomainAccountCallback> &callback)
    : callback_(callback)
{}

NapiDomainAuthCallback::~NapiDomainAuthCallback()
{}

std::shared_ptr<DomainAccountCallback> NapiDomainAuthCallback::GetDomainAuthCallback()
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
    NAPI_CALL_BASE(env, napi_get_value_int32(env, argv[0], &(param->errCode)), false);
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
            Parcel parcel;
            if (!param->authResult.Marshalling(parcel)) {
                ACCOUNT_LOGE("authResult Marshalling failed");
                return;
            }
            param->callback->OnResult(param->errCode, parcel);
        },
        [](napi_env env, napi_status status, void *data) {
            delete reinterpret_cast<CallbackParam *>(data);
        },
        reinterpret_cast<void *>(param), &param->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, param->work, napi_qos_user_initiated));
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

NapiDomainAccountCallback::NapiDomainAccountCallback(napi_env env,
    std::shared_ptr<JsDomainAccountAuthCallback> &callback) : env_(env), callback_(callback)
{}

NapiDomainAccountCallback::~NapiDomainAccountCallback()
{}

static void DomainAuthResultWork(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<DomainAccountAuthCallbackParam> param(
        reinterpret_cast<DomainAccountAuthCallbackParam *>(work->data));
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_create_int32(param->env, param->errCode, &argv[0]);
    argv[1] = CreateAuthResult(param->env, param->authResult.token,
        param->authResult.authStatusInfo.remainingTimes, param->authResult.authStatusInfo.freezingTime);
    NapiCallVoidFunction(param->env, argv, ARGS_SIZE_TWO, param->callback->onResult);
    napi_close_handle_scope(param->env, scope);
}

void NapiDomainAccountCallback::OnResult(const int32_t errCode, Parcel &parcel)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callback_->onResultCalled) {
        ACCOUNT_LOGE("call twice is not allowed");
        return;
    }
    callback_->onResultCalled = true;
    std::unique_ptr<uv_work_t> work = std::make_unique<uv_work_t>();
    std::unique_ptr<DomainAccountAuthCallbackParam> param =
        std::make_unique<DomainAccountAuthCallbackParam>(env_);
    uv_loop_s *loop = nullptr;
    NAPI_CALL_RETURN_VOID(env_, napi_get_uv_event_loop(env_, &loop));
    if (loop == nullptr || work == nullptr || param == nullptr) {
        ACCOUNT_LOGE("fail for nullptr");
        return;
    }
    param->errCode = errCode;
    std::shared_ptr<DomainAuthResult> authResult(DomainAuthResult::Unmarshalling(parcel));
    if (authResult == nullptr) {
        ACCOUNT_LOGE("authResult is nullptr");
        return;
    }
    param->authResult = (*authResult);
    param->callback = callback_;
    work->data = reinterpret_cast<void *>(param.get());
    ErrCode ret = uv_queue_work_with_qos(
        loop, work.get(), [] (uv_work_t *work) {}, DomainAuthResultWork, uv_qos_user_initiated);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("fail to queue work");
        return;
    }
    work.release();
    param.release();
}
}  // namespace AccountJsKit
}  // namespace OHOS

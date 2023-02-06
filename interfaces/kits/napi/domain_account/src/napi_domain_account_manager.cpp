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

#include "napi_domain_account_manager.h"

#include <uv.h>
#include "account_log_wrapper.h"
#include "domain_account_client.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_account_common.h"
#include "napi_account_error.h"
#include "napi_domain_auth_callback.h"

namespace OHOS {
namespace AccountJsKit {
namespace {
const size_t ARG_SIZE_THREE = 3;
}
using namespace OHOS::AccountSA;

static napi_value CreateNapiDomainAccountInfo(napi_env env, const DomainAccountInfo &domainAccountInfo)
{
    napi_value napiInfo = nullptr;
    napi_create_object(env, &napiInfo);
    napi_value napiName = nullptr;
    napi_create_string_utf8(env, domainAccountInfo.accountName_.c_str(), NAPI_AUTO_LENGTH, &napiName);
    napi_set_named_property(env, napiInfo, "accountName", napiName);
    napi_value napiDomain = nullptr;
    napi_create_string_utf8(env, domainAccountInfo.domain_.c_str(), NAPI_AUTO_LENGTH, &napiDomain);
    napi_set_named_property(env, napiInfo, "domain", napiDomain);
    return napiInfo;
}

static napi_value CreateNapiDomainAuthCallback(
    napi_env env, const std::shared_ptr<DomainAuthCallback> &nativeCallback)
{
    napi_value napiCallback = nullptr;
    napi_value global = nullptr;
    napi_get_global(env, &global);
    if (global == nullptr) {
        ACCOUNT_LOGE("failed to get napi global");
        return napiCallback;
    }
    napi_value jsConstructor = nullptr;
    napi_get_named_property(env, global, "DomainAuthCallback", &jsConstructor);
    if (jsConstructor == nullptr) {
        ACCOUNT_LOGE("jsConstructor is nullptr");
        return napiCallback;
    }
    napi_new_instance(env, jsConstructor, 0, nullptr, &napiCallback);
    auto domainAuthCallback = new (std::nothrow) NapiDomainAuthCallback(nativeCallback);
    if (domainAuthCallback == nullptr) {
        ACCOUNT_LOGE("failed to create NapiDomainAuthCallback");
        return nullptr;
    }
    napi_status status = napi_wrap(
        env, napiCallback, domainAuthCallback,
        [](napi_env env, void *data, void *hint) {
            delete (reinterpret_cast<NapiDomainAuthCallback *>(data));
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        ACCOUNT_LOGE("wrap js DomainAuthCallback and native callback failed");
        delete domainAuthCallback;
        return nullptr;
    }
    return napiCallback;
}

static void AuthWork(uv_work_t *work, int status)
{
    if (work == nullptr || work->data == nullptr) {
        ACCOUNT_LOGE("invalid parameter, work or data is nullptr");
        return;
    }
    JsDomainPluginParam *param = reinterpret_cast<JsDomainPluginParam *>(work->data);
    napi_value napiDomainAccountInfo = CreateNapiDomainAccountInfo(param->env, param->domainAccountInfo);
    napi_value napiCredential = CreateUint8Array(param->env, param->credential.data(), param->credential.size());
    napi_value napiCallback = CreateNapiDomainAuthCallback(param->env, param->callback);
    napi_value argv[] = { napiDomainAccountInfo, napiCredential, napiCallback};
    napi_value undefined = nullptr;
    napi_get_undefined(param->env, &undefined);
    napi_value returnVal;
    napi_value funcRef = nullptr;
    napi_get_reference_value(param->env, param->jsPlugin.auth, &funcRef);
    if (funcRef == nullptr) {
        ACCOUNT_LOGE("funcRef is nullptr");
    }
    napi_call_function(param->env, undefined, funcRef, ARG_SIZE_THREE, argv, &returnVal);
}

NapiDomainAccountPlugin::NapiDomainAccountPlugin(napi_env env, const JsDomainPlugin &jsPlugin)
    : env_(env), jsPlugin_(jsPlugin)
{}

void NapiDomainAccountPlugin::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const std::shared_ptr<DomainAuthCallback> &callback)
{
    if (jsPlugin_.auth == nullptr) {
        return;
    }
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        ACCOUNT_LOGE("failed to get uv event loop");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        ACCOUNT_LOGE("failed to create uv_work_t");
        return;
    }
    JsDomainPluginParam *param = new (std::nothrow) JsDomainPluginParam();
    if (param == nullptr) {
        ACCOUNT_LOGE("failed to create JsDomainPluginParam");
        delete work;
        return;
    }
    param->env = env_;
    param->domainAccountInfo = info;
    param->credential = password;
    param->callback = callback;
    param->jsPlugin = jsPlugin_;
    work->data = reinterpret_cast<void *>(param);
    int errCode = uv_queue_work(loop, work, [](uv_work_t *work) {}, AuthWork);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        delete work;
        delete param;
    }
}

int32_t NapiDomainAccountPlugin::GetAuthProperty(const DomainAccountInfo &info, DomainAuthProperty &property)
{
    return 0;
}

napi_value NapiDomainAccountManager::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_STATIC_FUNCTION("registerPlugin", RegisterPlugin),
        DECLARE_NAPI_STATIC_FUNCTION("unregisterPlugin", UnregisterPlugin),
        DECLARE_NAPI_FUNCTION("registerPlugin", RegisterPlugin),
        DECLARE_NAPI_FUNCTION("unregisterPlugin", UnregisterPlugin)
    };
    std::string className = "DomainAccountManager";
    napi_value constructor = nullptr;
    NAPI_CALL(env, napi_define_class(env, className.c_str(), className.length(), JsConstructor,
        nullptr, sizeof(properties) / sizeof(napi_property_descriptor), properties, &constructor));
    NAPI_ASSERT(env, constructor != nullptr, "define js class DomainAccountManager failed");
    napi_status status = napi_set_named_property(env, exports, className.c_str(), constructor);
    NAPI_ASSERT(env, status == napi_ok, "set constructor to exports failed");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    status = napi_set_named_property(env, global, className.c_str(), constructor);
    NAPI_ASSERT(env, status == napi_ok, "set constructor to global failed");
    return exports;
}

napi_value NapiDomainAccountManager::JsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

static bool ParseContextForRegisterPlugin(napi_env env, napi_callback_info info, JsDomainPlugin &jsPlugin)
{
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != 1) {
        ACCOUNT_LOGE("The number of parameter must be one, but got %{public}zu", argc);
        std::string errMsg = "The number of parameter must be one";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    bool hasAuth = false;
    napi_has_named_property(env, argv[0], "auth", &hasAuth);
    if (!hasAuth) {
        ACCOUNT_LOGE("failed to parse auth funciton");
        return false;
    }
    napi_value authFunc = nullptr;
    napi_get_named_property(env, argv[0], "auth", &authFunc);
    return GetCallbackProperty(env, authFunc, jsPlugin.auth, 1);
}

napi_value NapiDomainAccountManager::RegisterPlugin(napi_env env, napi_callback_info info)
{
    JsDomainPlugin jsPlugin;
    if (!ParseContextForRegisterPlugin(env, info, jsPlugin)) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, "failed to parse parameters", true);
        return nullptr;
    }
    auto plugin = std::make_shared<NapiDomainAccountPlugin>(env, jsPlugin);
    int32_t errCode = DomainAccountClient::GetInstance().RegisterPlugin(plugin);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to register plugin, errCode=%{public}d", errCode);
        AccountNapiThrow(env, errCode, true);
    }
    return nullptr;
}

napi_value NapiDomainAccountManager::UnregisterPlugin(napi_env env, napi_callback_info info)
{
    int32_t errCode = DomainAccountClient::GetInstance().UnregisterPlugin();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to unregister plugin, errCode=%{public}d", errCode);
        AccountNapiThrow(env, errCode, true);
    }
    return nullptr;
}
}  // namespace AccountJsKit
}  // namespace OHOS

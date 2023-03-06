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
const size_t ARG_SIZE_ONE = 1;
const size_t ARG_SIZE_TWO = 2;
const size_t ARG_SIZE_THREE = 3;
}

using namespace OHOS::AccountSA;

static bool InitDomainPluginExecEnv(napi_env env, uv_loop_s **loop, uv_work_t **work, JsDomainPluginParam **param)
{
    *loop = nullptr;
    napi_get_uv_event_loop(env, loop);
    if (*loop == nullptr) {
        ACCOUNT_LOGE("failed to get uv event loop");
        return false;
    }
    *work = new (std::nothrow) uv_work_t;
    if (*work == nullptr) {
        ACCOUNT_LOGE("failed to create uv_work_t");
        return false;
    }
    *param = new (std::nothrow) JsDomainPluginParam(env);
    if (*param == nullptr) {
        ACCOUNT_LOGE("failed to create JsDomainPluginParam");
        delete *work;
        *work = nullptr;
        return false;
    }
    return true;
}

static napi_value CreatePluginAsyncCallback(napi_env env, napi_callback callback, JsDomainPluginParam *param)
{
    napi_value napiCallback = nullptr;
    napi_status status = napi_create_function(env, "callback", NAPI_AUTO_LENGTH, callback, param, &napiCallback);
    if (status != napi_ok) {
        ACCOUNT_LOGE("failed to create js function");
        return nullptr;
    }
    status = napi_wrap(env, napiCallback, param,
        [](napi_env env, void *data, void *hint) {
            ACCOUNT_LOGI("release JsDomainPluginParam");
            delete reinterpret_cast<JsDomainPluginParam *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        ACCOUNT_LOGE("failed to wrap callback with JsDomainPluginParam");
        return nullptr;
    }
    return napiCallback;
}

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
    napi_status status = napi_wrap(env, napiCallback, domainAuthCallback,
        [](napi_env env, void *data, void *hint) {
            delete (reinterpret_cast<NapiDomainAuthCallback *>(data));
        }, nullptr, nullptr);
    if (status != napi_ok) {
        ACCOUNT_LOGE("wrap js DomainAuthCallback and native callback failed");
        delete domainAuthCallback;
        return nullptr;
    }
    return napiCallback;
}

static bool ParseAuthStatusInfo(napi_env env, napi_value value, AuthStatusInfo &info)
{
    napi_value napiRemainTimes = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "remainTimes", &napiRemainTimes), false);
    if (napiRemainTimes == nullptr) {
        ACCOUNT_LOGE("remainTimes is undefined");
        return false;
    }
    NAPI_CALL_BASE(env, napi_get_value_int32(env, napiRemainTimes, &info.remainingTimes), false);
    napi_value napiFreezingTime = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "freezingTime", &napiFreezingTime), false);
    if (napiFreezingTime == nullptr) {
        ACCOUNT_LOGE("freezingTime is undefined");
        return false;
    }
    NAPI_CALL_BASE(env, napi_get_value_int32(env, napiFreezingTime, &info.freezingTime), false);
    return true;
}

static napi_value GetAuthStatusInfoCallback(napi_env env, napi_callback_info cbInfo)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {nullptr};
    void* data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, &data));
    if (argc != ARG_SIZE_TWO) {
        ACCOUNT_LOGE("the number of argument should be 2");
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, true);
        return nullptr;
    }
    JsDomainPluginParam *param = reinterpret_cast<JsDomainPluginParam *>(data);
    if ((param == nullptr) || (param->callback == nullptr)) {
        ACCOUNT_LOGE("native callback is nullptr");
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    BusinessError error;
    if (!ParseBusinessError(env, argv[0], error)) {
        ACCOUNT_LOGE("failed to parse BusinessError");
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, true);
        return nullptr;
    }
    AuthStatusInfo info;
    if (!ParseAuthStatusInfo(env, argv[1], info)) {
        ACCOUNT_LOGE("failed to parse AuthStatusInfo");
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, true);
        return nullptr;
    }
    Parcel parcel;
    if (!info.Marshalling(parcel)) {
        ACCOUNT_LOGE("fail to marshalling AuthStatusInfo");
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    param->callback->OnResult(error.code, parcel);
    return nullptr;
}

static void GetAuthStatusInfoWork(uv_work_t *work, int status)
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
    JsDomainPluginParam *param = reinterpret_cast<JsDomainPluginParam *>(work->data);
    napi_value napiDomainAccountInfo = CreateNapiDomainAccountInfo(param->env, param->domainAccountInfo);
    napi_value napiCallback = CreatePluginAsyncCallback(param->env, GetAuthStatusInfoCallback, param);
    napi_value argv[] = {napiDomainAccountInfo, napiCallback};
    NapiCallVoidFunction(param->env, argv, ARG_SIZE_TWO, param->func);
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->count--;
    param->lockInfo->condition.notify_all();
    if (napiCallback == nullptr) {
        delete param;
    }
    delete work;
}

NapiDomainAccountPlugin::NapiDomainAccountPlugin(napi_env env, const JsDomainPlugin &jsPlugin)
    : env_(env), jsPlugin_(jsPlugin)
{}

NapiDomainAccountPlugin::~NapiDomainAccountPlugin()
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    lockInfo_.condition.wait(lock, [this] { return this->lockInfo_.count == 0; });
    lockInfo_.count--;
    if (env_ == nullptr) {
        return;
    }
    if (jsPlugin_.auth != nullptr) {
        napi_delete_reference(env_, jsPlugin_.auth);
        jsPlugin_.auth = nullptr;
    }
    if (jsPlugin_.authWithPopup != nullptr) {
        napi_delete_reference(env_, jsPlugin_.authWithPopup);
        jsPlugin_.authWithPopup = nullptr;
    }
    if (jsPlugin_.authWithToken != nullptr) {
        napi_delete_reference(env_, jsPlugin_.authWithToken);
        jsPlugin_.authWithToken = nullptr;
    }
    if (jsPlugin_.getAuthStatusInfo != nullptr) {
        napi_delete_reference(env_, jsPlugin_.getAuthStatusInfo);
        jsPlugin_.getAuthStatusInfo = nullptr;
    }
}

static void AuthCommonWork(uv_work_t *work, int status)
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
    JsDomainPluginParam *param = reinterpret_cast<JsDomainPluginParam *>(work->data);
    int argc = 0;
    napi_value argv[ARG_SIZE_THREE] = {0};
    argv[argc++] = CreateNapiDomainAccountInfo(param->env, param->domainAccountInfo);
    if (param->authMode != AUTH_WITH_POPUP_MODE) {
        argv[argc++] = CreateUint8Array(param->env, param->authData.data(), param->authData.size());
    }
    argv[argc++] = CreateNapiDomainAuthCallback(param->env, param->authCallback);
    NapiCallVoidFunction(param->env, argv, argc, param->func);
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->count--;
    param->lockInfo->condition.notify_all();
    delete param;
    delete work;
}

void NapiDomainAccountPlugin::AuthCommon(AccountSA::AuthMode authMode, const AccountSA::DomainAccountInfo &info,
    const std::vector<uint8_t> &authData, const std::shared_ptr<AccountSA::DomainAuthCallback> &callback)
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if (lockInfo_.count < 0) {
        ACCOUNT_LOGE("the plugin has been released");
        return;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsDomainPluginParam *param = nullptr;
    if (!InitDomainPluginExecEnv(env_, &loop, &work, &param)) {
        ACCOUNT_LOGE("failed to init domain plugin execution environment");
        return;
    }
    switch (authMode) {
        case AUTH_WITH_CREDENTIAL_MODE:
            param->func = jsPlugin_.auth;
            break;
        case AUTH_WITH_POPUP_MODE:
            param->func = jsPlugin_.authWithPopup;
            break;
        case AUTH_WITH_TOKEN_MODE:
            param->func = jsPlugin_.authWithToken;
            break;
        default:
            break;
    }
    if (param->func == nullptr) {
        ACCOUNT_LOGE("func is nullptr");
        delete work;
        delete param;
        return;
    }
    param->env = env_;
    param->authCallback = callback;
    param->lockInfo = &lockInfo_;
    param->domainAccountInfo = info;
    param->authMode = authMode;
    param->authData = authData;
    work->data = reinterpret_cast<void *>(param);
    int errCode = uv_queue_work(loop, work, [](uv_work_t *work) {}, AuthCommonWork);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        delete param;
        delete work;
        return;
    }
    lockInfo_.count++;
}

void NapiDomainAccountPlugin::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &credential,
    const std::shared_ptr<DomainAuthCallback> &callback)
{
    AuthCommon(AUTH_WITH_CREDENTIAL_MODE, info, credential, callback);
}

void NapiDomainAccountPlugin::AuthWithPopup(
    const DomainAccountInfo &info, const std::shared_ptr<DomainAuthCallback> &callback)
{
    AuthCommon(AUTH_WITH_POPUP_MODE, info, {}, callback);
}

void NapiDomainAccountPlugin::AuthWithToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
    const std::shared_ptr<DomainAuthCallback> &callback)
{
    AuthCommon(AUTH_WITH_TOKEN_MODE, info, token, callback);
}


void NapiDomainAccountPlugin::GetAuthStatusInfo(
    const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback)
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if (lockInfo_.count < 0) {
        ACCOUNT_LOGE("the plugin has been released");
        return;
    }
    if (jsPlugin_.getAuthStatusInfo == nullptr) {
        ACCOUNT_LOGE("getAuthStatusInfo function of the js plugin is undefined");
        return;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsDomainPluginParam *param = nullptr;
    if (!InitDomainPluginExecEnv(env_, &loop, &work, &param)) {
        ACCOUNT_LOGE("failed to init domain plugin execution environment");
        return;
    }
    param->func = jsPlugin_.getAuthStatusInfo;
    param->domainAccountInfo = info;
    param->callback = callback;
    param->lockInfo = &lockInfo_;
    work->data = reinterpret_cast<void *>(param);
    int errCode = uv_queue_work(loop, work, [](uv_work_t *work) {}, GetAuthStatusInfoWork);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        delete param;
        delete work;
        return;
    }
    lockInfo_.count++;
}

napi_value NapiDomainAccountManager::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_STATIC_FUNCTION("registerPlugin", RegisterPlugin),
        DECLARE_NAPI_STATIC_FUNCTION("unregisterPlugin", UnregisterPlugin),
        DECLARE_NAPI_STATIC_FUNCTION("auth", Auth),
        DECLARE_NAPI_STATIC_FUNCTION("authWithPopup", AuthWithPopup),
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

napi_value NapiDomainAccountManager::JsConstructor(napi_env env, napi_callback_info cbInfo)
{
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

static bool ParseContextForRegisterPlugin(napi_env env, napi_callback_info cbInfo, JsDomainPlugin &jsPlugin)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr), false);
    if (argc != ARG_SIZE_ONE) {
        ACCOUNT_LOGE("the number of parameter must be one, but got %{public}zu", argc);
        return false;
    }
    if (!GetNamedJsFunction(env, argv[0], "getAuthStatusInfo", jsPlugin.getAuthStatusInfo)) {
        ACCOUNT_LOGE("fail to parse getAuthStatusInfo function");
        return false;
    }
    if (!GetNamedJsFunction(env, argv[0], "auth", jsPlugin.auth)) {
        ACCOUNT_LOGE("fail to parse getAuthStatusInfo function");
        return false;
    }
    if (!GetNamedJsFunction(env, argv[0], "authWithPopup", jsPlugin.authWithPopup)) {
        ACCOUNT_LOGE("fail to parse getAuthStatusInfo function");
        return false;
    }
    if (!GetNamedJsFunction(env, argv[0], "authWithToken", jsPlugin.authWithToken)) {
        ACCOUNT_LOGE("fail to parse getAuthStatusInfo function");
        return false;
    }
    return true;
}

napi_value NapiDomainAccountManager::RegisterPlugin(napi_env env, napi_callback_info cbInfo)
{
    JsDomainPlugin jsPlugin;
    if (!ParseContextForRegisterPlugin(env, cbInfo, jsPlugin)) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, true);
        return nullptr;
    }
    auto plugin = std::make_shared<NapiDomainAccountPlugin>(env, jsPlugin);
    int32_t errCode = DomainAccountClient::GetInstance().RegisterPlugin(plugin);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to register plugin, errCode=%{public}d", errCode);
        AccountNapiThrow(env, errCode, true);
    }
    return nullptr;
}

napi_value NapiDomainAccountManager::UnregisterPlugin(napi_env env, napi_callback_info cbInfo)
{
    int32_t errCode = DomainAccountClient::GetInstance().UnregisterPlugin();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to unregister plugin, errCode=%{public}d", errCode);
        AccountNapiThrow(env, errCode, true);
    }
    return nullptr;
}

static bool ParseDomainAccountInfo(napi_env env, napi_value object, DomainAccountInfo &info)
{
    if (!GetStringPropertyByKey(env, object, "domain", info.domain_)) {
        ACCOUNT_LOGE("get domainInfo's domain failed");
        return false;
    }
    if (!GetStringPropertyByKey(env, object, "accountName", info.accountName_)) {
        ACCOUNT_LOGE("get domainInfo's accountName failed");
        return false;
    }
    return true;
}

static bool ParseContextForAuth(napi_env env, napi_callback_info cbInfo, JsDomainPluginParam &authContext)
{
    size_t argc = ARG_SIZE_THREE;
    napi_value argv[ARG_SIZE_THREE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr), false);
    if (argc != ARG_SIZE_THREE) {
        ACCOUNT_LOGE("the number of parameter must be one, but got %{public}zu", argc);
        return false;
    }
    int index = 0;
    if (!ParseDomainAccountInfo(env, argv[index++], authContext.domainAccountInfo)) {
        ACCOUNT_LOGE("get domainInfo failed");
        return false;
    }
    if (ParseUint8TypedArrayToVector(env, argv[index++], authContext.authData) != napi_ok) {
        ACCOUNT_LOGE("get credential failed");
        return false;
    }
    napi_ref callbackRef = nullptr;
    if (!GetNamedJsFunction(env, argv[index++], "onResult", callbackRef)) {
        ACCOUNT_LOGE("get callback failed");
        return false;
    }
    authContext.authCallback = std::make_shared<NapiDomainAccountCallback>(env, callbackRef);
    if (authContext.authCallback == nullptr) {
        ACCOUNT_LOGE("failed to create NapiUserAuthCallback");
        return false;
    }
    return true;
}

napi_value NapiDomainAccountManager::Auth(napi_env env, napi_callback_info cbInfo)
{
    JsDomainPluginParam authContext = JsDomainPluginParam(env);
    if (!ParseContextForAuth(env, cbInfo, authContext)) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, true);
        return nullptr;
    }
    int32_t errCode = DomainAccountClient::GetInstance().Auth(
        authContext.domainAccountInfo, authContext.authData, authContext.authCallback);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to auth domain account, errCode = %{public}d", errCode);
        AccountSA::DomainAuthResult emptyResult;
        authContext.authCallback->OnResult(ConvertToJSErrCode(errCode), emptyResult);
    }
    return nullptr;
}

static bool ParseContextForAuthWithPopup(
    napi_env env, napi_callback_info cbInfo, JsDomainPluginParam &authWithPopupContext)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr), false);
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("need input at least one parameter, but got %{public}zu", argc);
        return false;
    }
    napi_ref callbackRef = nullptr;
    if (!GetNamedJsFunction(env, argv[argc - 1], "onResult", callbackRef)) {
        ACCOUNT_LOGE("get callback failed");
        return false;
    }
    if (argc == ARG_SIZE_TWO) {
        if (!GetIntProperty(env, argv[0], authWithPopupContext.userId)) {
            ACCOUNT_LOGE("get id failed");
            return false;
        }
    }
    authWithPopupContext.authCallback = std::make_shared<NapiDomainAccountCallback>(env, callbackRef);
    if (authWithPopupContext.authCallback == nullptr) {
        ACCOUNT_LOGE("failed to create NapiUserAuthCallback");
        return false;
    }
    return true;
}

napi_value NapiDomainAccountManager::AuthWithPopup(napi_env env, napi_callback_info cbInfo)
{
    JsDomainPluginParam authWithPopupContext = JsDomainPluginParam(env);
    if (!ParseContextForAuthWithPopup(env, cbInfo, authWithPopupContext)) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, true);
        return nullptr;
    }
    int32_t errCode = DomainAccountClient::GetInstance().AuthWithPopup(
        authWithPopupContext.userId, authWithPopupContext.authCallback);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to auth domain account with popup, errCode = %{public}d", errCode);
        AccountSA::DomainAuthResult emptyResult;
        authWithPopupContext.authCallback->OnResult(ConvertToJSErrCode(errCode), emptyResult);
    }
    return nullptr;
}
}  // namespace AccountJsKit
}  // namespace OHOS

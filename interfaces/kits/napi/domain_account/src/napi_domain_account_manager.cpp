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
#include <memory>
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

static bool InitDomainPluginExecEnv(
    napi_env env, uv_loop_s **loop, uv_work_t **work, JsDomainPluginParam **param, ThreadLockInfo *lockInfo)
{
    if (!CreateExecEnv(env, loop, work)) {
        return false;
    }
    *param = new (std::nothrow) JsDomainPluginParam(env);
    if (*param == nullptr) {
        ACCOUNT_LOGE("failed to create JsDomainPluginParam");
        delete *work;
        *work = nullptr;
        return false;
    }
    (*param)->lockInfo = lockInfo;
    (*work)->data = reinterpret_cast<void *>(*param);
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

static bool GetPluginCallbackCommonParam(napi_env env, napi_callback_info cbInfo,
    JsDomainPluginParam **param, BusinessError &error, napi_value *businessData)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {nullptr};
    void *data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, &data), false);
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("the number of argument should be at least 1");
        return false;
    }
    *param = reinterpret_cast<JsDomainPluginParam *>(data);
    if ((*param == nullptr) || ((*param)->callback == nullptr)) {
        ACCOUNT_LOGE("native callback is nullptr");
        return false;
    }
    if (!ParseBusinessError(env, argv[0], error)) {
        ACCOUNT_LOGE("ParseBussinessError failed");
        return false;
    }
    if (argc == ARG_SIZE_TWO) {
        *businessData = argv[1];
    }
    return true;
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
    napi_value napiAccountId = nullptr;
    napi_create_string_utf8(env, domainAccountInfo.accountId_.c_str(), NAPI_AUTO_LENGTH, &napiAccountId);
    napi_set_named_property(env, napiInfo, "accountId", napiAccountId);
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
    if (!GetStringPropertyByKey(env, object, "accountId", info.accountId_)) {
        ACCOUNT_LOGE("get domainInfo's accountName failed");
        return false;
    }
    return true;
}

static napi_value GetDomainAccountInfoCallback(napi_env env, napi_callback_info cbInfo)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {nullptr};
    void *data = nullptr;
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
        ACCOUNT_LOGE("ParseBussinessError failed");
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, true);
        return nullptr;
    }
    DomainAccountInfo info;
    if (!ParseDomainAccountInfo(env, argv[1], info)) {
        ACCOUNT_LOGE("ParseDomainAccountInfo failed");
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, true);
        return nullptr;
    }
    Parcel parcel;
    if (!info.Marshalling(parcel)) {
        ACCOUNT_LOGE("info Marshalling failed");
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    param->callback->OnResult(error.code, parcel);
    return nullptr;
}

static void GetDomainAccountInfoWork(uv_work_t *work, int status)
{
    if (work == nullptr) {
        ACCOUNT_LOGE("invalid parameter, work is nullptr");
        return;
    }
    if (work->data == nullptr) {
        ACCOUNT_LOGE("invalid parameter, data is nullptr");
        delete work;
        return;
    }
    JsDomainPluginParam *param = reinterpret_cast<JsDomainPluginParam *>(work->data);
    napi_value napiName = nullptr;
    napi_create_string_utf8(param->env, param->domainAccountInfo.accountName_.c_str(), NAPI_AUTO_LENGTH, &napiName);
    napi_value napiDomain = nullptr;
    napi_create_string_utf8(param->env, param->domainAccountInfo.domain_.c_str(), NAPI_AUTO_LENGTH, &napiDomain);
    napi_value napiCallback = CreatePluginAsyncCallback(param->env, GetDomainAccountInfoCallback, param);
    napi_value argv[] = {napiDomain, napiName, napiCallback};
    NapiCallVoidFunction(param->env, argv, ARG_SIZE_THREE, param->func);
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->count--;
    param->lockInfo->condition.notify_all();
    if (napiCallback == nullptr) {
        delete param;
    }
    delete work;
}

static napi_value OnAccountBoundCallback(napi_env env, napi_callback_info cbInfo)
{
    JsDomainPluginParam *param = nullptr;
    BusinessError error;
    napi_value businessData = nullptr;
    if (!GetPluginCallbackCommonParam(env, cbInfo, &param, error, &businessData)) {
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, true);
        return nullptr;
    }
    DomainAccountInfo info;
    Parcel parcel;
    if (!info.Marshalling(parcel)) {
        ACCOUNT_LOGE("info Marshalling failed");
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    if (error.code != 0) {
        ACCOUNT_LOGI("bind or unbind error, code: %{public}d", error.code);
    }
    param->callback->OnResult(error.code, parcel);
    return nullptr;
}

static void OnAccountBoundWork(uv_work_t *work, int status)
{
    if (work == nullptr) {
        ACCOUNT_LOGE("invalid parameter, work is nullptr");
        return;
    }
    if (work->data == nullptr) {
        ACCOUNT_LOGE("invalid parameter, data is nullptr");
        delete work;
        return;
    }
    JsDomainPluginParam *param = reinterpret_cast<JsDomainPluginParam *>(work->data);
    napi_value napiLocalId = nullptr;
    napi_create_int32(param->env, param->userId, &napiLocalId);
    napi_value napiDomainAccountInfo = CreateNapiDomainAccountInfo(param->env, param->domainAccountInfo);
    napi_value napiCallback = CreatePluginAsyncCallback(param->env, OnAccountBoundCallback, param);
    napi_value argv[] = {napiDomainAccountInfo, napiLocalId, napiCallback};
    NapiCallVoidFunction(param->env, argv, ARG_SIZE_THREE, param->func);
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->count--;
    param->lockInfo->condition.notify_all();
    delete work;
    delete param;
}

static void OnAccountUnBoundWork(uv_work_t *work, int status)
{
    if (work == nullptr) {
        ACCOUNT_LOGE("invalid parameter, work is nullptr");
        return;
    }
    if (work->data == nullptr) {
        ACCOUNT_LOGE("invalid parameter, data is nullptr");
        delete work;
        return;
    }
    JsDomainPluginParam *param = reinterpret_cast<JsDomainPluginParam *>(work->data);
    napi_value napiDomainAccountInfo = CreateNapiDomainAccountInfo(param->env, param->domainAccountInfo);
    napi_value napiCallback = CreatePluginAsyncCallback(param->env, OnAccountBoundCallback, param);
    napi_value argv[] = {napiDomainAccountInfo, napiCallback};
    NapiCallVoidFunction(param->env, argv, ARG_SIZE_TWO, param->func);
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->count--;
    param->lockInfo->condition.notify_all();
    delete work;
    delete param;
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
    if (jsPlugin_.getDomainAccountInfo != nullptr) {
        napi_delete_reference(env_, jsPlugin_.getDomainAccountInfo);
        jsPlugin_.getDomainAccountInfo = nullptr;
    }
    if (jsPlugin_.onAccountBound != nullptr) {
        napi_delete_reference(env_, jsPlugin_.onAccountBound);
        jsPlugin_.onAccountBound = nullptr;
    }
    if (jsPlugin_.onAccountUnbound != nullptr) {
        napi_delete_reference(env_, jsPlugin_.onAccountUnbound);
        jsPlugin_.onAccountUnbound = nullptr;
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
    if (!InitDomainPluginExecEnv(env_, &loop, &work, &param, &lockInfo_)) {
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
    param->authCallback = callback;
    param->domainAccountInfo = info;
    param->authMode = authMode;
    param->authData = authData;
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
    if (!InitDomainPluginExecEnv(env_, &loop, &work, &param, &lockInfo_)) {
        ACCOUNT_LOGE("failed to init domain plugin execution environment");
        return;
    }
    param->func = jsPlugin_.getAuthStatusInfo;
    param->domainAccountInfo = info;
    param->callback = callback;
    int errCode = uv_queue_work(loop, work, [](uv_work_t *work) {}, GetAuthStatusInfoWork);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        delete param;
        delete work;
        return;
    }
    lockInfo_.count++;
}

void NapiDomainAccountPlugin::OnAccountBound(const DomainAccountInfo &info, const int32_t localId,
    const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if (lockInfo_.count < 0) {
        ACCOUNT_LOGE("the plugin has been released");
        return;
    }
    if (jsPlugin_.onAccountBound == nullptr) {
        ACCOUNT_LOGE("auth function of the js plugin is undefined");
        return;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsDomainPluginParam *param = nullptr;
    if (!InitDomainPluginExecEnv(env_, &loop, &work, &param, &lockInfo_)) {
        ACCOUNT_LOGE("failed to init domain plugin execution environment");
        return;
    }
    param->domainAccountInfo = info;
    param->func = jsPlugin_.onAccountBound;
    param->callback = callback;
    param->userId = localId;
    int errCode = uv_queue_work(loop, work, [](uv_work_t *work) {}, OnAccountBoundWork);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        delete work;
        delete param;
    }
    lockInfo_.count++;
}

void NapiDomainAccountPlugin::OnAccountUnBound(const DomainAccountInfo &info,
    const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if (lockInfo_.count < 0) {
        ACCOUNT_LOGE("the plugin has been released");
        return;
    }
    if (jsPlugin_.onAccountUnbound == nullptr) {
        ACCOUNT_LOGE("auth function of the js plugin is undefined");
        return;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsDomainPluginParam *param = nullptr;
    if (!InitDomainPluginExecEnv(env_, &loop, &work, &param, &lockInfo_)) {
        ACCOUNT_LOGE("failed to init domain plugin execution environment");
        return;
    }
    param->domainAccountInfo = info;
    param->func = jsPlugin_.onAccountUnbound;
    param->callback = callback;
    int errCode = uv_queue_work(
        loop, work, [](uv_work_t *work) {}, OnAccountUnBoundWork);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        delete work;
        delete param;
    }
    lockInfo_.count++;
}

void NapiDomainAccountPlugin::GetDomainAccountInfo(const std::string &domain, const std::string &accountName,
    const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if (lockInfo_.count < 0) {
        ACCOUNT_LOGE("the plugin has been released");
        return;
    }
    if (jsPlugin_.getDomainAccountInfo == nullptr) {
        ACCOUNT_LOGE("auth function of the js plugin is undefined");
        return;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsDomainPluginParam *param = nullptr;
    if (!InitDomainPluginExecEnv(env_, &loop, &work, &param, &lockInfo_)) {
        ACCOUNT_LOGE("failed to init domain plugin execution environment");
        return;
    }
    param->domainAccountInfo.accountName_ = accountName;
    param->domainAccountInfo.domain_ = domain;
    param->callback = callback;
    param->func = jsPlugin_.getDomainAccountInfo;
    int errCode = uv_queue_work(
        loop, work, [](uv_work_t *work) {}, GetDomainAccountInfoWork);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        delete work;
        delete param;
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
        DECLARE_NAPI_STATIC_FUNCTION("hasAccount", HasDomainAccount),
        DECLARE_NAPI_FUNCTION("registerPlugin", RegisterPlugin),
        DECLARE_NAPI_FUNCTION("unregisterPlugin", UnregisterPlugin),
        DECLARE_NAPI_FUNCTION("hasAccount", HasDomainAccount)
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
    if (!GetNamedJsFunction(env, argv[0], "bindAccount", jsPlugin.onAccountBound)) {
        ACCOUNT_LOGE("fail to parse onAccountBound function");
        return false;
    }
    if (!GetNamedJsFunction(env, argv[0], "unbindAccount", jsPlugin.onAccountUnbound)) {
        ACCOUNT_LOGE("fail to parse onAccountUnbound function");
        return false;
    }
    if (!GetNamedJsFunction(env, argv[0], "getAccountInfo", jsPlugin.getDomainAccountInfo)) {
        ACCOUNT_LOGE("fail to parse getDomainAccountInfo function");
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

static bool ParseParamForHasDomainAccount(
    napi_env env, napi_callback_info cbInfo, HasDomainAccountAsyncContext *asyncContext)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("paramter number should be at least one");
        return false;
    }
    if (argc == ARG_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            return false;
        }
    }
    if (!GetStringPropertyByKey(env, argv[0], "domain", asyncContext->domainInfo.domain_)) {
        ACCOUNT_LOGE("Get domainInfo's domain failed");
        return false;
    }
    if (!GetStringPropertyByKey(env, argv[0], "accountName", asyncContext->domainInfo.accountName_)) {
        ACCOUNT_LOGE("Get domainInfo's accountName failed");
        return false;
    }
    return true;
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

static void HasDomainAccountCompletedCB(uv_work_t *work, int status)
{
    if (work == nullptr) {
        ACCOUNT_LOGE("invalid parameter, work is nullptr");
        return;
    }
    if (work->data == nullptr) {
        ACCOUNT_LOGE("invalid parameter, data is nullptr");
        delete work;
        return;
    }
    HasDomainAccountAsyncContext *asyncContext = reinterpret_cast<HasDomainAccountAsyncContext *>(work->data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == ERR_OK) {
        napi_get_boolean(asyncContext->env, asyncContext->isHasDomainAccount, &dataJs);
    } else {
        errJs = GenerateBusinessError(asyncContext->env, asyncContext->errCode);
    }
    ProcessCallbackOrPromise(asyncContext->env, asyncContext, errJs, dataJs);
    delete asyncContext;
    delete work;
}

NapiHasDomainInfoCallback::NapiHasDomainInfoCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred)
    : env_(env), callbackRef_(callbackRef), deferred_(deferred)
{}

NapiHasDomainInfoCallback::~NapiHasDomainInfoCallback()
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if (callbackRef_ != nullptr) {
        napi_delete_reference(env_, callbackRef_);
        callbackRef_ = nullptr;
    }
    deferred_ = nullptr;
}

void NapiHasDomainInfoCallback::OnResult(const int32_t errCode, Parcel &parcel)
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if ((callbackRef_ == nullptr) && (deferred_ == nullptr)) {
        ACCOUNT_LOGE("js callback is nullptr");
        return;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    if (!CreateExecEnv(env_, &loop, &work)) {
        ACCOUNT_LOGE("failed to init domain plugin execution environment");
        return;
    }
    auto *asyncContext = new (std::nothrow) HasDomainAccountAsyncContext();
    if (asyncContext == nullptr) {
        delete work;
        return;
    }
    if (errCode == ERR_OK) {
        parcel.ReadBool(asyncContext->isHasDomainAccount);
    }
    asyncContext->errCode = errCode;
    asyncContext->env = env_;
    asyncContext->callbackRef = callbackRef_;
    asyncContext->deferred = deferred_;
    work->data = reinterpret_cast<void *>(asyncContext);
    int resultCode = uv_queue_work(
        loop, work, [](uv_work_t *work) {}, HasDomainAccountCompletedCB);
    if (resultCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        delete asyncContext;
        delete work;
        return;
    }
    callbackRef_ = nullptr;
    deferred_ = nullptr;
}

static void HasDomainAccountExecuteCB(napi_env env, void *data)
{
    HasDomainAccountAsyncContext *asyncContext = reinterpret_cast<HasDomainAccountAsyncContext *>(data);
    auto callback = std::make_shared<NapiHasDomainInfoCallback>(env, asyncContext->callbackRef, asyncContext->deferred);
    if (callback == nullptr) {
        asyncContext->errCode = ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
        ACCOUNT_LOGE("insufficient memory for HasDomainAccountCB!");
        return;
    }
    asyncContext->errCode = DomainAccountClient::GetInstance().HasDomainAccount(asyncContext->domainInfo, callback);
    if (asyncContext->errCode != ERR_OK) {
        Parcel emptyParcel;
        emptyParcel.WriteBool(false);
        callback->OnResult(asyncContext->errCode, emptyParcel);
        asyncContext->errCode = ERR_OK;
    }
}

napi_value NapiDomainAccountManager::HasDomainAccount(napi_env env, napi_callback_info cbInfo)
{
    HasDomainAccountAsyncContext *hasDomainAccountCB = new (std::nothrow) HasDomainAccountAsyncContext();
    if (hasDomainAccountCB == nullptr) {
        ACCOUNT_LOGE("insufficient memory for HasDomainAccountCB!");
        return nullptr;
    }
    std::unique_ptr<HasDomainAccountAsyncContext> contextPtr(hasDomainAccountCB);
    hasDomainAccountCB->env = env;
    if (!ParseParamForHasDomainAccount(env, cbInfo, hasDomainAccountCB)) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, true);
        return nullptr;
    }
    napi_value result = nullptr;
    if (hasDomainAccountCB->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &hasDomainAccountCB->deferred, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "hasDomainAccount", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, HasDomainAccountExecuteCB,
        [](napi_env env, napi_status status, void *data) {
            auto *asyncContext = reinterpret_cast<HasDomainAccountAsyncContext *>(data);
            napi_delete_async_work(env, asyncContext->work);
            if (asyncContext->errCode != ERR_OK) {
                napi_delete_reference(env, asyncContext->callbackRef);
                delete asyncContext;
            }
        }, reinterpret_cast<void *>(hasDomainAccountCB), &hasDomainAccountCB->work));
    NAPI_CALL(env, napi_queue_async_work(env, hasDomainAccountCB->work));
    contextPtr.release();
    return result;
}
}  // namespace AccountJsKit
}  // namespace OHOS

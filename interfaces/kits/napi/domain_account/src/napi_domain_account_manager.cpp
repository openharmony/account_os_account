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
#include "napi_common.h"
#include "napi_domain_auth_callback.h"

namespace OHOS {
namespace AccountJsKit {
namespace {
const size_t ARG_SIZE_ONE = 1;
const size_t ARG_SIZE_TWO = 2;
const size_t ARG_SIZE_THREE = 3;
const size_t PARAM_ONE = 1;
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
    NAPI_CALL(env, napi_create_object(env, &napiInfo));
    napi_value napiName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, domainAccountInfo.accountName_.c_str(), NAPI_AUTO_LENGTH, &napiName));
    NAPI_CALL(env, napi_set_named_property(env, napiInfo, "accountName", napiName));
    napi_value napiDomain = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, domainAccountInfo.domain_.c_str(), NAPI_AUTO_LENGTH, &napiDomain));
    NAPI_CALL(env, napi_set_named_property(env, napiInfo, "domain", napiDomain));
    napi_value napiAccountId = nullptr;
    NAPI_CALL(
        env, napi_create_string_utf8(env, domainAccountInfo.accountId_.c_str(), NAPI_AUTO_LENGTH, &napiAccountId));
    NAPI_CALL(env, napi_set_named_property(env, napiInfo, "accountId", napiAccountId));
    return napiInfo;
}

static napi_value CreateNapiGetAccessTokenOptions(const JsDomainPluginParam *param)
{
    napi_value napiOptions = nullptr;
    NAPI_CALL(param->env, napi_create_object(param->env, &napiOptions));
    napi_value napiDomainAccountInfo = CreateNapiDomainAccountInfo(param->env, param->domainAccountInfo);
    NAPI_CALL(param->env, napi_set_named_property(param->env, napiOptions, "domainAccountInfo", napiDomainAccountInfo));
    napi_value napiAccountToken = CreateUint8Array(param->env, param->authData.data(), param->authData.size());
    NAPI_CALL(param->env, napi_set_named_property(param->env, napiOptions, "domainAccountToken", napiAccountToken));
    napi_value napiParam = AppExecFwk::WrapWantParams(param->env, param->option.getTokenParams_);
    NAPI_CALL(param->env, napi_set_named_property(param->env, napiOptions, "businessParams", napiParam));
    napi_value napiUid = nullptr;
    NAPI_CALL(param->env, napi_create_int32(param->env, param->option.callingUid_, &napiUid));
    NAPI_CALL(param->env, napi_set_named_property(param->env, napiOptions, "callerUid", napiUid));
    return napiOptions;
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
    bool hasProp = false;
    napi_has_named_property(env, object, "accountId", &hasProp);
    if (hasProp) {
        napi_value value = nullptr;
        napi_get_named_property(env, object, "accountId", &value);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, value, &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("the accountId is undefined or null");
        } else {
            if (!GetStringProperty(env, value, info.accountId_)) {
                ACCOUNT_LOGE("get domainInfo's accountId failed");
                return false;
            }
        }
    }
    return true;
}

static bool ParseParamForUpdateAccountToken(
    napi_env env, napi_callback_info cbInfo, UpdateAccountTokenAsyncContext *asyncContext)
{
    size_t argc = ARG_SIZE_THREE;
    napi_value argv[ARG_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARG_SIZE_TWO) {
        ACCOUNT_LOGE("the parameter of number should be at least two");
        return false;
    }
    if (argc == ARG_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            return false;
        }
    }
    if (!ParseDomainAccountInfo(env, argv[0], asyncContext->domainInfo)) {
        ACCOUNT_LOGE("get domainInfo failed");
        return false;
    }
    if (ParseUint8TypedArrayToVector(env, argv[PARAM_ONE], asyncContext->token) != napi_ok) {
        ACCOUNT_LOGE("get token failed");
        return false;
    }
    return true;
}

static bool ParseParamForGetAccessToken(
    napi_env env, napi_callback_info cbInfo, GetAccessTokenAsyncContext *asyncContext)
{
    size_t argc = ARG_SIZE_THREE;
    napi_value argv[ARG_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARG_SIZE_TWO) {
        ACCOUNT_LOGE("the parameter of number should be at least two");
        return false;
    }
    if (argc == ARG_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            return false;
        }
    }
    if (!ParseDomainAccountInfo(env, argv[0], asyncContext->domainInfo)) {
        ACCOUNT_LOGE("get domainInfo failed");
        return false;
    }
    if (!AppExecFwk::UnwrapWantParams(env, argv[PARAM_ONE], asyncContext->getTokenParams)) {
        ACCOUNT_LOGE("unwrapWantParams failed");
        return false;
    }
    return true;
}

static napi_value GetDomainAccountInfoCallback(napi_env env, napi_callback_info cbInfo)
{
    JsDomainPluginParam *param = nullptr;
    BusinessError error;
    napi_value businessData = nullptr;
    if (!GetPluginCallbackCommonParam(env, cbInfo, &param, error, &businessData)) {
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, true);
        return nullptr;
    }
    DomainAccountInfo info;
    if ((error.code == 0) && (!ParseDomainAccountInfo(env, businessData, info))) {
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
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
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
    napi_close_handle_scope(param->env, scope);
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
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
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
    if (napiCallback == nullptr) {
        delete param;
    }
    napi_close_handle_scope(param->env, scope);
}

static void OnAccountUnBoundWork(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
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
    if (napiCallback == nullptr) {
        delete param;
    }
    napi_close_handle_scope(param->env, scope);
}

static napi_value GetAuthStatusInfoCallback(napi_env env, napi_callback_info cbInfo)
{
    JsDomainPluginParam *param = nullptr;
    BusinessError error;
    napi_value businessData = nullptr;
    if (!GetPluginCallbackCommonParam(env, cbInfo, &param, error, &businessData)) {
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, true);
        return nullptr;
    }
    AuthStatusInfo info;
    if ((error.code == 0) && (!ParseAuthStatusInfo(env, businessData, info))) {
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

static napi_value GetAccessTokenCallback(napi_env env, napi_callback_info cbInfo)
{
    JsDomainPluginParam *param = nullptr;
    BusinessError error;
    napi_value businessData = nullptr;
    if (!GetPluginCallbackCommonParam(env, cbInfo, &param, error, &businessData)) {
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    std::vector<uint8_t> accessToken;
    if ((error.code == 0) && (ParseUint8TypedArrayToVector(env, businessData, accessToken) != napi_ok)) {
        ACCOUNT_LOGE("Parse access token failed");
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    Parcel parcel;
    if (!parcel.WriteUInt8Vector(accessToken)) {
        ACCOUNT_LOGE("failed to write accessToken");
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    param->callback->OnResult(error.code, parcel);
    return nullptr;
}

static napi_value IsUserTokenValidCallback(napi_env env, napi_callback_info cbInfo)
{
    JsDomainPluginParam *param = nullptr;
    BusinessError error;
    napi_value businessData = nullptr;
    if (!GetPluginCallbackCommonParam(env, cbInfo, &param, error, &businessData)) {
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    bool isTokenValid = false;
    if ((error.code == 0) && (!GetBoolProperty(env, businessData, isTokenValid))) {
        ACCOUNT_LOGE("Parse access token failed");
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    Parcel parcel;
    if (!parcel.WriteBool(isTokenValid)) {
        ACCOUNT_LOGE("failed to write accessToken");
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    param->callback->OnResult(error.code, parcel);
    return nullptr;
}

static void GetAccessTokenWork(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    JsDomainPluginParam *param = reinterpret_cast<JsDomainPluginParam *>(work->data);
    napi_value napiCallback = CreatePluginAsyncCallback(param->env, GetAccessTokenCallback, param);
    napi_value napiOptions = CreateNapiGetAccessTokenOptions(param);
    napi_value argv[] = {napiOptions, napiCallback};
    NapiCallVoidFunction(param->env, argv, ARG_SIZE_TWO, param->func);
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->count--;
    param->lockInfo->condition.notify_all();
    if (napiCallback == nullptr) {
        delete param;
    }
    napi_close_handle_scope(param->env, scope);
}

static void IsUserTokenValidWork(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    JsDomainPluginParam *param = reinterpret_cast<JsDomainPluginParam *>(work->data);
    napi_value napiCallback = CreatePluginAsyncCallback(param->env, IsUserTokenValidCallback, param);
    napi_value napiDomainAccountInfo = CreateNapiDomainAccountInfo(param->env, param->domainAccountInfo);
    napi_value napiUserToken = CreateUint8Array(param->env, param->authData.data(), param->authData.size());
    napi_value argv[] = {napiDomainAccountInfo, napiUserToken, napiCallback};
    NapiCallVoidFunction(param->env, argv, ARG_SIZE_THREE, param->func);
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->count--;
    param->lockInfo->condition.notify_all();
    if (napiCallback == nullptr) {
        delete param;
    }
    napi_close_handle_scope(param->env, scope);
}

static void GetAuthStatusInfoWork(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
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
    napi_close_handle_scope(param->env, scope);
}

JsDomainPluginParam::JsDomainPluginParam(napi_env napiEnv)
{
    env = napiEnv;
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
    ReleaseNapiRefAsync(env_, jsPlugin_.auth);
    jsPlugin_.auth = nullptr;
    ReleaseNapiRefAsync(env_, jsPlugin_.authWithPopup);
    jsPlugin_.authWithPopup = nullptr;
    ReleaseNapiRefAsync(env_, jsPlugin_.authWithToken);
    jsPlugin_.authWithToken = nullptr;
    ReleaseNapiRefAsync(env_, jsPlugin_.getAuthStatusInfo);
    jsPlugin_.getAuthStatusInfo = nullptr;
    ReleaseNapiRefAsync(env_, jsPlugin_.getDomainAccountInfo);
    jsPlugin_.getDomainAccountInfo = nullptr;
    ReleaseNapiRefAsync(env_, jsPlugin_.onAccountBound);
    jsPlugin_.onAccountBound = nullptr;
    ReleaseNapiRefAsync(env_, jsPlugin_.onAccountUnbound);
    jsPlugin_.onAccountUnbound = nullptr;
    ReleaseNapiRefAsync(env_, jsPlugin_.isAccountTokenValid);
    jsPlugin_.isAccountTokenValid = nullptr;
    ReleaseNapiRefAsync(env_, jsPlugin_.getAccessToken);
    jsPlugin_.getAccessToken = nullptr;
}

static void AuthCommonWork(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
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
    napi_close_handle_scope(param->env, scope);
    delete param;
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
        return;
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
        return;
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
        return;
    }
    lockInfo_.count++;
}

void NapiDomainAccountPlugin::IsAccountTokenValid(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
    const std::shared_ptr<DomainAccountCallback> &callback)
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if (lockInfo_.count < 0) {
        ACCOUNT_LOGE("the plugin has been released");
        return;
    }
    if (jsPlugin_.isAccountTokenValid == nullptr) {
        ACCOUNT_LOGE("isUserTokenValid function of the js plugin is undefined");
        return;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsDomainPluginParam *param = nullptr;
    if (!InitDomainPluginExecEnv(env_, &loop, &work, &param, &lockInfo_)) {
        ACCOUNT_LOGE("failed to init domain plugin execution environment");
        return;
    }
    param->callback = callback;
    param->authData = token;
    param->domainAccountInfo = info;
    param->func = jsPlugin_.isAccountTokenValid;
    int errCode = uv_queue_work(
        loop, work, [](uv_work_t *work) {}, IsUserTokenValidWork);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        delete work;
        delete param;
        return;
    }
    lockInfo_.count++;
}

void NapiDomainAccountPlugin::GetAccessToken(const AccountSA::DomainAccountInfo &domainInfo,
    const std::vector<uint8_t> &accountToken, const AccountSA::GetAccessTokenOptions &option,
    const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if (lockInfo_.count < 0) {
        ACCOUNT_LOGE("the plugin has been released");
        return;
    }
    if (jsPlugin_.getAccessToken == nullptr) {
        ACCOUNT_LOGE("getAccessToken function of the js plugin is undefined");
        return;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsDomainPluginParam *param = nullptr;
    if (!InitDomainPluginExecEnv(env_, &loop, &work, &param, &lockInfo_)) {
        ACCOUNT_LOGE("failed to init domain plugin execution environment");
        return;
    }
    param->domainAccountInfo = domainInfo;
    param->callback = callback;
    param->authData = accountToken;
    param->option = option;
    param->func = jsPlugin_.getAccessToken;
    int errCode = uv_queue_work(
        loop, work, [](uv_work_t *work) {}, GetAccessTokenWork);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        delete work;
        delete param;
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
        DECLARE_NAPI_STATIC_FUNCTION("hasAccount", HasDomainAccount),
        DECLARE_NAPI_STATIC_FUNCTION("updateAccountToken", UpdateAccountToken),
        DECLARE_NAPI_STATIC_FUNCTION("getAccessToken", GetAccessToken),
        DECLARE_NAPI_FUNCTION("registerPlugin", RegisterPlugin),
        DECLARE_NAPI_FUNCTION("unregisterPlugin", UnregisterPlugin),
        DECLARE_NAPI_FUNCTION("hasAccount", HasDomainAccount),
        DECLARE_NAPI_FUNCTION("updateAccountToken", UpdateAccountToken),
        DECLARE_NAPI_FUNCTION("getAccessToken", GetAccessToken)
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
    if (!GetNamedJsFunction(env, argv[0], "isAccountTokenValid", jsPlugin.isAccountTokenValid)) {
        ACCOUNT_LOGE("fail to parse isUserTokenValid function");
        return false;
    }
    if (!GetNamedJsFunction(env, argv[0], "getAccessToken", jsPlugin.getAccessToken)) {
        ACCOUNT_LOGE("fail to parse getAccessToken function");
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
    if (!ParseDomainAccountInfo(env, argv[0], asyncContext->domainInfo)) {
        ACCOUNT_LOGE("get domainInfo failed");
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
    authContext.callbackRef = callbackRef;
    authContext.authCallback = std::make_shared<NapiDomainAccountCallback>(env, callbackRef);
    if (authContext.authCallback == nullptr) {
        ACCOUNT_LOGE("failed to create NapiUserAuthCallback");
        return false;
    }
    return true;
}

void AuthCompletedCallback(napi_env env, napi_status status, void *data)
{
    JsDomainPluginParam *param = reinterpret_cast<JsDomainPluginParam *>(data);
    napi_delete_async_work(env, param->work);
    if (param->errCode != ERR_OK) {
        napi_value argv[ARG_SIZE_TWO] = {nullptr};
        napi_create_int32(param->env, ConvertToJSErrCode(param->errCode), &argv[0]);
        AccountSA::DomainAuthResult emptyResult;
        argv[1] = CreateAuthResult(param->env, emptyResult.token,
            emptyResult.authStatusInfo.remainingTimes, emptyResult.authStatusInfo.freezingTime);
        NapiCallVoidFunction(param->env, argv, ARG_SIZE_TWO, param->callbackRef);
    }
    delete param;
}

napi_value NapiDomainAccountManager::Auth(napi_env env, napi_callback_info cbInfo)
{
    JsDomainPluginParam *authContext = new (std::nothrow) JsDomainPluginParam(env);
    if (authContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for authContext!");
        return nullptr;
    }
    std::unique_ptr<JsDomainPluginParam> authContextPtr(authContext);
    if (!ParseContextForAuth(env, cbInfo, *authContext)) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, true);
        return nullptr;
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "Auth", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            JsDomainPluginParam *param = reinterpret_cast<JsDomainPluginParam *>(data);
            param->errCode = DomainAccountClient::GetInstance().Auth(
                param->domainAccountInfo, param->authData, param->authCallback);
            if (param->errCode == ERR_OK) {
                param->authCallback = nullptr;
            }
        },
        AuthCompletedCallback,
        reinterpret_cast<void *>(authContext), &authContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, authContext->work));
    authContextPtr.release();
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
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[0], &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("the userId is undefined or null");
        } else {
            if (!GetIntProperty(env, argv[0], authWithPopupContext.userId)) {
                ACCOUNT_LOGE("get id failed");
                return false;
            }
        }
    }
    authWithPopupContext.callbackRef = callbackRef;
    authWithPopupContext.authCallback = std::make_shared<NapiDomainAccountCallback>(env, callbackRef);
    if (authWithPopupContext.authCallback == nullptr) {
        ACCOUNT_LOGE("failed to create NapiUserAuthCallback");
        return false;
    }
    return true;
}

static void GetAccessTokenExecuteCB(napi_env env, void *data)
{
    GetAccessTokenAsyncContext *asyncContext = reinterpret_cast<GetAccessTokenAsyncContext *>(data);
    auto callback =
        std::make_shared<NapiGetAccessTokenCallback>(env, asyncContext->callbackRef, asyncContext->deferred);
    asyncContext->errCode = DomainAccountClient::GetInstance().GetAccessToken(
        asyncContext->domainInfo, asyncContext->getTokenParams, callback);
    if (asyncContext->errCode != ERR_OK) {
        std::vector<uint8_t> accessToken;
        callback->OnResult(asyncContext->errCode, accessToken);
    }
}

static void GetAccessTokenCompleteCB(napi_env env, napi_status status, void *data)
{
    auto *asyncContext = reinterpret_cast<GetAccessTokenAsyncContext *>(data);
    napi_delete_async_work(env, asyncContext->work);
}

static void GetAccessTokenCompleteWork(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        if ((work != nullptr) && (work->data != nullptr)) {
            delete reinterpret_cast<GetAccessTokenAsyncContext *>(work->data);
        }
        return;
    }
    GetAccessTokenAsyncContext *asyncContext = reinterpret_cast<GetAccessTokenAsyncContext *>(work->data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == ERR_OK) {
        dataJs =
            CreateUint8Array(asyncContext->env, asyncContext->accessToken.data(), asyncContext->accessToken.size());
    } else {
        errJs = GenerateBusinessError(asyncContext->env, asyncContext->errCode);
    }
    ReturnCallbackOrPromise(asyncContext->env, asyncContext, errJs, dataJs);
    napi_close_handle_scope(asyncContext->env, scope);
    delete asyncContext;
}

napi_value NapiDomainAccountManager::AuthWithPopup(napi_env env, napi_callback_info cbInfo)
{
    JsDomainPluginParam *authWithPopupContext = new (std::nothrow) JsDomainPluginParam(env);
    if (authWithPopupContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for authWithPopupContext!");
        return nullptr;
    }
    std::unique_ptr<JsDomainPluginParam> authContextPtr(authWithPopupContext);
    if (!ParseContextForAuthWithPopup(env, cbInfo, *authWithPopupContext)) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, true);
        return nullptr;
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "AuthWithPopup", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            JsDomainPluginParam *param = reinterpret_cast<JsDomainPluginParam *>(data);
            param->errCode = DomainAccountClient::GetInstance().AuthWithPopup(param->userId, param->authCallback);
            if (param->errCode == ERR_OK) {
                param->authCallback = nullptr;
            }
        },
        AuthCompletedCallback,
        reinterpret_cast<void *>(authWithPopupContext), &authWithPopupContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, authWithPopupContext->work));
    authContextPtr.release();
    return nullptr;
}

HasDomainAccountAsyncContext::~HasDomainAccountAsyncContext()
{
    if (callbackRef != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, callbackRef));
        callbackRef = nullptr;
    }
}

static void HasDomainAccountCompletedWork(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
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
    ReturnCallbackOrPromise(asyncContext->env, asyncContext, errJs, dataJs);
    napi_close_handle_scope(asyncContext->env, scope);
    delete asyncContext;
}

NapiHasDomainInfoCallback::NapiHasDomainInfoCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred)
    : env_(env), callbackRef_(callbackRef), deferred_(deferred)
{}

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
        loop, work, [](uv_work_t *work) {}, HasDomainAccountCompletedWork);
    if (resultCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        delete asyncContext;
        delete work;
        return;
    }
    callbackRef_ = nullptr;
    deferred_ = nullptr;
}

GetAccessTokenAsyncContext::~GetAccessTokenAsyncContext()
{
    if (callbackRef != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, callbackRef));
        callbackRef = nullptr;
    }
}

NapiGetAccessTokenCallback::NapiGetAccessTokenCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred)
    : env_(env), callbackRef_(callbackRef), deferred_(deferred)
{}

void NapiGetAccessTokenCallback::OnResult(const int32_t errCode, const std::vector<uint8_t> &accessToken)
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
    auto *asyncContext = new (std::nothrow) GetAccessTokenAsyncContext();
    if (asyncContext == nullptr) {
        delete work;
        return;
    }
    asyncContext->errCode = errCode;
    asyncContext->env = env_;
    asyncContext->accessToken = accessToken;
    asyncContext->callbackRef = callbackRef_;
    asyncContext->deferred = deferred_;
    work->data = reinterpret_cast<void *>(asyncContext);
    int resultCode = uv_queue_work(
        loop, work, [](uv_work_t *work) {}, GetAccessTokenCompleteWork);
    if (resultCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        delete asyncContext;
        delete work;
        return;
    }
    callbackRef_ = nullptr;
    deferred_ = nullptr;
}

static void HasDomainAccountCompleteCB(napi_env env, napi_status status, void *data)
{
    auto *asyncContext = reinterpret_cast<HasDomainAccountAsyncContext *>(data);
    napi_delete_async_work(env, asyncContext->work);
}

static void HasDomainAccountExecuteCB(napi_env env, void *data)
{
    HasDomainAccountAsyncContext *asyncContext = reinterpret_cast<HasDomainAccountAsyncContext *>(data);
    auto callback = std::make_shared<NapiHasDomainInfoCallback>(env, asyncContext->callbackRef, asyncContext->deferred);
    asyncContext->errCode = DomainAccountClient::GetInstance().HasDomainAccount(asyncContext->domainInfo, callback);
    if (asyncContext->errCode != ERR_OK) {
        Parcel emptyParcel;
        callback->OnResult(asyncContext->errCode, emptyParcel);
    }
}

static void UpdateAccountTokenExecuteCB(napi_env env, void *data)
{
    UpdateAccountTokenAsyncContext *asyncContext = reinterpret_cast<UpdateAccountTokenAsyncContext *>(data);
    asyncContext->errCode =
        DomainAccountClient::GetInstance().UpdateAccountToken(asyncContext->domainInfo, asyncContext->token);
}

static void UpdateAccountTokenCompletedCB(napi_env env, napi_status status, void *data)
{
    UpdateAccountTokenAsyncContext *asyncContext = reinterpret_cast<UpdateAccountTokenAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode != ERR_OK) {
        errJs = GenerateBusinessError(asyncContext->env, asyncContext->errCode);
    } else {
        napi_get_null(asyncContext->env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
}

napi_value NapiDomainAccountManager::UpdateAccountToken(napi_env env, napi_callback_info cbInfo)
{
    UpdateAccountTokenAsyncContext *updateAccountTokenCB = new (std::nothrow) UpdateAccountTokenAsyncContext();
    if (updateAccountTokenCB == nullptr) {
        ACCOUNT_LOGE("insufficient memory for HasDomainAccountCB!");
        return nullptr;
    }
    std::unique_ptr<UpdateAccountTokenAsyncContext> contextPtr(updateAccountTokenCB);
    updateAccountTokenCB->env = env;
    if (!ParseParamForUpdateAccountToken(env, cbInfo, updateAccountTokenCB)) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, true);
        return nullptr;
    }
    napi_value result = nullptr;
    if (updateAccountTokenCB->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &updateAccountTokenCB->deferred, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "updateAccountToken", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        UpdateAccountTokenExecuteCB,
        UpdateAccountTokenCompletedCB,
        reinterpret_cast<void *>(updateAccountTokenCB),
        &updateAccountTokenCB->work));
    NAPI_CALL(env, napi_queue_async_work(env, updateAccountTokenCB->work));
    contextPtr.release();
    return result;
}

napi_value NapiDomainAccountManager::GetAccessToken(napi_env env, napi_callback_info cbInfo)
{
    GetAccessTokenAsyncContext *getAccessTokenCB = new (std::nothrow) GetAccessTokenAsyncContext();
    if (getAccessTokenCB == nullptr) {
        ACCOUNT_LOGE("insufficient memory for getAccessTokenCB!");
        return nullptr;
    }
    std::unique_ptr<GetAccessTokenAsyncContext> contextPtr(getAccessTokenCB);
    getAccessTokenCB->env = env;
    if (!ParseParamForGetAccessToken(env, cbInfo, getAccessTokenCB)) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, true);
        return nullptr;
    }
    napi_value result = nullptr;
    if (getAccessTokenCB->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &getAccessTokenCB->deferred, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "getAccessToken", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        GetAccessTokenExecuteCB,
        GetAccessTokenCompleteCB,
        reinterpret_cast<void *>(getAccessTokenCB),
        &getAccessTokenCB->work));
    NAPI_CALL(env, napi_queue_async_work(env, getAccessTokenCB->work));
    contextPtr.release();
    return result;
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
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        HasDomainAccountExecuteCB,
        HasDomainAccountCompleteCB,
        reinterpret_cast<void *>(hasDomainAccountCB),
        &hasDomainAccountCB->work));
    NAPI_CALL(env, napi_queue_async_work(env, hasDomainAccountCB->work));
    contextPtr.release();
    return result;
}
}  // namespace AccountJsKit
}  // namespace OHOS

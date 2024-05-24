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
#include "napi_domain_account_common.h"
#include "napi_domain_auth_callback.h"

namespace OHOS {
namespace AccountJsKit {
namespace {
const size_t ARG_SIZE_ONE = 1;
const size_t ARG_SIZE_TWO = 2;
const size_t ARG_SIZE_THREE = 3;
const size_t PARAM_ONE = 1;
const size_t PARAM_ZERO = 0;
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
    napi_env env, const std::shared_ptr<DomainAccountCallback> &nativeCallback)
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

static bool ParseParamForUpdateAccountToken(
    napi_env env, napi_callback_info cbInfo, UpdateAccountTokenAsyncContext *asyncContext)
{
    size_t argc = ARG_SIZE_THREE;
    napi_value argv[ARG_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARG_SIZE_TWO) {
        ACCOUNT_LOGE("the parameter number for updating account token should be at least two");
        std::string errMsg = "Parameter error. The number of parameters should be at least 2";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (argc == ARG_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("failed to get callbackRef for updating account token");
            std::string errMsg = "Parameter error. The type of \"callback\" must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return false;
        }
    }
    if (!ParseDomainAccountInfo(env, argv[0], asyncContext->domainInfo)) {
        ACCOUNT_LOGE("get domainInfo failed");
        std::string errMsg = "Parameter error. The type of \"domainAccountInfo\" must be DomainAccountInfo";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (ParseUint8TypedArrayToVector(env, argv[PARAM_ONE], asyncContext->token) != napi_ok) {
        ACCOUNT_LOGE("get token failed");
        std::string errMsg = "Parameter error. The type of \"token\" must be Uint8Array";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    return true;
}

static bool ParseParamForIsAuthenticationExpired(
    napi_env env, napi_callback_info cbInfo, IsAuthenticationExpiredAsyncContext *asyncContext)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("The number of parameters should be at least 1.");
        std::string errMsg = "Parameter error. The number of parameters should be at least 1";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!ParseDomainAccountInfo(env, argv[PARAM_ZERO], asyncContext->domainInfo)) {
        ACCOUNT_LOGE("Get domainInfo failed.");
        std::string errMsg = "Parameter error. The type of \"domainAccountInfo\" must be DomainAccountInfo";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    return true;
}

static bool ParseParamForGetAccessByAccount(
    napi_env env, const napi_value *argv, size_t argc, GetAccessTokenAsyncContext *asyncContext)
{
    if ((argc == ARG_SIZE_THREE) && (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1))) {
        ACCOUNT_LOGE("failed to get callbackRef for getting access token");
        return false;
    }
    if (!AppExecFwk::UnwrapWantParams(env, argv[PARAM_ONE], asyncContext->getTokenParams)) {
        ACCOUNT_LOGE("unwrapWantParams failed");
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
    if (argc < ARG_SIZE_ONE) {
        std::string errMsg = "Parameter error. The number of parameters should be at least 1";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (ParseDomainAccountInfo(env, argv[0], asyncContext->domainInfo)) {
        return ParseParamForGetAccessByAccount(env, argv, argc, asyncContext);
    }
    if ((argc == ARG_SIZE_TWO) && (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1))) {
        ACCOUNT_LOGE("failed to get callbackRef for getting access token");
        std::string errMsg = "Parameter error. The type of \"callback\" must be function";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!AppExecFwk::UnwrapWantParams(env, argv[0], asyncContext->getTokenParams)) {
        ACCOUNT_LOGE("unwrapWantParams failed");
        std::string errMsg = "Parameter error. The type of \"businessParams\" must be Record";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    return true;
}

static napi_value GetDomainAccountInfoCallback(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("GetDomainAccountInfoCallback enter");
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
    AAFwk::WantParams getAccountInfoParams;
    if (!AppExecFwk::UnwrapWantParams(env, businessData, getAccountInfoParams)) {
        ACCOUNT_LOGE("unwrapWantParams failed");
        return nullptr;
    }
    Parcel parcel;
    if (!getAccountInfoParams.Marshalling(parcel)) {
        ACCOUNT_LOGE("info Marshalling failed");
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    param->callback->OnResult(error.code, parcel);
    return nullptr;
}

static napi_value CreatePluginAccountInfoOptions(const JsDomainPluginParam *param)
{
    napi_value napiOptions = nullptr;
    NAPI_CALL(param->env, napi_create_object(param->env, &napiOptions));
    napi_value napiName = nullptr;
    NAPI_CALL(param->env, napi_create_string_utf8(
        param->env, param->domainAccountInfo.accountName_.c_str(), NAPI_AUTO_LENGTH, &napiName));
    NAPI_CALL(param->env, napi_set_named_property(param->env, napiOptions, "accountName", napiName));
    napi_value napiDomain = nullptr;
    NAPI_CALL(param->env,
        napi_create_string_utf8(param->env, param->domainAccountInfo.domain_.c_str(), NAPI_AUTO_LENGTH, &napiDomain));
    NAPI_CALL(param->env, napi_set_named_property(param->env, napiOptions, "domain", napiDomain));
    napi_value napiCallingUid = nullptr;
    NAPI_CALL(param->env, napi_create_int32(param->env, param->callingUid, &napiCallingUid));
    NAPI_CALL(param->env, napi_set_named_property(param->env, napiOptions, "callerUid", napiCallingUid));
    return napiOptions;
}

static void GetDomainAccountInfoWork(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    JsDomainPluginParam *param = reinterpret_cast<JsDomainPluginParam *>(work->data);
    napi_value napiCallback = CreatePluginAsyncCallback(param->env, GetDomainAccountInfoCallback, param);
    napi_value getDomainAccountInfoPLuginOptions = CreatePluginAccountInfoOptions(param);
    napi_value argv[] = {getDomainAccountInfoPLuginOptions, napiCallback};
    NapiCallVoidFunction(param->env, argv, ARG_SIZE_TWO, param->func);
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->count--;
    param->lockInfo->condition.notify_all();
    napi_close_handle_scope(param->env, scope);
    if (napiCallback == nullptr) {
        delete param;
    }
}

static napi_value OnAccountBoundCallback(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("OnAccountBoundCallback enter");
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
    napi_close_handle_scope(param->env, scope);
    if (napiCallback == nullptr) {
        delete param;
    }
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
    napi_close_handle_scope(param->env, scope);
    if (napiCallback == nullptr) {
        delete param;
    }
}

static napi_value GetAuthStatusInfoCallback(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("GetAuthStatusInfoCallback enter");
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
    ACCOUNT_LOGI("GetAccessTokenCallback enter");
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
    ACCOUNT_LOGI("IsUserTokenValidCallback enter");
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
    napi_close_handle_scope(param->env, scope);
    if (napiCallback == nullptr) {
        delete param;
    }
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
    napi_close_handle_scope(param->env, scope);
    if (napiCallback == nullptr) {
        delete param;
    }
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
    napi_close_handle_scope(param->env, scope);
    if (napiCallback == nullptr) {
        delete param;
    }
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
    argv[argc++] = CreateNapiDomainAuthCallback(param->env, param->callback);
    NapiCallVoidFunction(param->env, argv, argc, param->func);
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->count--;
    param->lockInfo->condition.notify_all();
    napi_close_handle_scope(param->env, scope);
    delete param;
}

void NapiDomainAccountPlugin::AuthCommon(AccountSA::AuthMode authMode, const AccountSA::DomainAccountInfo &info,
    const std::vector<uint8_t> &authData, const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
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
    param->callback = callback;
    param->domainAccountInfo = info;
    param->authMode = authMode;
    param->authData = authData;
    int errCode = uv_queue_work_with_qos(loop, work, [](uv_work_t *work) {}, AuthCommonWork, uv_qos_user_initiated);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work_with_qos, errCode: %{public}d", errCode);
        delete param;
        delete work;
        return;
    }
    lockInfo_.count++;
}

void NapiDomainAccountPlugin::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &credential,
    const std::shared_ptr<DomainAccountCallback> &callback)
{
    AuthCommon(AUTH_WITH_CREDENTIAL_MODE, info, credential, callback);
}

void NapiDomainAccountPlugin::AuthWithPopup(
    const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback)
{
    AuthCommon(AUTH_WITH_POPUP_MODE, info, {}, callback);
}

void NapiDomainAccountPlugin::AuthWithToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
    const std::shared_ptr<DomainAccountCallback> &callback)
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
    int errCode = uv_queue_work_with_qos(
        loop, work, [](uv_work_t *work) {}, GetAuthStatusInfoWork, uv_qos_default);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work_with_qos, errCode: %{public}d", errCode);
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
        ACCOUNT_LOGE("OnAccountBound function of the js plugin is undefined");
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
    int errCode = uv_queue_work_with_qos(loop, work, [](uv_work_t *work) {}, OnAccountBoundWork, uv_qos_default);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work_with_qos, errCode: %{public}d", errCode);
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
        ACCOUNT_LOGE("OnAccountUnBound function of the js plugin is undefined");
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
    int errCode = uv_queue_work_with_qos(
        loop, work, [](uv_work_t *work) {}, OnAccountUnBoundWork, uv_qos_default);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work_with_qos, errCode: %{public}d", errCode);
        delete work;
        delete param;
        return;
    }
    lockInfo_.count++;
}

void NapiDomainAccountPlugin::GetDomainAccountInfo(const GetDomainAccountInfoOptions &options,
    const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if (lockInfo_.count < 0) {
        ACCOUNT_LOGE("the plugin has been released");
        return;
    }
    if (jsPlugin_.getDomainAccountInfo == nullptr) {
        ACCOUNT_LOGE("GetDomainAccountInfo function of the js plugin is undefined");
        return;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsDomainPluginParam *param = nullptr;
    if (!InitDomainPluginExecEnv(env_, &loop, &work, &param, &lockInfo_)) {
        ACCOUNT_LOGE("failed to init domain plugin execution environment");
        return;
    }
    param->domainAccountInfo = options.accountInfo;
    param->callingUid = options.callingUid;
    param->callback = callback;
    param->func = jsPlugin_.getDomainAccountInfo;
    int errCode = uv_queue_work_with_qos(
        loop, work, [](uv_work_t *work) {}, GetDomainAccountInfoWork, uv_qos_default);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work_with_qos, errCode: %{public}d", errCode);
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
    int errCode = uv_queue_work_with_qos(
        loop, work, [](uv_work_t *work) {}, IsUserTokenValidWork, uv_qos_default);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work_with_qos, errCode: %{public}d", errCode);
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
    int errCode = uv_queue_work_with_qos(
        loop, work, [](uv_work_t *work) {}, GetAccessTokenWork, uv_qos_default);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work_with_qos, errCode: %{public}d", errCode);
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
        DECLARE_NAPI_STATIC_FUNCTION("hasAccount", HasAccount),
        DECLARE_NAPI_STATIC_FUNCTION("updateAccountToken", UpdateAccountToken),
        DECLARE_NAPI_STATIC_FUNCTION("isAuthenticationExpired", IsAuthenticationExpired),
        DECLARE_NAPI_STATIC_FUNCTION("getAccessToken", GetAccessToken),
        DECLARE_NAPI_STATIC_FUNCTION("getAccountInfo", GetDomainAccountInfo),
        DECLARE_NAPI_STATIC_FUNCTION("updateAccountInfo", UpdateAccountInfo),
        DECLARE_NAPI_FUNCTION("registerPlugin", RegisterPlugin),
        DECLARE_NAPI_FUNCTION("unregisterPlugin", UnregisterPlugin),
        DECLARE_NAPI_FUNCTION("hasAccount", HasAccount),
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
        std::string errMsg = "Parameter error. The type of \"plugin\" must be DomainPlugin";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
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
        std::string errMsg = "Parameter error. The number of parameters should be at least 1";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (argc == ARG_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "Parameter error. The type of \"callback\" must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return false;
        }
    }
    if (!ParseDomainAccountInfo(env, argv[0], asyncContext->domainInfo)) {
        ACCOUNT_LOGE("get domainInfo failed");
        std::string errMsg = "Parameter error. The type of \"domainAccountInfo\" must be DomainAccountInfo";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
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
        std::string errMsg = "Parameter error. The number of parameters should be at least 3";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    int index = 0;
    if (!ParseDomainAccountInfo(env, argv[index++], authContext.domainAccountInfo)) {
        ACCOUNT_LOGE("get domainInfo failed");
        std::string errMsg = "Parameter error. The type of \"domainAccountInfo\" must be DomainAccountInfo";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (ParseUint8TypedArrayToVector(env, argv[index++], authContext.authData) != napi_ok) {
        ACCOUNT_LOGE("get credential failed");
        std::string errMsg = "Parameter error. The type of \"credential\" must be Uint8Array";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!GetNamedJsFunction(env, argv[index++], "onResult", authContext.callbackRef)) {
        ACCOUNT_LOGE("get callback failed");
        std::string errMsg = "Parameter error. The type of \"callback\" must be IUserAuthCallback";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    return true;
}

void AuthCompletedCallback(napi_env env, napi_status status, void *data)
{
    delete reinterpret_cast<JsDomainPluginParam *>(data);
}

napi_value NapiDomainAccountManager::Auth(napi_env env, napi_callback_info cbInfo)
{
    auto authContext = std::make_unique<JsDomainPluginParam>(env);
    if (!ParseContextForAuth(env, cbInfo, *authContext)) {
        return nullptr;
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "Auth", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            JsDomainPluginParam *param = reinterpret_cast<JsDomainPluginParam *>(data);
            auto jsCallback = std::make_shared<JsDomainAccountAuthCallback>(env, param->callbackRef);
            auto callback = std::make_shared<NapiDomainAccountCallback>(env, jsCallback);
            param->callbackRef = nullptr;
            param->errCode = DomainAccountClient::GetInstance().Auth(
                param->domainAccountInfo, param->authData, callback);
            if (param->errCode != ERR_OK) {
                Parcel emptyParcel;
                AccountSA::DomainAuthResult emptyResult;
                if (!emptyResult.Marshalling(emptyParcel)) {
                    ACCOUNT_LOGE("authResult Marshalling failed");
                    return;
                }
                callback->OnResult(ConvertToJSErrCode(param->errCode), emptyParcel);
            }
        },
        AuthCompletedCallback,
        reinterpret_cast<void *>(authContext.get()), &authContext->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, authContext->work, napi_qos_user_initiated));
    authContext.release();
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
        std::string errMsg = "Parameter error. The number of parameters should be at least 1";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!GetNamedJsFunction(env, argv[argc - 1], "onResult", authWithPopupContext.callbackRef)) {
        ACCOUNT_LOGE("get callback failed");
        std::string errMsg = "Parameter error. The type of \"callback\" must be function";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (argc == ARG_SIZE_TWO) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[0], &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("the userId is undefined or null");
        } else {
            if (!GetIntProperty(env, argv[0], authWithPopupContext.userId)) {
                std::string errMsg = "Parameter error. The type of \"localId\" must be number";
                AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
                ACCOUNT_LOGE("get id failed");
                return false;
            }
        }
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
    asyncContext->callbackRef = nullptr;
}

static void GetAccessTokenCompleteCB(napi_env env, napi_status status, void *data)
{
    delete reinterpret_cast<GetAccessTokenAsyncContext *>(data);
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
    auto authWithPopupContext = std::make_unique<JsDomainPluginParam>(env);
    if (!ParseContextForAuthWithPopup(env, cbInfo, *authWithPopupContext)) {
        return nullptr;
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "AuthWithPopup", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            JsDomainPluginParam *param = reinterpret_cast<JsDomainPluginParam *>(data);
            auto jsCallback = std::make_shared<JsDomainAccountAuthCallback>(env, param->callbackRef);
            auto callback = std::make_shared<NapiDomainAccountCallback>(env, jsCallback);
            param->callbackRef = nullptr;
            param->errCode = DomainAccountClient::GetInstance().AuthWithPopup(param->userId, callback);
            if (param->errCode != ERR_OK) {
                Parcel emptyParcel;
                AccountSA::DomainAuthResult emptyResult;
                if (!emptyResult.Marshalling(emptyParcel)) {
                    ACCOUNT_LOGE("authResult Marshalling failed");
                    return;
                }
                callback->OnResult(ConvertToJSErrCode(param->errCode), emptyParcel);
            }
        },
        AuthCompletedCallback,
        reinterpret_cast<void *>(authWithPopupContext.get()), &authWithPopupContext->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, authWithPopupContext->work, napi_qos_user_initiated));
    authWithPopupContext.release();
    return nullptr;
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
    auto *asyncContext = new (std::nothrow) HasDomainAccountAsyncContext(env_);
    if (asyncContext == nullptr) {
        delete work;
        return;
    }
    if (errCode == ERR_OK) {
        parcel.ReadBool(asyncContext->isHasDomainAccount);
    }
    asyncContext->errCode = errCode;
    asyncContext->callbackRef = callbackRef_;
    asyncContext->deferred = deferred_;
    work->data = reinterpret_cast<void *>(asyncContext);
    int resultCode = uv_queue_work_with_qos(
        loop, work, [](uv_work_t *work) {}, HasDomainAccountCompletedWork, uv_qos_default);
    if (resultCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work_with_qos, errCode: %{public}d", errCode);
        delete asyncContext;
        delete work;
        return;
    }
    callbackRef_ = nullptr;
    deferred_ = nullptr;
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
    auto *asyncContext = new (std::nothrow) GetAccessTokenAsyncContext(env_);
    if (asyncContext == nullptr) {
        delete work;
        return;
    }
    asyncContext->errCode = errCode;
    asyncContext->accessToken = accessToken;
    asyncContext->callbackRef = callbackRef_;
    asyncContext->deferred = deferred_;
    work->data = reinterpret_cast<void *>(asyncContext);
    int resultCode = uv_queue_work_with_qos(
        loop, work, [](uv_work_t *work) {}, GetAccessTokenCompleteWork, uv_qos_default);
    if (resultCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work_with_qos, errCode: %{public}d", errCode);
        delete asyncContext;
        delete work;
        return;
    }
    callbackRef_ = nullptr;
    deferred_ = nullptr;
}

static void HasDomainAccountCompleteCB(napi_env env, napi_status status, void *data)
{
    delete reinterpret_cast<HasDomainAccountAsyncContext *>(data);
}

static void HasDomainAccountExecuteCB(napi_env env, void *data)
{
    HasDomainAccountAsyncContext *asyncContext = reinterpret_cast<HasDomainAccountAsyncContext *>(data);
    auto callback = std::make_shared<NapiHasDomainInfoCallback>(env, asyncContext->callbackRef, asyncContext->deferred);
    asyncContext->errCode = DomainAccountClient::GetInstance().HasAccount(asyncContext->domainInfo, callback);
    if (asyncContext->errCode != ERR_OK) {
        Parcel emptyParcel;
        callback->OnResult(asyncContext->errCode, emptyParcel);
    }
    asyncContext->callbackRef = nullptr;
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
    delete asyncContext;
}

napi_value NapiDomainAccountManager::UpdateAccountToken(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<UpdateAccountTokenAsyncContext>(env);
    if (!ParseParamForUpdateAccountToken(env, cbInfo, context.get())) {
        return nullptr;
    }
    napi_value result = nullptr;
    if (context->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "updateAccountToken", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        UpdateAccountTokenExecuteCB,
        UpdateAccountTokenCompletedCB,
        reinterpret_cast<void *>(context.get()),
        &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return result;
}

static void IsAuthenticationExpiredExecuteCB(napi_env env, void *data)
{
    IsAuthenticationExpiredAsyncContext *asyncContext = reinterpret_cast<IsAuthenticationExpiredAsyncContext *>(data);
    asyncContext->errCode =
        DomainAccountClient::GetInstance().IsAuthenticationExpired(asyncContext->domainInfo, asyncContext->isExpired);
}

static void IsAuthenticationExpiredCompletedCB(napi_env env, napi_status status, void *data)
{
    IsAuthenticationExpiredAsyncContext *asyncContext = reinterpret_cast<IsAuthenticationExpiredAsyncContext *>(data);
    std::unique_ptr<IsAuthenticationExpiredAsyncContext> asyncContextPtr{asyncContext};
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == ERR_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &errJs));
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncContext->isExpired, &dataJs));
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode);
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &dataJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
}

napi_value NapiDomainAccountManager::IsAuthenticationExpired(napi_env env, napi_callback_info cbInfo)
{
    auto asyncContextPtr = std::make_unique<IsAuthenticationExpiredAsyncContext>(env);
    if (!ParseParamForIsAuthenticationExpired(env, cbInfo, asyncContextPtr.get())) {
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &asyncContextPtr->deferred, &result));

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "IsAuthenticationExpired", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        IsAuthenticationExpiredExecuteCB,
        IsAuthenticationExpiredCompletedCB,
        reinterpret_cast<void *>(asyncContextPtr.get()),
        &asyncContextPtr->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContextPtr->work, napi_qos_default));
    asyncContextPtr.release();
    return result;
}

napi_value NapiDomainAccountManager::GetAccessToken(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<GetAccessTokenAsyncContext>(env);
    if (!ParseParamForGetAccessToken(env, cbInfo, context.get())) {
        return nullptr;
    }
    napi_value result = nullptr;
    if (context->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "getAccessToken", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        GetAccessTokenExecuteCB, GetAccessTokenCompleteCB,
        reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return result;
}

napi_value NapiDomainAccountManager::HasAccount(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<HasDomainAccountAsyncContext>(env);
    if (!ParseParamForHasDomainAccount(env, cbInfo, context.get())) {
        return nullptr;
    }
    napi_value result = nullptr;
    if (context->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "hasAccount", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        HasDomainAccountExecuteCB,
        HasDomainAccountCompleteCB,
        reinterpret_cast<void *>(context.get()),
        &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return result;
}

static bool ParseGetDomainAccountInfoOptions(napi_env env, napi_value object, DomainAccountInfo &info)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, object, &type);
    if (type != napi_object) {
        ACCOUNT_LOGE("Value is not an object.");
        return false;
    }
    if (!GetStringPropertyByKey(env, object, "accountName", info.accountName_)) {
        ACCOUNT_LOGE("get domainInfo's accountName failed");
        return false;
    }
    bool hasProp = false;
    napi_has_named_property(env, object, "domain", &hasProp);
    if (hasProp) {
        napi_value value = nullptr;
        napi_get_named_property(env, object, "domain", &value);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, value, &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("the accountId is undefined or null");
        } else if (!GetStringPropertyByKey(env, object, "domain", info.domain_)) {
            ACCOUNT_LOGE("get domainInfo's domain failed");
            return false;
        }
    }
    return true;
}

static bool ParseParamForGetAccountInfo(
    napi_env env, napi_callback_info cbInfo, GetAccountInfoAsyncContext *asyncContext)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("the parameter of number should be at least one");
        std::string errMsg = "Parameter error. The number of parameters should be at least 1";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (argc == ARG_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "Parameter error. The type of \"callback\" must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return false;
        }
    }
    if (!ParseGetDomainAccountInfoOptions(env, argv[0], asyncContext->domainInfo)) {
        ACCOUNT_LOGE("get domainInfo failed");
        std::string errMsg = "Parameter error. The type of \"options\" must be GetDomainAccountInfoOptions";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    return true;
}

static void GetAccountInfoCompleteWork(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        if ((work != nullptr) && (work->data != nullptr)) {
            delete reinterpret_cast<GetAccountInfoAsyncContext *>(work->data);
        }
        return;
    }
    GetAccountInfoAsyncContext *asyncContext = reinterpret_cast<GetAccountInfoAsyncContext *>(work->data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == ERR_OK) {
        dataJs = AppExecFwk::WrapWantParams(asyncContext->env, asyncContext->getAccountInfoParams);
    } else {
        errJs = GenerateBusinessError(asyncContext->env, asyncContext->errCode);
    }
    ReturnCallbackOrPromise(asyncContext->env, asyncContext, errJs, dataJs);
    napi_close_handle_scope(asyncContext->env, scope);
    delete asyncContext;
}

NapiGetAccountInfoCallback::NapiGetAccountInfoCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred)
    : env_(env), callbackRef_(callbackRef), deferred_(deferred)
{}

void NapiGetAccountInfoCallback::OnResult(const int32_t errCode, Parcel &parcel)
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
    auto *asyncContext = new (std::nothrow) GetAccountInfoAsyncContext(env_);
    if (asyncContext == nullptr) {
        delete work;
        return;
    }
    if (errCode == ERR_OK) {
        std::shared_ptr<AAFwk::WantParams> parameters(AAFwk::WantParams::Unmarshalling(parcel));
        asyncContext->getAccountInfoParams = *parameters;
    }
    asyncContext->errCode = errCode;
    asyncContext->callbackRef = callbackRef_;
    asyncContext->deferred = deferred_;
    work->data = reinterpret_cast<void *>(asyncContext);
    int resultCode = uv_queue_work(
        loop, work, [](uv_work_t *work) {}, GetAccountInfoCompleteWork);
    if (resultCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        delete asyncContext;
        delete work;
        return;
    }
    callbackRef_ = nullptr;
    deferred_ = nullptr;
}

static void GetAccountInfoExecuteCB(napi_env env, void *data)
{
    GetAccountInfoAsyncContext *asyncContext = reinterpret_cast<GetAccountInfoAsyncContext *>(data);
    auto callback =
        std::make_shared<NapiGetAccountInfoCallback>(env, asyncContext->callbackRef, asyncContext->deferred);
    asyncContext->errCode = DomainAccountClient::GetInstance().GetDomainAccountInfo(asyncContext->domainInfo, callback);
    if (asyncContext->errCode != ERR_OK) {
        Parcel emptyParcel;
        callback->OnResult(asyncContext->errCode, emptyParcel);
    }
    asyncContext->callbackRef = nullptr;
}

static void GetAccountInfoCompleteCB(napi_env env, napi_status status, void *data)
{
    delete reinterpret_cast<GetAccountInfoAsyncContext *>(data);
}

napi_value NapiDomainAccountManager::GetDomainAccountInfo(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<GetAccountInfoAsyncContext>(env);
    if (!ParseParamForGetAccountInfo(env, cbInfo, context.get())) {
        return nullptr;
    }
    napi_value result = nullptr;
    if (context->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "getAccountInfo", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        GetAccountInfoExecuteCB, GetAccountInfoCompleteCB,
        reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return result;
}

static bool ParseParamForUpdateAccountInfo(
    napi_env env, napi_callback_info cbInfo, UpdateAccountInfoAsyncContext *asyncContext)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc != ARG_SIZE_TWO) {
        ACCOUNT_LOGE("The parameter of number should be two");
        std::string errMsg = "Parameter error. The number of parameters should be at least 2";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!ParseDomainAccountInfo(env, argv[0], asyncContext->oldAccountInfo)) {
        ACCOUNT_LOGE("Get oldAccountInfo failed");
        std::string errMsg = "Parameter error. The type of \"oldAccountInfo\" must be DomainAccountInfo";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!ParseDomainAccountInfo(env, argv[1], asyncContext->newAccountInfo)) {
        ACCOUNT_LOGE("Get newAccountInfo failed");
        std::string errMsg = "Parameter error. The type of \"newAccountInfo\" must be DomainAccountInfo";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    return true;
}

static void UpdateAccountInfoExecuteCB(napi_env env, void *data)
{
    UpdateAccountInfoAsyncContext *asyncContext = reinterpret_cast<UpdateAccountInfoAsyncContext *>(data);
    asyncContext->errCode = DomainAccountClient::GetInstance().UpdateAccountInfo(
        asyncContext->oldAccountInfo, asyncContext->newAccountInfo);
}

static void UpdateAccountInfoCompleteCB(napi_env env, napi_status status, void *data)
{
    UpdateAccountInfoAsyncContext *asyncContext = reinterpret_cast<UpdateAccountInfoAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode != ERR_OK) {
        errJs = GenerateBusinessError(asyncContext->env, asyncContext->errCode);
    } else {
        napi_get_null(asyncContext->env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    delete asyncContext;
}

napi_value NapiDomainAccountManager::UpdateAccountInfo(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<UpdateAccountInfoAsyncContext>(env);
    if (!ParseParamForUpdateAccountInfo(env, cbInfo, context.get())) {
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "UpdateAccountInfo", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        UpdateAccountInfoExecuteCB, UpdateAccountInfoCompleteCB,
        reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return result;
}
}  // namespace AccountJsKit
}  // namespace OHOS

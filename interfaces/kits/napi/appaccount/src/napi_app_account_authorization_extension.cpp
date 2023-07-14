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

#include "napi_app_account_authorization_extension.h"

#include <memory>
#include <uv.h>
#include "ability_info.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "app_account_authorization_extension_service.h"
#include "app_account_common.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_account_common.h"
#include "napi_account_error.h"
#include "napi_common_want.h"
#include "napi_remote_object.h"
#include "js_extension_common.h"
#include "js_extension_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace AccountJsKit {
namespace {
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
const char BUSINESS_ERROR_CODE_NAME[] = "code";
const char BUSINESS_ERROR_MESSAGE_NAME[] = "message";
const char BUSINESS_ERROR_DATA_NAME[] = "data";
}

using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AccountSA;

static bool ParseAsyncCallbackError(napi_env env, napi_value value, AsyncCallbackError &error)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valueType), false);
    if (valueType == napi_null || (valueType == napi_undefined)) {
        error.code = 0;
        return true;
    }
    napi_value napiCode = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, BUSINESS_ERROR_CODE_NAME, &napiCode), false);
    if (napiCode == nullptr) {
        ACCOUNT_LOGE("code is undefined");
        return false;
    }
    NAPI_CALL_BASE(env, napi_get_value_int32(env, napiCode, &error.code), false);
    bool hasData = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, value, BUSINESS_ERROR_MESSAGE_NAME, &hasData), false);
    if (hasData) {
        napi_value asyncCallbackMessage = nullptr;
        NAPI_CALL_BASE(
            env, napi_get_named_property(env, value, BUSINESS_ERROR_MESSAGE_NAME, &asyncCallbackMessage), false);
        valueType = napi_undefined;
        NAPI_CALL_BASE(env, napi_typeof(env, asyncCallbackMessage, &valueType), false);
        if ((valueType != napi_null) && (valueType != napi_undefined) &&
            (!GetStringPropertyByKey(env, value, BUSINESS_ERROR_MESSAGE_NAME, error.message))) {
            ACCOUNT_LOGE("parse request business message failed");
            return false;
        }
    }
    NAPI_CALL_BASE(env, napi_has_named_property(env, value, BUSINESS_ERROR_DATA_NAME, &hasData), false);
    if (hasData) {
        napi_value asyncCallbackErrorData = nullptr;
        NAPI_CALL_BASE(
            env, napi_get_named_property(env, value, BUSINESS_ERROR_DATA_NAME, &asyncCallbackErrorData), false);
        valueType = napi_undefined;
        NAPI_CALL_BASE(env, napi_typeof(env, asyncCallbackErrorData, &valueType), false);
        if ((valueType != napi_null) && (valueType != napi_undefined) &&
            (!AppExecFwk::UnwrapWantParams(env, asyncCallbackErrorData, error.data))) {
            ACCOUNT_LOGE("parse request businessError data failed");
            return false;
        }
    }
    return true;
}

static bool GetExtentionCallbackCommonParam(napi_env env, napi_callback_info cbInfo,
    JsAppAuthorizationExtensionParam **param, AsyncCallbackError &error, napi_value *businessData)
{
    size_t argc = ARGC_TWO;
    napi_value argv[ARGC_TWO] = {nullptr};
    void *data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, &data), false);
    if (argc < ARGC_ONE) {
        ACCOUNT_LOGE("the number of argument should be at least 1");
        return false;
    }
    *param = reinterpret_cast<JsAppAuthorizationExtensionParam *>(data);
    if ((*param == nullptr) || ((*param)->callback == nullptr)) {
        ACCOUNT_LOGE("native callback is nullptr");
        return false;
    }
    if (!ParseAsyncCallbackError(env, argv[0], error)) {
        ACCOUNT_LOGE("parseBussinessError failed");
        return false;
    }
    if (argc == ARGC_TWO) {
        *businessData = argv[ARGC_ONE];
    }
    return true;
}

static bool InitAuthorizationExtensionExecEnv(napi_env env, uv_loop_s **loop, uv_work_t **work,
    JsAppAuthorizationExtensionParam **param, ThreadLockInfo *lockInfo)
{
    if (!CreateExecEnv(env, loop, work)) {
        return false;
    }
    *param = new (std::nothrow) JsAppAuthorizationExtensionParam(env);
    if (*param == nullptr) {
        ACCOUNT_LOGE("failed to create JsAppAuthorizationExtensionParam");
        delete *work;
        *work = nullptr;
        return false;
    }
    (*param)->lockInfo = lockInfo;
    (*work)->data = reinterpret_cast<void *>(*param);
    return true;
}

static napi_value CreateExtensionAsyncCallback(
    napi_env env, napi_callback callback, JsAppAuthorizationExtensionParam *param)
{
    napi_value napiCallback = nullptr;
    napi_status status = napi_create_function(env, "callback", NAPI_AUTO_LENGTH, callback, param, &napiCallback);
    if (status != napi_ok) {
        ACCOUNT_LOGE("failed to create js function");
        return nullptr;
    }
    status = napi_wrap(
        env, napiCallback, param,
        [](napi_env env, void *data, void *hint) {
            delete reinterpret_cast<JsAppAuthorizationExtensionParam *>(data);
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        ACCOUNT_LOGE("failed to wrap callback with JsAppAuthorizationExtensionParam");
        return nullptr;
    }
    return napiCallback;
}

static napi_value OnResultCallback(napi_env env, napi_callback_info cbInfo)
{
    JsAppAuthorizationExtensionParam *param = nullptr;
    AsyncCallbackError error;
    napi_value businessData = nullptr;
    if (!GetExtentionCallbackCommonParam(env, cbInfo, &param, error, &businessData)) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, true);
        return nullptr;
    }
    AAFwk::WantParams parameters;
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, businessData, &valueType);
    if ((valueType != napi_null) && (valueType != napi_undefined) &&
        (!AppExecFwk::UnwrapWantParams(env, businessData, parameters))) {
        ACCOUNT_LOGE("parse request WantParams failed");
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, true);
        return nullptr;
    }

    param->callback->OnResult(error, parameters);
    return nullptr;
}

JsAppAuthorizationExtensionParam::JsAppAuthorizationExtensionParam(napi_env napiEnv)
{
    env = napiEnv;
}

static napi_value CreateNapiRequest(napi_env env, JsAppAuthorizationExtensionParam *param)
{
    napi_value napiRequest = nullptr;
    NAPI_CALL(env, napi_create_object(env, &napiRequest));
    napi_value napiUid = nullptr;
    NAPI_CALL(env, napi_create_int32(env, param->request.callerUid, &napiUid));
    NAPI_CALL(env, napi_set_named_property(env, napiRequest, "callerUid", napiUid));
    napi_value napiParam = AppExecFwk::WrapWantParams(env, param->request.parameters);
    NAPI_CALL(env, napi_set_named_property(env, napiRequest, "parameters", napiParam));
    return napiRequest;
}

static napi_value CreateAuthorizationCallback(napi_env env, JsAppAuthorizationExtensionParam *param)
{
    napi_value authorizationCallback = nullptr;
    NAPI_CALL(env, napi_create_object(env, &authorizationCallback));
    napi_value napiCallback = CreateExtensionAsyncCallback(env, OnResultCallback, param);
    NAPI_CALL(env, napi_set_named_property(env, authorizationCallback, "onResult", napiCallback));
    return authorizationCallback;
}

JsAuthorizationExtension* JsAuthorizationExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    return new JsAuthorizationExtension(static_cast<JsRuntime&>(*runtime));
}

JsAuthorizationExtension::JsAuthorizationExtension(JsRuntime& jsRuntime) : jsRuntime_(jsRuntime) {}

JsAuthorizationExtension::~JsAuthorizationExtension()
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    lockInfo_.condition.wait(lock, [this] { return this->lockInfo_.count == 0; });
    lockInfo_.count--;
    jsRuntime_.FreeNativeReference(std::move(jsObj_));
}

void JsAuthorizationExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    AuthorizationExtension::Init(record, application, handler, token);
    std::string srcPath = "";
    GetSrcPath(srcPath);
    if (srcPath.empty()) {
        ACCOUNT_LOGE("Failed to get srcPath");
        return;
    }

    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(Extension::abilityInfo_->name);
    HandleScope handleScope(jsRuntime_);

    jsObj_ = jsRuntime_.LoadModule(moduleName, srcPath, Extension::abilityInfo_->hapPath,
        Extension::abilityInfo_->compileMode == CompileMode::ES_MODULE);
    if (jsObj_ == nullptr) {
        ACCOUNT_LOGE("Failed to get jsObj_");
        return;
    }
}

void JsAuthorizationExtension::OnStart(const AAFwk::Want &want)
{
    Extension::OnStart(want);
}

static void DeleteParamLocked(JsAppAuthorizationExtensionParam *param, napi_handle_scope &scope)
{
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->count--;
    param->lockInfo->condition.notify_all();
    delete param;
    napi_close_handle_scope(param->env, scope);
}

static void StartAuthorizationWork(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    JsAppAuthorizationExtensionParam *param = reinterpret_cast<JsAppAuthorizationExtensionParam *>(work->data);
    if (param->authorizationExtension == nullptr) {
        DeleteParamLocked(param, scope);
        return;
    }
    napi_value napiRequest = CreateNapiRequest(param->env, param);
    NativeValue *nativeRequest = reinterpret_cast<NativeValue *>(napiRequest);
    napi_value napiAuthorizationCallback = CreateAuthorizationCallback(param->env, param);
    if (napiAuthorizationCallback == nullptr) {
        DeleteParamLocked(param, scope);
        return;
    }
    NativeValue *nativeAuthorizationCallback = reinterpret_cast<NativeValue *>(napiAuthorizationCallback);
    NativeValue *argv[] = {nativeRequest, nativeAuthorizationCallback};
    param->authorizationExtension->CallObjectMethod("onStartAuthorization", argv, ARGC_TWO);
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->count--;
    param->lockInfo->condition.notify_all();
    napi_close_handle_scope(param->env, scope);
}

void JsAuthorizationExtension::StartAuthorization(const AccountSA::AuthorizationRequest &request,
    const std::shared_ptr<AccountSA::AppAccountAuthorizationExtensionCallbackClient> &callbackPtr,
    const std::shared_ptr<JsAuthorizationExtension> &extension)
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if (lockInfo_.count < 0) {
        ACCOUNT_LOGE("the extension has been released");
        return;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    JsAppAuthorizationExtensionParam *param = nullptr;
    NativeEngine *nativeEngine = &jsRuntime_.GetNativeEngine();
    if (!InitAuthorizationExtensionExecEnv(
        reinterpret_cast<napi_env>(nativeEngine), &loop, &work, &param, &lockInfo_)) {
        ACCOUNT_LOGE("failed to init authorization extension execution environment");
        return;
    }
    param->request = request;
    param->callback = callbackPtr;
    param->authorizationExtension = extension;

    int errCode = uv_queue_work(
        loop, work, [](uv_work_t *work) {}, StartAuthorizationWork);
    if (errCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        delete work;
        delete param;
        return;
    }
    lockInfo_.count++;
}

sptr<IRemoteObject> JsAuthorizationExtension::OnConnect(const OHOS::AAFwk::Want& want)
{
    ErrCode errCode = AccountPermissionManager::CheckSystemApp();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("the caller is not system application, errCode = %{public}d.", errCode);
        return nullptr;
    }
    Extension::OnConnect(want);
    if (providerRemoteObject_ == nullptr) {
        std::shared_ptr<JsAuthorizationExtension> authorizationExtension =
            std::static_pointer_cast<JsAuthorizationExtension>(shared_from_this());
        sptr<AppAccountAuthorizationExtensionService> providerService =
            new (std::nothrow) AppAccountAuthorizationExtensionService(authorizationExtension);
        if (providerService == nullptr) {
            ACCOUNT_LOGE("providerService is nullptr");
            return nullptr;
        }
        providerRemoteObject_ = providerService->AsObject();
    }
    return providerRemoteObject_;
}

NativeValue *JsAuthorizationExtension::CallObjectMethod(const std::string &name, NativeValue *const *argv, size_t argc)
{
    if (!jsObj_) {
        ACCOUNT_LOGE("not found AuthorizationExtension.js");
        return nullptr;
    }

    HandleScope handleScope(jsRuntime_);
    auto &nativeEngine = jsRuntime_.GetNativeEngine();

    NativeValue *value = jsObj_->Get();
    NativeObject *obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        ACCOUNT_LOGE("Failed to get AuthorizationExtension object");
        return nullptr;
    }

    NativeValue *method = obj->GetProperty(name.c_str());
    if ((method == nullptr) || (method->TypeOf() != NATIVE_FUNCTION)) {
        ACCOUNT_LOGE("Failed to get '%{public}s' from AuthorizationExtension object", name.c_str());
        return nullptr;
    }
    return nativeEngine.CallFunction(value, method, argv, argc);
}

void JsAuthorizationExtension::GetSrcPath(std::string &srcPath)
{
    if (!Extension::abilityInfo_->isModuleJson) {
        /* temporary compatibility api8 + config.json */
        srcPath.append(Extension::abilityInfo_->package);
        srcPath.append("/assets/js/");
        if (!Extension::abilityInfo_->srcPath.empty()) {
            srcPath.append(Extension::abilityInfo_->srcPath);
        }
        srcPath.append("/").append(Extension::abilityInfo_->name).append(".abc");
        return;
    }

    if (!Extension::abilityInfo_->srcEntrance.empty()) {
        srcPath.append(Extension::abilityInfo_->moduleName + "/");
        srcPath.append(Extension::abilityInfo_->srcEntrance);
        srcPath.erase(srcPath.rfind('.'));
        srcPath.append(".abc");
    }
}
} // namespace AccountJsKit
} // namespace OHOS
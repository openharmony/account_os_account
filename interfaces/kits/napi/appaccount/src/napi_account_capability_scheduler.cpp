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

#include "napi_account_capability_scheduler.h"

#include "account_log_wrapper.h"
#include "app_account_manager.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_account_error.h"
#include "napi_common.h"
#include "want.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;

#define RETURN_IF_NEED_THROW_ERROR(env, condition, message)                               \
    if (!(condition)) {                                                                   \
        std::string msg = (message);                                                      \
        napi_throw((env), GenerateBusinessError((env), ERR_JS_PARAMETER_ERROR, msg));     \
        ACCOUNT_LOGE("%{public}s", (message));                                            \
        return nullptr;                                                                   \
    }

namespace {
const size_t ARG_SIZE_ONE = 1;
const size_t ARG_SIZE_TWO = 2;
const std::string CLASS_NAME_REQUEST = "AccountCapabilityRequest";
const std::string CLASS_NAME_RESPONSE = "AccountCapabilityResponse";
static thread_local napi_ref g_requestConstructor = nullptr;
static thread_local napi_ref g_authorizationProviderConstructor = nullptr;
static thread_local napi_ref g_providerConstructor = nullptr;
static thread_local napi_ref g_responsConstructor = nullptr;
static thread_local napi_value g_responsePrototype = nullptr;
static bool g_initCompleted = false;
}

NapiAccountCapabilityProvider::NapiAccountCapabilityProvider(napi_env env, AccountCapabilityType type)
    : env_(env), type_(type)
{}

NapiAccountCapabilityRequest::NapiAccountCapabilityRequest(napi_env env) : env_(env)
{}

NapiAccountCapabilityRequest::~NapiAccountCapabilityRequest()
{
    if (providerRef_ != nullptr) {
        napi_delete_reference(env_, providerRef_);
        providerRef_ = nullptr;
    }
}

NapiAccountCapabilityResponse::NapiAccountCapabilityResponse(napi_env env) : env_(env)
{}

NapiAccountCapabilityResponse::~NapiAccountCapabilityResponse()
{
    if (requestRef_ != nullptr) {
        napi_delete_reference(env_, requestRef_);
        requestRef_ = nullptr;
    }
}

NapiAuthorizationProvider::NapiAuthorizationProvider(napi_env env, const AuthorizationProviderInfo &providerInfo)
    : NapiAccountCapabilityProvider(env, AccountCapabilityType::AUTHORIZATION), providerInfo_(providerInfo)
{}

napi_value NapiAppAccountCapability::ProviderConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "construct baseProvider napi_get_cb_info failed");
    if (!g_initCompleted) {
        ACCOUNT_LOGI("initialization in progress");
        return thisVar;
    }
    RETURN_IF_NEED_THROW_ERROR(env, argc > 0, "construct baseProvider need at least one params");
    int32_t capabilityType;
    RETURN_IF_NEED_THROW_ERROR(env, GetIntProperty(env, argv[0], capabilityType), "get capability type failed");
    
    NapiAccountCapabilityProvider *objectInfo =
        new (std::nothrow) NapiAccountCapabilityProvider(env, static_cast<AccountCapabilityType>(capabilityType));
    NAPI_ASSERT(env, objectInfo != nullptr, "failed to create NapiAccountCapabilityProvider for insufficient memory");
    std::unique_ptr<NapiAccountCapabilityProvider> objectInfoPtr(objectInfo);
    status = napi_wrap(env, thisVar, objectInfo,
        [](napi_env env, void *data, void *hint) {
            ACCOUNT_LOGI("js baseProvider instance garbage collection");
            delete reinterpret_cast<NapiAccountCapabilityProvider *>(data);
        }, nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "failed to wrap js instance with native object");
    
    // set readonly capabilityType property
    napi_property_descriptor descriptors[] = {
        { "capabilityType", nullptr, 0, 0, 0, argv[0], napi_enumerable, 0 },
    };
    status = napi_define_properties(env, thisVar, sizeof(descriptors) / sizeof(descriptors[0]), descriptors);
    NAPI_ASSERT(env, status == napi_ok, "failed to set capabilityType property");

    objectInfoPtr.release();
    return thisVar;
}

napi_value NapiAppAccountCapability::RequestConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {nullptr};
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "construct request napi_get_cb_info failed");
    if (!g_initCompleted) {
        ACCOUNT_LOGI("initialization in progress");
        return thisVar;
    }
    RETURN_IF_NEED_THROW_ERROR(env, argc > 0, "construct request need at least one params");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    napi_value constructor = nullptr;
    napi_get_reference_value(env, g_providerConstructor, &constructor);
    bool isInstance = false;
    napi_instanceof(env, argv[0], constructor, &isInstance);
    if ((valueType != napi_object) || (!isInstance)) {
        RETURN_IF_NEED_THROW_ERROR(env, false, "the type of baseProvider is invalid");
    }

    NapiAccountCapabilityRequest *objectInfo = new (std::nothrow) NapiAccountCapabilityRequest(env);
    NAPI_ASSERT(env, objectInfo != nullptr, "failed to create NapiAccountCapabilityRequest for insufficient memory");
    std::unique_ptr<NapiAccountCapabilityRequest> objectInfoPtr(objectInfo);

    status = napi_unwrap(env, argv[0], reinterpret_cast<void **>(&objectInfo->baseProvider_));
    NAPI_ASSERT(env, status == napi_ok, "failed to unwrap baseProvider from js instance");
    status = napi_create_reference(env, argv[0], 1, &objectInfo->providerRef_);
    NAPI_ASSERT(env, status == napi_ok, "failed to create baseProvider reference");

    if (argc == ARG_SIZE_TWO) {
        valueType = napi_undefined;
        napi_typeof(env, argv[1], &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("the requestType is undefined or null");
        } else {
            RETURN_IF_NEED_THROW_ERROR(
                env, GetIntProperty(env, argv[1], objectInfo->requestType_), "the type of requestType is invalid");
            // set readonly requestType property
            napi_property_descriptor descriptors[] = {
                {"requestType", nullptr, 0, 0, 0, argv[1], napi_enumerable, 0},
            };
            status = napi_define_properties(env, thisVar, sizeof(descriptors) / sizeof(descriptors[0]), descriptors);
            NAPI_ASSERT(env, status == napi_ok, "failed to set requestType property");
        }
    }

    status = napi_wrap(env, thisVar, objectInfo, [](napi_env env, void *data, void *hint) {
            delete reinterpret_cast<NapiAccountCapabilityRequest *>(data);
        }, nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "failed to wrap js instance with native object");

    objectInfoPtr.release();
    return thisVar;
}

napi_value NapiAppAccountCapability::ResponseConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "construct response napi_get_cb_info failed");
    if (argc == 0) {
        ACCOUNT_LOGI("initialization in progress");
        return thisVar;
    }
    RETURN_IF_NEED_THROW_ERROR(env, argc > 0, "construct response need at least one params");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if ((valueType == napi_undefined) || (valueType == napi_null)) {
        ACCOUNT_LOGI("no request to construct response");
        return thisVar;
    }

    napi_value constructor = nullptr;
    napi_get_reference_value(env, g_requestConstructor, &constructor);
    bool isInstance = false;
    napi_instanceof(env, argv[0], constructor, &isInstance);
    RETURN_IF_NEED_THROW_ERROR(env, isInstance, "the request is invalid");

    NapiAccountCapabilityResponse *objectInfo = new (std::nothrow) NapiAccountCapabilityResponse(env);
    NAPI_ASSERT(env, objectInfo != nullptr, "failed to create NapiAccountCapabilityResponse for insufficient memory");
    std::unique_ptr<NapiAccountCapabilityResponse> objectInfoPtr(objectInfo);
    status = napi_create_reference(env, argv[0], 1, &objectInfo->requestRef_);
    NAPI_ASSERT(env, status == napi_ok, "failed to create request reference");

    status = napi_wrap(env, thisVar, objectInfo,
        [](napi_env env, void *data, void *hint) {
            ACCOUNT_LOGI("js AppAccountManager instance garbage collection");
            delete reinterpret_cast<NapiAccountCapabilityResponse *>(data);
        }, nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "failed to wrap js instance with native object");

    // set readonly request property
    napi_property_descriptor descriptors[] = {
        { "request", nullptr, 0, 0, 0, argv[0], napi_enumerable, 0 },
    };
    status = napi_define_properties(env, thisVar, sizeof(descriptors) / sizeof(descriptors[0]), descriptors);
    NAPI_ASSERT(env, status == napi_ok, "failed to set request property");

    objectInfoPtr.release();
    return thisVar;
}

napi_value NapiAppAccountCapability::AuthorizationProviderConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "failed to get napi cbinfo");

    napi_value type = nullptr;
    status = napi_create_uint32(env, static_cast<uint32_t>(AccountCapabilityType::AUTHORIZATION), &type);
    NAPI_ASSERT(env, status == napi_ok, "failed to create uint32 type");
    // set readonly capabilityType property
    napi_property_descriptor descriptors[] = {
        { "capabilityType", nullptr, 0, 0, 0, type, napi_enumerable, 0 },
    };
    status = napi_define_properties(env, thisVar, sizeof(descriptors) / sizeof(descriptors[0]), descriptors);
    NAPI_ASSERT(env, status == napi_ok, "failed to set capabilityType property");

    if (!g_initCompleted) {
        ACCOUNT_LOGI("initialization in progress");
        return thisVar;
    }
    AuthorizationProviderInfo providerInfo;
    napi_value value = nullptr;
    status = napi_get_named_property(env, argv[0], "bundleName", &value);
    NAPI_ASSERT(env, status == napi_ok, "failed to get bundleName property");
    RETURN_IF_NEED_THROW_ERROR(
        env, GetStringProperty(env, value, providerInfo.bundleName), "the bundleName is invalid");
    status = napi_get_named_property(env, argv[0], "abilityName", &value);
    NAPI_ASSERT(env, status == napi_ok, "failed to get abilityName property");
    RETURN_IF_NEED_THROW_ERROR(
        env, GetStringProperty(env, value, providerInfo.abilityName), "the abilityName is invalid");

    NapiAuthorizationProvider *objectInfo =
        new (std::nothrow) NapiAuthorizationProvider(env, providerInfo);
    NAPI_ASSERT(env, objectInfo != nullptr,
        "failed to create NapiAuthorizationProvider for insufficient memory");
    status = napi_wrap(env, thisVar, objectInfo,
        [](napi_env env, void *data, void *hint) {
            ACCOUNT_LOGI("js authorizationProvider instance garbage collection");
            delete reinterpret_cast<NapiAuthorizationProvider *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        ACCOUNT_LOGE("failed to wrap js instance with native object");
        delete objectInfo;
        NAPI_ASSERT(env, false, "failed to create NapiAuthorizationProvider for insufficient memory");
    }
    return thisVar;
}

void NapiAppAccountCapability::DefineNapiProviderBaseClass(napi_env env, napi_value exports)
{
    std::string className = "AccountCapabilityProvider";
    napi_value jsConstructor = nullptr;
    napi_define_class(env, className.c_str(), className.length(),
        NapiAppAccountCapability::ProviderConstructor, nullptr, 0, nullptr, &jsConstructor);
    NAPI_ASSERT_RETURN_VOID(env, jsConstructor != nullptr, "define js class failed");
    napi_status status = napi_set_named_property(env, exports, className.c_str(), jsConstructor);
    NAPI_ASSERT_RETURN_VOID(env, status == napi_ok, "set property to exports failed");
    status = napi_create_reference(env, jsConstructor, 1, &g_providerConstructor);
    NAPI_ASSERT_RETURN_VOID(env, status == napi_ok, "failed to create reference");
}

void NapiAppAccountCapability::DefineNapiRequestBaseClass(napi_env env, napi_value exports)
{
    napi_value jsConstructor = nullptr;
    napi_define_class(env, CLASS_NAME_REQUEST.c_str(), CLASS_NAME_REQUEST.length(),
        NapiAppAccountCapability::RequestConstructor, nullptr, 0, nullptr, &jsConstructor);
    NAPI_ASSERT_RETURN_VOID(env, jsConstructor != nullptr, "define js class failed");
    napi_status status = napi_set_named_property(env, exports, CLASS_NAME_REQUEST.c_str(), jsConstructor);
    NAPI_ASSERT_RETURN_VOID(env, status == napi_ok, "set property to exports failed");
    status = napi_create_reference(env, jsConstructor, 1, &g_requestConstructor);
    NAPI_ASSERT_RETURN_VOID(env, status == napi_ok, "failed to create reference");
}

void NapiAppAccountCapability::DefineNapiResponseBaseClass(napi_env env, napi_value exports)
{
    napi_value jsConstructor = nullptr;
    napi_define_class(env, CLASS_NAME_RESPONSE.c_str(), CLASS_NAME_RESPONSE.length(),
        NapiAppAccountCapability::ResponseConstructor, nullptr, 0, nullptr, &jsConstructor);
    NAPI_ASSERT_RETURN_VOID(env, jsConstructor != nullptr, "define js class failed");
    napi_status status = napi_set_named_property(env, exports, CLASS_NAME_RESPONSE.c_str(), jsConstructor);
    NAPI_ASSERT_RETURN_VOID(env, status == napi_ok, "set property to exports failed");
    status = napi_create_reference(env, jsConstructor, 1, &g_responsConstructor);
    NAPI_ASSERT_RETURN_VOID(env, status == napi_ok, "failed to create reference");
}

void NapiAppAccountCapability::DefineNapiAuthorizationProviderClass(napi_env env, napi_value exports)
{
    napi_value authConstructor = nullptr;
    const std::string className = "AuthorizationProvider";
    napi_define_class(env, className.c_str(), className.length(),
        NapiAppAccountCapability::AuthorizationProviderConstructor, nullptr, 0, nullptr, &authConstructor);
    NAPI_ASSERT_RETURN_VOID(env, authConstructor != nullptr, "define js class failed");
    napi_status status =
        napi_set_named_property(env, exports, className.c_str(), authConstructor);
    NAPI_ASSERT_RETURN_VOID(env, status == napi_ok, "set property to exports failed");
    status = napi_create_reference(env, authConstructor, 1, &g_authorizationProviderConstructor);
    NAPI_ASSERT_RETURN_VOID(env, status == napi_ok, "failed to create reference");
}

static napi_value AccountCapabilityTypeConstructor(napi_env env)
{
    napi_value accountCapabilityType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &accountCapabilityType));
    napi_value authorization = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<uint32_t>(AccountCapabilityType::AUTHORIZATION), &authorization));
    NAPI_CALL(env, napi_set_named_property(env, accountCapabilityType, "AUTHORIZATION", authorization));
    return accountCapabilityType;
}

napi_value NapiAppAccountCapability::Init(napi_env env, napi_value exports)
{
    g_initCompleted = false;
    // define baseProvider class
    DefineNapiProviderBaseClass(env, exports);
    napi_value baseProviderConstructor = nullptr;
    NAPI_CALL(env, napi_get_reference_value(env, g_providerConstructor, &baseProviderConstructor));

    napi_value baseProvider = nullptr;
    NAPI_CALL(env, napi_new_instance(env, baseProviderConstructor, 0, nullptr, &baseProvider));

    napi_value baseProto = nullptr;
    NAPI_CALL(env, napi_get_prototype(env, baseProvider, &baseProto));
    // define base request class
    DefineNapiRequestBaseClass(env, exports);
    // define base response class
    DefineNapiResponseBaseClass(env, exports);
    // define authorization baseProvider class
    DefineNapiAuthorizationProviderClass(env, exports);
    napi_value authProviderConstructor = nullptr;
    NAPI_CALL(env, napi_get_reference_value(env, g_authorizationProviderConstructor, &authProviderConstructor));

    napi_value authProvider = nullptr;
    NAPI_CALL(env, napi_new_instance(env, authProviderConstructor, 0, nullptr, &authProvider));

    napi_value authProto = nullptr;
    NAPI_CALL(env, napi_get_prototype(env, authProvider, &authProto));
    // set authorizationProvider extends baseProvider
    NAPI_CALL(env, napi_set_named_property(env, authProto, "__proto__", baseProto));
    // define AccountCapabilityType
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_PROPERTY("AccountCapabilityType", AccountCapabilityTypeConstructor(env)),
    };
    NAPI_CALL(env,
        napi_define_properties(env, exports, sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors));

    g_initCompleted = true;
    return exports;
}

ExecuteRequestAsyncContext::~ExecuteRequestAsyncContext()
{
    if (requestRef != nullptr) {
        napi_delete_reference(env, requestRef);
        requestRef = nullptr;
    }
    if (callbackRef != nullptr) {
        napi_delete_reference(env, callbackRef);
        callbackRef = nullptr;
    }
}

static void ExecuteRequestCompletedWork(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    ExecuteRequestAsyncContext *asyncContext = reinterpret_cast<ExecuteRequestAsyncContext *>(work->data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == ERR_OK) {
        dataJs = AppExecFwk::WrapWantParams(asyncContext->env, asyncContext->parameters);
        napi_value requestRef = nullptr;
        napi_get_reference_value(asyncContext->env, asyncContext->requestRef, &requestRef);

        // set readonly request property
        napi_property_descriptor descriptors[] = {
            { "request", nullptr, 0, 0, 0, requestRef, napi_enumerable, 0 },
        };
        napi_status statusRet = napi_define_properties(
            asyncContext->env, dataJs, sizeof(descriptors) / sizeof(descriptors[0]), descriptors);
        if (statusRet != napi_ok) {
            ACCOUNT_LOGE("failed to set request property");
        }

        napi_value constructor = nullptr;
        napi_get_reference_value(asyncContext->env, g_responsConstructor, &constructor);
        napi_value responseInstance = nullptr;
        napi_value argv[1] = {nullptr};
        if (napi_new_instance(asyncContext->env, constructor, 1, argv, &responseInstance) != napi_ok) {
            ACCOUNT_LOGE("failed to construct response instance");
        }
        napi_get_prototype(asyncContext->env, responseInstance, &g_responsePrototype);
        // set dataJs extends baseResponse
        statusRet = napi_set_named_property(asyncContext->env, dataJs, "__proto__", g_responsePrototype);
        if (statusRet != napi_ok) {
            ACCOUNT_LOGE("failed to set __proto__ property");
        }
    } else {
        napi_create_uint32(asyncContext->env, asyncContext->errCode, &errJs);
    }
    ReturnCallbackOrPromise(asyncContext->env, asyncContext, errJs, dataJs);
    napi_close_handle_scope(asyncContext->env, scope);
    delete asyncContext;
}

NapiExecuteRequestCallback::NapiExecuteRequestCallback(
    napi_env env, napi_ref callbackRef, napi_deferred deferred, napi_ref requestRef)
    : env_(env), callbackRef_(callbackRef), deferred_(deferred), requestRef_(requestRef)
{}

NapiExecuteRequestCallback::~NapiExecuteRequestCallback()
{
    if (callbackRef_ != nullptr) {
        ReleaseNapiRefAsync(env_, callbackRef_);
        callbackRef_ = nullptr;
    }
    if (requestRef_ != nullptr) {
        ReleaseNapiRefAsync(env_, requestRef_);
        requestRef_ = nullptr;
    }
}

void NapiExecuteRequestCallback::OnResult(const int32_t errCode, const AAFwk::WantParams& parameters)
{
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if ((callbackRef_ == nullptr) && (deferred_ == nullptr)) {
        ACCOUNT_LOGE("js callback is nullptr");
        return;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    if (!CreateExecEnv(env_, &loop, &work)) {
        ACCOUNT_LOGE("failed to init execution environment");
        return;
    }
    auto *asyncContext = new (std::nothrow) ExecuteRequestAsyncContext(env_);
    if (asyncContext == nullptr) {
        delete work;
        return;
    }
    asyncContext->errCode = errCode;
    asyncContext->parameters = parameters;
    asyncContext->requestRef = requestRef_;
    asyncContext->callbackRef = callbackRef_;
    asyncContext->deferred = deferred_;
    work->data = reinterpret_cast<void *>(asyncContext);
    callbackRef_ = nullptr;
    requestRef_ = nullptr;
    deferred_ = nullptr;
    int resultCode = uv_queue_work(
        loop, work, [](uv_work_t *work) {}, ExecuteRequestCompletedWork);
    if (resultCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work, errCode: %{public}d", errCode);
        delete asyncContext;
        delete work;
        return;
    }
}

napi_value NapiAccountCapabilityScheduler::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("executeRequest", ExecuteRequest)
    };
    std::string className = "AccountCapabilityScheduler";
    napi_value constructor = nullptr;
    NAPI_CALL(env, napi_define_class(env, className.c_str(), className.length(), JsConstructor,
        nullptr, sizeof(properties) / sizeof(napi_property_descriptor), properties, &constructor));
    NAPI_ASSERT(env, constructor != nullptr, "define js class AccountCapabilityScheduler failed");
    napi_status status = napi_set_named_property(env, exports, className.c_str(), constructor);
    NAPI_ASSERT(env, status == napi_ok, "set constructor to exports failed");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    status = napi_set_named_property(env, global, className.c_str(), constructor);
    NAPI_ASSERT(env, status == napi_ok, "set constructor to global failed");

    return exports;
}

napi_value NapiAccountCapabilityScheduler::JsConstructor(napi_env env, napi_callback_info cbInfo)
{
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

static bool ParseRequestObject(
    napi_env env, napi_value object, AccountCapabilityRequest &request)
{
    napi_value constructor = nullptr;
    napi_get_reference_value(env, g_requestConstructor, &constructor);
    bool isInstance = false;
    napi_instanceof(env, object, constructor, &isInstance);
    if (!isInstance) {
        ACCOUNT_LOGE("the request object is invalid");
        return false;
    }

    NapiAccountCapabilityRequest *requesrObject = nullptr;
    napi_status status = napi_unwrap(env, object, reinterpret_cast<void **>(&requesrObject));
    if ((status != napi_ok) || (requesrObject == nullptr)) {
        ACCOUNT_LOGE("napi_unwrap native request failed");
        return false;
    }
    switch (requesrObject->baseProvider_->type_) {
        case AccountCapabilityType::AUTHORIZATION: {
            napi_value providerObject = nullptr;
            napi_get_reference_value(env, requesrObject->providerRef_, &providerObject);
            constructor = nullptr;
            napi_get_reference_value(env, g_authorizationProviderConstructor, &constructor);
            isInstance = false;
            napi_instanceof(env, providerObject, constructor, &isInstance);
            if (!isInstance) {
                ACCOUNT_LOGE("the authProvider object is invalid");
                return false;
            }
            NapiAuthorizationProvider *napiProvider = nullptr;
            status = napi_unwrap(env, providerObject, reinterpret_cast<void **>(&napiProvider));
            if ((status != napi_ok) || (napiProvider == nullptr)) {
                ACCOUNT_LOGE("napi_unwrap native request failed");
                return false;
            }
            request.bundleName = napiProvider->providerInfo_.bundleName;
            request.abilityName = napiProvider->providerInfo_.abilityName;
            break;
        }
        default: {
            ACCOUNT_LOGE("get invalid type");
            return false;
        }
    }
    if (!AppExecFwk::UnwrapWantParams(env, object, request.parameters)) {
        ACCOUNT_LOGE("UnwrapWantParams failed");
        return false;
    }
    return true;
}

static bool ParseParamForExecuteRequest(
    napi_env env, napi_callback_info cbInfo, ExecuteRequestAsyncContext *asyncContext)
{
    size_t argc = ARG_SIZE_TWO;
    napi_value argv[ARG_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARG_SIZE_ONE) {
        ACCOUNT_LOGE("the parameter of number should be at least one");
        return false;
    }
    if (argc == ARG_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            return false;
        }
    }
    if (!ParseRequestObject(env, argv[0], asyncContext->accountRequest)) {
        ACCOUNT_LOGE("get request failed");
        return false;
    }
    if (napi_create_reference(env, argv[0], 1, &asyncContext->requestRef) != napi_ok) {
        return false;
    }
    return true;
}

static void ExecuteRequestCB(napi_env env, void *data)
{
    ExecuteRequestAsyncContext *asyncContext = reinterpret_cast<ExecuteRequestAsyncContext *>(data);
    sptr<NapiExecuteRequestCallback> callback = new (std::nothrow)
        NapiExecuteRequestCallback(env, asyncContext->callbackRef, asyncContext->deferred, asyncContext->requestRef);
    NAPI_ASSERT_RETURN_VOID(env, callback != nullptr, "failed to create napi callback");
    asyncContext->requestRef = nullptr;
    asyncContext->callbackRef = nullptr;
    asyncContext->errCode = AppAccountManager::ExecuteRequest(asyncContext->accountRequest, callback);
    if (asyncContext->errCode != ERR_OK) {
        AAFwk::WantParams parameters;
        callback->OnResult(ConvertToJSErrCode(asyncContext->errCode), parameters);
    }
}

static void ExecuteRequestCompletedCB(napi_env env, napi_status status, void *data)
{
    ExecuteRequestAsyncContext *asyncContext = reinterpret_cast<ExecuteRequestAsyncContext *>(data);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
}

napi_value NapiAccountCapabilityScheduler::ExecuteRequest(napi_env env, napi_callback_info cbInfo)
{
    ExecuteRequestAsyncContext *executeRequestCB = new (std::nothrow) ExecuteRequestAsyncContext(env);
    if (executeRequestCB == nullptr) {
        ACCOUNT_LOGE("insufficient memory for HasDomainAccountCB!");
        return nullptr;
    }
    std::unique_ptr<ExecuteRequestAsyncContext> contextPtr(executeRequestCB);
    RETURN_IF_NEED_THROW_ERROR(env, ParseParamForExecuteRequest(env, cbInfo, executeRequestCB), "parse params failed");

    napi_value result = nullptr;
    if (executeRequestCB->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &executeRequestCB->deferred, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "executeRequest", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        ExecuteRequestCB,
        ExecuteRequestCompletedCB,
        reinterpret_cast<void *>(executeRequestCB),
        &executeRequestCB->work));
    NAPI_CALL(env, napi_queue_async_work(env, executeRequestCB->work));
    contextPtr.release();
    return result;
}
}  // namespace AccountJsKit
}  // namespace OHOS
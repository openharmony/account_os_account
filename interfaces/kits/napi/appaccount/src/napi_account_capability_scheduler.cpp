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

ExecuteRequestAsyncContext::~ExecuteRequestAsyncContext()
{
    if (requestRef != nullptr) {
        napi_delete_reference(env, requestRef);
        requestRef = nullptr;
    }
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
        }
    }

    status = napi_wrap(env, thisVar, objectInfo, [](napi_env env, void *data, void *hint) {
            delete reinterpret_cast<NapiAccountCapabilityRequest *>(data);
        }, nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "failed to wrap js instance with native object");

    // set readonly requestType property
    napi_property_descriptor descriptors[] = {
        { "requestType", nullptr, 0, 0, 0, argv[1], napi_enumerable, 0 },
    };
    status = napi_define_properties(env, thisVar, sizeof(descriptors) / sizeof(descriptors[0]), descriptors);
    NAPI_ASSERT(env, status == napi_ok, "failed to set requestType property");

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
    NAPI_ASSERT(env, jsConstructor != nullptr, "define js class failed");
    napi_status status = napi_set_named_property(env, exports, className.c_str(), jsConstructor);
    NAPI_ASSERT(env, status == napi_ok, "set property to exports failed");
    status = napi_create_reference(env, jsConstructor, 1, &g_providerConstructor);
    NAPI_ASSERT(env, status == napi_ok, "failed to create reference");
}

void NapiAppAccountCapability::DefineNapiRequestBaseClass(napi_env env, napi_value exports)
{
    napi_value jsConstructor = nullptr;
    napi_define_class(env, CLASS_NAME_REQUEST.c_str(), CLASS_NAME_REQUEST.length(),
        NapiAppAccountCapability::RequestConstructor, nullptr, 0, nullptr, &jsConstructor);
    NAPI_ASSERT(env, jsConstructor != nullptr, "define js class failed");
    napi_status status = napi_set_named_property(env, exports, CLASS_NAME_REQUEST.c_str(), jsConstructor);
    NAPI_ASSERT(env, status == napi_ok, "set property to exports failed");
    status = napi_create_reference(env, jsConstructor, 1, &g_requestConstructor);
    NAPI_ASSERT(env, status == napi_ok, "failed to create reference");
}

void NapiAppAccountCapability::DefineNapiResponseBaseClass(napi_env env, napi_value exports)
{
    napi_value jsConstructor = nullptr;
    napi_define_class(env, CLASS_NAME_RESPONSE.c_str(), CLASS_NAME_RESPONSE.length(),
        NapiAppAccountCapability::ResponseConstructor, nullptr, 0, nullptr, &jsConstructor);
    NAPI_ASSERT(env, jsConstructor != nullptr, "define js class failed");
    napi_status status = napi_set_named_property(env, exports, CLASS_NAME_RESPONSE.c_str(), jsConstructor);
    NAPI_ASSERT(env, status == napi_ok, "set property to exports failed");
    status = napi_create_reference(env, jsConstructor, 1, &g_responsConstructor);
    NAPI_ASSERT(env, status == napi_ok, "failed to create reference");
}

void NapiAppAccountCapability::DefineNapiAuthorizationProviderClass(napi_env env, napi_value exports)
{
    napi_value authConstructor = nullptr;
    const std::string className = "AuthorizationProvider";
    napi_define_class(env, className.c_str(), className.length(),
        NapiAppAccountCapability::AuthorizationProviderConstructor, nullptr, 0, nullptr, &authConstructor);
    NAPI_ASSERT(env, authConstructor != nullptr, "define js class failed");
    napi_status status =
        napi_set_named_property(env, exports, className.c_str(), authConstructor);
    NAPI_ASSERT(env, status == napi_ok, "set property to exports failed");
    status = napi_create_reference(env, authConstructor, 1, &g_authorizationProviderConstructor);
    NAPI_ASSERT(env, status == napi_ok, "failed to create reference");
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
}  // namespace AccountJsKit
}  // namespace OHOS

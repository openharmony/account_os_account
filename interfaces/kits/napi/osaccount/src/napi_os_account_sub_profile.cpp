/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "napi_os_account.h"
#include "napi_os_account_sub_profile_manager.h"

#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "napi_account_common.h"
#include "napi_account_error.h"
#include "napi_os_account_common.h"
#include "napi/native_common.h"
#include "os_account_subspace_client.h"

using namespace OHOS::AccountSA;

namespace OHOS {
namespace AccountJsKit {
namespace {
static thread_local napi_ref subProfileRef_ = nullptr;

static void CreateOsAccountSubProfileExecuteCB(napi_env env, void *data)
{
    auto *ctx = reinterpret_cast<SubProfileAsyncContext *>(data);
    ctx->errCode = OsAccountSubspaceClient::GetInstance().CreateOsAccountSubspace(
        ctx->osAccountId, ctx->result);
}

static void CreateOsAccountSubProfileCompletedCB(napi_env env, napi_status status, void *data)
{
    auto *ctx = reinterpret_cast<SubProfileAsyncContext *>(data);
    napi_value result[RESULT_COUNT] = {0};
    if (ctx->errCode == ERR_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        napi_value obj;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &obj));
        napi_value idVal;
        napi_value osAccountIdVal;
        napi_value indexVal;
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, ctx->result.id, &idVal));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, ctx->result.osAccountId, &osAccountIdVal));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, ctx->result.index, &indexVal));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, obj, "id", idVal));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, obj, "osAccountLocalId", osAccountIdVal));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, obj, "index", indexVal));
        result[1] = obj;
    } else {
        result[0] = GenerateBusinessError(env, ctx->errCode);
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[1]));
    }
    ProcessCallbackOrPromise(env, ctx, result[0], result[1]);
    delete ctx;
}

static void DeleteOsAccountSubProfileExecuteCB(napi_env env, void *data)
{
    auto *ctx = reinterpret_cast<SubProfileAsyncContext *>(data);
    ctx->errCode = OsAccountSubspaceClient::GetInstance().DeleteOsAccountSubspace(
        ctx->osAccountId, ctx->subProfileId);
}

static void SwitchOsAccountSubProfileExecuteCB(napi_env env, void *data)
{
    auto *ctx = reinterpret_cast<SubProfileAsyncContext *>(data);
    ctx->errCode = OsAccountSubspaceClient::GetInstance().SwitchOsAccountSubspace(
        ctx->osAccountId, ctx->subProfileId);
}
}  // namespace

napi_value NapiOsAccountSubProfileManager::GetOsAccountSubProfileManager(napi_env env, napi_callback_info cbInfo)
{
    if (AccountPermissionManager::CheckSystemApp(false) != ERR_OK) {
        std::string errMsg = "Not system application.";
        AccountNapiThrow(env, ERR_JS_IS_NOT_SYSTEM_APP, errMsg, true);
        return nullptr;
    }
    napi_value instance = nullptr;
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, subProfileRef_, &cons) != napi_ok) {
        ACCOUNT_LOGE("Failed to get OsAccountSubProfileManager reference");
        return nullptr;
    }

    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        ACCOUNT_LOGE("Failed to create OsAccountSubProfileManager instance");
        return nullptr;
    }

    return instance;
}

napi_value NapiOsAccountSubProfileManager::CreateOsAccountSubProfile(napi_env env, napi_callback_info cbInfo)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_SIZE_ONE) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, "Parameter error. 1 parameter required.", true);
        return nullptr;
    }

    auto *ctx = new (std::nothrow) SubProfileAsyncContext();
    if (ctx == nullptr) {
        ACCOUNT_LOGE("Insufficient memory for context.");
        return nullptr;
    }
    std::unique_ptr<SubProfileAsyncContext> contextPtr(ctx);
    ctx->env = env;
    ctx->throwErr = true;

    if (!GetIntProperty(env, argv[PARAMZERO], ctx->osAccountId)) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, "Parameter error. osAccountId must be number.", true);
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &ctx->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "CreateOsAccountSubProfile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, CreateOsAccountSubProfileExecuteCB,
        CreateOsAccountSubProfileCompletedCB, reinterpret_cast<void *>(ctx), &ctx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, ctx->work, napi_qos_user_initiated));
    contextPtr.release();
    return result;
}

napi_value NapiOsAccountSubProfileManager::DeleteOsAccountSubProfile(napi_env env, napi_callback_info cbInfo)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_SIZE_TWO) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, "Parameter error. 2 parameters required.", true);
        return nullptr;
    }

    auto *ctx = new (std::nothrow) SubProfileAsyncContext();
    if (ctx == nullptr) {
        ACCOUNT_LOGE("Insufficient memory for context.");
        return nullptr;
    }
    std::unique_ptr<SubProfileAsyncContext> contextPtr(ctx);
    ctx->env = env;
    ctx->throwErr = true;

    if (!GetIntProperty(env, argv[PARAMZERO], ctx->osAccountId)) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR,
            "Parameter error. The type of \"osAccountId\" must be number.", true);
        return nullptr;
    }
    if (!GetIntProperty(env, argv[PARAMONE], ctx->subProfileId)) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR,
            "Parameter error. The type of \"subProfileId\" must be number.", true);
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &ctx->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "DeleteOsAccountSubProfile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, DeleteOsAccountSubProfileExecuteCB,
        [](napi_env env, napi_status status, void *data) {
            auto *ctx = reinterpret_cast<SubProfileAsyncContext *>(data);
            napi_value result[RESULT_COUNT] = {0};
            if (ctx->errCode == ERR_OK) {
                NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
                NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[1]));
            } else {
                result[0] = GenerateBusinessError(env, ctx->errCode);
                NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[1]));
            }
            ProcessCallbackOrPromise(env, ctx, result[0], result[1]);
            delete ctx;
        },
        reinterpret_cast<void *>(ctx), &ctx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, ctx->work, napi_qos_user_initiated));
    contextPtr.release();
    return result;
}

napi_value NapiOsAccountSubProfileManager::SwitchOsAccountSubProfile(napi_env env, napi_callback_info cbInfo)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_SIZE_TWO) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, "Parameter error. 2 parameters required.", true);
        return nullptr;
    }

    auto *ctx = new (std::nothrow) SubProfileAsyncContext();
    if (ctx == nullptr) {
        ACCOUNT_LOGE("Insufficient memory for context.");
        return nullptr;
    }
    std::unique_ptr<SubProfileAsyncContext> contextPtr(ctx);
    ctx->env = env;
    ctx->throwErr = true;

    if (!GetIntProperty(env, argv[PARAMZERO], ctx->osAccountId)) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR,
            "Parameter error. The type of \"osAccountId\" must be number.", true);
        return nullptr;
    }
    if (!GetIntProperty(env, argv[PARAMONE], ctx->subProfileId)) {
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR,
            "Parameter error. The type of \"subProfileId\" must be number.", true);
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &ctx->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SwitchOsAccountSubProfile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, SwitchOsAccountSubProfileExecuteCB,
        [](napi_env env, napi_status status, void *data) {
            auto *ctx = reinterpret_cast<SubProfileAsyncContext *>(data);
            napi_value result[RESULT_COUNT] = {0};
            if (ctx->errCode == ERR_OK) {
                NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
                NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[1]));
            } else {
                result[0] = GenerateBusinessError(env, ctx->errCode);
                NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[1]));
            }
            ProcessCallbackOrPromise(env, ctx, result[0], result[1]);
            delete ctx;
        },
        reinterpret_cast<void *>(ctx), &ctx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, ctx->work, napi_qos_user_initiated));
    contextPtr.release();
    return result;
}

napi_value NapiOsAccountSubProfileManager::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptor[] = {
        DECLARE_NAPI_FUNCTION("getOsAccountSubProfileManager", GetOsAccountSubProfileManager),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor),
        descriptor));

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("createOsAccountSubProfile", CreateOsAccountSubProfile),
        DECLARE_NAPI_FUNCTION("deleteOsAccountSubProfile", DeleteOsAccountSubProfile),
        DECLARE_NAPI_FUNCTION("switchOsAccountSubProfile", SwitchOsAccountSubProfile),
    };
    std::string className = "OsAccountSubProfileManager";
    napi_value cons = nullptr;
    NAPI_CALL(env, napi_define_class(env, className.c_str(), className.size(),
        JsConstructor, nullptr, sizeof(properties) / sizeof(napi_property_descriptor), properties, &cons));
    NAPI_CALL(env, napi_create_reference(env, cons, 1, &subProfileRef_));
    NAPI_CALL(env, napi_set_named_property(env, exports, className.c_str(), cons));

    return exports;
}

napi_value NapiOsAccountSubProfileManager::JsConstructor(napi_env env, napi_callback_info cbInfo)
{
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

}  // namespace AccountJsKit
}  // namespace OHOS
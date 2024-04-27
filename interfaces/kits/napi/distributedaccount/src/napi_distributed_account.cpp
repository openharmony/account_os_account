/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "napi_distributed_account.h"
#include <map>
#include <string>
#include <unistd.h>
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi_account_common.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "node_api.h"
#include "ohos_account_kits.h"
#include "napi_account_error.h"
#include "napi_common.h"

using namespace OHOS::AccountSA;

namespace OHOS {
namespace AccountJsKit {
constexpr std::int32_t PARAM_ZERO = 0;
constexpr std::int32_t PARAM_ONE = 1;
constexpr std::int32_t PARAM_TWO = 2;
constexpr std::int32_t PARAM_THREE = 3;
constexpr int RESULT_COUNT = 2;
const std::string DISTRIBUTED_ACCOUNT_CLASS_NAME = "DistributedAccountAbility";
const std::string PROPERTY_KEY_NAME = "name";
const std::string PROPERTY_KEY_ID = "id";
const std::string PROPERTY_KEY_EVENT = "event";
const std::string PROPERTY_KEY_NICKNAME = "nickname";
const std::string PROPERTY_KEY_AVATAR = "avatar";
const std::string PROPERTY_KEY_SCALABLE = "scalableData";
const std::string PROPERTY_KEY_STATUS = "status";

static thread_local napi_ref distributedAccountRef_ = nullptr;

DistributedAccountAsyncContext::DistributedAccountAsyncContext(napi_env napiEnv) : env(napiEnv)
{}

DistributedAccountAsyncContext::~DistributedAccountAsyncContext()
{
    if (callbackRef != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, callbackRef));
        callbackRef = nullptr;
    }
}

napi_value DistributedAccountStatusConstructor(napi_env env)
{
    napi_value distributedAccountStatus = nullptr;
    napi_value status1 = nullptr;
    napi_value status2 = nullptr;
    NAPI_CALL(env, napi_create_object(env, &distributedAccountStatus));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(OHOS_ACCOUNT_STATE::ACCOUNT_STATE_UNBOUND), &status1));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(OHOS_ACCOUNT_STATE::ACCOUNT_STATE_LOGIN), &status2));
    NAPI_CALL(env, napi_set_named_property(env, distributedAccountStatus, "NOT_LOGGED_IN", status1));
    NAPI_CALL(env, napi_set_named_property(env, distributedAccountStatus, "LOGGED_IN", status2));
    return distributedAccountStatus;
}

bool ParseQueryOhosAccountInfoAsyncContext(
    napi_env env, napi_callback_info cbInfo, DistributedAccountAsyncContext *asyncContext)
{
    size_t argc = PARAM_TWO;
    napi_value argv[PARAM_TWO] = {nullptr};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == PARAM_ONE) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[PARAM_ZERO], &valueType);
        if (valueType == napi_number) {
            if (!GetIntProperty(env, argv[PARAM_ZERO], asyncContext->localId)) {
                ACCOUNT_LOGE("Get localId failed");
                return false;
            }
            asyncContext->withLocalId = true;
            return true;
        }
        if (!GetCallbackProperty(env, argv[PARAM_ZERO], asyncContext->callbackRef, PARAM_ONE)) {
            ACCOUNT_LOGE("Get callback failed");
            return false;
        }
    }
    if (argc == PARAM_TWO) {
        if ((!GetCallbackProperty(env, argv[PARAM_TWO - 1], asyncContext->callbackRef, PARAM_ONE))) {
            ACCOUNT_LOGE("Get callbackRef failed");
            return false;
        }
        if (!GetIntProperty(env, argv[PARAM_ZERO], asyncContext->localId)) {
            ACCOUNT_LOGE("Get localId failed");
            return false;
        }
        asyncContext->withLocalId = true;
        return true;
    }
    return true;
}

bool GetAccountInfo(napi_env env, napi_value object, DistributedAccountAsyncContext *asyncContext)
{
    if (!GetStringPropertyByKey(env, object, PROPERTY_KEY_NAME, asyncContext->ohosAccountInfo.name_)) {
        ACCOUNT_LOGE("Failed to get DistributedInfo's %{public}s property", PROPERTY_KEY_NAME.c_str());
        std::string errMsg = "Parameter error. The type of " + PROPERTY_KEY_NAME + " must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (!GetStringPropertyByKey(env, object, PROPERTY_KEY_ID, asyncContext->ohosAccountInfo.uid_)) {
        ACCOUNT_LOGE("Failed to get DistributedInfo's %{public}s property", PROPERTY_KEY_ID.c_str());
        std::string errMsg = "Parameter error. The type of " + PROPERTY_KEY_ID + " must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (!GetOptionalStringPropertyByKey(env, object, PROPERTY_KEY_NICKNAME, asyncContext->ohosAccountInfo.nickname_)) {
        ACCOUNT_LOGE("Failed to get DistributedInfo's %{public}s property", PROPERTY_KEY_NICKNAME.c_str());
        std::string errMsg = "Parameter error. The type of " + PROPERTY_KEY_NICKNAME + " must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (!GetOptionalStringPropertyByKey(env, object, PROPERTY_KEY_AVATAR, asyncContext->ohosAccountInfo.avatar_)) {
        ACCOUNT_LOGE("Failed to get DistributedInfo's %{public}s property", PROPERTY_KEY_AVATAR.c_str());
        std::string errMsg = "Parameter error. The type of " + PROPERTY_KEY_AVATAR + " must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    bool hasProp = false;
    napi_has_named_property(env, object, "scalableData", &hasProp);
    AAFwk::WantParams params;
    if (hasProp) {
        napi_value value = nullptr;
        napi_get_named_property(env, object, "scalableData", &value);
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL_BASE(env, napi_typeof(env, value, &valuetype), false);
        if ((valuetype == napi_undefined) || (valuetype == napi_null)) {
            ACCOUNT_LOGI("the scalableData is undefined or null");
        } else {
            if (!AppExecFwk::UnwrapWantParams(env, value, params)) {
                ACCOUNT_LOGE("Failed to get DistributedInfo's %{public}s property", PROPERTY_KEY_SCALABLE.c_str());
                std::string errMsg = "Parameter error. The type of " + PROPERTY_KEY_SCALABLE + " must be object";
                AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
                return false;
            }
        }
    }
    asyncContext->ohosAccountInfo.scalableData_.SetParams(params);
    return true;
}

static bool ParseInfoAndEvent(napi_env env, napi_value argv, DistributedAccountAsyncContext *asyncContext)
{
    if (!GetAccountInfo(env, argv, asyncContext)) {
        ACCOUNT_LOGE("Failed to get account info");
        return false;
    }
    if (!GetStringPropertyByKey(env, argv, PROPERTY_KEY_EVENT, asyncContext->event)) {
        ACCOUNT_LOGE("Failed to get DistributedInfo's %{public}s property", PROPERTY_KEY_EVENT.c_str());
        return false;
    }
    return true;
}

bool ParseUpdateOhosAccountInfoAsyncContext(
    napi_env env, napi_callback_info cbInfo, DistributedAccountAsyncContext *asyncContext)
{
    size_t argc = PARAM_TWO;
    napi_value argv[PARAM_TWO] = {nullptr};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < PARAM_ONE) {
        ACCOUNT_LOGE("paramter should be at least one");
        return false;
    }
    if (!(ParseInfoAndEvent(env, argv[PARAM_ZERO], asyncContext))) {
        ACCOUNT_LOGE("Failed to get account info");
        return false;
    }
    if (argc > PARAM_ONE) {
        if (!GetCallbackProperty(env, argv[PARAM_ONE], asyncContext->callbackRef, PARAM_ONE)) {
            ACCOUNT_LOGE("Failed to get callback property");
            return false;
        }
    }
    return true;
}

void ProcessCallbackOrPromise(
    napi_env env, const DistributedAccountAsyncContext *asyncContext, napi_value err, napi_value data)
{
    if (asyncContext->deferred != nullptr) {
        if (asyncContext->errCode == ERR_OK) {
            napi_resolve_deferred(env, asyncContext->deferred, data);
        } else {
            napi_reject_deferred(env, asyncContext->deferred, err);
        }
    } else {
        napi_value args[RESULT_COUNT] = { err, data };
        napi_value callback = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, args, &returnVal);
    }
}

void ProcessSetNamedProperty(napi_env env, const DistributedAccountAsyncContext *asyncContext)
{
    napi_value result[RESULT_COUNT] = {0};
    if (asyncContext->errCode == ERR_OK) {
        if (asyncContext->throwErr) {
            napi_get_null(env, &result[0]);
        } else {
            napi_get_undefined(env, &result[0]);
        }
        napi_create_object(env, &result[1]);
        napi_value value = nullptr;
        napi_create_string_utf8(env, asyncContext->ohosAccountInfo.name_.c_str(),
                                asyncContext->ohosAccountInfo.name_.size(), &value);
        napi_set_named_property(env, result[1], PROPERTY_KEY_NAME.c_str(), value);
        napi_create_string_utf8(env, asyncContext->ohosAccountInfo.uid_.c_str(),
                                asyncContext->ohosAccountInfo.uid_.size(), &value);
        napi_set_named_property(env, result[1], PROPERTY_KEY_ID.c_str(), value);
        napi_create_string_utf8(env, asyncContext->event.c_str(), asyncContext->event.size(), &value);
        napi_set_named_property(env, result[1], PROPERTY_KEY_EVENT.c_str(), value);
        napi_create_string_utf8(env, asyncContext->ohosAccountInfo.nickname_.c_str(),
                                asyncContext->ohosAccountInfo.nickname_.size(), &value);
        napi_set_named_property(env, result[1], PROPERTY_KEY_NICKNAME.c_str(), value);
        napi_create_string_utf8(env, asyncContext->ohosAccountInfo.avatar_.c_str(),
                                asyncContext->ohosAccountInfo.avatar_.size(), &value);
        napi_set_named_property(env, result[1], PROPERTY_KEY_AVATAR.c_str(), value);
        napi_create_int32(env, asyncContext->ohosAccountInfo.status_, &value);
        napi_set_named_property(env, result[1], PROPERTY_KEY_STATUS.c_str(), value);
        napi_value scalable = nullptr;
        napi_create_object(env, &scalable);
        scalable = AppExecFwk::WrapWantParams(env, (asyncContext->ohosAccountInfo.scalableData_).GetParams());
        napi_set_named_property(env, result[1], PROPERTY_KEY_SCALABLE.c_str(), scalable);
    } else {
        if (asyncContext->throwErr) {
            result[0] = GenerateBusinessError(env, asyncContext->errCode);
            napi_get_null(env, &result[1]);
        } else {
            napi_value message = nullptr;
            napi_create_string_utf8(env, "query ohos account info failed", NAPI_AUTO_LENGTH, &message);
            napi_create_error(env, nullptr, message, &result[0]);
            napi_get_undefined(env, &result[1]);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, result[0], result[1]);
}

napi_value NapiDistributedAccount::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptor[] = {
        DECLARE_NAPI_FUNCTION("getDistributedAccountAbility", GetDistributedAccountAbility),
        DECLARE_NAPI_PROPERTY("DistributedAccountStatus", DistributedAccountStatusConstructor(env)),
    };
    napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor);

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("queryOsAccountDistributedInfo", QueryOsAccountDistributedInfo),
        DECLARE_NAPI_FUNCTION("getOsAccountDistributedInfo", GetOsAccountDistributedInfo),
        DECLARE_NAPI_FUNCTION("updateOsAccountDistributedInfo", UpdateOsAccountDistributedInfo),
        DECLARE_NAPI_FUNCTION("setOsAccountDistributedInfo", SetOsAccountDistributedInfo),
        DECLARE_NAPI_FUNCTION("getOsAccountDistributedInfoByLocalId", GetOsAccountDistributedInfo),
        DECLARE_NAPI_FUNCTION("setOsAccountDistributedInfoByLocalId", SetOsAccountDistributedInfoByLocalId),
        DECLARE_NAPI_FUNCTION("setCurrentOsAccountDistributedInfo", SetCurrentOsAccountDistributedInfo),
    };
    napi_value cons = nullptr;
    napi_define_class(env, DISTRIBUTED_ACCOUNT_CLASS_NAME.c_str(), DISTRIBUTED_ACCOUNT_CLASS_NAME.size(),
        JsConstructor, nullptr, sizeof(properties) / sizeof(napi_property_descriptor), properties, &cons);
    napi_create_reference(env, cons, 1, &distributedAccountRef_);
    napi_set_named_property(env, exports, DISTRIBUTED_ACCOUNT_CLASS_NAME.c_str(), cons);

    return exports;
}

napi_value NapiDistributedAccount::JsConstructor(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiDistributedAccount::GetDistributedAccountAbility(napi_env env, napi_callback_info cbInfo)
{
    napi_value instance = nullptr;
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, distributedAccountRef_, &cons) != napi_ok) {
        return nullptr;
    }

    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        return nullptr;
    }

    return instance;
}

napi_value NapiDistributedAccount::QueryOsAccountDistributedInfo(napi_env env, napi_callback_info cbInfo)
{
    return QueryOhosAccountInfo(env, cbInfo, false);
}

napi_value NapiDistributedAccount::GetOsAccountDistributedInfo(napi_env env, napi_callback_info cbInfo)
{
    return QueryOhosAccountInfo(env, cbInfo, true);
}

static void QueryOhosAccountInfoExecuteCB(napi_env env, void *data)
{
    DistributedAccountAsyncContext *asyncContext = reinterpret_cast<DistributedAccountAsyncContext *>(data);
    if (!asyncContext->throwErr) {
        std::pair<bool, OhosAccountInfo> accountInfo = OhosAccountKits::GetInstance().QueryOhosAccountInfo();
        if (accountInfo.first) {
            asyncContext->ohosAccountInfo.name_ = accountInfo.second.name_;
            asyncContext->ohosAccountInfo.uid_ = accountInfo.second.uid_;
            asyncContext->ohosAccountInfo.status_ = accountInfo.second.status_;
            asyncContext->errCode = napi_ok;
        } else {
            asyncContext->errCode = napi_generic_failure;
        }
    } else if (!asyncContext->withLocalId) {
        asyncContext->errCode = OhosAccountKits::GetInstance().GetOhosAccountInfo(asyncContext->ohosAccountInfo);
    } else {
        asyncContext->errCode = OhosAccountKits::GetInstance().GetOhosAccountInfoByUserId(
            asyncContext->localId, asyncContext->ohosAccountInfo);
    }
}

static void QueryOhosAccountInfoCompletedCB(napi_env env, napi_status status, void *data)
{
    DistributedAccountAsyncContext *asyncContext = reinterpret_cast<DistributedAccountAsyncContext *>(data);
    ProcessSetNamedProperty(env, asyncContext);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
}

napi_value NapiDistributedAccount::QueryOhosAccountInfo(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto *asyncContext = new (std::nothrow) DistributedAccountAsyncContext(env);
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DistributedAccountAsyncContext> contextPtr(asyncContext);
    asyncContext->throwErr = throwErr;
    if (!ParseQueryOhosAccountInfoAsyncContext(env, cbInfo, asyncContext) && throwErr) {
        std::string errMsg =
            "Parameter error. The type of \"callback\" must be function, the type of \"localId\" must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    }
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "QueryOhosAccountInfo", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        QueryOhosAccountInfoExecuteCB,
        QueryOhosAccountInfoCompletedCB,
        reinterpret_cast<void *>(asyncContext), &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));
    contextPtr.release();
    return result;
}

napi_value NapiDistributedAccount::UpdateOsAccountDistributedInfo(napi_env env, napi_callback_info cbInfo)
{
    return UpdateOhosAccountInfo(env, cbInfo, false);
}

napi_value NapiDistributedAccount::SetOsAccountDistributedInfo(napi_env env, napi_callback_info cbInfo)
{
    return UpdateOhosAccountInfo(env, cbInfo, true);
}

napi_value NapiDistributedAccount::SetCurrentOsAccountDistributedInfo(napi_env env, napi_callback_info cbInfo)
{
    if (AccountPermissionManager::CheckSystemApp(false) != ERR_OK) {
        AccountNapiThrow(env, ERR_JS_IS_NOT_SYSTEM_APP);
        return nullptr;
    }
    return UpdateOhosAccountInfo(env, cbInfo, true);
}

static void UpdateOhosAccountInfoExecuteCB(napi_env env, void *data)
{
    DistributedAccountAsyncContext *context = reinterpret_cast<DistributedAccountAsyncContext *>(data);
    if (!context->throwErr) {
        context->errCode = OhosAccountKits::GetInstance().UpdateOhosAccountInfo(context->ohosAccountInfo.name_,
            context->ohosAccountInfo.uid_, context->event) ? napi_ok: napi_generic_failure;
    } else if (context->withLocalId) {
        context->errCode = OhosAccountKits::GetInstance().SetOhosAccountInfoByUserId(
            context->localId, context->ohosAccountInfo, context->event);
    } else {
        context->errCode = OhosAccountKits::GetInstance().SetOhosAccountInfo(context->ohosAccountInfo, context->event);
    }
}

static void UpdateOhosAccountInfoCompletedCB(napi_env env, napi_status status, void *data)
{
    DistributedAccountAsyncContext *asyncContext = reinterpret_cast<DistributedAccountAsyncContext *>(data);
    napi_value result[RESULT_COUNT] = {0};
    if (asyncContext->errCode == ERR_OK) {
        if (asyncContext->throwErr) {
            napi_get_null(env, &result[0]);
            napi_get_null(env, &result[1]);
        } else {
            napi_get_undefined(env, &result[1]);
        }
    } else if (asyncContext->throwErr) {
        result[0] = GenerateBusinessError(env, asyncContext->errCode);
    } else {
        napi_value message = nullptr;
        napi_create_string_utf8(env, "Update distributed account info failed", NAPI_AUTO_LENGTH, &message);
        napi_create_error(env, nullptr, message, &result[0]);
    }
    ProcessCallbackOrPromise(env, asyncContext, result[0], result[1]);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
}

napi_value NapiDistributedAccount::SetOhosAccountInfo(napi_env env, DistributedAccountAsyncContext *asyncContext)
{
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    }
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "SetOhosAccountInfo", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        UpdateOhosAccountInfoExecuteCB,
        UpdateOhosAccountInfoCompletedCB,
        reinterpret_cast<void *>(asyncContext), &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));
    return result;
}

bool ParseSetOsAccountDistributedInfoByLocalId(
    napi_env env, napi_callback_info cbInfo, DistributedAccountAsyncContext *asyncContext)
{
    size_t argc = PARAM_THREE;
    napi_value argv[PARAM_THREE] = {nullptr};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < PARAM_ONE) {
        ACCOUNT_LOGE("paramter should be at least one");
        return false;
    }
    if (!GetIntProperty(env, argv[PARAM_ZERO], asyncContext->localId)) {
        ACCOUNT_LOGE("Get localId failed");
        return false;
    }
    if (!(ParseInfoAndEvent(env, argv[PARAM_ONE], asyncContext))) {
        ACCOUNT_LOGE("Failed to get account info");
        return false;
    }
    if (argc > PARAM_TWO) {
        if (!GetCallbackProperty(env, argv[PARAM_TWO], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Failed to get callback property");
            return false;
        }
    }
    return true;
}

napi_value NapiDistributedAccount::SetOsAccountDistributedInfoByLocalId(napi_env env, napi_callback_info cbInfo)
{
    auto *asyncContext = new (std::nothrow) DistributedAccountAsyncContext(env);
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return nullptr;
    }
    asyncContext->throwErr = true;
    std::unique_ptr<DistributedAccountAsyncContext> contextPtr(asyncContext);
    if (!ParseSetOsAccountDistributedInfoByLocalId(env, cbInfo, asyncContext)) {
        std::string errMsg = "Parameter error. The type of \"localId\" must be number,"
            " the type of \"accountInfo\" must be DistributedInfo, the type of \"callback\" must be function";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    napi_value result = SetOhosAccountInfo(env, asyncContext);
    contextPtr.release();
    return result;
}

napi_value NapiDistributedAccount::UpdateOhosAccountInfo(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto *asyncContext = new (std::nothrow) DistributedAccountAsyncContext(env);
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return nullptr;
    }
    asyncContext->throwErr = throwErr;
    std::unique_ptr<DistributedAccountAsyncContext> contextPtr(asyncContext);
    if (!ParseUpdateOhosAccountInfoAsyncContext(env, cbInfo, asyncContext) && throwErr) {
        std::string errMsg = "Parameter error. The type of \"accountInfo\" must be DistributedInfo,"
            " the type of \"callback\" must be function";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return nullptr;
    }
    napi_value result = SetOhosAccountInfo(env, asyncContext);
    contextPtr.release();
    return result;
}
} // namespace AccountJsKit
} // namespace OHOS

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports)
{
    return OHOS::AccountJsKit::NapiDistributedAccount::Init(env, exports);
}
EXTERN_C_END

/*
 * module define
 */
static napi_module _module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "account.distributedAccount",
    .nm_priv = ((void*)0),
    .reserved = {0}
};
/*
 * module register
 */
extern "C" __attribute__((constructor)) void Register()
{
    napi_module_register(&_module);
}

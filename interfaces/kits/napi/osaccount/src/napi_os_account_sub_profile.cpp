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

#include <unordered_set>
#include "napi_os_account.h"
#include "napi_os_account_sub_profile_manager.h"

#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "napi_account_common.h"
#include "napi_account_error.h"
#include "napi_common_want.h"
#include "napi_os_account_common.h"
#include "napi/native_common.h"
#include "os_account_manager.h"
#include "os_account_subprofile_client.h"
#include "want.h"

using namespace OHOS::AccountSA;

namespace OHOS {
namespace AccountJsKit {
namespace {
static thread_local napi_ref subProfileRef_ = nullptr;
static std::unordered_set<napi_env> g_registeredEnvs;
static std::mutex g_envRegistrationLock;
std::mutex g_lockForSubspaceSubscribers;
std::vector<std::shared_ptr<SubspaceSubscriber>> g_subspaceSubscribers;

static void CreateOsAccountSubProfileExecuteCB(napi_env env, void *data)
{
    auto *ctx = reinterpret_cast<SubProfileAsyncContext *>(data);
    ctx->errCode = OsAccountSubProfileClient::GetInstance().CreateOsAccountSubProfile(
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
    ctx->errCode = OsAccountSubProfileClient::GetInstance().DeleteOsAccountSubProfile(
        ctx->osAccountId, ctx->subProfileId);
}

static void SwitchOsAccountSubProfileExecuteCB(napi_env env, void *data)
{
    auto *ctx = reinterpret_cast<SubProfileAsyncContext *>(data);
    ctx->errCode = OsAccountSubProfileClient::GetInstance().SwitchOsAccountSubProfile(
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

static void OnDistributedAccountEnvCleanup(void* data)
{
    ACCOUNT_LOGI("Start.");
    napi_env cleanupEnv = static_cast<napi_env>(data);
    {
        std::lock_guard<std::mutex> lock(g_lockForSubspaceSubscribers);
        auto it = g_subspaceSubscribers.begin();
        while (it != g_subspaceSubscribers.end()) {
            if ((*it)->env == cleanupEnv) {
                ACCOUNT_LOGW("Removing subscriber for destroyed environment");
                ErrCode errCode = OsAccountSubProfileClient::GetInstance().UnsubscribeOsAccountSubProfileEvents(*it);
                if (errCode != ERR_OK) {
                    ACCOUNT_LOGE("Unsubscribe failed during env cleanup, errCode=%{public}d", errCode);
                }
                it = g_subspaceSubscribers.erase(it);
            } else {
                ++it;
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(g_envRegistrationLock);
        g_registeredEnvs.erase(cleanupEnv);
    }
}

static bool RegisterDistributedAccountEnvCleanupHook(napi_env env)
{
    std::lock_guard<std::mutex> lock(g_envRegistrationLock);
    if (g_registeredEnvs.find(env) != g_registeredEnvs.end()) {
        return true;
    }
    napi_status status = napi_add_env_cleanup_hook(env, OnDistributedAccountEnvCleanup, env);
    if (status == napi_ok) {
        g_registeredEnvs.insert(env);
        return true;
    }
    return false;
}

SubspaceSubscriber::SubspaceSubscriber(napi_env &env, napi_ref &ref)
{
    this->env = env;
    this->callback = std::make_shared<NapiCallbackRef>(env, ref);
}

SubspaceSubscriber::~SubspaceSubscriber()
{
    if (callback != nullptr) {
        callback.reset();
    }
}

std::function<void()> SubspaceEventNotifyTask(const std::shared_ptr<SubspaceEventWorker> &worker)
{
    return [worker] {
        ACCOUNT_LOGI("Enter SubspaceEventNotifyTask task");
        if (worker->callback == nullptr || worker->callback->callbackRef == nullptr) {
            ACCOUNT_LOGE("Callback is nullptr");
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(worker->env, &scope);
        if (scope == nullptr) {
            ACCOUNT_LOGE("Fail to open scope");
            return;
        }

        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(worker->env, napi_create_object(worker->env, &result));
        napi_value eventValue = nullptr;
        NAPI_CALL_RETURN_VOID(worker->env,
            napi_create_int32(worker->env, static_cast<int32_t>(worker->eventData.type_), &eventValue));
        NAPI_CALL_RETURN_VOID(worker->env, napi_set_named_property(worker->env, result, "event", eventValue));
        napi_value osAccountIdValue = nullptr;
        NAPI_CALL_RETURN_VOID(worker->env,
            napi_create_int32(worker->env, worker->eventData.osAccountId_, &osAccountIdValue));
        NAPI_CALL_RETURN_VOID(worker->env,
            napi_set_named_property(worker->env, result, "osAccountLocalId", osAccountIdValue));
        napi_value subspaceIdValue = nullptr;
        NAPI_CALL_RETURN_VOID(worker->env,
            napi_create_int32(worker->env, worker->eventData.subspaceId_, &subspaceIdValue));
        NAPI_CALL_RETURN_VOID(worker->env,
            napi_set_named_property(worker->env, result, "subProfileId", subspaceIdValue));
        napi_value previousSubspaceIdValue = nullptr;
        if (worker->eventData.previousSubspaceId_ != -1) {
            NAPI_CALL_RETURN_VOID(worker->env,
                napi_create_int32(worker->env, worker->eventData.previousSubspaceId_, &previousSubspaceIdValue));
            NAPI_CALL_RETURN_VOID(worker->env,
                napi_set_named_property(worker->env, result, "previousSubProfileId", previousSubspaceIdValue));
        }
        napi_value undefined = nullptr;
        NAPI_CALL_RETURN_VOID(worker->env, napi_get_undefined(worker->env, &undefined));
        napi_value callback = nullptr;
        NAPI_CALL_RETURN_VOID(worker->env,
            napi_get_reference_value(worker->env, worker->callback->callbackRef, &callback));
        napi_value args[1] = { result };
        NAPI_CALL_RETURN_VOID(worker->env, napi_call_function(worker->env, undefined, callback, 1, args, nullptr));
        napi_close_handle_scope(worker->env, scope);
    };
}

void SubspaceSubscriber::OnSubProfileAccountsChanged(const DistributedAccountSubProfileEventData &eventData)
{
    std::shared_ptr<SubspaceEventWorker> worker = std::make_shared<SubspaceEventWorker>();
    if (worker == nullptr) {
        ACCOUNT_LOGE("failed to create SubspaceEventWorker");
        return;
    }
    worker->env = env;
    worker->eventData = eventData;
    worker->subscriber = shared_from_this();
    worker->callback = callback;
    auto task = SubspaceEventNotifyTask(worker);
    if (napi_ok != napi_send_event(env, task, napi_eprio_vip, "OnSubProfileAccountsChanged")) {
        ACCOUNT_LOGE("napi_send_event failed");
    }
    ACCOUNT_LOGI("Post task finish");
}

static bool ParseSubspaceEventArray(napi_env env, napi_value array,
    std::set<DistributedAccountSubProfileEventType> &types)
{
    bool isArray = false;
    NAPI_CALL_BASE(env, napi_is_array(env, array, &isArray), false);
    if (!isArray) {
        ACCOUNT_LOGE("argv[0] is not array");
        std::string errMsg = "Parameter error. The type of \"events\" must be array";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    uint32_t arrayLen = 0;
    NAPI_CALL_BASE(env, napi_get_array_length(env, array, &arrayLen), false);
    if (arrayLen == 0) {
        ACCOUNT_LOGE("events array is empty");
        std::string errMsg = "Parameter error. The \"events\" array cannot be empty";
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, errMsg, true);
        return false;
    }
    for (uint32_t i = 0; i < arrayLen; i++) {
        napi_value element = nullptr;
        NAPI_CALL_BASE(env, napi_get_element(env, array, i, &element), false);
        int32_t eventValue = 0;
        if (!GetIntProperty(env, element, eventValue)) {
            ACCOUNT_LOGE("Get event value failed at index %{public}u", i);
            std::string errMsg = "Parameter error. The type of element at index " + std::to_string(i) +
                " in \"events\" must be number";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
            return false;
        }
        if (eventValue < static_cast<int32_t>(DistributedAccountSubProfileEventType::CREATED) ||
            eventValue >= static_cast<int32_t>(DistributedAccountSubProfileEventType::INVALID_TYPE)) {
            ACCOUNT_LOGE("Invalid event value %{public}d", eventValue);
            std::string errMsg = "Parameter error. The event value at index " + std::to_string(i) +
                " must be a valid OsAccountSubspaceEvent";
            AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, errMsg, true);
            return false;
        }
        types.insert(static_cast<DistributedAccountSubProfileEventType>(eventValue));
    }
    return true;
}

static bool ParseParaOnOsAccountSubspaceEvent(napi_env env, napi_callback_info cbInfo,
    napi_ref &tempRef, std::set<DistributedAccountSubProfileEventType> &types)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr), false);
    if (argc < ARGS_SIZE_TWO) {
        ACCOUNT_LOGE("argc is invalid");
        std::string errMsg = "Parameter error. The number of parameters should be 2";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!ParseSubspaceEventArray(env, argv[PARAMZERO], types)) {
        return false;
    }
    if (!GetCallbackPropertyWithoutNull(env, argv[PARAMONE], tempRef, 1)) {
        if (tempRef != nullptr) {
            napi_delete_reference(env, tempRef);
            tempRef = nullptr;
        }
        ACCOUNT_LOGE("Get callbackRef failed");
        std::string errMsg = "Parameter error. The type of \"callback\" must be function";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    return true;
}

napi_value NapiOsAccountSubProfileManager::onOsAccountSubProfileEvent(napi_env env, napi_callback_info cbInfo)
{
    if (!RegisterDistributedAccountEnvCleanupHook(env)) {
        ACCOUNT_LOGE("Failed to register env cleanup hook");
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    napi_ref tempRef = nullptr;
    std::set<DistributedAccountSubProfileEventType> types;
    if (!ParseParaOnOsAccountSubspaceEvent(env, cbInfo, tempRef, types)) {
        ACCOUNT_LOGE("Parse parameters for onOsAccountSubProfileEvent failed");
        return nullptr;
    }

    auto newSubscriber = std::make_shared<SubspaceSubscriber>(env, tempRef);
    tempRef = nullptr;
    std::shared_ptr<SubspaceSubscriber> subscriber = nullptr;
    bool hasExistingRecord = false;

    std::lock_guard<std::mutex> lock(g_lockForSubspaceSubscribers);
    for (const auto &item : g_subspaceSubscribers) {
        if (item->env == env && item->callback != nullptr && newSubscriber->callback != nullptr &&
            CompareOnAndOffRef(env, item->callback->callbackRef, newSubscriber->callback->callbackRef)) {
            hasExistingRecord = true;
            subscriber = item;
            break;
        }
    }

    if (!hasExistingRecord) {
        subscriber = newSubscriber;
    }

    ErrCode errCode = OsAccountSubProfileClient::GetInstance().SubscribeOsAccountSubProfileEvents(types, subscriber);
    if (errCode == ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR) {
        AccountNapiThrow(env, ERR_JS_IS_NOT_SYSTEM_APP);
        return nullptr;
    }
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Subscribe subspace events failed with errCode=%{public}d", errCode);
        AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
        return nullptr;
    }
    if (!hasExistingRecord) {
        g_subspaceSubscribers.emplace_back(subscriber);
    }
    ACCOUNT_LOGI("Subspace subscriber added, total=%zu", g_subspaceSubscribers.size());
    return nullptr;
}

static bool ParseParaOffOsAccountSubspaceEvent(napi_env env, napi_callback_info cbInfo, napi_ref &tempRef)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr), false);
    if (argc == 0) {
        return true;
    }
    if (!GetCallbackProperty(env, argv[PARAMZERO], tempRef, 1)) {
        if (tempRef != nullptr) {
            napi_delete_reference(env, tempRef);
            tempRef = nullptr;
        }
        ACCOUNT_LOGE("Get callback property failed");
        std::string errMsg = "Parameter error. The type of \"callback\" must be function";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    return true;
}

napi_value NapiOsAccountSubProfileManager::offOsAccountSubProfileEvent(napi_env env, napi_callback_info cbInfo)
{
    if (AccountPermissionManager::CheckSystemApp(false) != ERR_OK) {
        AccountNapiThrow(env, ERR_JS_IS_NOT_SYSTEM_APP);
        return nullptr;
    }
    napi_ref tempRef = nullptr;
    if (!ParseParaOffOsAccountSubspaceEvent(env, cbInfo, tempRef)) {
        ACCOUNT_LOGE("Parse parameters for offOsAccountSubProfileEvent failed");
        return nullptr;
    }
    auto targetSubscriber = std::make_shared<SubspaceSubscriber>(env, tempRef);
    tempRef = nullptr;

    std::lock_guard<std::mutex> lock(g_lockForSubspaceSubscribers);
    auto it = g_subspaceSubscribers.begin();
    while (it != g_subspaceSubscribers.end()) {
        if ((*it)->env != env) {
            it++;
            continue;
        }
        if (targetSubscriber->callback != nullptr && targetSubscriber->callback->callbackRef != nullptr &&
            !CompareOnAndOffRef(env, (*it)->callback->callbackRef, targetSubscriber->callback->callbackRef)) {
            it++;
            continue;
        }

        ErrCode errCode = OsAccountSubProfileClient::GetInstance().UnsubscribeOsAccountSubProfileEvents(*it);
        if (errCode == ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR) {
            AccountNapiThrow(env, ERR_JS_IS_NOT_SYSTEM_APP);
            return nullptr;
        }
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Unsubscribe subspace events failed with errCode=%{public}d", errCode);
            AccountNapiThrow(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION, true);
            return nullptr;
        }
        it = g_subspaceSubscribers.erase(it);
        if (targetSubscriber->callback != nullptr && targetSubscriber->callback->callbackRef != nullptr) {
            ACCOUNT_LOGI("Unsubscribe specific callback succeed");
            return nullptr;
        }
    }
    ACCOUNT_LOGI("Unsubscribe subspace events succeed");
    return nullptr;
}

static bool ParseParaGetForegroundSubProfileId(napi_env env, napi_callback_info cbInfo,
    GetOsAccountSubProfileInfoAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr), false);
    if (argc == ARGS_SIZE_ZERO) {
        asyncContext->hasLocalId = false;
        return true;
    }
    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->localId)) {
        ACCOUNT_LOGE("Get osAccountId failed");
        std::string errMsg = "Parameter error. The type of \"osAccountId\" must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    asyncContext->hasLocalId = true;
    return true;
}

static void GetForegroundSubProfileIdExecuteCB(napi_env env, void *data)
{
    GetOsAccountSubProfileInfoAsyncContext *asyncContext =
        reinterpret_cast<GetOsAccountSubProfileInfoAsyncContext *>(data);
    if (asyncContext->hasLocalId) {
        asyncContext->errCode = OsAccountSubProfileClient::GetInstance().GetOsAccountForegroundSubProfileId(
            asyncContext->localId, asyncContext->subProfileId);
    } else {
        asyncContext->errCode = OsAccountSubProfileClient::GetInstance().GetOsAccountForegroundSubProfileId(
            asyncContext->subProfileId);
    }
}

static void GetForegroundSubProfileIdCompletedCB(napi_env env, napi_status status, void *data)
{
    GetOsAccountSubProfileInfoAsyncContext *asyncContext =
        reinterpret_cast<GetOsAccountSubProfileInfoAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == ERR_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &errJs));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->subProfileId, &dataJs));
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode);
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &dataJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    delete asyncContext;
}

napi_value NapiOsAccountSubProfileManager::GetOsAccountForegroundSubProfileId(napi_env env, napi_callback_info cbInfo)
{
    auto asyncContext = std::make_unique<GetOsAccountSubProfileInfoAsyncContext>();
    asyncContext->env = env;
    asyncContext->throwErr = true;

    if (!ParseParaGetForegroundSubProfileId(env, cbInfo, asyncContext.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetOsAccountForegroundSubProfileId", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        GetForegroundSubProfileIdExecuteCB,
        GetForegroundSubProfileIdCompletedCB,
        reinterpret_cast<void *>(asyncContext.get()),
        &asyncContext->work));

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated));
    asyncContext.release();
    return result;
}

static bool ParseParaGetSubProfileIds(napi_env env, napi_callback_info cbInfo,
    GetOsAccountSubProfileInfoAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr), false);
    if (argc == ARGS_SIZE_ZERO) {
        asyncContext->hasLocalId = false;
        return true;
    }
    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->localId)) {
        ACCOUNT_LOGE("Get osAccountId failed");
        std::string errMsg = "Parameter error. The type of \"osAccountId\" must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    asyncContext->hasLocalId = true;
    return true;
}

static void GetSubProfileIdsExecuteCB(napi_env env, void *data)
{
    GetOsAccountSubProfileInfoAsyncContext *asyncContext =
        reinterpret_cast<GetOsAccountSubProfileInfoAsyncContext *>(data);
    if (asyncContext->hasLocalId) {
        asyncContext->errCode = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileIds(
            asyncContext->localId, asyncContext->subProfileIds);
    } else {
        asyncContext->errCode = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileIds(
            asyncContext->subProfileIds);
    }
}

static void GetSubProfileIdsCompletedCB(napi_env env, napi_status status, void *data)
{
    GetOsAccountSubProfileInfoAsyncContext *asyncContext =
        reinterpret_cast<GetOsAccountSubProfileInfoAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == ERR_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &errJs));
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &dataJs));
        uint32_t index = 0;
        for (const auto& id : asyncContext->subProfileIds) {
            napi_value jsId = nullptr;
            NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, id, &jsId));
            NAPI_CALL_RETURN_VOID(env, napi_set_element(env, dataJs, index, jsId));
            index++;
        }
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &dataJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    delete asyncContext;
}

napi_value NapiOsAccountSubProfileManager::GetOsAccountSubProfileIds(napi_env env, napi_callback_info cbInfo)
{
    auto getOASubProfileIds = std::make_unique<GetOsAccountSubProfileInfoAsyncContext>();
    getOASubProfileIds->env = env;
    getOASubProfileIds->throwErr = true;

    if (!ParseParaGetSubProfileIds(env, cbInfo, getOASubProfileIds.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &getOASubProfileIds->deferred, &result));

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetOsAccountSubProfileIds", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        GetSubProfileIdsExecuteCB,
        GetSubProfileIdsCompletedCB,
        reinterpret_cast<void *>(getOASubProfileIds.get()),
        &getOASubProfileIds->work));

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, getOASubProfileIds->work, napi_qos_user_initiated));
    getOASubProfileIds.release();
    return result;
}

static bool ParseParaGetLocalIdForSubProfile(napi_env env, napi_callback_info cbInfo,
    GetOsAccountSubProfileInfoAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr), false);
    if (argc == ARGS_SIZE_ZERO) {
        ACCOUNT_LOGE("The number of parameters should be at least 1");
        std::string errMsg = "Parameter error. The number of parameters should be at least 1";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->subProfileId)) {
        ACCOUNT_LOGE("Get subProfileId failed");
        std::string errMsg = "Parameter error. The type of \"subProfileId\" must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    return true;
}

static void GetLocalIdForSubProfileExecuteCB(napi_env env, void *data)
{
    GetOsAccountSubProfileInfoAsyncContext *asyncContext =
        reinterpret_cast<GetOsAccountSubProfileInfoAsyncContext *>(data);
    asyncContext->errCode = OsAccountSubProfileClient::GetInstance().GetOsAccountLocalIdForSubProfile(
        asyncContext->subProfileId, asyncContext->localId);
}

static void GetLocalIdForSubProfileCompletedCB(napi_env env, napi_status status, void *data)
{
    GetOsAccountSubProfileInfoAsyncContext *asyncContext =
        reinterpret_cast<GetOsAccountSubProfileInfoAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == ERR_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &errJs));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->localId, &dataJs));
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode);
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &dataJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    delete asyncContext;
}

napi_value NapiOsAccountSubProfileManager::GetOsAccountLocalIdForSubProfile(napi_env env, napi_callback_info cbInfo)
{
    auto getOALocalIdForSubProfile = std::make_unique<GetOsAccountSubProfileInfoAsyncContext>();
    getOALocalIdForSubProfile->env = env;
    getOALocalIdForSubProfile->throwErr = true;

    if (!ParseParaGetLocalIdForSubProfile(env, cbInfo, getOALocalIdForSubProfile.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &getOALocalIdForSubProfile->deferred, &result));

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetOsAccountLocalIdForSubProfile", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        GetLocalIdForSubProfileExecuteCB,
        GetLocalIdForSubProfileCompletedCB,
        reinterpret_cast<void *>(getOALocalIdForSubProfile.get()),
        &getOALocalIdForSubProfile->work));

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, getOALocalIdForSubProfile->work, napi_qos_user_initiated));
    getOALocalIdForSubProfile.release();
    return result;
}

static bool ParseParaGetSubProfile(napi_env env, napi_callback_info cbInfo,
    GetOsAccountSubProfileAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr), false);
    if (argc == ARGS_SIZE_ZERO) {
        ACCOUNT_LOGE("The number of parameters should be at least 1");
        std::string errMsg = "Parameter error. The number of parameters should be at least 1";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }

    if (argc == ARGS_SIZE_TWO) {
        if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->localId)) {
            ACCOUNT_LOGE("Get localId failed");
            std::string errMsg = "Parameter error. The type of \"osAccountId\" must be number";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
        if (!GetIntProperty(env, argv[PARAMONE], asyncContext->subProfileId)) {
            ACCOUNT_LOGE("Get subProfileId failed");
            std::string errMsg = "Parameter error. The type of \"subProfileId\" must be number";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
        asyncContext->hasLocalId = true;
    } else {
        if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->subProfileId)) {
            ACCOUNT_LOGE("Get subProfileId failed");
            std::string errMsg = "Parameter error. The type of \"subProfileId\" must be number";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
        asyncContext->hasLocalId = false;
    }
    return true;
}

static void GetSubProfileExecuteCB(napi_env env, void *data)
{
    GetOsAccountSubProfileAsyncContext *asyncContext =
        reinterpret_cast<GetOsAccountSubProfileAsyncContext *>(data);
    if (asyncContext->hasLocalId) {
        asyncContext->errCode = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(
            asyncContext->localId, asyncContext->subProfileId,
            asyncContext->subspaceResult, asyncContext->distributedInfo);
    } else {
        asyncContext->errCode = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(
            asyncContext->subProfileId, asyncContext->subspaceResult, asyncContext->distributedInfo);
    }
}

static void GetSubProfileCompletedCB(napi_env env, napi_status status, void *data)
{
    GetOsAccountSubProfileAsyncContext *asyncContext =
        reinterpret_cast<GetOsAccountSubProfileAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == ERR_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &errJs));
        napi_value obj;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &obj));
        napi_value idVal;
        napi_value osAccountIdVal;
        napi_value indexVal;
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->subspaceResult.id, &idVal));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->subspaceResult.osAccountId,
            &osAccountIdVal));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->subspaceResult.index, &indexVal));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, obj, "id", idVal));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, obj, "osAccountLocalId", osAccountIdVal));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, obj, "index", indexVal));
        if (asyncContext->distributedInfo.status_ != ACCOUNT_STATE_UNBOUND) {
            napi_value distInfo = BuildDistributedInfoFromOhosAccountInfo(env, asyncContext->distributedInfo);
            NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, obj, "distributedInfo", distInfo));
        }
        dataJs = obj;
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode);
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &dataJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    delete asyncContext;
}

napi_value NapiOsAccountSubProfileManager::GetOsAccountSubProfile(napi_env env, napi_callback_info cbInfo)
{
    auto getOASubProfile = std::make_unique<GetOsAccountSubProfileAsyncContext>();
    getOASubProfile->env = env;
    getOASubProfile->throwErr = true;

    if (!ParseParaGetSubProfile(env, cbInfo, getOASubProfile.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &getOASubProfile->deferred, &result));

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetOsAccountSubProfile", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        GetSubProfileExecuteCB,
        GetSubProfileCompletedCB,
        reinterpret_cast<void *>(getOASubProfile.get()),
        &getOASubProfile->work));

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, getOASubProfile->work, napi_qos_user_initiated));
    getOASubProfile.release();
    return result;
}

napi_value NapiOsAccountSubProfileManager::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptor[] = {
        DECLARE_NAPI_FUNCTION("getOsAccountSubProfileManager", GetOsAccountSubProfileManager),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor),
        descriptor));

    napi_value osAccountSubProfileEvent = nullptr;
    napi_create_object(env, &osAccountSubProfileEvent);
    SetEnumProperty(env, osAccountSubProfileEvent,
        static_cast<int>(DistributedAccountSubProfileEventType::CREATED), "CREATED");
    SetEnumProperty(env, osAccountSubProfileEvent,
        static_cast<int>(DistributedAccountSubProfileEventType::DELETED), "DELETED");
    SetEnumProperty(env, osAccountSubProfileEvent,
        static_cast<int>(DistributedAccountSubProfileEventType::SWITCHING), "SWITCHING");
    SetEnumProperty(env, osAccountSubProfileEvent,
        static_cast<int>(DistributedAccountSubProfileEventType::SWITCHED), "SWITCHED");

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("createOsAccountSubProfile", CreateOsAccountSubProfile),
        DECLARE_NAPI_FUNCTION("deleteOsAccountSubProfile", DeleteOsAccountSubProfile),
        DECLARE_NAPI_FUNCTION("switchOsAccountSubProfile", SwitchOsAccountSubProfile),
        DECLARE_NAPI_FUNCTION("onOsAccountSubProfileEvent", onOsAccountSubProfileEvent),
        DECLARE_NAPI_FUNCTION("offOsAccountSubProfileEvent", offOsAccountSubProfileEvent),
        DECLARE_NAPI_FUNCTION("getOsAccountForegroundSubProfileId", GetOsAccountForegroundSubProfileId),
        DECLARE_NAPI_FUNCTION("getOsAccountSubProfileIds", GetOsAccountSubProfileIds),
        DECLARE_NAPI_FUNCTION("getOsAccountLocalIdForSubProfile", GetOsAccountLocalIdForSubProfile),
        DECLARE_NAPI_FUNCTION("getOsAccountSubProfile", GetOsAccountSubProfile),
    };
    napi_property_descriptor exportEnum[] = {
        DECLARE_NAPI_PROPERTY("OsAccountSubProfileEvent", osAccountSubProfileEvent),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(exportEnum) / sizeof(*exportEnum), exportEnum));

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
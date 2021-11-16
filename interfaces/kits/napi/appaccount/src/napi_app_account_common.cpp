/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <uv.h>
#include "app_account_manager.h"
#include "napi_app_account_common.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;

std::map<AppAccountManager *, AsyncContextForSubscribe *> subscriberInstances;

SubscriberPtr::SubscriberPtr(const AppAccountSubscribeInfo &subscribeInfo) : AppAccountSubscriber(subscribeInfo)
{}

SubscriberPtr::~SubscriberPtr()
{}

void UvQueueWorkOnAccountsChanged(uv_work_t *work, int status)
{
    ACCOUNT_LOGI("enter");

    if (work == nullptr) {
        return;
    }
    SubscriberAccountsWorker *subscriberAccountsWorkerData = (SubscriberAccountsWorker *)work->data;
    if (subscriberAccountsWorkerData == nullptr) {
        return;
    }

    int32_t index = 0;
    napi_value results[ARGS_SIZE_ONE] = {nullptr};
    napi_create_array(subscriberAccountsWorkerData->env, &results[0]);

    for (auto item : subscriberAccountsWorkerData->accounts) {
        napi_value objAppAccountInfo = nullptr;
        napi_create_object(subscriberAccountsWorkerData->env, &objAppAccountInfo);

        std::string name;
        item.GetName(name);
        ACCOUNT_LOGI("The name %{public}s transfer to a js value.", name.c_str());
        napi_value nName;
        napi_create_string_utf8(subscriberAccountsWorkerData->env, name.c_str(), NAPI_AUTO_LENGTH, &nName);
        napi_set_named_property(subscriberAccountsWorkerData->env, objAppAccountInfo, "name", nName);

        std::string owner;
        item.GetOwner(owner);
        ACCOUNT_LOGI("The owner %{public}s transfer to a js value.", owner.c_str());
        napi_value nOwner = nullptr;
        napi_create_string_utf8(subscriberAccountsWorkerData->env, owner.c_str(), NAPI_AUTO_LENGTH, &nOwner);
        napi_set_named_property(subscriberAccountsWorkerData->env, objAppAccountInfo, "owner", nOwner);

        napi_set_element(subscriberAccountsWorkerData->env, results[0], index, objAppAccountInfo);
        index++;
    }

    napi_value undefined = nullptr;
    napi_get_undefined(subscriberAccountsWorkerData->env, &undefined);

    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    napi_get_reference_value(subscriberAccountsWorkerData->env, subscriberAccountsWorkerData->ref, &callback);

    NAPI_CALL_RETURN_VOID(subscriberAccountsWorkerData->env,
        napi_call_function(
            subscriberAccountsWorkerData->env, undefined, callback, ARGS_SIZE_ONE, &results[0], &resultout));

    delete subscriberAccountsWorkerData;
    subscriberAccountsWorkerData = nullptr;
    delete work;
    work = nullptr;

    ACCOUNT_LOGI("end");
}

void SubscriberPtr::OnAccountsChanged(const std::vector<AppAccountInfo> &accounts_)
{
    ACCOUNT_LOGI("enter");

    ErrCode result;
    std::string owner;
    std::string name;
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        ACCOUNT_LOGI("loop instance is nullptr");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        ACCOUNT_LOGI("work is null");
        return;
    }

    SubscriberAccountsWorker *subscriberAccountsWorker = new (std::nothrow) SubscriberAccountsWorker();

    if (subscriberAccountsWorker == nullptr) {
        ACCOUNT_LOGI("SubscriberAccountsWorker is null");
        return;
    }

    for (auto account : accounts_) {
        result = account.GetOwner(owner);
        ACCOUNT_LOGI("owner = %{public}s", owner.c_str());

        result = account.GetName(name);
        ACCOUNT_LOGI("name = %{public}s", name.c_str());
    }

    subscriberAccountsWorker->accounts = accounts_;
    subscriberAccountsWorker->env = env_;
    subscriberAccountsWorker->ref = ref_;

    ACCOUNT_LOGI("subscriberAccountsWorker->ref == %{public}p", subscriberAccountsWorker->ref);

    work->data = (void *)subscriberAccountsWorker;

    uv_queue_work(loop, work, [](uv_work_t *work) {}, UvQueueWorkOnAccountsChanged);

    ACCOUNT_LOGI("end");
}

void SubscriberPtr::SetEnv(const napi_env &env)
{
    env_ = env;
}

void SubscriberPtr::SetCallbackRef(const napi_ref &ref)
{
    ref_ = ref;
}

napi_value NapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);

    return result;
}

std::string GetNamedProperty(napi_env env, napi_value obj)
{
    ACCOUNT_LOGI("enter");
    char propValue[MAX_VALUE_LEN] = {0};
    size_t propLen;
    if (napi_get_value_string_utf8(env, obj, propValue, MAX_VALUE_LEN, &propLen) != napi_ok) {
        ACCOUNT_LOGI("Can not get string param from argv");
    }

    return std::string(propValue);
}

napi_value GetErrorCodeValue(napi_env env, int errCode)
{
    ACCOUNT_LOGI("Enter GetErrorCodeValue function.");
    napi_value jsObject = nullptr;
    napi_value jsValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errCode, &jsValue));
    NAPI_CALL(env, napi_create_object(env, &jsObject));
    NAPI_CALL(env, napi_set_named_property(env, jsObject, "code", jsValue));
    return jsObject;
}

void GetAppAccountInfoForResult(napi_env env, const std::vector<AppAccountInfo> &info, napi_value result)
{
    ACCOUNT_LOGI("enter");

    int32_t index = 0;

    for (auto item : info) {
        napi_value objAppAccountInfo = nullptr;
        napi_create_object(env, &objAppAccountInfo);

        std::string name;
        item.GetName(name);
        napi_value nName = nullptr;
        napi_create_string_utf8(env, name.c_str(), NAPI_AUTO_LENGTH, &nName);
        napi_set_named_property(env, objAppAccountInfo, "name", nName);

        std::string owner;
        item.GetOwner(owner);
        napi_value nOwner = nullptr;
        napi_create_string_utf8(env, owner.c_str(), NAPI_AUTO_LENGTH, &nOwner);
        napi_set_named_property(env, objAppAccountInfo, "owner", nOwner);

        napi_set_element(env, result, index, objAppAccountInfo);
        index++;
    }
}

void ParseContextWithExInfo(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            asyncContext->name = GetNamedProperty(env, argv[i]);
        } else if (i == 1 && valueType == napi_string) {
            asyncContext->extraInfo = GetNamedProperty(env, argv[i]);
        } else if (i == 1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext->callbackRef);
            break;
        } else if (i == PARAMTWO && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
        }
    }
}

void ParseContextForSetExInfo(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            asyncContext->name = GetNamedProperty(env, argv[i]);
        } else if (i == 1 && valueType == napi_string) {
            asyncContext->extraInfo = GetNamedProperty(env, argv[i]);
        } else if (i == PARAMTWO && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
        }
    }
}

void ParseContextForSetOAuth(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            asyncContext->name = GetNamedProperty(env, argv[i]);
        } else if (i == 1 && valueType == napi_string) {
            asyncContext->token = GetNamedProperty(env, argv[i]);
        } else if (i == PARAMTWO && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
        }
    }
}

void ParseContextWithBdName(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            asyncContext->name = GetNamedProperty(env, argv[i]);
        } else if (i == 1 && valueType == napi_string) {
            asyncContext->bundleName = GetNamedProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
        }
    }
}

void ParseContextWithIsEnable(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            asyncContext->name = GetNamedProperty(env, argv[i]);
        } else if (i == 1 && valueType == napi_boolean) {
            napi_get_value_bool(env, argv[i], &asyncContext->isEnable);
            if (asyncContext->isEnable) {
                ACCOUNT_LOGE("isEnable para is true");
            } else {
                ACCOUNT_LOGE("isEnable para is false");
            }
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
        }
    }
}

void ParseContextWithTwoPara(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            asyncContext->name = GetNamedProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
        }
    }
}

void ParseContextToSetCredential(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            asyncContext->name = GetNamedProperty(env, argv[i]);
        } else if (i == 1 && valueType == napi_string) {
            asyncContext->credentialType = GetNamedProperty(env, argv[i]);
        } else if (i == PARAMTWO && valueType == napi_string) {
            asyncContext->credential = GetNamedProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
        }
    }
}

void ParseContextForAssociatedData(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            asyncContext->name = GetNamedProperty(env, argv[i]);
        } else if (i == 1 && valueType == napi_string) {
            asyncContext->key = GetNamedProperty(env, argv[i]);
        } else if (i == PARAMTWO && valueType == napi_string) {
            asyncContext->value = GetNamedProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
        }
    }
}

void ParseContextToGetData(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            asyncContext->name = GetNamedProperty(env, argv[i]);
        } else if (i == 1 && valueType == napi_string) {
            asyncContext->key = GetNamedProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
        }
    }
}

void ParseContextCBArray(napi_env env, napi_callback_info cbInfo, GetAccountsAsyncContext *asyncContext)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    bool callBackMode = false;
    if (argc >= 1) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[0], &valueType);
        callBackMode = valueType == napi_function ? true : false;
    }

    if (callBackMode) {
        napi_create_reference(env, argv[0], 1, &asyncContext->callbackRef);
    }
}

void ParseContextWithCredentialType(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            asyncContext->name = GetNamedProperty(env, argv[i]);
        } else if (i == 1 && valueType == napi_string) {
            asyncContext->credentialType = GetNamedProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
        }
    }
}

void ParseContextWithStrCBArray(napi_env env, napi_callback_info cbInfo, GetAccountsAsyncContext *asyncContext)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            asyncContext->owner = GetNamedProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
        }
    }
}

void ProcessCallbackOrPromise(napi_env env, const AppAccountAsyncContext *asyncContext, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("Enter ProcessCallbackOrPromise function.");
    napi_value args[RESULT_COUNT] = {err, data};
    if (asyncContext->deferred) {
        ACCOUNT_LOGI("Promise");
        if (asyncContext->status == napi_ok) {
            napi_resolve_deferred(env, asyncContext->deferred, args[1]);
        } else {
            napi_reject_deferred(env, asyncContext->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (asyncContext->callbackRef != nullptr) {
            napi_delete_reference(env, asyncContext->callbackRef);
        }
    }
}

void ProcessCallbackOrPromiseCBArray(
    napi_env env, const GetAccountsAsyncContext *asyncContext, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("Enter ProcessCallbackOrPromiseCBArray function.");
    napi_value args[RESULT_COUNT] = {err, data};
    if (asyncContext->deferred) {
        ACCOUNT_LOGI("Promise");
        if (asyncContext->status == napi_ok) {
            napi_resolve_deferred(env, asyncContext->deferred, args[1]);
        } else {
            napi_reject_deferred(env, asyncContext->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (asyncContext->callbackRef != nullptr) {
            napi_delete_reference(env, asyncContext->callbackRef);
        }
    }
}

napi_value ParseParametersBySubscribe(const napi_env &env, const napi_value (&argv)[ARGS_SIZE_THREE],
    std::vector<std::string> &owners, napi_ref &callback)
{
    ACCOUNT_LOGI("ParseParametersBySubscribe start");

    bool isArray = false;
    uint32_t length = 0;
    size_t strLen = 0;
    napi_valuetype valuetype;

    // argv[0] type: 'change'
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype == napi_string) {
        std::string type = GetNamedProperty(env, argv[0]);
        if (type != "change") {
            ACCOUNT_LOGI("%{public}s, Wrong type=%{public}s", __func__, type.c_str());
            return nullptr;
        }
    } else {
        ACCOUNT_LOGI("%{public}s, Wrong argument type.", __func__);
        return nullptr;
    }

    // argv[1] owners: Array<string>
    NAPI_CALL(env, napi_is_array(env, argv[1], &isArray));
    NAPI_ASSERT(env, isArray, "Wrong argument type for arg1. Array<string> expected.");
    if (isArray) {
        NAPI_CALL(env, napi_get_array_length(env, argv[1], &length));
        NAPI_ASSERT(env, length > 0, "The array is empty.");
        for (size_t i = 0; i < length; i++) {
            napi_value ownerStr = nullptr;
            napi_get_element(env, argv[1], i, &ownerStr);
            NAPI_CALL(env, napi_typeof(env, ownerStr, &valuetype));
            NAPI_ASSERT(env, valuetype == napi_string, "Wrong argument type. String expected.");
            char str[STR_MAX_SIZE] = {0};
            NAPI_CALL(env, napi_get_value_string_utf8(env, ownerStr, str, STR_MAX_SIZE - 1, &strLen));
            ACCOUNT_LOGI("Get owners.string by subscribe str = %{public}s", str);
            owners.push_back(str);
        }
    }

    // argv[2] callback
    NAPI_CALL(env, napi_typeof(env, argv[PARAMTWO], &valuetype));
    NAPI_ASSERT(env, valuetype == napi_function, "Wrong argument type. Function expected.");
    NAPI_CALL(env, napi_create_reference(env, argv[PARAMTWO], 1, &callback));

    return NapiGetNull(env);
}

napi_value GetSubscriberByUnsubscribe(const napi_env &env, std::shared_ptr<SubscriberPtr> &subscriber,
    AsyncContextForUnsubscribe *asyncContextForOff, bool &isFind)
{
    ACCOUNT_LOGI("GetSubscriberByUnsubscribe start");
    napi_value result;
    ACCOUNT_LOGI("subscriberInstances.size = %{public}zu", subscriberInstances.size());

    for (auto subscriberInstance : subscriberInstances) {
        ACCOUNT_LOGI("Through static map to get the subscribe objectInfo = %{public}p", subscriberInstance.first);
        if (subscriberInstance.first == asyncContextForOff->appAccountManager) {
            subscriber = subscriberInstance.second->subscriber;
            isFind = true;
            break;
        }
    }

    NAPI_CALL(env, napi_get_boolean(env, isFind, &result));
    return result;
}

napi_value ParseParametersByUnsubscribe(
    const napi_env &env, const size_t &argc, const napi_value (&argv)[UNSUBSCRIBE_MAX_PARA], napi_ref &callback)
{
    ACCOUNT_LOGI("ParseParametersByUnsubscribe start");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    // argv[0]: type: 'change'
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    NAPI_ASSERT(env, valuetype == napi_string, "Wrong argument type for arg0. String expected.");
    if (valuetype == napi_string) {
        std::string type = GetNamedProperty(env, argv[0]);
        if (type != "change") {
            ACCOUNT_LOGI("%{public}s, Wrong type=%{public}s", __func__, type.c_str());
            return nullptr;
        }
    } else {
        ACCOUNT_LOGI("%{public}s, Wrong argument type.", __func__);
        return nullptr;
    }

    // argv[1]:callback
    if (argc >= UNSUBSCRIBE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
        NAPI_ASSERT(env, valuetype == napi_function, "Wrong argument type. Function expected.");
        NAPI_CALL(env, napi_create_reference(env, argv[1], 1, &callback));
    }
    return result;
}

void UnsubscribeCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("Unsubscribe napi_create_async_work end.");
    AsyncContextForUnsubscribe *asyncContextForOff = (AsyncContextForUnsubscribe *)data;

    if (asyncContextForOff->argc >= UNSUBSCRIBE_MAX_PARA) {
        napi_value result = nullptr;
        napi_get_null(env, &result);

        napi_value undefined = nullptr;
        napi_get_undefined(env, &undefined);

        napi_value callback = nullptr;
        napi_value resultout = nullptr;
        napi_get_reference_value(env, asyncContextForOff->callbackRef, &callback);

        napi_value results[ARGS_SIZE_TWO] = {nullptr};
        results[PARAM0] = result;

        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, ARGS_SIZE_ONE, &results[0], &resultout));
    }

    if (asyncContextForOff->callbackRef != nullptr) {
        napi_delete_reference(env, asyncContextForOff->callbackRef);
    }

    napi_delete_async_work(env, asyncContextForOff->work);

    ACCOUNT_LOGI("Earse before subscriberInstances.size = %{public}zu", subscriberInstances.size());
    // earse the info from map
    auto subscribe = subscriberInstances.find(asyncContextForOff->appAccountManager);
    if (subscribe != subscriberInstances.end()) {
        if (subscribe->second->callbackRef != nullptr) {
            napi_delete_reference(env, subscribe->second->callbackRef);
        }
    }
    subscriberInstances.erase(subscribe);
    ACCOUNT_LOGI("Earse end subscriberInstances.size = %{public}zu", subscriberInstances.size());

    if (asyncContextForOff) {
        ACCOUNT_LOGI("delete asyncContextForOff");
        delete asyncContextForOff;
        asyncContextForOff = nullptr;
    }
}
}  // namespace AccountJsKit
}  // namespace OHOS
/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "napi_app_account_common.h"
#include "account_log_wrapper.h"
#include "app_account_constants.h"
#include "app_account_manager.h"
#include "napi_common.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;

std::mutex g_lockForAppAccountSubscribers;
std::map<AppAccountManager *, std::vector<AsyncContextForSubscribe *>> g_AppAccountSubscribers;

SubscriberPtr::SubscriberPtr(const AppAccountSubscribeInfo &subscribeInfo) : AppAccountSubscriber(subscribeInfo)
{}

SubscriberPtr::~SubscriberPtr()
{}

void UvQueueWorkOnAppAccountsChanged(uv_work_t *work, int status)
{
    ACCOUNT_LOGD("enter");
    if (work == nullptr || work->data == nullptr) {
        return;
    }
    SubscriberAccountsWorker *subscriberAccountsWorkerData = reinterpret_cast<SubscriberAccountsWorker *>(work->data);
    uint32_t index = 0;
    napi_value results[ARGS_SIZE_ONE] = {nullptr};
    napi_create_array(subscriberAccountsWorkerData->env, &results[0]);
    for (auto item : subscriberAccountsWorkerData->accounts) {
        napi_value objAppAccountInfo = nullptr;
        napi_create_object(subscriberAccountsWorkerData->env, &objAppAccountInfo);

        std::string name;
        item.GetName(name);
        napi_value nName;
        napi_create_string_utf8(subscriberAccountsWorkerData->env, name.c_str(), NAPI_AUTO_LENGTH, &nName);
        napi_set_named_property(subscriberAccountsWorkerData->env, objAppAccountInfo, "name", nName);

        std::string owner;
        item.GetOwner(owner);
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
    bool isFound = false;
    {
        std::lock_guard<std::mutex> lock(g_lockForAppAccountSubscribers);
        for (auto objectInfoTmp : g_AppAccountSubscribers) {
            for (auto item : objectInfoTmp.second) {
                if (item->subscriber.get() == subscriberAccountsWorkerData->subscriber) {
                    isFound = true;
                    break;
                }
            }
            if (isFound) {
                break;
            }
        }
        if (isFound) {
            ACCOUNT_LOGI("app account subscriber has been found.");
            napi_get_reference_value(subscriberAccountsWorkerData->env, subscriberAccountsWorkerData->ref, &callback);
        } else {
            ACCOUNT_LOGI("app account subscriber has already been deleted, ignore callback.");
        }
    }
    if (isFound) {
        NAPI_CALL_RETURN_VOID(subscriberAccountsWorkerData->env,
            napi_call_function(subscriberAccountsWorkerData->env, undefined, callback, ARGS_SIZE_ONE,
            &results[0], &resultout));
    }

    delete subscriberAccountsWorkerData;
    subscriberAccountsWorkerData = nullptr;
    delete work;
}

void SubscriberPtr::OnAccountsChanged(const std::vector<AppAccountInfo> &accounts_)
{
    ACCOUNT_LOGD("enter");

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
        delete work;
        return;
    }

    subscriberAccountsWorker->accounts = accounts_;
    subscriberAccountsWorker->env = env_;
    subscriberAccountsWorker->ref = ref_;
    subscriberAccountsWorker->subscriber = this;

    work->data = reinterpret_cast<void *>(subscriberAccountsWorker);

    uv_queue_work(loop, work, [](uv_work_t *work) {}, UvQueueWorkOnAppAccountsChanged);

    ACCOUNT_LOGD("end");
}

void SubscriberPtr::SetEnv(const napi_env &env)
{
    env_ = env;
}

void SubscriberPtr::SetCallbackRef(const napi_ref &ref)
{
    ref_ = ref;
}

void CheckAccountLabelsOnResultWork(uv_work_t *work, int status)
{
    (void)status;
    AuthenticatorCallbackParam *param = reinterpret_cast<AuthenticatorCallbackParam*>(work->data);
    napi_value checkResult[RESULT_COUNT] = {0};
    if (param->context.errCode == ERR_JS_SUCCESS) {
        bool hasLabels = param->result.GetBoolParam(Constants::KEY_BOOLEAN_RESULT, false);
        napi_get_boolean(param->context.env, hasLabels, &checkResult[PARAMONE]);
    } else {
        checkResult[PARAMZERO] = GetErrorCodeValue(param->context.env, param->context.errCode);
    }
    ProcessCallbackOrPromise(param->context.env, &(param->context), checkResult[PARAMZERO], checkResult[PARAMONE]);
    delete param;
    delete work;
}

void SelectAccountsOnResultWork(uv_work_t *work, int status)
{
    (void)status;
    AuthenticatorCallbackParam *param = reinterpret_cast<AuthenticatorCallbackParam*>(work->data);
    std::vector<std::string> names = param->result.GetStringArrayParam(Constants::KEY_ACCOUNT_NAMES);
    std::vector<std::string> owners = param->result.GetStringArrayParam(Constants::KEY_ACCOUNT_OWNERS);
    if (names.size() != owners.size()) {
        param->context.errCode = ERR_JS_INVALID_RESPONSE;
    }
    napi_env env = param->context.env;
    napi_value selectResult[RESULT_COUNT] = {0};
    if (param->context.errCode == ERR_JS_SUCCESS) {
        napi_create_array(env, &selectResult[PARAMONE]);
        for (size_t i = 0; i < names.size(); ++i) {
            napi_value object = nullptr;
            napi_create_object(env, &object);
            napi_value value = nullptr;
            napi_create_string_utf8(env, names[i].c_str(), NAPI_AUTO_LENGTH, &value);
            napi_set_named_property(env, object, "name", value);
            napi_create_string_utf8(env, owners[i].c_str(), NAPI_AUTO_LENGTH, &value);
            napi_set_named_property(env, object, "owner", value);
            napi_set_element(env, selectResult[PARAMONE], i, object);
        }
    } else {
        selectResult[PARAMZERO] = GetErrorCodeValue(env, param->context.errCode);
    }
    ProcessCallbackOrPromise(env, &(param->context), selectResult[PARAMZERO], selectResult[PARAMONE]);
    delete param;
    delete work;
}

AuthenticatorAsyncCallback::AuthenticatorAsyncCallback(
    const CommonAsyncContext &context, uv_after_work_cb workCb)
    : context_(context), workCb_(workCb)
{
    ACCOUNT_LOGD("enter");
}

AuthenticatorAsyncCallback::~AuthenticatorAsyncCallback()
{
    ACCOUNT_LOGD("enter");
}

void AuthenticatorAsyncCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    ACCOUNT_LOGD("enter");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (isDone) {
            return;
        }
        isDone = true;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    AuthenticatorCallbackParam *param = nullptr;
    if (!InitAuthenticatorWorkEnv(context_.env, &loop, &work, &param)) {
        ACCOUNT_LOGD("failed to init work environment");
        return;
    }
    param->context = context_;
    param->context.errCode = resultCode;
    param->result = result;
    work->data = param;
    if (uv_queue_work(loop, work, [](uv_work_t *work) {}, workCb_) == ERR_OK) {
        return;
    }
    if (context_.callbackRef != nullptr) {
        napi_delete_reference(context_.env, context_.callbackRef);
    }
    delete param;
    delete work;
}

void AuthenticatorAsyncCallback::OnRequestRedirected(AAFwk::Want &request)
{}

void AuthenticatorAsyncCallback::OnRequestContinued()
{}

AppAccountManagerCallback::AppAccountManagerCallback(napi_env env, JSAuthCallback callback)
    : env_(env), callback_(callback)
{
    ACCOUNT_LOGD("enter");
}

AppAccountManagerCallback::~AppAccountManagerCallback()
{
    ACCOUNT_LOGD("enter");
}

void UvQueueWorkOnResult(uv_work_t *work, int status)
{
    if ((work == nullptr) || (work->data == nullptr)) {
        ACCOUNT_LOGE("work or data is nullptr");
        return;
    }
    AuthenticatorCallbackParam *data = reinterpret_cast<AuthenticatorCallbackParam *>(work->data);
    ProcessOnResultCallback(data->env, data->callback, data->resultCode, data->result.GetParams());
    delete data;
    data = nullptr;
    delete work;
}

void UvQueueWorkOnRequestRedirected(uv_work_t *work, int status)
{
    if ((work == nullptr) || (work->data == nullptr)) {
        ACCOUNT_LOGE("work or data is nullptr");
        return;
    }
    AuthenticatorCallbackParam *data = reinterpret_cast<AuthenticatorCallbackParam *>(work->data);
    napi_value results[ARGS_SIZE_ONE] = {nullptr};
    results[0] = AppExecFwk::WrapWant(data->env, data->request);
    napi_value undefined = nullptr;
    napi_get_undefined(data->env, &undefined);
    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    napi_get_reference_value(data->env, data->callback.onRequestRedirected, &callback);
    napi_call_function(data->env, undefined, callback, ARGS_SIZE_ONE, results, &resultout);
    delete data;
    data = nullptr;
    delete work;
}

void UvQueueWorkOnRequestContinued(uv_work_t *work, int status)
{
    (void)status;
    if ((work == nullptr) || (work->data == nullptr)) {
        ACCOUNT_LOGE("work or data is nullptr");
        return;
    }
    AuthenticatorCallbackParam *data = reinterpret_cast<AuthenticatorCallbackParam *>(work->data);
    napi_value callback = nullptr;
    napi_get_reference_value(data->env, data->callback.onRequestContinued, &callback);
    napi_value undefined = nullptr;
    napi_get_undefined(data->env, &undefined);
    napi_value results[0];
    napi_value resultout = nullptr;
    napi_call_function(data->env, undefined, callback, 0, results, &resultout);
    delete data;
    data = nullptr;
    delete work;
}

void AppAccountManagerCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    ACCOUNT_LOGD("enter");
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    AuthenticatorCallbackParam *param = nullptr;
    if (!InitAuthenticatorWorkEnv(env_, &loop, &work, &param)) {
        ACCOUNT_LOGD("failed to init authenticator work environment");
        return;
    }
    param->resultCode = resultCode;
    param->result = result;
    param->callback = callback_;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, UvQueueWorkOnResult);
}

void AppAccountManagerCallback::OnRequestRedirected(AAFwk::Want &request)
{
    ACCOUNT_LOGD("enter");
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    AuthenticatorCallbackParam *param = nullptr;
    if (!InitAuthenticatorWorkEnv(env_, &loop, &work, &param)) {
        ACCOUNT_LOGD("failed to init authenticator work environment");
        return;
    }
    param->request = request;
    param->callback = callback_;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, UvQueueWorkOnRequestRedirected);
}

void AppAccountManagerCallback::OnRequestContinued()
{
    ACCOUNT_LOGD("enter");
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    AuthenticatorCallbackParam *param = nullptr;
    if (!InitAuthenticatorWorkEnv(env_, &loop, &work, &param)) {
        ACCOUNT_LOGD("failed to init authenticator work environment");
        return;
    }
    param->callback = callback_;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, UvQueueWorkOnRequestContinued);
}

bool InitAuthenticatorWorkEnv(napi_env env, uv_loop_s **loop, uv_work_t **work,
    AuthenticatorCallbackParam **param)
{
    napi_get_uv_event_loop(env, loop);
    if (*loop == nullptr) {
        ACCOUNT_LOGD("loop instance is nullptr");
        return false;
    }
    *work = new (std::nothrow) uv_work_t;
    if (*work == nullptr) {
        ACCOUNT_LOGD("work is null");
        return false;
    }
    *param = new (std::nothrow) AuthenticatorCallbackParam();
    if (*param == nullptr) {
        ACCOUNT_LOGD("failed to create AuthenticatorCallbackParam");
        delete *work;
        *work = nullptr;
        *loop = nullptr;
        return false;
    }
    (*param)->env = env;
    return true;
}

napi_value NapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);

    return result;
}

std::string GetNamedProperty(napi_env env, napi_value obj)
{
    ACCOUNT_LOGD("enter");
    char propValue[MAX_VALUE_LEN] = {0};
    size_t propLen;
    if (napi_get_value_string_utf8(env, obj, propValue, MAX_VALUE_LEN, &propLen) != napi_ok) {
        ACCOUNT_LOGE("Can not get string param from argv");
    }

    return std::string(propValue);
}

void SetNamedProperty(napi_env env, napi_value dstObj, const char *objName, const char *propName)
{
    napi_value prop = nullptr;
    napi_create_string_utf8(env, objName, NAPI_AUTO_LENGTH, &prop);
    napi_set_named_property(env, dstObj, propName, prop);
}

void SetNamedProperty(napi_env env, napi_value dstObj, const int32_t objValue, const char *propName)
{
    napi_value prop = nullptr;
    napi_create_int32(env, objValue, &prop);
    napi_set_named_property(env, dstObj, propName, prop);
}

napi_value GetErrorCodeValue(napi_env env, int errCode)
{
    ACCOUNT_LOGD("enter");
    napi_value jsObject = nullptr;
    napi_value jsValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errCode, &jsValue));
    NAPI_CALL(env, napi_create_object(env, &jsObject));
    NAPI_CALL(env, napi_set_named_property(env, jsObject, "code", jsValue));
    return jsObject;
}

void GetAppAccountInfoForResult(napi_env env, const std::vector<AppAccountInfo> &info, napi_value result)
{
    ACCOUNT_LOGD("enter");

    uint32_t index = 0;

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

void GetAuthenticatorInfoForResult(napi_env env, const AuthenticatorInfo &info, napi_value &result)
{
    napi_value nOwner = nullptr;
    napi_create_string_utf8(env, info.owner.c_str(), NAPI_AUTO_LENGTH, &nOwner);
    napi_set_named_property(env, result, "owner", nOwner);

    napi_value nIconId = nullptr;
    napi_create_int32(env, info.iconId, &nIconId);
    napi_set_named_property(env, result, "iconId", nIconId);

    napi_value nLabelId = nullptr;
    napi_create_int32(env, info.labelId, &nLabelId);
    napi_set_named_property(env, result, "labelId", nLabelId);
}

void GetOAuthTokenInfoForResult(napi_env env, const std::vector<OAuthTokenInfo> &info, napi_value result)
{
    int32_t index = 0;
    for (auto item : info) {
        napi_value objOAuthTokenInfo = nullptr;
        napi_create_object(env, &objOAuthTokenInfo);

        napi_value nToken = nullptr;
        napi_create_string_utf8(env, item.token.c_str(), NAPI_AUTO_LENGTH, &nToken);
        napi_set_named_property(env, objOAuthTokenInfo, "token", nToken);

        napi_value nAuthType = nullptr;
        napi_create_string_utf8(env, item.authType.c_str(), NAPI_AUTO_LENGTH, &nAuthType);
        napi_set_named_property(env, objOAuthTokenInfo, "authType", nAuthType);

        napi_set_element(env, result, index, objOAuthTokenInfo);
        index++;
    }
}

void GetOAuthListForResult(napi_env env, const std::set<std::string> &info, napi_value result)
{
    int32_t index = 0;
    for (auto item : info) {
        napi_value nBundleName = nullptr;
        napi_create_string_utf8(env, item.c_str(), NAPI_AUTO_LENGTH, &nBundleName);
        napi_set_element(env, result, index, nBundleName);
        index++;
    }
}

void GetAuthenticatorCallbackForResult(napi_env env, sptr<IRemoteObject> callback, napi_value *result)
{
    if (callback == nullptr) {
        napi_get_undefined(env, result);
        return;
    }
    napi_value remote;
    napi_create_int64(env, reinterpret_cast<int64_t>((IRemoteObject *)callback), &remote);
    napi_value global = nullptr;
    napi_get_global(env, &global);
    if (global == nullptr) {
        ACCOUNT_LOGE("get napi global failed");
        return;
    }
    napi_value jsAuthCallbackConstructor = nullptr;
    napi_get_named_property(env, global, "AuthCallbackConstructor_", &jsAuthCallbackConstructor);
    if (jsAuthCallbackConstructor == nullptr) {
        ACCOUNT_LOGE("jsAuthCallbackConstructor is null");
        return;
    }
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { remote };
    napi_new_instance(env, jsAuthCallbackConstructor, argc, argv, result);
}

void ParseContextWithExInfo(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    ACCOUNT_LOGD("enter");
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
    ACCOUNT_LOGD("enter");
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

void ParseArguments(napi_env env, napi_value *argv, const napi_valuetype *valueTypes, size_t argc)
{
    napi_valuetype valuetype = napi_undefined;
    for (size_t i = 0; i < argc; ++i) {
        napi_typeof(env, argv[i], &valuetype);
        if (valuetype != valueTypes[i]) {
            argv[i] = nullptr;
        }
    }
}

void ParseContextForAuthenticate(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext, size_t argc)
{
    napi_value argv[ARGS_SIZE_FIVE] = {0};
    napi_valuetype valueTypes[ARGS_SIZE_FIVE] = {napi_string, napi_string, napi_string, napi_object, napi_object};
    napi_value thisVar;
    napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr);
    size_t index = 0;
    if (argc == ARGS_SIZE_FIVE) {
        ParseArguments(env, argv, valueTypes, argc);
        asyncContext->name = GetNamedProperty(env, argv[index++]);
    } else {
        argc = ARGS_SIZE_FOUR;
        ParseArguments(env, argv, &valueTypes[1], argc);
    }
    asyncContext->owner = GetNamedProperty(env, argv[index++]);
    asyncContext->authType = GetNamedProperty(env, argv[index++]);
    AAFwk::WantParams params;
    if (!AppExecFwk::UnwrapWantParams(env, argv[index++], params)) {
        ACCOUNT_LOGI("UnwrapWantParams failed");
    }
    asyncContext->options.SetParams(params);
    napi_value global;
    napi_get_global(env, &global);
    napi_value abilityObj;
    napi_get_named_property(env, global, "ability", &abilityObj);
    if (abilityObj != nullptr) {
        AppExecFwk::Ability *ability = nullptr;
        napi_get_value_external(env, abilityObj, reinterpret_cast<void **>(&ability));
        auto abilityInfo = ability->GetAbilityInfo();
        asyncContext->options.SetParam(Constants::KEY_CALLER_ABILITY_NAME, abilityInfo->name);
    }
    JSAuthCallback callback;
    ParseJSAuthCallback(env, argv[index], callback);
    asyncContext->appAccountMgrCb = new (std::nothrow) AppAccountManagerCallback(env, callback);
}

void ParseContextForGetOAuthToken(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    ACCOUNT_LOGD("enter");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_valuetype valueTypes[] = {napi_string, napi_string, napi_string, napi_function};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    ParseArguments(env, argv, valueTypes, argc);
    asyncContext->name = GetNamedProperty(env, argv[0]);
    asyncContext->owner = GetNamedProperty(env, argv[1]);
    asyncContext->authType = GetNamedProperty(env, argv[PARAMTWO]);
    napi_create_reference(env, argv[PARAMTHREE], 1, &asyncContext->callbackRef);
}

void ParseContextForSetOAuthToken(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    ACCOUNT_LOGD("enter");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_valuetype valueTypes[] = {napi_string, napi_string, napi_string, napi_function};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    ParseArguments(env, argv, valueTypes, argc);
    asyncContext->name = GetNamedProperty(env, argv[0]);
    asyncContext->authType = GetNamedProperty(env, argv[1]);
    asyncContext->token = GetNamedProperty(env, argv[PARAMTWO]);
    napi_create_reference(env, argv[PARAMTHREE], 1, &asyncContext->callbackRef);
}

void ParseContextForDeleteOAuthToken(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    ACCOUNT_LOGD("enter");
    size_t argc = ARGS_SIZE_FIVE;
    napi_value argv[ARGS_SIZE_FIVE] = {0};
    napi_valuetype valueTypes[] = {napi_string, napi_string, napi_string, napi_string, napi_function};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    ParseArguments(env, argv, valueTypes, argc);
    asyncContext->name = GetNamedProperty(env, argv[0]);
    asyncContext->owner = GetNamedProperty(env, argv[1]);
    asyncContext->authType = GetNamedProperty(env, argv[PARAMTWO]);
    asyncContext->token = GetNamedProperty(env, argv[PARAMTHREE]);
    napi_create_reference(env, argv[PARAMFOUR], 1, &asyncContext->callbackRef);
}

void ParseContextForSetOAuthTokenVisibility(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    ACCOUNT_LOGD("enter");
    size_t argc = ARGS_SIZE_FIVE;
    napi_value argv[ARGS_SIZE_FIVE] = {0};
    napi_valuetype valueTypes[] = {napi_string, napi_string, napi_string, napi_boolean, napi_function};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    ParseArguments(env, argv, valueTypes, argc);
    asyncContext->name = GetNamedProperty(env, argv[0]);
    asyncContext->authType = GetNamedProperty(env, argv[1]);
    asyncContext->bundleName = GetNamedProperty(env, argv[PARAMTWO]);
    napi_get_value_bool(env, argv[PARAMTHREE], &asyncContext->isVisible);
    napi_create_reference(env, argv[PARAMFOUR], 1, &asyncContext->callbackRef);
}

void ParseContextForCheckOAuthTokenVisibility(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    ACCOUNT_LOGD("enter");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_valuetype valueTypes[] = {napi_string, napi_string, napi_string, napi_function};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    ParseArguments(env, argv, valueTypes, argc);
    asyncContext->name = GetNamedProperty(env, argv[0]);
    asyncContext->authType = GetNamedProperty(env, argv[1]);
    asyncContext->bundleName = GetNamedProperty(env, argv[PARAMTWO]);
    napi_create_reference(env, argv[PARAMTHREE], 1, &asyncContext->callbackRef);
}

void ParseContextForGetAuthenticatorInfo(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    ACCOUNT_LOGD("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_valuetype valueTypes[] = {napi_string, napi_function};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    ParseArguments(env, argv, valueTypes, argc);
    asyncContext->owner = GetNamedProperty(env, argv[0]);
    napi_create_reference(env, argv[1], 1, &asyncContext->callbackRef);
}

void ParseContextForGetAllOAuthTokens(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    ACCOUNT_LOGD("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_valuetype valueTypes[] = {napi_string, napi_string, napi_function};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    ParseArguments(env, argv, valueTypes, argc);
    asyncContext->name = GetNamedProperty(env, argv[0]);
    asyncContext->owner = GetNamedProperty(env, argv[1]);
    napi_create_reference(env, argv[PARAMTWO], 1, &asyncContext->callbackRef);
}

void ParseContextForGetOAuthList(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    ACCOUNT_LOGD("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_valuetype valueTypes[] = {napi_string, napi_string, napi_function};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    ParseArguments(env, argv, valueTypes, argc);
    asyncContext->name = GetNamedProperty(env, argv[0]);
    asyncContext->authType = GetNamedProperty(env, argv[1]);
    napi_create_reference(env, argv[PARAMTWO], 1, &asyncContext->callbackRef);
}

void ParseContextForGetAuthenticatorCallback(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    ACCOUNT_LOGD("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_valuetype valueTypes[] = {napi_string, napi_function};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    ParseArguments(env, argv, valueTypes, argc);
    asyncContext->sessionId = GetNamedProperty(env, argv[0]);
    napi_create_reference(env, argv[1], 1, &asyncContext->callbackRef);
}

void ParseContextWithBdName(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    ACCOUNT_LOGD("enter");
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
    ACCOUNT_LOGD("enter");
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
                ACCOUNT_LOGI("isEnable para is true");
            } else {
                ACCOUNT_LOGI("isEnable para is false");
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
    ACCOUNT_LOGD("enter");
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
    ACCOUNT_LOGD("enter");
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
    ACCOUNT_LOGD("enter");
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
    ACCOUNT_LOGD("enter");
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
    ACCOUNT_LOGD("enter");
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
    ACCOUNT_LOGD("enter");
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
    ACCOUNT_LOGD("enter");
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

void ProcessCallbackOrPromise(napi_env env, const CommonAsyncContext *asyncContext, napi_value err, napi_value data)
{
    ACCOUNT_LOGD("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (asyncContext->deferred) {
        if (asyncContext->errCode == ERR_OK) {
            napi_resolve_deferred(env, asyncContext->deferred, args[1]);
        } else {
            napi_reject_deferred(env, asyncContext->deferred, args[0]);
        }
    } else {
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
    ACCOUNT_LOGD("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (asyncContext->deferred) {
        if (asyncContext->errCode == ERR_OK) {
            napi_resolve_deferred(env, asyncContext->deferred, args[1]);
        } else {
            napi_reject_deferred(env, asyncContext->deferred, args[0]);
        }
    } else {
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
    ACCOUNT_LOGD("enter");

    bool isArray = false;
    uint32_t length = 0;
    size_t strLen = 0;
    napi_valuetype valuetype;

    // argv[0] type: 'change'
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype == napi_string) {
        std::string type = GetNamedProperty(env, argv[0]);
        if (type != "change") {
            ACCOUNT_LOGE("Wrong type=%{public}s", type.c_str());
            return nullptr;
        }
    } else {
        ACCOUNT_LOGE("Wrong argument type.");
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
            owners.emplace_back(str);
        }
    }

    // argv[2] callback
    NAPI_CALL(env, napi_typeof(env, argv[PARAMTWO], &valuetype));
    NAPI_ASSERT(env, valuetype == napi_function, "Wrong argument type. Function expected.");
    NAPI_CALL(env, napi_create_reference(env, argv[PARAMTWO], 1, &callback));

    return NapiGetNull(env);
}

napi_value GetSubscriberByUnsubscribe(const napi_env &env, std::vector<std::shared_ptr<SubscriberPtr>> &subscribers,
    AsyncContextForUnsubscribe *asyncContextForOff, bool &isFind)
{
    ACCOUNT_LOGD("enter");
    napi_value result;

    {
        std::lock_guard<std::mutex> lock(g_lockForAppAccountSubscribers);
        ACCOUNT_LOGD("g_AppAccountSubscribers.size = %{public}zu", g_AppAccountSubscribers.size());

        for (auto subscriberInstance : g_AppAccountSubscribers) {
            if (subscriberInstance.first == asyncContextForOff->appAccountManager) {
                for (auto item : subscriberInstance.second) {
                    subscribers.emplace_back(item->subscriber);
                }
                isFind = true;
                break;
            }
        }
    }

    NAPI_CALL(env, napi_get_boolean(env, isFind, &result));
    return result;
}

napi_value ParseParametersByUnsubscribe(
    const napi_env &env, const size_t &argc, const napi_value (&argv)[UNSUBSCRIBE_MAX_PARA], napi_ref &callback)
{
    ACCOUNT_LOGD("enter");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    // argv[0]: type: 'change'
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    NAPI_ASSERT(env, valuetype == napi_string, "Wrong argument type for arg0. String expected.");
    if (valuetype == napi_string) {
        std::string type = GetNamedProperty(env, argv[0]);
        if (type != "change") {
            ACCOUNT_LOGE("Wrong type=%{public}s", type.c_str());
            return nullptr;
        }
    } else {
        ACCOUNT_LOGE("Wrong argument type.");
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

void UnsubscribeExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGD("Unsubscribe napi_create_async_work start.");
    AsyncContextForUnsubscribe *asyncContextForOff = reinterpret_cast<AsyncContextForUnsubscribe *>(data);
    for (auto offSubscriber : asyncContextForOff->subscribers) {
        int errCode = AppAccountManager::UnsubscribeAppAccount(offSubscriber);
        ACCOUNT_LOGD("Unsubscribe errcode parameter is %{public}d", errCode);
    }
}

void UnsubscribeCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("Unsubscribe napi_create_async_work end.");
    AsyncContextForUnsubscribe *asyncContextForOff = reinterpret_cast<AsyncContextForUnsubscribe *>(data);
    if (asyncContextForOff == nullptr) {
        return;
    }

    if (asyncContextForOff->argc >= UNSUBSCRIBE_MAX_PARA) {
        napi_value result = nullptr;
        napi_get_null(env, &result);

        napi_value undefined = nullptr;
        napi_get_undefined(env, &undefined);

        napi_value callback = nullptr;
        napi_value resultout = nullptr;
        napi_get_reference_value(env, asyncContextForOff->callbackRef, &callback);

        napi_value results[ARGS_SIZE_TWO] = {nullptr};
        results[PARAMZERO] = result;

        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, ARGS_SIZE_ONE, &results[0], &resultout));
    }

    if (asyncContextForOff->callbackRef != nullptr) {
        napi_delete_reference(env, asyncContextForOff->callbackRef);
    }

    napi_delete_async_work(env, asyncContextForOff->work);

    {
        std::lock_guard<std::mutex> lock(g_lockForAppAccountSubscribers);
        ACCOUNT_LOGD("Erase before g_AppAccountSubscribers.size = %{public}zu", g_AppAccountSubscribers.size());
        // erase the info from map
        auto subscribe = g_AppAccountSubscribers.find(asyncContextForOff->appAccountManager);
        if (subscribe != g_AppAccountSubscribers.end()) {
            for (auto offCBInfo : subscribe->second) {
                napi_delete_reference(env, offCBInfo->callbackRef);
            }
            g_AppAccountSubscribers.erase(subscribe);
        }
        ACCOUNT_LOGD("Erase end g_AppAccountSubscribers.size = %{public}zu", g_AppAccountSubscribers.size());
    }
    delete asyncContextForOff;
    asyncContextForOff = nullptr;
}

void ParseVerifyCredentialOptions(napi_env env, napi_value object, VerifyCredentialOptions &options)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        return;
    }
    napi_value value = nullptr;
    napi_get_named_property(env, object, "credential", &value);
    options.credential = GetNamedProperty(env, value);
    napi_get_named_property(env, object, "credentialType", &value);
    options.credentialType = GetNamedProperty(env, value);
}

void ParseSelectAccountsOptions(napi_env env, napi_value object, SelectAccountsOptions &options)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        return;
    }
    napi_value value = nullptr;
    napi_has_named_property(env, object, "allowedAccounts", &options.hasAccounts);
    if (options.hasAccounts) {
        napi_get_named_property(env, object, "allowedAccounts", &value);
        ParseAccountVector(env, value, options.allowedAccounts);
    }
    napi_has_named_property(env, object, "allowedOwners", &options.hasOwners);
    if (options.hasOwners) {
        napi_get_named_property(env, object, "allowedOwners", &value);
        ParseStringVector(env, value, options.allowedOwners);
    }
    napi_has_named_property(env, object, "requiredLabels", &options.hasLabels);
    if (options.hasLabels) {
        napi_get_named_property(env, object, "requiredLabels", &value);
        ParseStringVector(env, value, options.requiredLabels);
        ACCOUNT_LOGE("requiredLabels.size: %{public}zu", options.requiredLabels.size());
    }
}

void ParseSetPropertiesOptions(napi_env env, napi_value object, SetPropertiesOptions &options)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        return;
    }
    napi_value value = nullptr;
    napi_get_named_property(env, object, "properties", &value);
    AppExecFwk::UnwrapWantParams(env, value, options.properties);
    napi_get_named_property(env, object, "parameters", &value);
    AppExecFwk::UnwrapWantParams(env, value, options.parameters);
}

napi_ref GetNamedFunction(napi_env env, napi_value object, std::string name)
{
    napi_value value = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_ref funcRef = nullptr;
    napi_get_named_property(env, object, name.c_str(), &value);
    napi_typeof(env, value, &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, value, 1, &funcRef);
    }
    if (funcRef == nullptr) {
        ACCOUNT_LOGI("funcRef is nullptr");
    }
    return funcRef;
}

void ParseJSAuthCallback(napi_env env, napi_value object, JSAuthCallback &callback)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        return;
    }
    callback.onResult = GetNamedFunction(env, object, "onResult");
    callback.onRequestRedirected = GetNamedFunction(env, object, "onRequestRedirected");
    callback.onRequestContinued = GetNamedFunction(env, object, "onRequestContinued");
}

void ParseContextForVerifyCredential(napi_env env, napi_callback_info info, VerifyCredentialContext *context)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_THREE) {
        return;
    }
    int32_t index = 0;
    context->name = GetNamedProperty(env, argv[index++]);
    context->owner = GetNamedProperty(env, argv[index++]);
    if (argc == ARGS_SIZE_FOUR) {
        ParseVerifyCredentialOptions(env, argv[index++], context->options);
    }
    ParseJSAuthCallback(env, argv[index], context->callback);
}

void ParseContextForSetProperties(napi_env env, napi_callback_info info, SetPropertiesContext *context)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_TWO) {
        return;
    }
    int32_t index = 0;
    context->owner = GetNamedProperty(env, argv[index++]);
    if (argc == ARGS_SIZE_THREE) {
        ParseSetPropertiesOptions(env, argv[index++], context->options);
    }
    ParseJSAuthCallback(env, argv[index], context->callback);
}

void ParseContextForSelectAccount(napi_env env, napi_callback_info info, SelectAccountsContext *context)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_ONE) {
        return;
    }
    ParseSelectAccountsOptions(env, argv[0], context->options);
    if (argc != ARGS_SIZE_TWO) {
        return;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[PARAMONE], &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, argv[PARAMONE], PARAMTWO, &context->callbackRef);
    }
}

uint32_t GetArrayLength(napi_env env, napi_value value)
{
    bool isArray = false;
    uint32_t length = 0;
    napi_is_array(env, value, &isArray);
    if (!isArray) {
        ACCOUNT_LOGD("Wrong argument type, array expected");
    } else {
        napi_get_array_length(env, value, &length);
    }
    return length;
}

void ParseAccountVector(napi_env env, napi_value value, std::vector<std::pair<std::string, std::string>> &accountVec)
{
    uint32_t length = GetArrayLength(env, value);
    napi_valuetype valueType = napi_undefined;
    for (uint32_t i = 0; i < length; ++i) {
        napi_value item = nullptr;
        napi_get_element(env, value, i, &item);
        NAPI_CALL_RETURN_VOID(env, napi_typeof(env, item, &valueType));
        if (valueType != napi_object) {
            ACCOUNT_LOGD("Wrong argument type, Object expected");
            return;
        }
        napi_value data = nullptr;
        napi_get_named_property(env, item, "name", &data);
        std::string name = GetNamedProperty(env, data);
        napi_get_named_property(env, item, "owner", &data);
        std::string owner = GetNamedProperty(env, data);
        accountVec.push_back(std::make_pair(owner, name));
    }
}

void ParseStringVector(napi_env env, napi_value value, std::vector<std::string> &strVec)
{
    uint32_t length = GetArrayLength(env, value);
    napi_valuetype valueType = napi_undefined;
    for (uint32_t i = 0; i < length; ++i) {
        napi_value item = nullptr;
        napi_get_element(env, value, i, &item);
        NAPI_CALL_RETURN_VOID(env, napi_typeof(env, item, &valueType));
        if (valueType != napi_string) {
            ACCOUNT_LOGD("Wrong argument type, String expected");
            return;
        }
        strVec.push_back(GetNamedProperty(env, item));
    }
}

void ParseContextForCheckAccountLabels(napi_env env, napi_callback_info info, CheckAccountLabelsContext *context)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_THREE) {
        return;
    }
    context->name = GetNamedProperty(env, argv[PARAMZERO]);
    context->owner = GetNamedProperty(env, argv[PARAMONE]);
    ParseStringVector(env, argv[PARAMTWO], context->labels);
    if (argc != ARGS_SIZE_FOUR) {
        return;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[PARAMTHREE], &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, argv[PARAMTHREE], PARAMTWO, &context->callbackRef);
    }
}

void VerifyCredCompleteCB(napi_env env, napi_status status, void *data)
{
    (void) status;
    auto context = reinterpret_cast<VerifyCredentialContext *>(data);
    if ((context->errCode != ERR_JS_SUCCESS) && (context->appAccountMgrCb != nullptr)) {
        AAFwk::Want errResult;
        context->appAccountMgrCb->OnResult(context->errCode, errResult);
    }
    napi_delete_async_work(env, context->work);
    delete context;
    context = nullptr;
}

void ProcessOnResultCallback(
    napi_env env, JSAuthCallback &callback, int32_t resultCode, const AAFwk::WantParams &result)
{
    napi_value results[ARGS_SIZE_TWO] = {nullptr};
    napi_create_int32(env, resultCode, &results[0]);
    results[ARGS_SIZE_ONE] = AppExecFwk::WrapWantParams(env, result);
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);
    napi_value onResultFunc = nullptr;
    napi_value resultout = nullptr;
    napi_get_reference_value(env, callback.onResult, &onResultFunc);
    napi_call_function(env, undefined, onResultFunc, ARGS_SIZE_TWO, results, &resultout);
    if (callback.onResult != nullptr) {
        napi_delete_reference(env, callback.onResult);
        callback.onResult = nullptr;
    }
    if (callback.onRequestRedirected != nullptr) {
        napi_delete_reference(env, callback.onRequestRedirected);
        callback.onRequestRedirected = nullptr;
    }
    if (callback.onRequestContinued != nullptr) {
        napi_delete_reference(env, callback.onRequestContinued);
        callback.onRequestContinued = nullptr;
    }
}
}  // namespace AccountJsKit
}  // namespace OHOS

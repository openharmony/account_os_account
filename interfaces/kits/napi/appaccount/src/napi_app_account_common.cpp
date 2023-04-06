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
#include "napi_app_account_common.h"
#include "account_error_no.h"
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
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<SubscriberAccountsWorker> data(reinterpret_cast<SubscriberAccountsWorker *>(work->data));
    bool isFound = false;
    {
        std::lock_guard<std::mutex> lock(g_lockForAppAccountSubscribers);
        SubscriberPtr *subscriber = data->subscriber;
        for (auto objectInfoTmp : g_AppAccountSubscribers) {
            isFound = std::any_of(objectInfoTmp.second.begin(), objectInfoTmp.second.end(),
                [subscriber](const AsyncContextForSubscribe *item) {
                    return item->subscriber.get() == subscriber;
                });
            if (isFound) {
                ACCOUNT_LOGD("app account subscriber has been found.");
                break;
            }
        }
    }
    if (isFound) {
        napi_value results[ARGS_SIZE_ONE] = {nullptr};
        GetAppAccountInfoForResult(data->env, data->accounts, results[0]);
        NapiCallVoidFunction(data->env, results, ARGS_SIZE_ONE, data->ref);
    }
    napi_close_handle_scope(data->env, scope);
}

void SubscriberPtr::OnAccountsChanged(const std::vector<AppAccountInfo> &accounts_)
{
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        ACCOUNT_LOGE("loop instance is nullptr");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        ACCOUNT_LOGE("work is null");
        return;
    }

    SubscriberAccountsWorker *subscriberAccountsWorker = new (std::nothrow) SubscriberAccountsWorker(env_);

    if (subscriberAccountsWorker == nullptr) {
        ACCOUNT_LOGE("SubscriberAccountsWorker is null");
        delete work;
        return;
    }

    subscriberAccountsWorker->accounts = accounts_;
    subscriberAccountsWorker->ref = ref_;
    subscriberAccountsWorker->subscriber = this;

    work->data = reinterpret_cast<void *>(subscriberAccountsWorker);

    uv_queue_work(loop, work, [](uv_work_t *work) {}, UvQueueWorkOnAppAccountsChanged);
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
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<AuthenticatorCallbackParam> data(reinterpret_cast<AuthenticatorCallbackParam *>(work->data));
    napi_value checkResult[RESULT_COUNT] = {NapiGetNull(data->context.env)};
    if (data->context.errCode == ERR_JS_SUCCESS) {
        bool hasLabels = data->result.GetBoolParam(Constants::KEY_BOOLEAN_RESULT, false);
        napi_get_boolean(data->context.env, hasLabels, &checkResult[PARAMONE]);
    } else {
        checkResult[PARAMZERO] = GetErrorCodeValue(data->context.env, data->context.errCode);
    }
    ProcessCallbackOrPromise(data->context.env, &(data->context), checkResult[PARAMZERO], checkResult[PARAMONE]);
    napi_close_handle_scope(data->context.env, scope);
}

static napi_value CreateJSAppAccountInfo(napi_env env, const std::string &name, const std::string &owner)
{
    napi_value object = nullptr;
    NAPI_CALL(env, napi_create_object(env, &object));
    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, name.c_str(), NAPI_AUTO_LENGTH, &value));
    NAPI_CALL(env, napi_set_named_property(env, object, "name", value));
    NAPI_CALL(env, napi_create_string_utf8(env, owner.c_str(), NAPI_AUTO_LENGTH, &value));
    NAPI_CALL(env, napi_set_named_property(env, object, "owner", value));
    return object;
}

void SelectAccountsOnResultWork(uv_work_t *work, int status)
{
    napi_handle_scope scope = nullptr;
    std::unique_ptr<uv_work_t> workPtr(work);
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<AuthenticatorCallbackParam> param(reinterpret_cast<AuthenticatorCallbackParam *>(work->data));
    std::vector<std::string> names = param->result.GetStringArrayParam(Constants::KEY_ACCOUNT_NAMES);
    std::vector<std::string> owners = param->result.GetStringArrayParam(Constants::KEY_ACCOUNT_OWNERS);
    if (names.size() != owners.size()) {
        param->context.errCode = ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION;
    }
    napi_env env = param->context.env;
    napi_value selectResult[RESULT_COUNT] = {0};
    if (param->context.errCode == ERR_JS_SUCCESS) {
        napi_create_array(env, &selectResult[PARAMONE]);
        for (size_t i = 0; i < names.size(); ++i) {
            napi_value object = CreateJSAppAccountInfo(env, names[i], owners[i]);
            napi_set_element(env, selectResult[PARAMONE], i, object);
        }
    } else {
        selectResult[PARAMZERO] = GetErrorCodeValue(env, param->context.errCode);
    }
    ProcessCallbackOrPromise(env, &(param->context), selectResult[PARAMZERO], selectResult[PARAMONE]);
    napi_close_handle_scope(env, scope);
}

AuthenticatorAsyncCallback::AuthenticatorAsyncCallback(
    const CommonAsyncContext &context, uv_after_work_cb workCb)
    : context_(context), workCb_(workCb)
{}

AuthenticatorAsyncCallback::~AuthenticatorAsyncCallback()
{}

void AuthenticatorAsyncCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
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
        ACCOUNT_LOGE("failed to init work environment");
        return;
    }
    param->context = context_;
    param->context.errCode = resultCode;
    param->result = result;
    work->data = param;
    if (uv_queue_work(loop, work, [](uv_work_t *work) {}, workCb_) == ERR_OK) {
        return;
    }
    ReleaseNapiRefAsync(context_.env, context_.callbackRef);
    delete param;
    delete work;
}

void AuthenticatorAsyncCallback::OnRequestRedirected(AAFwk::Want &request)
{}

void AuthenticatorAsyncCallback::OnRequestContinued()
{}

AppAccountManagerCallback::AppAccountManagerCallback(napi_env env, JSAuthCallback callback)
    : env_(env), callback_(callback)
{}

AppAccountManagerCallback::~AppAccountManagerCallback()
{}

void UvQueueWorkOnResult(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<AuthenticatorCallbackParam> data(reinterpret_cast<AuthenticatorCallbackParam *>(work->data));
    ProcessOnResultCallback(data->env, data->callback, data->resultCode, data->result.GetParams());
    napi_close_handle_scope(data->env, scope);
}

void UvQueueWorkOnRequestRedirected(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<AuthenticatorCallbackParam> data(reinterpret_cast<AuthenticatorCallbackParam *>(work->data));
    napi_value results[ARGS_SIZE_ONE] = {AppExecFwk::WrapWant(data->env, data->request)};
    NapiCallVoidFunction(data->env, results, ARGS_SIZE_ONE, data->callback.onRequestRedirected);
    napi_close_handle_scope(data->env, scope);
}

void UvQueueWorkOnRequestContinued(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<AuthenticatorCallbackParam> data(reinterpret_cast<AuthenticatorCallbackParam *>(work->data));
    NapiCallVoidFunction(data->env, nullptr, 0, data->callback.onRequestContinued);
    napi_close_handle_scope(data->env, scope);
}

void AppAccountManagerCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    AuthenticatorCallbackParam *param = nullptr;
    if (!InitAuthenticatorWorkEnv(env_, &loop, &work, &param)) {
        ACCOUNT_LOGE("failed to init authenticator work environment");
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
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    AuthenticatorCallbackParam *param = nullptr;
    if (!InitAuthenticatorWorkEnv(env_, &loop, &work, &param)) {
        ACCOUNT_LOGE("failed to init authenticator work environment");
        return;
    }
    param->request = request;
    param->callback = callback_;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, UvQueueWorkOnRequestRedirected);
}

void AppAccountManagerCallback::OnRequestContinued()
{
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    AuthenticatorCallbackParam *param = nullptr;
    if (!InitAuthenticatorWorkEnv(env_, &loop, &work, &param)) {
        ACCOUNT_LOGE("failed to init authenticator work environment");
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
        ACCOUNT_LOGE("loop instance is nullptr");
        return false;
    }
    *work = new (std::nothrow) uv_work_t;
    if (*work == nullptr) {
        ACCOUNT_LOGE("work is null");
        return false;
    }
    *param = new (std::nothrow) AuthenticatorCallbackParam(env);
    if (*param == nullptr) {
        ACCOUNT_LOGE("failed to create AuthenticatorCallbackParam");
        delete *work;
        *work = nullptr;
        *loop = nullptr;
        return false;
    }
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
    napi_value jsObject = nullptr;
    napi_value jsValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errCode, &jsValue));
    NAPI_CALL(env, napi_create_object(env, &jsObject));
    NAPI_CALL(env, napi_set_named_property(env, jsObject, "code", jsValue));
    return jsObject;
}

void GetAppAccountInfoForResult(napi_env env, const std::vector<AppAccountInfo> &info, napi_value &result)
{
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result));
    uint32_t index = 0;
    for (auto item : info) {
        std::string name;
        item.GetName(name);
        std::string owner;
        item.GetOwner(owner);
        napi_value objAppAccountInfo = CreateJSAppAccountInfo(env, name, owner);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, index++, objAppAccountInfo));
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
    napi_create_int64(env, reinterpret_cast<int64_t>(callback.GetRefPtr()), &remote);
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

bool ParseContextWithExInfo(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_ONE) {
        asyncContext->errMsg = "the number of parameters should be at least 1";
        return false;
    }
    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            GetStringProperty(env, argv[i], asyncContext->name);
        } else if (i == 1 && valueType == napi_string) {
            GetStringProperty(env, argv[i], asyncContext->extraInfo);
        } else if (i == 1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext->callbackRef);
            break;
        } else if (i == PARAMTWO && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            asyncContext->errMsg = "the type of param " + std::to_string(i) + " is incorrect";
            return false;
        }
    }
    return true;
}

bool ParseContextForSetExInfo(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_TWO) {
        asyncContext->errMsg = "the number of parameter should be at least 2";
        return false;
    }
    if ((argc == ARGS_SIZE_THREE) && (!GetCallbackProperty(env, argv[PARAMTWO], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[1], asyncContext->extraInfo)) {
        asyncContext->errMsg = "the extraInfo is not a string";
        return false;
    }
    return true;
}

bool ParseArguments(napi_env env, napi_value *argv, const napi_valuetype *valueTypes, size_t argc)
{
    napi_valuetype valuetype = napi_undefined;
    for (size_t i = 0; i < argc; ++i) {
        napi_typeof(env, argv[i], &valuetype);
        if (valuetype != valueTypes[i]) {
            argv[i] = nullptr;
            return false;
        }
    }
    return true;
}

bool ParseContextForAuth(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *context)
{
    std::string abilityName;
    GetAbilityName(env, abilityName);
    context->options.SetParam(Constants::KEY_CALLER_ABILITY_NAME, abilityName);
    size_t argc = ARGS_SIZE_FIVE;
    napi_value argv[ARGS_SIZE_FIVE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_FOUR) {
        context->errMsg = "the number of parameters should be at least 4";
        return false;
    }
    size_t index = 0;
    if (!GetStringProperty(env, argv[index++], context->name)) {
        context->errMsg = "the name is not string";
        return false;
    }
    if (!GetStringProperty(env, argv[index++], context->owner)) {
        context->errMsg = "the owner is not string";
        return false;
    }
    if (!GetStringProperty(env, argv[index++], context->authType)) {
        context->errMsg = "the authType is not string";
        return false;
    }
    AAFwk::WantParams params;
    if ((argc == ARGS_SIZE_FIVE) && (!AppExecFwk::UnwrapWantParams(env, argv[index++], params))) {
        ACCOUNT_LOGE("UnwrapWantParams failed");
        context->errMsg = "the type of options is incorrect";
        return false;
    }
    context->options.SetParams(params);
    context->options.SetParam(Constants::KEY_CALLER_ABILITY_NAME, abilityName);
    JSAuthCallback callback;
    if (!ParseJSAuthCallback(env, argv[index], callback)) {
        context->errMsg = "the type of authCallback is incorrect";
        return false;
    }
    context->appAccountMgrCb = new (std::nothrow) AppAccountManagerCallback(env, callback);
    return true;
}

void ParseContextForAuthenticate(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext, size_t argc)
{
    napi_value argv[ARGS_SIZE_FIVE] = {0};
    napi_value thisVar;
    napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr);
    napi_valuetype valueTypes[ARGS_SIZE_FIVE] = {napi_string, napi_string, napi_string, napi_object, napi_object};
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
        ACCOUNT_LOGE("UnwrapWantParams failed");
    }
    asyncContext->options.SetParams(params);
    std::string abilityName;
    GetAbilityName(env, abilityName);
    asyncContext->options.SetParam(Constants::KEY_CALLER_ABILITY_NAME, abilityName);
    JSAuthCallback callback;
    ParseJSAuthCallback(env, argv[index], callback);
    asyncContext->appAccountMgrCb = new (std::nothrow) AppAccountManagerCallback(env, callback);
}

bool ParseContextForGetOAuthToken(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_THREE) {
        asyncContext->errMsg = "the number of parameter should be at least 3";
        return false;
    }
    if ((argc == ARGS_SIZE_FOUR) && (!GetCallbackProperty(env, argv[PARAMTHREE], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[1], asyncContext->owner)) {
        asyncContext->errMsg = "the owner is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMTWO], asyncContext->authType)) {
        asyncContext->errMsg = "the authType is not a string";
        return false;
    }
    return true;
}

bool ParseContextForSetOAuthToken(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_THREE) {
        asyncContext->errMsg = "the number of parameter should be at least 3";
        return false;
    }
    if ((argc == ARGS_SIZE_FOUR) && (!GetCallbackProperty(env, argv[PARAMTHREE], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[1], asyncContext->authType)) {
        asyncContext->errMsg = "the authType is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMTWO], asyncContext->token)) {
        asyncContext->errMsg = "the token is not a string";
        return false;
    }
    return true;
}

bool ParseContextForDeleteOAuthToken(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_FIVE;
    napi_value argv[ARGS_SIZE_FIVE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_FOUR) {
        asyncContext->errMsg = "the number of parameter should be at least 4";
        return false;
    }
    if ((argc == ARGS_SIZE_FIVE) && (!GetCallbackProperty(env, argv[PARAMFOUR], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[1], asyncContext->owner)) {
        asyncContext->errMsg = "the owner is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMTWO], asyncContext->authType)) {
        asyncContext->errMsg = "the authType is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMTHREE], asyncContext->token)) {
        asyncContext->errMsg = "the token is not a string";
        return false;
    }
    return true;
}

bool ParseContextForSetOAuthTokenVisibility(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_FIVE;
    napi_value argv[ARGS_SIZE_FIVE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_FOUR) {
        asyncContext->errMsg = "the number of parameter should be at least 4";
        return false;
    }
    if ((argc == ARGS_SIZE_FIVE) && (!GetCallbackProperty(env, argv[PARAMFOUR], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[1], asyncContext->authType)) {
        asyncContext->errMsg = "the authType is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMTWO], asyncContext->bundleName)) {
        asyncContext->errMsg = "the bundleName is not a string";
        return false;
    }
    if (napi_get_value_bool(env, argv[PARAMTHREE], &asyncContext->isVisible) != napi_ok) {
        asyncContext->errMsg = "the isVisible is not a bool value";
        return false;
    }
    return true;
}

bool ParseContextForCheckOAuthTokenVisibility(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_THREE) {
        asyncContext->errMsg = "the number of parameter should be at least 3";
        return false;
    }
    if ((argc == ARGS_SIZE_FOUR) && (!GetCallbackProperty(env, argv[PARAMTHREE], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[1], asyncContext->authType)) {
        asyncContext->errMsg = "the authType is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMTWO], asyncContext->bundleName)) {
        asyncContext->errMsg = "the bundleName is not a string";
        return false;
    }
    return true;
}

bool ParseContextForGetAuthenticatorInfo(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_ONE) {
        asyncContext->errMsg = "the number of parameter should be at least 1";
        return false;
    }
    if ((argc == ARGS_SIZE_TWO) && (!GetCallbackProperty(env, argv[1], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->owner)) {
        asyncContext->errMsg = "the owner is not a string";
        return false;
    }
    return true;
}

bool ParseContextForGetAllOAuthTokens(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_TWO) {
        asyncContext->errMsg = "the number of parameter should be at least 2";
        return false;
    }
    if ((argc == ARGS_SIZE_THREE) && (!GetCallbackProperty(env, argv[PARAMTWO], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[1], asyncContext->owner)) {
        asyncContext->errMsg = "the owner is not a string";
        return false;
    }
    return true;
}

bool ParseContextForGetOAuthList(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_TWO) {
        asyncContext->errMsg = "the number of parameter should be at least 2";
        return false;
    }
    if ((argc == ARGS_SIZE_THREE) && (!GetCallbackProperty(env, argv[PARAMTWO], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[1], asyncContext->authType)) {
        asyncContext->errMsg = "the authType is not a string";
        return false;
    }
    return true;
}

bool ParseContextForGetAuthenticatorCallback(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_ONE) {
        asyncContext->errMsg = "the number of parameters should be at least 1";
        return false;
    }
    if ((argc == ARGS_SIZE_TWO) && (!GetCallbackProperty(env, argv[1], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->sessionId)) {
        asyncContext->errMsg = "the sessionId is not a string";
        return false;
    }
    return true;
}

bool ParseContextWithBdName(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_TWO) {
        asyncContext->errMsg = "the number of parameters should be at least 2";
        return false;
    }
    if ((argc == ARGS_SIZE_THREE) && (!GetCallbackProperty(env, argv[PARAMTWO], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[1], asyncContext->bundleName)) {
        asyncContext->errMsg = "the bundleName is not a string";
        return false;
    }
    return true;
}

bool ParseContextForSetAppAccess(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_THREE) {
        asyncContext->errMsg = "the number of parameters should be at least 2";
        return false;
    }
    if ((argc == ARGS_SIZE_FOUR) && (!GetCallbackProperty(env, argv[PARAMTHREE], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[1], asyncContext->bundleName)) {
        asyncContext->errMsg = "the bundleName is not a string";
        return false;
    }
    if (napi_get_value_bool(env, argv[PARAMTWO], &asyncContext->isAccessible) != napi_ok) {
        asyncContext->errMsg = "the isAccessible is not a bool value";
        return false;
    }
    return true;
}

bool ParseContextWithIsEnable(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_TWO) {
        asyncContext->errMsg = "the number of parameters should be at least 2";
        return false;
    }
    if ((argc == ARGS_SIZE_THREE) && (!GetCallbackProperty(env, argv[PARAMTWO], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (napi_get_value_bool(env, argv[1], &asyncContext->isEnable) != napi_ok) {
        asyncContext->errMsg = "the isEnable is not a string";
        return false;
    }
    return true;
}

bool ParseContextWithTwoPara(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_ONE) {
        asyncContext->errMsg = "the number of parameters should be at least 1";
        return false;
    }
    if ((argc == ARGS_SIZE_TWO) && (!GetCallbackProperty(env, argv[1], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    return true;
}

bool ParseContextToSetCredential(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_THREE) {
        asyncContext->errMsg = "the number of parameters should be at least 3";
        return false;
    }
    if ((argc == ARGS_SIZE_FOUR) && (!GetCallbackProperty(env, argv[PARAMTHREE], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[1], asyncContext->credentialType)) {
        asyncContext->errMsg = "the credentialType is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMTWO], asyncContext->credential)) {
        asyncContext->errMsg = "the credential is not a string";
        return false;
    }
    return true;
}

bool ParseContextForAssociatedData(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_THREE) {
        asyncContext->errMsg = "the number of parameters should be at least 3";
        return false;
    }
    if ((argc == ARGS_SIZE_FOUR) && (!GetCallbackProperty(env, argv[PARAMTHREE], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[1], asyncContext->key)) {
        asyncContext->errMsg = "the key is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMTWO], asyncContext->value)) {
        asyncContext->errMsg = "the value is not a string";
        return false;
    }
    return true;
}

bool ParseContextToGetData(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_TWO) {
        asyncContext->errMsg = "the number of parameter shoulde be 3";
        return false;
    }
    if ((argc == ARGS_SIZE_THREE) && (!GetCallbackProperty(env, argv[PARAMTWO], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[1], asyncContext->key)) {
        asyncContext->errMsg = "the key is not a string";
        return false;
    }
    return true;
}

bool ParseContextCBArray(napi_env env, napi_callback_info cbInfo, GetAccountsAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if ((argc == ARGS_SIZE_ONE) && (!GetCallbackProperty(env, argv[0], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    return true;
}

bool ParseContextWithCredentialType(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_TWO) {
        asyncContext->errMsg = "the number of parameter should be at least 2";
        return false;
    }
    if ((argc == ARGS_SIZE_THREE) && (!GetCallbackProperty(env, argv[PARAMTWO], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[1], asyncContext->credentialType)) {
        asyncContext->errMsg = "the credentialType is not a string";
        return false;
    }
    return true;
}

bool ParseContextWithStrCBArray(napi_env env, napi_callback_info cbInfo, GetAccountsAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_ONE) {
        asyncContext->errMsg = "the number of parameter should be at least 2";
        return false;
    }
    if ((argc == ARGS_SIZE_TWO) && (!GetCallbackProperty(env, argv[1], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->owner)) {
        asyncContext->errMsg = "the owner is not a string";
        return false;
    }
    return true;
}

bool ParseParametersBySubscribe(const napi_env &env, napi_callback_info cbInfo, AsyncContextForSubscribe *context)
{
    size_t argc = SUBSCRIBE_MAX_PARA;
    napi_value argv[SUBSCRIBE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr);
    context->errCode = ERR_JS_PARAMETER_ERROR;
    if (argc != SUBSCRIBE_MAX_PARA) {
        context->errMsg = "the number of parameters should be 3";
        return false;
    }
    if (!GetStringProperty(env, argv[0], context->type)) {
        context->errMsg = "the type is not a string";
        return false;
    }
    if ((context->type != "change") && (context->type != "accountChange")) {
        context->errMsg = "the type is invalid";
        context->errCode = ERR_JS_INVALID_PARAMETER;
        return false;
    }
    bool isArray = false;
    napi_is_array(env, argv[1], &isArray);
    if (!isArray) {
        context->errMsg = "the owners is not a string array";
        return false;
    }
    uint32_t length = 0;
    napi_get_array_length(env, argv[1], &length);
    if (length == 0) {
        context->errMsg = "the owers should not be empty";
        context->errCode = ERR_JS_INVALID_PARAMETER;
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        napi_value ownerStr = nullptr;
        napi_get_element(env, argv[1], i, &ownerStr);
        std::string owner;
        if (!GetStringProperty(env, ownerStr, owner)) {
            context->errMsg = "the owners is not a string array";
            return false;
        }
        context->owners.emplace_back(owner);
    }
    if (!GetCallbackProperty(env, argv[PARAMTWO], context->callbackRef, 1)) {
        context->errMsg = "the callback is not a function";
        return false;
    }
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&context->appAccountManager));
    return true;
}

napi_value GetSubscriberByUnsubscribe(const napi_env &env, std::vector<std::shared_ptr<SubscriberPtr>> &subscribers,
    AsyncContextForUnsubscribe *asyncContextForOff, bool &isFind)
{
    napi_value result;

    {
        std::lock_guard<std::mutex> lock(g_lockForAppAccountSubscribers);

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

bool ParseParametersByUnsubscribe(
    const napi_env &env, napi_callback_info cbInfo, AsyncContextForUnsubscribe *context)
{
    size_t argc = UNSUBSCRIBE_MAX_PARA;
    napi_value argv[UNSUBSCRIBE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL), false);
    if (argc < 1) {
        context->errMsg = "the number of parameters should be at least 1";
        context->errCode = ERR_JS_PARAMETER_ERROR;
        return false;
    }
    if (!GetStringProperty(env, argv[0], context->type)) {
        context->errMsg = "the type is not a string";
        context->errCode = ERR_JS_PARAMETER_ERROR;
        return false;
    }
    if ((context->type != "change") && (context->type != "accountChange")) {
        context->errMsg = "the type is invalid";
        context->errCode = ERR_JS_INVALID_PARAMETER;
        return false;
    }
    if ((argc == UNSUBSCRIBE_MAX_PARA) && (!GetCallbackProperty(env, argv[1], context->callbackRef, 1))) {
        context->errMsg = "the callback is not a function";
        context->errCode = ERR_JS_PARAMETER_ERROR;
        return false;
    }
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&context->appAccountManager));
    if (context->appAccountManager == nullptr) {
        ACCOUNT_LOGE("appAccountManager is nullptr");
        return false;
    }
    context->argc = argc;
    return true;
}

void UnsubscribeExecuteCB(napi_env env, void *data)
{
    AsyncContextForUnsubscribe *asyncContextForOff = reinterpret_cast<AsyncContextForUnsubscribe *>(data);
    for (auto offSubscriber : asyncContextForOff->subscribers) {
        int errCode = AppAccountManager::UnsubscribeAppAccount(offSubscriber);
        ACCOUNT_LOGD("Unsubscribe errcode parameter is %{public}d", errCode);
    }
}

void UnsubscribeCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    AsyncContextForUnsubscribe *asyncContextForOff = reinterpret_cast<AsyncContextForUnsubscribe *>(data);
    if (asyncContextForOff == nullptr) {
        return;
    }

    if (asyncContextForOff->argc >= UNSUBSCRIBE_MAX_PARA) {
        napi_value result = nullptr;
        napi_get_null(env, &result);
        napi_value results[ARGS_SIZE_ONE] = {result};
        NapiCallVoidFunction(env, results, ARGS_SIZE_ONE, asyncContextForOff->callbackRef);
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
                delete offCBInfo;
            }
            g_AppAccountSubscribers.erase(subscribe);
        }
        ACCOUNT_LOGD("Erase end g_AppAccountSubscribers.size = %{public}zu", g_AppAccountSubscribers.size());
    }
    delete asyncContextForOff;
    asyncContextForOff = nullptr;
}

bool ParseVerifyCredentialOptions(napi_env env, napi_value object, VerifyCredentialOptions &options)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        ACCOUNT_LOGE("the type of object is not napi_object");
        return false;
    }
    napi_value value = nullptr;
    bool hasProp = false;
    napi_has_named_property(env, object, "credential", &hasProp);
    if (hasProp) {
        napi_get_named_property(env, object, "credential", &value);
        if (!GetStringProperty(env, value, options.credential)) {
            return false;
        }
    }
    hasProp = false;
    napi_has_named_property(env, object, "credentialType", &hasProp);
    if (hasProp) {
        napi_get_named_property(env, object, "credentialType", &value);
        if (!GetStringProperty(env, value, options.credentialType)) {
            return false;
        }
    }
    hasProp = false;
    napi_has_named_property(env, object, "parameters", &hasProp);
    if (hasProp) {
        napi_get_named_property(env, object, "parameters", &value);
        if (!AppExecFwk::UnwrapWantParams(env, value, options.parameters)) {
            return false;
        }
    }
    return true;
}

bool ParseSelectAccountsOptions(napi_env env, napi_value object, SelectAccountsOptions &options)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        return false;
    }
    napi_value value = nullptr;
    napi_has_named_property(env, object, "allowedAccounts", &options.hasAccounts);
    if (options.hasAccounts) {
        napi_get_named_property(env, object, "allowedAccounts", &value);
        if (!ParseAccountVector(env, value, options.allowedAccounts)) {
            return false;
        }
    }
    napi_has_named_property(env, object, "allowedOwners", &options.hasOwners);
    if (options.hasOwners) {
        value = nullptr;
        napi_get_named_property(env, object, "allowedOwners", &value);
        if (!ParseStringVector(env, value, options.allowedOwners)) {
            return false;
        }
    }
    napi_has_named_property(env, object, "requiredLabels", &options.hasLabels);
    if (options.hasLabels) {
        value = nullptr;
        napi_get_named_property(env, object, "requiredLabels", &value);
        if (!ParseStringVector(env, value, options.requiredLabels)) {
            return false;
        }
    }
    return true;
}

bool ParseSetPropertiesOptions(napi_env env, napi_value object, SetPropertiesOptions &options)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        return false;
    }
    napi_value value = nullptr;
    bool hasProp = false;
    napi_has_named_property(env, object, "properties", &hasProp);
    if (hasProp) {
        napi_get_named_property(env, object, "properties", &value);
        if (!AppExecFwk::UnwrapWantParams(env, value, options.properties)) {
            return false;
        }
    }
    hasProp = false;
    napi_has_named_property(env, object, "parameters", &hasProp);
    if (hasProp) {
        napi_get_named_property(env, object, "parameters", &value);
        if (!AppExecFwk::UnwrapWantParams(env, value, options.parameters)) {
            return false;
        }
    }
    return true;
}

bool GetNamedFunction(napi_env env, napi_value object, const std::string &name, napi_ref &funcRef)
{
    napi_value value = nullptr;
    napi_get_named_property(env, object, name.c_str(), &value);
    return GetCallbackProperty(env, value, funcRef, 1);
}

bool ParseJSAuthCallback(napi_env env, napi_value object, JSAuthCallback &callback)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        return false;
    }
    bool hasProp = false;
    napi_has_named_property(env, object, "onRequestContinued", &hasProp);
    if (hasProp && (!GetNamedFunction(env, object, "onRequestContinued", callback.onRequestContinued))) {
        return false;
    }
    return GetNamedFunction(env, object, "onResult", callback.onResult) ||
        GetNamedFunction(env, object, "onRequestRedirected", callback.onRequestRedirected);
}

bool ParseContextForVerifyCredential(napi_env env, napi_callback_info info, VerifyCredentialContext *context)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_THREE) {
        context->errMsg = "the number of parameter shoulde be at least 3";
        return false;
    }
    int32_t index = 0;
    if (!GetStringProperty(env, argv[index++], context->name)) {
        context->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[index++], context->owner)) {
        context->errMsg = "the owner is not a string";
        return false;
    }
    if ((argc == ARGS_SIZE_FOUR) && (!ParseVerifyCredentialOptions(env, argv[index++], context->options))) {
        context->errMsg = "the type of options is not VerifyCredentialOptions";
        return false;
    }
    if (!ParseJSAuthCallback(env, argv[index], context->callback)) {
        context->errMsg = "the type of callback is not AuthCallback";
        return false;
    }
    return true;
}

bool ParseContextForSetProperties(napi_env env, napi_callback_info info, SetPropertiesContext *context)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_TWO) {
        context->errMsg = "the number of parameter shoulde be at least 2";
        return false;
    }
    int32_t index = 0;
    if (!GetStringProperty(env, argv[index++], context->owner)) {
        context->errMsg = "the owner is not a string";
        return false;
    }
    if (argc == ARGS_SIZE_THREE) {
        if (!ParseSetPropertiesOptions(env, argv[index++], context->options)) {
            context->errMsg = "the type of options is not SetPropertiesOptions";
            return false;
        }
    }
    if (!ParseJSAuthCallback(env, argv[index], context->callback)) {
        context->errMsg = "the type of callback is not AuthCallback";
        return false;
    }
    return true;
}

bool ParseContextForSelectAccount(napi_env env, napi_callback_info info, SelectAccountsContext *context)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_ONE) {
        context->errMsg = "the number of parameter shoulde be at least 1";
        return false;
    }
    if ((argc == ARGS_SIZE_TWO) && (!GetCallbackProperty(env, argv[PARAMONE], context->callbackRef, PARAMTWO))) {
        context->errMsg = "the callback is not a function";
        return false;
    }
    if (!ParseSelectAccountsOptions(env, argv[0], context->options)) {
        context->errMsg = "the type of options is not SelectAccountsOptions";
        return false;
    }
    return true;
}

bool GetArrayLength(napi_env env, napi_value value, uint32_t &length)
{
    bool isArray = false;
    napi_is_array(env, value, &isArray);
    if (!isArray) {
        ACCOUNT_LOGE("wrong argument type, array expected");
        return false;
    }
    napi_get_array_length(env, value, &length);
    return true;
}

bool ParseAccountVector(napi_env env, napi_value value, std::vector<std::pair<std::string, std::string>> &accountVec)
{
    uint32_t length = 0;
    if (!GetArrayLength(env, value, length)) {
        return false;
    }
    napi_valuetype valueType = napi_undefined;
    for (uint32_t i = 0; i < length; ++i) {
        napi_value item = nullptr;
        napi_get_element(env, value, i, &item);
        NAPI_CALL_BASE(env, napi_typeof(env, item, &valueType), false);
        if (valueType != napi_object) {
            ACCOUNT_LOGD("Wrong argument type, Object expected");
            return false;
        }
        std::string name;
        if (!GetStringPropertyByKey(env, item, "name", name)) {
            return false;
        }
        std::string owner;
        if (!GetStringPropertyByKey(env, item, "owner", owner)) {
            return false;
        }
        accountVec.push_back(std::make_pair(owner, name));
    }
    return true;
}

bool ParseStringVector(napi_env env, napi_value value, std::vector<std::string> &strVec)
{
    uint32_t length = 0;
    if (!GetArrayLength(env, value, length)) {
        return false;
    }
    for (uint32_t i = 0; i < length; ++i) {
        napi_value item = nullptr;
        napi_get_element(env, value, i, &item);
        std::string str;
        if (!GetStringProperty(env, item, str)) {
            return false;
        }
        strVec.push_back(str);
    }
    return true;
}

bool ParseContextForCheckAccountLabels(napi_env env, napi_callback_info info, CheckAccountLabelsContext *context)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_THREE) {
        context->errMsg = "the number of parameter should be at least 3";
        return false;
    }
    if ((argc == ARGS_SIZE_FOUR) && (!GetCallbackProperty(env, argv[PARAMTHREE], context->callbackRef, PARAMTWO))) {
        context->errMsg = "the callback is not a function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], context->name)) {
        context->errMsg = "the name is not a string";
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMONE], context->owner)) {
        context->errMsg = "the owner is not a string";
        return false;
    }
    if (!ParseStringVector(env, argv[PARAMTWO], context->labels)) {
        context->errMsg = "the labels is not a string vector";
        return false;
    }
    return true;
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
    NapiCallVoidFunction(env, results, ARGS_SIZE_TWO, callback.onResult);
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

bool ParseCreateAccountOptions(napi_env env, napi_value object, CreateAccountOptions &options)
{
    bool hasCustomData = false;
    napi_has_named_property(env, object, "customData", &hasCustomData);
    if (!hasCustomData) {
        return true;
    }
    napi_value customDataValue = nullptr;
    napi_get_named_property(env, object, "customData", &customDataValue);
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, customDataValue, &valueType);
    if (valueType != napi_object) {
        ACCOUNT_LOGE("not napi object");
        return false;
    }
    napi_value keyArr = nullptr;
    napi_get_property_names(env, customDataValue, &keyArr);
    uint32_t keyNum = 0;
    napi_get_array_length(env, keyArr, &keyNum);
    for (uint32_t i = 0; i < keyNum; ++i) {
        napi_value item = nullptr;
        napi_get_element(env, keyArr, i, &item);
        std::string keyStr;
        if (!GetStringProperty(env, item, keyStr)) {
            ACCOUNT_LOGE("fail to get string");
            return false;
        }
        napi_value val = nullptr;
        napi_get_named_property(env, customDataValue, keyStr.c_str(), &val);
        std::string valStr;
        if (!GetStringProperty(env, val, valStr)) {
            ACCOUNT_LOGE("fail to get string");
            return false;
        }
        options.customData.emplace(keyStr, valStr);
    }
    return true;
}

bool ParseCreateAccountImplicitlyOptions(napi_env env, napi_value object, CreateAccountImplicitlyOptions &options)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        return false;
    }
    napi_value value = nullptr;
    napi_has_named_property(env, object, "requiredLabels", &options.hasRequiredLabels);
    if (options.hasRequiredLabels) {
        napi_get_named_property(env, object, "requiredLabels", &value);
        if (!ParseStringVector(env, value, options.requiredLabels)) {
            return false;
        }
    }
    napi_has_named_property(env, object, "authType", &options.hasAuthType);
    if (options.hasAuthType) {
        napi_get_named_property(env, object, "authType", &value);
        if (!GetStringProperty(env, value, options.authType)) {
            return false;
        }
    }
    bool hasParam = false;
    napi_has_named_property(env, object, "parameters", &hasParam);
    AAFwk::WantParams params;
    if (hasParam) {
        napi_get_named_property(env, object, "parameters", &value);
        if (!AppExecFwk::UnwrapWantParams(env, value, params)) {
            return false;
        }
    }
    options.parameters.SetParams(params);
    return true;
}

bool ParseContextForCreateAccount(napi_env env, napi_callback_info cbInfo, CreateAccountContext *context)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_ONE) {
        context->errMsg = "the number of parameters should be at least 1";
        return false;
    }
    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            GetStringProperty(env, argv[i], context->name);
        } else if (i == 1 && valueType == napi_object) {
            if (!ParseCreateAccountOptions(env, argv[i], context->options)) {
                context->errMsg = "the type of options is not CreateAccountOptions";
                return false;
            }
        } else if (i == 1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &context->callbackRef);
            break;
        } else if (i == PARAMTWO && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &context->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            context->errMsg = "the type of param " + std::to_string(i) + " is incorrect";
            return false;
        }
    }
    return true;
}

bool ParseContextForCreateAccountImplicitly(
    napi_env env, napi_callback_info cbInfo, CreateAccountImplicitlyContext *context)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_TWO) {
        context->errMsg = "the number of parameters should be at least 2";
        return false;
    }
    size_t index = 0;
    if (!GetStringProperty(env, argv[index++], context->owner)) {
        context->errMsg = "the type of owner is not string";
        return false;
    }
    if ((argc == ARGS_SIZE_THREE) && (!ParseCreateAccountImplicitlyOptions(env, argv[index++], context->options))) {
        context->errMsg = "the type of options is not CreateAccountImplicitlyOptions";
        return false;
    }
    if (!ParseJSAuthCallback(env, argv[index], context->callback)) {
        context->errMsg = "the type of callback is not AuthCallback";
        return false;
    }
    std::string abilityName;
    GetAbilityName(env, abilityName);
    context->options.parameters.SetParam(Constants::KEY_CALLER_ABILITY_NAME, abilityName);
    return true;
}

bool GetAbilityName(napi_env env, std::string &abilityName)
{
    napi_value global;
    napi_get_global(env, &global);
    napi_value abilityObj;
    napi_get_named_property(env, global, "ability", &abilityObj);
    if (abilityObj == nullptr) {
        return false;
    }
    AppExecFwk::Ability *ability = nullptr;
    napi_get_value_external(env, abilityObj, reinterpret_cast<void **>(&ability));
    if (ability == nullptr) {
        return false;
    }
    auto abilityInfo = ability->GetAbilityInfo();
    if (abilityInfo == nullptr) {
        return false;
    }
    abilityName = abilityInfo->name;
    return true;
}
}  // namespace AccountJsKit
}  // namespace OHOS

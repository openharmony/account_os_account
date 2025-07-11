/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
static const std::int32_t SUBSCRIBE_MAX_PARA = 3;
static const std::int32_t UNSUBSCRIBE_MAX_PARA = 2;

static const std::string ErrMsgList[] = {
    "Parameter error. The type of \"name\" must be string",           // index equals to PropertyType::NAME value
    "Parameter error. The type of \"owner\" must be string",          // index equals to PropertyType::OWNER value
    "Parameter error. The type of \"authType\" must be string",       // index equals to PropertyType::AUTH_TYPE value
    "Parameter error. The type of \"bundleName\" must be string",     // index equals to PropertyType::BUNDLE_NAME value
    "Parameter error. The type of \"sessionId\" must be string",      // index equals to PropertyType::SESSION_ID value
    "Parameter error. The type of \"isVisible\" must be bool",        // index equals to PropertyType::IS_VISIBLE value
    "Parameter error. The type of \"token\" must be string",          // index equals to PropertyType::TOKEN value
    "Parameter error. The type of \"extraInfo\" must be string",      // index equals to PropertyType::EXTRA_INFO value
    "Parameter error. The type of \"credentialType\" must be string", // index equals to PropertyType::CREDENTIAL_TYPE
                                                                      // value
    "Parameter error. The type of \"credential\" must be string",     // index equals to PropertyType::CREDENTIAL value
    "Parameter error. The type of \"key\" must be string",            // index equals to PropertyType::KEY value
    "Parameter error. The type of \"value\" must be string",          // index equals to PropertyType::VALUE value
    "Parameter error. The type of \"isAccessible\" must be bool",     // index equals to PropertyType::IS_ACCESSIBLE
                                                                      // value
    "Parameter error. The type of \"isEnable\" must be bool",         // index equals to PropertyType::IS_ENABLE value
};

std::mutex g_lockForAppAccountSubscribers;
std::map<AppAccountManager *, std::vector<AsyncContextForSubscribe *>> g_AppAccountSubscribers;

SubscriberPtr::SubscriberPtr(const AppAccountSubscribeInfo &subscribeInfo) : AppAccountSubscriber(subscribeInfo)
{}

static std::function<void()> OnAppAccountsChangedWork(const std::shared_ptr<SubscriberAccountsWorker> &data)
{
    return [data = data] {
        ACCOUNT_LOGI("Enter OnAppAccountsChangedWork");
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(data->env, &scope);
        if (scope == nullptr) {
            ACCOUNT_LOGE("Fail to open scope");
            return;
        }
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
                    ACCOUNT_LOGD("AppAccount subscriber has been found.");
                    break;
                }
            }
        }
        if (isFound) {
            napi_value results[ARGS_SIZE_ONE] = { nullptr };
            GetAppAccountInfoForResult(data->env, data->accounts, results[0]);
            NapiCallVoidFunction(data->env, results, ARGS_SIZE_ONE, data->ref);
        }
        napi_close_handle_scope(data->env, scope);
    };
}

void SubscriberPtr::OnAccountsChanged(const std::vector<AppAccountInfo> &accounts_)
{
    std::shared_ptr<SubscriberAccountsWorker> worker = std::make_shared<SubscriberAccountsWorker>(env_);
    if (worker == nullptr) {
        ACCOUNT_LOGE("SubscriberAccountsWorker is null");
        return;
    }

    worker->accounts = accounts_;
    worker->ref = ref_;
    worker->subscriber = this;

    if (napi_ok != napi_send_event(env_, OnAppAccountsChangedWork(worker), napi_eprio_vip)) {
        ACCOUNT_LOGE("Post task failed");
        return;
    }
    ACCOUNT_LOGI("Post task finish");
}

void SubscriberPtr::SetEnv(const napi_env &env)
{
    env_ = env;
}

void SubscriberPtr::SetCallbackRef(const napi_ref &ref)
{
    ref_ = ref;
}

std::function<void()> CheckAccountLabelsOnResultWork(const std::shared_ptr<AuthenticatorCallbackParam> &param)
{
    return [data = param] {
        ACCOUNT_LOGI("Enter CheckAccountLabelsOnResultWork");
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(data->env, &scope);
        if (scope == nullptr) {
            ACCOUNT_LOGE("Fail to open scope");
            return;
        }
        napi_env env = data->env;
        napi_value checkResult[RESULT_COUNT] = { NapiGetNull(env) };
        if (data->errCode == ERR_JS_SUCCESS) {
            bool hasLabels = data->result.GetBoolParam(Constants::KEY_BOOLEAN_RESULT, false);
            napi_get_boolean(env, hasLabels, &checkResult[PARAMONE]);
        } else {
            checkResult[PARAMZERO] = GetErrorCodeValue(env, data->errCode);
        }
        ProcessCallbackOrPromise(env, data.get(), checkResult[PARAMZERO], checkResult[PARAMONE]);
        napi_close_handle_scope(env, scope);
    };
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

std::function<void()> SelectAccountsOnResultWork(const std::shared_ptr<AuthenticatorCallbackParam> &param)
{
    return [param = param] {
        ACCOUNT_LOGI("Enter SelectAccountsOnResultWork");
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(param->env, &scope);
        if (scope == nullptr) {
            ACCOUNT_LOGE("Fail to open scope");
            return;
        }
        std::vector<std::string> names = param->result.GetStringArrayParam(Constants::KEY_ACCOUNT_NAMES);
        std::vector<std::string> owners = param->result.GetStringArrayParam(Constants::KEY_ACCOUNT_OWNERS);
        if (names.size() != owners.size()) {
            param->errCode = ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION;
        }
        napi_env env = param->env;
        napi_value selectResult[RESULT_COUNT] = { 0 };
        if (param->errCode == ERR_JS_SUCCESS) {
            napi_create_array(env, &selectResult[PARAMONE]);
            for (size_t i = 0; i < names.size(); ++i) {
                napi_value object = CreateJSAppAccountInfo(env, names[i], owners[i]);
                napi_set_element(env, selectResult[PARAMONE], i, object);
            }
        } else {
            selectResult[PARAMZERO] = GetErrorCodeValue(env, param->errCode);
        }
        ProcessCallbackOrPromise(env, param.get(), selectResult[PARAMZERO], selectResult[PARAMONE]);
        napi_close_handle_scope(env, scope);
    };
}

AuthenticatorAsyncCallback::AuthenticatorAsyncCallback(
    napi_env env, std::shared_ptr<NapiCallbackRef> callback, napi_deferred deferred,
    std::function<std::function<void()>(const std::shared_ptr<AuthenticatorCallbackParam> &)> workCb)
    : env_(env), callbackRef_(callback), deferred_(deferred), workCb_(workCb)
{}

AuthenticatorAsyncCallback::~AuthenticatorAsyncCallback()
{}

ErrCode AuthenticatorAsyncCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (isDone) {
            return ERR_OK;
        }
        isDone = true;
    }
    std::shared_ptr<AuthenticatorCallbackParam> param = std::make_shared<AuthenticatorCallbackParam>(callbackRef_);
    param->env = env_;
    param->deferred = deferred_;
    param->errCode = resultCode;
    param->result = result;
    if (napi_ok == napi_send_event(env_, workCb_(param), napi_eprio_vip)) {
        ACCOUNT_LOGI("Post task finish");
        return ERR_OK;
    }
    ACCOUNT_LOGE("Post task failed");
    return ERR_OK;
}

ErrCode AuthenticatorAsyncCallback::OnRequestRedirected(const AAFwk::Want &request)
{
    return ERR_OK;
}

ErrCode AuthenticatorAsyncCallback::OnRequestContinued()
{
    return ERR_OK;
}

ErrCode AuthenticatorAsyncCallback::CallbackEnter([[maybe_unused]] uint32_t code)
{
    return ERR_OK;
}

ErrCode AuthenticatorAsyncCallback::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    switch (code) {
        case static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_RESULT): {
            if (result == ERR_INVALID_DATA) {
                AAFwk::Want resultWant;
                OnResult(ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION, resultWant);
                return ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE;
            }
            break;
        }
        case static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_REQUEST_REDIRECTED): {
            if (result == ERR_INVALID_DATA) {
                AAFwk::Want request;
                OnRequestRedirected(request);
                return ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE;
            }
            break;
        }
        default:
            return ERR_NONE;
    }
    return ERR_NONE;
}

AppAccountManagerCallback::AppAccountManagerCallback(napi_env env, JSAuthCallback callback)
    : env_(env), callback_(callback)
{}

AppAccountManagerCallback::~AppAccountManagerCallback()
{}

static std::function<void()> OnResultWork(const std::shared_ptr<AuthenticatorCallbackParam> &param)
{
    return [data = param] {
        ACCOUNT_LOGI("Enter OnResultWork");
        napi_handle_scope scope = nullptr;
        napi_env env = data->authCallback.onResult->env;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            ACCOUNT_LOGE("Fail to open scope");
            return;
        }
        ProcessOnResultCallback(env, data->authCallback, data->resultCode, data->result.GetParams());
        napi_close_handle_scope(env, scope);
    };
}

static std::function<void()> OnRequestRedirectedWork(const std::shared_ptr<AuthenticatorCallbackParam> &param)
{
    return [data = param] {
        ACCOUNT_LOGI("Enter OnRequestRedirectedWork");
        napi_handle_scope scope = nullptr;
        napi_env env = data->authCallback.onRequestRedirected->env;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            ACCOUNT_LOGE("Fail to open scope");
            return;
        }
        napi_value results[ARGS_SIZE_ONE] = { AppExecFwk::WrapWant(env, data->request) };
        NapiCallVoidFunction(env, results, ARGS_SIZE_ONE, data->authCallback.onRequestRedirected->callbackRef);
        napi_close_handle_scope(env, scope);
    };
}

static std::function<void()> OnRequestContinuedWork(const std::shared_ptr<AuthenticatorCallbackParam> &param)
{
    return [data = param] {
        ACCOUNT_LOGI("Enter OnRequestContinuedWork");
        napi_handle_scope scope = nullptr;
        napi_env env = data->authCallback.onRequestContinued->env;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            ACCOUNT_LOGE("Fail to open scope");
            return;
        }
        NapiCallVoidFunction(env, nullptr, 0, data->authCallback.onRequestContinued->callbackRef);
        napi_close_handle_scope(env, scope);
    };
}

ErrCode AppAccountManagerCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (isDone) {
            return ERR_OK;
        }
        isDone = true;
    }
    if (callback_.onResult == nullptr) {
        ACCOUNT_LOGE("onResult is null");
        return ERR_OK;
    }
    std::shared_ptr<AuthenticatorCallbackParam> param = std::make_shared<AuthenticatorCallbackParam>(callback_);
    param->resultCode = resultCode;
    param->result = result;
    if (napi_ok != napi_send_event(env_, OnResultWork(param), napi_eprio_vip)) {
        ACCOUNT_LOGE("Post task failed");
        return ERR_OK;
    }
    ACCOUNT_LOGI("Post task finish");
    return ERR_OK;
}

ErrCode AppAccountManagerCallback::OnRequestRedirected(const AAFwk::Want &request)
{
    if (callback_.onRequestRedirected == nullptr) {
        ACCOUNT_LOGE("onRequestRedirected is null");
        return ERR_OK;
    }
    std::shared_ptr<AuthenticatorCallbackParam> param = std::make_shared<AuthenticatorCallbackParam>(callback_);
    param->request = request;
    if (napi_ok != napi_send_event(env_, OnRequestRedirectedWork(param), napi_eprio_vip)) {
        ACCOUNT_LOGE("Post task failed");
        return ERR_OK;
    }
    ACCOUNT_LOGI("Post task finish");
    return ERR_OK;
}

ErrCode AppAccountManagerCallback::OnRequestContinued()
{
    if (callback_.onRequestContinued == nullptr) {
        ACCOUNT_LOGE("OnRequestContinued is null");
        return ERR_OK;
    }
    std::shared_ptr<AuthenticatorCallbackParam> param = std::make_shared<AuthenticatorCallbackParam>(callback_);
    if (napi_ok != napi_send_event(env_, OnRequestContinuedWork(param), napi_eprio_vip)) {
        ACCOUNT_LOGE("Post task failed");
        return ERR_OK;
    }
    ACCOUNT_LOGI("Post task finish");
    return ERR_OK;
}

ErrCode AppAccountManagerCallback::CallbackEnter([[maybe_unused]] uint32_t code)
{
    return ERR_OK;
}

ErrCode AppAccountManagerCallback::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    switch (code) {
        case static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_RESULT): {
            if (result == ERR_INVALID_DATA) {
                AAFwk::Want resultWant;
                OnResult(ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION, resultWant);
                return ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE;
            }
            break;
        }
        case static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_REQUEST_REDIRECTED): {
            if (result == ERR_INVALID_DATA) {
                AAFwk::Want request;
                OnRequestRedirected(request);
                return ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE;
            }
            break;
        }
        default:
            return ERR_NONE;
    }
    return ERR_NONE;
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
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, objName, NAPI_AUTO_LENGTH, &prop));
    napi_set_named_property(env, dstObj, propName, prop);
}

void SetNamedProperty(napi_env env, napi_value dstObj, const int32_t objValue, const char *propName)
{
    napi_value prop = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, objValue, &prop));
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
    napi_create_uint32(env, info.iconId, &nIconId);
    napi_set_named_property(env, result, "iconId", nIconId);

    napi_value nLabelId = nullptr;
    napi_create_uint32(env, info.labelId, &nLabelId);
    napi_set_named_property(env, result, "labelId", nLabelId);
}

void GetOAuthTokenInfoForResult(napi_env env, const std::vector<OAuthTokenInfo> &info, napi_value result)
{
    int32_t index = 0;
    for (auto item : info) {
        napi_value objOAuthTokenInfo = nullptr;
        napi_create_object(env, &objOAuthTokenInfo);

        napi_value nToken = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, item.token.c_str(), NAPI_AUTO_LENGTH, &nToken));
        napi_set_named_property(env, objOAuthTokenInfo, "token", nToken);

        napi_value nAuthType = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, item.authType.c_str(), NAPI_AUTO_LENGTH, &nAuthType));
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
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, item.c_str(), NAPI_AUTO_LENGTH, &nBundleName));
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
    napi_valuetype valueType = napi_undefined;
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_ONE) {
        asyncContext->errMsg = "the number of parameters should be at least 1";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->name)) {
        ACCOUNT_LOGE("the name is not a string");
        asyncContext->errMsg = "the name is not a string";
        return false;
    }
    if (argc > PARAMTWO) {
        if (!GetCallbackProperty(env, argv[PARAMTWO], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            return false;
        }
    }
    if (argc > ARGS_SIZE_ONE) {
        napi_typeof(env, argv[1], &valueType);
        if (valueType == napi_string) {
            if (!GetStringProperty(env, argv[1], asyncContext->extraInfo)) {
                asyncContext->errMsg = "the extraInfo is not a string";
                return false;
            }
        } else if (valueType == napi_function) {
            if (!GetCallbackProperty(env, argv[1], asyncContext->callbackRef, 1)) {
                ACCOUNT_LOGE("Get callbackRef failed");
                return false;
            }
            return true;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            asyncContext->errMsg = "the type of param 2 is incorrect";
            return false;
        }
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
    size_t argc = ARGS_SIZE_FIVE;
    napi_value argv[ARGS_SIZE_FIVE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_FOUR) {
        context->errMsg = "the number of parameters should be at least 4";
        return false;
    }
    if (!GetStringProperty(env, argv[0], context->name)) {
        context->errMsg = "Parameter error. The type of \"name\" must be string";
        return false;
    }
    if (!GetStringProperty(env, argv[1], context->owner)) {
        context->errMsg = "Parameter error. The type of \"owner\" must be string";
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMTWO], context->authType)) {
        context->errMsg = "Parameter error. The type of \"authType\" must be string";
        return false;
    }
    AAFwk::WantParams params;
    if (argc == ARGS_SIZE_FIVE) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[PARAMTHREE], &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("the options is undefined or null");
        } else {
            if (!AppExecFwk::UnwrapWantParams(env, argv[PARAMTHREE], params)) {
                ACCOUNT_LOGE("UnwrapWantParams failed");
                context->errMsg = "Parameter error. The type of \"options\" must be Record";
                return false;
            }
        }
    }
    context->options.SetParams(params);
    JSAuthCallback callback;
    if (!ParseJSAuthCallback(env, argv[argc - 1], callback)) {
        context->errMsg = "Parameter error. The type of \"callback\" must be AuthCallback";
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
    JSAuthCallback callback;
    ParseJSAuthCallback(env, argv[index], callback);
    asyncContext->appAccountMgrCb = new (std::nothrow) AppAccountManagerCallback(env, callback);
}

bool ParseContextOAuthProperty(napi_env env, napi_value &argv, PropertyType type, OAuthAsyncContext *asyncContext)
{
    bool result = false;
    switch (type) {
        case PropertyType::NAME :
            result = GetStringProperty(env, argv, asyncContext->name);
            break;
        case PropertyType::OWNER :
            result = GetStringProperty(env, argv, asyncContext->owner);
            break;
        case PropertyType::AUTH_TYPE :
            result = GetStringProperty(env, argv, asyncContext->authType);
            break;
        case PropertyType::BUNDLE_NAME :
            result = GetStringProperty(env, argv, asyncContext->bundleName);
            break;
        case PropertyType::SESSION_ID :
            result = GetStringProperty(env, argv, asyncContext->sessionId);
            break;
        case PropertyType::IS_VISIBLE :
            result = napi_get_value_bool(env, argv, &asyncContext->isVisible) == napi_ok;
            break;
        case PropertyType::TOKEN :
            result = GetStringProperty(env, argv, asyncContext->token);
            break;
        // when new PropertyType is added, new error message need to be added in ErrMsgList.
        default:
            break;
    }
    if (!result) {
        asyncContext->errMsg = ErrMsgList[type];
    }
    return result;
}

bool ParseContextForOAuth(napi_env env, napi_callback_info cbInfo,
    OAuthAsyncContext *asyncContext, const std::vector<PropertyType> &propertyList, napi_value *result)
{
    // the inner caller promise posInfo.argcSize to be at least 1
    size_t argcSize = propertyList.size() + 1;
    size_t argc = argcSize;
    napi_value argv[ARGS_SIZE_MAX] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < argcSize - 1) {
        asyncContext->errMsg = "the number of parameter should be at least " + std::to_string(argcSize - 1);
        return false;
    }
    if ((argc == argcSize) && (!GetCallbackProperty(env, argv[argcSize - 1], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "Parameter error. The type of \"callback\" must be AuthCallback";
        return false;
    }
    for (uint32_t i = 0; i < propertyList.size(); i++) {
        if (!ParseContextOAuthProperty(env, argv[i], propertyList[i], asyncContext)) {
            return false;
        }
    }
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, result);
    } else {
        napi_get_undefined(env, result);
    }
    return true;
}

bool ParseAppAccountProperty(napi_env env, napi_value &argv, PropertyType type, AppAccountAsyncContext *asyncContext)
{
    bool result = false;
    switch (type) {
        case PropertyType::NAME :
            result = GetStringProperty(env, argv, asyncContext->name);
            break;
        case PropertyType::OWNER :
            result = GetStringProperty(env, argv, asyncContext->owner);
            break;
        case PropertyType::EXTRA_INFO :
            result = GetStringProperty(env, argv, asyncContext->extraInfo);
            break;
        case PropertyType::BUNDLE_NAME :
            result = GetStringProperty(env, argv, asyncContext->bundleName);
            break;
        case PropertyType::CREDENTIAL_TYPE :
            result = GetStringProperty(env, argv, asyncContext->credentialType);
            break;
        case PropertyType::CREDENTIAL :
            result = GetStringProperty(env, argv, asyncContext->credential);
            break;
        case PropertyType::KEY :
            result = GetStringProperty(env, argv, asyncContext->key);
            break;
        case PropertyType::VALUE :
            result = GetStringProperty(env, argv, asyncContext->value);
            break;
        case PropertyType::IS_ACCESSIBLE :
            result = napi_get_value_bool(env, argv, &asyncContext->isAccessible) == napi_ok;
            break;
        case PropertyType::IS_ENABLE :
            result = napi_get_value_bool(env, argv, &asyncContext->isEnable) == napi_ok;
            break;
        default:
            break;
    }
    return result;
}

bool ParseContextForAppAccount(napi_env env, napi_callback_info cbInfo,
    AppAccountAsyncContext *context, const std::vector<PropertyType> &propertyList, napi_value *result)
{
    size_t argcSize = propertyList.size() + 1;
    size_t argc = argcSize;
    napi_value argv[ARGS_SIZE_MAX] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < (argcSize - 1)) {
        context->errMsg =
            "Parameter error. The number of parameter should be at least " + std::to_string(argcSize - 1);
        return false;
    }
    if ((argc == argcSize) && (!GetCallbackProperty(env, argv[argcSize - 1], context->callbackRef, 1))) {
        context->errMsg = "Parameter error. The type of \"callback\" must be function";
        return false;
    }
    for (size_t i = 0; i < propertyList.size(); i++) {
        if (!ParseAppAccountProperty(env, argv[i], propertyList[i], context)) {
            context->errMsg = ErrMsgList[propertyList[i]];
            return false;
        }
    }
    if (context->callbackRef == nullptr) {
        napi_create_promise(env, &context->deferred, result);
    } else {
        napi_get_undefined(env, result);
    }
    return true;
}

bool ParseContextCBArray(napi_env env, napi_callback_info cbInfo, GetAccountsAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if ((argc == ARGS_SIZE_ONE) && (!GetCallbackProperty(env, argv[0], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "Parameter error. The type of \"callback\" must be function";
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
        asyncContext->errMsg = "Parameter error. The number of parameter should be at least 2";
        return false;
    }
    if ((argc == ARGS_SIZE_TWO) && (!GetCallbackProperty(env, argv[1], asyncContext->callbackRef, 1))) {
        asyncContext->errMsg = "Parameter error. The type of \"callback\" must be function";
        return false;
    }
    if (!GetStringProperty(env, argv[0], asyncContext->owner)) {
        asyncContext->errMsg = "Parameter error. The type of \"owner\" must be string";
        return false;
    }
    return true;
}

bool GetArrayProperty(const napi_env &env, napi_value *argv, AsyncContextForSubscribe *context)
{
    bool isArray = false;
    napi_is_array(env, argv[1], &isArray);
    if (!isArray) {
        context->errMsg = "Parameter error. The type of \"owners\" must be string array";
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
            context->errMsg = "Parameter error. The type of \"owners\" must be string array";
            return false;
        }
        context->owners.emplace_back(owner);
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
        context->errMsg = "Parameter error. The number of parameters should be 3";
        return false;
    }
    if (!GetStringProperty(env, argv[0], context->type)) {
        context->errMsg = "Parameter error. The type of \"type\" must be string";
        return false;
    }
    if ((context->type != "change") && (context->type != "accountChange")) {
        context->errMsg = "Parameter error. The content of \"type\" must be \"change|accountChange\"";
        context->errCode = ERR_JS_INVALID_PARAMETER;
        return false;
    }
    if (!GetArrayProperty(env, argv, context)) {
        context->errMsg = "Parameter error. The type of \"owners\" must be array";
        return false;
    }
    if (!GetCallbackProperty(env, argv[PARAMTWO], context->callbackRef, 1)) {
        context->errMsg = "Parameter error. The type of \"callback\" must be function";
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
        context->errMsg = "Parameter error. The number of parameters should be at least 1";
        context->errCode = ERR_JS_PARAMETER_ERROR;
        return false;
    }
    if (!GetStringProperty(env, argv[0], context->type)) {
        context->errMsg = "Parameter error. The type of \"type\" must be string";
        context->errCode = ERR_JS_PARAMETER_ERROR;
        return false;
    }
    if ((context->type != "change") && (context->type != "accountChange")) {
        context->errMsg = "Parameter error. The content of \"type\" must be \"change|accountChange\"";
        context->errCode = ERR_JS_INVALID_PARAMETER;
        return false;
    }
    if ((argc == UNSUBSCRIBE_MAX_PARA) && (!GetCallbackProperty(env, argv[1], context->callbackRef, 1))) {
        context->errMsg = "Parameter error. The type of \"callback\" must be function";
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

    {
        std::lock_guard<std::mutex> lock(g_lockForAppAccountSubscribers);
        ACCOUNT_LOGD("Erase before g_AppAccountSubscribers.size = %{public}zu", g_AppAccountSubscribers.size());
        // erase the info from map
        auto subscribe = g_AppAccountSubscribers.find(asyncContextForOff->appAccountManager);
        if (subscribe != g_AppAccountSubscribers.end()) {
            for (auto offCBInfo : subscribe->second) {
                delete offCBInfo;
            }
            g_AppAccountSubscribers.erase(subscribe);
        }
        ACCOUNT_LOGD("Erase end g_AppAccountSubscribers.size = %{public}zu", g_AppAccountSubscribers.size());
    }
    delete asyncContextForOff;
}

bool ParseVerifyCredentialOptions(napi_env env, napi_value object, VerifyCredentialOptions &options)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if ((valueType == napi_undefined) || (valueType == napi_null)) {
        ACCOUNT_LOGI("the VerifyCredentialOptions is undefined or null");
        return true;
    }
    if (valueType != napi_object) {
        ACCOUNT_LOGE("the type of object is not napi_object");
        return false;
    }
    if (!GetOptionalStringPropertyByKey(env, object, "credential", options.credential)) {
        ACCOUNT_LOGE("failed to get options's credential property");
        return false;
    }
    if (!GetOptionalStringPropertyByKey(env, object, "credentialType", options.credentialType)) {
        ACCOUNT_LOGE("failed to get options's credentialType property");
        return false;
    }
    napi_value value = nullptr;
    bool hasProp = false;
    napi_has_named_property(env, object, "parameters", &hasProp);
    if (hasProp) {
        napi_get_named_property(env, object, "parameters", &value);
        valueType = napi_undefined;
        napi_typeof(env, value, &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("the parameters is undefined or null");
        } else {
            if (!AppExecFwk::UnwrapWantParams(env, value, options.parameters)) {
                return false;
            }
        }
    }
    return true;
}

static bool ParseOptionalStringVectorByKey(
    napi_env env, napi_value object, const char* key, bool &result, std::vector<std::string> &array)
{
    napi_has_named_property(env, object, key, &result);
    if (result) {
        napi_value value = nullptr;
        napi_get_named_property(env, object, key, &value);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, value, &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            result = false;
            ACCOUNT_LOGI("the %{public}s is undefined or null", key);
            return true;
        }
        if (!ParseStringVector(env, value, array)) {
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
        valueType = napi_undefined;
        napi_typeof(env, value, &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            options.hasAccounts = false;
            ACCOUNT_LOGI("the allowedAccounts is undefined or null");
        } else {
            if (!ParseAccountVector(env, value, options.allowedAccounts)) {
                return false;
            }
        }
    }
    if (!ParseOptionalStringVectorByKey(env, object, "allowedOwners", options.hasOwners, options.allowedOwners)) {
        return false;
    }
    if (!ParseOptionalStringVectorByKey(env, object, "requiredLabels", options.hasLabels, options.requiredLabels)) {
        return false;
    }
    return true;
}

bool ParseSetPropertiesOptions(napi_env env, napi_value object, SetPropertiesOptions &options)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if ((valueType == napi_undefined) || (valueType == napi_null)) {
        ACCOUNT_LOGI("the SetPropertiesOptions is undefined or null");
        return true;
    }
    if (valueType != napi_object) {
        return false;
    }
    napi_value value = nullptr;
    bool hasProp = false;
    napi_has_named_property(env, object, "properties", &hasProp);
    if (hasProp) {
        napi_get_named_property(env, object, "properties", &value);
        valueType = napi_undefined;
        napi_typeof(env, value, &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("the properties is undefined or null");
        } else {
            if (!AppExecFwk::UnwrapWantParams(env, value, options.properties)) {
                return false;
            }
        }
    }
    hasProp = false;
    napi_has_named_property(env, object, "parameters", &hasProp);
    if (hasProp) {
        napi_get_named_property(env, object, "parameters", &value);
        valueType = napi_undefined;
        napi_typeof(env, value, &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("the parameters is undefined or null");
        } else {
            if (!AppExecFwk::UnwrapWantParams(env, value, options.parameters)) {
                return false;
            }
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
        ACCOUNT_LOGE("the type of callback is invalid");
        return false;
    }
    bool hasProp = false;
    napi_has_named_property(env, object, "onRequestContinued", &hasProp);
    if (hasProp) {
        napi_value value = nullptr;
        napi_get_named_property(env, object, "onRequestContinued", &value);
        valueType = napi_undefined;
        napi_typeof(env, value, &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("the parameters is undefined or null");
        } else {
            napi_ref ref = nullptr;
            if (!GetNamedFunction(env, object, "onRequestContinued", ref)) {
                ACCOUNT_LOGE("the onRequestContinued is invalid");
                return false;
            }
            callback.onRequestContinued = std::make_shared<NapiCallbackRef>(env, ref);
        }
    }
    napi_ref onResultRef = nullptr;
    bool onResultParse = GetNamedFunction(env, object, "onResult", onResultRef);
    if (onResultParse && onResultRef != nullptr) {
        callback.onResult = std::make_shared<NapiCallbackRef>(env, onResultRef);
    }
    napi_ref onRequestRedirectedRef = nullptr;
    bool onRequestRedirectedParse = GetNamedFunction(env, object, "onRequestRedirected", onRequestRedirectedRef);
    if (onRequestRedirectedParse && onRequestRedirectedRef != nullptr) {
        callback.onRequestRedirected = std::make_shared<NapiCallbackRef>(env, onRequestRedirectedRef);
    }
    return onResultParse && onRequestRedirectedParse;
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
        context->errMsg = "Parameter error. The type of \"name\" must be string";
        return false;
    }
    if (!GetStringProperty(env, argv[index++], context->owner)) {
        context->errMsg = "Parameter error. The type of \"owner\" must be string";
        return false;
    }
    if ((argc == ARGS_SIZE_FOUR) && (!ParseVerifyCredentialOptions(env, argv[index++], context->options))) {
        context->errMsg = "Parameter error. The type of \"options\" must be VerifyCredentialOptions";
        return false;
    }
    if (!ParseJSAuthCallback(env, argv[index], context->callback)) {
        context->errMsg = "Parameter error. The type of \"callback\" must be AuthCallback";
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
        context->errMsg = "Parameter error. The number of parameters should be 2";
        return false;
    }
    int32_t index = 0;
    if (!GetStringProperty(env, argv[index++], context->owner)) {
        context->errMsg = "Parameter error. The type of \"owner\" must be string";
        return false;
    }
    if (argc == ARGS_SIZE_THREE) {
        if (!ParseSetPropertiesOptions(env, argv[index++], context->options)) {
            context->errMsg = "Parameter error. The type of \"options\" must be SetPropertiesOptions";
            return false;
        }
    }
    if (!ParseJSAuthCallback(env, argv[index], context->callback)) {
        context->errMsg = "Parameter error. The type of \"callback\" must be AuthCallback";
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
        context->errMsg = "Parameter error. The number of parameters should be 1";
        return false;
    }
    napi_ref callbackRef = nullptr;
    if ((argc == ARGS_SIZE_TWO) && (!GetCallbackProperty(env, argv[PARAMONE], callbackRef, 1))) {
        context->errMsg = "Parameter error. The type of \"callback\" must be AuthCallback";
        return false;
    }
    if (callbackRef != nullptr) {
        context->callbackRef = std::make_shared<NapiCallbackRef>(env, callbackRef);
    }
    if (!ParseSelectAccountsOptions(env, argv[0], context->options)) {
        context->errMsg = "Parameter error. The type of \"options\" must be SelectAccountsOptions";
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
        context->errMsg = "Parameter error. The number of parameters should be 3";
        return false;
    }
    napi_ref callbackRef = nullptr;
    if ((argc == ARGS_SIZE_FOUR) && (!GetCallbackProperty(env, argv[PARAMTHREE], callbackRef, 1))) {
        context->errMsg = "Parameter error. The type of \"callback\" must be AuthCallback";
        return false;
    }
    if (callbackRef != nullptr) {
        context->callbackRef = std::make_shared<NapiCallbackRef>(env, callbackRef);
    }
    if (!GetStringProperty(env, argv[0], context->name)) {
        context->errMsg = "Parameter error. The type of \"name\" must be string";
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMONE], context->owner)) {
        context->errMsg = "Parameter error. The type of \"owner\" must be string";
        return false;
    }
    if (!ParseStringVector(env, argv[PARAMTWO], context->labels)) {
        context->errMsg = "Parameter error. The type of \"labels\" must be string vector";
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
    delete context;
}

void ProcessOnResultCallback(
    napi_env env, JSAuthCallback &callback, int32_t resultCode, const AAFwk::WantParams &result)
{
    napi_value results[ARGS_SIZE_TWO] = {nullptr};
    napi_create_int32(env, resultCode, &results[0]);
    results[ARGS_SIZE_ONE] = AppExecFwk::WrapWantParams(env, result);
    NapiCallVoidFunction(env, results, ARGS_SIZE_TWO, callback.onResult->callbackRef);
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
    if ((valueType == napi_undefined) || (valueType == napi_null)) {
        ACCOUNT_LOGI("the customData of CreateAccountOptions is undefined or null");
        return true;
    }
    if (valueType != napi_object) {
        ACCOUNT_LOGE("customData type is not object");
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
    if ((valueType == napi_undefined) || (valueType == napi_null)) {
        ACCOUNT_LOGI("the CreateAccountImplicitlyOptions is undefined or null");
        return true;
    }
    if (valueType != napi_object) {
        return false;
    }
    napi_value value = nullptr;
    napi_has_named_property(env, object, "requiredLabels", &options.hasRequiredLabels);
    if (options.hasRequiredLabels) {
        napi_get_named_property(env, object, "requiredLabels", &value);
        valueType = napi_undefined;
        napi_typeof(env, value, &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            options.hasRequiredLabels = false;
            ACCOUNT_LOGI("the requiredLabels is undefined or null");
        } else {
            if (!ParseStringVector(env, value, options.requiredLabels)) {
                return false;
            }
        }
    }
    if (!GetOptionalStringPropertyByKey(env, object, "authType", options.authType)) {
        ACCOUNT_LOGE("failed to get options's authType property");
        return false;
    }
    bool hasParam = false;
    napi_has_named_property(env, object, "parameters", &hasParam);
    AAFwk::WantParams params;
    if (hasParam) {
        napi_get_named_property(env, object, "parameters", &value);
        valueType = napi_undefined;
        napi_typeof(env, value, &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("the authType is undefined or null");
        } else {
            if (!AppExecFwk::UnwrapWantParams(env, value, params)) {
                return false;
            }
        }
    }
    options.parameters.SetParams(params);
    return true;
}

bool ParseContextForCreateAccount(napi_env env, napi_callback_info cbInfo, CreateAccountContext *context)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_valuetype valueType = napi_undefined;
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc < ARGS_SIZE_ONE) {
        context->errMsg = "Parameter error. The number of parameters should be at least 1";
        return false;
    }
    if (!GetStringProperty(env, argv[0], context->name)) {
        ACCOUNT_LOGE("the name is not a string");
        context->errMsg = "Parameter error. The type of \"name\" must be string";
        return false;
    }
    if (argc > PARAMTWO) {
        if (!GetCallbackProperty(env, argv[PARAMTWO], context->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            return false;
        }
    }
    if (argc > ARGS_SIZE_ONE) {
        napi_typeof(env, argv[1], &valueType);
        if (valueType == napi_object) {
            if (!ParseCreateAccountOptions(env, argv[1], context->options)) {
                ACCOUNT_LOGE("the type of param 1 is incorrect");
                context->errMsg = "Parameter error. The type of \"options\" must be CreateAccountOptions";
                return false;
            }
        } else if (valueType == napi_function) {
            if (!GetCallbackProperty(env, argv[1], context->callbackRef, 1)) {
                ACCOUNT_LOGE("Get callbackRef failed");
                context->errMsg = "Parameter error. The type of \"callback\" must be napi_function";
                return false;
            }
            return true;
        } else if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("the param'1 is undefined or null");
            return true;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            context->errMsg = "Parameter error. The type of param 2 is incorrect";
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
        context->errMsg = "Parameter error. The number of parameters should be at least 2";
        return false;
    }
    if (!GetStringProperty(env, argv[0], context->owner)) {
        context->errMsg = "Parameter error. The type of \"owner\" must be string";
        return false;
    }
    if (argc == ARGS_SIZE_THREE) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[1], &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("the authType is undefined or null");
        } else {
            if (!ParseCreateAccountImplicitlyOptions(env, argv[1], context->options)) {
                context->errMsg = "Parameter error. The type of \"options\" must be CreateAccountImplicitlyOptions";
                return false;
            }
        }
    }
    if (!ParseJSAuthCallback(env, argv[argc - 1], context->callback)) {
        context->errMsg = "Parameter error. The type of \"callback\" must be AuthCallback";
        return false;
    }
    return true;
}
}  // namespace AccountJsKit
}  // namespace OHOS

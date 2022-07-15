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

#include "napi_app_account.h"

#include <string>
#include <cstring>
#include <vector>
#include "account_log_wrapper.h"
#include "app_account_common.h"
#include "app_account_manager.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_app_account_common.h"

using namespace OHOS::AccountSA;
namespace OHOS {
namespace AccountJsKit {
napi_value NapiAppAccount::Init(napi_env env, napi_value exports)
{
    ACCOUNT_LOGD("enter");
    napi_property_descriptor descriptor[] = {
        DECLARE_NAPI_FUNCTION("createAppAccountManager", CreateAppAccountManager),
    };
    NAPI_CALL(
        env, napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor));

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("addAccount", AddAccount),
        DECLARE_NAPI_FUNCTION("addAccountImplicitly", AddAccountImplicitly),
        DECLARE_NAPI_FUNCTION("deleteAccount", DeleteAccount),
        DECLARE_NAPI_FUNCTION("disableAppAccess", DisableAppAccess),
        DECLARE_NAPI_FUNCTION("enableAppAccess", EnableAppAccess),
        DECLARE_NAPI_FUNCTION("checkAppAccountSyncEnable", CheckAppAccountSyncEnable),
        DECLARE_NAPI_FUNCTION("setAccountCredential", SetAccountCredential),
        DECLARE_NAPI_FUNCTION("setAccountExtraInfo", SetAccountExtraInfo),
        DECLARE_NAPI_FUNCTION("setAppAccountSyncEnable", SetAppAccountSyncEnable),
        DECLARE_NAPI_FUNCTION("setAssociatedData", SetAssociatedData),
        DECLARE_NAPI_FUNCTION("authenticate", Authenticate),
        DECLARE_NAPI_FUNCTION("getAllAccessibleAccounts", GetAllAccessibleAccounts),
        DECLARE_NAPI_FUNCTION("getAllAccounts", GetAllAccounts),
        DECLARE_NAPI_FUNCTION("getAccountCredential", GetAccountCredential),
        DECLARE_NAPI_FUNCTION("getAccountExtraInfo", GetAccountExtraInfo),
        DECLARE_NAPI_FUNCTION("getAssociatedData", GetAssociatedData),
        DECLARE_NAPI_FUNCTION("getAssociatedDataSync", GetAssociatedDataSync),
        DECLARE_NAPI_FUNCTION("getOAuthToken", GetOAuthToken),
        DECLARE_NAPI_FUNCTION("setOAuthToken", SetOAuthToken),
        DECLARE_NAPI_FUNCTION("deleteOAuthToken", DeleteOAuthToken),
        DECLARE_NAPI_FUNCTION("getAuthenticatorInfo", GetAuthenticatorInfo),
        DECLARE_NAPI_FUNCTION("getAllOAuthTokens", GetAllOAuthTokens),
        DECLARE_NAPI_FUNCTION("getOAuthList", GetOAuthList),
        DECLARE_NAPI_FUNCTION("setOAuthTokenVisibility", SetOAuthTokenVisibility),
        DECLARE_NAPI_FUNCTION("checkOAuthTokenVisibility", CheckOAuthTokenVisibility),
        DECLARE_NAPI_FUNCTION("getAuthenticatorCallback", GetAuthenticatorCallback),
        DECLARE_NAPI_FUNCTION("on", Subscribe),
        DECLARE_NAPI_FUNCTION("off", Unsubscribe),
        DECLARE_NAPI_FUNCTION("checkAppAccess", CheckAppAccess),
        DECLARE_NAPI_FUNCTION("checkAccountLabels", CheckAccountLabels),
        DECLARE_NAPI_FUNCTION("setAuthenticatorProperties", SetAuthenticatorProperties),
        DECLARE_NAPI_FUNCTION("verifyCredential", VerifyCredential),
        DECLARE_NAPI_FUNCTION("selectAccountsByOptions", SelectAccountsByOptions),
        DECLARE_NAPI_FUNCTION("deleteAccountCredential", DeleteAccountCredential),
    };
    napi_value cons = nullptr;
    NAPI_CALL(env, napi_define_class(env, APP_ACCOUNT_CLASS_NAME.c_str(), APP_ACCOUNT_CLASS_NAME.size(),
        JsConstructor, nullptr, sizeof(properties) / sizeof(napi_property_descriptor), properties, &cons));
    NAPI_CALL(env, napi_create_reference(env, cons, 1, &appAccountRef_));
    NAPI_CALL(env, napi_set_named_property(env, exports, APP_ACCOUNT_CLASS_NAME.c_str(), cons));
    return exports;
}

napi_value NapiAppAccount::JsConstructor(napi_env env, napi_callback_info cbinfo)
{
    ACCOUNT_LOGD("enter");
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, nullptr));

    AppAccountManager *objectInfo = new (std::nothrow) AppAccountManager();
    if (objectInfo == nullptr) {
        ACCOUNT_LOGE("objectInfo == nullptr");
        return NapiGetNull(env);
    }
    napi_wrap(env, thisVar, objectInfo, [](napi_env env, void *data, void *hint) {
        AppAccountManager *objInfo = (AppAccountManager *)data;
        delete objInfo;
    }, nullptr, nullptr);

    return thisVar;
}

napi_value NapiAppAccount::CreateAppAccountManager(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    napi_value instance = nullptr;
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, appAccountRef_, &cons) != napi_ok) {
        return nullptr;
    }
    ACCOUNT_LOGI("Get a reference to the global variable appAccountRef_ complete");
    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        return nullptr;
    }
    ACCOUNT_LOGI("New the js instance complete");
    return instance;
}

napi_value NapiAppAccount::AddAccount(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *asyncContext = new (std::nothrow) AppAccountAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithExInfo(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "AddAccount", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ErrCode errCode = AppAccountManager::AddAccount(asyncContext->name, asyncContext->extraInfo);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
            ACCOUNT_LOGD("AddAccount errcode parameter is %{public}d", asyncContext->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value addResult[RESULT_COUNT] = {0};
            addResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_get_undefined(env, &addResult[PARAMONE]);
            ProcessCallbackOrPromise(env, asyncContext, addResult[PARAMZERO], addResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::AddAccountImplicitly(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("start");
    auto *asyncContext = new (std::nothrow) OAuthAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    ParseContextForAuthenticate(env, cbInfo, asyncContext, ARGS_SIZE_FOUR);
    if (asyncContext->appAccountMgrCb == nullptr) {
        ACCOUNT_LOGE("insufficient memory for AppAccountManagerCallback!");
        return NapiGetNull(env);
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "AddAccountImplicitly", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                ErrCode errCode = AppAccountManager::AddAccountImplicitly(asyncContext->owner,
                    asyncContext->authType, asyncContext->options, asyncContext->appAccountMgrCb);
                asyncContext->errCode = ConvertToJSErrCode(errCode);
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                AAFwk::Want errResult;
                if ((asyncContext->errCode != 0) && (asyncContext->appAccountMgrCb != nullptr)) {
                    asyncContext->appAccountMgrCb->OnResult(asyncContext->errCode, errResult);
                }
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            reinterpret_cast<void *>(asyncContext),
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return NapiGetNull(env);
}

napi_value NapiAppAccount::DeleteAccount(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *asyncContext = new (std::nothrow) AppAccountAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithTwoPara(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "DeleteAccount", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ErrCode errCode = AppAccountManager::DeleteAccount(asyncContext->name);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
            ACCOUNT_LOGD("DeleteAccount errcode parameter is %{public}d", asyncContext->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value delResult[RESULT_COUNT] = {0};
            delResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_get_undefined(env, &delResult[PARAMONE]);
            ProcessCallbackOrPromise(env, asyncContext, delResult[PARAMZERO], delResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::DisableAppAccess(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *asyncContext = new (std::nothrow) AppAccountAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithBdName(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "DisableAppAccess", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ErrCode errCode = AppAccountManager::DisableAppAccess(asyncContext->name, asyncContext->bundleName);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
            ACCOUNT_LOGD("DisableAppAccess errcode parameter is %{public}d", asyncContext->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value disResult[RESULT_COUNT] = {0};
            disResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_get_undefined(env, &disResult[PARAMONE]);
            ProcessCallbackOrPromise(env, asyncContext, disResult[PARAMZERO], disResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::EnableAppAccess(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *asyncContext = new (std::nothrow) AppAccountAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithBdName(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "EnableAppAccess", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ErrCode errCode = AppAccountManager::EnableAppAccess(asyncContext->name, asyncContext->bundleName);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
            ACCOUNT_LOGD("EnableAppAccess errcode parameter is %{public}d", asyncContext->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value enResult[RESULT_COUNT] = {0};
            enResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_get_undefined(env, &enResult[PARAMONE]);
            ProcessCallbackOrPromise(env, asyncContext, enResult[PARAMZERO], enResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::CheckAppAccountSyncEnable(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *asyncContext = new (std::nothrow) AppAccountAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithTwoPara(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "CheckAppAccountSyncEnable", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ErrCode errCode =
                AppAccountManager::CheckAppAccountSyncEnable(asyncContext->name, asyncContext->result);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
            ACCOUNT_LOGD("CheckAppAccountSyncEnable errcode parameter is %{public}d", asyncContext->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value checkResult[RESULT_COUNT] = {0};
            checkResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_get_boolean(env, asyncContext->result, &checkResult[PARAMONE]);
            ProcessCallbackOrPromise(env, asyncContext, checkResult[PARAMZERO], checkResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::SetAccountCredential(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *asyncContext = new (std::nothrow) AppAccountAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextToSetCredential(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "SetAccountCredential", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ErrCode errCode = AppAccountManager::SetAccountCredential(
                asyncContext->name, asyncContext->credentialType, asyncContext->credential);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
            ACCOUNT_LOGD("SetAccountCredential errcode parameter is %{public}d", asyncContext->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value setResult[RESULT_COUNT] = {0};
            setResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_get_undefined(env, &setResult[PARAMONE]);
            ProcessCallbackOrPromise(env, asyncContext, setResult[PARAMZERO], setResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::SetAccountExtraInfo(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *asyncContext = new (std::nothrow) AppAccountAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextForSetExInfo(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        ACCOUNT_LOGD("Create promise");
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        ACCOUNT_LOGD("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "SetAccountExtraInfo", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            ACCOUNT_LOGD("SetAccountExtraInfo, napi_create_async_work running.");
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ErrCode errCode = AppAccountManager::SetAccountExtraInfo(
                asyncContext->name, asyncContext->extraInfo);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
            ACCOUNT_LOGD("SetAccountExtraInfo errcode parameter is %{public}d", asyncContext->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value setResult[RESULT_COUNT] = {0};
            setResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_get_undefined(env, &setResult[PARAMONE]);
            ProcessCallbackOrPromise(env, asyncContext, setResult[PARAMZERO], setResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::SetAppAccountSyncEnable(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *asyncContext = new (std::nothrow) AppAccountAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithIsEnable(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "SetAppAccountSyncEnable", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ErrCode errCode =
                AppAccountManager::SetAppAccountSyncEnable(asyncContext->name, asyncContext->isEnable);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
            ACCOUNT_LOGD("SetAppAccountSyncEnable errcode parameter is %{public}d", asyncContext->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value setResult[RESULT_COUNT] = {0};
            setResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_get_undefined(env, &setResult[PARAMONE]);
            ProcessCallbackOrPromise(env, asyncContext, setResult[PARAMZERO], setResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::SetAssociatedData(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *asyncContext = new (std::nothrow) AppAccountAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextForAssociatedData(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "SetAssociatedData", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ErrCode errCode =
                AppAccountManager::SetAssociatedData(asyncContext->name, asyncContext->key, asyncContext->value);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
            ACCOUNT_LOGD("SetAssociatedData errcode parameter is %{public}d", asyncContext->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value setResult[RESULT_COUNT] = {0};
            setResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_get_undefined(env, &setResult[PARAMONE]);
            ProcessCallbackOrPromise(env, asyncContext, setResult[PARAMZERO], setResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::GetAllAccessibleAccounts(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *asyncContext = new (std::nothrow) GetAccountsAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextCBArray(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetAllAccessibleAccounts", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            GetAccountsAsyncContext *asyncContext = reinterpret_cast<GetAccountsAsyncContext *>(data);
            ErrCode errCode = AppAccountManager::GetAllAccessibleAccounts(asyncContext->appAccounts);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
            ACCOUNT_LOGD("GetAllAccessibleAccounts errcode parameter is %{public}d", asyncContext->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            GetAccountsAsyncContext *asyncContext = reinterpret_cast<GetAccountsAsyncContext *>(data);
            napi_value getResult[RESULT_COUNT] = {0};
            getResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_create_array(env, &getResult[PARAMONE]);
            GetAppAccountInfoForResult(env, asyncContext->appAccounts, getResult[PARAMONE]);
            ProcessCallbackOrPromiseCBArray(env, asyncContext, getResult[PARAMZERO], getResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::GetAllAccounts(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *asyncContext = new (std::nothrow) GetAccountsAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithStrCBArray(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetAllAccounts", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            GetAccountsAsyncContext *asyncContext = reinterpret_cast<GetAccountsAsyncContext *>(data);
            ErrCode errCode = AppAccountManager::GetAllAccounts(asyncContext->owner, asyncContext->appAccounts);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
            ACCOUNT_LOGD("GetAllAccounts errcode parameter is %{public}d", asyncContext->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            GetAccountsAsyncContext *asyncContext = reinterpret_cast<GetAccountsAsyncContext *>(data);
            napi_value getResult[RESULT_COUNT] = {0};
            getResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_create_array(env, &getResult[PARAMONE]);
            GetAppAccountInfoForResult(env, asyncContext->appAccounts, getResult[PARAMONE]);
            ProcessCallbackOrPromiseCBArray(env, asyncContext, getResult[PARAMZERO], getResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::GetAccountCredential(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *asyncContext = new (std::nothrow) AppAccountAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithCredentialType(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetAccountCredential", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ErrCode errCode = AppAccountManager::GetAccountCredential(
                asyncContext->name, asyncContext->credentialType, asyncContext->credential);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
            ACCOUNT_LOGD("GetAccountCredential errcode parameter is %{public}d", asyncContext->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value getResult[RESULT_COUNT] = {0};
            getResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_create_string_utf8(env, asyncContext->credential.c_str(), NAPI_AUTO_LENGTH, &getResult[PARAMONE]);
            ProcessCallbackOrPromise(env, asyncContext, getResult[PARAMZERO], getResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::GetAccountExtraInfo(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *asyncContext = new (std::nothrow) AppAccountAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithTwoPara(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetAccountExtraInfo", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ErrCode errCode = AppAccountManager::GetAccountExtraInfo(asyncContext->name, asyncContext->extraInfo);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
            ACCOUNT_LOGD("GetAccountExtraInfo errcode parameter is %{public}d", asyncContext->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value getResult[RESULT_COUNT] = {0};
            getResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_create_string_utf8(env, asyncContext->extraInfo.c_str(), NAPI_AUTO_LENGTH, &getResult[PARAMONE]);
            ProcessCallbackOrPromise(env, asyncContext, getResult[PARAMZERO], getResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::GetAssociatedData(napi_env env, napi_callback_info cbInfo)
{
    auto *asyncContext = new (std::nothrow) AppAccountAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextToGetData(env, cbInfo, asyncContext);
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetAssociatedData", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ErrCode errCode =
                AppAccountManager::GetAssociatedData(asyncContext->name, asyncContext->key, asyncContext->value);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
            ACCOUNT_LOGD("GetAssociatedData errcode parameter is %{public}d", asyncContext->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value getResult[RESULT_COUNT] = {0};
            getResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_create_string_utf8(env, asyncContext->value.c_str(), NAPI_AUTO_LENGTH, &getResult[PARAMONE]);
            ProcessCallbackOrPromise(env, asyncContext, getResult[PARAMZERO], getResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::GetAssociatedDataSync(napi_env env, napi_callback_info cbInfo)
{
    AppAccountAsyncContext asyncContext;
    ParseContextToGetData(env, cbInfo, &asyncContext);
    napi_value result = nullptr;
    ErrCode errCode = AppAccountManager::GetAssociatedData(asyncContext.name, asyncContext.key, asyncContext.value);
    if (errCode == ERR_OK) {
        NAPI_CALL(env, napi_create_string_utf8(env, asyncContext.value.c_str(), NAPI_AUTO_LENGTH, &result));
    }
    return result;
}

napi_value NapiAppAccount::Authenticate(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("start");
    auto *asyncContext = new (std::nothrow) OAuthAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    ParseContextForAuthenticate(env, cbInfo, asyncContext, ARGS_SIZE_FIVE);
    napi_value result = nullptr;
    if (asyncContext->appAccountMgrCb == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "Authenticate", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                auto asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                ErrCode errCode = AppAccountManager::Authenticate(asyncContext->name, asyncContext->owner,
                    asyncContext->authType, asyncContext->options, asyncContext->appAccountMgrCb);
                asyncContext->errCode = ConvertToJSErrCode(errCode);
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                AAFwk::Want errResult;
                if ((asyncContext->errCode != 0) && (asyncContext->appAccountMgrCb != nullptr)) {
                    asyncContext->appAccountMgrCb->OnResult(asyncContext->errCode, errResult);
                }
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            reinterpret_cast<void *>(asyncContext),
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return NapiGetNull(env);
}

napi_value NapiAppAccount::GetOAuthToken(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *asyncContext = new (std::nothrow) OAuthAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextForGetOAuthToken(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetOAuthToken", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            auto asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
            ErrCode errCode = AppAccountManager::GetOAuthToken(
                asyncContext->name, asyncContext->owner, asyncContext->authType, asyncContext->token);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
            napi_value getResult[RESULT_COUNT] = {0};
            getResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_create_string_utf8(env, asyncContext->token.c_str(), NAPI_AUTO_LENGTH, &getResult[PARAMONE]);
            ProcessCallbackOrPromise(env, asyncContext, getResult[PARAMZERO], getResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::SetOAuthToken(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *asyncContext = new (std::nothrow) OAuthAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextForSetOAuthToken(env, cbInfo, asyncContext);
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "SetOAuthToken", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
            ErrCode errCode = AppAccountManager::SetOAuthToken(
                asyncContext->name, asyncContext->authType, asyncContext->token);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
            napi_value setResult[RESULT_COUNT] = {0};
            setResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
            napi_get_undefined(env, &setResult[PARAMONE]);
            ProcessCallbackOrPromise(env, asyncContext, setResult[PARAMZERO], setResult[PARAMONE]);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        },
        reinterpret_cast<void *>(asyncContext),
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

napi_value NapiAppAccount::DeleteOAuthToken(napi_env env, napi_callback_info cbInfo)
{
    auto *asyncContext = new (std::nothrow) OAuthAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextForDeleteOAuthToken(env, cbInfo, asyncContext);
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "DeleteOAuthToken", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                ErrCode errCode = AppAccountManager::DeleteOAuthToken(
                    asyncContext->name, asyncContext->owner, asyncContext->authType, asyncContext->token);
                asyncContext->errCode = ConvertToJSErrCode(errCode);
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                napi_value delResult[RESULT_COUNT] = {0};
                delResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_get_undefined(env, &delResult[PARAMONE]);
                ProcessCallbackOrPromise(env, asyncContext, delResult[PARAMZERO], delResult[PARAMONE]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            reinterpret_cast<void *>(asyncContext),
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::SetOAuthTokenVisibility(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter.");
    auto *asyncContext = new (std::nothrow) OAuthAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextForSetOAuthTokenVisibility(env, cbInfo, asyncContext);
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetOAuthTokenVisibility", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                ErrCode errCode = AppAccountManager::SetOAuthTokenVisibility(
                    asyncContext->name, asyncContext->authType, asyncContext->bundleName, asyncContext->isVisible);
                asyncContext->errCode = ConvertToJSErrCode(errCode);
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                napi_value setResult[RESULT_COUNT] = {0};
                setResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_get_boolean(env, asyncContext->isVisible, &setResult[PARAMONE]);
                ProcessCallbackOrPromise(env, asyncContext, setResult[PARAMZERO], setResult[PARAMONE]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            reinterpret_cast<void *>(asyncContext),
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::CheckOAuthTokenVisibility(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter.");
    auto *asyncContext = new (std::nothrow) OAuthAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextForCheckOAuthTokenVisibility(env, cbInfo, asyncContext);
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "CheckOAuthTokenVisibility", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                ErrCode errCode = AppAccountManager::CheckOAuthTokenVisibility(
                    asyncContext->name, asyncContext->authType, asyncContext->bundleName, asyncContext->isVisible);
                asyncContext->errCode = ConvertToJSErrCode(errCode);
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                napi_value checkResult[RESULT_COUNT] = {0};
                checkResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_get_boolean(env, asyncContext->isVisible, &checkResult[PARAMONE]);
                ProcessCallbackOrPromise(env, asyncContext, checkResult[PARAMZERO], checkResult[PARAMONE]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            reinterpret_cast<void *>(asyncContext),
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::GetAuthenticatorInfo(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter.");
    auto *asyncContext = new (std::nothrow) OAuthAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextForGetAuthenticatorInfo(env, cbInfo, asyncContext);
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetAuthenticatorInfo", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                ErrCode errCode = AppAccountManager::GetAuthenticatorInfo(
                    asyncContext->owner, asyncContext->authenticatorInfo);
                asyncContext->errCode = ConvertToJSErrCode(errCode);
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                napi_value getResult[RESULT_COUNT] = {0};
                getResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_create_object(env, &getResult[PARAMONE]);
                GetAuthenticatorInfoForResult(env, asyncContext->authenticatorInfo, getResult[PARAMONE]);
                ProcessCallbackOrPromise(env, asyncContext, getResult[PARAMZERO], getResult[PARAMONE]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            reinterpret_cast<void *>(asyncContext),
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::GetAllOAuthTokens(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter.");
    auto *asyncContext = new (std::nothrow) OAuthAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextForGetAllOAuthTokens(env, cbInfo, asyncContext);
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetAllOAuthTokens", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                ErrCode errCode = AppAccountManager::GetAllOAuthTokens(
                    asyncContext->name, asyncContext->owner, asyncContext->oauthTokenInfos);
                asyncContext->errCode = ConvertToJSErrCode(errCode);
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                napi_value getResult[RESULT_COUNT] = {0};
                getResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_create_array(env, &getResult[PARAMONE]);
                GetOAuthTokenInfoForResult(env, asyncContext->oauthTokenInfos, getResult[PARAMONE]);
                ProcessCallbackOrPromise(env, asyncContext, getResult[PARAMZERO], getResult[PARAMONE]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            reinterpret_cast<void *>(asyncContext),
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::GetOAuthList(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter.");
    auto *asyncContext = new (std::nothrow) OAuthAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextForGetOAuthList(env, cbInfo, asyncContext);
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetOAuthList", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                ErrCode errCode = AppAccountManager::GetOAuthList(
                    asyncContext->name, asyncContext->authType, asyncContext->authList);
                asyncContext->errCode = ConvertToJSErrCode(errCode);
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                napi_value getResult[RESULT_COUNT] = {0};
                getResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_create_array(env, &getResult[PARAMONE]);
                GetOAuthListForResult(env, asyncContext->authList, getResult[PARAMONE]);
                ProcessCallbackOrPromise(env, asyncContext, getResult[PARAMZERO], getResult[PARAMONE]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            reinterpret_cast<void *>(asyncContext),
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::GetAuthenticatorCallback(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter.");
    auto *asyncContext = new (std::nothrow) OAuthAsyncContext();
    if (asyncContext == nullptr) {
        ACCOUNT_LOGE("insufficient memory for asyncContext!");
        return NapiGetNull(env);
    }
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextForGetAuthenticatorCallback(env, cbInfo, asyncContext);
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetAuthenticatorCallback", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                ErrCode errCode = AppAccountManager::GetAuthenticatorCallback(
                    asyncContext->sessionId, asyncContext->authenticatorCb);
                asyncContext->errCode = ConvertToJSErrCode(errCode);
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                napi_value getResult[RESULT_COUNT] = {0};
                getResult[PARAMZERO] = GetErrorCodeValue(env, asyncContext->errCode);
                GetAuthenticatorCallbackForResult(env, asyncContext->authenticatorCb, &getResult[PARAMONE]);
                ProcessCallbackOrPromise(env, asyncContext, getResult[PARAMZERO], getResult[PARAMONE]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            reinterpret_cast<void *>(asyncContext),
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::CheckAppAccess(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *context = new (std::nothrow) AppAccountAsyncContext();
    if (context == nullptr) {
        ACCOUNT_LOGE("insufficient memory for context!");
        return NapiGetNull(env);
    }
    context->env = env;
    ParseContextWithBdName(env, cbInfo, context);
    napi_value result = nullptr;
    if (context->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "CheckAppAccess", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            auto context = reinterpret_cast<AppAccountAsyncContext *>(data);
            context->errCode = AppAccountManager::CheckAppAccess(
                context->name, context->bundleName, context->isAccessible);
            context->errCode = ConvertToJSErrCode(context->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            auto context = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value checkResult[RESULT_COUNT] = {0};
            if (context->errCode != ERR_JS_SUCCESS) {
                checkResult[PARAMZERO] = GetErrorCodeValue(env, context->errCode);
            } else {
                napi_get_boolean(env, context->isAccessible, &checkResult[PARAMONE]);
            }
            ProcessCallbackOrPromise(env, context, checkResult[PARAMZERO], checkResult[PARAMONE]);
            napi_delete_async_work(env, context->work);
            delete context;
            context = nullptr;
        },
        reinterpret_cast<void *>(context),
        &context->work));
    NAPI_CALL(env, napi_queue_async_work(env, context->work));
    return result;
}

napi_value NapiAppAccount::DeleteAccountCredential(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *context = new (std::nothrow) AppAccountAsyncContext();
    if (context == nullptr) {
        ACCOUNT_LOGE("insufficient memory for context!");
        return NapiGetNull(env);
    }
    context->env = env;
    ParseContextWithCredentialType(env, cbInfo, context);
    napi_value result = nullptr;
    if (context->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "DeleteAccountCredential", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            auto context = reinterpret_cast<AppAccountAsyncContext *>(data);
            context->errCode = AppAccountManager::DeleteAccountCredential(
                context->name, context->credentialType);
            context->errCode = ConvertToJSErrCode(context->errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            auto context = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value deleteResult[RESULT_COUNT] = {0};
            if (context->errCode != ERR_JS_SUCCESS) {
                deleteResult[PARAMZERO] = GetErrorCodeValue(env, context->errCode);
            }
            napi_get_undefined(env, &deleteResult[PARAMONE]);
            ProcessCallbackOrPromise(env, context, deleteResult[PARAMZERO], deleteResult[PARAMONE]);
            napi_delete_async_work(env, context->work);
            delete context;
            context = nullptr;
        },
        reinterpret_cast<void *>(context),
        &context->work));
    NAPI_CALL(env, napi_queue_async_work(env, context->work));
    return result;
}

napi_value NapiAppAccount::CheckAccountLabels(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto context = new (std::nothrow) CheckAccountLabelsContext();
    if (context == nullptr) {
        ACCOUNT_LOGE("insufficient memory for context!");
        return NapiGetNull(env);
    }
    context->env = env;
    ParseContextForCheckAccountLabels(env, cbInfo, context);
    napi_value result = nullptr;
    if (context->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "CheckAccountLabels", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            auto context = reinterpret_cast<CheckAccountLabelsContext *>(data);
            sptr<AuthenticatorAsyncCallback> callback = new (std::nothrow) AuthenticatorAsyncCallback(
                *context, CheckAccountLabelsOnResultWork);
            if (callback == nullptr) {
                ACCOUNT_LOGD("failed to create AuthenticatorAsyncCallback for insufficient memory");
                context->errCode = ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
                return;
            }
            context->errCode = AppAccountManager::CheckAccountLabels(
                context->name, context->owner, context->labels, callback);
        },
        [](napi_env env, napi_status status, void *data) {
            auto context = reinterpret_cast<CheckAccountLabelsContext *>(data);
            if (context->errCode != ERR_OK) {
                napi_value checkResult[RESULT_COUNT] = {0};
                checkResult[PARAMZERO] = GetErrorCodeValue(env, ConvertToJSErrCode(context->errCode));
                ProcessCallbackOrPromise(env, context, checkResult[PARAMZERO], checkResult[PARAMONE]);
            }
            napi_delete_async_work(env, context->work);
            delete context;
            context = nullptr;
        },
        reinterpret_cast<void *>(context), &context->work));
    NAPI_CALL(env, napi_queue_async_work(env, context->work));
    return result;
}

napi_value NapiAppAccount::SelectAccountsByOptions(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *context = new (std::nothrow) SelectAccountsContext();
    if (context == nullptr) {
        ACCOUNT_LOGE("insufficient memory for context!");
        return NapiGetNull(env);
    }
    context->env = env;
    ParseContextForSelectAccount(env, cbInfo, context);
    napi_value result = nullptr;
    if (context->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SelectAccountsByOptions", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            auto context = reinterpret_cast<SelectAccountsContext *>(data);
            sptr<AuthenticatorAsyncCallback> callback = new (std::nothrow) AuthenticatorAsyncCallback(
                *context, SelectAccountsOnResultWork);
            if (callback == nullptr) {
                ACCOUNT_LOGD("failed to create AuthenticatorAsyncCallback for insufficient memory");
                context->errCode = ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
                return;
            }
            context->errCode =
                AppAccountManager::SelectAccountsByOptions(context->options, callback);
        },
        [](napi_env env, napi_status status, void *data) {
            auto context = reinterpret_cast<SelectAccountsContext *>(data);
            if (context->errCode != ERR_OK) {
                napi_value selectResult[RESULT_COUNT] = {0};
                selectResult[PARAMZERO] = GetErrorCodeValue(env, ConvertToJSErrCode(context->errCode));
                ProcessCallbackOrPromise(env, context, selectResult[PARAMZERO], selectResult[PARAMONE]);
            }
            napi_delete_async_work(env, context->work);
            delete context;
            context = nullptr;
        },
        reinterpret_cast<void *>(context), &context->work));
    NAPI_CALL(env, napi_queue_async_work(env, context->work));
    return result;
}

napi_value NapiAppAccount::VerifyCredential(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *context = new (std::nothrow) VerifyCredentialContext();
    if (context == nullptr) {
        ACCOUNT_LOGE("insufficient memory for context!");
        return NapiGetNull(env);
    }
    context->env = env;
    ParseContextForVerifyCredential(env, cbInfo, context);
    context->appAccountMgrCb = new (std::nothrow) AppAccountManagerCallback(env, context->callback);
    if (context->appAccountMgrCb == nullptr) {
        ACCOUNT_LOGD("failed to create AppAccountManagerCallback for insufficient memory");
        AAFwk::WantParams result;
        ProcessOnResultCallback(env, context->callback, ERR_JS_APP_ACCOUNT_SERVICE_EXCEPTION, result);
        delete context;
        return NapiGetNull(env);
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "VerifyCredential", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            auto context = reinterpret_cast<VerifyCredentialContext *>(data);
            ErrCode errCode = AppAccountManager::VerifyCredential(
                context->name, context->owner, context->options, context->appAccountMgrCb);
            context->errCode = ConvertToJSErrCode(errCode);
        },
        VerifyCredCompleteCB, reinterpret_cast<void *>(context), &context->work));
    NAPI_CALL(env, napi_queue_async_work(env, context->work));
    return NapiGetNull(env);
}

napi_value NapiAppAccount::SetAuthenticatorProperties(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter");
    auto *context = new (std::nothrow) SetPropertiesContext();
    if (context == nullptr) {
        ACCOUNT_LOGE("insufficient memory for context!");
        return NapiGetNull(env);
    }
    context->env = env;
    ParseContextForSetProperties(env, cbInfo, context);
    context->appAccountMgrCb = new (std::nothrow) AppAccountManagerCallback(env, context->callback);
    if (context->appAccountMgrCb == nullptr) {
        ACCOUNT_LOGD("failed to create AppAccountManagerCallback for insufficient memory");
        AAFwk::WantParams result;
        ProcessOnResultCallback(env, context->callback, ERR_JS_APP_ACCOUNT_SERVICE_EXCEPTION, result);
        delete context;
        return NapiGetNull(env);
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetAuthenticatorProperties", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            auto context = reinterpret_cast<SetPropertiesContext *>(data);
            ErrCode errCode = AppAccountManager::SetAuthenticatorProperties(
                context->owner, context->options, context->appAccountMgrCb);
            context->errCode = ConvertToJSErrCode(errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            auto context = reinterpret_cast<SetPropertiesContext *>(data);
            if ((context->errCode != ERR_JS_SUCCESS) && (context->appAccountMgrCb != nullptr)) {
                AAFwk::Want errResult;
                context->appAccountMgrCb->OnResult(context->errCode, errResult);
            }
            napi_delete_async_work(env, context->work);
            delete context;
            context = nullptr;
        },
        reinterpret_cast<void *>(context),
        &context->work));
    NAPI_CALL(env, napi_queue_async_work(env, context->work));
    return NapiGetNull(env);
}

napi_value NapiAppAccount::Subscribe(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter.");

    size_t argc = SUBSCRIBE_MAX_PARA;
    napi_value argv[SUBSCRIBE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL));
    NAPI_ASSERT(env, argc >= SUBSCRIBE_MAX_PARA, "Wrong number of arguments");

    std::vector<std::string> owners;

    napi_ref callback = nullptr;

    if (ParseParametersBySubscribe(env, argv, owners, callback) == nullptr) {
        return NapiGetNull(env);
    }

    AsyncContextForSubscribe *asyncContextForOn = new (std::nothrow) AsyncContextForSubscribe();
    if (asyncContextForOn == nullptr) {
        ACCOUNT_LOGE("asyncContextForOn is null");
        return NapiGetNull(env);
    }
    asyncContextForOn->env = env;
    asyncContextForOn->work = nullptr;
    asyncContextForOn->callbackRef = nullptr;

    AppAccountSubscribeInfo subscribeInfo(owners);
    asyncContextForOn->subscriber = std::make_shared<SubscriberPtr>(subscribeInfo);
    if (asyncContextForOn->subscriber == nullptr) {
        ACCOUNT_LOGE("fail to create subscriber");
        delete asyncContextForOn;
        return NapiGetNull(env);
    }
    asyncContextForOn->subscriber->SetEnv(env);
    asyncContextForOn->subscriber->SetCallbackRef(callback);
    AppAccountManager *objectInfo = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&objectInfo));
    asyncContextForOn->appAccountManager = objectInfo;

    {
        std::lock_guard<std::mutex> lock(g_lockForAppAccountSubscribers);
        g_AppAccountSubscribers[objectInfo].emplace_back(asyncContextForOn);
    }

    AppAccountManager::SubscribeAppAccount(asyncContextForOn->subscriber);
    return NapiGetNull(env);
}

napi_value NapiAppAccount::Unsubscribe(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGD("enter.");

    // Argument parsing
    size_t argc = UNSUBSCRIBE_MAX_PARA;
    napi_value argv[UNSUBSCRIBE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    std::vector<std::shared_ptr<SubscriberPtr>> subscribers = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL));
    NAPI_ASSERT(env, argc >= 1, "Wrong number of arguments");

    napi_ref callback = nullptr;
    ParseParametersByUnsubscribe(env, argc, argv, callback);
    AsyncContextForUnsubscribe *asyncContextForOff = new (std::nothrow) AsyncContextForUnsubscribe();
    if (asyncContextForOff == nullptr) {
        ACCOUNT_LOGE("asyncContextForOff is null");
        return NapiGetNull(env);
    }
    asyncContextForOff->env = env;
    asyncContextForOff->work = nullptr;
    asyncContextForOff->callbackRef = nullptr;

    AppAccountManager *objectInfo = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&objectInfo));

    asyncContextForOff->appAccountManager = objectInfo;
    asyncContextForOff->callbackRef = callback;
    asyncContextForOff->argc = argc;
    bool isFind = false;
    napi_value result = GetSubscriberByUnsubscribe(env, subscribers, asyncContextForOff, isFind);
    if (!result) {
        ACCOUNT_LOGE("Unsubscribe failed. The current subscriber does not exist");
        return NapiGetNull(env);
    }
    asyncContextForOff->subscribers = subscribers;

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "Unsubscribe", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(env,
        nullptr,
        resourceName,
        UnsubscribeExecuteCB,
        UnsubscribeCallbackCompletedCB,
        reinterpret_cast<void *>(asyncContextForOff),
        &asyncContextForOff->work);
    napi_queue_async_work(env, asyncContextForOff->work);
    return NapiGetNull(env);
}
}  // namespace AccountJsKit
}  // namespace OHOS

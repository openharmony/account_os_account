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

#include <string>
#include <cstring>
#include <vector>
#include "app_account_manager.h"
#include "napi_app_account_common.h"
#include "account_log_wrapper.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_app_account.h"

using namespace OHOS::AccountSA;
namespace OHOS {
namespace AccountJsKit {
napi_ref NapiAppAccount::constructorRef_;

napi_value NapiAppAccount::Init(napi_env env, napi_value exports)
{
    ACCOUNT_LOGI("Enter appaccount init function.");
    napi_property_descriptor descriptor[] = {
        DECLARE_NAPI_FUNCTION("createAppAccountManager", CreateAppAccountManager),
    };
    NAPI_CALL(
        env, napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor));

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("addAccount", AddAccount),
        DECLARE_NAPI_FUNCTION("deleteAccount", DeleteAccount),
        DECLARE_NAPI_FUNCTION("disableAppAccess", DisableAppAccess),
        DECLARE_NAPI_FUNCTION("enableAppAccess", EnableAppAccess),
        DECLARE_NAPI_FUNCTION("checkAppAccountSyncEnable", CheckAppAccountSyncEnable),
        DECLARE_NAPI_FUNCTION("setAccountCredential", SetAccountCredential),
        DECLARE_NAPI_FUNCTION("setAccountExtraInfo", SetAccountExtraInfo),
        DECLARE_NAPI_FUNCTION("setAppAccountSyncEnable", SetAppAccountSyncEnable),
        DECLARE_NAPI_FUNCTION("setAssociatedData", SetAssociatedData),
        DECLARE_NAPI_FUNCTION("getAllAccessibleAccounts", GetAllAccessibleAccounts),
        DECLARE_NAPI_FUNCTION("getAllAccounts", GetAllAccounts),
        DECLARE_NAPI_FUNCTION("getAccountCredential", GetAccountCredential),
        DECLARE_NAPI_FUNCTION("getAccountExtraInfo", GetAccountExtraInfo),
        DECLARE_NAPI_FUNCTION("getAssociatedData", GetAssociatedData),
        DECLARE_NAPI_FUNCTION("on", Subscribe),
        DECLARE_NAPI_FUNCTION("off", Unsubscribe),
    };
    napi_value cons = nullptr;
    NAPI_CALL(env,
        napi_define_class(env,
            APP_ACCOUNT_CLASS_NAME.c_str(),
            APP_ACCOUNT_CLASS_NAME.size(),
            JsConstructor,
            nullptr,
            sizeof(properties) / sizeof(napi_property_descriptor),
            properties,
            &cons));
    NAPI_CALL(env, napi_create_reference(env, cons, 1, &constructorRef_));
    NAPI_CALL(env, napi_set_named_property(env, exports, APP_ACCOUNT_CLASS_NAME.c_str(), cons));

    return exports;
}

napi_value NapiAppAccount::JsConstructor(napi_env env, napi_callback_info cbinfo)
{
    ACCOUNT_LOGI("Enter JsConstructor function");
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

napi_value NapiAppAccount::CreateAppAccountManager(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Enter CreateAppAccountManager function to new js instance");
    napi_value instance = nullptr;
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, constructorRef_, &cons) != napi_ok) {
        return nullptr;
    }
    ACCOUNT_LOGI("Get a reference to the global variable constructorRef_ complete");
    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        return nullptr;
    }
    ACCOUNT_LOGI("New the js instance complete");
    return instance;
}

napi_value NapiAppAccount::AddAccount(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Enter N-API AddAccount function.");
    auto *asyncContext = new AppAccountAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithExInfo(env, cbInfo, asyncContext);
    ACCOUNT_LOGI("Parsing completed, name = %{public}s, extraInfo = %{public}s",
        asyncContext->name.c_str(),
        asyncContext->extraInfo.c_str());

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "AddAccount", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("AddAccount, napi_create_async_work running.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                asyncContext->errCode = AppAccountManager::AddAccount(asyncContext->name, asyncContext->extraInfo);
                ACCOUNT_LOGI("Addcount errcode parameter is %{public}d", asyncContext->errCode);
                asyncContext->status = asyncContext->errCode == 0 ? napi_ok : napi_generic_failure;
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("AddAccount, napi_create_async_work complete.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                napi_value addResult[RESULT_COUNT] = {0};
                addResult[PARAM0] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_get_undefined(env, &addResult[PARAM1]);
                ProcessCallbackOrPromise(env, asyncContext, addResult[PARAM0], addResult[PARAM1]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            (void *)asyncContext,
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::DeleteAccount(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Enter N-API DeleteAccount function.");
    auto *asyncContext = new AppAccountAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithTwoPara(env, cbInfo, asyncContext);
    ACCOUNT_LOGI("Parameter parsing completed, name = %{public}s", asyncContext->name.c_str());

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "DeleteAccount", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("DeleteAccount, napi_create_async_work running.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                asyncContext->errCode = AppAccountManager::DeleteAccount(asyncContext->name);
                ACCOUNT_LOGI("Deleteaccount errcode parameter is %{public}d", asyncContext->errCode);
                asyncContext->status = asyncContext->errCode == 0 ? napi_ok : napi_generic_failure;
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("DeleteAccount, napi_create_async_work complete.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                napi_value delResult[RESULT_COUNT] = {0};
                delResult[PARAM0] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_get_undefined(env, &delResult[PARAM1]);
                ProcessCallbackOrPromise(env, asyncContext, delResult[PARAM0], delResult[PARAM1]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            (void *)asyncContext,
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::DisableAppAccess(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Enter N-API DisableAppAccess function.");
    auto *asyncContext = new AppAccountAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithBdName(env, cbInfo, asyncContext);
    ACCOUNT_LOGI("Parsing completed, name = %{public}s, bundleName = %{public}s",
        asyncContext->name.c_str(),
        asyncContext->bundleName.c_str());

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "DisableAppAccess", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("DisableAppAccess, napi_create_async_work running.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                asyncContext->errCode =
                    AppAccountManager::DisableAppAccess(asyncContext->name, asyncContext->bundleName);
                ACCOUNT_LOGI("DisableAppAccess errcode parameter is %{public}d", asyncContext->errCode);
                asyncContext->status = asyncContext->errCode == 0 ? napi_ok : napi_generic_failure;
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("DisableAppAccess, napi_create_async_work complete.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                napi_value disResult[RESULT_COUNT] = {0};
                disResult[PARAM0] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_get_undefined(env, &disResult[PARAM1]);
                ProcessCallbackOrPromise(env, asyncContext, disResult[PARAM0], disResult[PARAM1]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            (void *)asyncContext,
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::EnableAppAccess(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Enter N-API EnableAppAccess function.");
    auto *asyncContext = new AppAccountAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithBdName(env, cbInfo, asyncContext);
    ACCOUNT_LOGI("Parsing completed, name = %{public}s, bundleName = %{public}s",
        asyncContext->name.c_str(),
        asyncContext->bundleName.c_str());

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "EnableAppAccess", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("EnableAppAccess, napi_create_async_work running.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                asyncContext->errCode =
                    AppAccountManager::EnableAppAccess(asyncContext->name, asyncContext->bundleName);
                ACCOUNT_LOGI("EnableAppAccess errcode parameter is %{public}d", asyncContext->errCode);
                asyncContext->status = asyncContext->errCode == 0 ? napi_ok : napi_generic_failure;
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("EnableAppAccess, napi_create_async_work complete.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                napi_value enResult[RESULT_COUNT] = {0};
                enResult[PARAM0] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_get_undefined(env, &enResult[PARAM1]);
                ProcessCallbackOrPromise(env, asyncContext, enResult[PARAM0], enResult[PARAM1]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            (void *)asyncContext,
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::CheckAppAccountSyncEnable(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Enter N-API CheckAppAccountSyncEnable function.");
    auto *asyncContext = new AppAccountAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithTwoPara(env, cbInfo, asyncContext);
    ACCOUNT_LOGI("Parameter parsing completed, name = %{public}s", asyncContext->name.c_str());

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "CheckAppAccountSyncEnable", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("CheckAppAccountSyncEnable, napi_create_async_work running.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                asyncContext->errCode =
                    AppAccountManager::CheckAppAccountSyncEnable(asyncContext->name, asyncContext->result);
                ACCOUNT_LOGI("CheckAppAccountSyncEnable errcode parameter is %{public}d", asyncContext->errCode);
                asyncContext->status = asyncContext->errCode == 0 ? napi_ok : napi_generic_failure;
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("CheckAppAccountSyncEnable, napi_create_async_work complete.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                napi_value checkResult[RESULT_COUNT] = {0};
                checkResult[PARAM0] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_get_boolean(env, asyncContext->result, &checkResult[PARAM1]);
                ProcessCallbackOrPromise(env, asyncContext, checkResult[PARAM0], checkResult[PARAM1]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            (void *)asyncContext,
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::SetAccountCredential(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Enter N-API SetAccountCredential function.");
    auto *asyncContext = new AppAccountAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextToSetCredential(env, cbInfo, asyncContext);
    ACCOUNT_LOGI("Parsing completed, name = %{public}s, credentialType = %{public}s, credential = %{public}s",
        asyncContext->name.c_str(),
        asyncContext->credentialType.c_str(),
        asyncContext->credential.c_str());

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetAccountCredential", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("SetAccountCredential, napi_create_async_work running.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                asyncContext->errCode = AppAccountManager::SetAccountCredential(
                    asyncContext->name, asyncContext->credentialType, asyncContext->credential);
                ACCOUNT_LOGI("SetAccountCredential errcode parameter is %{public}d", asyncContext->errCode);
                asyncContext->status = asyncContext->errCode == 0 ? napi_ok : napi_generic_failure;
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("SetAccountCredential, napi_create_async_work complete.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                napi_value setResult[RESULT_COUNT] = {0};
                setResult[PARAM0] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_get_undefined(env, &setResult[PARAM1]);
                ProcessCallbackOrPromise(env, asyncContext, setResult[PARAM0], setResult[PARAM1]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            (void *)asyncContext,
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::SetAccountExtraInfo(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Enter N-API SetAccountExtraInfo function.");
    auto *asyncContext = new AppAccountAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithExInfo(env, cbInfo, asyncContext);
    ACCOUNT_LOGI("Parameter parsing completed, name = %{public}s, extraInfo = %{public}s",
        asyncContext->name.c_str(),
        asyncContext->extraInfo.c_str());

    if (asyncContext == nullptr) {
        ACCOUNT_LOGI("The asyncContext for SetAccountExtraInfo is nullptr");
        return NapiGetNull(env);
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetAccountExtraInfo", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("SetAccountExtraInfo, napi_create_async_work running.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                asyncContext->errCode =
                    AppAccountManager::SetAccountExtraInfo(asyncContext->name, asyncContext->extraInfo);
                ACCOUNT_LOGI("SetAccountExtraInfo errcode parameter is %{public}d", asyncContext->errCode);
                asyncContext->status = asyncContext->errCode == 0 ? napi_ok : napi_generic_failure;
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("SetAccountExtraInfo, napi_create_async_work complete.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                napi_value setResult[RESULT_COUNT] = {0};
                setResult[PARAM0] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_get_undefined(env, &setResult[PARAM1]);
                ProcessCallbackOrPromise(env, asyncContext, setResult[PARAM0], setResult[PARAM1]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            (void *)asyncContext,
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::SetAppAccountSyncEnable(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Enter N-API SetAppAccountSyncEnable function");
    auto *asyncContext = new AppAccountAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithIsEnable(env, cbInfo, asyncContext);
    ACCOUNT_LOGI("Parameter parsing completed, name = %{public}s", asyncContext->name.c_str());

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetAppAccountSyncEnable", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("SetAppAccountSyncEnable, napi_create_async_work running.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                asyncContext->errCode =
                    AppAccountManager::SetAppAccountSyncEnable(asyncContext->name, asyncContext->isEnable);
                ACCOUNT_LOGI("SetAppAccountSyncEnable errcode parameter is %{public}d", asyncContext->errCode);
                asyncContext->status = asyncContext->errCode == 0 ? napi_ok : napi_generic_failure;
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("SetAppAccountSyncEnable, napi_create_async_work complete.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                napi_value setResult[RESULT_COUNT] = {0};
                setResult[PARAM0] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_get_undefined(env, &setResult[PARAM1]);
                ProcessCallbackOrPromise(env, asyncContext, setResult[PARAM0], setResult[PARAM1]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            (void *)asyncContext,
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::SetAssociatedData(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Enter N-API SetAssociatedData function.");
    auto *asyncContext = new AppAccountAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextForAssociatedData(env, cbInfo, asyncContext);
    ACCOUNT_LOGI("Parameter parsing completed, name = %{public}s", asyncContext->name.c_str());

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetAssociatedData", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("SetAssociatedData, napi_create_async_work running.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                asyncContext->errCode =
                    AppAccountManager::SetAssociatedData(asyncContext->name, asyncContext->key, asyncContext->value);
                ACCOUNT_LOGI("SetAssociatedData errcode parameter is %{public}d", asyncContext->errCode);
                asyncContext->status = asyncContext->errCode == 0 ? napi_ok : napi_generic_failure;
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("SetAssociatedData, napi_create_async_work complete.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                napi_value setResult[RESULT_COUNT] = {0};
                setResult[PARAM0] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_get_undefined(env, &setResult[PARAM1]);
                ProcessCallbackOrPromise(env, asyncContext, setResult[PARAM0], setResult[PARAM1]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            (void *)asyncContext,
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::GetAllAccessibleAccounts(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Enter N-API GetAllAccessibleAccounts function.");
    auto *asyncContext = new GetAccountsAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextCBArray(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetAllAccessibleAccounts", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("GetAllAccessibleAccounts, napi_create_async_work running.");
                GetAccountsAsyncContext *asyncContext = (GetAccountsAsyncContext *)data;
                asyncContext->errCode = AppAccountManager::GetAllAccessibleAccounts(asyncContext->appAccounts);
                ACCOUNT_LOGI("GetAllAccessibleAccounts errcode parameter is %{public}d", asyncContext->errCode);
                asyncContext->status = asyncContext->errCode == 0 ? napi_ok : napi_generic_failure;
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("GetAllAccessibleAccounts, napi_create_async_work complete.");
                GetAccountsAsyncContext *asyncContext = (GetAccountsAsyncContext *)data;
                napi_value getResult[RESULT_COUNT] = {0};
                getResult[PARAM0] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_create_array(env, &getResult[PARAM1]);
                GetAppAccountInfoForResult(env, asyncContext->appAccounts, getResult[PARAM1]);
                ProcessCallbackOrPromiseCBArray(env, asyncContext, getResult[PARAM0], getResult[PARAM1]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            (void *)asyncContext,
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::GetAllAccounts(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Enter N-API GetAllAccounts function.");
    auto *asyncContext = new GetAccountsAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithStrCBArray(env, cbInfo, asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetAllAccounts", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("GetAllAccounts, napi_create_async_work running.");
                GetAccountsAsyncContext *asyncContext = (GetAccountsAsyncContext *)data;
                asyncContext->errCode =
                    AppAccountManager::GetAllAccounts(asyncContext->owner, asyncContext->appAccounts);
                ACCOUNT_LOGI("GetAllAccounts errcode parameter is %{public}d", asyncContext->errCode);
                asyncContext->status = asyncContext->errCode == 0 ? napi_ok : napi_generic_failure;
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("GetAllAccounts, napi_create_async_work complete.");
                GetAccountsAsyncContext *asyncContext = (GetAccountsAsyncContext *)data;
                napi_value getResult[RESULT_COUNT] = {0};
                getResult[PARAM0] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_create_array(env, &getResult[PARAM1]);
                GetAppAccountInfoForResult(env, asyncContext->appAccounts, getResult[PARAM1]);
                ProcessCallbackOrPromiseCBArray(env, asyncContext, getResult[PARAM0], getResult[PARAM1]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            (void *)asyncContext,
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::GetAccountCredential(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Enter N-API GetAccountCredential function.");
    auto *asyncContext = new AppAccountAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithCredentialType(env, cbInfo, asyncContext);
    ACCOUNT_LOGI("Parameter parsing completed, name = %{public}s, credentialType = %{public}s",
        asyncContext->name.c_str(),
        asyncContext->credentialType.c_str());

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetAccountCredential", NAPI_AUTO_LENGTH, &resource);

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("GetAccountCredential, napi_create_async_work running.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                asyncContext->errCode = AppAccountManager::GetAccountCredential(
                    asyncContext->name, asyncContext->credentialType, asyncContext->credential);
                ACCOUNT_LOGI("GetAccountCredential errcode parameter is %{public}d", asyncContext->errCode);
                asyncContext->status = asyncContext->errCode == 0 ? napi_ok : napi_generic_failure;
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("GetAccountCredential, napi_create_async_work complete.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                napi_value getResult[RESULT_COUNT] = {0};
                getResult[PARAM0] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_create_string_utf8(env, asyncContext->credential.c_str(), NAPI_AUTO_LENGTH, &getResult[PARAM1]);
                ProcessCallbackOrPromise(env, asyncContext, getResult[PARAM0], getResult[PARAM1]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            (void *)asyncContext,
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::GetAccountExtraInfo(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Enter N-API GetAccountExtraInfo function.");
    auto *asyncContext = new AppAccountAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextWithTwoPara(env, cbInfo, asyncContext);
    ACCOUNT_LOGI("Parameter parsing completed, name = %{public}s", asyncContext->name.c_str());

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetAccountExtraInfo", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("GetAccountExtraInfo, napi_create_async_work running.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                asyncContext->errCode =
                    AppAccountManager::GetAccountExtraInfo(asyncContext->name, asyncContext->extraInfo);
                ACCOUNT_LOGI("GetAccountExtraInfo errcode parameter is %{public}d", asyncContext->errCode);
                asyncContext->status = asyncContext->errCode == 0 ? napi_ok : napi_generic_failure;
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("GetAccountExtraInfo, napi_create_async_work complete.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                napi_value getResult[RESULT_COUNT] = {0};
                getResult[PARAM0] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_create_string_utf8(env, asyncContext->extraInfo.c_str(), NAPI_AUTO_LENGTH, &getResult[PARAM1]);
                ProcessCallbackOrPromise(env, asyncContext, getResult[PARAM0], getResult[PARAM1]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            (void *)asyncContext,
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::GetAssociatedData(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Enter N-API GetAssociatedData function.");
    auto *asyncContext = new AppAccountAsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    ParseContextToGetData(env, cbInfo, asyncContext);
    ACCOUNT_LOGI("Parameter parsing completed, name = %{public}s", asyncContext->name.c_str());

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetAssociatedData", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("GetAssociatedData, napi_create_async_work running.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                asyncContext->errCode =
                    AppAccountManager::GetAssociatedData(asyncContext->name, asyncContext->key, asyncContext->value);
                ACCOUNT_LOGI("GetAssociatedData errcode parameter is %{public}d", asyncContext->errCode);
                asyncContext->status = asyncContext->errCode == 0 ? napi_ok : napi_generic_failure;
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("GetAssociatedData, napi_create_async_work complete.");
                AppAccountAsyncContext *asyncContext = (AppAccountAsyncContext *)data;
                napi_value getResult[RESULT_COUNT] = {0};
                getResult[PARAM0] = GetErrorCodeValue(env, asyncContext->errCode);
                napi_create_string_utf8(env, asyncContext->value.c_str(), NAPI_AUTO_LENGTH, &getResult[PARAM1]);
                ProcessCallbackOrPromise(env, asyncContext, getResult[PARAM0], getResult[PARAM1]);
                napi_delete_async_work(env, asyncContext->work);
                delete asyncContext;
                asyncContext = nullptr;
            },
            (void *)asyncContext,
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

napi_value NapiAppAccount::Subscribe(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Subscribe start");

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

    AsyncContextForSubscribe *asyncContextForOn = new (std::nothrow) AsyncContextForSubscribe {
        .env = env,
        .work = nullptr,
        .callbackRef = nullptr,
    };
    if (asyncContextForOn == nullptr) {
        ACCOUNT_LOGI("asyncContextForOn is null");
        return NapiGetNull(env);
    }
    ACCOUNT_LOGI("Subscribe AsyncCallbackInfoSubscribe * asyncContextForOn = %{public}p", asyncContextForOn);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo(owners);
    // make a subscriber
    asyncContextForOn->subscriber = std::make_shared<SubscriberPtr>(subscribeInfo);
    asyncContextForOn->callbackRef = callback;
    ACCOUNT_LOGI("callbackRef = %{public}p, thisVar = %{public}p", asyncContextForOn->callbackRef, thisVar);

    subscriberInstances[thisVar] = asyncContextForOn;

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "Subscribe", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("Subscribe, napi_create_async_work running.");
                AsyncContextForSubscribe *asyncContextForOn = (AsyncContextForSubscribe *)data;
                asyncContextForOn->subscriber->SetEnv(env);
                asyncContextForOn->subscriber->SetCallbackRef(asyncContextForOn->callbackRef);
                int errCode = AppAccountManager::SubscribeAppAccount(asyncContextForOn->subscriber);
                asyncContextForOn->subscriber->SetErrorCode(errCode);
            },
            [](napi_env env, napi_status status, void *data) {
                ACCOUNT_LOGI("Subscribe, napi_create_async_work complete.");
                AsyncContextForSubscribe *asyncContextForOn = (AsyncContextForSubscribe *)data;
                napi_delete_async_work(env, asyncContextForOn->work);
            },
            (void *)asyncContextForOn,
            &asyncContextForOn->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContextForOn->work));
    return NapiGetNull(env);
}

napi_value NapiAppAccount::Unsubscribe(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("Unsubscribe start");

    // Argument parsing
    size_t argc = UNSUBSCRIBE_MAX_PARA;
    napi_value argv[UNSUBSCRIBE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    std::shared_ptr<SubscriberPtr> subscriber = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL));
    NAPI_ASSERT(env, argc >= 1, "Wrong number of arguments");

    napi_ref callback = nullptr;
    if (ParseParametersByUnsubscribe(env, argc, argv, callback) == nullptr) {
        return NapiGetNull(env);
    }
    AsyncContextForUnsubscribe *asyncContextForOff = new (std::nothrow) AsyncContextForUnsubscribe {
        .env = env,
        .work = nullptr,
        .callbackRef = nullptr,
    };
    if (asyncContextForOff == nullptr) {
        ACCOUNT_LOGI("asyncContextForOff is null");
        return NapiGetNull(env);
    }
    ACCOUNT_LOGI("Subscribe new asyncContext = %{public}p", asyncContextForOff);

    asyncContextForOff->callbackRef = callback;
    asyncContextForOff->thisVar = thisVar;
    asyncContextForOff->argc = argc;
    bool isFind = false;
    napi_value result = GetSubscriberByUnsubscribe(env, thisVar, subscriber, asyncContextForOff, isFind);
    if (!result) {
        ACCOUNT_LOGI("Unsubscribe failed. The current subscriber does not exist");
        return NapiGetNull(env);
    }
    asyncContextForOff->subscriber = subscriber;

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "Unsubscribe", NAPI_AUTO_LENGTH, &resourceName));

    // Asynchronous function call
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                ACCOUNT_LOGI("Unsubscribe napi_create_async_work start.");
                AsyncContextForUnsubscribe *asyncContextForOff = (AsyncContextForUnsubscribe *)data;
                AppAccountManager::UnsubscribeAppAccount(asyncContextForOff->subscriber);
            },
            UnsubscribeCallbackCompletedCB,
            (void *)asyncContextForOff,
            &asyncContextForOff->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContextForOff->work));
    return NapiGetNull(env);
}
}  // namespace AccountJsKit
}  // namespace OHOS

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports)
{
    ACCOUNT_LOGI("Register end, start init.");
    return OHOS::AccountJsKit::NapiAppAccount::Init(env, exports);
}
EXTERN_C_END

/*
 * module define
 */
static napi_module _module = {.nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "account.appAccount",
    .nm_priv = ((void *)0),
    .reserved = {0}};
/*
 * module register
 */
extern "C" __attribute__((constructor)) void Register()
{
    napi_module_register(&_module);
}
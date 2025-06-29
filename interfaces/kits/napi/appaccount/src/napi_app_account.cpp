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

#include "napi_app_account.h"

#include <string>
#include <cstring>
#include <vector>
#include "account_log_wrapper.h"
#include "app_account_common.h"
#include "app_account_manager.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_account_common.h"
#include "napi_account_error.h"
#include "napi_app_account_common.h"

using namespace OHOS::AccountSA;
namespace OHOS {
namespace AccountJsKit {
const std::string APP_ACCOUNT_CLASS_NAME = "AppAccountManager";
const char TYPE_CHANGE[] = "change";
static thread_local napi_ref appAccountRef_ = nullptr;
napi_property_descriptor NapiAppAccount::appAccountProperties[] = {
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
    // new api
    DECLARE_NAPI_FUNCTION("createAccount", CreateAccount),
    DECLARE_NAPI_FUNCTION("createAccountImplicitly", CreateAccountImplicitly),
    DECLARE_NAPI_FUNCTION("auth", Auth),
    DECLARE_NAPI_FUNCTION("removeAccount", RemoveAccount),
    DECLARE_NAPI_FUNCTION("setAppAccess", SetAppAccess),
    DECLARE_NAPI_FUNCTION("setCredential", SetCredential),
    DECLARE_NAPI_FUNCTION("getCredential", GetCredential),
    DECLARE_NAPI_FUNCTION("deleteCredential", DeleteCredential),
    DECLARE_NAPI_FUNCTION("setDataSyncEnabled", SetDataSyncEnabled),
    DECLARE_NAPI_FUNCTION("checkDataSyncEnabled", CheckDataSyncEnabled),
    DECLARE_NAPI_FUNCTION("setCustomData", SetCustomData),
    DECLARE_NAPI_FUNCTION("getCustomData", GetCustomData),
    DECLARE_NAPI_FUNCTION("getCustomDataSync", GetAssociatedDataSync),
    DECLARE_NAPI_FUNCTION("getAccountsByOwner", GetAccountsByOwner),
    DECLARE_NAPI_FUNCTION("getAuthToken", GetAuthToken),
    DECLARE_NAPI_FUNCTION("setAuthToken", SetAuthToken),
    DECLARE_NAPI_FUNCTION("deleteAuthToken", DeleteAuthToken),
    DECLARE_NAPI_FUNCTION("getAllAuthTokens", GetAllAuthTokens),
    DECLARE_NAPI_FUNCTION("getAuthList", GetAuthList),
    DECLARE_NAPI_FUNCTION("setAuthTokenVisibility", SetAuthTokenVisibility),
    DECLARE_NAPI_FUNCTION("checkAuthTokenVisibility", CheckAuthTokenVisibility),
    DECLARE_NAPI_FUNCTION("getAuthCallback", GetAuthCallback),
    DECLARE_NAPI_FUNCTION("queryAuthenticatorInfo", QueryAuthenticatorInfo)
};

static bool CheckSpecialCharacters(const std::string &name)
{
    for (const auto &specialCharacter : Constants::SPECIAL_CHARACTERS) {
        std::size_t index = name.find(specialCharacter);
        if (index != std::string::npos) {
            ACCOUNT_LOGE("found a special character, specialCharacter = %{public}c", specialCharacter);
            NativeErrMsg() = "Invalid name. The name cannot contain space characters";
            return false;
        }
    }
    return true;
}

napi_value NapiAppAccount::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptor[] = {
        DECLARE_NAPI_FUNCTION("createAppAccountManager", CreateAppAccountManager),
    };
    NAPI_CALL(
        env, napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor));

    napi_value cons = nullptr;
    NAPI_CALL(env,
        napi_define_class(env, APP_ACCOUNT_CLASS_NAME.c_str(), APP_ACCOUNT_CLASS_NAME.size(), JsConstructor, nullptr,
            sizeof(appAccountProperties) / sizeof(napi_property_descriptor), appAccountProperties, &cons));
    NAPI_CALL(env, napi_create_reference(env, cons, 1, &appAccountRef_));
    NAPI_CALL(env, napi_set_named_property(env, exports, APP_ACCOUNT_CLASS_NAME.c_str(), cons));
    return exports;
}

napi_value NapiAppAccount::JsConstructor(napi_env env, napi_callback_info cbInfo)
{
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

napi_value NapiAppAccount::CreateAppAccountManager(napi_env env, napi_callback_info cbInfo)
{
    napi_value instance = nullptr;
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, appAccountRef_, &cons) != napi_ok) {
        return nullptr;
    }

    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        return nullptr;
    }

    AppAccountManager *objectInfo = new (std::nothrow) AppAccountManager();
    if (objectInfo == nullptr) {
        ACCOUNT_LOGE("failed to create AppAccountManager for insufficient memory");
        return nullptr;
    }
    napi_status status = napi_wrap(env, instance, objectInfo,
        [](napi_env env, void *data, void *hint) {
            ACCOUNT_LOGI("js AppAccountManager instance garbage collection");
            delete reinterpret_cast<AppAccountManager *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        ACCOUNT_LOGE("failed to wrap js instance with native object");
        delete objectInfo;
        return nullptr;
    }
    return instance;
}

napi_value NapiAppAccount::AddAccount(napi_env env, napi_callback_info cbInfo)
{
    auto asyncContext = std::make_unique<AppAccountAsyncContext>(env);
    ParseContextWithExInfo(env, cbInfo, asyncContext.get());
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "AddAccountInternal", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            asyncContext->errCode = AppAccountManager::AddAccount(asyncContext->name, asyncContext->extraInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ProcessCallbackOrPromise(env, asyncContext,
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode)), NapiGetNull(env));
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext.get()),
        &asyncContext->work);
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::CreateAccount(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<CreateAccountContext>(env);
    if (!ParseContextForCreateAccount(env, cbInfo, context.get())) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, context->errMsg));
        return NapiGetNull(env);
    }
    napi_value result = nullptr;
    if (context->callbackRef == nullptr) {
        napi_create_promise(env, &context->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "CreateAccount", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            CreateAccountContext *context = reinterpret_cast<CreateAccountContext *>(data);
            NativeErrMsg() = "";
            context->errCode = AppAccountManager::CreateAccount(context->name, context->options);
            context->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            CreateAccountContext *context = reinterpret_cast<CreateAccountContext *>(data);
            ProcessCallbackOrPromise(env, context,
                GenerateBusinessError(env, context->errCode), NapiGetNull(env));
            delete context;
        }, reinterpret_cast<void *>(context.get()), &context->work);
    napi_queue_async_work_with_qos(env, context->work, napi_qos_default);
    context.release();
    return result;
}

napi_value NapiAppAccount::CreateAccountImplicitly(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<CreateAccountImplicitlyContext>(env);
    if (!ParseContextForCreateAccountImplicitly(env, cbInfo, context.get())) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, context->errMsg));
        return NapiGetNull(env);
    }
    context->appAccountMgrCb = new (std::nothrow) AppAccountManagerCallback(env, context->callback);
    if (context->appAccountMgrCb == nullptr) {
        ACCOUNT_LOGE("insufficient memory for AppAccountManagerCallback!");
        return NapiGetNull(env);
    }
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "CreateAccountImplicitly", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            auto context = reinterpret_cast<CreateAccountImplicitlyContext *>(data);
            NativeErrMsg() = "";
            ErrCode errCode = AppAccountManager::CreateAccountImplicitly(context->owner,
                context->options, context->appAccountMgrCb);
            context->errCode = ConvertToJSErrCode(errCode);
            context->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            auto context = reinterpret_cast<CreateAccountImplicitlyContext *>(data);
            AAFwk::Want errResult;
            if ((context->errCode != 0) && (context->appAccountMgrCb != nullptr)) {
                context->appAccountMgrCb->OnResult(context->errCode, errResult);
            }
            delete context;
        }, reinterpret_cast<void *>(context.get()), &context->work);
    napi_queue_async_work_with_qos(env, context->work, napi_qos_default);
    context.release();
    return NapiGetNull(env);
}

napi_value NapiAppAccount::AddAccountImplicitly(napi_env env, napi_callback_info cbInfo)
{
    auto asyncContext = std::make_unique<OAuthAsyncContext>(env);
    ParseContextForAuthenticate(env, cbInfo, asyncContext.get(), ARGS_SIZE_FOUR);
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
                asyncContext->errCode = ConvertToJSErrCodeV8(errCode);
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                AAFwk::Want errResult;
                if ((asyncContext->errCode != 0) && (asyncContext->appAccountMgrCb != nullptr)) {
                    asyncContext->appAccountMgrCb->OnResult(asyncContext->errCode, errResult);
                }
                delete asyncContext;
            },
            reinterpret_cast<void *>(asyncContext.get()), &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));
    asyncContext.release();
    return NapiGetNull(env);
}

napi_value NapiAppAccount::DeleteAccount(napi_env env, napi_callback_info cbInfo)
{
    return RemoveAccountInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::RemoveAccount(napi_env env, napi_callback_info cbInfo)
{
    return RemoveAccountInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::RemoveAccountInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<AppAccountAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = { PropertyType::NAME };
    napi_value result = nullptr;
    if ((!ParseContextForAppAccount(env, cbInfo, asyncContext.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "DeleteAccount", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            NativeErrMsg() = "";
            asyncContext->errCode = AppAccountManager::DeleteAccount(asyncContext->name);
            asyncContext->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
            ProcessCallbackOrPromise(env, asyncContext, err, NapiGetNull(env));
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext.get()),
        &asyncContext->work);
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::DisableAppAccess(napi_env env, napi_callback_info cbInfo)
{
    auto asyncContext = std::make_unique<AppAccountAsyncContext>(env);
    std::vector<PropertyType> propertyList = {PropertyType::NAME, PropertyType::BUNDLE_NAME};
    napi_value result = nullptr;
    ParseContextForAppAccount(env, cbInfo, asyncContext.get(), propertyList, &result);

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "DisableAppAccess", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            asyncContext->errCode = AppAccountManager::DisableAppAccess(asyncContext->name, asyncContext->bundleName);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ProcessCallbackOrPromise(env, asyncContext,
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode)), NapiGetNull(env));
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext.get()),
        &asyncContext->work);
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::EnableAppAccess(napi_env env, napi_callback_info cbInfo)
{
    auto asyncContext = std::make_unique<AppAccountAsyncContext>(env);
    std::vector<PropertyType> propertyList = {PropertyType::NAME, PropertyType::BUNDLE_NAME};
    napi_value result = nullptr;
    ParseContextForAppAccount(env, cbInfo, asyncContext.get(), propertyList, &result);

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "EnableAppAccess", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ErrCode errCode = AppAccountManager::EnableAppAccess(asyncContext->name, asyncContext->bundleName);
            asyncContext->errCode = ConvertToJSErrCode(errCode);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ProcessCallbackOrPromise(env, asyncContext,
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode)), NapiGetNull(env));
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext.get()),
        &asyncContext->work);
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::SetAppAccess(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<AppAccountAsyncContext>(env);
    std::vector<PropertyType> propertyList = {
        PropertyType::NAME, PropertyType::BUNDLE_NAME, PropertyType::IS_ACCESSIBLE};
    napi_value result = nullptr;
    if (!ParseContextForAppAccount(env, cbInfo, context.get(), propertyList, &result)) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, context->errMsg));
        return NapiGetNull(env);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "SetAppAccess", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *context = reinterpret_cast<AppAccountAsyncContext *>(data);
            NativeErrMsg() = "";
            context->errCode =
                AppAccountManager::SetAppAccess(context->name, context->bundleName, context->isAccessible);
            context->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *context = reinterpret_cast<AppAccountAsyncContext *>(data);
            ProcessCallbackOrPromise(env, context,
                GenerateBusinessError(env, context->errCode), NapiGetNull(env));
            delete context;
        }, reinterpret_cast<void *>(context.get()), &context->work);
    napi_queue_async_work_with_qos(env, context->work, napi_qos_default);
    context.release();
    return result;
}

napi_value NapiAppAccount::CheckAppAccountSyncEnable(napi_env env, napi_callback_info cbInfo)
{
    return CheckDataSyncEnabledInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::CheckDataSyncEnabled(napi_env env, napi_callback_info cbInfo)
{
    return CheckDataSyncEnabledInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::CheckDataSyncEnabledInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<AppAccountAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = { PropertyType::NAME };
    napi_value result = nullptr;
    if ((!ParseContextForAppAccount(env, cbInfo, asyncContext.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "CheckAppAccountSyncEnable", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            NativeErrMsg() = "";
            asyncContext->errCode =
                AppAccountManager::CheckAppAccountSyncEnable(asyncContext->name, asyncContext->result);
            asyncContext->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value boolVal = nullptr;
            napi_get_boolean(env, asyncContext->result, &boolVal);
            napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
            ProcessCallbackOrPromise(env, asyncContext, err, boolVal);
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext.get()),
        &asyncContext->work);
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::SetAccountCredential(napi_env env, napi_callback_info cbInfo)
{
    return SetCredentialInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::SetCredential(napi_env env, napi_callback_info cbInfo)
{
    return SetCredentialInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::SetCredentialInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto context = std::make_unique<AppAccountAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = {
        PropertyType::NAME, PropertyType::CREDENTIAL_TYPE, PropertyType::CREDENTIAL };
    napi_value result = nullptr;
    if ((!ParseContextForAppAccount(env, cbInfo, context.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, context->errMsg));
        return NapiGetNull(env);
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetAccountCredential", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            NativeErrMsg() = "";
            if ((!asyncContext->throwErr) && (!CheckSpecialCharacters(asyncContext->name))) {
                asyncContext->errCode = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
                asyncContext->nativeErrMsg = NativeErrMsg();
                return;
            }
            asyncContext->errCode = AppAccountManager::SetAccountCredential(
                asyncContext->name, asyncContext->credentialType, asyncContext->credential);
            asyncContext->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
            ProcessCallbackOrPromise(env, asyncContext, err, NapiGetNull(env));
            delete asyncContext;
        },
        reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return result;
}

napi_value NapiAppAccount::SetAccountExtraInfo(napi_env env, napi_callback_info cbInfo)
{
    auto asyncContext = std::make_unique<AppAccountAsyncContext>(env);
    std::vector<PropertyType> propertyList = { PropertyType::NAME, PropertyType::EXTRA_INFO };
    napi_value result = nullptr;
    ParseContextForAppAccount(env, cbInfo, asyncContext.get(), propertyList, &result);
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetAccountExtraInfo", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            asyncContext->errCode = AppAccountManager::SetAccountExtraInfo(
                asyncContext->name, asyncContext->extraInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            ProcessCallbackOrPromise(env, asyncContext,
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode)), NapiGetNull(env));
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext.get()), &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::SetAppAccountSyncEnable(napi_env env, napi_callback_info cbInfo)
{
    return SetDataSyncEnabledInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::SetDataSyncEnabled(napi_env env, napi_callback_info cbInfo)
{
    return SetDataSyncEnabledInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::SetDataSyncEnabledInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<AppAccountAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = { PropertyType::NAME, PropertyType::IS_ENABLE };
    napi_value result = nullptr;
    if ((!ParseContextForAppAccount(env, cbInfo, asyncContext.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "SetAppAccountSyncEnable", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            NativeErrMsg() = "";
            if ((!asyncContext->throwErr) && (!CheckSpecialCharacters(asyncContext->name))) {
                asyncContext->errCode = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
                asyncContext->nativeErrMsg = NativeErrMsg();
                return;
            }
            asyncContext->errCode =
                AppAccountManager::SetAppAccountSyncEnable(asyncContext->name, asyncContext->isEnable);
            asyncContext->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
            ProcessCallbackOrPromise(env, asyncContext, err, NapiGetNull(env));
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext.get()), &asyncContext->work);
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::SetAssociatedData(napi_env env, napi_callback_info cbInfo)
{
    return SetCustomDataInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::SetCustomData(napi_env env, napi_callback_info cbInfo)
{
    return SetCustomDataInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::SetCustomDataInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<AppAccountAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = { PropertyType::NAME, PropertyType::KEY, PropertyType::VALUE };
    napi_value result = nullptr;
    if ((!ParseContextForAppAccount(env, cbInfo, asyncContext.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "SetAssociatedData", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            NativeErrMsg() = "";
            if ((!asyncContext->throwErr) && (!CheckSpecialCharacters(asyncContext->name))) {
                asyncContext->errCode = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
                asyncContext->nativeErrMsg = NativeErrMsg();
                return;
            }
            asyncContext->errCode =
                AppAccountManager::SetAssociatedData(asyncContext->name, asyncContext->key, asyncContext->value);
            asyncContext->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
            ProcessCallbackOrPromise(env, asyncContext, err, NapiGetNull(env));
            delete asyncContext;
        }, reinterpret_cast<void *>(asyncContext.get()), &asyncContext->work);
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::GetAllAccessibleAccounts(napi_env env, napi_callback_info cbInfo)
{
    return GetAllAccessibleAccountsInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::GetAllAccessibleAccountsInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<GetAccountsAsyncContext>(env, isThrowable);
    if ((!ParseContextCBArray(env, cbInfo, asyncContext.get())) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetAllAccessibleAccounts", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            GetAccountsAsyncContext *asyncContext = reinterpret_cast<GetAccountsAsyncContext *>(data);
            NativeErrMsg() = "";
            if (asyncContext->throwErr) {
                asyncContext->errCode =
                    AppAccountManager::QueryAllAccessibleAccounts(asyncContext->owner, asyncContext->appAccounts);
            } else {
                asyncContext->errCode =
                    AppAccountManager::GetAllAccessibleAccounts(asyncContext->appAccounts);
            }
            asyncContext->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            GetAccountsAsyncContext *asyncContext = reinterpret_cast<GetAccountsAsyncContext *>(data);
            napi_value arrVal = nullptr;
            GetAppAccountInfoForResult(env, asyncContext->appAccounts, arrVal);
            napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
            ProcessCallbackOrPromise(env, asyncContext, err, arrVal);
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext.get()),
        &asyncContext->work);
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::GetAllAccounts(napi_env env, napi_callback_info cbInfo)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == 0) {
        return GetAllAccessibleAccountsInternal(env, cbInfo, true);
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType == napi_function) {
        return GetAllAccessibleAccountsInternal(env, cbInfo, true);
    }
    return GetAccountsByOwnerInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::GetAccountsByOwner(napi_env env, napi_callback_info cbInfo)
{
    return GetAccountsByOwnerInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::GetAccountsByOwnerInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<GetAccountsAsyncContext>(env, isThrowable);
    if ((!ParseContextWithStrCBArray(env, cbInfo, asyncContext.get())) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetAllAccounts", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            GetAccountsAsyncContext *asyncContext = reinterpret_cast<GetAccountsAsyncContext *>(data);
            NativeErrMsg() = "";
            if (!asyncContext->throwErr) {
                asyncContext->errCode =
                    AppAccountManager::GetAllAccounts(asyncContext->owner, asyncContext->appAccounts);
            } else if (asyncContext->owner.empty()) {
                asyncContext->errCode = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
            } else {
                asyncContext->errCode =
                    AppAccountManager::QueryAllAccessibleAccounts(asyncContext->owner, asyncContext->appAccounts);
            }
            asyncContext->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            GetAccountsAsyncContext *asyncContext = reinterpret_cast<GetAccountsAsyncContext *>(data);
            napi_value arrVal = nullptr;
            GetAppAccountInfoForResult(env, asyncContext->appAccounts, arrVal);
            napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
            ProcessCallbackOrPromise(env, asyncContext, err, arrVal);
            delete asyncContext;
        }, reinterpret_cast<void *>(asyncContext.get()), &asyncContext->work);
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::GetAccountCredential(napi_env env, napi_callback_info cbInfo)
{
    return GetCredentialInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::GetCredential(napi_env env, napi_callback_info cbInfo)
{
    return GetCredentialInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::GetCredentialInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<AppAccountAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = { PropertyType::NAME, PropertyType::CREDENTIAL_TYPE };
    napi_value result = nullptr;
    if ((!ParseContextForAppAccount(env, cbInfo, asyncContext.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetAccountCredential", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            NativeErrMsg() = "";
            asyncContext->errCode = AppAccountManager::GetAccountCredential(
                asyncContext->name, asyncContext->credentialType, asyncContext->credential);
            asyncContext->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value strVal = nullptr;
            napi_create_string_utf8(env, asyncContext->credential.c_str(), NAPI_AUTO_LENGTH, &strVal);
            napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
            ProcessCallbackOrPromise(env, asyncContext, err, strVal);
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext.get()), &asyncContext->work);
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::GetAccountExtraInfo(napi_env env, napi_callback_info cbInfo)
{
    auto asyncContext = std::make_unique<AppAccountAsyncContext>(env);
    std::vector<PropertyType> propertyList = { PropertyType::NAME };
    napi_value result = nullptr;
    ParseContextForAppAccount(env, cbInfo, asyncContext.get(), propertyList, &result);

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetAccountExtraInfo", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            asyncContext->errCode = AppAccountManager::GetAccountExtraInfo(
                asyncContext->name, asyncContext->extraInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value strVal = nullptr;
            napi_create_string_utf8(env, asyncContext->extraInfo.c_str(), NAPI_AUTO_LENGTH, &strVal);
            ProcessCallbackOrPromise(env, asyncContext,
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode)), strVal);
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext.get()),
        &asyncContext->work);
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::GetAssociatedData(napi_env env, napi_callback_info cbInfo)
{
    return GetCustomDataInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::GetCustomData(napi_env env, napi_callback_info cbInfo)
{
    return GetCustomDataInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::GetCustomDataInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<AppAccountAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = { PropertyType::NAME, PropertyType::KEY };
    napi_value result = nullptr;
    if ((!ParseContextForAppAccount(env, cbInfo, asyncContext.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetAssociatedData", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            NativeErrMsg() = "";
            asyncContext->errCode =
                AppAccountManager::GetAssociatedData(asyncContext->name, asyncContext->key, asyncContext->value);
            asyncContext->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            AppAccountAsyncContext *asyncContext = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value strVal = NapiGetNull(env);
            napi_create_string_utf8(env, asyncContext->value.c_str(), NAPI_AUTO_LENGTH, &strVal);
            napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
            ProcessCallbackOrPromise(env, asyncContext, err, strVal);
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext.get()),
        &asyncContext->work);
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::GetAssociatedDataSync(napi_env env, napi_callback_info cbInfo)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    std::string name;
    std::string key;
    if ((argc < ARGS_SIZE_TWO) || (!GetStringProperty(env, argv[0], name)) ||
        (!GetStringProperty(env, argv[1], key))) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR));
        return nullptr;
    }
    std::string value;
    NativeErrMsg() = "";
    ErrCode errCode = AppAccountManager::GetAssociatedData(name, key, value);
    napi_value result = nullptr;
    if (errCode == ERR_OK) {
        NAPI_CALL(env, napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &result));
    } else if (errCode == ERR_ACCOUNT_COMMON_INVALID_PARAMETER) {
        napi_throw(env, GenerateBusinessError(env, ConvertToJSErrCode(errCode), NativeErrMsg()));
    } else {
        napi_throw(env, GenerateBusinessError(env, errCode));
    }
    return result;
}

napi_value NapiAppAccount::Authenticate(napi_env env, napi_callback_info cbInfo)
{
    return AuthInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::Auth(napi_env env, napi_callback_info cbInfo)
{
    return AuthInternal(env, cbInfo, true);
}

void AuthInternalExecuteCB(napi_env env, void *data)
{
    auto asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
    if ((!asyncContext->throwErr) && (!CheckSpecialCharacters(asyncContext->name))) {
        asyncContext->errCode = ConvertToJSErrCodeV8(ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
        asyncContext->nativeErrMsg = NativeErrMsg();
        return;
    }
    NativeErrMsg() = "";
    ErrCode errCode = AppAccountManager::Authenticate(asyncContext->name, asyncContext->owner,
        asyncContext->authType, asyncContext->options, asyncContext->appAccountMgrCb);
    asyncContext->errCode =
        asyncContext->throwErr ? ConvertToJSErrCode(errCode) : ConvertToJSErrCodeV8(errCode);
    asyncContext->nativeErrMsg = NativeErrMsg();
}

void AuthInternalCompletedCB(napi_env env, napi_status status, void *data)
{
    OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
    AAFwk::Want errResult;
    if ((asyncContext->errCode != 0) && (asyncContext->appAccountMgrCb != nullptr)) {
        asyncContext->appAccountMgrCb->OnResult(asyncContext->errCode, errResult);
    }
    delete asyncContext;
}

napi_value NapiAppAccount::AuthInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<OAuthAsyncContext>(env, isThrowable);
    if (isThrowable) {
        if (!ParseContextForAuth(env, cbInfo, asyncContext.get())) {
            napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
            return NapiGetNull(env);
        }
        asyncContext->options.SetParam(Constants::API_V9, true);
    } else {
        ParseContextForAuthenticate(env, cbInfo, asyncContext.get(), ARGS_SIZE_FIVE);
    }
    napi_value result = nullptr;
    if (asyncContext->appAccountMgrCb == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "Authenticate", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        AuthInternalExecuteCB,
        AuthInternalCompletedCB,
        reinterpret_cast<void *>(asyncContext.get()),
        &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated));
    asyncContext.release();
    return NapiGetNull(env);
}

napi_value NapiAppAccount::GetOAuthToken(napi_env env, napi_callback_info cbInfo)
{
    return GetAuthTokenInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::GetAuthToken(napi_env env, napi_callback_info cbInfo)
{
    return GetAuthTokenInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::GetAuthTokenInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<OAuthAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = { PropertyType::NAME, PropertyType::OWNER, PropertyType::AUTH_TYPE };
    napi_value result = nullptr;
    if ((!ParseContextForOAuth(env, cbInfo, asyncContext.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetOAuthToken", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            auto asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
            NativeErrMsg() = "";
            if (asyncContext->throwErr) {
                asyncContext->errCode = AppAccountManager::GetAuthToken(
                    asyncContext->name, asyncContext->owner, asyncContext->authType, asyncContext->token);
            } else {
                asyncContext->errCode = AppAccountManager::GetOAuthToken(
                    asyncContext->name, asyncContext->owner, asyncContext->authType, asyncContext->token);
            }
            asyncContext->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
            napi_value strVal = nullptr;
            napi_create_string_utf8(env, asyncContext->token.c_str(), NAPI_AUTO_LENGTH, &strVal);
            napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
            ProcessCallbackOrPromise(env, asyncContext, err, strVal);
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext.get()),
        &asyncContext->work);
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::SetOAuthToken(napi_env env, napi_callback_info cbInfo)
{
    return SetAuthTokenInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::SetAuthToken(napi_env env, napi_callback_info cbInfo)
{
    return SetAuthTokenInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::SetAuthTokenInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<OAuthAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = { PropertyType::NAME, PropertyType::AUTH_TYPE, PropertyType::TOKEN };
    napi_value result = nullptr;
    if ((!ParseContextForOAuth(env, cbInfo, asyncContext.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "SetOAuthToken", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
            NativeErrMsg() = "";
            if ((!asyncContext->throwErr) && (!CheckSpecialCharacters(asyncContext->name))) {
                asyncContext->errCode = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
                asyncContext->nativeErrMsg = NativeErrMsg();
                return;
            }
            asyncContext->errCode = AppAccountManager::SetOAuthToken(
                asyncContext->name, asyncContext->authType, asyncContext->token);
            asyncContext->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
            napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
            ProcessCallbackOrPromise(env, asyncContext, err, NapiGetNull(env));
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext.get()),
        &asyncContext->work);
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::DeleteOAuthToken(napi_env env, napi_callback_info cbInfo)
{
    return DeleteAuthTokenInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::DeleteAuthToken(napi_env env, napi_callback_info cbInfo)
{
    return DeleteAuthTokenInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::DeleteAuthTokenInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<OAuthAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = {
        PropertyType::NAME, PropertyType::OWNER, PropertyType::AUTH_TYPE, PropertyType::TOKEN };
    napi_value result = nullptr;
    if ((!ParseContextForOAuth(env, cbInfo, asyncContext.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "DeleteOAuthToken", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resource,
            [](napi_env env, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                NativeErrMsg() = "";
                if (asyncContext->throwErr) {
                    asyncContext->errCode = AppAccountManager::DeleteAuthToken(
                        asyncContext->name, asyncContext->owner, asyncContext->authType, asyncContext->token);
                } else {
                    asyncContext->errCode = AppAccountManager::DeleteOAuthToken(
                        asyncContext->name, asyncContext->owner, asyncContext->authType, asyncContext->token);
                }
                asyncContext->nativeErrMsg = NativeErrMsg();
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                    GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
                ProcessCallbackOrPromise(env, asyncContext, err, NapiGetNull(env));
                delete asyncContext;
            },
            reinterpret_cast<void *>(asyncContext.get()), &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::SetOAuthTokenVisibility(napi_env env, napi_callback_info cbInfo)
{
    return SetAuthTokenVisibilityInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::SetAuthTokenVisibility(napi_env env, napi_callback_info cbInfo)
{
    return SetAuthTokenVisibilityInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::SetAuthTokenVisibilityInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<OAuthAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = {
        PropertyType::NAME, PropertyType::AUTH_TYPE, PropertyType::BUNDLE_NAME, PropertyType::IS_VISIBLE };
    napi_value result = nullptr;
    if ((!ParseContextForOAuth(env, cbInfo, asyncContext.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetOAuthTokenVisibility", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                NativeErrMsg() = "";
                if (asyncContext->throwErr) {
                    asyncContext->errCode = AppAccountManager::SetAuthTokenVisibility(
                        asyncContext->name, asyncContext->authType, asyncContext->bundleName, asyncContext->isVisible);
                } else {
                    asyncContext->errCode = AppAccountManager::SetOAuthTokenVisibility(
                        asyncContext->name, asyncContext->authType, asyncContext->bundleName, asyncContext->isVisible);
                }
                asyncContext->nativeErrMsg = NativeErrMsg();
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                    GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
                ProcessCallbackOrPromise(env, asyncContext, err, NapiGetNull(env));
                delete asyncContext;
            },
            reinterpret_cast<void *>(asyncContext.get()),
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::CheckOAuthTokenVisibility(napi_env env, napi_callback_info cbInfo)
{
    return CheckAuthTokenVisibilityInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::CheckAuthTokenVisibility(napi_env env, napi_callback_info cbInfo)
{
    return CheckAuthTokenVisibilityInternal(env, cbInfo, true);
}

static void CheckAuthTokenVisibilityExecuteCB(napi_env env, void *data)
{
    OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
    NativeErrMsg() = "";
    if (asyncContext->throwErr) {
        asyncContext->errCode = AppAccountManager::CheckAuthTokenVisibility(
            asyncContext->name, asyncContext->authType, asyncContext->bundleName, asyncContext->isVisible);
    } else {
        asyncContext->errCode = AppAccountManager::CheckOAuthTokenVisibility(
            asyncContext->name, asyncContext->authType, asyncContext->bundleName, asyncContext->isVisible);
    }
    asyncContext->nativeErrMsg = NativeErrMsg();
}

static void CheckAuthTokenVisibilityCompleteCB(napi_env env, napi_status status, void *data)
{
    OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
    napi_value boolVal = nullptr;
    napi_get_boolean(env, asyncContext->isVisible, &boolVal);
    napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
        GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
    ProcessCallbackOrPromise(env, asyncContext, err, boolVal);
    delete asyncContext;
}

napi_value NapiAppAccount::CheckAuthTokenVisibilityInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<OAuthAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = {
        PropertyType::NAME, PropertyType::AUTH_TYPE, PropertyType::BUNDLE_NAME };
    napi_value result = nullptr;
    if ((!ParseContextForOAuth(env, cbInfo, asyncContext.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "CheckOAuthTokenVisibility", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        CheckAuthTokenVisibilityExecuteCB, CheckAuthTokenVisibilityCompleteCB,
        reinterpret_cast<void *>(asyncContext.get()), &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::GetAuthenticatorInfo(napi_env env, napi_callback_info cbInfo)
{
    return QueryAuthenticatorInfoInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::QueryAuthenticatorInfo(napi_env env, napi_callback_info cbInfo)
{
    return QueryAuthenticatorInfoInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::QueryAuthenticatorInfoInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<OAuthAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = { PropertyType::OWNER };
    napi_value result = nullptr;
    if ((!ParseContextForOAuth(env, cbInfo, asyncContext.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetAuthenticatorInfo", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                NativeErrMsg() = "";
                asyncContext->errCode = AppAccountManager::GetAuthenticatorInfo(
                    asyncContext->owner, asyncContext->authenticatorInfo);
                asyncContext->nativeErrMsg = NativeErrMsg();
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                napi_value result = nullptr;
                napi_create_object(env, &result);
                GetAuthenticatorInfoForResult(env, asyncContext->authenticatorInfo, result);
                napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                    GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
                ProcessCallbackOrPromise(env, asyncContext, err, result);
                delete asyncContext;
            },
            reinterpret_cast<void *>(asyncContext.get()),
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::GetAllOAuthTokens(napi_env env, napi_callback_info cbInfo)
{
    return GetAllAuthTokensInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::GetAllAuthTokens(napi_env env, napi_callback_info cbInfo)
{
    return GetAllAuthTokensInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::GetAllAuthTokensInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<OAuthAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = { PropertyType::NAME, PropertyType::OWNER };
    napi_value result = nullptr;
    if ((!ParseContextForOAuth(env, cbInfo, asyncContext.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetAllOAuthTokens", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                NativeErrMsg() = "";
                asyncContext->errCode = AppAccountManager::GetAllOAuthTokens(
                    asyncContext->name, asyncContext->owner, asyncContext->oauthTokenInfos);
                asyncContext->nativeErrMsg = NativeErrMsg();
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                napi_value arrVal = nullptr;
                napi_create_array(env, &arrVal);
                GetOAuthTokenInfoForResult(env, asyncContext->oauthTokenInfos, arrVal);
                napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                    GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
                ProcessCallbackOrPromise(env, asyncContext, err, arrVal);
                delete asyncContext;
            },
            reinterpret_cast<void *>(asyncContext.get()),
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::GetOAuthList(napi_env env, napi_callback_info cbInfo)
{
    return GetAuthListInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::GetAuthList(napi_env env, napi_callback_info cbInfo)
{
    return GetAuthListInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::GetAuthListInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<OAuthAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = { PropertyType::NAME, PropertyType::AUTH_TYPE };
    napi_value result = nullptr;
    if ((!ParseContextForOAuth(env, cbInfo, asyncContext.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetOAuthList", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resource,
            [](napi_env env, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                NativeErrMsg() = "";
                if (asyncContext->throwErr) {
                    asyncContext->errCode = AppAccountManager::GetAuthList(
                        asyncContext->name, asyncContext->authType, asyncContext->authList);
                } else {
                    asyncContext->errCode = AppAccountManager::GetOAuthList(
                        asyncContext->name, asyncContext->authType, asyncContext->authList);
                }
                asyncContext->nativeErrMsg = NativeErrMsg();
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                napi_value arrVal = nullptr;
                napi_create_array(env, &arrVal);
                GetOAuthListForResult(env, asyncContext->authList, arrVal);
                napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                    GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
                ProcessCallbackOrPromise(env, asyncContext, err, arrVal);
                delete asyncContext;
            },
            reinterpret_cast<void *>(asyncContext.get()),
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::GetAuthenticatorCallback(napi_env env, napi_callback_info cbInfo)
{
    return GetAuthCallbackInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::GetAuthCallback(napi_env env, napi_callback_info cbInfo)
{
    return GetAuthCallbackInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::GetAuthCallbackInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto asyncContext = std::make_unique<OAuthAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = { PropertyType::SESSION_ID };
    napi_value result = nullptr;
    if ((!ParseContextForOAuth(env, cbInfo, asyncContext.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, asyncContext->errMsg));
        return NapiGetNull(env);
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetAuthenticatorCallback", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resource,
            [](napi_env env, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                NativeErrMsg() = "";
                asyncContext->errCode = AppAccountManager::GetAuthenticatorCallback(
                    asyncContext->sessionId, asyncContext->authenticatorCb);
                asyncContext->nativeErrMsg = NativeErrMsg();
            },
            [](napi_env env, napi_status status, void *data) {
                OAuthAsyncContext *asyncContext = reinterpret_cast<OAuthAsyncContext *>(data);
                napi_value result = nullptr;
                GetAuthenticatorCallbackForResult(env, asyncContext->authenticatorCb, &result);
                napi_value err = asyncContext->throwErr ? GenerateBusinessError(env, asyncContext->errCode) :
                    GetErrorCodeValue(env, ConvertToJSErrCodeV8(asyncContext->errCode));
                ProcessCallbackOrPromise(env, asyncContext, err, result);
                delete asyncContext;
            },
            reinterpret_cast<void *>(asyncContext.get()),
            &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));
    asyncContext.release();
    return result;
}

napi_value NapiAppAccount::CheckAppAccess(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<AppAccountAsyncContext>(env);
    std::vector<PropertyType> propertyList = { PropertyType::NAME, PropertyType::BUNDLE_NAME };
    napi_value result = nullptr;
    if (!ParseContextForAppAccount(env, cbInfo, context.get(), propertyList, &result)) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, context->errMsg));
        return NapiGetNull(env);
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "CheckAppAccess", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            auto context = reinterpret_cast<AppAccountAsyncContext *>(data);
            NativeErrMsg() = "";
            context->errCode = AppAccountManager::CheckAppAccess(
                context->name, context->bundleName, context->isAccessible);
            context->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            auto context = reinterpret_cast<AppAccountAsyncContext *>(data);
            napi_value boolVal = nullptr;
            napi_get_boolean(env, context->isAccessible, &boolVal);
            ProcessCallbackOrPromise(env, context, GenerateBusinessError(env, context->errCode), boolVal);
            delete context;
        },
        reinterpret_cast<void *>(context.get()),
        &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return result;
}

napi_value NapiAppAccount::DeleteAccountCredential(napi_env env, napi_callback_info cbInfo)
{
    return DeleteCredentialInternal(env, cbInfo, false);
}

napi_value NapiAppAccount::DeleteCredential(napi_env env, napi_callback_info cbInfo)
{
    return DeleteCredentialInternal(env, cbInfo, true);
}

napi_value NapiAppAccount::DeleteCredentialInternal(napi_env env, napi_callback_info cbInfo, bool isThrowable)
{
    auto context = std::make_unique<AppAccountAsyncContext>(env, isThrowable);
    std::vector<PropertyType> propertyList = { PropertyType::NAME, PropertyType::CREDENTIAL_TYPE };
    napi_value result = nullptr;
    if ((!ParseContextForAppAccount(env, cbInfo, context.get(), propertyList, &result)) && isThrowable) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, context->errMsg));
        return NapiGetNull(env);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "DeleteAccountCredential", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            auto context = reinterpret_cast<AppAccountAsyncContext *>(data);
            NativeErrMsg() = "";
            context->errCode = AppAccountManager::DeleteAccountCredential(
                context->name, context->credentialType);
            context->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            auto context = reinterpret_cast<AppAccountAsyncContext *>(data);
            if (context->throwErr) {
                ProcessCallbackOrPromise(env, context, GenerateBusinessError(env, context->errCode), NapiGetNull(env));
            } else {
                napi_value ret = nullptr;
                napi_get_undefined(env, &ret);
                ProcessCallbackOrPromise(env, context, GenerateBusinessError(env, context->errCode), ret);
            }
            delete context;
        }, reinterpret_cast<void *>(context.get()), &context->work);
    napi_queue_async_work_with_qos(env, context->work, napi_qos_default);
    context.release();
    return result;
}

napi_value NapiAppAccount::CheckAccountLabels(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<CheckAccountLabelsContext>(env);
    if (!ParseContextForCheckAccountLabels(env, cbInfo, context.get())) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, context->errMsg));
        return NapiGetNull(env);
    }
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
                context->env, context->callbackRef, context->deferred, CheckAccountLabelsOnResultWork);
            if (callback == nullptr) {
                ACCOUNT_LOGE("failed to create AuthenticatorAsyncCallback for insufficient memory");
                context->errCode = ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
                return;
            }
            NativeErrMsg() = "";
            context->errCode = AppAccountManager::CheckAccountLabels(
                context->name, context->owner, context->labels, callback);
            context->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            auto context = reinterpret_cast<CheckAccountLabelsContext *>(data);
            if (context->errCode != ERR_OK) {
                ProcessCallbackOrPromise(env, context, GenerateBusinessError(env, context->errCode), NapiGetNull(env));
            }
            delete context;
        },
        reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return result;
}

napi_value NapiAppAccount::SelectAccountsByOptions(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<SelectAccountsContext>(env);
    if (!ParseContextForSelectAccount(env, cbInfo, context.get())) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, context->errMsg));
        return NapiGetNull(env);
    }
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
                context->env, context->callbackRef, context->deferred, SelectAccountsOnResultWork);
            if (callback == nullptr) {
                ACCOUNT_LOGD("failed to create AuthenticatorAsyncCallback for insufficient memory");
                context->errCode = ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
                return;
            }
            NativeErrMsg() = "";
            context->errCode =
                AppAccountManager::SelectAccountsByOptions(context->options, callback);
            context->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            auto context = reinterpret_cast<SelectAccountsContext *>(data);
            if (context->errCode != ERR_OK) {
                ProcessCallbackOrPromise(env, context, GenerateBusinessError(env, context->errCode), NapiGetNull(env));
            }
            delete context;
        },
        reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return result;
}

napi_value NapiAppAccount::VerifyCredential(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<VerifyCredentialContext>(env);
    if (!ParseContextForVerifyCredential(env, cbInfo, context.get())) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, context->errMsg));
        return NapiGetNull(env);
    }
    context->appAccountMgrCb = new (std::nothrow) AppAccountManagerCallback(env, context->callback);
    if (context->appAccountMgrCb == nullptr) {
        ACCOUNT_LOGD("failed to create AppAccountManagerCallback for insufficient memory");
        AAFwk::WantParams result;
        ProcessOnResultCallback(env, context->callback, ERR_JS_SYSTEM_SERVICE_EXCEPTION, result);
        return NapiGetNull(env);
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "VerifyCredential", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            auto context = reinterpret_cast<VerifyCredentialContext *>(data);
            NativeErrMsg() = "";
            ErrCode errCode = AppAccountManager::VerifyCredential(
                context->name, context->owner, context->options, context->appAccountMgrCb);
            context->errCode = ConvertToJSErrCode(errCode);
            context->nativeErrMsg = NativeErrMsg();
        },
        VerifyCredCompleteCB, reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return NapiGetNull(env);
}

napi_value NapiAppAccount::SetAuthenticatorProperties(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<SetPropertiesContext>(env);
    if (!ParseContextForSetProperties(env, cbInfo, context.get())) {
        napi_throw(env, GenerateBusinessError(env, ERR_JS_PARAMETER_ERROR, context->errMsg));
        return NapiGetNull(env);
    }
    context->appAccountMgrCb = new (std::nothrow) AppAccountManagerCallback(env, context->callback);
    if (context->appAccountMgrCb == nullptr) {
        ACCOUNT_LOGD("failed to create AppAccountManagerCallback for insufficient memory");
        AAFwk::WantParams result;
        ProcessOnResultCallback(env, context->callback, ERR_JS_SYSTEM_SERVICE_EXCEPTION, result);
        return NapiGetNull(env);
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetAuthenticatorProperties", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            auto context = reinterpret_cast<SetPropertiesContext *>(data);
            NativeErrMsg() = "";
            ErrCode errCode = AppAccountManager::SetAuthenticatorProperties(
                context->owner, context->options, context->appAccountMgrCb);
            context->errCode = ConvertToJSErrCode(errCode);
            context->nativeErrMsg = NativeErrMsg();
        },
        [](napi_env env, napi_status status, void *data) {
            auto context = reinterpret_cast<SetPropertiesContext *>(data);
            if ((context->errCode != ERR_JS_SUCCESS) && (context->appAccountMgrCb != nullptr)) {
                AAFwk::Want errResult;
                context->appAccountMgrCb->OnResult(context->errCode, errResult);
            }
            delete context;
        },
        reinterpret_cast<void *>(context.get()),
        &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return NapiGetNull(env);
}

static bool IsExitSubscribe(napi_env env, AsyncContextForSubscribe *context)
{
    auto subscribe = g_AppAccountSubscribers.find(context->appAccountManager);
    if (subscribe == g_AppAccountSubscribers.end()) {
        return false;
    }
    for (size_t index = 0; index < subscribe->second.size(); index++) {
        if (CompareOnAndOffRef(env, subscribe->second[index]->callbackRef, context->callbackRef)) {
            return true;
        }
    }
    return false;
}

napi_value NapiAppAccount::Subscribe(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<AsyncContextForSubscribe>(env);
    if (!ParseParametersBySubscribe(env, cbInfo, context.get())) {
        if (context->type != TYPE_CHANGE) {
            napi_throw(env, GenerateBusinessError(env, context->errCode, context->errMsg));
        }
        return NapiGetNull(env);
    }
    if (context->appAccountManager == nullptr) {
        if (context->type != TYPE_CHANGE) {
            napi_throw(env, GenerateBusinessError(env, ERR_JS_SYSTEM_SERVICE_EXCEPTION,
                std::string("system service exception")));
        }
        return NapiGetNull(env);
    }
    AppAccountSubscribeInfo subscribeInfo(context->owners);
    context->subscriber = std::make_shared<SubscriberPtr>(subscribeInfo);
    if (context->subscriber == nullptr) {
        ACCOUNT_LOGE("fail to create subscriber");
        return NapiGetNull(env);
    }
    context->subscriber->SetEnv(env);
    context->subscriber->SetCallbackRef(context->callbackRef);
    std::lock_guard<std::mutex> lock(g_lockForAppAccountSubscribers);
    if (IsExitSubscribe(env, context.get())) {
        return NapiGetNull(env);
    }
    NativeErrMsg() = "";
    ErrCode errCode = AppAccountManager::SubscribeAppAccount(context->subscriber);
    if (errCode == ERR_ACCOUNT_COMMON_INVALID_PARAMETER) {
        NativeErrMsg() = "Invalid owner. The length of the owner must be greater than 0 and less than 1025";
    }
    if ((errCode != ERR_OK) && (context->type != TYPE_CHANGE)) {
        napi_throw(env, GenerateBusinessError(env, errCode));
        return NapiGetNull(env);
    }
    g_AppAccountSubscribers[context->appAccountManager].emplace_back(context.get());
    context.release();
    return NapiGetNull(env);
}

static void UnsubscribeSync(napi_env env, const AsyncContextForUnsubscribe *context)
{
    std::lock_guard<std::mutex> lock(g_lockForAppAccountSubscribers);
    auto subscribe = g_AppAccountSubscribers.find(context->appAccountManager);
    if (subscribe == g_AppAccountSubscribers.end()) {
        return;
    }
    for (size_t index = 0; index < subscribe->second.size(); ++index) {
        if ((context->callbackRef != nullptr) &&
            (!CompareOnAndOffRef(env, subscribe->second[index]->callbackRef, context->callbackRef))) {
            continue;
        }
        int errCode = AppAccountManager::UnsubscribeAppAccount(subscribe->second[index]->subscriber);
        if (errCode != ERR_OK) {
            napi_throw(env, GenerateBusinessError(env, errCode));
            return;
        }
        delete subscribe->second[index];
        if (context->callbackRef != nullptr) {
            subscribe->second.erase(subscribe->second.begin() + index);
            break;
        }
    }
    if ((context->callbackRef == nullptr) || (subscribe->second.empty())) {
        g_AppAccountSubscribers.erase(subscribe);
    }
}

napi_value NapiAppAccount::Unsubscribe(napi_env env, napi_callback_info cbInfo)
{
    AsyncContextForUnsubscribe *context = new (std::nothrow) AsyncContextForUnsubscribe(env);
    if (context == nullptr) {
        ACCOUNT_LOGE("asyncContextForOff is null");
        return NapiGetNull(env);
    }
    if (!ParseParametersByUnsubscribe(env, cbInfo, context)) {
        if (context->type != TYPE_CHANGE) {
            napi_throw(env, GenerateBusinessError(env, context->errCode, context->errMsg));
        }
        delete context;
        return NapiGetNull(env);
    };
    if (context->type == TYPE_CHANGE) {
        bool isFind = false;
        std::vector<std::shared_ptr<SubscriberPtr>> subscribers = {nullptr};
        napi_value result = GetSubscriberByUnsubscribe(env, subscribers, context, isFind);
        if (!result) {
            ACCOUNT_LOGE("Unsubscribe failed. The current subscriber does not exist");
            delete context;
            return NapiGetNull(env);
        }
        context->subscribers = subscribers;

        napi_value resourceName = nullptr;
        napi_create_string_latin1(env, "Unsubscribe", NAPI_AUTO_LENGTH, &resourceName);

        napi_create_async_work(env, nullptr, resourceName, UnsubscribeExecuteCB, UnsubscribeCallbackCompletedCB,
            reinterpret_cast<void *>(context), &context->work);
        napi_queue_async_work_with_qos(env, context->work, napi_qos_default);
    } else {
        UnsubscribeSync(env, context);
        delete context;
    }
    return NapiGetNull(env);
}
}  // namespace AccountJsKit
}  // namespace OHOS

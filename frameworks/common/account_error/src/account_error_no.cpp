/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "account_error_no.h"
#include <unordered_map>

namespace OHOS {
static const std::unordered_map<uint32_t, std::string> g_errorStringMap = {
    {ERR_JS_PARAMETER_ERROR, "Parameter invalid, please input the correct parameter"},
    {ERR_JS_ACCOUNT_NOT_FOUND, "Account not found, please check whether the account exists"},
    {ERR_JS_IS_NOT_SYSTEM_APP, "This api is system api, Please use the system application to call this api"},
    {ERR_JS_ACCOUNT_ALREADY_EXIST, "Account already exists, please cancel or try other account"},
    {ERR_JS_ACCOUNT_ALREADY_ACTIVATED, "Account already activated, do not activate duplicately"},
    {ERR_JS_ACCOUNT_SERVICE_BUSY, "Account service is busy, please wait for a moment and try again"},
    {ERR_JS_ACCOUNT_NUMBER_REACH_LIMIT, "Account number limit exceeded, please try again after delete other accounts"},
    {ERR_JS_MULTI_USER_NOT_SUPPORT, "Multiple users not supported, please cancel the creation"},
    {ERR_JS_ACCOUNT_TYPE_NOT_SUPPORT, "Account type not supported, please create a non administrator account"},
    {ERR_JS_ACCOUNT_RESTRICTED, "Account is restricted, the operation account ID is the reserved for system"},
    {ERR_JS_LISTENER_ALREADY_REGISTERED,
     "Listener is already registered, please register new listener or delete old listener and try again"},
    {ERR_JS_LISTENER_NOT_REGISTERED, "Listener is not registered, please use the registered listener"},
    {ERR_JS_CREDENTIAL_INPUTER_ALREADY_EXIST, "PIN inputer is already registered, please do not repeat register"},
    {ERR_JS_SYSTEM_SERVICE_EXCEPTION, "System service exception. Possible causes:"
        "(1)IPC communication failure;"
        "(2)Insufficient memory;"
        "(3)Insufficient disk space;"
        "(4)Inability to start necessary system services."
        "Please try again or restart your device"},
    {ERR_JS_INVALID_PARAMETER, "Parameter invalid, please input the correct parameter"},
    {ERR_JS_TRUST_LEVEL_NOT_SUPPORTED, "Trust level not supported, please input the correct trust level"},
    {ERR_JS_AUTH_TYPE_NOT_SUPPORTED, "Auth type not supported, please input the correct auth type"},
    {ERR_JS_AUTH_TIMEOUT, "Auth timeout, please try again or check your internet connection"},
    {ERR_JS_AUTH_SERVICE_BUSY, "Auth service is busy, please try again later"},
    {ERR_JS_AUTH_SERVICE_LOCKED,
     "Auth service is locked, auth fail too many times, please try again after freezingTime"},
    {ERR_JS_CREDENTIAL_NOT_EXIST, "Credential not found, please check whether credential exists and try again"},
    {ERR_JS_INVALID_CONTEXT_ID, "Context ID is invalid, please check the context ID and try again"},
    {ERR_JS_AUTH_CREDENTIAL_WRONG_ERROR,
     "Auth credential incorrect, please check the password or credential, and try again"},
    {ERR_JS_APPLICATION_NOT_EXIST, "Application not found, please check the bundle name and try again"},
    {ERR_JS_ACCOUNT_AUTHENTICATOR_NOT_EXIST, "Application account authenticator service is not available, please try "
                                             "again with applications that support authenticator service"},
    {ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION,
     "Application account authenticator service exception, please try again or reboot your device"},
    {ERR_JS_SESSION_NOT_EXIST,
     "Application account session is not exists, please use sessionId that successfully opened"},
    {ERR_JS_AUTHORIZATION_LIST_TOO_LARGE,
     "Application account authorization list is too large, please cancel some existed authentications and try again"},
    {ERR_JS_TOKEN_NUMBER_REACH_LIMIT,
     "Application account token number reach limitations, please delete some existed token and try again"},
    {ERR_JS_CUSTOM_DATA_NUMBER_REACH_LIMIT,
     "Application account customized data number reach limit, please delete some existed custom data and try again"},
    {ERR_JS_CUSTOM_DATA_NOT_FOUND,
     "Application account customized data not found, please use existed customized data and try again"},
    {ERR_JS_AUTH_TYPE_NOT_FOUND, "Application account auth type not found, please use existed auth type"},
    {ERR_JS_PERMISSION_DENIED, "Permission denied"},
    {ERR_JS_PLUGIN_NETWORK_EXCEPTION, "Network exception"},
    {ERR_JS_CAPABILITY_NOT_SUPPORTED, "capability not supported"},
    {ERR_JS_ACCOUNT_LOGGED_IN_ACCOUNTS_OVERSIZE, "The number of the logged in OS accounts reaches upper limit"},
    {ERR_JS_COMPLEXITY_CHECK_FAILED, "The complexity of credential check failed"},
    {ERR_JS_PIN_IS_EXPIRED, "The PIN credential is expired"},
    {ERR_JS_DOMAIN_PLUGIN_ALREADY_REGISTERED, "The domain plugin is already registered"},
    {ERR_JS_SERVER_UNREACHABLE, "The server is unreachable"},
    {ERR_JS_SERVER_CONFIG_NOT_FOUND, "The server config not found"},
    {ERR_JS_SERVER_CONFIG_ALREADY_EXISTS, "Server config already exists"},
    {ERR_JS_SERVER_CONFIG_ASSOCIATED_ACCOUNT, "Server config has been associated with an account"},
    {ERR_JS_SERVER_CONFIG_UPPER_LIMIT, "The number of server config reaches the upper limit"},
    {ERR_JS_OS_ACCOUNT_ALREADY_BOUND, "The OS account is already bound."},
    {ERR_JS_DOMAIN_ACCOUNT_ALREADY_BOUND, "The domain account is already bound."},
    {ERR_JS_AUTH_CANCELLED, "The authentication, enrollment, or update operation is canceled."},
    {ERR_JS_ACCOUNT_CROSS_DEVICE_CAPABILITY_NOT_SUPPORT, "Cross-device capability not supported"},
    {ERR_JS_ACCOUNT_CROSS_DEVICE_COMMUNICATION_FAILED, "Cross-device communication failed"},
    {ERR_JS_FOREGROUND_OS_ACCOUNT_NOT_FOUND, "The foreground OS account is not found"},
    {ERR_JS_DISPLAY_NOT_FOUND, "Display not found"},
    {ERR_JS_CROSS_DISPLAY_ACTIVATION_NOT_SUPPORTED, "Cross-display activation not supported"},
};

const std::unordered_map<int32_t, int32_t> errorMap = {
    { ERR_OK, ERR_JS_SUCCESS },
    { ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, ERR_JS_IS_NOT_SYSTEM_APP },
    { ERR_ACCOUNT_COMMON_INVALID_PARAMETER, ERR_JS_INVALID_PARAMETER },
    { ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, ERR_JS_ACCOUNT_NOT_FOUND },
    { ERR_ACCOUNT_COMMON_NOT_AUTHENTICATED, ERR_JS_ACCOUNT_NOT_AUTHENTICATED }
};

static const std::unordered_map<int32_t, int32_t> IAM_ERRCODE_MAP = {
    {ERR_IAM_SUCCESS, ERR_JS_SUCCESS},
    {ERR_IAM_FAIL, ERR_JS_AUTH_CREDENTIAL_WRONG_ERROR},
    {ERR_IAM_AUTH_TOKEN_CHECK_FAILED, ERR_JS_AUTH_CREDENTIAL_WRONG_ERROR},
    {ERR_IAM_AUTH_TOKEN_EXPIRED, ERR_JS_AUTH_CREDENTIAL_WRONG_ERROR},
    {ERR_IAM_TOKEN_TIMEOUT, ERR_JS_AUTH_CREDENTIAL_WRONG_ERROR},
    {ERR_IAM_TOKEN_AUTH_FAILED, ERR_JS_AUTH_CREDENTIAL_WRONG_ERROR},
    {ERR_IAM_TRUST_LEVEL_NOT_SUPPORT, ERR_JS_TRUST_LEVEL_NOT_SUPPORTED},
    {ERR_IAM_TYPE_NOT_SUPPORT, ERR_JS_AUTH_TYPE_NOT_SUPPORTED},
    {ERR_IAM_TIMEOUT, ERR_JS_AUTH_TIMEOUT},
    {ERR_IAM_CANCELED, ERR_JS_AUTH_CANCELLED},
    {ERR_IAM_BUSY, ERR_JS_AUTH_SERVICE_BUSY},
    {ERR_IAM_LOCKED, ERR_JS_AUTH_SERVICE_LOCKED},
    {ERR_IAM_NOT_ENROLLED, ERR_JS_CREDENTIAL_NOT_EXIST},
    {ERR_IAM_PIN_IS_EXPIRED, ERR_JS_PIN_IS_EXPIRED},
    {ERR_IAM_COMPLEXITY_CHECK_FAILED, ERR_JS_COMPLEXITY_CHECK_FAILED},
    {ERR_IAM_INVALID_CONTEXT_ID, ERR_JS_INVALID_CONTEXT_ID},
    {ERR_ACCOUNT_COMMON_INVALID_PARAMETER, ERR_JS_INVALID_PARAMETER},
    {ERR_IAM_INVALID_PARAMETERS, ERR_JS_INVALID_PARAMETER},
    {ERR_ACCOUNT_IAM_KIT_INPUTER_ALREADY_REGISTERED, ERR_JS_CREDENTIAL_INPUTER_ALREADY_EXIST},
    {ERR_ACCOUNT_IAM_KIT_INPUTER_NOT_REGISTERED, ERR_JS_CREDENTIAL_INPUTER_NOT_EXIST},
    {ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE, ERR_JS_AUTH_TYPE_NOT_SUPPORTED},
    {ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT, ERR_JS_AUTH_TYPE_NOT_SUPPORTED},
    {ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST, ERR_JS_AUTH_TYPE_NOT_SUPPORTED},
    {ERR_IAM_CREDENTIAL_NUMBER_REACH_LIMIT, ERR_JS_CREDENTIAL_NUMBER_REACH_LIMIT},
    {ERR_IAM_SESSION_TIMEOUT, ERR_JS_SESSION_TIMEOUT},
    {ERR_IAM_CHECK_SYSTEM_APP_FAILED, ERR_JS_IS_NOT_SYSTEM_APP}
};

static int32_t AccountIAMConvertOtherToJSErrCode(int32_t errCode)
{
    auto it = IAM_ERRCODE_MAP.find(errCode);
    if (it == IAM_ERRCODE_MAP.end()) {
        return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
    }
    return it->second;
}

int32_t AccountIAMConvertToJSErrCode(int32_t errCode)
{
    if (CheckJsErrorCode(errCode)) {
        return errCode;
    }
    if (errCode == ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR) {
        return ERR_JS_IS_NOT_SYSTEM_APP;
    } else if (errCode == ERR_ACCOUNT_COMMON_PERMISSION_DENIED || errCode == ERR_IAM_CHECK_PERMISSION_FAILED) {
        return ERR_JS_PERMISSION_DENIED;
    } else if (errCode == ERR_ACCOUNT_COMMON_INVALID_PARAMETER) {
        return ERR_JS_INVALID_PARAMETER;
    } else if (errCode == ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR) {
        return ERR_JS_ACCOUNT_NOT_FOUND;
    } else if (errCode == ERR_ACCOUNT_COMMON_ACCOUNT_IS_RESTRICTED) {
        return ERR_JS_ACCOUNT_RESTRICTED;
    } else if (errCode == ERR_IAM_CROSS_DEVICE_COMMUNICATION_FAILED) {
        return ERR_JS_ACCOUNT_CROSS_DEVICE_COMMUNICATION_FAILED;
    } else if (errCode == ERR_IAM_CROSS_DEVICE_CAPABILITY_NOT_SUPPORT) {
        return ERR_JS_ACCOUNT_CROSS_DEVICE_CAPABILITY_NOT_SUPPORT;
    } else {
        return AccountIAMConvertOtherToJSErrCode(errCode);
    }
}

bool CheckJsErrorCode(int32_t errCode)
{
    auto iter = g_errorStringMap.find(errCode);
    if (iter == g_errorStringMap.end()) {
        return false;
    }
    return true;
}

int32_t GenerateBusinessErrorCode(int32_t nativeErrCode)
{
    int32_t jsErrCode = nativeErrCode;
    auto iter = g_errorStringMap.find(jsErrCode);
    if (iter == g_errorStringMap.end()) {
        jsErrCode = ConvertToJSErrCode(nativeErrCode);
    }
    return jsErrCode;
}

std::string ConvertToJsErrMsg(int32_t jsErrCode)
{
    auto iter = g_errorStringMap.find(jsErrCode);
    if (iter != g_errorStringMap.end()) {
        return iter->second;
    } else {
        return "Unknown error, please reboot your device and try again";
    }
}

int32_t AppAccountConvertOtherJSErrCode(int32_t errCode)
{
    switch (errCode) {
        case ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST:
        case ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID:
            return ERR_JS_ACCOUNT_NOT_FOUND;
        case ERR_APPACCOUNT_SERVICE_ADD_EXISTING_ACCOUNT:
            return ERR_JS_ACCOUNT_ALREADY_EXIST;
        case ERR_APPACCOUNT_SERVICE_ACCOUNT_MAX_SIZE:
            return ERR_JS_ACCOUNT_NUMBER_REACH_LIMIT;
        case ERR_APPACCOUNT_SUBSCRIBER_ALREADY_REGISTERED:
            return ERR_JS_LISTENER_ALREADY_REGISTERED;
        case ERR_APPACCOUNT_SERVICE_ASSOCIATED_DATA_OVER_SIZE:
            return ERR_JS_CUSTOM_DATA_NUMBER_REACH_LIMIT;
        case ERR_APPACCOUNT_SERVICE_ASSOCIATED_DATA_KEY_NOT_EXIST:
            return ERR_JS_CUSTOM_DATA_NOT_FOUND;
        case ERR_APPACCOUNT_SERVICE_ACCOUNT_CREDENTIAL_NOT_EXIST:
            return ERR_JS_CREDENTIAL_NOT_EXIST;
        case ERR_APPACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED:
            return ERR_JS_LISTENER_NOT_REGISTERED;
        case ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST:
            return ERR_JS_ACCOUNT_AUTHENTICATOR_NOT_EXIST;
        case ERR_APPACCOUNT_SERVICE_OAUTH_BUSY:
            return ERR_JS_ACCOUNT_SERVICE_BUSY;
        case ERR_APPACCOUNT_SERVICE_OAUTH_LIST_MAX_SIZE:
            return ERR_JS_AUTHORIZATION_LIST_TOO_LARGE;
        case ERR_APPACCOUNT_SERVICE_OAUTH_SESSION_NOT_EXIST:
        case ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_CALLBACK_NOT_EXIST:
            return ERR_JS_SESSION_NOT_EXIST;
        case ERR_APPACCOUNT_SERVICE_OAUTH_TYPE_NOT_EXIST:
        case ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST:
            return ERR_JS_AUTH_TYPE_NOT_FOUND;
        case ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_MAX_SIZE:
            return ERR_JS_TOKEN_NUMBER_REACH_LIMIT;
        default:
            return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
    }
}

int32_t AppAccountConvertToJSErrCode(int32_t errCode)
{
    if (errCode == ERR_ACCOUNT_COMMON_PERMISSION_DENIED) {
        return ERR_JS_PERMISSION_DENIED;
    } else if (errCode == ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME ||
        errCode == ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO ||
        errCode == ERR_APPACCOUNT_SERVICE_DISABLE_APP_ACCESS_NOT_EXISTED) {
        return ERR_JS_APPLICATION_NOT_EXIST;
    } else if (errCode == ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION) {
        return ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION;
    } else {
        return AppAccountConvertOtherJSErrCode(errCode);
    }
}

int32_t OsAccountConvertToJSErrCode(int32_t errCode)
{
    if (errCode == ERR_ACCOUNT_COMMON_INVALID_PARAMETER) {
        return ERR_JS_INVALID_PARAMETER;
    }
    switch (errCode) {
        case ERR_OSACCOUNT_SERVICE_INNER_SELECT_ERROR:
        case ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR:
            return ERR_JS_ACCOUNT_NOT_FOUND;
        case ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR:
        case ERR_ACCOUNT_COMMON_NAME_HAD_EXISTED:
            return ERR_JS_ACCOUNT_ALREADY_EXIST;
        case ERR_ACCOUNT_COMMON_SHORT_NAME_HAD_EXISTED:
            return ERR_JS_ACCOUNT_SHORT_NAME_ALREADY_EXIST;
        case ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_ALREADY_ACTIVE_ERROR:
            return ERR_JS_ACCOUNT_ALREADY_ACTIVATED;
        case ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR:
            return ERR_JS_ACCOUNT_NUMBER_REACH_LIMIT;
        case ERR_OSACCOUNT_SERVICE_LOGGED_IN_ACCOUNTS_OVERSIZE:
            return ERR_JS_ACCOUNT_LOGGED_IN_ACCOUNTS_OVERSIZE;
        case ERR_OSACCOUNT_SERVICE_MANAGER_NOT_ENABLE_MULTI_ERROR:
            return ERR_JS_MULTI_USER_NOT_SUPPORT;
        case ERR_OSACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR:
            return ERR_JS_ACCOUNT_TYPE_NOT_SUPPORT;
        case ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR:
        case ERR_OSACCOUNT_SERVICE_CONTROL_CANNOT_DELETE_ID_ERROR:
        case ERR_OSACCOUNT_SERVICE_CONTROL_ID_CANNOT_CREATE_ERROR:
        case ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_STOP_ACTIVE_ERROR:
            return ERR_JS_ACCOUNT_RESTRICTED;
        case ERR_OSACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED:
            return ERR_JS_LISTENER_NOT_REGISTERED;
        case ERR_ACCOUNT_COMMON_PERMISSION_DENIED:
            return ERR_JS_PERMISSION_DENIED;
        case ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR:
            return ERR_JS_ACCOUNT_SERVICE_BUSY;
        case ERR_OSACCOUNT_SERVICE_INNER_OS_ACCOUNT_ALREADY_BOUND:
            return ERR_JS_OS_ACCOUNT_ALREADY_BOUND;
        case ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ACCOUNT_ALREADY_BOUND:
            return ERR_JS_DOMAIN_ACCOUNT_ALREADY_BOUND;
        case ERR_ACCOUNT_COMMON_ACCOUNT_IN_DISPLAY_ID_NOT_FOUND_ERROR:
            return ERR_JS_FOREGROUND_OS_ACCOUNT_NOT_FOUND;
        case ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR:
            return ERR_JS_DISPLAY_NOT_FOUND;
        case ERR_ACCOUNT_COMMON_CROSS_DISPLAY_ACTIVE_ERROR:
            return ERR_JS_CROSS_DISPLAY_ACTIVATION_NOT_SUPPORTED;
        default:
            return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
    }
}

static int32_t DomainAccountConvertToJSErrCode(int32_t errCode)
{
    switch (errCode) {
        case ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_ALREADY_EXIST:
            return ERR_JS_DOMAIN_PLUGIN_ALREADY_REGISTERED;
        case ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT:
            return ERR_JS_ACCOUNT_NOT_FOUND;
        case ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST:
        case ERR_DOMAIN_ACCOUNT_NOT_SUPPORT:
            return ERR_JS_CAPABILITY_NOT_SUPPORTED;
        case ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST:
            return ERR_JS_CAPABILITY_NOT_SUPPORTED;
        default:
            return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
    }
}

static bool IsAppAccountKitError(int32_t errCode)
{
    return (errCode >= ERR_APPACCOUNT_KIT_GET_APP_ACCOUNT_SERVICE &&
        errCode <= ERR_APPACCOUNT_KIT_READ_PARCELABLE_VECTOR_ACCOUNT_INFO);
}

static bool IsAppAccountServiceError(int32_t errCode)
{
    return (errCode >= ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST && errCode <= ERR_APPACCOUNT_SERVICE_OTHER);
}

static bool IsOsAccountKitError(int32_t errCode)
{
    return (errCode >= ERR_OSACCOUNT_KIT_CREATE_OS_ACCOUNT_FOR_DOMAIN_ERROR &&
        errCode <= ERR_OSACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED);
}

static bool IsOsAccountServiceError(int32_t errCode)
{
    return ((errCode >= ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR) &&
            (errCode <= ERR_OS_ACCOUNT_SERVICE_CODE_END)) ||
           (errCode == ERR_ACCOUNT_COMMON_NAME_HAD_EXISTED) ||
           (errCode == ERR_ACCOUNT_COMMON_SHORT_NAME_HAD_EXISTED) ||
           (errCode == ERR_ACCOUNT_COMMON_ACCOUNT_IN_DISPLAY_ID_NOT_FOUND_ERROR) ||
           (errCode == ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR) ||
           (errCode == ERR_ACCOUNT_COMMON_CROSS_DISPLAY_ACTIVE_ERROR);
}

static bool IsDomainAccountServiceError(int32_t errCode)
{
    return (errCode >= ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_ALREADY_EXIST) &&
        (errCode <= ERR_DOMAIN_ACCOUNT_SERVICE_ERR_CODE_LIMIT);
}

int32_t ConvertToJSErrCode(int32_t nativeErrCode)
{
    auto it = errorMap.find(nativeErrCode);
    if (it != errorMap.end()) {
        return it->second;
    }
    if (IsAppAccountKitError(nativeErrCode) || IsAppAccountServiceError(nativeErrCode)) {
        return AppAccountConvertToJSErrCode(nativeErrCode);
    } else if (IsOsAccountKitError(nativeErrCode) || IsOsAccountServiceError(nativeErrCode)) {
        return OsAccountConvertToJSErrCode(nativeErrCode);
    } else if (IsDomainAccountServiceError(nativeErrCode)) {
        return DomainAccountConvertToJSErrCode(nativeErrCode);
    } else if (nativeErrCode == ERR_ACCOUNT_COMMON_PERMISSION_DENIED) {
        return ERR_JS_PERMISSION_DENIED;
    } else {
        return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
    }
}

std::string &NativeErrMsg()
{
    thread_local static std::string nativeErrMsg;
    return nativeErrMsg;
}
}  // namespace OHOS
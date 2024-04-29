/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <map>

namespace OHOS {
const std::map<int32_t, int32_t> errorMap = {
    { ERR_OK, ERR_JS_SUCCESS },
    { ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, ERR_JS_IS_NOT_SYSTEM_APP },
    { ERR_ACCOUNT_COMMON_INVALID_PARAMETER, ERR_JS_INVALID_PARAMETER },
    { ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, ERR_JS_ACCOUNT_NOT_FOUND },
    { ERR_ACCOUNT_COMMON_NOT_AUTHENTICATED, ERR_JS_ACCOUNT_NOT_AUTHENTICATED }
};

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
           (errCode <= ERR_OSACCOUNT_SERVICE_STORAGE_PREPARE_ADD_USER_FAILED)) ||
           (errCode == ERR_ACCOUNT_COMMON_NAME_HAD_EXISTED) || (errCode == ERR_ACCOUNT_COMMON_SHORT_NAME_HAD_EXISTED);
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
}  // namespace OHOS
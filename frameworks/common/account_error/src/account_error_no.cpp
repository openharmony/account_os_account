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

namespace OHOS {
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
    if ((errCode >= ERR_APPACCOUNT_KIT_NAME_IS_EMPTY && errCode <= ERR_APPACCOUNT_KIT_INVALID_PARAMETER) ||
        (errCode >= ERR_APPACCOUNT_SERVICE_NAME_IS_EMPTY && errCode <= ERR_APPACCOUNT_SERVICE_INVALID_PARAMETER)) {
        return ERR_JS_INVALID_PARAMETER;
    } else if (errCode == ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED ||
        errCode == ERR_APPACCOUNT_SERVICE_SUBSCRIBE_PERMISSION_DENIED) {
        return ERR_JS_PERMISSION_DENIED;
    } else if (errCode == ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME ||
        errCode == ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO ||
        errCode == ERR_APPACCOUNT_SERVICE_DISABLE_APP_ACCESS_NOT_EXISTED) {
        return ERR_JS_APPLICATION_NOT_EXIST;
    } else if (errCode == ERR_APPACCOUNT_SERVICE_AUTHENTICATOR_MANAGER_PTR_IS_NULLPTR ||
        errCode == ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION) {
        return ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION;
    } else {
        return AppAccountConvertOtherJSErrCode(errCode);
    }
}

int32_t OsAccountConvertToJSErrCode(int32_t errCode)
{
    if ((errCode >= ERR_OSACCOUNT_KIT_LOCAL_NAME_OUTFLOW_ERROR && errCode <= ERR_OSACCOUNT_KIT_TYPE_ERROR) ||
        (errCode >= ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR &&
        errCode <= ERR_OSACCOUNT_SERVICE_MANAGER_DOMAIN_SIZE_OVERFLOW_ERROR)) {
        return ERR_JS_INVALID_PARAMETER;
    }
    if (errCode == ERR_ACCOUNT_COMMON_INVALID_PARAMTER) {
        return ERR_JS_INVALID_PARAMETER;
    }
    switch (errCode) {
        case ERR_OSACCOUNT_SERVICE_CONTROL_SELECT_OS_ACCOUNT_ERROR:
        case ERR_OSACCOUNT_SERVICE_INNER_CANNOT_FIND_OSACCOUNT_ERROR:
        case ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR:
            return ERR_JS_ACCOUNT_NOT_FOUND;
        case ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR:
            return ERR_JS_ACCOUNT_ALREADY_EXIST;
        case ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_ALREADY_ACTIVE_ERROR:
            return ERR_JS_ACCOUNT_ALREADY_ACTIVATED;
        case ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR:
            return ERR_JS_ACCOUNT_NUMBER_REACH_LIMIT;
        case ERR_OSACCOUNT_SERVICE_MANAGER_NOT_ENABLE_MULTI_ERROR:
            return ERR_JS_MULTI_USER_NOT_SUPPORT;
        case ERR_OSACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR:
            return ERR_JS_ACCOUNT_TYPE_NOT_SUPPORT;
        case ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR:
        case ERR_OSACCOUNT_SERVICE_CONTROL_CANNOT_DELETE_ID_ERROR:
        case ERR_OSACCOUNT_SERVICE_CONTROL_ID_CANNOT_CREATE_ERROR:
            return ERR_JS_ACCOUNT_RESTRICTED;
        case ERR_OSACCOUNT_SERVICE_MANAGER_PHOTO_SIZE_OVERFLOW_ERROR:
        case ERR_OSACCOUNT_KIT_PHOTO_OUTFLOW_ERROR:
        case ERR_OSACCOUNT_SERVICE_CONTROL_PHOTO_STR_ERROR:
        case ERR_OSACCOUNT_SERVICE_MANAGER_BAD_UID_ERROR:
            return ERR_JS_INVALID_PARAMETER;
        case ERR_OSACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED:
            return ERR_JS_LISTENER_NOT_REGISTERED;
        case ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED:
            return ERR_JS_PERMISSION_DENIED;
        default:
            return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
    }
}

static int32_t DomainAccountConvertToJSErrCode(int32_t errCode)
{
    switch (errCode) {
        case ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_ALREADY_EXIST:
            return ERR_JS_DOMAIN_PLUGIN_ALREADY_REGISTERED;
        default:
            return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
    }
}

static bool IsAppAccountKitError(int32_t errCode)
{
    return (errCode >= ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER &&
        errCode <= ERR_APPACCOUNT_KIT_READ_PARCELABLE_VECTOR_ACCOUNT_INFO);
}

static bool IsAppAccountServiceError(int32_t errCode)
{
    return (errCode >= ERR_APPACCOUNT_SERVICE_NAME_IS_EMPTY && errCode <= ERR_APPACCOUNT_SERVICE_OTHER);
}

static bool IsOsAccountKitError(int32_t errCode)
{
    return (errCode >= ERR_OSACCOUNT_KIT_WRITE_LOCALNAME_ERROR &&
        errCode <= ERR_OSACCOUNT_KIT_QUERY_ACTIVE_OS_ACCOUNT_IDS_ERROR);
}

static bool IsOsAccountServiceError(int32_t errCode)
{
    return (errCode >= ERR_OSACCOUNT_SERVICE_MANAGER_BAD_UID_ERROR &&
        errCode <= ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_SPECIFIC_CONSTRAINTS_FILE_EMPTY);
}

static bool IsDomainAccountServiceError(int32_t errCode)
{
    return (errCode >= ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_ALREADY_EXIST) &&
        (errCode <= ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
}

int32_t ConvertToJSErrCode(int32_t nativeErrCode)
{
    if (nativeErrCode == ERR_OK) {
        return ERR_JS_SUCCESS;
    }
    if (nativeErrCode == ERR_ACCOUNT_COMMON_INVALID_PARAMTER) {
        return ERR_JS_INVALID_PARAMETER;
    }
    if (IsAppAccountKitError(nativeErrCode) || IsAppAccountServiceError(nativeErrCode)) {
        return AppAccountConvertToJSErrCode(nativeErrCode);
    } else if (IsOsAccountKitError(nativeErrCode) || IsOsAccountServiceError(nativeErrCode)) {
        return OsAccountConvertToJSErrCode(nativeErrCode);
    } else if (IsDomainAccountServiceError(nativeErrCode)) {
        return DomainAccountConvertToJSErrCode(nativeErrCode);
    } else if (nativeErrCode == ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR) {
        return ERR_JS_PERMISSION_DENIED;
    } else {
        return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
    }
}
}  // namespace OHOS
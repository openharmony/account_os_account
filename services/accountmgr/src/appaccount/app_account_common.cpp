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

#include "app_account_common.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "app_account_constants.h"

namespace OHOS {
namespace AccountSA {
int32_t ConvertToJSErrCode(int32_t errCode)
{
    switch (errCode) {
        case ERR_OK:
            return ERR_JS_SUCCESS;
        case ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST:
            return ERR_JS_ACCOUNT_NOT_EXIST;
        case ERR_APPACCOUNT_KIT_INVALID_PARAMETER:
        case ERR_APPACCOUNT_SERVICE_INVALID_PARAMETER:
            return ERR_JS_INVALID_REQUEST;
        case ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE:
            return ERR_JS_INVALID_RESPONSE;
        case ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST:
            return ERR_JS_OAUTH_AUTHENTICATOR_NOT_EXIST;
        case ERR_APPACCOUNT_SERVICE_OAUTH_BUSY:
            return ERR_JS_OAUTH_SERVICE_BUSY;
        case ERR_APPACCOUNT_SERVICE_OAUTH_LIST_MAX_SIZE:
            return ERR_JS_OAUTH_LIST_TOO_LARGE;
        case ERR_APPACCOUNT_SERVICE_OAUTH_SESSION_NOT_EXIST:
            return ERR_JS_OAUTH_SESSION_NOT_EXIST;
        case ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST:
            return ERR_JS_OAUTH_TOKEN_NOT_EXIST;
        case ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_MAX_SIZE:
            return ERR_JS_OAUTH_TOKEN_TOO_MANY;
        case ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED:
            return ERR_JS_PERMISSION_DENIED;
        default:
            return ERR_JS_APP_ACCOUNT_SERVICE_EXCEPTION;
    }
}
}  // namespace AccountSA
}  // namespace OHOS
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

#include "napi_app_account_constant.h"

#include "account_log_wrapper.h"
#include "app_account_common.h"
#include "app_account_constants.h"
#include "napi_app_account_common.h"

namespace OHOS {
namespace AccountJsKit {
namespace {
const char OAUTH_ACTION_ADD_ACCOUNT_IMPLICITLY[] = "addAccountImplicitly";
const char OAUTH_ACTION_AUTHENTICATE[] = "authenticate";
const char ACTION_CREATE_ACCOUNT_IMPLICITLY[] = "createAccountImplicitly";
const char ACTION_AUTH[] = "auth";
const char ACTION_VERIFY_CREDENTIAL[] = "verifyCredential";
const char ACTION_SET_AUTHENTICATOR_PROPERTIES[] = "setAuthenticatorProperties";
const char KEY_OWNER[] = "owner";
const char KEY_REQUIRED_LABELS[] = "requiredLabels";
}

static void ResultCodeInit(napi_env env, napi_value *resultCode)
{
    SetNamedProperty(env, (*resultCode), ERR_JS_SUCCESS_V8, "SUCCESS");
    SetNamedProperty(env, (*resultCode), ERR_JS_ACCOUNT_NOT_EXIST, "ERROR_ACCOUNT_NOT_EXIST");
    SetNamedProperty(env, (*resultCode), ERR_JS_APP_ACCOUNT_SERVICE_EXCEPTION, "ERROR_APP_ACCOUNT_SERVICE_EXCEPTION");
    SetNamedProperty(env, (*resultCode), ERR_JS_INVALID_PASSWORD, "ERROR_INVALID_PASSWORD");
    SetNamedProperty(env, (*resultCode), ERR_JS_INVALID_REQUEST, "ERROR_INVALID_REQUEST");
    SetNamedProperty(env, (*resultCode), ERR_JS_INVALID_RESPONSE, "ERROR_INVALID_RESPONSE");
    SetNamedProperty(env, (*resultCode), ERR_JS_NETWORK_EXCEPTION, "ERROR_NETWORK_EXCEPTION");
    SetNamedProperty(env, (*resultCode), ERR_JS_OAUTH_AUTHENTICATOR_NOT_EXIST, "ERROR_OAUTH_AUTHENTICATOR_NOT_EXIST");
    SetNamedProperty(env, (*resultCode), ERR_JS_OAUTH_CANCELED, "ERROR_OAUTH_CANCELED");
    SetNamedProperty(env, (*resultCode), ERR_JS_OAUTH_LIST_TOO_LARGE, "ERROR_OAUTH_LIST_TOO_LARGE");
    SetNamedProperty(env, (*resultCode), ERR_JS_OAUTH_SERVICE_EXCEPTION, "ERROR_OAUTH_SERVICE_EXCEPTION");
    SetNamedProperty(env, (*resultCode), ERR_JS_OAUTH_SESSION_NOT_EXIST, "ERROR_OAUTH_SESSION_NOT_EXIST");
    SetNamedProperty(env, (*resultCode), ERR_JS_OAUTH_TIMEOUT, "ERROR_OAUTH_TIMEOUT");
    SetNamedProperty(env, (*resultCode), ERR_JS_OAUTH_TOKEN_NOT_EXIST, "ERROR_OAUTH_TOKEN_NOT_EXIST");
    SetNamedProperty(env, (*resultCode), ERR_JS_OAUTH_TOKEN_TOO_MANY, "ERROR_OAUTH_TOKEN_TOO_MANY");
    SetNamedProperty(env, (*resultCode), ERR_JS_OAUTH_SERVICE_BUSY, "ERROR_OAUTH_SERVICE_BUSY");
    SetNamedProperty(env, (*resultCode), ERR_JS_OAUTH_UNSUPPORT_ACTION, "ERROR_OAUTH_UNSUPPORT_ACTION");
    SetNamedProperty(env, (*resultCode), ERR_JS_OAUTH_UNSUPPORT_AUTH_TYPE, "ERROR_OAUTH_UNSUPPORT_AUTH_TYPE");
    SetNamedProperty(env, (*resultCode), ERR_JS_PERMISSION_DENIED_V8, "ERROR_PERMISSION_DENIED");
}
napi_value NapiAppAccountConstant::Init(napi_env env, napi_value exports)
{
    napi_value resultCode = nullptr;
    napi_value constants = nullptr;
    napi_create_object(env, &resultCode);
    napi_create_object(env, &constants);
    ResultCodeInit(env, &resultCode);

    SetNamedProperty(env, constants, OAUTH_ACTION_ADD_ACCOUNT_IMPLICITLY,
        "ACTION_ADD_ACCOUNT_IMPLICITLY");
    SetNamedProperty(env, constants, OAUTH_ACTION_AUTHENTICATE, "ACTION_AUTHENTICATE");
    SetNamedProperty(env, constants, ACTION_CREATE_ACCOUNT_IMPLICITLY,
        "ACTION_CREATE_ACCOUNT_IMPLICITLY");
    SetNamedProperty(env, constants, ACTION_AUTH, "ACTION_AUTH");
    SetNamedProperty(env, constants, ACTION_VERIFY_CREDENTIAL, "ACTION_VERIFY_CREDENTIAL");
    SetNamedProperty(env, constants, ACTION_SET_AUTHENTICATOR_PROPERTIES,
        "ACTION_SET_AUTHENTICATOR_PROPERTIES");
    SetNamedProperty(env, constants, Constants::KEY_NAME, "KEY_NAME");
    SetNamedProperty(env, constants, KEY_OWNER, "KEY_OWNER");
    SetNamedProperty(env, constants, Constants::KEY_TOKEN, "KEY_TOKEN");
    SetNamedProperty(env, constants, Constants::KEY_ACTION, "KEY_ACTION");
    SetNamedProperty(env, constants, Constants::KEY_AUTH_TYPE, "KEY_AUTH_TYPE");
    SetNamedProperty(env, constants, Constants::KEY_SESSION_ID, "KEY_SESSION_ID");
    SetNamedProperty(env, constants, Constants::KEY_CALLER_BUNDLE_NAME, "KEY_CALLER_BUNDLE_NAME");
    SetNamedProperty(env, constants, Constants::KEY_CALLER_PID, "KEY_CALLER_PID");
    SetNamedProperty(env, constants, Constants::KEY_CALLER_UID, "KEY_CALLER_UID");
    SetNamedProperty(env, constants, KEY_REQUIRED_LABELS, "KEY_REQUIRED_LABELS");
    SetNamedProperty(env, constants, Constants::KEY_BOOLEAN_RESULT, "KEY_BOOLEAN_RESULT");

    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_PROPERTY("ResultCode", resultCode),
        DECLARE_NAPI_PROPERTY("Constants", constants),
    };
    napi_define_properties(env, exports, sizeof(exportFuncs) / sizeof(*exportFuncs), exportFuncs);

    return exports;
}
}  // namespace AccountJsKit
}  // namespace OHOS
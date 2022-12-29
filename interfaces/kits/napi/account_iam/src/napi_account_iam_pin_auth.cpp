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

#include "napi_account_iam_pin_auth.h"

#include "account_iam_client.h"
#include "account_log_wrapper.h"
#include "napi_account_error.h"
#include "napi_account_iam_common.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;

napi_value NapiAccountIAMPINAuth::Init(napi_env env, napi_value exports)
{
    napi_value cons;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("registerInputer", RegisterInputer),
        DECLARE_NAPI_FUNCTION("unregisterInputer", UnregisterInputer)
    };
    NAPI_CALL(env, napi_define_class(env, "PINAuth", NAPI_AUTO_LENGTH, JsConstructor,
        nullptr, sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    NAPI_CALL(env, napi_set_named_property(env, exports, "PINAuth", cons));
    return exports;
}

napi_value NapiAccountIAMPINAuth::JsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

static bool ParseContextForRegisterInputer(napi_env env, napi_callback_info info, napi_ref *callback)
{
    size_t argc = ARG_SIZE_ONE;
    napi_value argv[ARG_SIZE_ONE] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != ARG_SIZE_ONE) {
        ACCOUNT_LOGE("expect at least one parameter, but got %zu", argc);
        std::string errMsg = "The arg number must be at least " + std::to_string(ARG_SIZE_ONE) + " characters";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    napi_valuetype valuetype = napi_undefined;
    napi_typeof(env, argv[PARAM_ZERO], &valuetype);
    napi_value onGetData = nullptr;
    if (valuetype == napi_object) {
        napi_get_named_property(env, argv[PARAM_ZERO], "onGetData", &onGetData);
    } else if (valuetype == napi_function) {
        onGetData = argv[PARAM_ZERO];
    } else {
        ACCOUNT_LOGE("inputer param type error");
        std::string errMsg = "The type of arg 1 must be function or object";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    return napi_create_reference(env, onGetData, 1, callback) == napi_ok ? true : false;
}

napi_value NapiAccountIAMPINAuth::RegisterInputer(napi_env env, napi_callback_info info)
{
    napi_value result;
    NAPI_CALL(env, napi_get_boolean(env, false, &result));
    napi_ref callback = nullptr;
    if (!ParseContextForRegisterInputer(env, info, &callback)) {
        return result;
    }
    auto inputer = std::make_shared<NapiGetDataCallback>(env, callback);
    int32_t errCode = AccountIAMClient::GetInstance().RegisterPINInputer(inputer);
    napi_value napiResult = nullptr;
    if (errCode == ERR_OK) {
        NAPI_CALL(env, napi_get_boolean(env, true, &napiResult));
        return napiResult;
    }
    ACCOUNT_LOGE("Failed to register inputer, errCode=%{public}d", errCode);
    AccountIAMNapiThrow(env, AccountIAMConvertToJSErrCode(errCode), true);
    return nullptr;
}

napi_value NapiAccountIAMPINAuth::UnregisterInputer(napi_env env, napi_callback_info info)
{
    AccountIAMClient::GetInstance().UnregisterPINInputer();
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}
}  // namespace AccountJsKit
}  // namespace OHOS

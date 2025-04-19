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

#include "napi_account_error.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"

using namespace OHOS::AccountSA;

namespace OHOS {
namespace AccountJsKit {
napi_value GenerateBusinessError(napi_env env, int32_t jsErrCode, const std::string &jsErrMsg)
{
    napi_value errCodeJs = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, jsErrCode, &errCodeJs));

    napi_value errMsgJs = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, jsErrMsg.c_str(), NAPI_AUTO_LENGTH, &errMsgJs));

    napi_value errJs = nullptr;
    NAPI_CALL(env, napi_create_error(env, nullptr, errMsgJs, &errJs));
    NAPI_CALL(env, napi_set_named_property(env, errJs, "code", errCodeJs));
    NAPI_CALL(env, napi_set_named_property(env, errJs, "message", errMsgJs));
    return errJs;
}

static napi_value GetErrorCodeValue(napi_env env, int errCode)
{
    napi_value jsObject = nullptr;
    napi_value jsValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errCode, &jsValue));
    NAPI_CALL(env, napi_create_object(env, &jsObject));
    NAPI_CALL(env, napi_set_named_property(env, jsObject, "code", jsValue));
    return jsObject;
}

napi_value GenerateBusinessSuccess(napi_env env, bool throwErr)
{
    if (throwErr) {
        napi_value errJs = nullptr;
        napi_get_null(env, &errJs);
        return errJs;
    }
    return GetErrorCodeValue(env, 0);
}

napi_value GenerateBusinessError(napi_env env, int32_t nativeErrCode, bool throwErr)
{
    if (throwErr) {
        return GenerateBusinessError(env, nativeErrCode);
    }
    return GetErrorCodeValue(env, nativeErrCode);
}

napi_value GenerateBusinessError(napi_env env, int32_t nativeErrCode)
{
    int32_t jsErrCode = GenerateBusinessErrorCode(nativeErrCode);
    std::string jsErrMsg = ConvertToJsErrMsg(jsErrCode);
    return GenerateBusinessError(env, jsErrCode, jsErrMsg);
}

void AccountNapiThrow(napi_env env, int32_t nativeErrCode, bool throwErr)
{
    if (throwErr) {
        napi_throw(env, GenerateBusinessError(env, nativeErrCode));
    }
}

void AccountNapiThrow(napi_env env, int32_t jsErrCode, const std::string &jsErrMsg, bool throwErr)
{
    if (throwErr) {
        napi_throw(env, GenerateBusinessError(env, jsErrCode, jsErrMsg));
    }
}

void AccountIAMNapiThrow(napi_env env, int32_t jsErrCode, bool throwErr)
{
    if (throwErr) {
        napi_throw(env, GenerateBusinessError(env, jsErrCode, ConvertToJsErrMsg(jsErrCode)));
    }
}
} // namespace AccountJsKit
} // namespace OHOS
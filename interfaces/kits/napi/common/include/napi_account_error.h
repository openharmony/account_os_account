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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_COMMON_INCLUDE_NAPI_ACCOUNT_ERROR_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_COMMON_INCLUDE_NAPI_ACCOUNT_ERROR_H

#include <stdint.h>
#include <string>
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace AccountJsKit {
std::string ConvertToJsErrMsg(int32_t jsErrCode);
napi_value GenerateBusinessSuccess(napi_env env, bool throwErr);
napi_value GenerateBusinessError(napi_env env, int32_t jsErrCode, const std::string &jsErrMsg);
napi_value GenerateBusinessError(napi_env env, int32_t nativeErrCode);
napi_value GenerateBusinessError(napi_env env, int32_t nativeErrCode, bool throwErr);
void AccountNapiThrow(napi_env env, int32_t jsErrCode, const std::string &jsErrMsg, bool throwErr);
void AccountNapiThrow(napi_env env, int32_t nativeErrCode, bool throwErr);
void AccountIAMNapiThrow(napi_env env, int32_t jsErrCode, bool throwErr);
} // namespace AccountJsKit
} // namespace OHOS

#endif // OS_ACCOUNT_INTERFACES_KITS_NAPI_COMMON_INCLUDE_NAPI_ACCOUNT_ERROR_H

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

#ifndef OS_ACCOUNT_INTERFACES_KITS_COMMON_INCLUDE_NAPI_ACCOUNT_COMMON_H
#define OS_ACCOUNT_INTERFACES_KITS_COMMON_INCLUDE_NAPI_ACCOUNT_COMMON_H

#include <string>

#include "account_error_no.h"
#include "napi/native_api.h"

namespace OHOS {
namespace AccountJsKit {
struct CommonAsyncContext {
    CommonAsyncContext() {};
    explicit CommonAsyncContext(napi_env napiEnv) : env(napiEnv) {};
    napi_env env = nullptr;
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callbackRef = nullptr;
    napi_status status = napi_ok;
    ErrCode errCode = ERR_OK;
    std::string errMsg;
    bool throwErr = false;
};

void ProcessCallbackOrPromise(napi_env env, const CommonAsyncContext *asyncContext, napi_value err, napi_value data);

bool GetCallbackProperty(napi_env env, napi_value obj, napi_ref &property, int argNum);
bool GetIntProperty(napi_env env, napi_value obj, int32_t &property);
bool GetLongIntProperty(napi_env env, napi_value obj, int64_t &property);
bool GetBoolProperty(napi_env env, napi_value obj, bool &property);
bool GetStringProperty(napi_env env, napi_value obj, std::string &property);
bool GetStringArrayProperty(napi_env env, napi_value obj, std::vector<std::string> &property, bool allowEmpty);
bool GetStringPropertyByKey(napi_env env, napi_value obj, const std::string &propertyName, std::string &property);
bool GetOptionalStringPropertyByKey(napi_env env, napi_value obj, const std::string &propertyName,
    std::string &property);
bool IsSystemApp(napi_env env);
napi_value CreateStringArray(napi_env env, const std::vector<std::string> &strVec);
} // namespace AccountJsKit
} // namespace OHOS

#endif // OS_ACCOUNT_INTERFACES_KITS_COMMON_INCLUDE_NAPI_ACCOUNT_COMMON_H

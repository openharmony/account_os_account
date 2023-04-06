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

#include <mutex>
#include <string>
#include <vector>
#include <uv.h>

#include "account_error_no.h"
#include "napi/native_api.h"

namespace OHOS {
namespace AccountJsKit {
struct CommonAsyncContext {
    CommonAsyncContext() {};
    CommonAsyncContext(napi_env napiEnv) : env(napiEnv) {};
    napi_env env = nullptr;
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callbackRef = nullptr;
    napi_status status = napi_ok;
    ErrCode errCode = ERR_OK;
    std::string errMsg;
    bool throwErr = false;
};

struct ThreadLockInfo {
    std::mutex mutex;
    std::condition_variable condition;
    int32_t count = 0;
};

struct NapiRefArrayContext {
    napi_env env;
    std::vector<napi_ref> napiRefVec;
};

void ProcessCallbackOrPromise(napi_env env, const CommonAsyncContext *asyncContext, napi_value err, napi_value data);
void ReleaseNapiRefAsync(napi_env env, napi_ref napiRef);
void ReleaseNapiRefArray(napi_env env, const std::vector<napi_ref> &napiRefVec);
void NapiCallVoidFunction(napi_env env, napi_value *argv, size_t argc, napi_ref funcRef);
bool GetCallbackProperty(napi_env env, napi_value obj, napi_ref &property, int argNum);
bool GetIntProperty(napi_env env, napi_value obj, int32_t &property);
bool GetLongIntProperty(napi_env env, napi_value obj, int64_t &property);
bool GetBoolProperty(napi_env env, napi_value obj, bool &property);
bool GetStringProperty(napi_env env, napi_value obj, std::string &property);
bool GetStringArrayProperty(napi_env env, napi_value obj, std::vector<std::string> &property, bool allowEmpty);
bool GetStringPropertyByKey(napi_env env, napi_value obj, const std::string &propertyName, std::string &property);
bool InitUvWorkCallbackEnv(uv_work_t *work, napi_handle_scope &scope);
bool GetOptionalStringPropertyByKey(napi_env env, napi_value obj, const std::string &propertyName,
    std::string &property);
napi_value CreateStringArray(napi_env env, const std::vector<std::string> &strVec);
napi_value CreateUint8Array(napi_env env, const uint8_t *data, size_t length);
napi_status ParseUint8TypedArray(napi_env env, napi_value value, uint8_t **data, size_t *length);
napi_status ParseUint8TypedArrayToVector(napi_env env, napi_value value, std::vector<uint8_t> &vec);
napi_status ParseUint8TypedArrayToUint64(napi_env env, napi_value value, uint64_t &result);
} // namespace AccountJsKit
} // namespace OHOS

#endif // OS_ACCOUNT_INTERFACES_KITS_COMMON_INCLUDE_NAPI_ACCOUNT_COMMON_H

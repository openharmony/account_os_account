/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <uv.h>

#include "account_error_no.h"
#include "napi/native_api.h"

namespace OHOS {
namespace AccountJsKit {
struct ThreadLockInfo {
    std::mutex mutex;
    std::condition_variable condition;
    int32_t count = 0;
};

struct CommonAsyncContext {
    CommonAsyncContext() {};
    CommonAsyncContext(napi_env napiEnv, bool throwAble = false) : env(napiEnv), throwErr(throwAble) {}
    virtual ~CommonAsyncContext ();
    napi_env env = nullptr;
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callbackRef = nullptr;
    napi_status status = napi_ok;
    ErrCode errCode = ERR_OK;
    std::string errMsg;
    std::string nativeErrMsg;
    bool throwErr = false;
};

struct BusinessError {
    int32_t code = 0;
    std::string data;
};

struct NapiRefArrayContext {
    napi_env env;
    std::vector<napi_ref> napiRefVec;
};

struct NapiCallbackRef {
    NapiCallbackRef(napi_env env, napi_ref callbackRef) : env(env), callbackRef(callbackRef) {}
    ~NapiCallbackRef();
    napi_env env;
    napi_ref callbackRef = nullptr;
};

class NapiAsyncContext {
public:
    NapiAsyncContext() {};
    NapiAsyncContext(napi_env env, napi_ref ref) : callbackRef(std::make_shared<NapiCallbackRef>(env, ref)) {};
    NapiAsyncContext(std::shared_ptr<NapiCallbackRef> &callbackRef) : callbackRef(callbackRef) {};
    NapiAsyncContext(napi_env env, bool throwAble = false)
        : env(env), throwErr(throwAble) {};
    napi_env env = nullptr;
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    std::shared_ptr<NapiCallbackRef> callbackRef = nullptr;
    napi_status status = napi_ok;
    ErrCode errCode = ERR_OK;
    std::string errMsg;
    std::string nativeErrMsg;
    bool throwErr = false;
};

struct AsyncContextForSubscribeBase {
    virtual ~AsyncContextForSubscribeBase() = default;
    std::string type;
    std::vector<std::string> owners;
    void *appAccountManager = nullptr;
};

class AppAccountSubscriberInfo {
public:
    static AppAccountSubscriberInfo& GetInstance();
    std::mutex lockForAppAccountSubscribers;
    std::map<uint64_t, std::vector<AsyncContextForSubscribeBase *>> appAccountSubscribersMap;
private:
    AppAccountSubscriberInfo() {}
    ~AppAccountSubscriberInfo() {}
    AppAccountSubscriberInfo(const AppAccountSubscriberInfo&) = delete;
    AppAccountSubscriberInfo& operator=(const AppAccountSubscriberInfo&) = delete;
};

void ProcessCallbackOrPromise(napi_env env, const CommonAsyncContext *asyncContext, napi_value err, napi_value data);
void ProcessCallbackOrPromise(napi_env env, const NapiAsyncContext *asyncContext, napi_value err, napi_value data);
void ReturnCallbackOrPromise(napi_env env, const CommonAsyncContext *asyncContext, napi_value err, napi_value data);
bool GetCallbackProperty(napi_env env, napi_value obj, napi_ref &property, int argNum);
bool GetIntProperty(napi_env env, napi_value obj, int32_t &property);
bool GetOptionIntProperty(napi_env env, napi_value obj, int32_t &property, bool &hasProperty);
bool GetLongIntProperty(napi_env env, napi_value obj, int64_t &property);
bool GetOptionBoolProperty(napi_env env, napi_value obj, const std::string &propertyName, bool &property);
bool GetBoolProperty(napi_env env, napi_value obj, bool &property);
bool GetStringProperty(napi_env env, napi_value obj, std::string &property);
bool GetStringArrayProperty(napi_env env, napi_value obj, std::vector<std::string> &property, bool allowEmpty);
bool GetStringArrayPropertyByKey(napi_env env, napi_value obj, const std::string &propertyName,
    std::vector<std::string> &property, bool allowEmpty);
bool GetStringPropertyByKey(napi_env env, napi_value obj, const std::string &propertyName, std::string &property);
bool GetOptionalStringPropertyByKey(napi_env env, napi_value obj, const std::string &propertyName,
    std::string &property);
bool GetOptionalStringPropertyByKey(napi_env env, napi_value obj, const std::string &propertyName,
    std::string &property, bool &hasProperty);
bool GetOptionalNumberPropertyByKey(napi_env env, napi_value obj, const std::string &propertyName,
    int32_t &numberProperty, bool &hasProperty);
void SetInt32ToJsProperty(napi_env env, int32_t number, const std::string &propertyName, napi_value &dataJs);
bool IsOptionalPropertyExist(napi_env env, napi_value obj, const std::string &propertyName);
bool CompareOnAndOffRef(const napi_env env, napi_ref subscriberRef, napi_ref unsubscriberRef);
bool IsSystemApp(napi_env env);
bool ParseBusinessError(napi_env env, napi_value value, BusinessError &error);
bool GetNamedJsFunction(napi_env env, napi_value object, const std::string &name, napi_ref &callback);
napi_value CreateStringArray(napi_env env, const std::vector<std::string> &strVec);
napi_value CreateUint8Array(napi_env env, const uint8_t *data, size_t length);
napi_status ParseUint8TypedArray(napi_env env, napi_value value, uint8_t **data, size_t *length);
napi_status ParseUint8ArrayToNativeUint8Array(napi_env env, napi_value value, uint8_t **data, size_t *length);
napi_status ParseUint8TypedArrayToVector(napi_env env, napi_value value, std::vector<uint8_t> &vec);
bool GetOptionalUint8TypedArrayToVector(napi_env env, napi_value obj, const std::string &propertyName,
    std::vector<uint8_t> &vec);
napi_status ParseUint8TypedArrayToUint64(napi_env env, napi_value value, uint64_t &result);
void NapiCallVoidFunction(napi_env env, napi_value *argv, size_t argc, napi_ref funcRef);
napi_value CreateAuthResult(
    napi_env env, const std::vector<uint8_t> &authData, int32_t remainTimes, int32_t freezingTime);
void ReleaseNapiRefAsync(napi_env env, napi_ref napiRef);
void ReleaseNapiRefArray(napi_env env, const std::vector<napi_ref> &napiRefVec);
bool JsObjectToNativeString(napi_env env, napi_value jsData, std::string &nativeData);
napi_value NativeStringToJsObject(napi_env env, const std::string &nativeData);
bool GetSelfTargetVersion(uint32_t &targetVersion);
} // namespace AccountJsKit
} // namespace OHOS

#endif // OS_ACCOUNT_INTERFACES_KITS_COMMON_INCLUDE_NAPI_ACCOUNT_COMMON_H

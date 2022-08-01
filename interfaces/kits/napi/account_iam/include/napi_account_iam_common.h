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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_COMMON_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_COMMON_H

#include "account_error_no.h"
#include "account_iam_info.h"
#include "i_inputer.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AccountJsKit {
constexpr size_t ARG_SIZE_ONE = 1;
constexpr size_t ARG_SIZE_TWO = 2;
constexpr size_t ARG_SIZE_THREE = 3;
constexpr size_t ARG_SIZE_FOUR = 4;
constexpr size_t ARG_SIZE_FIVE = 5;

constexpr size_t PARAM_ZERO = 0;
constexpr size_t PARAM_ONE = 1;
constexpr size_t PARAM_TWO = 2;
constexpr size_t PARAM_THREE = 3;
constexpr size_t PARAM_FOUR = 4;

struct IAMAsyncContext {
    explicit IAMAsyncContext(napi_env napiEnv);
    virtual ~IAMAsyncContext();
    napi_env env = nullptr;
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callbackRef = nullptr;
    ErrCode errCode = ERR_OK;
};

struct JsIAMCallback {
    napi_ref onResult;
    napi_ref onAcquireInfo;
};

#ifdef HAS_USER_AUTH_PART
struct IDMCallbackParam {
    napi_env env;
    JsIAMCallback callback;
    int32_t result;
    int32_t module;
    int32_t acquire;
    uint64_t credentialId;
};

struct AuthCallbackParam {
    napi_env env;
    int32_t module;
    uint32_t acquireInfo;
    int32_t extraInfo;
    int32_t resultCode;
    int32_t remainTimes;
    int32_t freezingTime;
    std::vector<uint8_t> token;
    JsIAMCallback callback;
};

struct AuthContext {
    int32_t userId = 0;
    int32_t authType;
    int32_t trustLevel;
    std::vector<uint8_t> challenge;
    std::shared_ptr<AccountSA::AuthenticationCallback> callback;
};

struct IDMContext : public IAMAsyncContext {
    explicit IDMContext(napi_env napiEnv) : IAMAsyncContext(napiEnv) {};
    std::vector<uint8_t> challenge;
    uint64_t credentialId;
    std::vector<uint8_t> token;
    AccountSA::CredentialParameters addCredInfo;
    JsIAMCallback callback;
};

struct GetAuthInfoContext : public IAMAsyncContext {
    explicit GetAuthInfoContext(napi_env napiEnv) : IAMAsyncContext(napiEnv) {};
    AccountSA::AuthType authType {0};
    std::vector<AccountSA::CredentialInfo> credInfo;
};

struct GetPropertyContext : public IAMAsyncContext {
    explicit GetPropertyContext(napi_env napiEnv) : IAMAsyncContext(napiEnv) {};
    AccountSA::GetPropertyRequest request;
    int32_t result;
    int32_t authSubType = 0;
    int32_t remainTimes = 0;
    int32_t freezingTime = 0;
};

struct SetPropertyContext : public IAMAsyncContext {
    explicit SetPropertyContext(napi_env napiEnv) : IAMAsyncContext(napiEnv) {};
    AccountSA::SetPropertyRequest request;
    int32_t result;
};

class NapiIDMCallback : public AccountSA::UserIdmClientCallback {
public:
    explicit NapiIDMCallback(napi_env env, const JsIAMCallback &callback);
    virtual ~NapiIDMCallback();

    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo) override;

private:
    std::mutex mutex_;
    bool isCalled_ = false;
    napi_env env_;
    JsIAMCallback callback_;
};

class NapiGetInfoCallback : public AccountSA::GetCredentialInfoCallback {
public:
    explicit NapiGetInfoCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred);
    virtual ~NapiGetInfoCallback();

    void OnCredentialInfo(const std::vector<AccountSA::CredentialInfo> &infoList) override;
private:
    napi_env env_;
    napi_ref callbackRef_;
    napi_deferred deferred_;
};

class NapiUserAuthCallback : public AccountSA::AuthenticationCallback {
public:
    explicit NapiUserAuthCallback(napi_env env, JsIAMCallback callback);
    virtual ~NapiUserAuthCallback();

    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo) override;
private:
    napi_env env_;
    JsIAMCallback callback_;
};

class NapiGetPropCallback : public AccountSA::GetPropCallback {
public:
    explicit NapiGetPropCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred);
    virtual ~NapiGetPropCallback();

    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override;
private:
    napi_env env_;
    napi_ref callbackRef_;
    napi_deferred deferred_;
};

class NapiSetPropCallback : public AccountSA::SetPropCallback {
public:
    explicit NapiSetPropCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred);
    virtual ~NapiSetPropCallback();
    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override;

private:
    napi_env env_;
    napi_ref callbackRef_;
    napi_deferred deferred_;
};
#endif  // HAS_USER_AUTH_PART

#ifdef HAS_PIN_AUTH_PART
struct InputerContext {
    napi_env env = nullptr;
    napi_ref callback = nullptr;
    int32_t authSubType = -1;
    std::shared_ptr<AccountSA::IInputerData> inputerData = nullptr;
};

class NapiInputer : public AccountSA::IInputer {
public:
    NapiInputer(napi_env env, napi_ref callback);
    virtual ~NapiInputer();

    void OnGetData(int32_t authSubType, std::shared_ptr<AccountSA::IInputerData> inputerData);
private:
    napi_env env_;
    napi_ref callback_;
};
#endif  // HAS_PIN_AUTH_PART

void CallbackAsyncOrPromise(napi_env env, IAMAsyncContext *context, napi_value data);
napi_value CreateUint8Array(napi_env env, const uint8_t *data, size_t length);
napi_value CreateErrorObject(napi_env env, int32_t code);
napi_status ParseUint8TypedArray(napi_env env, napi_value value, uint8_t **data, size_t *length);
napi_status ParseUint8TypedArrayToVector(napi_env env, napi_value value, std::vector<uint8_t> &vec);
napi_status ParseUint8TypedArrayToUint64(napi_env env, napi_value value, uint64_t &result);
napi_status ParseUInt32Array(napi_env env, napi_value value, std::vector<uint32_t> &data);
napi_status ParseIAMCallback(napi_env env, napi_value value, JsIAMCallback &callback);
#ifdef HAS_USER_AUTH_PART
napi_status ParseAddCredInfo(napi_env env, napi_value value, AccountSA::CredentialParameters &info);
napi_status ParseGetPropRequest(napi_env env, napi_value value, AccountSA::GetPropertyRequest &request);
napi_status ParseSetPropRequest(napi_env env, napi_value value, AccountSA::SetPropertyRequest &request);
napi_value CreateCredInfoArray(napi_env env, const std::vector<AccountSA::CredentialInfo> &info);
napi_value CreateExecutorProperty(napi_env env, const GetPropertyContext &prop);
napi_value CreateAuthResult(napi_env env, const std::vector<uint8_t> &token, int32_t remainTimes, int32_t freezingTime);
#endif
}  // namespace AccountJsKit
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_COMMON_H

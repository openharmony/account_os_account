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
#include "account_iam_client_callback.h"
#include "account_iam_info.h"
#include "i_inputer.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_account_common.h"

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

enum IAMResultCode : int32_t {
    ERR_IAM_SUCCESS = 0,
    ERR_IAM_FAIL = 1,
    ERR_IAM_GENERAL_ERROR = 2,
    ERR_IAM_CANCELED = 3,
    ERR_IAM_TIMEOUT = 4,
    ERR_IAM_TYPE_NOT_SUPPORT = 5,
    ERR_IAM_TRUST_LEVEL_NOT_SUPPORT = 6,
    ERR_IAM_BUSY = 7,
    ERR_IAM_INVALID_PARAMETERS = 8,
    ERR_IAM_LOCKED = 9,
    ERR_IAM_NOT_ENROLLED = 10,
    ERR_IAM_HARDWARE_NOT_SUPPORTED = 11,
    ERR_IAM_SYSTEM_ERROR_CODE_BEGIN = 1000,
    ERR_IAM_IPC_ERROR = 1001,
    ERR_IAM_INVALID_CONTEXT_ID = 1002,
    ERR_IAM_READ_PARCEL_ERROR = 1003,
    ERR_IAM_WRITE_PARCEL_ERROR = 1004,
    ERR_IAM_CHECK_PERMISSION_FAILED = 1005,
    ERR_IAM_INVALID_HDI_INTERFACE = 1006,
    ERR_IAM_VENDOR_ERROR_CODE_BEGIN = 10000,
};

int32_t AccountIAMConvertToJSErrCode(int32_t errCode);

struct IAMAsyncContext : public CommonAsyncContext {
    explicit IAMAsyncContext(napi_env napiEnv);
    virtual ~IAMAsyncContext();
    bool throwErr = true;
};

struct JsIAMCallback {
    napi_ref onResult = nullptr;
    napi_ref onAcquireInfo = nullptr;
};

#ifdef HAS_USER_AUTH_PART
struct IDMCallbackParam : public CommonAsyncContext {
    explicit IDMCallbackParam(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    JsIAMCallback callback;
    int32_t result = 0;
    int32_t module = 0;
    uint32_t acquire = 0;
    uint64_t credentialId = 0;
};

struct AuthCallbackParam : public CommonAsyncContext {
    explicit AuthCallbackParam(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    int32_t module = 0;
    uint32_t acquireInfo = 0;
    int32_t extraInfo = 0;
    int32_t resultCode = 0;
    int32_t remainTimes = -1;
    int32_t freezingTime = -1;
    std::vector<uint8_t> token;
    JsIAMCallback callback;
};

struct AuthContext {
    int32_t userId = 0;
    int32_t authType = -1;
    int32_t trustLevel = -1;
    bool throwErr = true;
    std::vector<uint8_t> challenge;
    std::shared_ptr<AccountSA::IDMCallback> callback;
};

struct IDMContext : public IAMAsyncContext {
    explicit IDMContext(napi_env napiEnv) : IAMAsyncContext(napiEnv) {};
    std::vector<uint8_t> challenge;
    uint64_t credentialId = 0;
    std::vector<uint8_t> token;
    AccountSA::CredentialParameters addCredInfo;
    JsIAMCallback callback;
};

struct GetAuthInfoContext : public CommonAsyncContext {
    explicit GetAuthInfoContext(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    AccountSA::AuthType authType {0};
    std::vector<AccountSA::CredentialInfo> credInfo;
};

struct GetPropertyContext : public CommonAsyncContext {
    explicit GetPropertyContext(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    ~GetPropertyContext();
    AccountSA::GetPropertyRequest request;
    int32_t result = 0;
    int32_t authSubType = 0;
    int32_t remainTimes = 0;
    int32_t freezingTime = 0;
};

struct SetPropertyContext : public CommonAsyncContext {
    explicit SetPropertyContext(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    ~SetPropertyContext();
    AccountSA::SetPropertyRequest request;
    int32_t result = 0;
};

class NapiIDMCallback : public AccountSA::IDMCallback {
public:
    explicit NapiIDMCallback(napi_env env, const JsIAMCallback &callback);
    virtual ~NapiIDMCallback();

    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo) override;

private:
    napi_env env_;
    JsIAMCallback callback_;
};

class NapiGetInfoCallback : public AccountSA::GetCredInfoCallback {
public:
    explicit NapiGetInfoCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred);
    virtual ~NapiGetInfoCallback();

    void OnCredentialInfo(int32_t result, const std::vector<AccountSA::CredentialInfo> &infoList) override;
private:
    napi_env env_;
    napi_ref callbackRef_;
    napi_deferred deferred_;
};

class NapiUserAuthCallback : public AccountSA::IDMCallback {
public:
    explicit NapiUserAuthCallback(napi_env env, JsIAMCallback callback);
    virtual ~NapiUserAuthCallback();

    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo) override;
private:
    napi_env env_;
    JsIAMCallback callback_;
};

class NapiGetPropCallback : public AccountSA::GetSetPropCallback {
public:
    explicit NapiGetPropCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred);
    virtual ~NapiGetPropCallback();

    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override;
private:
    napi_env env_ = nullptr;
    napi_ref callbackRef_ = nullptr;
    napi_deferred deferred_ = nullptr;
    std::mutex mutex_;
};

class NapiSetPropCallback : public AccountSA::GetSetPropCallback {
public:
    explicit NapiSetPropCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred);
    virtual ~NapiSetPropCallback();

    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override;

private:
    napi_env env_ = nullptr;
    napi_ref callbackRef_ = nullptr;
    napi_deferred deferred_ = nullptr;
    std::mutex mutex_;
};
#endif  // HAS_USER_AUTH_PART

#ifdef HAS_PIN_AUTH_PART
struct InputerContext : public CommonAsyncContext {
  int32_t authSubType = -1;
  std::shared_ptr<AccountSA::IInputerData> inputerData = nullptr;
  ThreadLockInfo *lockInfo = nullptr;
};

class NapiGetDataCallback : public AccountSA::IInputer {
public:
    NapiGetDataCallback(napi_env env, napi_ref callback);
    virtual ~NapiGetDataCallback();

    void OnGetData(int32_t authSubType, const std::shared_ptr<AccountSA::IInputerData> inputerData) override;

private:
    napi_env env_;
    napi_ref callback_;
    ThreadLockInfo lockInfo_;
};
#endif  // HAS_PIN_AUTH_PART

void CallbackAsyncOrPromise(napi_env env, CommonAsyncContext *context, napi_value errJs, napi_value dataJs);
napi_value CreateErrorObject(napi_env env, int32_t code);
napi_status ParseUInt32Array(napi_env env, napi_value value, std::vector<uint32_t> &data);
napi_status ParseIAMCallback(napi_env env, napi_value value, JsIAMCallback &callback);
#ifdef HAS_USER_AUTH_PART
napi_status ParseAddCredInfo(napi_env env, napi_value value, AccountSA::CredentialParameters &info);
napi_status ParseGetPropRequest(napi_env env, napi_value value, AccountSA::GetPropertyRequest &request);
napi_status ParseSetPropRequest(napi_env env, napi_value value, AccountSA::SetPropertyRequest &request);
napi_value CreateCredInfoArray(napi_env env, const std::vector<AccountSA::CredentialInfo> &info);
napi_value CreateAuthResult(napi_env env, const std::vector<uint8_t> &token, int32_t remainTimes, int32_t freezingTime);
#endif
}  // namespace AccountJsKit
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_COMMON_H

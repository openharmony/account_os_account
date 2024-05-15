/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#ifdef HAS_PIN_AUTH_PART
#include "i_inputer.h"
#endif
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
constexpr size_t PARAM_FIVE = 5;

constexpr int32_t RESTRICTED_ACCOUNT_ID_BEGINNING = 0;
constexpr int32_t RESTRICTED_ACCOUNT_ID_ENDDING = 100;

int32_t AccountIAMConvertToJSErrCode(int32_t errCode);

struct JsIAMCallback {
    JsIAMCallback(napi_env env) : env(env) {}
    ~JsIAMCallback()
    {
        ReleaseNapiRefArray(env, {onResult, onAcquireInfo});
    }
    bool onResultCalled = false;
    napi_env env;
    napi_ref onResult = nullptr;
    napi_ref onAcquireInfo = nullptr;
    bool hasOnAcquireInfo = false;
};

#ifdef HAS_USER_AUTH_PART
struct IDMCallbackParam : public CommonAsyncContext {
    explicit IDMCallbackParam(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    std::shared_ptr<JsIAMCallback> callback;
    int32_t result = 0;
    int32_t module = 0;
    uint32_t acquire = 0;
    uint64_t credentialId = 0;
    std::vector<uint8_t> extraInfo;
};

struct AuthCallbackParam : public CommonAsyncContext {
    explicit AuthCallbackParam(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    int32_t module = 0;
    uint32_t acquireInfo = 0;
    std::vector<uint8_t> extraInfo;
    int32_t resultCode = 0;
    int32_t remainTimes = -1;
    int32_t freezingTime = -1;
    std::vector<uint8_t> token;
    std::shared_ptr<JsIAMCallback> callback;
    bool hasNextPhaseFreezingTime = false;
    bool hasCredentialId = false;
    bool hasAccountId = false;
    bool hasPinValidityPeriod = false;
    int32_t nextPhaseFreezingTime = -1;
    uint64_t credentialId = 0;
    int32_t accountId = 0;
    int64_t pinValidityPeriod = -1;
};

struct AuthContext {
    int32_t userId = 0;
    int32_t authType = -1;
    int32_t trustLevel = -1;
    bool throwErr = true;
    bool parseHasAccountId = false;
    std::vector<uint8_t> challenge;
    AccountSA::AuthOptions authOptions;
    std::shared_ptr<AccountSA::IDMCallback> callback;
};

struct PrepareRemoteAuthContext : public CommonAsyncContext {
    explicit PrepareRemoteAuthContext(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    int32_t result = 0;
    std::string remoteNetworkId;
};

class NapiPrepareRemoteAuthCallback : public AccountSA::PreRemoteAuthCallback {
public:
    explicit NapiPrepareRemoteAuthCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred);
    virtual ~NapiPrepareRemoteAuthCallback();

    void OnResult(int32_t result) override;

private:
    napi_env env_ = nullptr;
    napi_ref callbackRef_ = nullptr;
    napi_deferred deferred_ = nullptr;
    std::mutex mutex_;
};

struct IDMContext : public CommonAsyncContext {
    IDMContext(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    bool throwErr = true;
    std::vector<uint8_t> challenge;
    uint64_t credentialId = 0;
    int32_t accountId = 0;
    bool parseHasAccountId = false;
    std::vector<uint8_t> token;
    AccountSA::CredentialParameters addCredInfo;
    std::shared_ptr<JsIAMCallback> callback;
};

struct GetAuthInfoContext : public CommonAsyncContext {
    explicit GetAuthInfoContext(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    int32_t accountId = 0;
    bool parseHasAccountId = false;
    AccountSA::AuthType authType {0};
    std::vector<AccountSA::CredentialInfo> credInfo;
};

struct GetEnrolledIdContext : public CommonAsyncContext {
    explicit GetEnrolledIdContext(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    int32_t accountId = -1;
    bool parseHasAccountId = false;
    AccountSA::AuthType authType {0};
    uint64_t enrolledId = 0;
};

struct GetPropertyContext : public CommonAsyncContext {
    explicit GetPropertyContext(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    AccountSA::GetPropertyRequest request;
    int32_t result = 0;
    int32_t authSubType = 0;
    int32_t remainTimes = 0;
    int32_t freezingTime = 0;
    std::string enrollmentProgress;
    std::string sensorInfo;
    int32_t accountId = 0;
    bool parseHasAccountId = false;
    int32_t nextPhaseFreezingTime = -1;
};

struct SetPropertyContext : public CommonAsyncContext {
    explicit SetPropertyContext(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    AccountSA::SetPropertyRequest request;
    int32_t result = 0;
};

class NapiIDMCallback : public AccountSA::IDMCallback {
public:
    NapiIDMCallback(napi_env env, const std::shared_ptr<JsIAMCallback> &callback);
    virtual ~NapiIDMCallback();

    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo) override;

private:
    napi_env env_;
    std::shared_ptr<JsIAMCallback> callback_;
    std::mutex mutex_;
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

class NapiGetEnrolledIdCallback : public AccountSA::GetEnrolledIdCallback {
public:
    explicit NapiGetEnrolledIdCallback(napi_env env, napi_deferred deferred);
    virtual ~NapiGetEnrolledIdCallback();

    void OnEnrolledId(int32_t result, uint64_t enrolledId) override;
private:
    napi_env env_;
    napi_deferred deferred_;
};

class NapiUserAuthCallback : public AccountSA::IDMCallback {
public:
    NapiUserAuthCallback(napi_env env, const std::shared_ptr<JsIAMCallback> &callback);
    virtual ~NapiUserAuthCallback();

    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo) override;
private:
    napi_env env_;
    std::shared_ptr<JsIAMCallback> callback_;
    std::mutex mutex_;
};

class NapiGetPropCallback : public AccountSA::GetSetPropCallback {
public:
    explicit NapiGetPropCallback(
        napi_env env, napi_ref callbackRef, napi_deferred deferred, const AccountSA::GetPropertyRequest &request);
    virtual ~NapiGetPropCallback();
    void GetContextParams(const UserIam::UserAuth::Attributes &extraInfo, GetPropertyContext &context);
    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override;
private:
    napi_env env_ = nullptr;
    napi_ref callbackRef_ = nullptr;
    napi_deferred deferred_ = nullptr;
    AccountSA::GetPropertyRequest request_;
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
    std::vector<uint8_t> challenge;
    std::shared_ptr<AccountSA::IInputerData> inputerData = nullptr;
    std::shared_ptr<NapiCallbackRef> callback;
};

class NapiGetDataCallback : public AccountSA::IInputer {
public:
    NapiGetDataCallback(napi_env env, const std::shared_ptr<NapiCallbackRef> &callback);
    virtual ~NapiGetDataCallback();

    void OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
        const std::shared_ptr<AccountSA::IInputerData> inputerData) override;

private:
    napi_env env_;
    std::shared_ptr<NapiCallbackRef> callback_;
    ThreadLockInfo lockInfo_;
};
#endif  // HAS_PIN_AUTH_PART

void CallbackAsyncOrPromise(napi_env env, CommonAsyncContext *context, napi_value errJs, napi_value dataJs);
napi_value CreateErrorObject(napi_env env, int32_t code);
napi_status ParseUInt32Array(napi_env env, napi_value value, std::vector<uint32_t> &data);
napi_status ParseIAMCallback(napi_env env, napi_value object, std::shared_ptr<JsIAMCallback> &callback);
#ifdef HAS_USER_AUTH_PART
napi_status ParseAddCredInfo(napi_env env, napi_value value, IDMContext &context);
napi_status ParseGetPropRequest(napi_env env, napi_value object, GetPropertyContext &context);
napi_status ParseSetPropRequest(napi_env env, napi_value object, AccountSA::SetPropertyRequest &request);
napi_value CreateCredInfoArray(napi_env env, const std::vector<AccountSA::CredentialInfo> &info);
napi_value CreateAuthResult(napi_env env, const std::vector<uint8_t> &token, int32_t remainTimes, int32_t freezingTime);
bool IsRestrictedAccountId(int32_t accountId);
#endif
}  // namespace AccountJsKit
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_COMMON_H

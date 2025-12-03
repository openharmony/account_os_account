/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <ctime>
#include <securec.h>
#include <thread>
#include "account_log_wrapper.h"
#include "account_error_no.h"
#include "mock_domain_so_plugin.h"

namespace OHOS {
namespace AccountSA {
#ifdef __cplusplus
extern "C" {
#endif
static int32_t g_authenicationValidityPeriod = -1;
static int32_t g_authTime = 0;
static const std::string UPDATE_CONFIG_ID = "updateAccountId";
static const std::string DOMAIN = "testDomain";
static const int32_t ERROR_CODE = 12300001;
namespace {
static int32_t g_callingLocalId = -1;
static bool g_needWaitCancel = false;
static std::mutex g_needWaitCancelMutex;
static std::mutex g_mutex;
const int32_t WAIT_TIME = 5;
std::condition_variable g_Cv;
static int32_t g_contextId = 1;
static PluginAuthResultInfoCallback g_authResultInfoCallback = nullptr;
};

static void SetPluginString(const std::string &str, PluginString &pStr)
{
    if (str.empty()) {
        ACCOUNT_LOGE("Str is empty.");
        pStr.data = nullptr;
        pStr.length = 0;
        return;
    }
    pStr.data = strdup(str.c_str());
    if (pStr.data == nullptr) {
        ACCOUNT_LOGE("Failed to duplicate string.");
        pStr.length = 0;
        return;
    }
    pStr.length = str.length();
}

static bool SetPluginUint8Vector(const std::vector<uint8_t> &vector, PluginUint8Vector &pVector)
{
    if (vector.empty()) {
        ACCOUNT_LOGE("Vector is empty.");
        pVector.data = nullptr;
        return true;
    }
    pVector.data = (uint8_t *)malloc(vector.size());
    (void)memcpy_s(pVector.data, vector.size(), (uint8_t *)vector.data(), vector.size());
    pVector.capcity = vector.size();
    pVector.size = vector.size();
    return true;
}

PluginBussnessError *Auth(const PluginDomainAccountInfo *domainAccountInfo, const PluginUint8Vector *credential,
    const int32_t callerLocalId, PluginAuthResultInfoCallback callback, uint64_t *contextId)
{
    ACCOUNT_LOGI("Mock Auth enter.");
    PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }

    ACCOUNT_LOGI("Mock Auth time: %{public}d.", g_authTime);

    error->code = 0;
    error->msg.data = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        *contextId = g_contextId;
        g_contextId++;
    }
    
    auto delayCallback = [callback, contextId = *contextId]() {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        ACCOUNT_LOGI("Mock Auth begin");
        PluginAuthResultInfo *authResultInfo = (PluginAuthResultInfo *)malloc(sizeof(PluginAuthResultInfo));
        SetPluginUint8Vector({1, 2}, authResultInfo->accountToken);
        authResultInfo->remainTimes = 1;
        authResultInfo->freezingTime = 1;

        PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
        if (error != nullptr) {
            error->code = 0;
            error->msg.data = nullptr;
        }
        time_t authTime;
        (void)time(&authTime);
        g_authTime = authTime;
        callback(contextId, authResultInfo, error);
    };
    std::thread thread(delayCallback);
    pthread_setname_np(thread.native_handle(), "AuthCallbackTest");
    thread.detach();
    
    return error;
}

PluginBussnessError *BindAccount(const PluginDomainAccountInfo *domainAccountInfo, const int32_t localId)
{
    ACCOUNT_LOGI("Mock BindAccount enter.");
    PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError *BindAccountError(const PluginDomainAccountInfo *domainAccountInfo, const int32_t localId)
{
    ACCOUNT_LOGI("Mock BindAccountError enter.");
    PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = g_testErrCode;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError *GetAccountInfo(const PluginGetDomainAccountInfoOptions *options, const int32_t callerLocalId,
                                    PluginDomainAccountInfo **domainAccountInfo)
{
    ACCOUNT_LOGI("Mock GetAccountInfo enter.");
    PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    if (strcmp(options->domainAccountInfo.accountName.data, "testNewAccountInvalid") == 0) {
        error->code = 12300003; // 12300003 is ERR_JS_ACCOUNT_NOT_FOUND
        error->msg.data = nullptr;
        return error;
    }
    error->code = 0;
    error->msg.data = nullptr;
    *domainAccountInfo = (PluginDomainAccountInfo *)malloc(sizeof(PluginDomainAccountInfo));
    if (*domainAccountInfo == NULL) {
        free(error);
        return nullptr;
    }

    (*domainAccountInfo)->serverConfigId.data = nullptr;
    SetPluginString(options->domainAccountInfo.domain.data, (*domainAccountInfo)->domain);
    SetPluginString(options->domainAccountInfo.accountName.data, (*domainAccountInfo)->accountName);
    SetPluginString(options->domainAccountInfo.accountId.data, (*domainAccountInfo)->accountId);

    if (options->domainAccountInfo.serverConfigId.data != nullptr) {
        SetPluginString(options->domainAccountInfo.serverConfigId.data,
            (*domainAccountInfo)->serverConfigId);
    } else {
        (*domainAccountInfo)->serverConfigId.data = nullptr;
    }
    return error;
}

PluginBussnessError *GetAccountInfoError(const PluginGetDomainAccountInfoOptions *options, const int32_t callerLocalId,
    PluginDomainAccountInfo **domainAccountInfo)
{
    ACCOUNT_LOGI("Mock GetAccountInfoError enter.");
    PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = g_testErrCode;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError *IsAuthenticationExpired(const PluginDomainAccountInfo *domainAccountInfo,
                                             const PluginUint8Vector *token, int32_t *isValid)
{
    ACCOUNT_LOGI("Mock IsAuthenticationExpired enter.");
    if (domainAccountInfo == nullptr) {
        return nullptr;
    }
    if (isValid == nullptr) {
        return nullptr;
    }
    PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    if (token != nullptr && token->size == 0) {
        *isValid = 0;
        return error;
    }
    if (g_authenicationValidityPeriod == -1) {
        ACCOUNT_LOGI("Mock Auth not set.");
        *isValid = 1;
        return error;
    }

    time_t curTime;
    (void)time(&curTime);
    int32_t calTime = static_cast<int32_t>(curTime - g_authTime);
    if (calTime > g_authenicationValidityPeriod) {
        ACCOUNT_LOGI("Mock Auth expired: %{public}d.", calTime);
        *isValid = 0;
    } else {
        ACCOUNT_LOGI("Mock Auth not expired: %{public}d.", calTime);
        *isValid = 1;
    }
    return error;
}

PluginBussnessError* SetAccountPolicy(const PluginString *parameters,
    const PluginDomainAccountInfo *domainAccountInfo, const int32_t callerLocalId)
{
    ACCOUNT_LOGI("Mock SetAccountPolicy enter.");
    PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    if (parameters == nullptr || parameters->data == nullptr) {
        ACCOUNT_LOGI("Mock SetAccountPolicy data is nullptr.");
        g_authenicationValidityPeriod = -1;
        return error;
    }
    const char *found = std::find(parameters->data, parameters->data + parameters->length, '-');
    g_authenicationValidityPeriod = found != parameters->data + parameters->length ? -1 : 1;
    return error;
}

PluginBussnessError *GetAccountPolicy(const PluginDomainAccountInfo *domainAccountInfo,
    const int32_t callerLocalId, PluginDomainAccountPolicy **domainAccountPolicy)
{
    ACCOUNT_LOGI("Mock GetAccountPolicy enter.");
    PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError* UpdateAccountInfo(const PluginDomainAccountInfo *domainAccountInfo,
    const PluginDomainAccountInfo *newDomainAccountInfo)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError *UnBindAccount(const PluginDomainAccountInfo *domainAccountInfo, const int32_t localId)
{
    ACCOUNT_LOGI("Mock UnBindAccount enter.");
    g_callingLocalId = localId;
    PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError *UnBindAccountError(const PluginDomainAccountInfo *domainAccountInfo, const int32_t localId)
{
    ACCOUNT_LOGI("Mock UnBindAccountError enter.");
    g_callingLocalId = localId;
    PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = g_testErrCode;
    error->msg.data = nullptr;
    return error;
}

int32_t GetCallingLocalId()
{
    return g_callingLocalId;
}

void ResetCallingLocalId()
{
    g_callingLocalId = -1;
}

PluginBussnessError* UpdateServerConfig(const PluginString *serverConfigId, const PluginString *parameters,
    const int32_t localId, PluginServerConfigInfo **serverConfigInfo)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
     *serverConfigInfo = (PluginServerConfigInfo *)malloc(sizeof(PluginServerConfigInfo));
    if (*serverConfigInfo == NULL) {
        error->code = ERROR_CODE;
        return nullptr;
    }

    (*serverConfigInfo)->parameters.data = nullptr;
    SetPluginString(UPDATE_CONFIG_ID, (*serverConfigInfo)->id);
    SetPluginString(DOMAIN, (*serverConfigInfo)->domain);
    return error;
}

PluginBussnessError *AuthBlocking(const PluginDomainAccountInfo *domainAccountInfo, const PluginUint8Vector *credential,
    const int32_t callerLocalId, PluginAuthResultInfoCallback callback, uint64_t *contextId)
{
    ACCOUNT_LOGI("Mock AuthBlock enter.");
    PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }

    time_t authTime;
    (void)time(&authTime);
    g_authTime = authTime;
    ACCOUNT_LOGI("Mock Auth time: %{public}d.", g_authTime);
    g_needWaitCancel = true;
    error->code = 0;
    error->msg.data = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        *contextId = g_contextId;
        g_contextId++;
        g_authResultInfoCallback = callback;
    }
    auto delayCallback = [callback, contextId = *contextId]() {
        ACCOUNT_LOGI("Mock AuthBlocking begin");
        {
                std::unique_lock<std::mutex> lock(g_needWaitCancelMutex);
                g_Cv.wait_for(lock, std::chrono::seconds(WAIT_TIME), [] {
                    return !g_needWaitCancel;
                });
        }
        PluginAuthResultInfo *authResultInfo = (PluginAuthResultInfo *)malloc(sizeof(PluginAuthResultInfo));
        SetPluginUint8Vector({1, 2}, authResultInfo->accountToken);
        authResultInfo->remainTimes = 1;
        authResultInfo->freezingTime = 1;

        PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
        if (error != nullptr) {
            error->code = 0;
            error->msg.data = nullptr;
        }
        time_t authTime;
        (void)time(&authTime);
        g_authTime = authTime;
        callback(contextId, authResultInfo, error);
    };
    std::thread thread(delayCallback);
    pthread_setname_np(thread.native_handle(), "AuthBlocking");
    thread.detach();
    
    return error;
}

PluginBussnessError *CancelAuth(const uint64_t contextId)
{
    if (g_needWaitCancel) {
        g_needWaitCancel = false;
        g_Cv.notify_all();
    }
    PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        ACCOUNT_LOGI("Mock cancel begin");
        PluginAuthResultInfo *authResultInfo = (PluginAuthResultInfo *)malloc(sizeof(PluginAuthResultInfo));
        SetPluginUint8Vector({1, 2}, authResultInfo->accountToken);
        authResultInfo->remainTimes = 1;
        authResultInfo->freezingTime = 1;

        PluginBussnessError *errorCallback = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
        if (errorCallback != nullptr) {
            errorCallback->code = ERR_JS_AUTH_CANCELLED;
            errorCallback->msg.data = nullptr;
        }
        g_authResultInfoCallback(contextId, authResultInfo, errorCallback);
    }
    return error;
}
#ifdef __cplusplus
}
#endif
} // namespace AccountSA
} // namespace OHOS
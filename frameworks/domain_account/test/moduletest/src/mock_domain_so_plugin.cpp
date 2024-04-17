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
#include "account_log_wrapper.h"
#include "mock_domain_so_plugin.h"

namespace OHOS {
namespace AccountSA {
#ifdef __cplusplus
extern "C" {
#endif
static int32_t g_authenicationValidityPeriod = -1;
static int32_t g_authTime = 0;

static void SetPluginString(const std::string &str, PluginString &pStr)
{
    if (str.empty()) {
        ACCOUNT_LOGE("Str is empty.");
        pStr.data = nullptr;
        return;
    }
    pStr.length = str.length();
    pStr.data = strdup(str.c_str());
    return;
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
                          const int32_t callerLocalId, PluginAuthResultInfo **authResultInfo)
{
    ACCOUNT_LOGI("Mock Auth enter.");
    PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }

    time_t authTime;
    (void)time(&authTime);
    g_authTime = authTime;
    ACCOUNT_LOGI("Mock Auth time: %{public}d.", g_authTime);

    error->code = 0;
    error->msg.data = nullptr;

    *authResultInfo = (PluginAuthResultInfo *)malloc(sizeof(PluginAuthResultInfo));
    SetPluginUint8Vector({1, 2}, (*authResultInfo)->accountToken);
    (*authResultInfo)->remainTimes = 1;
    (*authResultInfo)->freezingTime = 1;
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
    return error;
}

PluginBussnessError *IsAuthenticationExpired(const PluginDomainAccountInfo *domainAccountInfo,
                                             const PluginUint8Vector *token, int32_t *isValid)
{
    ACCOUNT_LOGI("Mock IsAuthenticationExpired enter.");
    PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    if (domainAccountInfo == nullptr) {
        return nullptr;
    }

    if (g_authenicationValidityPeriod == -1) {
        ACCOUNT_LOGI("Mock Auth not set.");
        *isValid = 1;
        error->code = 0;
        error->msg.data = nullptr;
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

    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError *SetAccountPolicy(PluginDomainAccountPolicy *domainAccountPolicy)
{
    ACCOUNT_LOGI("Mock SetAccountPolicy enter.");
    PluginBussnessError *error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    g_authenicationValidityPeriod = domainAccountPolicy->authenicationValidityPeriod;
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
#ifdef __cplusplus
}
#endif
} // namespace AccountSA
} // namespace OHOS
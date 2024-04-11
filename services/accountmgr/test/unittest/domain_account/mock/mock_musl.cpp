/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "dlfcn.h"
#include "account_log_wrapper.h"
#include "domain_plugin.h"

namespace OHOS {
namespace AccountSA {
#ifdef __cplusplus
extern "C" {
#endif
static const char* RIGHT_SO = "right.z.so";
static const char* RIGHT_ALL = "/rightPath/right.z.so";
static int g_a = 1;
static void* g_ptr = &g_a;

int dlclose(void *handler)
{
    if (handler == nullptr) {
        ACCOUNT_LOGI("mock dlopen equal");
        errno = 1;
        return 1;
    }
    errno = 0;
    return 0;
}

char *dlerror(void)
{
    ACCOUNT_LOGI("mock dlerror enter");
    if (errno == 0) {
        return nullptr;
    }
    errno = 0;
    return const_cast<char *>(RIGHT_SO);
}

void *dlopen(const char* path, int flag)
{
    ACCOUNT_LOGI("mock dlopen enter");
    if (strcmp(path, RIGHT_SO) == 0 || strcmp(path, RIGHT_ALL) == 0) {
        ACCOUNT_LOGI("mock dlopen equal");
        return g_ptr;
    }
    return nullptr;
}

PluginBussnessError* AddServerConfig(const PluginString *parameters, const int32_t localId,
    PluginServerConfigInfo **serverConfigInfo)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError* RemoveServerConfig(const PluginString *serverConfigId, const int32_t localId)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError* GetAccountServerConfig(const PluginDomainAccountInfo *domainAccountInfo,
    PluginServerConfigInfo **serverConfigInfo)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError* Auth(const PluginDomainAccountInfo *domainAccountInfo,
    const PluginUint8Vector *credential, const int32_t localId, PluginAuthResultInfo **authResultInfo)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError* AuthWithPopup(const PluginDomainAccountInfo *domainAccountInfo,
    PluginAuthResultInfo **authResultInfo)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError* AuthWithToken(const PluginDomainAccountInfo *domainAccountInfo,
    const PluginUint8Vector *token, PluginAuthResultInfo **authResultInfo)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError* GetAccountInfo(const PluginGetDomainAccountInfoOptions *options, const int32_t callerLocalId,
    PluginDomainAccountInfo **domainAccountInfo)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError* GetAuthStatusInfo(const PluginDomainAccountInfo *domainAccountInfo,
    PluginAuthStatusInfo **authStatusInfo)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError* BindAccount(const PluginDomainAccountInfo *domainAccountInfo, const int32_t localId,
    const int32_t callerLocalId)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError* UnbindAccount(const PluginDomainAccountInfo *domainAccountInfo)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
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

PluginBussnessError* IsAccountTokenValid(const PluginDomainAccountInfo *domainAccountInfo,
    const PluginUint8Vector *token, int32_t *isValid)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError* GetAccessToken(const PluginGetDomainAccessTokenOptions *options,
    PluginUint8Vector **accessToken)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError* SetAccountPolicy(const PluginDomainAccountPolicy *domainAccountPolicy)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError* GetServerConfig(const PluginString *serverConfigId, const int32_t callerLocalId,
    PluginServerConfigInfo **serverConfigInfo)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

void *dlsym(void *__restrict, const char * methodName)
{
    if (strcmp(methodName, "AddServerConfig") == 0) {
        return reinterpret_cast<void *>(AddServerConfig);
    }
    if (strcmp(methodName, "RemoveServerConfig") == 0) {
        return reinterpret_cast<void *>(RemoveServerConfig);
    }
    if (strcmp(methodName, "GetAccountServerConfig") == 0) {
        return reinterpret_cast<void *>(GetAccountServerConfig);
    }
    if (strcmp(methodName, "Auth") == 0) {
        return reinterpret_cast<void *>(Auth);
    }
    if (strcmp(methodName, "AuthWithPopup") == 0) {
        return reinterpret_cast<void *>(AuthWithPopup);
    }
    if (strcmp(methodName, "AuthWithToken") == 0) {
        return reinterpret_cast<void *>(AuthWithToken);
    }
    if (strcmp(methodName, "GetAccountInfo") == 0) {
        return reinterpret_cast<void *>(GetAccountInfo);
    }
    if (strcmp(methodName, "GetAuthStatusInfo") == 0) {
        return reinterpret_cast<void *>(GetAuthStatusInfo);
    }
    if (strcmp(methodName, "BindAccount") == 0) {
        return reinterpret_cast<void *>(BindAccount);
    }
    if (strcmp(methodName, "UnbindAccount") == 0) {
        return reinterpret_cast<void *>(UnbindAccount);
    }
    if (strcmp(methodName, "IsAccountTokenValid") == 0) {
        return reinterpret_cast<void *>(IsAccountTokenValid);
    }
    if (strcmp(methodName, "GetAccessToken") == 0) {
        return reinterpret_cast<void *>(GetAccessToken);
    }
    if (strcmp(methodName, "UpdateAccountInfo") == 0) {
        return reinterpret_cast<void *>(UpdateAccountInfo);
    }
    if (strcmp(methodName, "SetAccountPolicy") == 0) {
        return reinterpret_cast<void *>(SetAccountPolicy);
    }
    if (strcmp(methodName, "GetServerConfig") == 0) {
        return reinterpret_cast<void *>(GetServerConfig);
    }
    return nullptr;
}
#ifdef __cplusplus
}
#endif

}  // namespace AccountSA
}  // namespace OHOS
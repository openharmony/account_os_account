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
#include <map>
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
    errno = 1;
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

PluginBussnessError* UpdateServerConfig(const PluginString *serverConfigId, const PluginString *parameters,
    const int32_t localId, PluginServerConfigInfo **serverConfigInfo)
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

PluginBussnessError* GetServerConfigList(PluginServerConfigInfoList **serverConfigInfoList)
{
    PluginServerConfigInfoList *list = (PluginServerConfigInfoList *)malloc(sizeof(PluginServerConfigInfoList));
    if (list == nullptr) {
        return nullptr;
    }
    list->items = nullptr;
    list->size = 0;
    *serverConfigInfoList = list;
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        free(list);
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

using PluginFunction = void* (*)();

static const std::map<std::string, PluginFunction> pluginFunctions = {
    {"AddServerConfig", reinterpret_cast<PluginFunction>(AddServerConfig)},
    {"RemoveServerConfig", reinterpret_cast<PluginFunction>(RemoveServerConfig)},
    {"UpdateServerConfig", reinterpret_cast<PluginFunction>(UpdateServerConfig)},
    {"GetServerConfig", reinterpret_cast<PluginFunction>(GetServerConfig)},
    {"GetServerConfigList", reinterpret_cast<PluginFunction>(GetServerConfigList)},
    {"GetAccountServerConfig", reinterpret_cast<PluginFunction>(GetAccountServerConfig)},
    {"Auth", reinterpret_cast<PluginFunction>(Auth)},
    {"AuthWithPopup", reinterpret_cast<PluginFunction>(AuthWithPopup)},
    {"AuthWithToken", reinterpret_cast<PluginFunction>(AuthWithToken)},
    {"GetAccountInfo", reinterpret_cast<PluginFunction>(GetAccountInfo)},
    {"GetAuthStatusInfo", reinterpret_cast<PluginFunction>(GetAuthStatusInfo)},
    {"BindAccount", reinterpret_cast<PluginFunction>(BindAccount)},
    {"UnbindAccount", reinterpret_cast<PluginFunction>(UnbindAccount)},
    {"IsAccountTokenValid", reinterpret_cast<PluginFunction>(IsAccountTokenValid)},
    {"GetAccessToken", reinterpret_cast<PluginFunction>(GetAccessToken)},
    {"UpdateAccountInfo", reinterpret_cast<PluginFunction>(UpdateAccountInfo)},
    {"SetAccountPolicy", reinterpret_cast<PluginFunction>(SetAccountPolicy)}
};

void *dlsym(void *__restrict, const char *methodName)
{
    const auto it = pluginFunctions.find(methodName);
    if (it != pluginFunctions.end()) {
        return reinterpret_cast<void*>(it->second);
    }
    return nullptr;
}
#ifdef __cplusplus
}
#endif

}  // namespace AccountSA
}  // namespace OHOS
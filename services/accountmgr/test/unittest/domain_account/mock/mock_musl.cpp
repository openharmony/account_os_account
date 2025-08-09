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
static int g_addServerConfig = 0;
const char PARAM_CONTENT_ONE = '1';
const int32_t SERVER_CONFIG_CASE_ONE = 1;
const int32_t SERVER_CONFIG_CASE_TWO = 2;
const int32_t ITEM_SIZE = 2;

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
    *serverConfigInfo = nullptr;
    if (parameters == nullptr || parameters->data == nullptr) {
        return error;
    }
    g_addServerConfig = *(parameters->data) == PARAM_CONTENT_ONE ? SERVER_CONFIG_CASE_ONE : SERVER_CONFIG_CASE_TWO;
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
    if (serverConfigId != nullptr && serverConfigId->data != nullptr && *(serverConfigId->data) == PARAM_CONTENT_ONE) {
        g_addServerConfig = 0;
    }
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

static void AddServerConfigToList(PluginServerConfigInfoList **serverConfigInfoList)
{
    (*serverConfigInfoList)->items = (PluginServerConfigInfo*)malloc(ITEM_SIZE * sizeof(PluginServerConfigInfo));
    if ((*serverConfigInfoList)->items == nullptr) {
        return;
    }
    (*serverConfigInfoList)->size = ITEM_SIZE;
    PluginServerConfigInfo *item = &(*serverConfigInfoList)->items[0];
    item->id.data = strdup(RIGHT_SO);
    item->id.length = strlen(RIGHT_SO);
    item->domain.data = strdup(RIGHT_SO);
    item->domain.length = strlen(RIGHT_SO);
    item->parameters.data = strdup(RIGHT_SO);
    item->parameters.length = strlen(RIGHT_SO);
    PluginServerConfigInfo *item2 = &(*serverConfigInfoList)->items[1];
    item2->id.data = strdup(RIGHT_SO);
    item2->id.length = strlen(RIGHT_SO);
    item2->domain.data = strdup(RIGHT_SO);
    item2->domain.length = strlen(RIGHT_SO);
    item2->parameters.data = nullptr;
    item2->parameters.length = 0;
}

PluginBussnessError* GetServerConfigList(PluginServerConfigInfoList **serverConfigInfoList)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    if (g_addServerConfig == 0) {
        return error;
    }
    PluginServerConfigInfoList *list = (PluginServerConfigInfoList *)malloc(sizeof(PluginServerConfigInfoList));
    if (list == nullptr) {  //GetServerConfigList return serverConfigInfoList is nullptr
        return error;
    }
    if (g_addServerConfig == SERVER_CONFIG_CASE_ONE) {
        list->items = nullptr; // GetServerConfigList return serverConfigInfoList ,items is nullptr
        list->size = 0;
    }
    if (g_addServerConfig == SERVER_CONFIG_CASE_TWO) {
        AddServerConfigToList(&list);
    }
    *serverConfigInfoList = list;
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

PluginBussnessError* UnbindAccount(const PluginDomainAccountInfo *domainAccountInfo, const int32_t localId)
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
    error->msg.data = strdup(RIGHT_SO);
    error->msg.length = strlen(RIGHT_SO);
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

PluginBussnessError* SetAccountPolicy(const PluginString *parameters,
    const PluginDomainAccountInfo *domainAccountInfo, const int32_t callerLocalId)
{
    PluginBussnessError* error = (PluginBussnessError *)malloc(sizeof(PluginBussnessError));
    if (error == nullptr) {
        return nullptr;
    }
    error->code = 0;
    error->msg.data = nullptr;
    return error;
}

PluginBussnessError* GetAccountPolicy(const PluginDomainAccountInfo *domainAccountInfo,
    const int32_t callerLocalId, PluginDomainAccountPolicy **domainAccountPolicy)
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
    {"SetAccountPolicy", reinterpret_cast<PluginFunction>(SetAccountPolicy)},
    {"GetAccountPolicy", reinterpret_cast<PluginFunction>(GetAccountPolicy)}
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
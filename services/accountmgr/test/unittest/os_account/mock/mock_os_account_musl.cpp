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

#include "mock_os_account_dlfcn.h"
#include "account_log_wrapper.h"
#include "os_account_plugin_manager.h"

namespace OHOS {
namespace AccountSA {
#ifdef __cplusplus
extern "C" {
#endif
static const char* RIGHT_SO = "right.z.so";
static const char* RIGHT_ALL = "/rightPath/right.z.so";
static int g_int = 1;
static void* g_ptr = &g_int;

int dlclose(void *handler)
{
    if (handler == nullptr) {
        ACCOUNT_LOGI("Mock handler is null.");
        errno = 1;
        return 1;
    }
    errno = 0;
    return 0;
}

char *dlerror(void)
{
    ACCOUNT_LOGI("Mock dlerror enter.");
    if (errno == 0) {
        return nullptr;
    }
    errno = 0;
    return const_cast<char *>(RIGHT_SO);
}

void *dlopen(const char* path, int flag)
{
    ACCOUNT_LOGI("Mock dlopen enter.");
    if (strcmp(path, RIGHT_SO) == 0 || strcmp(path, RIGHT_ALL) == 0) {
        ACCOUNT_LOGI("Mock dlopen success.");
        return g_ptr;
    }
    return nullptr;
}

int32_t VerifyActivationLock(std::function<int32_t(bool)> callback)
{
    callback(false);
    return 0;
}

void *dlsym(void *__restrict, const char * methodName)
{
    if (strcmp(methodName, "VerifyActivationLock") == 0) {
        ACCOUNT_LOGI("Mock dlsym VerifyActivationLock success.");
        return reinterpret_cast<void *>(VerifyActivationLock);
    }
    ACCOUNT_LOGI("Mock dlsym %{public}s failed.", methodName);
    return nullptr;
}
#ifdef __cplusplus
}
#endif
}  // namespace AccountSA
}  // namespace OHOS
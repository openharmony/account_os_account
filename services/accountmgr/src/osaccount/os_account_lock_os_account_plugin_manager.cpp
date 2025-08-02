/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "os_account_lock_os_account_plugin_manager.h"
#include <chrono>
#include <dlfcn.h>
#include <unistd.h>
#include <future>
#include <pthread.h>
#include <thread>

namespace OHOS {
namespace AccountSA {
namespace {
#ifdef _ARM64_
static const char OS_ACCOUNT_PLUGIN_LIB_PATH[] = "/system/lib64/";
#else
static const char OS_ACCOUNT_PLUGIN_LIB_PATH[] = "/system/lib/";
#endif
static const char OS_ACCOUNT_PLUGIN_LIB_NAME[] = "libos_account_locking_plugin.z.so";
static const char* LOCK_OS_ACCOUNT = "LockUserAccount";
}

OsAccountLockOsAccountPluginManager::OsAccountLockOsAccountPluginManager(
    const std::string &libPath, const std::string &libName)
{
    InitFuncSymbolList();
    LoaderLib(libPath, libName);
    ACCOUNT_LOGI("OsAccountLockOsAccountPluginManager init end.");
}

void OsAccountLockOsAccountPluginManager::InitFuncSymbolList(void)
{
    funcSymbolList_.emplace_back(LOCK_OS_ACCOUNT);
}

OsAccountLockOsAccountPluginManager &OsAccountLockOsAccountPluginManager::GetInstance()
{
    static OsAccountLockOsAccountPluginManager *instance = new (std::nothrow) OsAccountLockOsAccountPluginManager(
        OS_ACCOUNT_PLUGIN_LIB_PATH, OS_ACCOUNT_PLUGIN_LIB_NAME);
    return *instance;
}

ErrCode OsAccountLockOsAccountPluginManager::LockOsAccount(int32_t localId)
{
    std::lock_guard<std::mutex> lock(libMutex_);
    auto iter = methodMap_.find(LOCK_OS_ACCOUNT);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}s not exsit.", LOCK_OS_ACCOUNT);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_PLUGIN_NOT_EXIST_ERROR;
    }

    int32_t res = (*reinterpret_cast<LockOsAccountFunc>(iter->second))(localId);
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Call plugin method failed.");
        return res;
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
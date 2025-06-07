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
static const char OS_ACCOUNT_PLUGIN_LIB_PATH[] = "/system/lib64/platformsdk/";
#else
static const char OS_ACCOUNT_PLUGIN_LIB_PATH[] = "/system/lib/platformsdk/";
#endif
static const char OS_ACCOUNT_PLUGIN_LIB_NAME[] = "liblock_os_account.z.so";
}

OsAccountLockOsAccountPluginManager::OsAccountLockOsAccountPluginManager(
    const std::string &libPath, const std::string &libName)
{}

void OsAccountLockOsAccountPluginManager::InitFuncSymbolList(void)
{}

OsAccountLockOsAccountPluginManager &OsAccountLockOsAccountPluginManager::GetInstance()
{
    static OsAccountLockOsAccountPluginManager *instance =
        new (std::nothrow) OsAccountLockOsAccountPluginManager(
            OS_ACCOUNT_PLUGIN_LIB_PATH, OS_ACCOUNT_PLUGIN_LIB_NAME);
    return *instance;
}

ErrCode OsAccountLockOsAccountPluginManager::LockOsAccount(int32_t localId)
{
    if (libHandle_ == nullptr) {
        ACCOUNT_LOGE("LibHandle_ is nullptr");
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
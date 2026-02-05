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

#include "os_account_activate_lock_plugin_manager.h"
#include <chrono>
#include <dlfcn.h>
#include <unistd.h>
#include <future>
#include <pthread.h>
#include <thread>
#include "hitrace_adapter.h"

namespace OHOS {
namespace AccountSA {
namespace {
#ifdef _ARM64_
static const char OS_ACCOUNT_PLUGIN_LIB_PATH[] = "/system/lib64/platformsdk/";
#else
static const char OS_ACCOUNT_PLUGIN_LIB_PATH[] = "/system/lib/platformsdk/";
#endif
static const char OS_ACCOUNT_PLUGIN_LIB_NAME[] = "libactivation_lock_sdk.z.so";
static const char* VERIFY_ACTIVATION_LOCK = "VerifyActivationLock";
}

OsAccountActivateLockPluginManager::OsAccountActivateLockPluginManager(
    const std::string &libPath, const std::string &libName)
{
    InitFuncSymbolList();
    StartTraceAdapter("LoadActiateLockPlugin");
    LoaderLib(libPath, libName);
    FinishTraceAdapter();
    ACCOUNT_LOGI("OsAccountActivateLockPluginManager init end.");
}

void OsAccountActivateLockPluginManager::InitFuncSymbolList()
{
    funcSymbolList_.emplace_back(VERIFY_ACTIVATION_LOCK);
}

OsAccountActivateLockPluginManager &OsAccountActivateLockPluginManager::GetInstance()
{
    static OsAccountActivateLockPluginManager *instance = new (std::nothrow) OsAccountActivateLockPluginManager(
        OS_ACCOUNT_PLUGIN_LIB_PATH, OS_ACCOUNT_PLUGIN_LIB_NAME);
    return *instance;
}

ErrCode OsAccountActivateLockPluginManager::PluginVerifyActivationLockFunc(bool& isAllowed)
{
    std::lock_guard<std::mutex> lock(libMutex_);
    auto iter = methodMap_.find(VERIFY_ACTIVATION_LOCK);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}s not exsit.", VERIFY_ACTIVATION_LOCK);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_PLUGIN_NOT_EXIST_ERROR;
    }

    auto promise = std::make_shared<std::promise<bool>>();
    auto future = promise->get_future();
    auto callback = [promise] (bool isActivated) mutable -> int32_t {
        promise->set_value(isActivated);
        return ERR_OK;
    };

    int32_t res = (*reinterpret_cast<VerifyActivationLockFunc>(iter->second))(callback);
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Call plugin method failed.");
        return res;
    }
    isAllowed = future.get();
    return ERR_OK;
}

bool OsAccountActivateLockPluginManager::IsCreationAllowed()
{
#if defined(ACCOUNT_TEST) || defined(ACCOUNT_COVERAGE_TEST)
    return true;
#else
    if (!IsPluginAvailable()) {
        ACCOUNT_LOGI("Plugin not availabel.");
        return true;
    }
    bool isAllowed = false;
    ACCOUNT_LOGI("Call plugin method start.");
    ErrCode res = PluginVerifyActivationLockFunc(isAllowed);
    ACCOUNT_LOGI("Call plugin method end.");
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Call IsOsAccountCreationAllowed failed, ErrCode=%{public}d", res);
        return false;
    }
    return isAllowed;
#endif
}
}  // namespace AccountSA
}  // namespace OHOS
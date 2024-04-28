/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "os_account_plugin_manager.h"
#include <chrono>
#include <dlfcn.h>
#include <unistd.h>
#include <future>
#include <pthread.h>
#include <thread>

namespace OHOS {
namespace AccountSA {
namespace {
const int32_t PLUGIN_CALLBACK_TIMEOUT = 5000;
#ifdef _ARM64_
static const std::string OS_ACCOUNT_PLUGIN_LIB_PATH = "/system/lib64/platformsdk/";
#else
static const std::string OS_ACCOUNT_PLUGIN_LIB_PATH = "/system/lib/platformsdk/";
#endif
static const std::string OS_ACCOUNT_PLUGIN_LIB_NAME = "libactivation_lock_sdk.z.so";
}

OsAccountPluginManager::OsAccountPluginManager()
{
    LoaderLib(OS_ACCOUNT_PLUGIN_LIB_PATH, OS_ACCOUNT_PLUGIN_LIB_NAME);
    ACCOUNT_LOGI("OsAccountPluginManager init end.");
}

OsAccountPluginManager::~OsAccountPluginManager()
{
    CloseLib();
}

OsAccountPluginManager &OsAccountPluginManager::GetInstance()
{
    static OsAccountPluginManager *instance = new (std::nothrow) OsAccountPluginManager();
    return *instance;
}

std::string GetMethodNameByEnum(OsPluginMethodEnum methondEnum)
{
    switch (methondEnum) {
        case OsPluginMethodEnum::VERIFY_ACTIVATION_LOCK:
            return "VerifyActivationLock";
        default:
            ACCOUNT_LOGE("Find method name failed, enum=%{public}d.", methondEnum);
            return "";
    }
}

void OsAccountPluginManager::LoaderLib(const std::string &path, const std::string &libName)
{
    if (IsPluginAvailable()) {
        ACCOUNT_LOGE("LibHandle_ is not nullptr.");
        return;
    }
    std::lock_guard<std::mutex> lock(libMutex_);
    std::string soPath = path + libName;
    libHandle_ = dlopen(soPath.c_str(), RTLD_LAZY);
    if (libHandle_ == nullptr) {
        ACCOUNT_LOGE("Call dlopen failed, error=%{public}s.", dlerror());
        return;
    }
    for (auto i = 0; i < static_cast<int>(OsPluginMethodEnum::OS_ACCOUNT_PLUGIN_COUNT); ++i) {
        std::string methodName = GetMethodNameByEnum(static_cast<OsPluginMethodEnum>(i));
        if (methodName.empty()) {
            ACCOUNT_LOGE("Call check methodName empty.");
            dlclose(libHandle_);
            libHandle_ = nullptr;
            methodMap_.clear();
            return;
        }
        dlerror();
        void *func = dlsym(libHandle_, methodName.c_str());
        const char *dlsym_error = dlerror();
        if (dlsym_error) {
            ACCOUNT_LOGE("Call check failed, method=%{public}s error=%{public}s.", methodName.c_str(), dlsym_error);
            dlclose(libHandle_);
            libHandle_ = nullptr;
            methodMap_.clear();
            return;
        }
        methodMap_.emplace(static_cast<OsPluginMethodEnum>(i), func);
    }
    ACCOUNT_LOGI("Load library success.");
}

void OsAccountPluginManager::CloseLib()
{
    std::lock_guard<std::mutex> lock(libMutex_);
    if (libHandle_ == nullptr) {
        ACCOUNT_LOGE("LibHandle_ is nullptr.");
        return;
    }
    dlclose(libHandle_);
    libHandle_ = nullptr;
}

bool OsAccountPluginManager::IsPluginAvailable()
{
    std::lock_guard<std::mutex> lock(libMutex_, std::adopt_lock);
    return libHandle_ != nullptr;
}

ErrCode OsAccountPluginManager::PluginVerifyActivationLockFunc(bool& isAllowed)
{
    std::lock_guard<std::mutex> lock(libMutex_);
    auto iter = methodMap_.find(OsPluginMethodEnum::VERIFY_ACTIVATION_LOCK);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", OsPluginMethodEnum::VERIFY_ACTIVATION_LOCK);
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
    std::chrono::milliseconds span(PLUGIN_CALLBACK_TIMEOUT);
    if (future.wait_for(span) == std::future_status::timeout) {
        ACCOUNT_LOGE("Wait callback timeout.");
        isAllowed = false;
        return ERR_ACCOUNT_COMMON_OPERATION_TIMEOUT;
    }
    isAllowed = future.get();

    return ERR_OK;
}

bool OsAccountPluginManager::IsCreationAllowed()
{
#ifdef ACCOUNT_TEST
    return true;
#else
    if (!IsPluginAvailable()) {
        ACCOUNT_LOGI("Plugin not availabel.");
        return true;
    }
    bool isAllowed = false;
    ErrCode res = PluginVerifyActivationLockFunc(isAllowed);
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Call IsOsAccountCreationAllowed failed, ErrCode=%{public}d", res);
        return false;
    }
    return isAllowed;
#endif
}
}  // namespace AccountSA
}  // namespace OHOS
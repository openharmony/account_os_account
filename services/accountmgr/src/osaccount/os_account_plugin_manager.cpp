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

OsAccountPluginManager::~OsAccountPluginManager()
{
    CloseLib();
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
    for (size_t i = 0; i < funcSymbolList_.size(); i++) {
        std::string methodName = funcSymbolList_[i];
        if (methodName.empty()) {
            ACCOUNT_LOGE("Call check methodName empty.");
            dlclose(libHandle_);
            libHandle_ = nullptr;
            methodMap_.clear();
            return;
        }
        dlerror();
        void *func = dlsym(libHandle_, methodName.c_str());
        if (func == nullptr) {
            ACCOUNT_LOGE("Call check failed, method=%{public}s error=%{public}s.", methodName.c_str(), dlerror());
            dlclose(libHandle_);
            libHandle_ = nullptr;
            methodMap_.clear();
            return;
        }
        methodMap_.emplace(methodName, func);
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
}  // namespace AccountSA
}  // namespace OHOS
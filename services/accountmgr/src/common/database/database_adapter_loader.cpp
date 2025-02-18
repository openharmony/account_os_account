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

#include "database_adapter_loader.h"

#include <dlfcn.h>
#include <thread>
#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"
#include "event_handler.h"
#include "event_runner.h"

namespace OHOS {
namespace AccountSA {
namespace {
const uint32_t DLCLOSE_SLEEP_TIME = 100;
};
DatabaseAdapterLoader &DatabaseAdapterLoader::GetInstance()
{
    static DatabaseAdapterLoader instance;
    return instance;
}

DatabaseAdapterLoader::~DatabaseAdapterLoader()
{
    CheckAndUnload();
}

bool DatabaseAdapterLoader::CheckAndUnload()
{
    std::lock_guard<std::mutex> lock(loadMutex_);
    if (handle_ == nullptr) {
        ACCOUNT_LOGW("DatabaseAdapterLoader has not been loaded");
    } else {
        int32_t err = dlclose(handle_);
        if (err != ERR_OK) {
            char* errMsg = dlerror();
            ACCOUNT_LOGE("Dlclose failed, err: %{public}d, errmsg: %{public}s", err, errMsg);
            return false;
        }
        handle_ = nullptr;
        std::this_thread::sleep_for(std::chrono::milliseconds(DLCLOSE_SLEEP_TIME));
    }
    createFunc_ = nullptr;
    destroyFunc_ = nullptr;
    return true;
}

bool DatabaseAdapterLoader::CheckAndLoad()
{
    std::lock_guard<std::mutex> lock(loadMutex_);
    if ((handle_ != nullptr) && (createFunc_ != nullptr) && (destroyFunc_ != nullptr)) {
        return true;
    }

    if (handle_ == nullptr) {
        handle_ = dlopen("libaccount_database_adapter.z.so", RTLD_LAZY);
        if (handle_ == nullptr) {
            char* errMsg = dlerror();
            ACCOUNT_LOGE("Load libaccount_database_adapter.z.so failed, errMsg: %{public}s", errMsg);
            return false;
        }
    }
    createFunc_ = reinterpret_cast<FUNC_CREATE>(dlsym(handle_, "CreateDataManager"));
    if (createFunc_ == nullptr) {
        char* errMsg = dlerror();
        ACCOUNT_LOGE("Get createDataManager failed, errMsg: %{public}s", errMsg);
        return false;
    }
    destroyFunc_ = reinterpret_cast<FUNC_DESTROY>(dlsym(handle_, "DestroyDataManager"));
    if (destroyFunc_ == nullptr) {
        char* errMsg = dlerror();
        ACCOUNT_LOGE("Get destroyDataManager failed, errMsg: %{public}s", errMsg);
        return false;
    }
    return true;
}

std::shared_ptr<IDbAdapterDataManager> DatabaseAdapterLoader::GetDataManager()
{
    if (!CheckAndLoad()) {
        ACCOUNT_LOGE("Load kvstore adapter failed.");
        return nullptr;
    }
    std::shared_ptr<IDbAdapterDataManager> dataManager(
        createFunc_(),
        [](IDbAdapterDataManager *ptr) {DatabaseAdapterLoader::GetInstance().DestroyDataManager(ptr);});
    return dataManager;
}

void DatabaseAdapterLoader::DestroyDataManager(IDbAdapterDataManager* dataManager)
{
    std::lock_guard<std::mutex> lock(loadMutex_);
    if (destroyFunc_ == nullptr) {
        ACCOUNT_LOGE("Destroy func is null, destroy failed.");
        return;
    }
    destroyFunc_(dataManager);
}
} // namespace AccountSA
} // namespace OHOS
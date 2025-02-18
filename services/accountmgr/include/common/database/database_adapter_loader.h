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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DATABASE_LOADER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DATABASE_LOADER_H

#include <mutex>
#include "database_adapter_interface.h"
#include "event_handler.h"

namespace OHOS {
namespace AccountSA {
namespace {
typedef IDbAdapterDataManager* (*FUNC_CREATE) (void);
typedef void (*FUNC_DESTROY) (IDbAdapterDataManager*);
};

class DatabaseAdapterLoader final {
public:
    static DatabaseAdapterLoader &GetInstance();
    ~DatabaseAdapterLoader();

    std::shared_ptr<IDbAdapterDataManager> GetDataManager();
    void DestroyDataManager(IDbAdapterDataManager* dataManager);
    bool CheckAndUnload();
private:
    bool CheckAndLoad();
    FUNC_CREATE createFunc_ = nullptr;
    FUNC_DESTROY destroyFunc_ = nullptr;
    void *handle_ = nullptr;
    std::mutex loadMutex_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DATABASE_LOADER_H
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_PLUGIN_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_PLUGIN_MANAGER_H

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "safe_map.h"

namespace OHOS {
namespace AccountSA {
class OsAccountPluginManager {
public:
    OsAccountPluginManager() = default;
    ~OsAccountPluginManager();

    void LoaderLib(const std::string &path, const std::string &libName);
    void CloseLib();
    bool IsPluginAvailable();
    virtual void InitFuncSymbolList() {};

protected:
    std::mutex libMutex_;
    std::map<std::string, void*> methodMap_;
    std::vector<const char *> funcSymbolList_;
    void* libHandle_ = nullptr;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_PLUGIN_MANAGER_H

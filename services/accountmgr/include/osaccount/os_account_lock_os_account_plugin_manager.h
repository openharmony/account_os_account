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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_LOCK_OS_ACCOUNT_PLUGIN_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_LOCK_OS_ACCOUNT_PLUGIN_MANAGER_H

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_plugin_manager.h"
#include "safe_map.h"

typedef int32_t (*LockOsAccountFunc)(int32_t localId);

namespace OHOS {
namespace AccountSA {
class OsAccountLockOsAccountPluginManager : public OsAccountPluginManager  {
public:
    ~OsAccountLockOsAccountPluginManager();
    static OsAccountLockOsAccountPluginManager &GetInstance();

    ErrCode LockOsAccount(int32_t localId);
    void InitFuncSymbolList() override;
private:
    OsAccountLockOsAccountPluginManager(const std::string &path, const std::string &libName);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_LOCK_OS_ACCOUNT_PLUGIN_MANAGER_H

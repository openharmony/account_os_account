/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CACHE_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CACHE_MANAGER_H

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include "account_log_wrapper.h"
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
class OsAccountCacheManager {
public:
    OsAccountCacheManager();
    ~OsAccountCacheManager();

    /**
     * Get account type from cache
     * @param id Account ID
     * @return Optional containing the type if found in cache
     */
    std::optional<OsAccountType> GetAccountTypeFromCache(int32_t id);

    /**
     * Set account type in cache
     * @param id Account ID
     * @param type Account type
     */
    void SetAccountTypeInCache(int32_t id, OsAccountType type);

    /**
     * Batch set account types in cache (used for preloading)
     * @param typeMap Map of account ID to type
     */
    void SetAccountTypesInCache(const std::map<int32_t, OsAccountType> &typeMap);

    /**
     * Clear cache for a specific account
     * @param id Account ID
     */
    void ClearAccountCache(int32_t id);

    /**
     * Clear all cached account types
     */
    void ClearAllCache();

private:
    mutable std::mutex cacheLock_;
    std::unordered_map<int32_t, OsAccountType> accountTypeCache_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CACHE_MANAGER_H

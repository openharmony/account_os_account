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
     * Get account type and restricted flag from cache
     * @param id Account ID
     * @return Optional pair of (type, restricted): restricted=true means TEE has no entry and type
     * is sourced from local file; restricted=false means type comes directly from TEE.
     */
    std::optional<std::pair<OsAccountType, bool>> GetAccountTypeFromCache(int32_t id);

    /**
     * Set account type in cache
     * @param id Account ID
     * @param typeAndRestricted Pair of account type and restricted flag.
     * restricted=false: type from TEE (authoritative)
     * restricted=true: TEE has no entry, type from local file
     */
    void SetAccountTypeInCache(int32_t id, const std::pair<OsAccountType, bool> &typeAndRestricted);

    /**
     * Batch set account types in cache (used for preloading)
     * @param typeMap Map of account ID to (type, restricted) pair
     */
    void SetAccountTypesInCache(const std::map<int32_t, std::pair<OsAccountType, bool>> &typeMap);

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
    std::unordered_map<int32_t, std::pair<OsAccountType, bool>> accountTypeCache_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CACHE_MANAGER_H

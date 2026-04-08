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

#include "os_account_cache_manager.h"

namespace OHOS {
namespace AccountSA {
OsAccountCacheManager::OsAccountCacheManager()
{
}

OsAccountCacheManager::~OsAccountCacheManager()
{
    std::lock_guard<std::mutex> lock(cacheLock_);
    accountTypeCache_.clear();
}

std::optional<OsAccountType> OsAccountCacheManager::GetAccountTypeFromCache(int32_t id)
{
    std::lock_guard<std::mutex> lock(cacheLock_);
    auto it = accountTypeCache_.find(id);
    if (it != accountTypeCache_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void OsAccountCacheManager::SetAccountTypeInCache(int32_t id, OsAccountType type)
{
    std::lock_guard<std::mutex> lock(cacheLock_);
    accountTypeCache_[id] = type;
}

void OsAccountCacheManager::SetAccountTypesInCache(const std::map<int32_t, OsAccountType> &typeMap)
{
    std::lock_guard<std::mutex> lock(cacheLock_);
    for (const auto &entry : typeMap) {
        accountTypeCache_[entry.first] = entry.second;
    }
}

void OsAccountCacheManager::ClearAccountCache(int32_t id)
{
    std::lock_guard<std::mutex> lock(cacheLock_);
    auto it = accountTypeCache_.find(id);
    if (it != accountTypeCache_.end()) {
        accountTypeCache_.erase(it);
    }
}

void OsAccountCacheManager::ClearAllCache()
{
    std::lock_guard<std::mutex> lock(cacheLock_);
    accountTypeCache_.clear();
}

}  // namespace AccountSA
}  // namespace OHOS

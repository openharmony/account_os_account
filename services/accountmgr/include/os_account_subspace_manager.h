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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_SUBSPACE_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_SUBSPACE_MANAGER_H

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include "account_error_no.h"
#include "os_account_subspace_data_deal.h"

namespace OHOS {
namespace AccountSA {
/**
 * Manages distributed account space lifecycle (create / remove / switch).
 * Owns the data-deal object and the per-operation mutex; called by
 * OhosAccountManager which is responsible for event publishing.
 */
class OsAccountSubspaceManager {
public:
    static OsAccountSubspaceManager &GetInstance();

    void Init(const std::string &rootPath);
    void CleanupOrphanedSubspaces();

    ErrCode CreateSubspace(int32_t osAccountId, int32_t &newSubspaceId);
    ErrCode RemoveSubspace(int32_t osAccountId, int32_t subspaceId);
    ErrCode SwitchSubspace(int32_t osAccountId, int32_t subspaceId, int32_t &fromSubspaceId);

    bool CheckActiveSessionStatus(
        OsAccountSubspaceDataDeal *dataDeal, int32_t osAccountId, int32_t fromSubspaceId);
    ErrCode LoadSubspaceInfo(int32_t osAccountId, int32_t subspaceId,
        OsAccountSubspaceInfo &info);
    ErrCode SaveSubspaceInfo(const OsAccountSubspaceInfo &info);
    ErrCode ScanOsAccountSubspaceIds(int32_t osAccountId, std::set<int32_t> &validIds);

private:
    OsAccountSubspaceManager() = default;
    ~OsAccountSubspaceManager() = default;

    ErrCode CreateSubspaceLocked(int32_t osAccountId, int32_t &newSubspaceId);
    ErrCode RemoveSubspaceLocked(int32_t osAccountId, int32_t subspaceId);
    ErrCode SwitchSubspaceLocked(int32_t osAccountId, int32_t subspaceId, int32_t &fromSubspaceId);

    std::mutex subspaceOpMutex_;
    std::string rootPath_;
    std::unique_ptr<OsAccountSubspaceDataDeal> subspaceDataDeal_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_SUBSPACE_MANAGER_H

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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_SUB_PROFILE_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_SUB_PROFILE_MANAGER_H

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include "account_error_no.h"
#include "account_info.h"
#include "os_account_info.h"
#include "sub_profile_context.h"
#include "os_account_subspace_data_deal.h"

namespace OHOS {
namespace AccountSA {
/**
 * Manages distributed account space lifecycle (create / remove / switch).
 * Owns the data-deal object and the per-operation mutex; called by
 * OhosAccountManager which is responsible for event publishing.
 */
class OsAccountSubProfileManager {
public:
    static OsAccountSubProfileManager &GetInstance();

    void Init(const std::string &rootPath);
    void CleanupOrphanedSubProfiles();

    ErrCode CreateSubProfile(int32_t osAccountId, int32_t &newSubspaceId, int32_t &outIndex);
    ErrCode RemoveSubProfile(int32_t osAccountId, int32_t subspaceId);
    ErrCode SwitchSubProfile(int32_t osAccountId, int32_t subspaceId, int32_t &fromSubspaceId);

    ErrCode GetSubProfileIds(int32_t osAccountId, std::vector<int32_t> &subProfileIds);
    ErrCode GetLocalIdForSubProfile(int32_t subProfileId, int32_t &osAccountId);
    ErrCode GetSubProfile(int32_t osAccountId, int32_t subProfileId,
        OsAccountSubspaceResult &subspaceResult, OhosAccountInfo &distributedInfo);
    ErrCode GetSubProfileIdByLocalIdAndAppIndex(
        int32_t osAccountId, int32_t appIndex, int32_t &subProfileId);
    ErrCode GetSubProfileIndexByLocalIdAndSubProfileId(
        int32_t osAccountId, int32_t subProfileId, int32_t &index);

    bool CheckActiveSessionStatus(
        OsAccountSubProfileDataDeal *dataDeal, int32_t osAccountId, int32_t fromSubspaceId);
    ErrCode LoadSubProfileInfo(int32_t osAccountId, int32_t subspaceId,
        OsAccountSubspaceInfo &info);
    ErrCode SaveSubProfileInfo(const OsAccountSubspaceInfo &info);
    ErrCode ScanOsAccountSubProfileIds(int32_t osAccountId, std::set<int32_t> &validIds);

private:
    OsAccountSubProfileManager() = default;
    ~OsAccountSubProfileManager() = default;

    ErrCode CreateSubProfileLocked(int32_t osAccountId, int32_t &newSubspaceId, int32_t &outIndex);
    ErrCode AllocateAndPersistSubProfile(int32_t osAccountId, SubProfileContext &subprofileCtx,
        int32_t newSubspaceId, int32_t &outIndex);
    void RollbackSubProfileCreation(int32_t osAccountId, int32_t newSubspaceId,
        int32_t allocatedIndex, SubProfileContext &subprofileCtx);
    ErrCode RemoveSubProfileLocked(int32_t osAccountId, int32_t subspaceId);
    void UpdateContextAfterRemove(int32_t osAccountId, int32_t subspaceId);
    ErrCode SwitchSubProfileLocked(int32_t osAccountId, int32_t subspaceId, int32_t &fromSubspaceId);
    void RemoveOsAccountSubProfileInfo(int32_t osAccountId, int32_t subspaceId,
        const SubProfileContext &subprofileCtx);
    ErrCode TryReclaimSubProfileSlots(int32_t osAccountId, SubProfileContext &subprofileCtx);
    int32_t RemoveGarbageSubProfiles(int32_t osAccountId);
    void PurgeGarbageIdsFromContext(int32_t osAccountId, const std::set<int32_t> &garbageIds);
    ErrCode GetHeadlessSubProfile(int32_t osAccountId, int32_t subProfileId,
        OsAccountSubspaceResult &subspaceResult, OhosAccountInfo &distributedInfo);
    ErrCode ResolveSubProfileIndexFromContext(int32_t osAccountId, int32_t subProfileId,
        int32_t &resolvedIndex);
    ErrCode FilterValidSubProfileIdsLocked(int32_t base,
        const std::vector<std::pair<int32_t, OsAccountSubspaceInfo>> &loadedProfiles,
        std::vector<int32_t> &subProfileIds);

    std::shared_mutex subProfileOpMutex_;
    std::string rootPath_;
    std::unique_ptr<OsAccountSubProfileDataDeal> subProfileDataDeal_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_SUB_PROFILE_MANAGER_H

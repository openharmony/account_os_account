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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_SUB_PROFILE_DATA_DEAL_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_SUB_PROFILE_DATA_DEAL_H

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

#include <dirent.h>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include "account_error_no.h"
#include "account_file_operator.h"
#include "account_info.h"
#include "os_account_sub_profile_id_counter.h"

namespace OHOS {
namespace AccountSA {

extern const int32_t MAX_OS_ACCOUNT_SUB_PROFILE_COUNT;

/**
 * @brief Handles read/write of non-0 OS account subspace account.json files.
 *
 * File path: {configRootDir}/{osAccountId}/{subspaceId}/account.json
 */
class OsAccountSubProfileDataDeal {
public:

public:
    explicit OsAccountSubProfileDataDeal(const std::string &configRootDir);
    ~OsAccountSubProfileDataDeal() = default;

    ErrCode AllocateOsAccountSubProfileId(int32_t &outId);

    /**
     * @brief Scan non-0 OS account subspace directories under osAccountId.
     * Returns only subspaces where is_create_completed=true and to_be_removed=false.
     *
     * @param osAccountId  the OS account ID
     * @param validIds     output: set of valid subspaceIds
     * @return ERR_OK always (invalid subspaces are simply skipped)
     */
    ErrCode ScanOsAccountSubProfileIds(int32_t osAccountId, std::set<int32_t> &validIds) const;

    /**
     * @brief Write OsAccountSubspaceInfo to the corresponding account.json.
     *
     * @param info  subspace info to persist
     * @return ERR_OK on success
     */
    ErrCode SaveSubProfileInfo(const OsAccountSubspaceInfo &info);

    /**
     * @brief Read OsAccountSubspaceInfo from account.json.
     *
     * @param osAccountId   OS account ID
     * @param subspaceId    OS account subspace ID
     * @param info          output: loaded subspace info
     * @return ERR_OK on success, error code otherwise
     */
    ErrCode LoadSubProfileInfo(int32_t osAccountId, int32_t subspaceId,
        OsAccountSubspaceInfo &info) const;

    /**
     * @brief Remove the entire OS account subspace directory.
     *
     * @param osAccountId   OS account ID
     * @param subspaceId    OS account subspace ID
     * @return ERR_OK on success
     */
    ErrCode RemoveSubProfileDir(int32_t osAccountId, int32_t subspaceId);

    /**
     * @brief Scan non-0 OS account subspace directories for orphaned (incomplete) subspaces.
     * Returns IDs where is_create_completed=false (crash survivors that need cleanup).
     *
     * @param osAccountId  the OS account ID
     * @param orphanIds    output: set of orphaned subspaceIds
     * @return ERR_OK always (missing dirs are simply skipped)
     */
    ErrCode ScanOrphanedSubProfileIds(int32_t osAccountId, std::set<int32_t> &orphanIds) const;

    /**
     * @brief Scan non-0 OS account subspace directories for subspaces pending removal.
     * Returns IDs where to_be_removed=true (crash survivors from an interrupted remove operation).
     *
     * @param osAccountId      the OS account ID
     * @param pendingRemoveIds output: set of subspaceIds with to_be_removed=true
     * @return ERR_OK always (missing dirs are simply skipped)
     */
    ErrCode ScanPendingRemovalSubProfileIds(int32_t osAccountId, std::set<int32_t> &pendingRemoveIds) const;

    /**
     * @brief Check whether a valid (completed, not-to-be-removed) subspace exists.
     */
    bool IsValidSubProfileExists(int32_t osAccountId, int32_t subspaceId) const;

private:
    static int32_t ParseDirEntryAsSubProfileId(const struct dirent *entry, int32_t osAccountId);
    std::string GetSubProfileDir(int32_t osAccountId, int32_t subspaceId) const;
    std::string GetSubProfileFilePath(int32_t osAccountId, int32_t subspaceId) const;
    ErrCode ParseSubProfileInfoFromJson(const std::string &jsonStr, OsAccountSubspaceInfo &info) const;
    std::string SerializeSubProfileInfoToJson(const OsAccountSubspaceInfo &info) const;
    ErrCode ScanSubProfileIds(int32_t osAccountId,
        std::function<bool(const OsAccountSubspaceInfo &)> filter,
        std::set<int32_t> &resultIds) const;

    std::string configRootDir_;
    std::shared_ptr<AccountFileOperator> fileOperator_;
};

}  // namespace AccountSA
}  // namespace OHOS

#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_SUB_PROFILE_DATA_DEAL_H

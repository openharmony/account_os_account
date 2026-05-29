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

#include "os_account_subspace_manager.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_state_machine.h"
#include "iinner_os_account_manager.h"
#include "os_account_constants.h"
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
OsAccountSubspaceManager &OsAccountSubspaceManager::GetInstance()
{
    static OsAccountSubspaceManager instance;
    return instance;
}

void OsAccountSubspaceManager::Init(const std::string &rootPath)
{
    std::lock_guard<std::mutex> lock(subspaceOpMutex_);
    rootPath_ = rootPath;
    subspaceDataDeal_ = std::make_unique<OsAccountSubspaceDataDeal>(rootPath);
}

void OsAccountSubspaceManager::CleanupOrphanedSubspaces()
{
    // Crash-recovery: remove orphaned space dirs with is_create_completed=false
    // and pending-removal spaces with to_be_removed=true.
    // Runs once at startup; acquires mutex to avoid racing with concurrent operations.
    std::unique_lock<std::mutex> lock(subspaceOpMutex_);
    std::vector<OsAccountInfo> osAccountInfos;
    ErrCode ret = IInnerOsAccountManager::GetInstance().QueryAllCreatedOsAccounts(osAccountInfos);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("QueryAllCreatedOsAccounts failed, ret=%{public}d, skip orphaned subspace cleanup", ret);
        return;
    }
    for (const auto &info : osAccountInfos) {
        std::set<int32_t> orphanIds;
        subspaceDataDeal_->ScanOrphanedSubspaceIds(info.GetLocalId(), orphanIds);
        for (int32_t distId : orphanIds) {
            ACCOUNT_LOGW("CleanupOrphanSubspace, osAccountId=%{public}d, subspaceId=%{public}d",
                info.GetLocalId(), distId);
            subspaceDataDeal_->RemoveSubspaceDir(info.GetLocalId(), distId);
        }

        std::set<int32_t> pendingRemoveIds;
        subspaceDataDeal_->ScanPendingRemovalSubspaceIds(info.GetLocalId(), pendingRemoveIds);
        for (int32_t distId : pendingRemoveIds) {
            ACCOUNT_LOGW("CleanupPendingRemovalSubspace, osAccountId=%{public}d, subspaceId=%{public}d",
                info.GetLocalId(), distId);
            subspaceDataDeal_->RemoveSubspaceDir(info.GetLocalId(), distId);
        }
    }
}

ErrCode OsAccountSubspaceManager::CreateSubspace(int32_t osAccountId, int32_t &newSubspaceId)
{
    std::unique_lock<std::mutex> lock(subspaceOpMutex_);
    return CreateSubspaceLocked(osAccountId, newSubspaceId);
}

ErrCode OsAccountSubspaceManager::RemoveSubspace(int32_t osAccountId, int32_t subspaceId)
{
    std::unique_lock<std::mutex> lock(subspaceOpMutex_);
    return RemoveSubspaceLocked(osAccountId, subspaceId);
}

ErrCode OsAccountSubspaceManager::SwitchSubspace(
    int32_t osAccountId, int32_t subspaceId, int32_t &fromSubspaceId)
{
    std::unique_lock<std::mutex> lock(subspaceOpMutex_);
    return SwitchSubspaceLocked(osAccountId, subspaceId, fromSubspaceId);
}

ErrCode OsAccountSubspaceManager::CreateSubspaceLocked(int32_t osAccountId, int32_t &newSubspaceId)
{
    std::set<int32_t> validIds;
    subspaceDataDeal_->ScanOsAccountSubspaceIds(osAccountId, validIds);
    if (static_cast<int32_t>(validIds.size()) >= MAX_OS_ACCOUNT_SUBSPACE_COUNT) {
        ACCOUNT_LOGE("Distributed account space count reached limit for osAccountId=%{public}d", osAccountId);
        return ERR_OS_ACCOUNT_SUBSPACE_LIMIT;
    }

    std::set<int32_t> usedIndices;
    int32_t base = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    for (int32_t id : validIds) {
        usedIndices.insert(id - base);
    }
    // Safe to ignore return: validIds.size() < MAX guarantees an unused index exists.
    (void)OsAccountSubspaceDataDeal::AllocateOsAccountSubspaceId(
        osAccountId, usedIndices, newSubspaceId);
    ErrCode ret;
    OsAccountSubspaceInfo info;
    info.subspaceId = newSubspaceId;
    info.userId_ = osAccountId;
    info.isCreateCompleted = false;
    info.toBeRemoved = false;
    info.version_ = ACCOUNT_VERSION_ANON;
    info.bindTime_ = 0;
    info.ohosAccountInfo_.name_ = DEFAULT_OHOS_ACCOUNT_NAME;
    info.ohosAccountInfo_.uid_ = DEFAULT_OHOS_ACCOUNT_UID;
    info.ohosAccountInfo_.SetRawUid(DEFAULT_OHOS_ACCOUNT_UID);
    info.ohosAccountInfo_.status_ = ACCOUNT_STATE_UNBOUND;
    info.ohosAccountInfo_.callingUid_ = DEFAULT_CALLING_UID;
    ret = subspaceDataDeal_->SaveSubspaceInfo(info);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("SaveSubspaceInfo incomplete failed, subspaceId=%{public}d, ret=%{public}d",
            newSubspaceId, ret);
        subspaceDataDeal_->RemoveSubspaceDir(osAccountId, newSubspaceId);
        return ret;
    }

    info.isCreateCompleted = true;
    ret = subspaceDataDeal_->SaveSubspaceInfo(info);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("SaveSubspaceInfo complete failed, subspaceId=%{public}d, ret=%{public}d",
            newSubspaceId, ret);
        subspaceDataDeal_->RemoveSubspaceDir(osAccountId, newSubspaceId);
        return ret;
    }
    return ERR_OK;
}

ErrCode OsAccountSubspaceManager::RemoveSubspaceLocked(int32_t osAccountId, int32_t subspaceId)
{
    if (!subspaceDataDeal_->IsValidSubspaceExists(osAccountId, subspaceId)) {
        ACCOUNT_LOGE("Distributed account space %{public}d does not exist or is not valid", subspaceId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }

    OsAccountInfo osAccountInfo;
    if (IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(osAccountId, osAccountInfo) == ERR_OK) {
        if (osAccountInfo.GetForegroundSubspaceId() == subspaceId) {
            ACCOUNT_LOGE("Cannot remove foreground distributed account space %{public}d", subspaceId);
            return ERR_OS_ACCOUNT_SUBSPACE_IS_FOREGROUND;
        }
    }

    OsAccountSubspaceInfo info;
    // Safe to ignore: IsValidSubspaceExists above already called LoadSubspaceInfo under the same mutex
    // and validated the subspace, so the load here is guaranteed to succeed.
    (void)subspaceDataDeal_->LoadSubspaceInfo(osAccountId, subspaceId, info);
    info.toBeRemoved = true;
    ErrCode saveRet = subspaceDataDeal_->SaveSubspaceInfo(info);
    if (saveRet != ERR_OK) {
        ACCOUNT_LOGE("SaveSubspaceInfo toBeRemoved failed, subspaceId=%{public}d, ret=%{public}d",
            subspaceId, saveRet);
        return saveRet;
    }

    ErrCode ret = subspaceDataDeal_->RemoveSubspaceDir(osAccountId, subspaceId);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("RemoveSubspaceDir failed for distId=%{public}d, ret=%{public}d", subspaceId, ret);
    }
    return ret;
}

bool OsAccountSubspaceManager::CheckActiveSessionStatus(
    OsAccountSubspaceDataDeal *dataDeal, int32_t osAccountId, int32_t fromSubspaceId)
{
    if (dataDeal == nullptr) {
        return false;
    }
    // index-0 subspace is checked in OhosAccountManager under mgrMutex_ — not here.
    int32_t base = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    if (fromSubspaceId == base) {
        return false;
    }
    OsAccountSubspaceInfo spaceInfo;
    if (dataDeal->LoadSubspaceInfo(osAccountId, fromSubspaceId, spaceInfo) == ERR_OK) {
        if (spaceInfo.ohosAccountInfo_.status_ == ACCOUNT_STATE_LOGIN) {
            return true;
        }
    }
    return false;
}

ErrCode OsAccountSubspaceManager::SwitchSubspaceLocked(
    int32_t osAccountId, int32_t subspaceId, int32_t &fromSubspaceId)
{
    // index-0 subspace always exists, skip file-based existence check
    int32_t base = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    if (subspaceId != base && !subspaceDataDeal_->IsValidSubspaceExists(osAccountId, subspaceId)) {
        ACCOUNT_LOGE("OS account subspace %{public}d does not exist or is not valid", subspaceId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    OsAccountInfo osAccountInfo;
    if (IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(osAccountId, osAccountInfo) != ERR_OK) {
        ACCOUNT_LOGE("GetOsAccountInfoById failed for osAccountId=%{public}d", osAccountId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    fromSubspaceId = osAccountInfo.GetForegroundSubspaceId();
    if (CheckActiveSessionStatus(subspaceDataDeal_.get(), osAccountId, fromSubspaceId)) {
        ACCOUNT_LOGE("Current foreground OS account subspace has active session");
        return ERR_OS_ACCOUNT_SUBSPACE_HAS_ACTIVE_SESSION;
    }
    ErrCode ret = IInnerOsAccountManager::GetInstance().SetOsAccountForegroundSubspaceId(
        osAccountId, subspaceId);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("SetOsAccountForegroundSubspaceId failed, ret=%{public}d", ret);
    }
    return ret;
}
}  // namespace AccountSA
}  // namespace OHOS

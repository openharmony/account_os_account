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
#include <algorithm>
#include <shared_mutex>
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_state_machine.h"
#include "hitrace_adapter.h"
#include "iinner_os_account_manager.h"
#include "account_hisysevent_adapter.h"
#include "os_account_constants.h"
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
OsAccountSubProfileManager &OsAccountSubProfileManager::GetInstance()
{
    static OsAccountSubProfileManager instance;
    return instance;
}

void OsAccountSubProfileManager::Init(const std::string &rootPath)
{
    std::lock_guard<std::shared_mutex> lock(subProfileOpMutex_);
    rootPath_ = rootPath;
    subProfileDataDeal_ = std::make_unique<OsAccountSubProfileDataDeal>(rootPath);
}

void OsAccountSubProfileManager::CleanupOrphanedSubProfiles()
{
    // Crash-recovery: remove orphaned space dirs with is_create_completed=false
    // and pending-removal spaces with to_be_removed=true.
    // Runs once at startup; acquires mutex to avoid racing with concurrent operations.
    std::lock_guard<std::shared_mutex> lock(subProfileOpMutex_);
    std::vector<OsAccountInfo> osAccountInfos;
    ErrCode ret = IInnerOsAccountManager::GetInstance().QueryAllCreatedOsAccounts(osAccountInfos);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("QueryAllCreatedOsAccounts failed, ret=%{public}d, skip orphaned subspace cleanup", ret);
        return;
    }
    for (const auto &info : osAccountInfos) {
        std::set<int32_t> orphanIds;
        subProfileDataDeal_->ScanOrphanedSubProfileIds(info.GetLocalId(), orphanIds);
        for (int32_t distId : orphanIds) {
            ACCOUNT_LOGW("CleanupOrphanSubProfile, osAccountId=%{public}d, subspaceId=%{public}d",
                info.GetLocalId(), distId);
            subProfileDataDeal_->RemoveSubProfileDir(info.GetLocalId(), distId);
        }

        std::set<int32_t> pendingRemoveIds;
        subProfileDataDeal_->ScanPendingRemovalSubProfileIds(info.GetLocalId(), pendingRemoveIds);
        for (int32_t distId : pendingRemoveIds) {
            ACCOUNT_LOGW("CleanupPendingRemovalSubProfile, osAccountId=%{public}d, subspaceId=%{public}d",
                info.GetLocalId(), distId);
            subProfileDataDeal_->RemoveSubProfileDir(info.GetLocalId(), distId);
        }
    }
}

ErrCode OsAccountSubProfileManager::CreateSubProfile(int32_t osAccountId, int32_t &newSubspaceId, int32_t &outIndex)
{
    StartTraceAdapter("CreateSubProfile");
    std::lock_guard<std::shared_mutex> lock(subProfileOpMutex_);
    ErrCode result = CreateSubProfileLocked(osAccountId, newSubspaceId, outIndex);
    FinishTraceAdapter();
    return result;
}

ErrCode OsAccountSubProfileManager::RemoveSubProfile(int32_t osAccountId, int32_t subspaceId)
{
    std::lock_guard<std::shared_mutex> lock(subProfileOpMutex_);
    return RemoveSubProfileLocked(osAccountId, subspaceId);
}

ErrCode OsAccountSubProfileManager::SwitchSubProfile(
    int32_t osAccountId, int32_t subspaceId, int32_t &fromSubspaceId)
{
    std::lock_guard<std::shared_mutex> lock(subProfileOpMutex_);
    return SwitchSubProfileLocked(osAccountId, subspaceId, fromSubspaceId);
}

ErrCode OsAccountSubProfileManager::CreateSubProfileLocked(int32_t osAccountId, int32_t &newSubspaceId,
    int32_t &outIndex)
{
    SubProfileContext subprofileCtx;
    ErrCode ret = IInnerOsAccountManager::GetInstance().ReadSubProfileContext(osAccountId, subprofileCtx);
    if (ret == ERR_ACCOUNT_COMMON_FILE_NOT_EXIST) {
        ACCOUNT_LOGI("subprofile_info.json not found for osAccountId=%{public}d, initializing with headless defaults",
            osAccountId);
        subprofileCtx = SubProfileContext::CreateWithHeadlessDefault(osAccountId);
    } else if (ret != ERR_OK) {
        ACCOUNT_LOGE("ReadSubProfileContext failed for osAccountId=%{public}d, ret=%{public}d",
            osAccountId, ret);
        return ret;
    }

    auto &subProfileIdList = subprofileCtx.subProfileIdList;
    if (static_cast<int32_t>(subProfileIdList.size()) >= MAX_OS_ACCOUNT_SUB_PROFILE_COUNT) {
        ErrCode reclaimRet = TryReclaimSubProfileSlots(osAccountId, subprofileCtx);
        if (reclaimRet != ERR_OK) {
            return reclaimRet;
        }
    }

    ErrCode allocRet = subProfileDataDeal_->AllocateOsAccountSubProfileId(
        osAccountId, subprofileCtx.nextSubProfileId,
        subprofileCtx.subProfileIdList, newSubspaceId);
    if (allocRet != ERR_OK) {
        ACCOUNT_LOGE("AllocateOsAccountSubProfileId failed for osAccountId=%{public}d, ret=%{public}d",
            osAccountId, allocRet);
        return allocRet;
    }

    return AllocateAndPersistSubProfile(osAccountId, subprofileCtx, newSubspaceId, outIndex);
}

ErrCode OsAccountSubProfileManager::AllocateAndPersistSubProfile(int32_t osAccountId,
    SubProfileContext &subprofileCtx, int32_t newSubspaceId, int32_t &outIndex)
{
    auto &subProfileIndexMap = subprofileCtx.subProfileIndexMap;
    int32_t nextIndex = subprofileCtx.nextSubProfileIndex;
    int32_t allocatedIndex = 0;
    ErrCode indexRet = subProfileDataDeal_->AllocateSubProfileIndex(nextIndex, subProfileIndexMap, allocatedIndex);
    if (indexRet != ERR_OK) {
        ACCOUNT_LOGE("AllocateSubProfileIndex failed for osAccountId=%{public}d, ret=%{public}d",
            osAccountId, indexRet);
        return indexRet;
    }
    outIndex = allocatedIndex;

    int32_t base = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    int32_t subspaceOffset = newSubspaceId - base;

    auto &subProfileIdList = subprofileCtx.subProfileIdList;
    subProfileIdList.push_back(newSubspaceId);
    subProfileIndexMap[allocatedIndex] = newSubspaceId;
    int32_t nextSubProfileIndex = allocatedIndex + 1;
    SubProfileContext persistData(newSubspaceId + 1, subProfileIdList,
        nextSubProfileIndex, subProfileIndexMap);
    ErrCode updateRet = IInnerOsAccountManager::GetInstance().UpdateOsAccountSubspaceInfo(
        osAccountId, persistData);
    if (updateRet != ERR_OK) {
        ACCOUNT_LOGE("UpdateOsAccountSubspaceInfo failed for osAccountId=%{public}d, ret=%{public}d, aborting",
            osAccountId, updateRet);
        return updateRet;
    }

    OsAccountSubspaceInfo info(osAccountId, newSubspaceId, allocatedIndex, subspaceOffset);
    info.isCreateCompleted = true;
    ErrCode ret = subProfileDataDeal_->SaveSubProfileInfo(info);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("SaveSubProfileInfo failed, subspaceId=%{public}d, ret=%{public}d",
            newSubspaceId, ret);
        RollbackSubProfileCreation(osAccountId, newSubspaceId, allocatedIndex, subprofileCtx);
        return ret;
    }
    return ERR_OK;
}

void OsAccountSubProfileManager::RollbackSubProfileCreation(int32_t osAccountId, int32_t newSubspaceId,
    int32_t allocatedIndex, SubProfileContext &subprofileCtx)
{
    subProfileDataDeal_->RemoveSubProfileDir(osAccountId, newSubspaceId);
    subprofileCtx.subProfileIdList.pop_back();
    subprofileCtx.subProfileIndexMap.erase(allocatedIndex);
    ErrCode rollbackRet = IInnerOsAccountManager::GetInstance().UpdateOsAccountSubspaceInfo(
        osAccountId, subprofileCtx);
    if (rollbackRet != ERR_OK) {
        ACCOUNT_LOGE("Rollback UpdateOsAccountSubspaceInfo failed, subspaceId=%{public}d may leak, ret=%{public}d",
            newSubspaceId, rollbackRet);
    }
}

void OsAccountSubProfileManager::UpdateContextAfterRemove(
    int32_t osAccountId, int32_t subspaceId)
{
    SubProfileContext subprofileCtx;
    ErrCode ctxRet = IInnerOsAccountManager::GetInstance().ReadSubProfileContext(
        osAccountId, subprofileCtx);
    if (ctxRet == ERR_OK) {
        RemoveOsAccountSubProfileInfo(osAccountId, subspaceId, subprofileCtx);
    } else if (ctxRet == ERR_ACCOUNT_COMMON_FILE_NOT_EXIST) {
        ACCOUNT_LOGI("No SubProfileContext to update after removing subspaceId=%{public}d", subspaceId);
    } else {
        ACCOUNT_LOGE("ReadSubProfileContext failed after remove, ret=%{public}d, subspaceId=%{public}d",
            ctxRet, subspaceId);
        REPORT_OS_ACCOUNT_FAIL(osAccountId, Constants::OPERATION_SUBPROFILE_DELETE,
            ctxRet, "SubProfileContext read failed after directory delete, stale mapping may persist");
    }
}

ErrCode OsAccountSubProfileManager::RemoveSubProfileLocked(int32_t osAccountId, int32_t subspaceId)
{
    int32_t base = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    if (subspaceId == base) {
        ACCOUNT_LOGE("Cannot remove headless subprofile (index=0, subspaceId=%{public}d)", subspaceId);
        return ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED;
    }
    if (!subProfileDataDeal_->IsValidSubProfileExists(osAccountId, subspaceId)) {
        ACCOUNT_LOGE("Distributed account space %{public}d does not exist or is not valid", subspaceId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }

    OsAccountInfo osAccountInfo;
    ErrCode infoRet = IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(osAccountId, osAccountInfo);
    if (infoRet == ERR_OK) {
        if (osAccountInfo.GetForegroundSubProfileId() == subspaceId) {
            ACCOUNT_LOGE("Cannot remove foreground distributed account space %{public}d", subspaceId);
            return ERR_OS_ACCOUNT_SUBSPACE_IS_FOREGROUND;
        }
    }

    OsAccountSubspaceInfo info;
    // Safe to ignore: IsValidSubProfileExists above already validated the subspace.
    (void)subProfileDataDeal_->LoadSubProfileInfo(osAccountId, subspaceId, info);
    info.toBeRemoved = true;
    ErrCode saveRet = subProfileDataDeal_->SaveSubProfileInfo(info);
    if (saveRet != ERR_OK) {
        ACCOUNT_LOGE("SaveSubProfileInfo toBeRemoved failed, subspaceId=%{public}d, ret=%{public}d",
            subspaceId, saveRet);
        return saveRet;
    }

    ErrCode ret = subProfileDataDeal_->RemoveSubProfileDir(osAccountId, subspaceId);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("RemoveSubProfileDir failed for distId=%{public}d, ret=%{public}d", subspaceId, ret);
    } else {
        UpdateContextAfterRemove(osAccountId, subspaceId);
    }
    return ret;
}

void OsAccountSubProfileManager::RemoveOsAccountSubProfileInfo(
    int32_t osAccountId, int32_t subspaceId, const SubProfileContext &subprofileCtx)
{
    auto subProfileIdList = subprofileCtx.subProfileIdList;
    auto it = std::find(subProfileIdList.begin(), subProfileIdList.end(), subspaceId);
    if (it == subProfileIdList.end()) {
        return;
    }
    subProfileIdList.erase(it);

    auto subProfileIndexMap = subprofileCtx.subProfileIndexMap;
    for (auto mapIt = subProfileIndexMap.begin(); mapIt != subProfileIndexMap.end(); ++mapIt) {
        if (mapIt->second == subspaceId) {
            subProfileIndexMap.erase(mapIt);
            break;
        }
    }

    SubProfileContext removeData(subprofileCtx.nextSubProfileId, subProfileIdList,
        subprofileCtx.nextSubProfileIndex, subProfileIndexMap);
    ErrCode updateRet = IInnerOsAccountManager::GetInstance().UpdateOsAccountSubspaceInfo(
        osAccountId, removeData);
    if (updateRet != ERR_OK) {
        ACCOUNT_LOGE("UpdateOsAccountSubspaceInfo after remove failed, ret=%{public}d", updateRet);
        REPORT_OS_ACCOUNT_FAIL(osAccountId, Constants::OPERATION_SUBPROFILE_DELETE,
            updateRet, "UpdateOsAccountSubspaceInfo after remove failed");
    }
}

ErrCode OsAccountSubProfileManager::TryReclaimSubProfileSlots(
    int32_t osAccountId, SubProfileContext &subprofileCtx)
{
    int32_t cleaned = RemoveGarbageSubProfiles(osAccountId);
    if (cleaned <= 0) {
        ACCOUNT_LOGE("Distributed account space count reached limit for osAccountId=%{public}d", osAccountId);
        REPORT_OS_ACCOUNT_FAIL(osAccountId, Constants::OPERATION_SUBPROFILE_CREATE,
            ERR_OS_ACCOUNT_SUBSPACE_LIMIT, "No garbage to reclaim, at limit");
        return ERR_OS_ACCOUNT_SUBSPACE_LIMIT;
    }
    ErrCode refreshRet = IInnerOsAccountManager::GetInstance().ReadSubProfileContext(
        osAccountId, subprofileCtx);
    if (refreshRet == ERR_ACCOUNT_COMMON_FILE_NOT_EXIST) {
        subprofileCtx = SubProfileContext::CreateWithHeadlessDefault(osAccountId);
    } else if (refreshRet != ERR_OK) {
        ACCOUNT_LOGE("Refresh SubProfileContext after cleanup failed, ret=%{public}d", refreshRet);
        return ERR_OS_ACCOUNT_SUBSPACE_LIMIT;
    }
    if (static_cast<int32_t>(subprofileCtx.subProfileIdList.size()) >= MAX_OS_ACCOUNT_SUB_PROFILE_COUNT) {
        ACCOUNT_LOGE("Still at limit after cleaning.");
        REPORT_OS_ACCOUNT_FAIL(osAccountId, Constants::OPERATION_SUBPROFILE_CREATE,
            ERR_OS_ACCOUNT_SUBSPACE_LIMIT, "Still at limit after reclaim");
        return ERR_OS_ACCOUNT_SUBSPACE_LIMIT;
    }
    ACCOUNT_LOGI(
        "Cleaned %{public}d garbage sub-profiles, retrying create for osAccountId=%{public}d", cleaned, osAccountId);
    return ERR_OK;
}

namespace {
void PurgeGarbageIdFromAccountInfo(int32_t garbageId,
    std::vector<int32_t> &idList, std::map<int32_t, int32_t> &indexMap)
{
    auto idIt = std::find(idList.begin(), idList.end(), garbageId);
    if (idIt != idList.end()) {
        idList.erase(idIt);
    }
    for (auto mapIt = indexMap.begin(); mapIt != indexMap.end(); ++mapIt) {
        if (mapIt->second == garbageId) {
            indexMap.erase(mapIt);
            break;
        }
    }
}
} // namespace

void OsAccountSubProfileManager::PurgeGarbageIdsFromContext(
    int32_t osAccountId, const std::set<int32_t> &garbageIds)
{
    SubProfileContext subprofileCtx;
    ErrCode infoRet = IInnerOsAccountManager::GetInstance().ReadSubProfileContext(
        osAccountId, subprofileCtx);
    if (infoRet == ERR_ACCOUNT_COMMON_FILE_NOT_EXIST) {
        ACCOUNT_LOGI("No SubProfileContext to purge for osAccountId=%{public}d", osAccountId);
        return;
    }
    if (infoRet != ERR_OK) {
        ACCOUNT_LOGE("ReadSubProfileContext failed after garbage cleanup, ret=%{public}d", infoRet);
        // Garbage directories are already deleted, but stale IDs remain in SubProfileContext.
        REPORT_OS_ACCOUNT_FAIL(osAccountId, Constants::OPERATION_SUBPROFILE_DELETE,
            infoRet, "SubProfileContext read failed after garbage cleanup, stale IDs may persist");
        return;
    }
    auto idList = subprofileCtx.subProfileIdList;
    auto indexMap = subprofileCtx.subProfileIndexMap;
    for (int32_t garbageId : garbageIds) {
        PurgeGarbageIdFromAccountInfo(garbageId, idList, indexMap);
    }
    SubProfileContext cleanupData(subprofileCtx.nextSubProfileId, idList,
        subprofileCtx.nextSubProfileIndex, indexMap);
    ErrCode updateRet = IInnerOsAccountManager::GetInstance().UpdateOsAccountSubspaceInfo(
        osAccountId, cleanupData);
    if (updateRet != ERR_OK) {
        ACCOUNT_LOGE("UpdateOsAccountSubspaceInfo after garbage cleanup failed, ret=%{public}d", updateRet);
        REPORT_OS_ACCOUNT_FAIL(osAccountId, Constants::OPERATION_SUBPROFILE_DELETE,
            updateRet, "UpdateOsAccountSubspaceInfo after garbage cleanup failed");
    }
}

int32_t OsAccountSubProfileManager::RemoveGarbageSubProfiles(int32_t osAccountId)
{
    // Phase 1: scan for garbage sub-profile directories on disk
    std::set<int32_t> garbageIds;
    subProfileDataDeal_->ScanOrphanedSubProfileIds(osAccountId, garbageIds);
    subProfileDataDeal_->ScanPendingRemovalSubProfileIds(osAccountId, garbageIds);
    if (garbageIds.empty()) {
        return 0;
    }

    // Phase 2: remove garbage directories from disk first.
    // Must delete dirs before releasing subspaceIds in SubProfileContext to prevent ID reuse.
    // Crash-safety: if we crash after dirs are deleted but before SubProfileContext is updated,
    // stale IDs in SubProfileContext are harmless — LoadSubProfileInfo will fail on missing dir.
    int32_t removeNum = 0;
    for (int32_t subId : garbageIds) {
        if (subProfileDataDeal_->RemoveSubProfileDir(osAccountId, subId) == ERR_OK) {
            removeNum++;
        }
    }
    if (removeNum <= 0) {
        return removeNum;
    }

    // Phase 3: purge garbage IDs from SubProfileContext and persist
    ACCOUNT_LOGI("Removed %{public}d garbage sub-profiles for osAccountId=%{public}d", removeNum, osAccountId);
    PurgeGarbageIdsFromContext(osAccountId, garbageIds);
    return removeNum;
}

bool OsAccountSubProfileManager::CheckActiveSessionStatus(
    OsAccountSubProfileDataDeal *dataDeal, int32_t osAccountId, int32_t fromSubspaceId)
{
    if (dataDeal == nullptr) {
        return false;
    }
    if (fromSubspaceId == -1) {
        return false;
    }
    OsAccountSubspaceInfo spaceInfo;
    if (dataDeal->LoadSubProfileInfo(osAccountId, fromSubspaceId, spaceInfo) == ERR_OK) {
        if (spaceInfo.ohosAccountInfo_.status_ == ACCOUNT_STATE_LOGIN) {
            return true;
        }
    }
    return false;
}

ErrCode OsAccountSubProfileManager::SwitchSubProfileLocked(
    int32_t osAccountId, int32_t subspaceId, int32_t &fromSubspaceId)
{
    // index-0 subspace always exists (headless), but cannot be used as foreground
    int32_t base = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    if (subspaceId == base) {
        ACCOUNT_LOGE("Cannot switch to headless subprofile (index=0, subspaceId=%{public}d)", subspaceId);
        return ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED;
    }
    if (!subProfileDataDeal_->IsValidSubProfileExists(osAccountId, subspaceId)) {
        ACCOUNT_LOGE("OS account subspace %{public}d does not exist or is not valid", subspaceId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    OsAccountInfo osAccountInfo;
    if (IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(osAccountId, osAccountInfo) != ERR_OK) {
        ACCOUNT_LOGE("GetOsAccountInfoById failed for osAccountId=%{public}d", osAccountId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    fromSubspaceId = osAccountInfo.GetForegroundSubProfileId();
    if (CheckActiveSessionStatus(subProfileDataDeal_.get(), osAccountId, fromSubspaceId)) {
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

ErrCode OsAccountSubProfileManager::LoadSubProfileInfo(int32_t osAccountId, int32_t subspaceId,
    OsAccountSubspaceInfo &info)
{
    // fileOperator_->fileLock_ protects concurrent file I/O;
    // InputFileByPathAndContentWithTransaction provides atomic writes,
    // so no subProfileOpMutex_ needed for reading a single profile.
    return subProfileDataDeal_->LoadSubProfileInfo(osAccountId, subspaceId, info);
}

ErrCode OsAccountSubProfileManager::SaveSubProfileInfo(const OsAccountSubspaceInfo &info)
{
    // Serialize JSON outside the lock (pure computation, no shared data access).
    std::string content = subProfileDataDeal_->SerializeSubProfileInfoToJson(info);
    if (content.empty()) {
        ACCOUNT_LOGE("Serialize failed, subspaceId=%{public}d", info.subspaceId);
        return ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION;
    }
    // Lock only for file I/O to prevent concurrent directory create/delete races.
    std::lock_guard<std::shared_mutex> lock(subProfileOpMutex_);
    return subProfileDataDeal_->SaveSubProfileFiles(info, content);
}

ErrCode OsAccountSubProfileManager::ScanOsAccountSubProfileIds(int32_t osAccountId,
    std::set<int32_t> &validIds)
{
    validIds.clear();
    // Directory scan + file reads are protected by fileOperator_->fileLock_.
    std::set<int32_t> rawIds;
    ErrCode ret = subProfileDataDeal_->ScanRawSubProfileIds(osAccountId, rawIds);
    if (ret != ERR_OK) {
        return ret;
    }
    std::vector<std::pair<int32_t, OsAccountSubspaceInfo>> loaded;
    for (int32_t id : rawIds) {
        OsAccountSubspaceInfo info;
        if (subProfileDataDeal_->LoadSubProfileInfo(osAccountId, id, info) == ERR_OK) {
            loaded.emplace_back(id, std::move(info));
        }
    }
    for (const auto &[id, info] : loaded) {
        if (info.isCreateCompleted && !info.toBeRemoved) {
            validIds.insert(id);
        }
    }
    return ERR_OK;
}

ErrCode OsAccountSubProfileManager::GetSubProfileIds(
    int32_t osAccountId, std::vector<int32_t> &subProfileIds)
{
    subProfileIds.clear();
    int32_t base = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    // IPC + file reads moved outside lock (Pitfall 6: Process In Lock Should Be Fast).
    SubProfileContext subprofileCtx;
    ErrCode ctxRet = IInnerOsAccountManager::GetInstance().ReadSubProfileContext(
        osAccountId, subprofileCtx);
    if (ctxRet == ERR_ACCOUNT_COMMON_FILE_NOT_EXIST) {
        subProfileIds.push_back(base);
        return ERR_OK;
    }
    if (ctxRet != ERR_OK) {
        ACCOUNT_LOGE("ReadSubProfileContext failed, osAccountId=%{public}d, ret=%{public}d",
            osAccountId, ctxRet);
        return ctxRet;
    }
    std::vector<std::pair<int32_t, OsAccountSubspaceInfo>> loadedProfiles;
    for (int32_t id : subprofileCtx.subProfileIdList) {
        if (id == base) {
            continue;
        }
        OsAccountSubspaceInfo info;
        if (subProfileDataDeal_->LoadSubProfileInfo(osAccountId, id, info) != ERR_OK) {
            continue;
        }
        loadedProfiles.emplace_back(id, std::move(info));
    }
    return FilterValidSubProfileIdsLocked(base, loadedProfiles, subProfileIds);
}

ErrCode OsAccountSubProfileManager::FilterValidSubProfileIdsLocked(int32_t base,
    const std::vector<std::pair<int32_t, OsAccountSubspaceInfo>> &loadedProfiles,
    std::vector<int32_t> &subProfileIds)
{
    subProfileIds.push_back(base);
    for (const auto &[id, info] : loadedProfiles) {
        if (info.isCreateCompleted && !info.toBeRemoved) {
            subProfileIds.push_back(id);
        }
    }
    return ERR_OK;
}

ErrCode OsAccountSubProfileManager::GetLocalIdForSubProfile(
    int32_t subProfileId, int32_t &osAccountId)
{
    // Pure arithmetic: no shared data access, no lock needed.
    int32_t baseMultiplier = Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    osAccountId = subProfileId / baseMultiplier;
    int32_t base = osAccountId * baseMultiplier;
    if (subProfileId == base) {
        return ERR_OK;
    }
    if (!subProfileDataDeal_->IsValidSubProfileExists(osAccountId, subProfileId)) {
        ACCOUNT_LOGE("SubProfile %{public}d does not exist", subProfileId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    return ERR_OK;
}

ErrCode OsAccountSubProfileManager::ResolveSubProfileIndexFromContext(
    int32_t osAccountId, int32_t subProfileId, int32_t &resolvedIndex)
{
    // Pure resolution: look up index from SubProfileContext. Read failures are returned
    // as errors — business-level degraded handling belongs to the caller, not here.
    SubProfileContext subprofileCtx;
    ErrCode ctxRet = IInnerOsAccountManager::GetInstance().ReadSubProfileContext(
        osAccountId, subprofileCtx);
    if (ctxRet == ERR_ACCOUNT_COMMON_FILE_NOT_EXIST) {
        ACCOUNT_LOGE("SubProfileContext not found for osAccountId=%{public}d", osAccountId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    if (ctxRet != ERR_OK) {
        ACCOUNT_LOGE("ReadSubProfileContext failed, osAccountId=%{public}d, ret=%{public}d",
            osAccountId, ctxRet);
        return ctxRet;
    }
    for (const auto &[index, subspaceId] : subprofileCtx.subProfileIndexMap) {
        if (subspaceId == subProfileId) {
            resolvedIndex = index;
            return ERR_OK;
        }
    }
    ACCOUNT_LOGW("subProfileId=%{public}d not found in subProfileIndexMap for osAccountId=%{public}d",
        subProfileId, osAccountId);
    return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
}

ErrCode OsAccountSubProfileManager::GetHeadlessSubProfile(
    int32_t osAccountId, int32_t subProfileId,
    OsAccountSubspaceResult &subspaceResult, OhosAccountInfo &distributedInfo)
{
    // Headless index=0 is canonical regardless of SubProfileContext state.
    // Headless account.json always exists independently in the OS account directory.
    subspaceResult.index = OsAccountSubProfileDataDeal::HEADLESS_SUBPROFILE_INDEX;
    ErrCode ret = ResolveSubProfileIndexFromContext(osAccountId, subProfileId,
        subspaceResult.index);
    if (ret == ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND) {
        // SubProfileContext missing or index not found is acceptable for headless —
        // account.json always exists independently; use canonical HEADLESS_SUBPROFILE_INDEX.
        ACCOUNT_LOGW("No SubProfileContext or index for headless osAccountId=%{public}d, "
            "using canonical index=0", osAccountId);
        subspaceResult.index = OsAccountSubProfileDataDeal::HEADLESS_SUBPROFILE_INDEX;
    } else if (ret != ERR_OK) {
        // Genuine I/O or corruption error: propagate to caller.
        ACCOUNT_LOGE("ResolveSubProfileIndex failed for headless osAccountId=%{public}d, "
            "ret=%{public}d", osAccountId, ret);
        return ret;
    }
    // distributedInfo comes from the parent OS account's account.json, not from
    // a subspace file. Caller (OhosAccountManager) fills it from dataDealer_->AccountInfoFromJson.
    distributedInfo = OhosAccountInfo();
    return ERR_OK;
}

ErrCode OsAccountSubProfileManager::GetSubProfile(int32_t osAccountId, int32_t subProfileId,
    OsAccountSubspaceResult &subspaceResult, OhosAccountInfo &distributedInfo)
{
    int32_t base = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    if (subProfileId != base &&
        !subProfileDataDeal_->IsValidSubProfileExists(osAccountId, subProfileId)) {
        ACCOUNT_LOGE("SubProfile %{public}d does not exist", subProfileId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    subspaceResult.id = subProfileId;
    subspaceResult.osAccountId = osAccountId;

    if (subProfileId == base) {
        return GetHeadlessSubProfile(osAccountId, subProfileId, subspaceResult, distributedInfo);
    }

    ErrCode ret = ResolveSubProfileIndexFromContext(osAccountId, subProfileId,
        subspaceResult.index);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("ResolveSubProfileIndexFromContext failed, osId=%{public}d, subId=%{public}d, ret=%{public}d",
            osAccountId, subProfileId, ret);
        return ret;
    }

    OsAccountSubspaceInfo subspaceInfo;
    ret = subProfileDataDeal_->LoadSubProfileInfo(osAccountId, subProfileId, subspaceInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("LoadSubProfileInfo failed, osId=%{public}d, subId=%{public}d, ret=%{public}d",
            osAccountId, subProfileId, ret);
        return ret;
    }
    distributedInfo = subspaceInfo.ohosAccountInfo_;
    return ERR_OK;
}

ErrCode OsAccountSubProfileManager::GetSubProfileIdByLocalIdAndAppIndex(
    int32_t osAccountId, int32_t appIndex, int32_t &subProfileId)
{
    SubProfileContext subprofileCtx;
    ErrCode ret = IInnerOsAccountManager::GetInstance().ReadSubProfileContext(
        osAccountId, subprofileCtx);
    if (ret == ERR_ACCOUNT_COMMON_FILE_NOT_EXIST) {
        ACCOUNT_LOGE("SubProfileContext not found for osAccountId=%{public}d", osAccountId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("ReadSubProfileContext failed, osAccountId=%{public}d, ret=%{public}d",
            osAccountId, ret);
        return ret;
    }
    auto it = subprofileCtx.subProfileIndexMap.find(appIndex);
    if (it == subprofileCtx.subProfileIndexMap.end()) {
        ACCOUNT_LOGE("SubProfile with appIndex=%{public}d not found for osAccountId=%{public}d",
            appIndex, osAccountId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    subProfileId = it->second;
    return ERR_OK;
}

ErrCode OsAccountSubProfileManager::GetSubProfileIndexByLocalIdAndSubProfileId(
    int32_t osAccountId, int32_t subProfileId, int32_t &index)
{
    return ResolveSubProfileIndexFromContext(osAccountId, subProfileId, index);
}

}  // namespace AccountSA
}  // namespace OHOS

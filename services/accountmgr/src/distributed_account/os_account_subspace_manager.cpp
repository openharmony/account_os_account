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
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_state_machine.h"
#include "iinner_os_account_manager.h"
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
    std::lock_guard<std::mutex> lock(subProfileOpMutex_);
    rootPath_ = rootPath;
    subProfileDataDeal_ = std::make_unique<OsAccountSubProfileDataDeal>(rootPath);
}

void OsAccountSubProfileManager::CleanupOrphanedSubProfiles()
{
    // Crash-recovery: remove orphaned space dirs with is_create_completed=false
    // and pending-removal spaces with to_be_removed=true.
    // Runs once at startup; acquires mutex to avoid racing with concurrent operations.
    std::unique_lock<std::mutex> lock(subProfileOpMutex_);
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

ErrCode OsAccountSubProfileManager::CreateSubProfile(int32_t osAccountId, int32_t &newSubspaceId)
{
    std::unique_lock<std::mutex> lock(subProfileOpMutex_);
    return CreateSubProfileLocked(osAccountId, newSubspaceId);
}

ErrCode OsAccountSubProfileManager::RemoveSubProfile(int32_t osAccountId, int32_t subspaceId)
{
    std::unique_lock<std::mutex> lock(subProfileOpMutex_);
    return RemoveSubProfileLocked(osAccountId, subspaceId);
}

ErrCode OsAccountSubProfileManager::SwitchSubProfile(
    int32_t osAccountId, int32_t subspaceId, int32_t &fromSubspaceId)
{
    std::unique_lock<std::mutex> lock(subProfileOpMutex_);
    return SwitchSubProfileLocked(osAccountId, subspaceId, fromSubspaceId);
}

OsAccountSubspaceInfo OsAccountSubProfileManager::CreateDefaultSubProfileInfo(
    int32_t osAccountId, int32_t subspaceId)
{
    OsAccountSubspaceInfo info;
    info.subspaceId = subspaceId;
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
    return info;
}

ErrCode OsAccountSubProfileManager::CreateSubProfileLocked(int32_t osAccountId, int32_t &newSubspaceId)
{
    OsAccountInfo osAccountInfo;
    ErrCode ret = IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(osAccountId, osAccountInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("GetOsAccountInfoById failed for osAccountId=%{public}d, ret=%{public}d",
            osAccountId, ret);
        return ret;
    }

    // Use subProfileIdList from OsAccountInfo for limit check (instead of disk scan)
    auto subProfileIdList = osAccountInfo.GetSubProfileIdList();
    if (static_cast<int32_t>(subProfileIdList.size()) >= MAX_OS_ACCOUNT_SUB_PROFILE_COUNT) {
        ACCOUNT_LOGE("Distributed account space count reached limit for osAccountId=%{public}d", osAccountId);
        return ERR_OS_ACCOUNT_SUBSPACE_LIMIT;
    }

    // Allocate using only OsAccountInfo data (no disk scan needed)
    ErrCode allocRet = subProfileDataDeal_->AllocateOsAccountSubProfileId(
        osAccountId, osAccountInfo.GetNextSubProfileId(),
        subProfileIdList, newSubspaceId);
    if (allocRet != ERR_OK) {
        ACCOUNT_LOGE("AllocateOsAccountSubProfileId failed for osAccountId=%{public}d, ret=%{public}d",
            osAccountId, allocRet);
        return allocRet;
    }

    // Persist next subspace ID hint (id+1) and updated list.
    // Wrapping/validity of the hint is handled by AllocateOsAccountSubProfileId on next call,
    // following the same pattern as GetAllowCreateId / GetNextLocalId.
    subProfileIdList.push_back(std::to_string(newSubspaceId));
    ErrCode updateRet = IInnerOsAccountManager::GetInstance().UpdateOsAccountSubspaceInfo(
        osAccountId, newSubspaceId + 1, subProfileIdList);
    if (updateRet != ERR_OK) {
        ACCOUNT_LOGE("UpdateOsAccountSubspaceInfo failed for osAccountId=%{public}d, ret=%{public}d, aborting",
            osAccountId, updateRet);
        return updateRet;
    }

    // Single-phase save: directory + account.json with isCreateCompleted=true
    OsAccountSubspaceInfo info = CreateDefaultSubProfileInfo(osAccountId, newSubspaceId);
    info.isCreateCompleted = true;
    ret = subProfileDataDeal_->SaveSubProfileInfo(info);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("SaveSubProfileInfo failed, subspaceId=%{public}d, ret=%{public}d",
            newSubspaceId, ret);
        subProfileDataDeal_->RemoveSubProfileDir(osAccountId, newSubspaceId);
        // Rollback the OsAccountInfo update so the leaked subspaceId is reclaimed
        subProfileIdList.pop_back();
        ErrCode rollbackRet = IInnerOsAccountManager::GetInstance().UpdateOsAccountSubspaceInfo(
            osAccountId, osAccountInfo.GetNextSubProfileId(), subProfileIdList);
        if (rollbackRet != ERR_OK) {
            ACCOUNT_LOGE("Rollback UpdateOsAccountSubspaceInfo failed, subspaceId=%{public}d may leak, ret=%{public}d",
                newSubspaceId, rollbackRet);
        }
        return ret;
    }
    return ERR_OK;
}

ErrCode OsAccountSubProfileManager::RemoveSubProfileLocked(int32_t osAccountId, int32_t subspaceId)
{
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
    // Safe to ignore: IsValidSubProfileExists above already called LoadSubProfileInfo under the same mutex
    // and validated the subspace, so the load here is guaranteed to succeed.
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
    } else if (infoRet == ERR_OK) {
        RemoveOsAccountSubProfileInfo(osAccountId, subspaceId, osAccountInfo);
    }
    return ret;
}

void OsAccountSubProfileManager::RemoveOsAccountSubProfileInfo(
    int32_t osAccountId, int32_t subspaceId, const OsAccountInfo &osAccountInfo)
{
    auto subProfileIdList = osAccountInfo.GetSubProfileIdList();
    auto it = std::find(subProfileIdList.begin(), subProfileIdList.end(), std::to_string(subspaceId));
    if (it == subProfileIdList.end()) {
        return;
    }
    subProfileIdList.erase(it);
    ErrCode updateRet = IInnerOsAccountManager::GetInstance().UpdateOsAccountSubspaceInfo(
        osAccountId, osAccountInfo.GetNextSubProfileId(), subProfileIdList);
    if (updateRet != ERR_OK) {
        ACCOUNT_LOGE("UpdateOsAccountSubspaceInfo after remove failed, ret=%{public}d", updateRet);
    }
}

bool OsAccountSubProfileManager::CheckActiveSessionStatus(
    OsAccountSubProfileDataDeal *dataDeal, int32_t osAccountId, int32_t fromSubspaceId)
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
    // index-0 subspace always exists, skip file-based existence check
    int32_t base = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    if (subspaceId != base && !subProfileDataDeal_->IsValidSubProfileExists(osAccountId, subspaceId)) {
        ACCOUNT_LOGE("OS account subspace %{public}d does not exist or is not valid", subspaceId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    OsAccountInfo osAccountInfo;
    if (IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(osAccountId, osAccountInfo) != ERR_OK) {
        ACCOUNT_LOGE("GetOsAccountInfoById failed for osAccountId=%{public}d", osAccountId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
    std::unique_lock<std::mutex> lock(subProfileOpMutex_);
    return subProfileDataDeal_->LoadSubProfileInfo(osAccountId, subspaceId, info);
}

ErrCode OsAccountSubProfileManager::SaveSubProfileInfo(const OsAccountSubspaceInfo &info)
{
    std::unique_lock<std::mutex> lock(subProfileOpMutex_);
    return subProfileDataDeal_->SaveSubProfileInfo(info);
}

ErrCode OsAccountSubProfileManager::ScanOsAccountSubProfileIds(int32_t osAccountId,
    std::set<int32_t> &validIds)
{
    std::unique_lock<std::mutex> lock(subProfileOpMutex_);
    return subProfileDataDeal_->ScanOsAccountSubProfileIds(osAccountId, validIds);
}

ErrCode OsAccountSubProfileManager::GetSubProfileIds(
    int32_t osAccountId, std::vector<int32_t> &subProfileIds)
{
    std::set<int32_t> idSet;
    ErrCode ret = subProfileDataDeal_->ScanOsAccountSubProfileIds(osAccountId, idSet);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("ScanOsAccountSubProfileIds failed, osAccountId=%{public}d, ret=%{public}d",
            osAccountId, ret);
        return ret;
    }
    int32_t baseSubProfileId = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    idSet.insert(baseSubProfileId);
    subProfileIds.assign(idSet.begin(), idSet.end());
    return ERR_OK;
}

ErrCode OsAccountSubProfileManager::GetLocalIdForSubProfile(
    int32_t subProfileId, int32_t &osAccountId)
{
    int32_t baseMultiplier = Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    osAccountId = subProfileId / baseMultiplier;
    int32_t base = osAccountId * baseMultiplier;
    if (subProfileId != base && !subProfileDataDeal_->IsValidSubProfileExists(osAccountId, subProfileId)) {
        ACCOUNT_LOGE("SubProfile %{public}d does not exist", subProfileId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    return ERR_OK;
}

ErrCode OsAccountSubProfileManager::GetSubProfile(int32_t osAccountId, int32_t subProfileId,
    OsAccountSubspaceResult &subspaceResult, OhosAccountInfo &distributedInfo)
{
    // Caller MUST validate subProfile ownership (subProfileId / MULTIPLIER == osAccountId) at the service layer.
    if (subProfileId != (osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER) &&
        !subProfileDataDeal_->IsValidSubProfileExists(osAccountId, subProfileId)) {
        ACCOUNT_LOGE("SubProfile %{public}d does not exist", subProfileId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    subspaceResult.id = subProfileId;
    subspaceResult.osAccountId = osAccountId;
    subspaceResult.index = subProfileId - (osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER);
    OsAccountSubspaceInfo subspaceInfo;
    ErrCode ret = subProfileDataDeal_->LoadSubProfileInfo(osAccountId, subProfileId, subspaceInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("LoadSubProfileInfo failed, osId=%{public}d, subId=%{public}d, ret=%{public}d",
            osAccountId, subProfileId, ret);
        return ret;
    }
    distributedInfo = subspaceInfo.ohosAccountInfo_;
    return ERR_OK;
}

}  // namespace AccountSA
}  // namespace OHOS

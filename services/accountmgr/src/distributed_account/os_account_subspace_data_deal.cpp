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

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

#include "os_account_subspace_data_deal.h"
#include <cerrno>
#include <dirent.h>
#include <sys/stat.h>
#include "account_error_no.h"
#include "account_hisysevent_adapter.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "json_utils.h"
#include "os_account_constants.h"
#include "parameters.h"

namespace OHOS {
namespace AccountSA {
namespace {
const char SUBSPACE_ACCOUNT_JSON[] = "/account.json";
const char JSON_KEY_SUBSPACE_ID[] = "subspaceId";
const char JSON_KEY_OS_ACCOUNT_ID[] = "osAccountId";
const char JSON_KEY_IS_CREATE_COMPLETED[] = "is_create_completed";
const char JSON_KEY_TO_BE_REMOVED[] = "to_be_removed";
const char JSON_KEY_BIND_TIME[] = "bind_time";
const char JSON_KEY_VERSION[] = "version";
// OhosAccountInfo fields — same key names as OhosAccountDataDeal for format reuse
const char JSON_KEY_OHOSACCOUNT_NAME[] = "account_name";
const char JSON_KEY_OHOSACCOUNT_RAW_UID[] = "raw_uid";
const char JSON_KEY_OHOSACCOUNT_UID[] = "open_id";
const char JSON_KEY_OHOSACCOUNT_STATUS[] = "bind_status";
const char JSON_KEY_OHOSACCOUNT_CALLINGUID[] = "calling_uid";
const char JSON_KEY_OHOSACCOUNT_NICKNAME[] = "account_nickname";
const char JSON_KEY_OHOSACCOUNT_SCALABLEDATA[] = "account_scalableData";
const char SUBSPACE_ACCOUNT_AVATAR[] = "/account_avatar";
const char JSON_KEY_SUBSPACE_INDEX[] = "subspaceIndex";
const char JSON_KEY_SUBSPACE_OFFSET[] = "subspaceOffset";
constexpr int32_t MAX_RETRY_TIMES = 3;
}  // namespace

const int32_t MAX_OS_ACCOUNT_SUB_PROFILE_COUNT =
    OHOS::system::GetIntParameter<int32_t>("const.bms.appCloneMaxCount", 1000, 1, 1000);

OsAccountSubProfileDataDeal::OsAccountSubProfileDataDeal(const std::string &configRootDir)
    : configRootDir_(configRootDir), fileOperator_(std::make_shared<AccountFileOperator>())
{}

ErrCode OsAccountSubProfileDataDeal::AllocateSubProfileIndex(
    int32_t nextSubProfileIndex, const std::map<int32_t, int32_t> &subProfileIndexMap, int32_t &outIndex)
{
    // Allocate a free logical slot index from [1, MAX_OS_ACCOUNT_SUB_PROFILE_COUNT - 1].
    // Index 0 (HEADLESS_SUBPROFILE_INDEX) is reserved and never allocated here.
    // Simple self-increment: if the map is not yet full, allocate the next free index.
    // When all indices have been allocated, wrap around to reuse the smallest available
    // index (not present in the map after deletions).
    int32_t minIndex = HEADLESS_SUBPROFILE_INDEX + 1;
    int32_t maxIndex = MAX_OS_ACCOUNT_SUB_PROFILE_COUNT - 1;
    int32_t totalRange = maxIndex - minIndex + 1;
    int32_t startIndex = nextSubProfileIndex;
    if (startIndex < minIndex || startIndex > maxIndex) {
        startIndex = minIndex;
    }

    // Phase 1 (normal allocation): map is not full — find a free slot
    int32_t candidate = startIndex;
    for (int32_t i = 0; i < totalRange; i++) {
        if (subProfileIndexMap.find(candidate) == subProfileIndexMap.end()) {
            outIndex = candidate;
            return ERR_OK;
        }
        ++candidate;
        if (candidate > maxIndex) {
            candidate = minIndex;
        }
    }

    // Phase 2 (exhausted): all slots are occupied
    ACCOUNT_LOGE("No available index slot, all %{public}d slots used.", totalRange);
    REPORT_OS_ACCOUNT_FAIL(0, Constants::OPERATION_SUBPROFILE_CREATE,
        ERR_OS_ACCOUNT_SUBSPACE_LIMIT, "All index slots used");
    return ERR_OS_ACCOUNT_SUBSPACE_LIMIT;
}

ErrCode OsAccountSubProfileDataDeal::AllocateOsAccountSubProfileId(
    int32_t osAccountId, int32_t nextSubProfileId,
    const std::vector<int32_t> &subProfileIdList, int32_t &outId)
{
    int32_t base = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    int32_t minId = base + OS_ACCOUNT_SUB_PROFILE_ID_MIN;
    int32_t maxId = base + OS_ACCOUNT_SUB_PROFILE_ID_MAX;
    int32_t startId = nextSubProfileId;

    if (startId < minId || startId > maxId) {
        startId = minId;
    }

    int32_t searchCount = 0;
    int32_t totalRange = OS_ACCOUNT_SUB_PROFILE_ID_MAX - OS_ACCOUNT_SUB_PROFILE_ID_MIN + 1;

    do {
        if (std::find(subProfileIdList.begin(), subProfileIdList.end(), startId) == subProfileIdList.end()) {
            outId = startId;
            ACCOUNT_LOGI("Allocated subspaceId=%{public}d for osAccountId=%{public}d", outId, osAccountId);
            return ERR_OK;
        }
        ++startId;
        ++searchCount;
        if (startId > maxId) {
            startId = minId;
        }
        if (searchCount >= totalRange) {
            ACCOUNT_LOGE("No available index for osAccountId=%{public}d, all %{public}d slots used.",
                osAccountId, OS_ACCOUNT_SUB_PROFILE_ID_MAX);
            return ERR_OS_ACCOUNT_SUBSPACE_LIMIT;
        }
    } while (true);
}

std::string OsAccountSubProfileDataDeal::GetSubProfileDir(int32_t osAccountId, int32_t subspaceId) const
{
    return configRootDir_ + std::to_string(osAccountId) + "/" + std::to_string(subspaceId);
}

std::string OsAccountSubProfileDataDeal::GetSubProfileFilePath(
    int32_t osAccountId, int32_t subspaceId) const
{
    return GetSubProfileDir(osAccountId, subspaceId) + SUBSPACE_ACCOUNT_JSON;
}

int32_t OsAccountSubProfileDataDeal::ParseDirEntryAsSubProfileId(
    const struct dirent *entry, int32_t osAccountId, int32_t base)
{
    if (entry->d_type != DT_DIR) {
        return -1;
    }
    std::string name(entry->d_name);
    if (name == "." || name == "..") {
        return -1;
    }
    bool isDigit = !name.empty() && std::all_of(name.begin(), name.end(),
        [](unsigned char c) { return std::isdigit(c) != 0; });
    if (!isDigit) {
        return -1;
    }
    char *endPtr = nullptr;
    errno = 0;
    long val = std::strtol(name.c_str(), &endPtr, 10);
    if (errno != 0 || endPtr == name.c_str() || *endPtr != '\0' ||
        val < INT32_MIN || val > INT32_MAX) {
        ACCOUNT_LOGW("Skip invalid directory name=%{public}s under osAccountId=%{public}d",
            name.c_str(), osAccountId);
        return -1;
    }
    int32_t subspaceId = static_cast<int32_t>(val);
    int32_t offset = subspaceId - base;
    if (offset < 0 || offset > OS_ACCOUNT_SUB_PROFILE_ID_MAX) {
        return -1;
    }
    return subspaceId;
}

ErrCode OsAccountSubProfileDataDeal::ScanSubProfileIds(int32_t osAccountId,
    std::function<bool(const OsAccountSubspaceInfo &)> filter,
    std::set<int32_t> &resultIds) const
{
    resultIds.clear();
    std::string osAccountDir = configRootDir_ + std::to_string(osAccountId) + "/";

    DIR *dir = opendir(osAccountDir.c_str());
    if (dir == nullptr) {
        ACCOUNT_LOGI("Directory does not exist for osAccountId=%{public}d", osAccountId);
        return ERR_OK;
    }

    int32_t base = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        int32_t subspaceId = ParseDirEntryAsSubProfileId(entry, osAccountId, base);
        if (subspaceId < 0) {
            continue;
        }

        if (filter == nullptr) {
            resultIds.insert(subspaceId);
            continue;
        }

        OsAccountSubspaceInfo info;
        ErrCode ret = LoadSubProfileInfo(osAccountId, subspaceId, info);
        if (ret != ERR_OK) {
            continue;
        }
        if (filter(info)) {
            resultIds.insert(subspaceId);
        }
    }
    closedir(dir);
    return ERR_OK;
}

ErrCode OsAccountSubProfileDataDeal::ScanOsAccountSubProfileIds(
    int32_t osAccountId, std::set<int32_t> &validIds) const
{
    return ScanSubProfileIds(osAccountId,
        [](const OsAccountSubspaceInfo &info) {
            return info.isCreateCompleted && !info.toBeRemoved;
        }, validIds);
}

ErrCode OsAccountSubProfileDataDeal::ScanOrphanedSubProfileIds(
    int32_t osAccountId, std::set<int32_t> &orphanIds) const
{
    return ScanSubProfileIds(osAccountId,
        [](const OsAccountSubspaceInfo &info) {
            return !info.isCreateCompleted;
        }, orphanIds);
}

ErrCode OsAccountSubProfileDataDeal::ScanPendingRemovalSubProfileIds(
    int32_t osAccountId, std::set<int32_t> &pendingRemoveIds) const
{
    return ScanSubProfileIds(osAccountId,
        [](const OsAccountSubspaceInfo &info) {
            return info.toBeRemoved;
        }, pendingRemoveIds);
}

ErrCode OsAccountSubProfileDataDeal::ScanRawSubProfileIds(
    int32_t osAccountId, std::set<int32_t> &rawIds) const
{
    return ScanSubProfileIds(osAccountId, nullptr, rawIds);
}

ErrCode OsAccountSubProfileDataDeal::SaveSubProfileFiles(
    const OsAccountSubspaceInfo &info, const std::string &serializedContent)
{
    std::string subspaceDir = GetSubProfileDir(info.userId_, info.subspaceId);
    if (!fileOperator_->IsExistDir(subspaceDir)) {
        ErrCode ret = fileOperator_->CreateDir(subspaceDir);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("CreateDir failed, osId=%{public}d, subId=%{public}d, ret=%{public}d",
                info.userId_, info.subspaceId, ret);
            return ret;
        }
    }
    std::string avatarFile = GetSubProfileDir(info.userId_, info.subspaceId) + SUBSPACE_ACCOUNT_AVATAR;
    ErrCode ret = fileOperator_->InputFileByPathAndContentWithTransaction(
        avatarFile, info.ohosAccountInfo_.avatar_);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to save avatar! ret = %{public}d", ret);
        return ret;
    }
    std::string filePath = GetSubProfileFilePath(info.userId_, info.subspaceId);
    ret = fileOperator_->InputFileByPathAndContentWithTransaction(filePath, serializedContent);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Write subspace failed, osId=%{public}d, subId=%{public}d, ret=%{public}d",
            info.userId_, info.subspaceId, ret);
    }
    return ret;
}

std::string OsAccountSubProfileDataDeal::SerializeSubProfileInfoToJson(
    const OsAccountSubspaceInfo &info) const
{
    auto jsonObj = CreateJson();
    AddIntToJson(jsonObj, JSON_KEY_SUBSPACE_ID, info.subspaceId);
    AddIntToJson(jsonObj, JSON_KEY_OS_ACCOUNT_ID, info.userId_);
    AddBoolToJson(jsonObj, JSON_KEY_IS_CREATE_COMPLETED, info.isCreateCompleted);
    AddBoolToJson(jsonObj, JSON_KEY_TO_BE_REMOVED, info.toBeRemoved);
    AddIntToJson(jsonObj, JSON_KEY_BIND_TIME, static_cast<int32_t>(info.bindTime_));
    AddIntToJson(jsonObj, JSON_KEY_VERSION, info.version_);
    AddStringToJson(jsonObj, JSON_KEY_OHOSACCOUNT_NAME, info.ohosAccountInfo_.name_);
    AddStringToJson(jsonObj, JSON_KEY_OHOSACCOUNT_RAW_UID, info.ohosAccountInfo_.GetRawUid());
    AddStringToJson(jsonObj, JSON_KEY_OHOSACCOUNT_UID, info.ohosAccountInfo_.uid_);
    AddIntToJson(jsonObj, JSON_KEY_OHOSACCOUNT_STATUS, static_cast<int32_t>(info.ohosAccountInfo_.status_));
    AddIntToJson(jsonObj, JSON_KEY_OHOSACCOUNT_CALLINGUID, info.ohosAccountInfo_.callingUid_);
    AddStringToJson(jsonObj, JSON_KEY_OHOSACCOUNT_NICKNAME, info.ohosAccountInfo_.nickname_);
    AddStringToJson(jsonObj, JSON_KEY_OHOSACCOUNT_SCALABLEDATA, info.ohosAccountInfo_.scalableData_);
    AddIntToJson(jsonObj, JSON_KEY_SUBSPACE_INDEX, info.index);
    AddIntToJson(jsonObj, JSON_KEY_SUBSPACE_OFFSET, info.subspaceOffset);
    return PackJsonToString(jsonObj);
}

ErrCode OsAccountSubProfileDataDeal::ParseSubProfileInfoFromJson(
    const std::string &jsonStr, OsAccountSubspaceInfo &info) const
{
    auto jsonObj = CreateJsonFromString(jsonStr);
    if (jsonObj == nullptr) {
        ACCOUNT_LOGE("Failed to parse subspace info JSON.");
        return ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION;
    }
    GetDataByType<int32_t>(jsonObj.get(), JSON_KEY_SUBSPACE_ID, info.subspaceId);
    GetDataByType<int32_t>(jsonObj.get(), JSON_KEY_OS_ACCOUNT_ID, info.userId_);
    GetDataByType<bool>(jsonObj.get(), JSON_KEY_IS_CREATE_COMPLETED, info.isCreateCompleted);
    GetDataByType<bool>(jsonObj.get(), JSON_KEY_TO_BE_REMOVED, info.toBeRemoved);
    int32_t bindTime = 0;
    GetDataByType<int32_t>(jsonObj.get(), JSON_KEY_BIND_TIME, bindTime);
    info.bindTime_ = static_cast<std::time_t>(bindTime);
    GetDataByType<int32_t>(jsonObj.get(), JSON_KEY_VERSION, info.version_);
    GetDataByType<std::string>(jsonObj.get(), JSON_KEY_OHOSACCOUNT_NAME, info.ohosAccountInfo_.name_);
    std::string rawUid;
    if (GetDataByType<std::string>(jsonObj.get(), JSON_KEY_OHOSACCOUNT_RAW_UID, rawUid)) {
        info.ohosAccountInfo_.SetRawUid(rawUid);
    }
    GetDataByType<std::string>(jsonObj.get(), JSON_KEY_OHOSACCOUNT_UID, info.ohosAccountInfo_.uid_);
    int32_t status = static_cast<int32_t>(ACCOUNT_STATE_UNBOUND);
    if (GetDataByType<int32_t>(jsonObj.get(), JSON_KEY_OHOSACCOUNT_STATUS, status)) {
        info.ohosAccountInfo_.status_ = status;
    }
    GetDataByType<int32_t>(jsonObj.get(), JSON_KEY_OHOSACCOUNT_CALLINGUID, info.ohosAccountInfo_.callingUid_);
    GetDataByType<std::string>(jsonObj.get(), JSON_KEY_OHOSACCOUNT_NICKNAME, info.ohosAccountInfo_.nickname_);
    GetDataByType<std::string>(jsonObj.get(), JSON_KEY_OHOSACCOUNT_SCALABLEDATA, info.ohosAccountInfo_.scalableData_);
    GetDataByType<int32_t>(jsonObj.get(), JSON_KEY_SUBSPACE_INDEX, info.index);
    GetDataByType<int32_t>(jsonObj.get(), JSON_KEY_SUBSPACE_OFFSET, info.subspaceOffset);
    return ERR_OK;
}

ErrCode OsAccountSubProfileDataDeal::SaveSubProfileInfo(const OsAccountSubspaceInfo &info)
{
    std::string content = SerializeSubProfileInfoToJson(info);
    if (content.empty()) {
        ACCOUNT_LOGE("Serialize failed for subspaceId=%{public}d", info.subspaceId);
        return ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION;
    }
    return SaveSubProfileFiles(info, content);
}

ErrCode OsAccountSubProfileDataDeal::LoadSubProfileInfo(
    int32_t osAccountId, int32_t subspaceId, OsAccountSubspaceInfo &info) const
{
    std::string filePath = GetSubProfileFilePath(osAccountId, subspaceId);
    if (!fileOperator_->IsExistFile(filePath)) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    std::string content;
    ErrCode ret = fileOperator_->GetFileContentByPath(filePath, content);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Read subspace failed, osId=%{public}d, subId=%{public}d, ret=%{public}d",
            osAccountId, subspaceId, ret);
        return ret;
    }
    ret = ParseSubProfileInfoFromJson(content, info);
    if (ret != ERR_OK) {
        return ret;
    }
    std::string avatarFile = GetSubProfileDir(osAccountId, subspaceId) + SUBSPACE_ACCOUNT_AVATAR;
    std::string avatarData;

    if (fileOperator_->GetFileContentByPath(avatarFile, avatarData) == ERR_OK) {
        info.ohosAccountInfo_.avatar_ = avatarData;
    } else {
        ACCOUNT_LOGW("Load avatar failed. OsAccountId=%{public}d, subspaceId=%{public}d",
            osAccountId, subspaceId);
        REPORT_OS_ACCOUNT_FAIL(osAccountId, Constants::OPERATION_SUBPROFILE_QUERY,
            ERR_ACCOUNT_COMMON_FILE_READ_FAILED, "Avatar file not loaded");
    }
    return ERR_OK;
}

ErrCode OsAccountSubProfileDataDeal::RemoveSubProfileDir(int32_t osAccountId, int32_t subspaceId)
{
    std::string subspaceDir = GetSubProfileDir(osAccountId, subspaceId);
    if (!fileOperator_->IsExistDir(subspaceDir)) {
        return ERR_OK;
    }
    int32_t retryCount = 0;
    ErrCode ret = ERR_OK;
    while (retryCount < MAX_RETRY_TIMES) {
        ret = fileOperator_->DeleteDir(subspaceDir);
        if (ret == ERR_OK) {
            return ERR_OK;
        }
        retryCount++;
        ACCOUNT_LOGW("Failed to remove subspace dir %{public}s, attempt %{public}d, ret=%{public}d",
            subspaceDir.c_str(), retryCount, ret);
    }
    ACCOUNT_LOGE("Failed to remove subspace dir after %{public}d retries, ret=%{public}d",
        MAX_RETRY_TIMES, ret);
    return ret;
}

bool OsAccountSubProfileDataDeal::IsValidSubProfileExists(
    int32_t osAccountId, int32_t subspaceId) const
{
    OsAccountSubspaceInfo info;
    ErrCode ret = LoadSubProfileInfo(osAccountId, subspaceId, info);
    if (ret != ERR_OK) {
        return false;
    }
    return info.isCreateCompleted && !info.toBeRemoved;
}

}  // namespace AccountSA
}  // namespace OHOS

#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

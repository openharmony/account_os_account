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
const char JSON_KEY_OHOSACCOUNT_AVATAR[] = "account_avatar";
const char JSON_KEY_OHOSACCOUNT_SCALABLEDATA[] = "account_scalableData";
constexpr int32_t MAX_RETRY_TIMES = 3;
}  // namespace

const int32_t MAX_OS_ACCOUNT_SUBSPACE_COUNT =
    OHOS::system::GetIntParameter<int32_t>("const.bms.appCloneMaxCount", 1000, 1, 1000) - 1;

OsAccountSubspaceDataDeal::OsAccountSubspaceDataDeal(const std::string &configRootDir)
    : configRootDir_(configRootDir), fileOperator_(std::make_shared<AccountFileOperator>())
{}

ErrCode OsAccountSubspaceDataDeal::AllocateOsAccountSubspaceId(
    int32_t osAccountId, const std::set<int32_t> &usedIndices, int32_t &outId)
{
    for (int32_t idx = OS_ACCOUNT_SUBSPACE_INDEX_MIN; idx <= OS_ACCOUNT_SUBSPACE_INDEX_MAX; ++idx) {
        if (usedIndices.find(idx) == usedIndices.end()) {
            outId = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + idx;
            ACCOUNT_LOGI("Allocated subspaceId=%{public}d for osAccountId=%{public}d",
                outId, osAccountId);
            return ERR_OK;
        }
    }
    ACCOUNT_LOGE("No available index for osAccountId=%{public}d, all %{public}d slots used.",
        osAccountId, OS_ACCOUNT_SUBSPACE_INDEX_MAX);
    return ERR_OS_ACCOUNT_SUBSPACE_LIMIT;
}

std::string OsAccountSubspaceDataDeal::GetSubspaceDir(int32_t osAccountId, int32_t subspaceId) const
{
    return configRootDir_ + std::to_string(osAccountId) + "/" + std::to_string(subspaceId);
}

std::string OsAccountSubspaceDataDeal::GetSubspaceFilePath(
    int32_t osAccountId, int32_t subspaceId) const
{
    return GetSubspaceDir(osAccountId, subspaceId) + SUBSPACE_ACCOUNT_JSON;
}

ErrCode OsAccountSubspaceDataDeal::ScanSubspaceIdsWithFilter(int32_t osAccountId,
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
        if (entry->d_type != DT_DIR) {
            continue;
        }
        std::string name(entry->d_name);
        if (name == "." || name == "..") {
            continue;
        }
        bool isDigit = !name.empty() && std::all_of(name.begin(), name.end(), ::isdigit);
        if (!isDigit) {
            continue;
        }
        char *endPtr = nullptr;
        errno = 0;
        long val = std::strtol(name.c_str(), &endPtr, 10);
        if (errno != 0 || endPtr == name.c_str() || *endPtr != '\0' ||
            val < INT32_MIN || val > INT32_MAX) {
            ACCOUNT_LOGE("Invalid directory name=%{public}s under osAccountId=%{public}d", name.c_str(), osAccountId);
            closedir(dir);
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }
        int32_t subspaceId = static_cast<int32_t>(val);
        int32_t index = subspaceId - base;
        if (index < OS_ACCOUNT_SUBSPACE_INDEX_MIN || index > OS_ACCOUNT_SUBSPACE_INDEX_MAX) {
            continue;
        }

        OsAccountSubspaceInfo info;
        ErrCode ret = LoadSubspaceInfo(osAccountId, subspaceId, info);
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

ErrCode OsAccountSubspaceDataDeal::ScanOsAccountSubspaceIds(
    int32_t osAccountId, std::set<int32_t> &validIds) const
{
    return ScanSubspaceIdsWithFilter(osAccountId,
        [](const OsAccountSubspaceInfo &info) {
            return info.isCreateCompleted && !info.toBeRemoved;
        }, validIds);
}

ErrCode OsAccountSubspaceDataDeal::ScanOrphanedSubspaceIds(
    int32_t osAccountId, std::set<int32_t> &orphanIds) const
{
    return ScanSubspaceIdsWithFilter(osAccountId,
        [](const OsAccountSubspaceInfo &info) {
            return !info.isCreateCompleted;
        }, orphanIds);
}

ErrCode OsAccountSubspaceDataDeal::ScanPendingRemovalSubspaceIds(
    int32_t osAccountId, std::set<int32_t> &pendingRemoveIds) const
{
    return ScanSubspaceIdsWithFilter(osAccountId,
        [](const OsAccountSubspaceInfo &info) {
            return info.toBeRemoved;
        }, pendingRemoveIds);
}

std::string OsAccountSubspaceDataDeal::SerializeSubspaceInfoToJson(
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
    AddStringToJson(jsonObj, JSON_KEY_OHOSACCOUNT_AVATAR, info.ohosAccountInfo_.avatar_);
    AddStringToJson(jsonObj, JSON_KEY_OHOSACCOUNT_SCALABLEDATA, info.ohosAccountInfo_.scalableData_);
    return PackJsonToString(jsonObj);
}

ErrCode OsAccountSubspaceDataDeal::ParseSubspaceInfoFromJson(
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
    GetDataByType<std::string>(jsonObj.get(), JSON_KEY_OHOSACCOUNT_AVATAR, info.ohosAccountInfo_.avatar_);
    GetDataByType<std::string>(jsonObj.get(), JSON_KEY_OHOSACCOUNT_SCALABLEDATA, info.ohosAccountInfo_.scalableData_);
    return ERR_OK;
}

ErrCode OsAccountSubspaceDataDeal::SaveSubspaceInfo(const OsAccountSubspaceInfo &info)
{
    std::string subspaceDir = GetSubspaceDir(info.userId_, info.subspaceId);
    if (!fileOperator_->IsExistDir(subspaceDir)) {
        ErrCode ret = fileOperator_->CreateDir(subspaceDir);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("CreateDir failed, osId=%{public}d, subId=%{public}d, ret=%{public}d",
                info.userId_, info.subspaceId, ret);
            return ret;
        }
    }
    std::string filePath = GetSubspaceFilePath(info.userId_, info.subspaceId);
    std::string content = SerializeSubspaceInfoToJson(info);
    ErrCode ret = fileOperator_->InputFileByPathAndContentWithTransaction(filePath, content);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Write subspace failed, osId=%{public}d, subId=%{public}d, ret=%{public}d",
            info.userId_, info.subspaceId, ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode OsAccountSubspaceDataDeal::LoadSubspaceInfo(
    int32_t osAccountId, int32_t subspaceId, OsAccountSubspaceInfo &info) const
{
    std::string filePath = GetSubspaceFilePath(osAccountId, subspaceId);
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
    return ParseSubspaceInfoFromJson(content, info);
}

ErrCode OsAccountSubspaceDataDeal::RemoveSubspaceDir(int32_t osAccountId, int32_t subspaceId)
{
    std::string subspaceDir = GetSubspaceDir(osAccountId, subspaceId);
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

bool OsAccountSubspaceDataDeal::IsValidSubspaceExists(
    int32_t osAccountId, int32_t subspaceId) const
{
    OsAccountSubspaceInfo info;
    ErrCode ret = LoadSubspaceInfo(osAccountId, subspaceId, info);
    if (ret != ERR_OK) {
        return false;
    }
    return info.isCreateCompleted && !info.toBeRemoved;
}

}  // namespace AccountSA
}  // namespace OHOS

#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

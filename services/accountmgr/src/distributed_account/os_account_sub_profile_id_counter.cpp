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

#include "os_account_sub_profile_id_counter.h"
#include <climits>
#include "account_log_wrapper.h"
#include "json_utils.h"
#include "os_account_info.h"
#include "string_ex.h"

namespace OHOS {
namespace AccountSA {
namespace {
const char JSON_KEY_CURRENT_ID[] = "currentId";
#ifndef ACCOUNT_TEST
const std::string COUNTER_FILE_DIR = "/data/service/el1/public/account";
#else
const std::string COUNTER_FILE_DIR = "/data/service/el1/public/account/test";
#endif
const std::string COUNTER_FILE_NAME = "/sub_profile_id_counter.json";
constexpr int32_t SUB_PROFILE_ID_MAX = INT32_MAX - 1;
}

SubProfileIdCounter &SubProfileIdCounter::GetInstance()
{
    static SubProfileIdCounter instance;
    return instance;
}

ErrCode SubProfileIdCounter::Init(const std::vector<OsAccountInfo> &existingAccounts)
{
    std::lock_guard<std::mutex> lock(mutex_);
    filePath_ = COUNTER_FILE_DIR + COUNTER_FILE_NAME;
    fileOperator_ = std::make_shared<AccountFileOperator>();

    int32_t persistedId = Constants::SUB_PROFILE_ID_INITIAL_VALUE;
    ErrCode loadRet = LoadFromFile();
    if (loadRet == ERR_OK) {
        persistedId = currentId_;
    }

    ReconstructFromList(existingAccounts);
    int32_t reconstructedId = currentId_;

    currentId_ = std::max(persistedId, reconstructedId);
    if (currentId_ > SUB_PROFILE_ID_MAX) {
        ACCOUNT_LOGE("Counter exhausted, currentId=%{public}d exceeds max=%{public}d", currentId_, SUB_PROFILE_ID_MAX);
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }

    if (loadRet != ERR_OK || currentId_ != persistedId) {
        ErrCode persistRet = SaveToFile();
        if (persistRet != ERR_OK) {
            ACCOUNT_LOGE("Persist after init failed, ret=%{public}d", persistRet);
            return persistRet;
        }
    }
    initialized_ = true;
    ACCOUNT_LOGI("SubProfileIdCounter initialized, currentId=%{public}d (persisted=%{public}d, reconstructed=%{public}d)",
        currentId_, persistedId, reconstructedId);
    return ERR_OK;
}

int32_t SubProfileIdCounter::GetNextId()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_ || fileOperator_ == nullptr) {
        ACCOUNT_LOGE("SubProfileIdCounter not initialized");
        return Constants::INVALID_SUB_PROFILE_ID;
    }
    if (currentId_ >= SUB_PROFILE_ID_MAX) {
        ACCOUNT_LOGE("Counter exhausted, currentId=%{public}d", currentId_);
        return Constants::INVALID_SUB_PROFILE_ID;
    }
    int32_t newId = currentId_ + 1;
    int32_t prevId = currentId_;
    currentId_ = newId;
    ErrCode ret = SaveToFile();
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Persist counter failed after GetNextId, ret=%{public}d, rolling back", ret);
        currentId_ = prevId;
        return Constants::INVALID_SUB_PROFILE_ID;
    }
    return newId;
}

void SubProfileIdCounter::ReconstructFromList(const std::vector<OsAccountInfo> &osAccountInfos)
{
    int32_t maxId = Constants::SUB_PROFILE_ID_INITIAL_VALUE;
    for (const auto &info : osAccountInfos) {
        int32_t commonId = info.GetCommonSubProfileId();
        if (commonId > maxId) {
            maxId = commonId;
        }
        const auto &subProfileIdList = info.GetSubProfileIdList();
        for (const auto &idStr : subProfileIdList) {
            int32_t id = 0;
            if (StrToInt(idStr, id) && id > maxId) {
                maxId = id;
            }
        }
    }
    currentId_ = maxId;
    ACCOUNT_LOGI("Reconstructed counter from existing data, currentId=%{public}d", currentId_);
}

ErrCode SubProfileIdCounter::LoadFromFile()
{
    std::string content;
    ErrCode ret = fileOperator_->GetFileContentByPath(filePath_, content);
    if (ret != ERR_OK) {
        ACCOUNT_LOGW("Counter file not found or unreadable, path=%{public}s, ret=%{public}d",
            filePath_.c_str(), ret);
        return ret;
    }
    auto jsonObj = CreateJsonFromString(content);
    if (jsonObj == nullptr) {
        ACCOUNT_LOGE("Failed to parse counter JSON");
        return ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION;
    }
    int32_t loadedId = Constants::SUB_PROFILE_ID_INITIAL_VALUE;
    if (!GetDataByType<int32_t>(jsonObj.get(), JSON_KEY_CURRENT_ID, loadedId)) {
        ACCOUNT_LOGE("Failed to read currentId from counter JSON");
        return ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION;
    }
    if (loadedId < Constants::SUB_PROFILE_ID_INITIAL_VALUE || loadedId > SUB_PROFILE_ID_MAX) {
        ACCOUNT_LOGE("Invalid currentId=%{public}d out of range [%{public}d, %{public}d], resetting",
            loadedId, Constants::SUB_PROFILE_ID_INITIAL_VALUE, SUB_PROFILE_ID_MAX);
        currentId_ = Constants::SUB_PROFILE_ID_INITIAL_VALUE;
        return ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION;
    }
    currentId_ = loadedId;
    return ERR_OK;
}

ErrCode SubProfileIdCounter::SaveToFile()
{
    auto jsonObj = CreateJson();
    AddIntToJson(jsonObj, JSON_KEY_CURRENT_ID, currentId_);
    std::string content = PackJsonToString(jsonObj);
    if (content.empty()) {
        ACCOUNT_LOGE("Failed to serialize counter JSON");
        return ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION;
    }
    if (!fileOperator_->IsExistDir(COUNTER_FILE_DIR)) {
        ErrCode ret = fileOperator_->CreateDir(COUNTER_FILE_DIR);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("CreateDir failed for counter, ret=%{public}d", ret);
            return ret;
        }
    }
    ErrCode ret = fileOperator_->InputFileByPathAndContentWithTransaction(filePath_, content);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Write counter file failed, ret=%{public}d", ret);
    }
    return ret;
}

}  // namespace AccountSA
}  // namespace OHOS

#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <vector>
#include "account_error_no.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "account_hisysevent_adapter.h"
#include "iinner_os_account_manager.h"
#include "ohos_account_data_deal.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string ACCOUNT_CFG_FILE_NAME = "/account.json";
const std::string DATADEAL_JSON_KEY_OHOSACCOUNT_NAME = "account_name";
const std::string DATADEAL_JSON_KEY_OHOSACCOUNT_RAW_UID = "raw_uid";
const std::string DATADEAL_JSON_KEY_OHOSACCOUNT_UID = "open_id";
const std::string DATADEAL_JSON_KEY_OHOSACCOUNT_STATUS = "bind_status";
const std::string DATADEAL_JSON_KEY_OHOSACCOUNT_CALLINGUID = "calling_uid";
const std::string DATADEAL_JSON_KEY_OHOSACCOUNT_NICKNAME = "account_nickname";
const std::string DATADEAL_JSON_KEY_OHOSACCOUNT_AVATAR = "account_avatar";
const std::string DATADEAL_JSON_KEY_OHOSACCOUNT_SCALABLEDATA = "account_scalableData";
const std::string DATADEAL_JSON_KEY_USERID = "user_id";
const std::string DATADEAL_JSON_KEY_BIND_TIME = "bind_time";
const uint32_t ALG_COMMON_SIZE = 32;
} // namespace

OhosAccountDataDeal::OhosAccountDataDeal(const std::string &configFileDir)
    : configFileDir_(configFileDir),
    accountFileWatcherMgr_(AccountFileWatcherMgr::GetInstance())
{
    accountFileOperator_ = accountFileWatcherMgr_.accountFileOperator_;
    initOk_ = false;
    checkCallbackFunc_ = [this](const std::string &fileName, const int32_t id, uint32_t event) {
        ACCOUNT_LOGI("inotify event = %{public}d, fileName = %{public}s", event, fileName.c_str());
        switch (event) {
            case IN_MODIFY: {
                return DealWithFileModifyEvent(fileName, id);
            }
            case IN_MOVE_SELF: {
                accountFileWatcherMgr_.RemoveFileWatcher(id, fileName);
                ReportOsAccountDataTampered(id, fileName, "DISTRIBUTED_ACCOUT_INFO");
                break;
            }
            case IN_DELETE_SELF: {
                DealWithFileDeleteEvent(fileName, id);
                break;
            }
            default: {
                ACCOUNT_LOGW("get event invalid!");
                return false;
            }
        }
        return true;
    };
}

bool OhosAccountDataDeal::DealWithFileModifyEvent(const std::string &fileName, const int32_t id)
{
    ACCOUNT_LOGI("enter");
    {
        std::shared_lock<std::shared_timed_mutex> lock(accountFileOperator_->fileLock_);
        if (accountFileOperator_->GetValidModifyFileOperationFlag(fileName)) {
            ACCOUNT_LOGD("this is valid service operate, no need to deal with it.");
            accountFileOperator_->SetValidModifyFileOperationFlag(fileName, false);
            return true;
        }
    }
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    std::string fileInfoStr;
    if (accountFileOperator_->GetFileContentByPath(fileName, fileInfoStr) != ERR_OK) {
        ACCOUNT_LOGE("get content from file %{public}s failed!", fileName.c_str());
        return false;
    }
    uint8_t localDigestData[ALG_COMMON_SIZE] = {0};
    accountFileWatcherMgr_.GetAccountInfoDigestFromFile(fileName, localDigestData, ALG_COMMON_SIZE);
    uint8_t newDigestData[ALG_COMMON_SIZE] = {0};
    GenerateAccountInfoDigest(fileInfoStr, newDigestData, ALG_COMMON_SIZE);
    if (memcmp(localDigestData, newDigestData, ALG_COMMON_SIZE) == 0) {
        ACCOUNT_LOGD("No need to recover local file data.");
        return true;
    }
    ReportOsAccountDataTampered(id, fileName, "DISTRIBUTED_ACCOUT_INFO");
    return true;
}

void OhosAccountDataDeal::DealWithFileDeleteEvent(const std::string &fileName, const int32_t id)
{
    {
        std::shared_lock<std::shared_timed_mutex> lock(accountFileOperator_->fileLock_);
        if (accountFileOperator_->GetValidDeleteFileOperationFlag(fileName)) {
            ACCOUNT_LOGD("this is valid service operate, no need to deal with it.");
            accountFileOperator_->SetValidDeleteFileOperationFlag(fileName, false);
            accountFileWatcherMgr_.RemoveFileWatcher(id, fileName);
            return;
        }
        std::string fileDir = configFileDir_ + std::to_string(id);
        if (!accountFileOperator_->IsExistDir(fileDir)) {
            ACCOUNT_LOGI("this id is already removed.");
            return;
        }
    }
    ReportOsAccountDataTampered(id, fileName, "DISTRIBUTED_ACCOUT_INFO");
}

void OhosAccountDataDeal::AddFileWatcher(const int32_t id)
{
    std::string configFile = configFileDir_ + std::to_string(id) + ACCOUNT_CFG_FILE_NAME;
    accountFileWatcherMgr_.AddFileWatcher(id, checkCallbackFunc_, configFile);
}

ErrCode OhosAccountDataDeal::Init(int32_t userId)
{
    std::string configFile = configFileDir_ + std::to_string(userId) + ACCOUNT_CFG_FILE_NAME;
    if (!accountFileOperator_->IsExistFile(configFile)) {
        ACCOUNT_LOGI("file %{public}s not exist, create!", configFile.c_str());
        BuildJsonFileFromScratch(userId);
    }

    std::ifstream fin(configFile);
    if (!fin) {
        ACCOUNT_LOGE("Failed to open config file %{public}s, errno %{public}d.", configFile.c_str(), errno);
        ReportOhosAccountOperationFail(userId, OPERATION_INIT_OPEN_FILE_TO_READ, errno, configFile);
        return ERR_ACCOUNT_DATADEAL_INPUT_FILE_ERROR;
    }

    // NOT-allow exceptions when parse json file
    std::lock_guard<std::mutex> lock(mutex_);
    nlohmann::json jsonData = json::parse(fin, nullptr, false);
    fin.close();
    if (jsonData.is_discarded() || !jsonData.is_structured()) {
        ACCOUNT_LOGE("Invalid json file, remove");
        if (RemoveFile(configFile)) {
            ACCOUNT_LOGE("Remove invalid json file %{public}s failed, errno %{public}d.", configFile.c_str(), errno);
            ReportOhosAccountOperationFail(userId, OPERATION_REMOVE_FILE, errno, configFile);
        }
        return ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION;
    }

    // recover watch for exist account info
    std::vector<OsAccountInfo> osAccountInfos;
    IInnerOsAccountManager::GetInstance().QueryAllCreatedOsAccounts(osAccountInfos);
    for (const auto &info : osAccountInfos) {
        AddFileWatcher(info.GetLocalId());
    }
    initOk_ = true;
    return ERR_OK;
}

ErrCode OhosAccountDataDeal::AccountInfoFromJson(AccountInfo &accountInfo, int32_t userId)
{
    if (!initOk_) {
        ACCOUNT_LOGE("not init yet!");
        return ERR_ACCOUNT_DATADEAL_NOT_READY;
    }
    return GetAccountInfo(accountInfo, userId);
}

ErrCode OhosAccountDataDeal::AccountInfoToJson(const AccountInfo &accountInfo)
{
    if (!initOk_) {
        ACCOUNT_LOGE("Not init ok");
        return ERR_ACCOUNT_DATADEAL_NOT_READY;
    }
    return SaveAccountInfo(accountInfo);
}

ErrCode OhosAccountDataDeal::SaveAccountInfo(const AccountInfo &accountInfo)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    std::string scalableDataStr = (accountInfo.ohosAccountInfo_.scalableData_).ToString();
    nlohmann::json jsonData = json {
        {DATADEAL_JSON_KEY_BIND_TIME, accountInfo.bindTime_},
        {DATADEAL_JSON_KEY_USERID, accountInfo.userId_},
        {DATADEAL_JSON_KEY_OHOSACCOUNT_NAME, accountInfo.ohosAccountInfo_.name_},
        {DATADEAL_JSON_KEY_OHOSACCOUNT_RAW_UID, accountInfo.ohosAccountInfo_.GetRawUid()},
        {DATADEAL_JSON_KEY_OHOSACCOUNT_UID, accountInfo.ohosAccountInfo_.uid_},
        {DATADEAL_JSON_KEY_OHOSACCOUNT_STATUS, accountInfo.ohosAccountInfo_.status_},
        {DATADEAL_JSON_KEY_OHOSACCOUNT_CALLINGUID, accountInfo.ohosAccountInfo_.callingUid_},
        {DATADEAL_JSON_KEY_OHOSACCOUNT_NICKNAME, accountInfo.ohosAccountInfo_.nickname_},
        {DATADEAL_JSON_KEY_OHOSACCOUNT_AVATAR, accountInfo.ohosAccountInfo_.avatar_},
        {DATADEAL_JSON_KEY_OHOSACCOUNT_SCALABLEDATA, scalableDataStr}
    };
    std::string accountInfoValue = jsonData.dump(-1, ' ', false, json::error_handler_t::ignore);
    std::string configFile = configFileDir_ + std::to_string(accountInfo.userId_) + ACCOUNT_CFG_FILE_NAME;

    ErrCode ret = accountFileOperator_->InputFileByPathAndContent(configFile, accountInfoValue);
    if (ret == ERR_OHOSACCOUNT_SERVICE_FILE_CHANGE_DIR_MODE_ERROR) {
        ReportOhosAccountOperationFail(accountInfo.userId_, OPERATION_CHANGE_MODE_FILE, errno, configFile);
    }
    if (ret != ERR_OK && ret != ERR_OHOSACCOUNT_SERVICE_FILE_CHANGE_DIR_MODE_ERROR) {
        ReportOhosAccountOperationFail(accountInfo.userId_, OPERATION_OPEN_FILE_TO_WRITE, errno, configFile);
    }
    accountFileWatcherMgr_.AddAccountInfoDigest(accountInfoValue, configFile);
    return ret;
}

ErrCode OhosAccountDataDeal::ParseJsonFromFile(const std::string &filePath, nlohmann::json &jsonData, int32_t userId)
{
    std::ifstream fin(filePath);
    if (!fin) {
        ACCOUNT_LOGE("Failed to open config file %{public}s, errno %{public}d.", filePath.c_str(), errno);
        ReportOhosAccountOperationFail(userId, OPERATION_OPEN_FILE_TO_READ, errno, filePath);
        return ERR_ACCOUNT_DATADEAL_INPUT_FILE_ERROR;
    }
    // NOT-allow exceptions when parse json file
    jsonData = json::parse(fin, nullptr, false);
    fin.close();
    if (jsonData.is_discarded() || !jsonData.is_structured()) {
        ACCOUNT_LOGE("Invalid json file,  %{public}s, remove", filePath.c_str());
        return ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION;
    }
    return ERR_OK;
}

ErrCode OhosAccountDataDeal::GetAccountInfoFromJson(
    const nlohmann::json &jsonData, AccountInfo &accountInfo, const int32_t userId)
{
    const auto &jsonObjectEnd = jsonData.end();
    if ((jsonData.find(DATADEAL_JSON_KEY_BIND_TIME) != jsonObjectEnd) &&
        (jsonData.at(DATADEAL_JSON_KEY_BIND_TIME).is_number())) {
        accountInfo.bindTime_ = jsonData.at(DATADEAL_JSON_KEY_BIND_TIME).get<std::time_t>();
    }

    if ((jsonData.find(DATADEAL_JSON_KEY_OHOSACCOUNT_NAME) != jsonObjectEnd) &&
        (jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_NAME).is_string())) {
        accountInfo.ohosAccountInfo_.name_ = jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_NAME).get<std::string>();
    }

    if ((jsonData.find(DATADEAL_JSON_KEY_OHOSACCOUNT_RAW_UID) != jsonObjectEnd) &&
        (jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_RAW_UID).is_string())) {
        std::string rawUid = jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_RAW_UID).get<std::string>();
        accountInfo.ohosAccountInfo_.SetRawUid(rawUid);
    }

    if ((jsonData.find(DATADEAL_JSON_KEY_OHOSACCOUNT_UID) != jsonObjectEnd) &&
        (jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_UID).is_string())) {
        accountInfo.ohosAccountInfo_.uid_ = jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_UID).get<std::string>();
    }

    if ((jsonData.find(DATADEAL_JSON_KEY_OHOSACCOUNT_STATUS) != jsonObjectEnd) &&
        (jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_STATUS).is_number())) {
        accountInfo.ohosAccountInfo_.status_ = jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_STATUS).get<int32_t>();
    }

    if ((jsonData.find(DATADEAL_JSON_KEY_OHOSACCOUNT_CALLINGUID) != jsonObjectEnd) &&
        (jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_CALLINGUID).is_number())) {
        accountInfo.ohosAccountInfo_.callingUid_ =
            jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_CALLINGUID).get<int32_t>();
    }

    if ((jsonData.find(DATADEAL_JSON_KEY_OHOSACCOUNT_NICKNAME) != jsonObjectEnd) &&
        (jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_NICKNAME).is_string())) {
        accountInfo.ohosAccountInfo_.nickname_ =
            jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_NICKNAME).get<std::string>();
    }

    if ((jsonData.find(DATADEAL_JSON_KEY_OHOSACCOUNT_AVATAR) != jsonObjectEnd) &&
        (jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_AVATAR).is_string())) {
        accountInfo.ohosAccountInfo_.avatar_ = jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_AVATAR).get<std::string>();
    }

    if ((jsonData.find(DATADEAL_JSON_KEY_OHOSACCOUNT_SCALABLEDATA) != jsonObjectEnd) &&
        (jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_SCALABLEDATA).is_string())) {
        auto scalableDataJson = jsonData.at(DATADEAL_JSON_KEY_OHOSACCOUNT_SCALABLEDATA).get<std::string>();
        sptr<AAFwk::Want> want = AAFwk::Want::FromString(scalableDataJson);
        if (want == nullptr) {
            return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
        }
        accountInfo.ohosAccountInfo_.scalableData_ = *want;
    }
    accountInfo.userId_ = userId;
    return ERR_OK;
}

ErrCode OhosAccountDataDeal::GetAccountInfo(AccountInfo &accountInfo, const int32_t userId)
{
    if (userId < 0) {
        ACCOUNT_LOGW("invalid userid = %{public}d", userId);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    std::string configFile = configFileDir_ + std::to_string(userId) + ACCOUNT_CFG_FILE_NAME;
    if (!accountFileOperator_->IsExistFile(configFile)) {
        if (errno != ENOENT) {
            std::string errorMsg = "Stat " + configFile + " failed";
            ReportOhosAccountOperationFail(userId, OPERATION_OPEN_FILE_TO_READ, errno, errorMsg);
            return ERR_ACCOUNT_DATADEAL_INPUT_FILE_ERROR;
        } else {
            ACCOUNT_LOGI("File %{public}s not exist, create!", configFile.c_str());
            BuildJsonFileFromScratch(userId); // create default config file for first login
        }
    }
    std::lock_guard<std::mutex> lock(mutex_);
    nlohmann::json jsonData;
    ErrCode ret = ParseJsonFromFile(configFile, jsonData, userId);
    if (ret != ERR_OK) {
        return ret;
    }
    return GetAccountInfoFromJson(jsonData, accountInfo, userId);
}

void OhosAccountDataDeal::BuildJsonFileFromScratch(int32_t userId)
{
    AccountInfo accountInfo;
    accountInfo.userId_ = userId;
    accountInfo.bindTime_ = 0;
    accountInfo.ohosAccountInfo_.uid_ = DEFAULT_OHOS_ACCOUNT_UID;
    accountInfo.ohosAccountInfo_.name_ = DEFAULT_OHOS_ACCOUNT_NAME;
    accountInfo.ohosAccountInfo_.status_ = ACCOUNT_STATE_UNBOUND;
    accountInfo.ohosAccountInfo_.callingUid_ = DEFAULT_CALLING_UID;
    accountInfo.digest_ = "";
    accountInfo.ohosAccountInfo_.SetRawUid(DEFAULT_OHOS_ACCOUNT_UID);
    SaveAccountInfo(accountInfo);
    AddFileWatcher(userId);
}
} // namespace AccountSA
} // namespace OHOS
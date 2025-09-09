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
#include "data_size_report_adapter.h"
#include "ohos_account_data_deal.h"

namespace OHOS {
namespace AccountSA {
namespace {
const char ACCOUNT_CFG_FILE_NAME[] = "/account.json";
const char ACCOUNT_AVATAR_NAME[] = "/account_avatar";
const char DATADEAL_JSON_KEY_OHOSACCOUNT_NAME[] = "account_name";
const char DATADEAL_JSON_KEY_OHOSACCOUNT_RAW_UID[] = "raw_uid";
const char DATADEAL_JSON_KEY_OHOSACCOUNT_UID[] = "open_id";
const char DATADEAL_JSON_KEY_OHOSACCOUNT_STATUS[] = "bind_status";
const char DATADEAL_JSON_KEY_OHOSACCOUNT_CALLINGUID[] = "calling_uid";
const char DATADEAL_JSON_KEY_OHOSACCOUNT_NICKNAME[] = "account_nickname";
const char DATADEAL_JSON_KEY_OHOSACCOUNT_AVATAR[] = "account_avatar";
const char DATADEAL_JSON_KEY_OHOSACCOUNT_SCALABLEDATA[] = "account_scalableData";
const char DATADEAL_JSON_KEY_OHOSACCOUNT_VERSION[] = "version";
const char DATADEAL_JSON_KEY_USERID[] = "user_id";
const char DATADEAL_JSON_KEY_BIND_TIME[] = "bind_time";
#ifdef ENABLE_FILE_WATCHER
const uint32_t ALG_COMMON_SIZE = 32;
#endif // ENABLE_FILE_WATCHER
} // namespace

#ifdef ENABLE_FILE_WATCHER
OhosAccountDataDeal::OhosAccountDataDeal(const std::string &configFileDir)
    : configFileDir_(configFileDir),
    accountFileWatcherMgr_(AccountFileWatcherMgr::GetInstance())
{
    accountFileOperator_ = accountFileWatcherMgr_.accountFileOperator_;
    initOk_ = false;
    checkCallbackFunc_ = [this](const std::string &fileName, int32_t id, uint32_t event) {
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
#else
OhosAccountDataDeal::OhosAccountDataDeal(const std::string &configFileDir)
    : configFileDir_(configFileDir)
{
    accountFileOperator_ = std::make_shared<AccountFileOperator>();
    initOk_ = false;
}
#endif // ENABLE_FILE_WATCHER

#ifdef ENABLE_FILE_WATCHER
bool OhosAccountDataDeal::DealWithFileModifyEvent(const std::string &fileName, const int32_t id)
{
    ACCOUNT_LOGI("enter");
    {
        std::unique_lock<std::shared_timed_mutex> lock(accountFileOperator_->fileLock_);
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
    ErrCode errCode = accountFileWatcherMgr_.GetAccountInfoDigestFromFile(fileName, localDigestData, ALG_COMMON_SIZE);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get account info digest from file failed, errCode = %{public}d", errCode);
        REPORT_OHOS_ACCOUNT_FAIL(id, "fileWatcher", errCode, "Get account info digest failed");
    }
#ifdef HAS_HUKS_PART
    uint8_t newDigestData[ALG_COMMON_SIZE] = {0};
    int32_t result = GenerateAccountInfoDigest(fileInfoStr, newDigestData, ALG_COMMON_SIZE);
    if (result != ERR_OK) {
        REPORT_OHOS_ACCOUNT_FAIL(id, "fileWatcher", result, "Generate account info digest failed");
    }
    if (memcmp(localDigestData, newDigestData, ALG_COMMON_SIZE) == 0) {
        ACCOUNT_LOGD("No need to recover local file data.");
        return true;
    }
#endif // HAS_HUKS_PART
    ReportOsAccountDataTampered(id, fileName, "DISTRIBUTED_ACCOUT_INFO");
    return true;
}

void OhosAccountDataDeal::DealWithFileDeleteEvent(const std::string &fileName, const int32_t id)
{
    {
        std::unique_lock<std::shared_timed_mutex> lock(accountFileOperator_->fileLock_);
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
#endif // ENABLE_FILE_WATCHER

ErrCode OhosAccountDataDeal::Init(int32_t userId)
{
    std::string configFile = configFileDir_ + std::to_string(userId) + ACCOUNT_CFG_FILE_NAME;
    if (!accountFileOperator_->IsExistFile(configFile)) {
        ACCOUNT_LOGI("file %{public}s not exist, create!", configFile.c_str());
        BuildJsonFileFromScratch(userId);
    }

    std::ifstream fin(configFile);
    if (!fin) {
        int32_t err = errno;
        ACCOUNT_LOGE("Failed to open config file %{public}s, errno %{public}d.", configFile.c_str(), err);
        ReportOhosAccountOperationFail(userId, OPERATION_INIT_OPEN_FILE_TO_READ, err, configFile);
        return ERR_ACCOUNT_DATADEAL_INPUT_FILE_ERROR;
    }

    // NOT-allow exceptions when parse json file
    std::lock_guard<std::mutex> lock(mutex_);
    std::string fileContent((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    fin.close();
    auto jsonData = CreateJsonFromString(fileContent);
    if (jsonData == nullptr || !IsObject(jsonData)) {
        ACCOUNT_LOGE("Invalid json file, remove");
        if (RemoveFile(configFile)) {
            int32_t err = errno;
            ACCOUNT_LOGE("Remove invalid json file %{public}s failed, errno %{public}d.", configFile.c_str(), err);
            ReportOhosAccountOperationFail(userId, OPERATION_REMOVE_FILE, err, configFile);
        }
        return ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION;
    }

    // recover watch for exist account info
    std::vector<OsAccountInfo> osAccountInfos;
    IInnerOsAccountManager::GetInstance().QueryAllCreatedOsAccounts(osAccountInfos);
#ifdef ENABLE_FILE_WATCHER
    for (const auto &info : osAccountInfos) {
        AddFileWatcher(info.GetLocalId());
    }
#endif // ENABLE_FILE_WATCHER
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
    auto jsonData = CreateJson();
    AddIntToJson(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_VERSION, accountInfo.version_);
    AddIntToJson(jsonData, DATADEAL_JSON_KEY_BIND_TIME, accountInfo.bindTime_);
    AddIntToJson(jsonData, DATADEAL_JSON_KEY_USERID, accountInfo.userId_);
    AddStringToJson(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_NAME, accountInfo.ohosAccountInfo_.name_);
    AddStringToJson(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_RAW_UID, accountInfo.ohosAccountInfo_.GetRawUid());
    AddStringToJson(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_UID, accountInfo.ohosAccountInfo_.uid_);
    AddIntToJson(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_STATUS, accountInfo.ohosAccountInfo_.status_);
    AddIntToJson(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_CALLINGUID, accountInfo.ohosAccountInfo_.callingUid_);
    AddStringToJson(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_NICKNAME, accountInfo.ohosAccountInfo_.nickname_);
    AddStringToJson(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_SCALABLEDATA, scalableDataStr);

    std::string avatarFile = configFileDir_ + std::to_string(accountInfo.userId_) + ACCOUNT_AVATAR_NAME;
    ErrCode ret = accountFileOperator_->InputFileByPathAndContentWithTransaction(
        avatarFile, accountInfo.ohosAccountInfo_.avatar_);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to save avatar! ret = %{public}d", ret);
        return ret;
    }
    std::string accountInfoValue = PackJsonToString(jsonData);
    std::string configFile = configFileDir_ + std::to_string(accountInfo.userId_) + ACCOUNT_CFG_FILE_NAME;

    ret = accountFileOperator_->InputFileByPathAndContent(configFile, accountInfoValue);
    if (ret == ERR_OHOSACCOUNT_SERVICE_FILE_CHANGE_DIR_MODE_ERROR) {
        ReportOhosAccountOperationFail(accountInfo.userId_, OPERATION_CHANGE_MODE_FILE, ret, configFile);
    }
    if (ret != ERR_OK && ret != ERR_OHOSACCOUNT_SERVICE_FILE_CHANGE_DIR_MODE_ERROR) {
        ReportOhosAccountOperationFail(accountInfo.userId_, OPERATION_OPEN_FILE_TO_WRITE, ret, configFile);
    }

    // report data_size when distributed account profile photo updated
    std::vector<int32_t> currentId{accountInfo.userId_};
    ReportUserDataSize(currentId);
#ifdef ENABLE_FILE_WATCHER
    accountFileWatcherMgr_.AddAccountInfoDigest(accountInfoValue, configFile);
#endif // ENABLE_FILE_WATCHER
    return ret;
}

ErrCode OhosAccountDataDeal::ParseJsonFromFile(const std::string &filePath, CJsonUnique &jsonData, int32_t userId)
{
    std::ifstream fin(filePath);
    if (!fin) {
        int32_t err = errno;
        ACCOUNT_LOGE("Failed to open config file %{public}s, errno %{public}d.", filePath.c_str(), err);
        ReportOhosAccountOperationFail(userId, OPERATION_OPEN_FILE_TO_READ, err, filePath);
        return ERR_ACCOUNT_DATADEAL_INPUT_FILE_ERROR;
    }
    std::string fileContent((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    fin.close();
    jsonData = CreateJsonFromString(fileContent);
    if (jsonData == nullptr || !IsObject(jsonData)) {
        ACCOUNT_LOGE("Invalid json file,  %{public}s, remove", filePath.c_str());
        return ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION;
    }
    std::string avatarData;
    if (IsKeyExist(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_AVATAR)) {
        cJSON *it = GetItemFromJson(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_AVATAR);
        if (IsString(it)) {
            AddStringToJson(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_AVATAR,  it->valuestring);
        }
    } else {
        std::string avatarFile = configFileDir_ + std::to_string(userId) + ACCOUNT_AVATAR_NAME;
        if (accountFileOperator_->GetFileContentByPath(avatarFile, avatarData) == ERR_OK) {
            AddStringToJson(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_AVATAR,  avatarData);
        }
    }
    return ERR_OK;
}

template <typename T, typename Callback>
bool GetJsonField(CJsonUnique &jsonData, const std::string &key, Callback callback)
{
    if (!IsKeyExist(jsonData, key)) {
        return false;
    }
    auto it = GetItemFromJson(jsonData, key);
    if constexpr (std::is_same_v<T, int> || std::is_same_v<T, std::time_t>) {
        if (!IsNumber(it)) {
            return false;
        }
        T value = static_cast<T>(GetJsonNumberValue(it));
        callback(value);
        return true;
    }
    if constexpr (std::is_same_v<T, std::string>) {
        if (!IsString(it)) {
            return false;
        }
        T value = it->valuestring;
        callback(value);
        return true;
    }
    return false;
}

ErrCode OhosAccountDataDeal::GetAccountInfoFromJson(
    CJsonUnique &jsonData, AccountInfo &accountInfo, const int32_t userId)
{
    GetJsonField<int>(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_VERSION, [&](int value) {
        accountInfo.version_ = value;
    });

    GetJsonField<std::time_t>(jsonData, DATADEAL_JSON_KEY_BIND_TIME, [&](std::time_t value) {
        accountInfo.bindTime_ = value;
    });

    GetJsonField<std::string>(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_NAME, [&](const std::string &value) {
        accountInfo.ohosAccountInfo_.name_ = value;
    });

    GetJsonField<std::string>(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_RAW_UID, [&](const std::string &value) {
        accountInfo.ohosAccountInfo_.SetRawUid(value);
    });

    GetJsonField<std::string>(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_UID, [&](const std::string &value) {
        accountInfo.ohosAccountInfo_.uid_ = value;
    });

    GetJsonField<int>(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_STATUS, [&](int value) {
        accountInfo.ohosAccountInfo_.status_ = value;
    });

    GetJsonField<int>(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_CALLINGUID, [&](int value) {
        accountInfo.ohosAccountInfo_.callingUid_ = value;
    });

    GetJsonField<std::string>(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_NICKNAME, [&](const std::string &value) {
        accountInfo.ohosAccountInfo_.nickname_ = value;
    });

    GetJsonField<std::string>(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_AVATAR, [&](const std::string &value) {
        accountInfo.ohosAccountInfo_.avatar_ = value;
    });

    GetJsonField<std::string>(jsonData, DATADEAL_JSON_KEY_OHOSACCOUNT_SCALABLEDATA, [&](std::string &value) {
        sptr<AAFwk::Want> want = AAFwk::Want::FromString(value);
        if (want != nullptr) {
            accountInfo.ohosAccountInfo_.scalableData_ = *want;
        }
    });

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
    ErrCode ret = accountFileOperator_->CheckFileExistence(configFile);
    if (ret != ERR_OK) {
        if (ret != ERR_ACCOUNT_COMMON_FILE_NOT_EXIST) {
            std::string errorMsg = "Stat " + configFile + " failed";
            ReportOhosAccountOperationFail(userId, OPERATION_OPEN_FILE_TO_READ, ret, errorMsg);
            return ERR_ACCOUNT_DATADEAL_INPUT_FILE_ERROR;
        } else {
            ACCOUNT_LOGI("File %{public}s not exist, create!", configFile.c_str());
            BuildJsonFileFromScratch(userId); // create default config file for first login
        }
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto jsonData = CreateJson();
    ret = ParseJsonFromFile(configFile, jsonData, userId);
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
    ErrCode result = SaveAccountInfo(accountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Save account Info failed, result = %{public}d", result);
    }
#ifdef ENABLE_FILE_WATCHER
    AddFileWatcher(userId);
#endif // ENABLE_FILE_WATCHER
}
} // namespace AccountSA
} // namespace OHOS
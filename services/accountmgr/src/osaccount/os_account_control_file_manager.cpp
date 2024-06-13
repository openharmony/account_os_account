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
#include "os_account_control_file_manager.h"
#include <dirent.h>
#include <string>
#include <pthread.h>
#include <securec.h>
#include <sstream>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"
#include "config_policy_utils.h"
#include "os_account_constants.h"
#include "os_account_interface.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string DEFAULT_ACTIVATED_ACCOUNT_ID = "DefaultActivatedAccountID";
const int32_t MAX_LOCAL_ID = 10736; // int32 max value reduce 200000 be divisible by 200000
const std::string OS_ACCOUNT_STORE_ID = "os_account_info";
const uint32_t ALG_COMMON_SIZE = 32;
#ifndef ACCOUNT_TEST
const std::string ACCOUNT_CFG_DIR_ROOT_PATH = "/data/service/el1/public/account/";
#else
const std::string ACCOUNT_CFG_DIR_ROOT_PATH = "/data/service/el1/public/account/test/";
#endif // ACCOUNT_TEST
const std::string DISTRIBUTED_ACCOUNT_FILE_NAME = "/account.json";
const std::string OS_ACCOUNT_CONFIG_FILE = "etc/os_account/os_account_config.json";
const std::string MAX_OS_ACCOUNT_NUM = "maxOsAccountNum";
const std::string MAX_LOGGED_IN_OS_ACCOUNT_NUM = "maxLoggedInOsAccountNum";
#ifndef ACCOUNT_TEST
const std::string DEFAULT_OS_ACCOUNT_CONFIG_FILE = "/system/etc/account/os_account_config.json";
#else
const std::string DEFAULT_OS_ACCOUNT_CONFIG_FILE = ACCOUNT_CFG_DIR_ROOT_PATH + "os_account_config.json";
#endif // ACCOUNT_TEST
}

bool GetValidAccountID(const std::string& dirName, std::int32_t& accountID)
{
    // check length first
    if (dirName.empty() || dirName.size() > Constants::MAX_USER_ID_LENGTH) {
        return false;
    }

    auto iter = std::any_of(dirName.begin(), dirName.end(),
        [dirName](char c) {
            return (c < '0' || c > '9');
        });
    if (iter) {
        return false;
    }

    // convert to osaccount id
    std::stringstream sstream;
    sstream << dirName;
    sstream >> accountID;
    return (accountID >= Constants::ADMIN_LOCAL_ID && accountID <= Constants::MAX_USER_ID);
}

ErrCode OsAccountControlFileManager::GetOsAccountConfig(OsAccountConfig &config)
{
    std::string cfgPath = DEFAULT_OS_ACCOUNT_CONFIG_FILE;
    CfgFiles *cfgFiles = GetCfgFiles(OS_ACCOUNT_CONFIG_FILE.c_str());
    if (cfgFiles != nullptr) {
        if (cfgFiles->paths[0] != nullptr) {
            cfgPath = cfgFiles->paths[0];
        }
        FreeCfgFiles(cfgFiles);
    }
    std::string configStr;
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(cfgPath, configStr);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get content from file %{public}s failed!", cfgPath.c_str());
        return errCode;
    }
    Json configJson = Json::parse(configStr, nullptr, false);
    if (configJson.is_discarded()) {
        ACCOUNT_LOGE("parse os account info json data failed");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    auto jsonEnd = configJson.end();
    int32_t maxOsAccountNum = -1;
    OHOS::AccountSA::GetDataByType<int32_t>(configJson, jsonEnd, MAX_OS_ACCOUNT_NUM,
        maxOsAccountNum, OHOS::AccountSA::JsonType::NUMBER);
    if (maxOsAccountNum > 0) {
        config.maxOsAccountNum = static_cast<uint32_t>(maxOsAccountNum);
    }
    OHOS::AccountSA::GetDataByType<int32_t>(configJson, jsonEnd, MAX_LOGGED_IN_OS_ACCOUNT_NUM,
        config.maxLoggedInOsAccountNum, OHOS::AccountSA::JsonType::NUMBER);
    if (config.maxLoggedInOsAccountNum > config.maxOsAccountNum) {
        config.maxLoggedInOsAccountNum = config.maxOsAccountNum;
    }
    return ERR_OK;
}

bool OsAccountControlFileManager::RecoverAccountData(const std::string &fileName, const int32_t id)
{
#ifdef HAS_KV_STORE_PART
    std::string recoverDataStr;
    if (fileName == Constants::ACCOUNT_LIST_FILE_JSON_PATH) {
        Json accountListJson;
        osAccountDataBaseOperator_->GetAccountListFromStoreID(OS_ACCOUNT_STORE_ID, accountListJson);
        recoverDataStr = accountListJson.dump();
    } else if (id >= Constants::START_USER_ID) {
        OsAccountInfo osAccountInfo;
        if (GetOsAccountFromDatabase(OS_ACCOUNT_STORE_ID, id, osAccountInfo) != ERR_OK) {
            ACCOUNT_LOGW("get recover file data failed");
            return false;
        }
        recoverDataStr = osAccountInfo.ToString();
    } else {
        ACCOUNT_LOGW("get recover file data failed");
        return false;
    }
    if (recoverDataStr.empty()) {
        ACCOUNT_LOGW("get recover file data failed");
        return false;
    }
    // recover data
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(fileName, recoverDataStr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("recover local file data failed, err = %{public}d", result);
        return false;
    }
    // update local digest
    if (accountFileWatcherMgr_.AddAccountInfoDigest(recoverDataStr, fileName) != ERR_OK) {
        ACCOUNT_LOGE("failed to update local digest");
        return false;
    }
#endif
    return true;
}

bool OsAccountControlFileManager::DealWithFileModifyEvent(const std::string &fileName, const int32_t id)
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

    if (memcmp(localDigestData, newDigestData, ALG_COMMON_SIZE) == EOK) {
        ACCOUNT_LOGD("No need to recover local file data.");
        return true;
    }
    ReportOsAccountDataTampered(id, fileName, "OS_ACCOUNT_INFO");
    ACCOUNT_LOGW("local file data has been changed");
    return RecoverAccountData(fileName, id);
}

bool OsAccountControlFileManager::DealWithFileDeleteEvent(const std::string &fileName, const int32_t id)
{
    ACCOUNT_LOGI("enter");
    {
        std::shared_lock<std::shared_timed_mutex> lock(accountFileOperator_->fileLock_);
        if (accountFileOperator_->GetValidDeleteFileOperationFlag(fileName)) {
            ACCOUNT_LOGD("this is valid service operate, no need to deal with it.");
            accountFileOperator_->SetValidDeleteFileOperationFlag(fileName, false);
            accountFileWatcherMgr_.RemoveFileWatcher(id, fileName);
            return true;
        }
    }
    ReportOsAccountDataTampered(id, fileName, "OS_ACCOUNT_INFO");
    {
        std::lock_guard<std::mutex> lock(accountInfoFileLock_);
        if (!RecoverAccountData(fileName, id)) {
            ACCOUNT_LOGE("recover account data failed.");
        }
    }
    accountFileWatcherMgr_.AddFileWatcher(id, eventCallbackFunc_, fileName);
    return true;
}

bool OsAccountControlFileManager::DealWithFileMoveEvent(const std::string &fileName, const int32_t id)
{
    ACCOUNT_LOGI("enter");
    // delete old file watcher
    accountFileWatcherMgr_.RemoveFileWatcher(id, fileName);
    ReportOsAccountDataTampered(id, fileName, "OS_ACCOUNT_INFO");
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    if (!RecoverAccountData(fileName, id)) {
        ACCOUNT_LOGE("recover account data failed.");
    }
    accountFileWatcherMgr_.AddFileWatcher(id, eventCallbackFunc_, fileName);
    return true;
}

OsAccountControlFileManager::OsAccountControlFileManager()
    : accountFileWatcherMgr_(AccountFileWatcherMgr::GetInstance())
{
    accountFileOperator_ = accountFileWatcherMgr_.accountFileOperator_;
#ifdef HAS_KV_STORE_PART
    osAccountDataBaseOperator_ = std::make_shared<OsAccountDatabaseOperator>();
#endif
    osAccountFileOperator_ = std::make_shared<OsAccountFileOperator>();
    osAccountPhotoOperator_ = std::make_shared<OsAccountPhotoOperator>();
    eventCallbackFunc_ = [this](const std::string &fileName, const int32_t id, uint32_t event) {
        ACCOUNT_LOGI("inotify event = %{public}d, fileName = %{public}s", event, fileName.c_str());
        switch (event) {
            case IN_MODIFY: {
                return DealWithFileModifyEvent(fileName, id);
            }
            case IN_MOVE_SELF: {
                return DealWithFileMoveEvent(fileName, id);
            }
            case IN_DELETE_SELF: {
                return DealWithFileDeleteEvent(fileName, id);
            }
            default: {
                ACCOUNT_LOGW("get event invalid!");
                return false;
            }
        }
    };
}
OsAccountControlFileManager::~OsAccountControlFileManager()
{}

void OsAccountControlFileManager::Init()
{
    osAccountFileOperator_->Init();
    FileInit();
    Json accountListJson;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        return;
    }
    auto jsonEnd = accountListJson.end();
    std::vector<std::string> accountIdList;
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        accountListJson, jsonEnd, Constants::ACCOUNT_LIST, accountIdList, OHOS::AccountSA::JsonType::ARRAY);
    if (!accountIdList.empty()) {
        std::lock_guard<std::mutex> lock(operatingIdMutex_);
        nextLocalId_ = atoi(accountIdList[accountIdList.size() - 1].c_str()) + 1;
        InitFileWatcherInfo(accountIdList);
    }
    ACCOUNT_LOGI("OsAccountControlFileManager Init end");
}

void OsAccountControlFileManager::FileInit()
{
    if (!accountFileOperator_->IsJsonFileReady(Constants::ACCOUNT_LIST_FILE_JSON_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account list, create!");
        RecoverAccountListJsonFile();
    }
    if (!accountFileOperator_->IsJsonFileReady(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account info digest file, create!");
        RecoverAccountInfoDigestJsonFile();
    }
    // -1 is special refers to conmon account data file.
    accountFileWatcherMgr_.AddFileWatcher(-1, eventCallbackFunc_, Constants::ACCOUNT_LIST_FILE_JSON_PATH);
    if (!accountFileOperator_->IsJsonFileReady(Constants::ACCOUNT_INDEX_JSON_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account index file, create!");
        BuildAndSaveOsAccountIndexJsonFile();
    }
    accountFileWatcherMgr_.AddFileWatcher(-1, eventCallbackFunc_, Constants::ACCOUNT_INDEX_JSON_PATH);
    if (!accountFileOperator_->IsJsonFileReady(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account list, create!");
        BuildAndSaveBaseOAConstraintsJsonFile();
    }
    accountFileWatcherMgr_.AddFileWatcher(-1, eventCallbackFunc_, Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH);
    if (!accountFileOperator_->IsJsonFileReady(Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account list, create!");
        BuildAndSaveGlobalOAConstraintsJsonFile();
    }
    accountFileWatcherMgr_.AddFileWatcher(-1, eventCallbackFunc_, Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH);
    if (!accountFileOperator_->IsJsonFileReady(Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account list, create!");
        BuildAndSaveSpecificOAConstraintsJsonFile();
    }
    accountFileWatcherMgr_.AddFileWatcher(-1, eventCallbackFunc_, Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH);
}

void OsAccountControlFileManager::InitFileWatcherInfo(std::vector<std::string> &accountIdList)
{
    for (std::string i : accountIdList) {
        accountFileWatcherMgr_.AddFileWatcher(stoi(i), eventCallbackFunc_);
    }
}

void OsAccountControlFileManager::BuildAndSaveAccountListJsonFile(const std::vector<std::string>& accounts)
{
    ACCOUNT_LOGD("enter.");
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    Json accountList = Json {
        {Constants::ACCOUNT_LIST, accounts},
        {Constants::COUNT_ACCOUNT_NUM, accounts.size()},
        {DEFAULT_ACTIVATED_ACCOUNT_ID, Constants::START_USER_ID},
        {Constants::MAX_ALLOW_CREATE_ACCOUNT_ID, Constants::MAX_USER_ID},
        {Constants::SERIAL_NUMBER_NUM, Constants::SERIAL_NUMBER_NUM_START},
        {Constants::IS_SERIAL_NUMBER_FULL, Constants::IS_SERIAL_NUMBER_FULL_INIT_VALUE},
    };
    SaveAccountListToFile(accountList);
}

void OsAccountControlFileManager::BuildAndSaveBaseOAConstraintsJsonFile()
{
    ACCOUNT_LOGI("enter.");
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    std::vector<std::string> baseOAConstraints;
    if (osAccountFileOperator_->GetConstraintsByType(OsAccountType::ADMIN, baseOAConstraints) != ERR_OK) {
        ACCOUNT_LOGE("get %{public}d base os account constraints failed.", Constants::START_USER_ID);
        return;
    }
    Json baseOsAccountConstraints = Json {
        {Constants::START_USER_STRING_ID, baseOAConstraints}
    };
    SaveBaseOAConstraintsToFile(baseOsAccountConstraints);
}

void OsAccountControlFileManager::BuildAndSaveGlobalOAConstraintsJsonFile()
{
    ACCOUNT_LOGI("enter.");
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    Json globalOsAccountConstraints = Json {
        {Constants::DEVICE_OWNER_ID, -1},
        {Constants::ALL_GLOBAL_CONSTRAINTS, {}}
    };
    SaveGlobalOAConstraintsToFile(globalOsAccountConstraints);
}

void OsAccountControlFileManager::BuildAndSaveSpecificOAConstraintsJsonFile()
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    Json OsAccountConstraintsList = Json {
        {Constants::ALL_SPECIFIC_CONSTRAINTS, {}},
    };
    Json specificOsAccountConstraints = Json {
        {Constants::START_USER_STRING_ID, OsAccountConstraintsList},
    };
    SaveSpecificOAConstraintsToFile(specificOsAccountConstraints);
}

void OsAccountControlFileManager::BuildAndSaveOsAccountIndexJsonFile()
{
    std::string accountIndex;
    ErrCode result = GetAccountIndexInfo(accountIndex);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get account index info error code %{public}d.", result);
        return;
    }
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    result = accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_INDEX_JSON_PATH, accountIndex);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to input account index info to file!");
    }
    return;
}

void OsAccountControlFileManager::RecoverAccountInfoDigestJsonFile()
{
    std::string listInfoStr;
    accountFileOperator_->GetFileContentByPath(Constants::ACCOUNT_LIST_FILE_JSON_PATH, listInfoStr);
    uint8_t digestOutData[ALG_COMMON_SIZE] = {0};
    GenerateAccountInfoDigest(listInfoStr, digestOutData, ALG_COMMON_SIZE);
    Json digestJsonData = Json {
        {Constants::ACCOUNT_LIST_FILE_JSON_PATH, digestOutData},
    };
    accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH, digestJsonData.dump());
    return;
}

void OsAccountControlFileManager::RecoverAccountListJsonFile()
{
    // get account list
    std::vector<std::string> accounts;
    DIR* rootDir = opendir(Constants::USER_INFO_BASE.c_str());
    if (rootDir == nullptr) {
        accounts.push_back(std::to_string(Constants::START_USER_ID));  // account 100 always exists
        BuildAndSaveAccountListJsonFile(accounts);
        ACCOUNT_LOGE("cannot open dir %{public}s, err %{public}d.", Constants::USER_INFO_BASE.c_str(), errno);
        return;
    }

    struct dirent* curDir = nullptr;
    while ((curDir = readdir(rootDir)) != nullptr) {
        std::string curDirName(curDir->d_name);
        if (curDirName == "." || curDirName == ".." || curDir->d_type != DT_DIR) {
            continue;
        }

        // get and check os account id
        std::int32_t accountID = Constants::INVALID_OS_ACCOUNT_ID;
        if (!GetValidAccountID(curDirName, accountID)) {
            ACCOUNT_LOGE("invalid account id %{public}s detected in %{public}s.", curDirName.c_str(),
                Constants::USER_INFO_BASE.c_str());
            continue;
        }

        // check repeat
        bool sameAccountID = false;
        std::string curAccountIDStr = std::to_string(accountID);
        for (size_t i = 0; i < accounts.size(); ++i) {
            if (accounts[i] == curAccountIDStr) {
                ACCOUNT_LOGE("repeated account id %{public}s detected in %{public}s.", curAccountIDStr.c_str(),
                    Constants::USER_INFO_BASE.c_str());
                sameAccountID = true;
                break;
            }
        }

        if (!sameAccountID && accountID >= Constants::START_USER_ID) {
            accounts.push_back(curAccountIDStr);
        }
    }

    (void)closedir(rootDir);
    BuildAndSaveAccountListJsonFile(accounts);
}

ErrCode OsAccountControlFileManager::GetOsAccountIdList(std::vector<int32_t> &idList)
{
    idList.clear();
    Json accountListJson;
    ErrCode errCode = GetAccountListFromFile(accountListJson);
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::vector<std::string> idStrList;
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(accountListJson, accountListJson.end(),
        Constants::ACCOUNT_LIST, idStrList, OHOS::AccountSA::JsonType::ARRAY);
    for (const auto &idStr : idStrList) {
        idList.emplace_back(atoi(idStr.c_str()));
    }
    return errCode;
}

ErrCode OsAccountControlFileManager::GetOsAccountList(std::vector<OsAccountInfo> &osAccountList)
{
    osAccountList.clear();
    Json accountListJson;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetAccountListFromFile failed!");
#ifdef HAS_KV_STORE_PART
        if (osAccountDataBaseOperator_->GetAccountListFromStoreID("", accountListJson) == ERR_OK) {
            SaveAccountListToFile(accountListJson);
        } else {
            return result;
        }
#else
        return result;
#endif
    }
    const auto &jsonObjectEnd = accountListJson.end();
    std::vector<std::string> idList;
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        accountListJson, jsonObjectEnd, Constants::ACCOUNT_LIST, idList, OHOS::AccountSA::JsonType::ARRAY);

    for (const auto& it : idList) {
        OsAccountInfo osAccountInfo;
        if (GetOsAccountInfoById(std::atoi(it.c_str()), osAccountInfo) == ERR_OK) {
            if (osAccountInfo.GetPhoto() != "") {
                std::string photo = osAccountInfo.GetPhoto();
                GetPhotoById(osAccountInfo.GetLocalId(), photo);
                osAccountInfo.SetPhoto(photo);
            }
            osAccountList.push_back(osAccountInfo);
        }
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo)
{
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) +
                       Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    if (!accountFileOperator_->IsExistFile(path)) {
        ACCOUNT_LOGE("file %{public}s does not exist err", path.c_str());
        if (GetOsAccountFromDatabase("", id, osAccountInfo) == ERR_OK) {
            InsertOsAccount(osAccountInfo);
            return ERR_OK;
        }
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    std::string accountInfoStr;
    if (accountFileOperator_->GetFileContentByPath(path, accountInfoStr) != ERR_OK) {
        ACCOUNT_LOGE("get content from file %{public}s failed!", path.c_str());
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    Json osAccountInfoJson = Json::parse(accountInfoStr, nullptr, false);
    if (osAccountInfoJson.is_discarded()) {
        ACCOUNT_LOGE("parse os account info json data failed");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    osAccountInfo.FromJson(osAccountInfoJson);
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetConstraintsByType(
    const OsAccountType type, std::vector<std::string> &constraints)
{
    int typeInit = static_cast<int>(type);
    return osAccountFileOperator_->GetConstraintsByType(typeInit, constraints);
}

ErrCode OsAccountControlFileManager::UpdateBaseOAConstraints(const std::string& idStr,
    const std::vector<std::string>& ConstraintStr, bool isAdd)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    Json baseOAConstraintsJson;
    ErrCode result = GetBaseOAConstraintsFromFile(baseOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get baseOAConstraints from json file failed!");
        return result;
    }

    if (baseOAConstraintsJson.find(idStr) == baseOAConstraintsJson.end()) {
        if (!isAdd) {
            return ERR_OK;
        }
        baseOAConstraintsJson.emplace(idStr, ConstraintStr);
    } else {
        std::vector<std::string> baseOAConstraints;
        auto jsonEnd = baseOAConstraintsJson.end();
        OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
            baseOAConstraintsJson, jsonEnd, idStr, baseOAConstraints, OHOS::AccountSA::JsonType::ARRAY);
        for (auto it = ConstraintStr.begin(); it != ConstraintStr.end(); it++) {
            if (!isAdd) {
                baseOAConstraints.erase(std::remove(baseOAConstraints.begin(), baseOAConstraints.end(), *it),
                    baseOAConstraints.end());
                continue;
            }
            if (std::find(baseOAConstraints.begin(), baseOAConstraints.end(), *it) == baseOAConstraints.end()) {
                baseOAConstraints.emplace_back(*it);
            }
        }
        baseOAConstraintsJson[idStr] = baseOAConstraints;
    }
    return SaveBaseOAConstraintsToFile(baseOAConstraintsJson);
}

ErrCode OsAccountControlFileManager::UpdateGlobalOAConstraints(
    const std::string& idStr, const std::vector<std::string>& ConstraintStr, bool isAdd)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    Json globalOAConstraintsJson;
    ErrCode result = GetGlobalOAConstraintsFromFile(globalOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get globalOAConstraints from file failed!");
        return result;
    }
    GlobalConstraintsDataOperate(idStr, ConstraintStr, isAdd, globalOAConstraintsJson);
    return SaveGlobalOAConstraintsToFile(globalOAConstraintsJson);
}

void OsAccountControlFileManager::GlobalConstraintsDataOperate(const std::string& idStr,
    const std::vector<std::string>& ConstraintStr, bool isAdd, Json &globalOAConstraintsJson)
{
    std::vector<std::string> globalOAConstraintsList;
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(globalOAConstraintsJson, globalOAConstraintsJson.end(),
        Constants::ALL_GLOBAL_CONSTRAINTS, globalOAConstraintsList, OHOS::AccountSA::JsonType::ARRAY);
    std::vector<std::string> waitForErase;
    for (auto it = ConstraintStr.begin(); it != ConstraintStr.end(); it++) {
        if (!isAdd) {
            if (std::find(globalOAConstraintsList.begin(),
            globalOAConstraintsList.end(), *it) == globalOAConstraintsList.end()) {
                continue;
            }
            std::vector<std::string> constraintSourceList;
            OHOS::AccountSA::GetDataByType<std::vector<std::string>>(globalOAConstraintsJson,
                globalOAConstraintsJson.end(), *it, constraintSourceList, OHOS::AccountSA::JsonType::ARRAY);
            constraintSourceList.erase(std::remove(constraintSourceList.begin(), constraintSourceList.end(), idStr),
                constraintSourceList.end());
            if (constraintSourceList.size() == 0) {
                globalOAConstraintsList.erase(std::remove(globalOAConstraintsList.begin(),
                    globalOAConstraintsList.end(), *it), globalOAConstraintsList.end());
                globalOAConstraintsJson[Constants::ALL_GLOBAL_CONSTRAINTS] = globalOAConstraintsList;
                waitForErase.push_back(*it);
            } else {
                globalOAConstraintsJson[*it] = constraintSourceList;
            }
            continue;
        }
        if (std::find(globalOAConstraintsList.begin(),
            globalOAConstraintsList.end(), *it) != globalOAConstraintsList.end()) {
            std::vector<std::string> constraintSourceList;
            OHOS::AccountSA::GetDataByType<std::vector<std::string>>(globalOAConstraintsJson,
                globalOAConstraintsJson.end(), *it, constraintSourceList, OHOS::AccountSA::JsonType::ARRAY);
            if (std::find(constraintSourceList.begin(),
                constraintSourceList.end(), idStr) == constraintSourceList.end()) {
                constraintSourceList.emplace_back(idStr);
                globalOAConstraintsJson[*it] = constraintSourceList;
            }
            continue;
        }
        std::vector<std::string> constraintSourceList;
        constraintSourceList.emplace_back(idStr);
        globalOAConstraintsList.emplace_back(*it);
        globalOAConstraintsJson.emplace(*it, constraintSourceList);
        globalOAConstraintsJson[Constants::ALL_GLOBAL_CONSTRAINTS] = globalOAConstraintsList;
    }
    for (auto keyStr : waitForErase) {
        globalOAConstraintsJson.erase(keyStr);
    }
}

ErrCode OsAccountControlFileManager::UpdateSpecificOAConstraints(
    const std::string& idStr, const std::string& targetIdStr, const std::vector<std::string>& ConstraintStr, bool isAdd)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    Json specificOAConstraintsJson;
    ErrCode result = GetSpecificOAConstraintsFromFile(specificOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get specificOAConstraints from file failed!");
        return result;
    }
    if (specificOAConstraintsJson.find(targetIdStr) == specificOAConstraintsJson.end()) {
        if (!isAdd) {
            return ERR_OK;
        }
        Json osAccountConstraintsList = Json {
            {Constants::ALL_SPECIFIC_CONSTRAINTS, {}},
        };
        specificOAConstraintsJson.emplace(targetIdStr, osAccountConstraintsList);
    }
    Json userPrivateConstraintsDataJson = specificOAConstraintsJson[targetIdStr];
    SpecificConstraintsDataOperate(idStr, targetIdStr, ConstraintStr, isAdd, userPrivateConstraintsDataJson);
    specificOAConstraintsJson[targetIdStr] = userPrivateConstraintsDataJson;
    return SaveSpecificOAConstraintsToFile(specificOAConstraintsJson);
}

void OsAccountControlFileManager::SpecificConstraintsDataOperate(
    const std::string& idStr, const std::string& targetIdStr, const std::vector<std::string>& ConstraintStr,
    bool isAdd, Json& userPrivateConstraintsDataJson)
{
    std::vector<std::string> specificOAConstraintsList;
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(userPrivateConstraintsDataJson,
        userPrivateConstraintsDataJson.end(), Constants::ALL_SPECIFIC_CONSTRAINTS,
        specificOAConstraintsList, OHOS::AccountSA::JsonType::ARRAY);
    std::vector<std::string> waitForErase;
    for (auto it = ConstraintStr.begin(); it != ConstraintStr.end(); it++) {
        if (!isAdd) {
            if (userPrivateConstraintsDataJson.find(*it) == userPrivateConstraintsDataJson.end()) {
                continue;
            }
            std::vector<std::string> constraintSourceList;
            OHOS::AccountSA::GetDataByType<std::vector<std::string>>(userPrivateConstraintsDataJson,
                userPrivateConstraintsDataJson.end(), *it, constraintSourceList, OHOS::AccountSA::JsonType::ARRAY);
            constraintSourceList.erase(std::remove(constraintSourceList.begin(), constraintSourceList.end(), idStr),
                constraintSourceList.end());
            if (constraintSourceList.size() == 0) {
                specificOAConstraintsList.erase(std::remove(specificOAConstraintsList.begin(),
                    specificOAConstraintsList.end(), *it), specificOAConstraintsList.end());
                userPrivateConstraintsDataJson[Constants::ALL_SPECIFIC_CONSTRAINTS] = specificOAConstraintsList;
                waitForErase.push_back(*it);
            } else {
                userPrivateConstraintsDataJson[*it] = constraintSourceList;
            }
            continue;
        }
        if (std::find(specificOAConstraintsList.begin(),
            specificOAConstraintsList.end(), *it) != specificOAConstraintsList.end()) {
            std::vector<std::string> constraintSourceList;
            OHOS::AccountSA::GetDataByType<std::vector<std::string>>(userPrivateConstraintsDataJson,
            userPrivateConstraintsDataJson.end(), *it, constraintSourceList, OHOS::AccountSA::JsonType::ARRAY);
            if (std::find(constraintSourceList.begin(),
                constraintSourceList.end(), idStr) == constraintSourceList.end()) {
                constraintSourceList.emplace_back(idStr);
                userPrivateConstraintsDataJson[*it] = constraintSourceList;
            }
            continue;
        }
        std::vector<std::string> constraintSourceList;
        constraintSourceList.emplace_back(idStr);
        specificOAConstraintsList.emplace_back(*it);
        userPrivateConstraintsDataJson.emplace(*it, constraintSourceList);
        userPrivateConstraintsDataJson[Constants::ALL_SPECIFIC_CONSTRAINTS] = specificOAConstraintsList;
    }
    for (auto keyStr : waitForErase) {
        userPrivateConstraintsDataJson.erase(keyStr);
    }
}

ErrCode OsAccountControlFileManager::RemoveOAConstraintsInfo(const int32_t id)
{
    ErrCode errCode = RemoveOABaseConstraintsInfo(id);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("remove os account %{public}d base constraints info failed!", id);
        return errCode;
    }
    errCode = RemoveOAGlobalConstraintsInfo(id);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("remove os account %{public}d global constraints info failed!", id);
        return errCode;
    }
    errCode = RemoveOASpecificConstraintsInfo(id);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("remove os account %{public}d specific constraints info failed!", id);
        return errCode;
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::RemoveOABaseConstraintsInfo(const int32_t id)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    Json baseOAConstraintsJson;
    ErrCode result = GetBaseOAConstraintsFromFile(baseOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get baseOAConstraints from file failed!");
        return result;
    }
    baseOAConstraintsJson.erase(std::to_string(id));
    result = SaveBaseOAConstraintsToFile(baseOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SaveBaseOAConstraintsToFile failed!");
        return result;
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::RemoveOAGlobalConstraintsInfo(const int32_t id)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    Json globalOAConstraintsJson;
    ErrCode result = GetGlobalOAConstraintsFromFile(globalOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get globalOAConstraints from file failed!");
        return result;
    }
    std::vector<std::string> waitForErase;
    for (auto it = globalOAConstraintsJson.begin(); it != globalOAConstraintsJson.end(); it++) {
        if (it.key() != Constants::ALL_GLOBAL_CONSTRAINTS && it.key() != Constants::DEVICE_OWNER_ID) {
            std::vector<std::string> sourceList;
            OHOS::AccountSA::GetDataByType<std::vector<std::string>>(globalOAConstraintsJson,
                globalOAConstraintsJson.end(),
                it.key(),
                sourceList,
                OHOS::AccountSA::JsonType::ARRAY);
            sourceList.erase(std::remove(sourceList.begin(), sourceList.end(), std::to_string(id)), sourceList.end());
            if (sourceList.size() == 0) {
                std::vector<std::string> allGlobalConstraints;
                OHOS::AccountSA::GetDataByType<std::vector<std::string>>(globalOAConstraintsJson,
                    globalOAConstraintsJson.end(),
                    Constants::ALL_GLOBAL_CONSTRAINTS,
                    allGlobalConstraints,
                    OHOS::AccountSA::JsonType::ARRAY);
                allGlobalConstraints.erase(std::remove(allGlobalConstraints.begin(),
                    allGlobalConstraints.end(), it.key()), allGlobalConstraints.end());
                globalOAConstraintsJson[Constants::ALL_GLOBAL_CONSTRAINTS] = allGlobalConstraints;
                waitForErase.push_back(it.key());
            } else {
                globalOAConstraintsJson[it.key()] = sourceList;
            }
        }
    }
    for (auto keyStr : waitForErase) {
        globalOAConstraintsJson.erase(keyStr);
    }
    return SaveGlobalOAConstraintsToFile(globalOAConstraintsJson);
}

ErrCode OsAccountControlFileManager::RemoveOASpecificConstraintsInfo(const int32_t id)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    Json specificOAConstraintsJson;
    ErrCode result = GetSpecificOAConstraintsFromFile(specificOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get specificOAConstraints from file failed!");
        return result;
    }
    if (specificOAConstraintsJson.find(std::to_string(id)) != specificOAConstraintsJson.end()) {
        specificOAConstraintsJson.erase(std::to_string(id));
    }
    for (auto it = specificOAConstraintsJson.begin(); it != specificOAConstraintsJson.end(); it++) {
        std::vector<std::string> waitForErase;
        Json userPrivateConstraintsJson;
        OHOS::AccountSA::GetDataByType<Json>(specificOAConstraintsJson, specificOAConstraintsJson.end(),
            it.key(), userPrivateConstraintsJson, OHOS::AccountSA::JsonType::OBJECT);
        std::vector<std::string> allSpecificConstraints;
        OHOS::AccountSA::GetDataByType<std::vector<std::string>>(userPrivateConstraintsJson,
            userPrivateConstraintsJson.end(), Constants::ALL_SPECIFIC_CONSTRAINTS,
            allSpecificConstraints, OHOS::AccountSA::JsonType::ARRAY);
        if (allSpecificConstraints.size() == 0) {
            continue;
        }
        for (auto item = userPrivateConstraintsJson.begin(); item != userPrivateConstraintsJson.end(); item++) {
            if (item.key() == Constants::ALL_SPECIFIC_CONSTRAINTS) {
                continue;
            }
            std::vector<std::string> sourceList;
            OHOS::AccountSA::GetDataByType<std::vector<std::string>>(userPrivateConstraintsJson,
                userPrivateConstraintsJson.end(), item.key(), sourceList, OHOS::AccountSA::JsonType::ARRAY);
            sourceList.erase(std::remove(sourceList.begin(),
                sourceList.end(), std::to_string(id)), sourceList.end());
            if (sourceList.size() == 0) {
                allSpecificConstraints.erase(std::remove(allSpecificConstraints.begin(),
                    allSpecificConstraints.end(), item.key()), allSpecificConstraints.end());
                userPrivateConstraintsJson[Constants::ALL_SPECIFIC_CONSTRAINTS] = allSpecificConstraints;
                waitForErase.push_back(item.key());
            } else {
                userPrivateConstraintsJson[item.key()] = sourceList;
            }
        }
        for (auto keyStr : waitForErase) {
            userPrivateConstraintsJson.erase(keyStr);
        }
        specificOAConstraintsJson[it.key()] = userPrivateConstraintsJson;
    }
    return SaveSpecificOAConstraintsToFile(specificOAConstraintsJson);
}

ErrCode OsAccountControlFileManager::UpdateAccountList(const std::string& idStr, bool isAdd)
{
    Json accountListJson;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get account list failed!");
        return result;
    }

    std::vector<std::string> accountIdList;
    auto jsonEnd = accountListJson.end();
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        accountListJson, jsonEnd, Constants::ACCOUNT_LIST, accountIdList, OHOS::AccountSA::JsonType::ARRAY);

    if (isAdd) {
        // check repeat
        if (std::find(accountIdList.begin(), accountIdList.end(), idStr) != accountIdList.end()) {
            return ERR_OK;  // already exist, no need to add.
        }
        accountIdList.emplace_back(idStr);
    } else {
        accountIdList.erase(std::remove(accountIdList.begin(), accountIdList.end(), idStr), accountIdList.end());
    }
    accountListJson[Constants::ACCOUNT_LIST] = accountIdList;
    accountListJson[Constants::COUNT_ACCOUNT_NUM] = accountIdList.size();
    return SaveAccountListToFileAndDataBase(accountListJson);
}

ErrCode OsAccountControlFileManager::UpdateAccountIndex(const OsAccountInfo &osAccountInfo, const bool isDelete)
{
    // private type account not write index to index file, don't check name in ValidateOsAccount
    if (osAccountInfo.GetType() == OsAccountType::PRIVATE) {
        return ERR_OK;
    }
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    Json accountIndexJson;
    ErrCode result = GetAccountIndexFromFile(accountIndexJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get account index failed!");
        return result;
    }
    std::string localIdStr = std::to_string(osAccountInfo.GetLocalId());
    if (isDelete) {
        accountIndexJson.erase(localIdStr);
    } else {
        Json accountBaseInfo;
        accountBaseInfo[Constants::LOCAL_NAME] = osAccountInfo.GetLocalName();
        accountBaseInfo[Constants::SHORT_NAME] = osAccountInfo.GetShortName();
        accountIndexJson[localIdStr] = accountBaseInfo;
    }
    std::string lastAccountIndexStr = accountIndexJson.dump();
    result = accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_INDEX_JSON_PATH, lastAccountIndexStr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to input account index info to file!");
        return result;
    }
    accountFileWatcherMgr_.AddAccountInfoDigest(lastAccountIndexStr, Constants::ACCOUNT_INDEX_JSON_PATH);
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::RemoveAccountIndex(const int32_t id)
{
    Json accountIndexJson;
    ErrCode result = GetAccountIndexFromFile(accountIndexJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get account index failed!");
        return result;
    }
    std::string localIdStr = std::to_string(id);
    accountIndexJson.erase(localIdStr);
    std::string lastAccountIndexStr = accountIndexJson.dump();
    result = accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_INDEX_JSON_PATH, lastAccountIndexStr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to input account index info to file!");
        return result;
    }
    accountFileWatcherMgr_.AddAccountInfoDigest(lastAccountIndexStr, Constants::ACCOUNT_INDEX_JSON_PATH);
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::InsertOsAccount(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("enter");
    if (osAccountInfo.GetLocalId() < Constants::ADMIN_LOCAL_ID ||
        osAccountInfo.GetLocalId() > Constants::MAX_USER_ID) {
        ACCOUNT_LOGE("error id %{public}d cannot insert", osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_CONTROL_ID_CANNOT_CREATE_ERROR;
    }

    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + osAccountInfo.GetPrimeKey() +
                       Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    if (accountFileOperator_->IsExistFile(path) && accountFileOperator_->IsJsonFormat(path)) {
        ACCOUNT_LOGE("OsAccountControlFileManagerInsertOsAccountControlFileManagerCreateAccountDir ERR");
        return ERR_OSACCOUNT_SERVICE_CONTROL_INSERT_FILE_EXISTS_ERROR;
    }

    std::string accountInfoStr = osAccountInfo.ToString();
    if (accountInfoStr.empty()) {
        ACCOUNT_LOGE("os account info is empty! maybe some illegal characters caused exception!");
        return ERR_OSACCOUNT_SERVICE_ACCOUNT_INFO_EMPTY_ERROR;
    }
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(path, accountInfoStr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("InputFileByPathAndContent failed! path %{public}s.", path.c_str());
        return result;
    }
#ifdef HAS_KV_STORE_PART
    osAccountDataBaseOperator_->InsertOsAccountIntoDataBase(osAccountInfo);
#endif

    if (osAccountInfo.GetLocalId() >= Constants::START_USER_ID) {
        accountFileWatcherMgr_.AddAccountInfoDigest(accountInfoStr, path);
        accountFileWatcherMgr_.AddFileWatcher(osAccountInfo.GetLocalId(), eventCallbackFunc_);
        return UpdateAccountList(osAccountInfo.GetPrimeKey(), true);
    }
    ACCOUNT_LOGI("end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::DelOsAccount(const int id)
{
    ACCOUNT_LOGD("enter");
    if (id <= Constants::START_USER_ID || id > Constants::MAX_USER_ID) {
        ACCOUNT_LOGE("invalid input id %{public}d to delete!", id);
        return ERR_OSACCOUNT_SERVICE_CONTROL_CANNOT_DELETE_ID_ERROR;
    }
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id);
    ErrCode result = accountFileOperator_->DeleteDirOrFile(path);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("DeleteDirOrFile failed! path %{public}s.", path.c_str());
        return result;
    }
#ifdef HAS_KV_STORE_PART
    osAccountDataBaseOperator_->DelOsAccountFromDatabase(id);
#endif
    path += Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    accountFileWatcherMgr_.DeleteAccountInfoDigest(path);
    std::string distributedDataPath =
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) + DISTRIBUTED_ACCOUNT_FILE_NAME;
    accountFileWatcherMgr_.DeleteAccountInfoDigest(distributedDataPath);
    RemoveAccountIndex(id);
    return UpdateAccountList(std::to_string(id), false);
}


ErrCode OsAccountControlFileManager::UpdateOsAccount(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGD("start");
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + osAccountInfo.GetPrimeKey() +
                       Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    if (!accountFileOperator_->IsExistFile(path)) {
        ACCOUNT_LOGE("path %{public}s does not exist!", path.c_str());
        return ERR_OSACCOUNT_SERVICE_CONTROL_UPDATE_FILE_NOT_EXISTS_ERROR;
    }

    std::string accountInfoStr = osAccountInfo.ToString();
    if (accountInfoStr.empty()) {
        ACCOUNT_LOGE("account info str is empty!");
        return ERR_OSACCOUNT_SERVICE_ACCOUNT_INFO_EMPTY_ERROR;
    }
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(path, accountInfoStr);
    if (result != ERR_OK) {
        return result;
    }

#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    // update in database
    if (osAccountInfo.GetLocalId() >= Constants::START_USER_ID) {
        osAccountDataBaseOperator_->UpdateOsAccountInDatabase(osAccountInfo);
    }
#else  // DISTRIBUTED_FEATURE_ENABLED
    ACCOUNT_LOGI("No distributed feature!");
#endif // DISTRIBUTED_FEATURE_ENABLED

    accountFileWatcherMgr_.AddAccountInfoDigest(accountInfoStr, path);
    ACCOUNT_LOGD("end");
    return ERR_OK;
}

bool AccountExistsWithSerialNumber(const std::vector<OsAccountInfo>& osAccountInfos, int serialNumber)
{
    const auto targetSerialNumber = Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN * Constants::CARRY_NUM + serialNumber;
    return std::any_of(osAccountInfos.begin(), osAccountInfos.end(),
        [&targetSerialNumber](const OsAccountInfo& accountInfo) {
        return accountInfo.GetSerialNumber() == targetSerialNumber;
    });
}

ErrCode OsAccountControlFileManager::GetSerialNumber(int64_t &serialNumber)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    Json accountListJson;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetSerialNumber get accountList error");
        return result;
    }
    OHOS::AccountSA::GetDataByType<int64_t>(accountListJson, accountListJson.end(), Constants::SERIAL_NUMBER_NUM,
        serialNumber, OHOS::AccountSA::JsonType::NUMBER);
    if (serialNumber == Constants::CARRY_NUM) {
        accountListJson[Constants::IS_SERIAL_NUMBER_FULL] = true;
        serialNumber = Constants::SERIAL_NUMBER_NUM_START;
    }
    bool isSerialNumberFull = false;
    OHOS::AccountSA::GetDataByType<bool>(accountListJson, accountListJson.end(), Constants::IS_SERIAL_NUMBER_FULL,
        isSerialNumberFull, OHOS::AccountSA::JsonType::BOOLEAN);
    if (isSerialNumberFull) {
        std::vector<OsAccountInfo> osAccountInfos;
        result = GetOsAccountList(osAccountInfos);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("GetSerialNumber get accountList error");
            return result;
        }
        while (serialNumber < Constants::CARRY_NUM) {
            bool exists = false;
            exists = AccountExistsWithSerialNumber(osAccountInfos, serialNumber);
            if (!exists) {
                break;
            }
            serialNumber++;
            serialNumber = (serialNumber == Constants::CARRY_NUM) ? Constants::SERIAL_NUMBER_NUM_START : serialNumber;
        }
    }
    accountListJson[Constants::SERIAL_NUMBER_NUM] = serialNumber + 1;
    result = SaveAccountListToFileAndDataBase(accountListJson);
    if (result != ERR_OK) {
        return result;
    }
    serialNumber = serialNumber + Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN * Constants::CARRY_NUM;
    return ERR_OK;
}

int OsAccountControlFileManager::GetNextLocalId(const std::vector<std::string> &accountIdList)
{
    do {
        if (nextLocalId_ > MAX_LOCAL_ID) {
            nextLocalId_ = Constants::START_USER_ID;
        }
        if (std::find(accountIdList.begin(), accountIdList.end(), std::to_string(nextLocalId_)) ==
            accountIdList.end()) {
            break;
        }
        nextLocalId_++;
    } while (true);
    return nextLocalId_;
}

ErrCode OsAccountControlFileManager::GetAllowCreateId(int &id)
{
    Json accountListJson;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetAllowCreateId get accountList error");
        return result;
    }
    auto jsonEnd = accountListJson.end();
    std::vector<std::string> accountIdList;
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        accountListJson, jsonEnd, Constants::ACCOUNT_LIST, accountIdList, OHOS::AccountSA::JsonType::ARRAY);
    std::lock_guard<std::mutex> lock(operatingIdMutex_);
    id = GetNextLocalId(accountIdList);
    nextLocalId_++;
    return ERR_OK;
}


ErrCode OsAccountControlFileManager::GetAccountListFromFile(Json &accountListJson)
{
    ACCOUNT_LOGD("enter");
    accountListJson.clear();
    std::string accountList;
    std::lock_guard<std::mutex> lock(accountListFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(Constants::ACCOUNT_LIST_FILE_JSON_PATH,
        accountList);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
        return errCode;
    }
    accountListJson = Json::parse(accountList, nullptr, false);
    if (accountListJson.is_discarded()) {
#ifdef HAS_KV_STORE_PART
        return osAccountDataBaseOperator_->GetAccountListFromStoreID(OS_ACCOUNT_STORE_ID, accountListJson);
#else
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
#endif
    }
    ACCOUNT_LOGD("end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetAccountIndexFromFile(Json &accountIndexJson)
{
    accountIndexJson.clear();
    std::string accountIndex;
    if (!accountFileOperator_->IsJsonFileReady(Constants::ACCOUNT_INDEX_JSON_PATH)) {
        ErrCode result = GetAccountIndexInfo(accountIndex);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("GetAccountIndexInfo error code %{public}d.", result);
            return result;
        }
    } else {
        ErrCode errCode = accountFileOperator_->GetFileContentByPath(Constants::ACCOUNT_INDEX_JSON_PATH, accountIndex);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
            return errCode;
        }
    }
    accountIndexJson = Json::parse(accountIndex, nullptr, false);
    if (accountIndexJson.is_discarded()) {
        ACCOUNT_LOGE("parse os account info json data failed");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetAccountIndexInfo(std::string &accountIndexInfo)
{
    std::vector<OsAccountInfo> osAccountInfos;
    ErrCode result = GetOsAccountList(osAccountInfos);
    if (result != ERR_OK) {
        return result;
    }
    Json accountIndexJson;
    for (auto account = osAccountInfos.begin(); account != osAccountInfos.end(); account++) {
        // private account don't check name
        if (account->GetType() == OsAccountType::PRIVATE) {
            continue;
        }
        std::string localIdStr = std::to_string(account->GetLocalId());
        Json accountIndexElement;
        accountIndexElement[Constants::LOCAL_NAME] = account->GetLocalName();
        accountIndexElement[Constants::SHORT_NAME] = account->GetShortName();
        accountIndexJson[localIdStr] = accountIndexElement;
    }
    accountIndexInfo = accountIndexJson.dump();
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetBaseOAConstraintsFromFile(Json &baseOAConstraintsJson)
{
    baseOAConstraintsJson.clear();
    std::string baseOAConstraints;
    std::lock_guard<std::mutex> lock(baseOAConstraintsFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(
        Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH, baseOAConstraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
        return errCode;
    }
    baseOAConstraintsJson = Json::parse(baseOAConstraints, nullptr, false);
    if (baseOAConstraintsJson.is_discarded() || !baseOAConstraintsJson.is_object()) {
        ACCOUNT_LOGE("base constraints json data parse failed code.");
        return errCode;
    }

    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetGlobalOAConstraintsFromFile(Json &globalOAConstraintsJson)
{
    globalOAConstraintsJson.clear();
    std::string globalOAConstraints;
    std::lock_guard<std::mutex> lock(globalOAConstraintsFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(
        Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH, globalOAConstraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
        return errCode;
    }
    globalOAConstraintsJson = Json::parse(globalOAConstraints, nullptr, false);
    if (globalOAConstraintsJson.is_discarded() || !globalOAConstraintsJson.is_object()) {
        ACCOUNT_LOGE("global constraints json data parse failed code.");
        return errCode;
    }

    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetSpecificOAConstraintsFromFile(Json &specificOAConstraintsJson)
{
    specificOAConstraintsJson.clear();
    std::string specificOAConstraints;
    std::lock_guard<std::mutex> lock(specificOAConstraintsFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(
        Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH, specificOAConstraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
        return errCode;
    }
    specificOAConstraintsJson = Json::parse(specificOAConstraints, nullptr, false);
    if (specificOAConstraintsJson.is_discarded() || !specificOAConstraintsJson.is_object()) {
        ACCOUNT_LOGE("specific constraints json data parse failed code.");
        return errCode;
    }

    return ERR_OK;
}

ErrCode OsAccountControlFileManager::IsFromBaseOAConstraintsList(
    const int32_t id, const std::string constraint, bool &isExist)
{
    isExist = false;
    std::vector<std::string> constraintsList;
    std::lock_guard<std::mutex> lock(baseOAConstraintsFileLock_);
    ErrCode errCode = osAccountFileOperator_->GetBaseOAConstraintsList(id, constraintsList);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetBaseOAConstraintsList failed! error code %{public}d.", errCode);
        return errCode;
    }

    if (std::find(constraintsList.begin(), constraintsList.end(), constraint) != constraintsList.end()) {
        isExist = true;
    }

    return ERR_OK;
}

ErrCode OsAccountControlFileManager::IsFromGlobalOAConstraintsList(const int32_t id, const int32_t deviceOwnerId,
    const std::string constraint, std::vector<ConstraintSourceTypeInfo> &globalSourceList)
{
    globalSourceList.clear();
    std::vector<std::string> constraintsList;
    ErrCode errCode = ERR_OK;
    {
        std::lock_guard<std::mutex> lock(globalOAConstraintsFileLock_);
        errCode = osAccountFileOperator_->GetGlobalOAConstraintsList(constraintsList);
    }
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetGlobalOAConstraintsList failed! error code %{public}d.", errCode);
        return errCode;
    }
    if (constraintsList.size() == 0) {
        return ERR_OK;
    }
    if (std::find(constraintsList.begin(), constraintsList.end(), constraint) != constraintsList.end()) {
        Json globalOAConstraintsJson;
        errCode = GetGlobalOAConstraintsFromFile(globalOAConstraintsJson);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("get globalOAConstraints from file failed!");
            return errCode;
        }
        std::vector<std::string> globalOAConstraintsList;
        OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
            globalOAConstraintsJson,
            globalOAConstraintsJson.end(),
            constraint,
            globalOAConstraintsList,
            OHOS::AccountSA::JsonType::ARRAY);
        ConstraintSourceTypeInfo constraintSourceTypeInfo;
        for (auto it = globalOAConstraintsList.begin(); it != globalOAConstraintsList.end(); it++) {
            if (stoi(*it) == deviceOwnerId) {
                constraintSourceTypeInfo.localId = stoi(*it);
                constraintSourceTypeInfo.typeInfo = ConstraintSourceType::CONSTRAINT_TYPE_DEVICE_OWNER;
                globalSourceList.push_back(constraintSourceTypeInfo);
            } else {
                constraintSourceTypeInfo.localId = stoi(*it);
                constraintSourceTypeInfo.typeInfo = ConstraintSourceType::CONSTRAINT_TYPE_PROFILE_OWNER;
                globalSourceList.push_back(constraintSourceTypeInfo);
            }
        }
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::IsFromSpecificOAConstraintsList(const int32_t id, const int32_t deviceOwnerId,
    const std::string constraint, std::vector<ConstraintSourceTypeInfo> &specificSourceList)
{
    specificSourceList.clear();
    std::vector<std::string> constraintsList;
    ErrCode errCode = ERR_OK;
    {
        std::lock_guard<std::mutex> lock(specificOAConstraintsFileLock_);
        errCode = osAccountFileOperator_->GetSpecificOAConstraintsList(id, constraintsList);
    }
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetSpecificOAConstraintsList failed! error code %{public}d.", errCode);
        return errCode;
    }

    if (std::find(constraintsList.begin(), constraintsList.end(), constraint) != constraintsList.end()) {
        Json specificOAConstraintsJson;
        errCode = GetSpecificOAConstraintsFromFile(specificOAConstraintsJson);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("get specificOAConstraints from file failed!");
            return errCode;
        }
        Json specificOAConstraintsInfo;
        OHOS::AccountSA::GetDataByType<Json>(specificOAConstraintsJson, specificOAConstraintsJson.end(),
            std::to_string(id), specificOAConstraintsInfo, OHOS::AccountSA::JsonType::OBJECT);
        std::vector<std::string> specificConstraintSource;
        OHOS::AccountSA::GetDataByType<std::vector<std::string>>(specificOAConstraintsInfo,
            specificOAConstraintsInfo.end(), constraint,
            specificConstraintSource, OHOS::AccountSA::JsonType::ARRAY);
        ConstraintSourceTypeInfo constraintSourceTypeInfo;
        for (auto it = specificConstraintSource.begin(); it != specificConstraintSource.end(); it++) {
            if (stoi(*it) == deviceOwnerId) {
                constraintSourceTypeInfo.localId =stoi(*it);
                constraintSourceTypeInfo.typeInfo =  ConstraintSourceType::CONSTRAINT_TYPE_DEVICE_OWNER;
                specificSourceList.push_back(constraintSourceTypeInfo);
            } else {
                constraintSourceTypeInfo.localId =stoi(*it);
                constraintSourceTypeInfo.typeInfo =  ConstraintSourceType::CONSTRAINT_TYPE_PROFILE_OWNER;
                specificSourceList.push_back(constraintSourceTypeInfo);
            }
        }
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveAccountListToFile(const Json &accountListJson)
{
    std::lock_guard<std::mutex> lock(accountListFileLock_);
    ErrCode result =
        accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_LIST_FILE_JSON_PATH, accountListJson.dump());
    if (result != ERR_OK) {
        ACCOUNT_LOGE("cannot save save account list file content!");
        return result;
    }
    accountFileWatcherMgr_.AddAccountInfoDigest(accountListJson.dump(), Constants::ACCOUNT_LIST_FILE_JSON_PATH);
    ACCOUNT_LOGD("save account list file succeed!");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveBaseOAConstraintsToFile(const Json &baseOAConstraints)
{
    std::lock_guard<std::mutex> lock(baseOAConstraintsFileLock_);
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(
        Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH, baseOAConstraints.dump());
    if (result != ERR_OK) {
        ACCOUNT_LOGE("cannot save base osaccount constraints file content!");
        return result;
    }
    accountFileWatcherMgr_.AddAccountInfoDigest(
        baseOAConstraints.dump(), Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH);
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveGlobalOAConstraintsToFile(const Json &globalOAConstraints)
{
    std::lock_guard<std::mutex> lock(globalOAConstraintsFileLock_);
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(
        Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH, globalOAConstraints.dump());
    if (result != ERR_OK) {
        ACCOUNT_LOGE("cannot save global osAccount constraints file content!");
        return result;
    }
    accountFileWatcherMgr_.AddAccountInfoDigest(
        globalOAConstraints.dump(), Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH);
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveSpecificOAConstraintsToFile(const Json &specificOAConstraints)
{
    std::lock_guard<std::mutex> lock(specificOAConstraintsFileLock_);
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(
        Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH, specificOAConstraints.dump());
    if (result != ERR_OK) {
        ACCOUNT_LOGE("cannot save specific osAccount constraints file content!");
        return result;
    }
    accountFileWatcherMgr_.AddAccountInfoDigest(
        specificOAConstraints.dump(), Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH);
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetDeviceOwnerId(int &deviceOwnerId)
{
    Json globalOAConstraintsJson;
    ErrCode result = GetGlobalOAConstraintsFromFile(globalOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get global json data from file failed!");
        return result;
    }
    OHOS::AccountSA::GetDataByType<int>(
        globalOAConstraintsJson,
        globalOAConstraintsJson.end(),
        Constants::DEVICE_OWNER_ID,
        deviceOwnerId,
        OHOS::AccountSA::JsonType::NUMBER);
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::UpdateDeviceOwnerId(const int deviceOwnerId)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    Json globalOAConstraintsJson;
    ErrCode result = GetGlobalOAConstraintsFromFile(globalOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get global json data from file failed!");
        return result;
    }
    globalOAConstraintsJson[Constants::DEVICE_OWNER_ID] = deviceOwnerId;
    return SaveGlobalOAConstraintsToFile(globalOAConstraintsJson);
}

ErrCode OsAccountControlFileManager::SetDefaultActivatedOsAccount(const int32_t id)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    Json accountListJson;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get account list failed!");
        return result;
    }

    accountListJson[DEFAULT_ACTIVATED_ACCOUNT_ID] = id;
    return SaveAccountListToFileAndDataBase(accountListJson);
}

ErrCode OsAccountControlFileManager::GetDefaultActivatedOsAccount(int32_t &id)
{
    Json accountListJsonData;
    ErrCode result = GetAccountListFromFile(accountListJsonData);
    if (result != ERR_OK) {
        return result;
    }
    OHOS::AccountSA::GetDataByType<int>(accountListJsonData,
        accountListJsonData.end(),
        DEFAULT_ACTIVATED_ACCOUNT_ID,
        id,
        OHOS::AccountSA::JsonType::NUMBER);
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveAccountListToFileAndDataBase(const Json &accountListJson)
{
#ifdef HAS_KV_STORE_PART
    osAccountDataBaseOperator_->UpdateOsAccountIDListInDatabase(accountListJson);
#endif
    return SaveAccountListToFile(accountListJson);
}

ErrCode OsAccountControlFileManager::IsOsAccountExists(const int id, bool &isExists)
{
    isExists = false;
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) +
                       Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    // check exist
    if (!accountFileOperator_->IsExistFile(path)) {
        ACCOUNT_LOGI("IsOsAccountExists path %{public}s does not exist!", path.c_str());
        return ERR_OK;
    }

    // check format
    if (!accountFileOperator_->IsJsonFormat(path)) {
        ACCOUNT_LOGI("IsOsAccountExists path %{public}s wrong format!", path.c_str());
        return ERR_OK;
    }

    isExists = true;
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetPhotoById(const int id, std::string &photo)
{
    if ((photo != Constants::USER_PHOTO_FILE_JPG_NAME) && (photo != Constants::USER_PHOTO_FILE_PNG_NAME)
        && (photo != Constants::USER_PHOTO_FILE_TXT_NAME)) {
        return ERR_OK;
    }
    std::string path =
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) + Constants::PATH_SEPARATOR + photo;
    std::string byteStr = "";
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(path, byteStr);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetPhotoById cannot find photo file error");
        return errCode;
    }
    if (photo == Constants::USER_PHOTO_FILE_TXT_NAME) {
        photo = byteStr;
        return ERR_OK;
    }
    // USER_PHOTO_FILE_JPG_NAME and USER_PHOTO_FILE_PNG_NAME are compatible with previous data
    if (photo == Constants::USER_PHOTO_FILE_JPG_NAME) {
        photo =
            Constants::USER_PHOTO_BASE_JPG_HEAD + osAccountPhotoOperator_->EnCode(byteStr.c_str(), byteStr.length());
    } else {
        photo =
            Constants::USER_PHOTO_BASE_PNG_HEAD + osAccountPhotoOperator_->EnCode(byteStr.c_str(), byteStr.length());
    }
    std::string substr = "\r\n";
    while (photo.find(substr) != std::string::npos) {
        photo.erase(photo.find(substr), substr.length());
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SetPhotoById(const int id, const std::string &photo)
{
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id)
        + Constants::PATH_SEPARATOR + Constants::USER_PHOTO_FILE_TXT_NAME;
    ErrCode errCode = accountFileOperator_->InputFileByPathAndContent(path, photo);
    if (errCode != ERR_OK) {
        return errCode;
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetGlobalOAConstraintsList(std::vector<std::string> &constraintsList)
{
    std::lock_guard<std::mutex> lock(globalOAConstraintsFileLock_);
    return osAccountFileOperator_->GetGlobalOAConstraintsList(constraintsList);
}

ErrCode OsAccountControlFileManager::GetSpecificOAConstraintsList(
    const int32_t id, std::vector<std::string> &constraintsList)
{
    std::lock_guard<std::mutex> lock(specificOAConstraintsFileLock_);
    return osAccountFileOperator_->GetSpecificOAConstraintsList(id, constraintsList);
}

ErrCode OsAccountControlFileManager::GetIsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    return osAccountFileOperator_->GetIsMultiOsAccountEnable(isMultiOsAccountEnable);
}
ErrCode OsAccountControlFileManager::CheckConstraintsList(
    const std::vector<std::string> &constraints, bool &isExists, bool &isOverSize)
{
    return osAccountFileOperator_->CheckConstraintsList(constraints, isExists, isOverSize);
}

ErrCode OsAccountControlFileManager::IsAllowedCreateAdmin(bool &isAllowedCreateAdmin)
{
    return osAccountFileOperator_->IsAllowedCreateAdmin(isAllowedCreateAdmin);
}

ErrCode OsAccountControlFileManager::GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
    int &createdOsAccountNum)
{
#ifdef HAS_KV_STORE_PART
    return osAccountDataBaseOperator_->GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
#else
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
#endif
}

ErrCode OsAccountControlFileManager::GetSerialNumberFromDatabase(const std::string& storeID,
    int64_t &serialNumber)
{
#ifdef HAS_KV_STORE_PART
    return osAccountDataBaseOperator_->GetSerialNumberFromDatabase(storeID, serialNumber);
#else
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
#endif
}

ErrCode OsAccountControlFileManager::GetMaxAllowCreateIdFromDatabase(const std::string& storeID,
    int &id)
{
#ifdef HAS_KV_STORE_PART
    return osAccountDataBaseOperator_->GetMaxAllowCreateIdFromDatabase(storeID, id);
#else
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
#endif
}

ErrCode OsAccountControlFileManager::GetOsAccountFromDatabase(const std::string& storeID,
    const int id, OsAccountInfo &osAccountInfo)
{
#ifdef HAS_KV_STORE_PART
    return osAccountDataBaseOperator_->GetOsAccountFromDatabase(storeID, id, osAccountInfo);
#else
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
#endif
}

ErrCode OsAccountControlFileManager::GetOsAccountListFromDatabase(const std::string& storeID,
    std::vector<OsAccountInfo> &osAccountList)
{
#ifdef HAS_KV_STORE_PART
    return osAccountDataBaseOperator_->GetOsAccountListFromDatabase(storeID, osAccountList);
#else
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
#endif
}
}  // namespace AccountSA
}  // namespace OHOS
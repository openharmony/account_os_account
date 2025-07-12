/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#ifdef HAS_CONFIG_POLICY_PART
#include "config_policy_utils.h"
#endif
#include "string_ex.h"
#include "os_account_constants.h"
#include "os_account_info_json_parser.h"
#include "parameters.h"

namespace OHOS {
namespace AccountSA {
namespace {
const char DEFAULT_ACTIVATED_ACCOUNT_ID[] = "DefaultActivatedAccountID";
const std::string OS_ACCOUNT_STORE_ID = "os_account_info";
#ifdef ENABLE_FILE_WATCHER
constexpr uint32_t ALG_COMMON_SIZE = 32;
const char DISTRIBUTED_ACCOUNT_FILE_NAME[] = "/account.json";
#endif // ENABLE_FILE_WATCHER
#ifndef ACCOUNT_TEST
const std::string ACCOUNT_CFG_DIR_ROOT_PATH = "/data/service/el1/public/account/";
const std::string DEFAULT_OS_ACCOUNT_CONFIG_FILE = "/system/etc/account/os_account_config.json";
#else
const std::string ACCOUNT_CFG_DIR_ROOT_PATH = "/data/service/el1/public/account/test/";
const std::string DEFAULT_OS_ACCOUNT_CONFIG_FILE = ACCOUNT_CFG_DIR_ROOT_PATH + "os_account_config.json";
#endif // ACCOUNT_TEST
#ifdef HAS_CONFIG_POLICY_PART
const char OS_ACCOUNT_CONFIG_FILE[] = "etc/os_account/os_account_config.json";
#endif // HAS_CONFIG_POLICY_PART
const char MAX_OS_ACCOUNT_NUM[] = "maxOsAccountNum";
const char MAX_LOGGED_IN_OS_ACCOUNT_NUM[] = "maxLoggedInOsAccountNum";
#ifdef ENABLE_U1_ACCOUNT
const char SYSTEM_ACCOUNTS_CONFIG[] = "systemAccounts";
const char U1_CONFIG[] = "1";
const char SYSTEM_ACCOUNT_TYPE[] = "type";
const char SYSTEM_ACCOUNT_NAME[] = "name";
const char SYSTEM_ACCOUNT_BLOCK_BOOT[] = "canBlockBoot";
#endif // ENABLE_U1_ACCOUNT
const char DEVELOPER_MODE_STATE[] = "const.security.developermode.state";
const char DEVELOPER_MODE[] = "developerMode";
const char USER_PHOTO_FILE_PNG_NAME[] = "fase.png";
const char USER_PHOTO_FILE_JPG_NAME[] = "fase.jpg";
const char USER_PHOTO_BASE_JPG_HEAD[] = "data:image/jpeg;base64,";
const char USER_PHOTO_BASE_PNG_HEAD[] = "data:image/png;base64,";
const char START_USER_STRING_ID[] = "100";
const char DEVICE_OWNER_ID[] = "deviceOwnerId";
const char NEXT_LOCAL_ID[] = "NextLocalId";
const char IS_SERIAL_NUMBER_FULL[] = "isSerialNumberFull";
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

#ifdef ENABLE_U1_ACCOUNT
void OsAccountControlFileManager::GetU1Config(const CJsonUnique &configJson, OsAccountConfig &config)
{
    CJson *systemAccountsJson = nullptr;
    bool ret = GetDataByType<CJson *>(configJson, SYSTEM_ACCOUNTS_CONFIG, systemAccountsJson);
    if (!ret) {
        ACCOUNT_LOGE("Failed to parse %{public}s", SYSTEM_ACCOUNTS_CONFIG);
        return;
    }
    CJson *u1Json = nullptr;
    ret = GetDataByType<CJson *>(systemAccountsJson, U1_CONFIG, u1Json);
    if (!ret) {
        ACCOUNT_LOGE("Failed to parse %{public}s", U1_CONFIG);
        return;
    }
    config.isU1Enable = true;
    int32_t type = -1;
    GetDataByType<std::int32_t>(u1Json, SYSTEM_ACCOUNT_TYPE, type);
    if (type != static_cast<int32_t>(OsAccountType::ADMIN) &&
        type != static_cast<int32_t>(OsAccountType::NORMAL) &&
        type != static_cast<int32_t>(OsAccountType::GUEST) &&
        type != static_cast<int32_t>(OsAccountType::PRIVATE)) {
        ACCOUNT_LOGE("Fail to get type:%{public}d from config.", type);
        config.u1AccountType = OsAccountType::ADMIN;
    } else {
        config.u1AccountType = static_cast<OsAccountType>(type);
    }
    GetDataByType<std::string>(u1Json, SYSTEM_ACCOUNT_NAME, config.u1AccountName);
    if (config.u1AccountName.length() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("Fail to get name:%{public}s from config.", config.u1AccountName.c_str());
        config.u1AccountName = "";
    }
    GetDataByType<bool>(u1Json, SYSTEM_ACCOUNT_BLOCK_BOOT, config.isBlockBoot);
}
#endif // ENABLE_U1_ACCOUNT

ErrCode OsAccountControlFileManager::GetOsAccountConfig(OsAccountConfig &config)
{
    std::string cfgPath = DEFAULT_OS_ACCOUNT_CONFIG_FILE;
#ifdef HAS_CONFIG_POLICY_PART
    char buf[MAX_PATH_LEN];
    char *path = GetOneCfgFile(OS_ACCOUNT_CONFIG_FILE, buf, MAX_PATH_LEN);
    if (path != nullptr && *path != '\0') {
        cfgPath = path;
    }
#endif
    std::string configStr;
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(cfgPath, configStr);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get content from file %{public}s failed!", cfgPath.c_str());
        return errCode;
    }
    auto configJson = CreateJsonFromString(configStr);
    if (configJson == nullptr) {
        ACCOUNT_LOGE("Parse os account info json data failed");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }

    int32_t maxOsAccountNum = -1;
    GetDataByType<int32_t>(configJson, MAX_OS_ACCOUNT_NUM, maxOsAccountNum);
    if (maxOsAccountNum > 0) {
        config.maxOsAccountNum = static_cast<uint32_t>(maxOsAccountNum);
    }
    GetDataByType<uint32_t>(configJson, MAX_LOGGED_IN_OS_ACCOUNT_NUM, config.maxLoggedInOsAccountNum);
#ifdef ENABLE_U1_ACCOUNT
    GetU1Config(configJson, config);
#endif // ENABLE_U1_ACCOUNT
    bool isDeveloperMode = OHOS::system::GetBoolParameter(DEVELOPER_MODE_STATE, false);
    if (isDeveloperMode && IsKeyExist(configJson, DEVELOPER_MODE)) {
        auto modeJson = GetItemFromJson(configJson, DEVELOPER_MODE);
        GetDataByType<uint32_t>(modeJson, MAX_LOGGED_IN_OS_ACCOUNT_NUM, config.maxLoggedInOsAccountNum);
    }
    if ((config.maxLoggedInOsAccountNum > config.maxOsAccountNum) ||
        (config.maxLoggedInOsAccountNum <= 0)) {
        config.maxLoggedInOsAccountNum = config.maxOsAccountNum;
    }
    return ERR_OK;
}

#ifdef ENABLE_FILE_WATCHER
bool OsAccountControlFileManager::RecoverAccountData(const std::string &fileName, const int32_t id)
{
#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    std::string recoverDataStr;
    if (fileName == Constants::ACCOUNT_LIST_FILE_JSON_PATH) {
        CJsonUnique accountListJson = nullptr;
        osAccountDataBaseOperator_->GetAccountListFromStoreID(OS_ACCOUNT_STORE_ID, accountListJson);
        recoverDataStr = PackJsonToString(accountListJson);
        if (recoverDataStr.empty()) {
            ACCOUNT_LOGE("failed to dump json object");
            return false;
        }
    } else if (id >= Constants::START_USER_ID) {
        OsAccountInfo osAccountInfo;
        if (GetOsAccountFromDatabase(OS_ACCOUNT_STORE_ID, id, osAccountInfo) != ERR_OK) {
            ACCOUNT_LOGW("Failed to get osaccount from database");
            return false;
        }
        recoverDataStr = osAccountInfo.ToString();
    } else {
        ACCOUNT_LOGW("Failed to parse parameters");
        return false;
    }
    if (recoverDataStr.empty()) {
        ACCOUNT_LOGW("Get empty recover file data");
        return false;
    }
    // recover data
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(fileName, recoverDataStr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Recover local file data failed, err = %{public}d", result);
        return false;
    }
    // update local digest
    if (accountFileWatcherMgr_.AddAccountInfoDigest(recoverDataStr, fileName) != ERR_OK) {
        ACCOUNT_LOGE("Failed to update local digest");
        return false;
    }
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    return true;
}

bool OsAccountControlFileManager::DealWithFileModifyEvent(const std::string &fileName, const int32_t id)
{
    ACCOUNT_LOGI("Enter");
    {
        std::unique_lock<std::shared_timed_mutex> lock(accountFileOperator_->fileLock_);
        if (accountFileOperator_->GetValidModifyFileOperationFlag(fileName)) {
            ACCOUNT_LOGD("This is valid service operate, no need to deal with it.");
            accountFileOperator_->SetValidModifyFileOperationFlag(fileName, false);
            return true;
        }
    }
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    std::string fileInfoStr;
    if (accountFileOperator_->GetFileContentByPath(fileName, fileInfoStr) != ERR_OK) {
        ACCOUNT_LOGE("Get content from file %{public}s failed!", fileName.c_str());
        return false;
    }
    uint8_t localDigestData[ALG_COMMON_SIZE] = {0};
    accountFileWatcherMgr_.GetAccountInfoDigestFromFile(fileName, localDigestData, ALG_COMMON_SIZE);
#ifdef HAS_HUKS_PART
    uint8_t newDigestData[ALG_COMMON_SIZE] = {0};
    GenerateAccountInfoDigest(fileInfoStr, newDigestData, ALG_COMMON_SIZE);

    if (memcmp(localDigestData, newDigestData, ALG_COMMON_SIZE) == EOK) {
        ACCOUNT_LOGD("No need to recover local file data.");
        return true;
    }
#endif // HAS_HUKS_PART
    ReportOsAccountDataTampered(id, fileName, "OS_ACCOUNT_INFO");
    ACCOUNT_LOGW("Local file data has been changed");
    return RecoverAccountData(fileName, id);
}

bool OsAccountControlFileManager::DealWithFileDeleteEvent(const std::string &fileName, const int32_t id)
{
    ACCOUNT_LOGI("Enter");
    {
        std::unique_lock<std::shared_timed_mutex> lock(accountFileOperator_->fileLock_);
        if (accountFileOperator_->GetValidDeleteFileOperationFlag(fileName)) {
            ACCOUNT_LOGD("This is valid service operate, no need to deal with it.");
            accountFileOperator_->SetValidDeleteFileOperationFlag(fileName, false);
            accountFileWatcherMgr_.RemoveFileWatcher(id, fileName);
            return true;
        }
    }
    ReportOsAccountDataTampered(id, fileName, "OS_ACCOUNT_INFO");
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    if (!RecoverAccountData(fileName, id)) {
        ACCOUNT_LOGE("Recover account data failed.");
    }
    accountFileWatcherMgr_.AddFileWatcher(id, eventCallbackFunc_, fileName);
    return true;
}

bool OsAccountControlFileManager::DealWithFileMoveEvent(const std::string &fileName, const int32_t id)
{
    ACCOUNT_LOGI("Enter");
    // delete old file watcher
    accountFileWatcherMgr_.RemoveFileWatcher(id, fileName);
    ReportOsAccountDataTampered(id, fileName, "OS_ACCOUNT_INFO");
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    if (!RecoverAccountData(fileName, id)) {
        ACCOUNT_LOGE("Recover account data failed.");
    }
    accountFileWatcherMgr_.AddFileWatcher(id, eventCallbackFunc_, fileName);
    return true;
}
#endif // ENABLE_FILE_WATCHER

#ifdef ENABLE_FILE_WATCHER
OsAccountControlFileManager::OsAccountControlFileManager()
    : accountFileWatcherMgr_(AccountFileWatcherMgr::GetInstance())
{
    accountFileOperator_ = accountFileWatcherMgr_.accountFileOperator_;
#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    osAccountDataBaseOperator_ = std::make_shared<OsAccountDatabaseOperator>();
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    osAccountFileOperator_ = std::make_shared<OsAccountFileOperator>();
    osAccountPhotoOperator_ = std::make_shared<OsAccountPhotoOperator>();
    eventCallbackFunc_ = [this](const std::string &fileName, int32_t id, uint32_t event) {
        ACCOUNT_LOGI("Inotify event = %{public}d, fileName = %{public}s", event, fileName.c_str());
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
                ACCOUNT_LOGW("Get event invalid!");
                return false;
            }
        }
    };
}
#else
OsAccountControlFileManager::OsAccountControlFileManager()
{
    accountFileOperator_ = std::make_shared<AccountFileOperator>();
#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    osAccountDataBaseOperator_ = std::make_shared<OsAccountDatabaseOperator>();
#endif // HAS_KV_STORE_PART && defined(DISTRIBUTED_FEATURE_ENABLED)
    osAccountFileOperator_ = std::make_shared<OsAccountFileOperator>();
    osAccountPhotoOperator_ = std::make_shared<OsAccountPhotoOperator>();
}
#endif // ENABLE_FILE_WATCHER
OsAccountControlFileManager::~OsAccountControlFileManager()
{}

void OsAccountControlFileManager::Init()
{
    FileInit();
    CJsonUnique accountListJson = nullptr;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        return;
    }
    std::vector<std::string> accountIdList;
    GetDataByType<std::vector<std::string>>(accountListJson, Constants::ACCOUNT_LIST, accountIdList);

#ifdef ENABLE_FILE_WATCHER
    if (!accountIdList.empty()) {
        InitFileWatcherInfo(accountIdList);
    }
#endif // ENABLE_FILE_WATCHER
    ACCOUNT_LOGI("OsAccountControlFileManager Init end");
}

void OsAccountControlFileManager::FileInit()
{
    if (!accountFileOperator_->IsJsonFileReady(Constants::ACCOUNT_LIST_FILE_JSON_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account list, create!");
        RecoverAccountListJsonFile();
    }
#ifdef ENABLE_FILE_WATCHER
    if (!accountFileOperator_->IsJsonFileReady(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account info digest file, create!");
        RecoverAccountInfoDigestJsonFile();
    }
#endif // ENABLE_FILE_WATCHER
    // -1 is special refers to conmon account data file.
#ifdef ENABLE_FILE_WATCHER
    accountFileWatcherMgr_.AddFileWatcher(-1, eventCallbackFunc_, Constants::ACCOUNT_LIST_FILE_JSON_PATH);
#endif // ENABLE_FILE_WATCHER
    if (!accountFileOperator_->IsJsonFileReady(Constants::ACCOUNT_INDEX_JSON_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account index file, create!");
        BuildAndSaveOsAccountIndexJsonFile();
    }
#ifdef ENABLE_FILE_WATCHER
    accountFileWatcherMgr_.AddFileWatcher(-1, eventCallbackFunc_, Constants::ACCOUNT_INDEX_JSON_PATH);
#endif // ENABLE_FILE_WATCHER
    if (!accountFileOperator_->IsJsonFileReady(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account list, create!");
        BuildAndSaveBaseOAConstraintsJsonFile();
    }
#ifdef ENABLE_FILE_WATCHER
    accountFileWatcherMgr_.AddFileWatcher(-1, eventCallbackFunc_, Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH);
#endif // ENABLE_FILE_WATCHER
    if (!accountFileOperator_->IsJsonFileReady(Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account list, create!");
        BuildAndSaveGlobalOAConstraintsJsonFile();
    }
#ifdef ENABLE_FILE_WATCHER
    accountFileWatcherMgr_.AddFileWatcher(-1, eventCallbackFunc_, Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH);
#endif // ENABLE_FILE_WATCHER
    if (!accountFileOperator_->IsJsonFileReady(Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account list, create!");
        BuildAndSaveSpecificOAConstraintsJsonFile();
    }
#ifdef ENABLE_FILE_WATCHER
    accountFileWatcherMgr_.AddFileWatcher(-1, eventCallbackFunc_, Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH);
#endif // ENABLE_FILE_WATCHER
}

#ifdef ENABLE_FILE_WATCHER
void OsAccountControlFileManager::InitFileWatcherInfo(std::vector<std::string> &accountIdList)
{
    for (std::string i : accountIdList) {
        int32_t id = 0;
        if (!StrToInt(i, id)) {
            ACCOUNT_LOGE("Convert localId failed");
            continue;
        }
        accountFileWatcherMgr_.AddFileWatcher(id, eventCallbackFunc_);
    }
}
#endif // ENABLE_FILE_WATCHER

void OsAccountControlFileManager::BuildAndSaveAccountListJsonFile(const std::vector<std::string>& accounts)
{
    ACCOUNT_LOGD("Enter.");
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    auto accountList = CreateJson();
    AddVectorStringToJson(accountList, Constants::ACCOUNT_LIST, accounts);
    AddIntToJson(accountList, Constants::COUNT_ACCOUNT_NUM, accounts.size());
    AddIntToJson(accountList, DEFAULT_ACTIVATED_ACCOUNT_ID, Constants::START_USER_ID);
    AddIntToJson(accountList, Constants::MAX_ALLOW_CREATE_ACCOUNT_ID, Constants::MAX_USER_ID);
    AddInt64ToJson(accountList, Constants::SERIAL_NUMBER_NUM, Constants::SERIAL_NUMBER_NUM_START);
    AddBoolToJson(accountList, IS_SERIAL_NUMBER_FULL, Constants::IS_SERIAL_NUMBER_FULL_INIT_VALUE);
    AddIntToJson(accountList, NEXT_LOCAL_ID, Constants::START_USER_ID + 1);

    SaveAccountListToFile(accountList);
}

void OsAccountControlFileManager::BuildAndSaveBaseOAConstraintsJsonFile()
{
    ACCOUNT_LOGI("Enter.");
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    std::vector<std::string> baseOAConstraints;
    if (osAccountFileOperator_->GetConstraintsByType(OsAccountType::ADMIN, baseOAConstraints) != ERR_OK) {
        ACCOUNT_LOGE("Get %{public}d base os account constraints failed.", Constants::START_USER_ID);
        return;
    }
    auto baseOsAccountConstraints = CreateJson();
    AddVectorStringToJson(baseOsAccountConstraints, START_USER_STRING_ID, baseOAConstraints);
    SaveBaseOAConstraintsToFile(baseOsAccountConstraints);
}

void OsAccountControlFileManager::BuildAndSaveGlobalOAConstraintsJsonFile()
{
    ACCOUNT_LOGI("Enter.");
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    auto globalOsAccountConstraints = CreateJson();
    AddIntToJson(globalOsAccountConstraints, DEVICE_OWNER_ID, -1);
    auto allGlobalConstraints = CreateJsonNull();
    AddObjToJson(globalOsAccountConstraints, Constants::ALL_GLOBAL_CONSTRAINTS, allGlobalConstraints);
    SaveGlobalOAConstraintsToFile(globalOsAccountConstraints);
}

void OsAccountControlFileManager::BuildAndSaveSpecificOAConstraintsJsonFile()
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    auto allGlobalConstraints = CreateJsonNull();
    auto osAccountConstraintsList = CreateJson();
    AddObjToJson(osAccountConstraintsList, Constants::ALL_SPECIFIC_CONSTRAINTS, allGlobalConstraints);
    auto specificOsAccountConstraints = CreateJson();
    AddObjToJson(specificOsAccountConstraints, START_USER_STRING_ID, osAccountConstraintsList);
    SaveSpecificOAConstraintsToFile(specificOsAccountConstraints);
}

void OsAccountControlFileManager::BuildAndSaveOsAccountIndexJsonFile()
{
    std::string accountIndex;
    ErrCode result = GetAccountIndexInfo(accountIndex);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get account index info error code %{public}d.", result);
        return;
    }
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    result = accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_INDEX_JSON_PATH, accountIndex);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to input account index info to file!");
    }
    return;
}

void OsAccountControlFileManager::RecoverAccountInfoDigestJsonFile()
{
    std::string listInfoStr;
    accountFileOperator_->GetFileContentByPath(Constants::ACCOUNT_LIST_FILE_JSON_PATH, listInfoStr);
#ifdef HAS_HUKS_PART
    uint8_t digestOutData[ALG_COMMON_SIZE] = {0};
    GenerateAccountInfoDigest(listInfoStr, digestOutData, ALG_COMMON_SIZE);
    auto digestJsonData = CreateJson();
    AddVectorUint8ToJson(digestJsonData, Constants::ACCOUNT_LIST_FILE_JSON_PATH,
                         std::vector<uint8_t>(digestOutData, digestOutData + ALG_COMMON_SIZE));
    std::string strValue = PackJsonToString(digestJsonData);
    accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH, strValue);
#endif // HAS_HUKS_PART
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
        ACCOUNT_LOGE("Cannot open dir %{public}s, err %{public}d.", Constants::USER_INFO_BASE.c_str(), errno);
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
            ACCOUNT_LOGE("Invalid account id %{public}s detected in %{public}s.", curDirName.c_str(),
                Constants::USER_INFO_BASE.c_str());
            continue;
        }

        // check repeat
        bool sameAccountID = false;
        std::string curAccountIDStr = std::to_string(accountID);
        for (size_t i = 0; i < accounts.size(); ++i) {
            if (accounts[i] == curAccountIDStr) {
                ACCOUNT_LOGE("Repeated account id %{public}s detected in %{public}s.", curAccountIDStr.c_str(),
                    Constants::USER_INFO_BASE.c_str());
                sameAccountID = true;
                break;
            }
        }

        if (!sameAccountID && accountID >= Constants::START_USER_ID) {
            accounts.push_back(curAccountIDStr);
        }
    }

    if (closedir(rootDir) != 0) {
        ACCOUNT_LOGE("Cannot closedir dir %{public}s, err %{public}d.", Constants::USER_INFO_BASE.c_str(), errno);
    }
    BuildAndSaveAccountListJsonFile(accounts);
}

ErrCode OsAccountControlFileManager::GetOsAccountIdList(std::vector<int32_t> &idList)
{
    idList.clear();
    CJsonUnique accountListJson = nullptr;
    ErrCode errCode = GetAccountListFromFile(accountListJson);
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::vector<std::string> idStrList;
    GetDataByType<std::vector<std::string>>(accountListJson, Constants::ACCOUNT_LIST, idStrList);
    for (const auto &idStr : idStrList) {
        int32_t id = 0;
        if (!StrToInt(idStr, id)) {
            ACCOUNT_LOGE("Convert localId failed");
            continue;
        }
        idList.emplace_back(id);
    }
    return errCode;
}

ErrCode OsAccountControlFileManager::GetOsAccountList(std::vector<OsAccountInfo> &osAccountList)
{
    osAccountList.clear();
    CJsonUnique accountListJson = nullptr;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetAccountListFromFile failed!");
#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
        if (osAccountDataBaseOperator_->GetAccountListFromStoreID("", accountListJson) == ERR_OK) {
            SaveAccountListToFile(accountListJson);
        } else {
            return result;
        }
#else
        return result;
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    }
    std::vector<std::string> idList;
    GetDataByType<std::vector<std::string>>(accountListJson, Constants::ACCOUNT_LIST, idList);

    for (const auto& it : idList) {
        OsAccountInfo osAccountInfo;
        int32_t id = 0;
        if (!StrToInt(it, id)) {
            ACCOUNT_LOGE("Convert localId failed");
            continue;
        }
        if (GetOsAccountInfoById(id, osAccountInfo) == ERR_OK) {
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
    ErrCode err = accountFileOperator_->CheckFileExistence(path);
    if (err != ERR_OK) {
        ACCOUNT_LOGE("File %{public}s does not exist err, errcode=%{public}d", path.c_str(), err);
        if (GetOsAccountFromDatabase("", id, osAccountInfo) == ERR_OK) {
            InsertOsAccount(osAccountInfo);
            return ERR_OK;
        }
        return err == ERR_ACCOUNT_COMMON_FILE_NOT_EXIST ?
            ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR : ERR_ACCOUNT_COMMON_FILE_READ_FAILED;
    }
    std::string accountInfoStr;
    if (accountFileOperator_->GetFileContentByPath(path, accountInfoStr) != ERR_OK) {
        ACCOUNT_LOGE("Get content from file %{public}s failed!", path.c_str());
        if (GetOsAccountFromDatabase("", id, osAccountInfo) == ERR_OK) {
            return ERR_OK;
        }
        return ERR_ACCOUNT_COMMON_FILE_READ_FAILED;
    }
    auto osAccountInfoJson = CreateJsonFromString(accountInfoStr);
    if (osAccountInfoJson == nullptr || !FromJson(osAccountInfoJson.get(), osAccountInfo)) {
        ACCOUNT_LOGE("Parse os account info json for %{public}d failed", id);
        if (GetOsAccountFromDatabase("", id, osAccountInfo) != ERR_OK) {
            ACCOUNT_LOGE("GetOsAccountFromDatabase failed id=%{public}d", id);
            return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
        }
    }
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
    CJsonUnique baseOAConstraintsJson = nullptr;
    ErrCode result = GetBaseOAConstraintsFromFile(baseOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get baseOAConstraints from json file failed!");
        return result;
    }
    if (!IsKeyExist(baseOAConstraintsJson, idStr)) {
        if (!isAdd) {
            return ERR_OK;
        }
        AddVectorStringToJson(baseOAConstraintsJson, idStr, ConstraintStr);
    } else {
        std::vector<std::string> baseOAConstraints;
        GetDataByType<std::vector<std::string>>(baseOAConstraintsJson, idStr, baseOAConstraints);
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
        AddVectorStringToJson(baseOAConstraintsJson, idStr, baseOAConstraints);
    }
    return SaveBaseOAConstraintsToFile(baseOAConstraintsJson);
}

ErrCode OsAccountControlFileManager::UpdateGlobalOAConstraints(
    const std::string& idStr, const std::vector<std::string>& ConstraintStr, bool isAdd)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    CJsonUnique globalOAConstraintsJson = nullptr;
    ErrCode result = GetGlobalOAConstraintsFromFile(globalOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get globalOAConstraints from file failed!");
        return result;
    }
    GlobalConstraintsDataOperate(idStr, ConstraintStr, isAdd, globalOAConstraintsJson);
    return SaveGlobalOAConstraintsToFile(globalOAConstraintsJson);
}

void OsAccountControlFileManager::GlobalConstraintsDataOperate(const std::string& idStr,
    const std::vector<std::string>& ConstraintStr, bool isAdd, CJsonUnique &globalOAConstraintsJson)
{
    std::vector<std::string> globalOAConstraintsList;
    GetDataByType<std::vector<std::string>>(globalOAConstraintsJson, Constants::ALL_GLOBAL_CONSTRAINTS,
                                            globalOAConstraintsList);
    std::vector<std::string> waitForErase;
    for (auto it = ConstraintStr.begin(); it != ConstraintStr.end(); it++) {
        if (!isAdd) {
            if (std::find(globalOAConstraintsList.begin(),
            globalOAConstraintsList.end(), *it) == globalOAConstraintsList.end()) {
                continue;
            }
            std::vector<std::string> constraintSourceList;
            GetDataByType<std::vector<std::string>>(globalOAConstraintsJson, *it, constraintSourceList);
            constraintSourceList.erase(std::remove(constraintSourceList.begin(), constraintSourceList.end(), idStr),
                constraintSourceList.end());
            if (constraintSourceList.size() == 0) {
                globalOAConstraintsList.erase(std::remove(globalOAConstraintsList.begin(),
                    globalOAConstraintsList.end(), *it), globalOAConstraintsList.end());
                AddVectorStringToJson(globalOAConstraintsJson, Constants::ALL_GLOBAL_CONSTRAINTS,
                                      globalOAConstraintsList);
                waitForErase.push_back(*it);
            } else {
                AddVectorStringToJson(globalOAConstraintsJson, *it, constraintSourceList);
            }
            continue;
        }
        if (std::find(globalOAConstraintsList.begin(),
            globalOAConstraintsList.end(), *it) != globalOAConstraintsList.end()) {
            std::vector<std::string> constraintSourceList;
            GetDataByType<std::vector<std::string>>(globalOAConstraintsJson, *it, constraintSourceList);
            if (std::find(constraintSourceList.begin(),
                constraintSourceList.end(), idStr) == constraintSourceList.end()) {
                constraintSourceList.emplace_back(idStr);
                AddVectorStringToJson(globalOAConstraintsJson, *it, constraintSourceList);
            }
            continue;
        }
        std::vector<std::string> constraintSourceList;
        constraintSourceList.emplace_back(idStr);
        globalOAConstraintsList.emplace_back(*it);
        AddVectorStringToJson(globalOAConstraintsJson, *it, constraintSourceList);
        AddVectorStringToJson(globalOAConstraintsJson, Constants::ALL_GLOBAL_CONSTRAINTS, globalOAConstraintsList);
    }
    for (auto keyStr : waitForErase) {
        DeleteItemFromJson(globalOAConstraintsJson, keyStr);
    }
}

ErrCode OsAccountControlFileManager::UpdateSpecificOAConstraints(
    const std::string& idStr, const std::string& targetIdStr, const std::vector<std::string>& ConstraintStr, bool isAdd)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    CJsonUnique specificOAConstraintsJson = nullptr;
    ErrCode result = GetSpecificOAConstraintsFromFile(specificOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get specificOAConstraints from file failed!");
        return result;
    }
    if (!IsKeyExist(specificOAConstraintsJson, targetIdStr)) {
        if (!isAdd) {
            return ERR_OK;
        }
        auto accountList = CreateJsonNull();
        auto osAccountConstraintsList = CreateJson();
        AddObjToJson(osAccountConstraintsList, Constants::ALL_SPECIFIC_CONSTRAINTS, accountList);
        AddObjToJson(specificOAConstraintsJson, targetIdStr, osAccountConstraintsList);
    }
    cJSON *userPrivateConstraintsDataJson = GetItemFromJson(specificOAConstraintsJson, targetIdStr);
    SpecificConstraintsDataOperate(idStr, targetIdStr, ConstraintStr, isAdd, userPrivateConstraintsDataJson);
    AddObjToJson(specificOAConstraintsJson.get(), targetIdStr, userPrivateConstraintsDataJson);
    return SaveSpecificOAConstraintsToFile(specificOAConstraintsJson);
}

void OsAccountControlFileManager::SpecificConstraintsDataOperate(
    const std::string& idStr, const std::string& targetIdStr, const std::vector<std::string>& ConstraintStr,
    bool isAdd, cJSON *userPrivateConstraintsDataJson)
{
    std::vector<std::string> specificOAConstraintsList;
    GetDataByType<std::vector<std::string>>(userPrivateConstraintsDataJson, Constants::ALL_SPECIFIC_CONSTRAINTS,
                                            specificOAConstraintsList);

    std::vector<std::string> waitForErase;
    for (auto it = ConstraintStr.begin(); it != ConstraintStr.end(); it++) {
        if (!isAdd) {
            if (!IsKeyExist(userPrivateConstraintsDataJson, *it)) {
                continue;
            }
            std::vector<std::string> constraintSourceList;
            GetDataByType<std::vector<std::string>>(userPrivateConstraintsDataJson, *it, constraintSourceList);
            constraintSourceList.erase(std::remove(constraintSourceList.begin(), constraintSourceList.end(), idStr),
                constraintSourceList.end());
            if (constraintSourceList.size() == 0) {
                specificOAConstraintsList.erase(std::remove(specificOAConstraintsList.begin(),
                    specificOAConstraintsList.end(), *it), specificOAConstraintsList.end());
                AddVectorStringToJson(userPrivateConstraintsDataJson, Constants::ALL_SPECIFIC_CONSTRAINTS,
                    specificOAConstraintsList);
                waitForErase.push_back(*it);
            } else {
                AddVectorStringToJson(userPrivateConstraintsDataJson, *it, constraintSourceList);
            }
            continue;
        }
        if (std::find(specificOAConstraintsList.begin(),
            specificOAConstraintsList.end(), *it) != specificOAConstraintsList.end()) {
            std::vector<std::string> constraintSourceList;
            GetDataByType<std::vector<std::string>>(userPrivateConstraintsDataJson, *it, constraintSourceList);
            if (std::find(constraintSourceList.begin(),
                constraintSourceList.end(), idStr) == constraintSourceList.end()) {
                constraintSourceList.emplace_back(idStr);
                AddVectorStringToJson(userPrivateConstraintsDataJson, *it, constraintSourceList);
            }
            continue;
        }
        std::vector<std::string> constraintSourceList;
        constraintSourceList.emplace_back(idStr);
        specificOAConstraintsList.emplace_back(*it);
        AddVectorStringToJson(userPrivateConstraintsDataJson, *it, constraintSourceList);
        AddVectorStringToJson(userPrivateConstraintsDataJson, Constants::ALL_SPECIFIC_CONSTRAINTS,
            specificOAConstraintsList);
    }
    for (auto keyStr : waitForErase) {
        DeleteItemFromJson(userPrivateConstraintsDataJson, keyStr);
    }
}

ErrCode OsAccountControlFileManager::RemoveOAConstraintsInfo(const int32_t id)
{
    ErrCode errCode = RemoveOABaseConstraintsInfo(id);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Remove os account %{public}d base constraints info failed!", id);
        return errCode;
    }
    errCode = RemoveOAGlobalConstraintsInfo(id);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Remove os account %{public}d global constraints info failed!", id);
        return errCode;
    }
    errCode = RemoveOASpecificConstraintsInfo(id);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Remove os account %{public}d specific constraints info failed!", id);
        return errCode;
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::RemoveOABaseConstraintsInfo(const int32_t id)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    CJsonUnique baseOAConstraintsJson = nullptr;
    ErrCode result = GetBaseOAConstraintsFromFile(baseOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get baseOAConstraints from file failed!");
        return result;
    }
    DeleteItemFromJson(baseOAConstraintsJson, std::to_string(id));
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
    CJsonUnique globalOAConstraintsJson = nullptr;
    ErrCode result = GetGlobalOAConstraintsFromFile(globalOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get globalOAConstraints from file failed!");
        return result;
    }
    std::vector<std::string> waitForErase;
    std::vector<cJSON *> globalOAConstraintsJsonLists;
    cJSON* item = nullptr;
    cJSON_ArrayForEach(item, globalOAConstraintsJson.get()) {
        globalOAConstraintsJsonLists.emplace_back(item);
    }
    for (const auto &it : globalOAConstraintsJsonLists) {
        std::string key(it->string);
        if (key != Constants::ALL_GLOBAL_CONSTRAINTS && key != DEVICE_OWNER_ID) {
            std::vector<std::string> sourceList;
            GetDataByType<std::vector<std::string>>(globalOAConstraintsJson, key, sourceList);
            sourceList.erase(std::remove(sourceList.begin(), sourceList.end(), std::to_string(id)), sourceList.end());
            if (sourceList.size() == 0) {
                std::vector<std::string> allGlobalConstraints;
                GetDataByType<std::vector<std::string>>(globalOAConstraintsJson, Constants::ALL_GLOBAL_CONSTRAINTS,
                                                        allGlobalConstraints);
                allGlobalConstraints.erase(std::remove(allGlobalConstraints.begin(),
                    allGlobalConstraints.end(), key), allGlobalConstraints.end());
                AddVectorStringToJson(globalOAConstraintsJson, Constants::ALL_GLOBAL_CONSTRAINTS, allGlobalConstraints);
                waitForErase.push_back(key);
            } else {
                AddVectorStringToJson(globalOAConstraintsJson, key, sourceList);
            }
        }
    }
    for (auto keyStr : waitForErase) {
        DeleteItemFromJson(globalOAConstraintsJson, keyStr);
    }
    return SaveGlobalOAConstraintsToFile(globalOAConstraintsJson);
}

ErrCode OsAccountControlFileManager::RemoveOASpecificConstraintsInfo(const int32_t id)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    CJsonUnique specificOAConstraintsJson = nullptr;
    ErrCode result = GetSpecificOAConstraintsFromFile(specificOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get specificOAConstraints from file failed!");
        return result;
    }
    if (IsKeyExist(specificOAConstraintsJson, std::to_string(id))) {
        DeleteItemFromJson(specificOAConstraintsJson, std::to_string(id));
    }

    RemoveAllUsersConstraintsInfo(specificOAConstraintsJson, id);

    return SaveSpecificOAConstraintsToFile(specificOAConstraintsJson);
}

void OsAccountControlFileManager::RemoveAllUsersConstraintsInfo(CJsonUnique &specificOAConstraintsJson,
                                                                const int32_t id)
{
    std::vector<cJSON *> specificJsonObjLists;
    cJSON* specificJsonObj = nullptr;
    cJSON_ArrayForEach(specificJsonObj, specificOAConstraintsJson.get()) {
        specificJsonObjLists.emplace_back(specificJsonObj);
    }
    for (const auto &it : specificJsonObjLists) {
        std::vector<std::string> waitForErase;
        cJSON *userPrivateConstraintsJson = nullptr;
        GetDataByType<CJson *>(specificOAConstraintsJson, it->string, userPrivateConstraintsJson);
        std::vector<std::string> allSpecificConstraints;
        GetDataByType<std::vector<std::string>>(userPrivateConstraintsJson, Constants::ALL_SPECIFIC_CONSTRAINTS,
                                                allSpecificConstraints);
        if (allSpecificConstraints.size() == 0) {
            continue;
        }
        std::vector<cJSON *> userJsonObjLists;
        cJSON* userJsonObj = nullptr;
        cJSON_ArrayForEach(userJsonObj, userPrivateConstraintsJson) {
            userJsonObjLists.emplace_back(userJsonObj);
        }
        for (const auto &item : userJsonObjLists) {
            if (std::string(item->string) == Constants::ALL_SPECIFIC_CONSTRAINTS) {
                continue;
            }
            std::vector<std::string> sourceList;
            GetDataByType<std::vector<std::string>>(userPrivateConstraintsJson, item->string, sourceList);
            sourceList.erase(std::remove(sourceList.begin(),
                sourceList.end(), std::to_string(id)), sourceList.end());
            if (sourceList.size() == 0) {
                allSpecificConstraints.erase(std::remove(allSpecificConstraints.begin(),
                    allSpecificConstraints.end(), item->string), allSpecificConstraints.end());
                AddVectorStringToJson(userPrivateConstraintsJson, Constants::ALL_SPECIFIC_CONSTRAINTS,
                    allSpecificConstraints);
                waitForErase.push_back(item->string);
            } else {
                AddVectorStringToJson(userPrivateConstraintsJson, item->string, sourceList);
            }
        }
        for (auto keyStr : waitForErase) {
            DeleteItemFromJson(userPrivateConstraintsJson, keyStr);
        }
        AddObjToJson(specificOAConstraintsJson.get(), it->string, userPrivateConstraintsJson);
    }
}

ErrCode OsAccountControlFileManager::UpdateAccountList(const std::string& idStr, bool isAdd)
{
    CJsonUnique accountListJson = nullptr;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get account list failed!");
        return result;
    }

    std::vector<std::string> accountIdList;
    GetDataByType<std::vector<std::string>>(accountListJson, Constants::ACCOUNT_LIST, accountIdList);
    if (isAdd) {
        // check repeat
        if (std::find(accountIdList.begin(), accountIdList.end(), idStr) != accountIdList.end()) {
            return ERR_OK;  // already exist, no need to add.
        }
        accountIdList.emplace_back(idStr);
    } else {
        accountIdList.erase(std::remove(accountIdList.begin(), accountIdList.end(), idStr), accountIdList.end());
    }
    AddVectorStringToJson(accountListJson, Constants::ACCOUNT_LIST, accountIdList);
    AddIntToJson(accountListJson, Constants::COUNT_ACCOUNT_NUM, accountIdList.size());
    return SaveAccountListToFileAndDataBase(accountListJson);
}

ErrCode OsAccountControlFileManager::UpdateAccountIndex(const OsAccountInfo &osAccountInfo, const bool isDelete)
{
    // private type account not write index to index file, don't check name in ValidateOsAccount
    if (osAccountInfo.GetType() == OsAccountType::PRIVATE) {
        return ERR_OK;
    }
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    CJsonUnique accountIndexJson = nullptr;
    ErrCode result = GetAccountIndexFromFile(accountIndexJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get account index failed!");
        return result;
    }
    std::string localIdStr = std::to_string(osAccountInfo.GetLocalId());
    if (isDelete) {
        if (!IsObject(accountIndexJson)) {
            ACCOUNT_LOGE("Get os account index json data failed");
            return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
        }
        DeleteItemFromJson(accountIndexJson, localIdStr);
    } else {
        auto accountBaseInfo = CreateJson();
        AddStringToJson(accountBaseInfo, Constants::LOCAL_NAME, osAccountInfo.GetLocalName());
        AddStringToJson(accountBaseInfo, Constants::SHORT_NAME, osAccountInfo.GetShortName());
        AddObjToJson(accountIndexJson, localIdStr, accountBaseInfo);
    }
    std::string lastAccountIndexStr = PackJsonToString(accountIndexJson);
    result = accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_INDEX_JSON_PATH, lastAccountIndexStr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to input account index info to file!");
        return result;
    }
#ifdef ENABLE_FILE_WATCHER
    accountFileWatcherMgr_.AddAccountInfoDigest(lastAccountIndexStr, Constants::ACCOUNT_INDEX_JSON_PATH);
#endif // ENABLE_FILE_WATCHER
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SetNextLocalId(const int32_t &nextLocalId)
{
    std::lock_guard<std::mutex> lock(operatingIdMutex_);
    CJsonUnique accountListJson = nullptr;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SetNextLocalId get accountList error.");
        return result;
    }
    int32_t nextLocalIdJson = -1;
    if (!GetDataByType<std::int32_t>(accountListJson, NEXT_LOCAL_ID, nextLocalIdJson)) {
        ACCOUNT_LOGW("SetNextLocalId get next localId failed");
        nextLocalIdJson = Constants::START_USER_ID + 1;
    }
    AddIntToJson(accountListJson, NEXT_LOCAL_ID, std::max(nextLocalId, nextLocalIdJson));
    result = SaveAccountListToFileAndDataBase(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SetNextLocalId save accountListJson error.");
    }
    return result;
}

ErrCode OsAccountControlFileManager::RemoveAccountIndex(const int32_t id)
{
    CJsonUnique accountIndexJson = nullptr;
    ErrCode result = GetAccountIndexFromFile(accountIndexJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get account index failed!");
        return result;
    }
    std::string localIdStr = std::to_string(id);
    if (!IsObject(accountIndexJson)) {
        ACCOUNT_LOGE("Get os account index data failed");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    DeleteItemFromJson(accountIndexJson, localIdStr);
    std::string lastAccountIndexStr = PackJsonToString(accountIndexJson);
    result = accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_INDEX_JSON_PATH, lastAccountIndexStr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to input account index info to file!");
        return result;
    }
#ifdef ENABLE_FILE_WATCHER
    accountFileWatcherMgr_.AddAccountInfoDigest(lastAccountIndexStr, Constants::ACCOUNT_INDEX_JSON_PATH);
#endif // ENABLE_FILE_WATCHER
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::InsertOsAccount(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("Enter");
    if (osAccountInfo.GetLocalId() < Constants::ADMIN_LOCAL_ID) {
        ACCOUNT_LOGE("Error id %{public}d cannot insert", osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_CONTROL_ID_CANNOT_CREATE_ERROR;
    }

    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + osAccountInfo.GetPrimeKey() +
                       Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    if (accountFileOperator_->IsExistFile(path) && accountFileOperator_->IsJsonFormat(path)) {
        ACCOUNT_LOGE("Account %{public}d already exists", osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_CONTROL_INSERT_FILE_EXISTS_ERROR;
    }

    std::string accountInfoStr = osAccountInfo.ToString();
    if (accountInfoStr.empty()) {
        ACCOUNT_LOGE("Os account info is empty! maybe some illegal characters caused exception!");
        return ERR_OSACCOUNT_SERVICE_ACCOUNT_INFO_EMPTY_ERROR;
    }
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    if (osAccountInfo.GetLocalId() >= Constants::START_USER_ID) {
        ErrCode updateRet = UpdateAccountList(osAccountInfo.GetPrimeKey(), true);
        if (updateRet != ERR_OK) {
            ACCOUNT_LOGE("Update account list failed, errCode: %{public}d", updateRet);
            return updateRet;
        }
    }
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(path, accountInfoStr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("InputFileByPathAndContent failed! path %{public}s.", path.c_str());
        return result;
    }
#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    osAccountDataBaseOperator_->InsertOsAccountIntoDataBase(osAccountInfo);
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)

#ifdef ENABLE_FILE_WATCHER
    if (osAccountInfo.GetLocalId() >= Constants::START_USER_ID || osAccountInfo.GetLocalId() == Constants::U1_ID) {
        accountFileWatcherMgr_.AddAccountInfoDigest(accountInfoStr, path);
        accountFileWatcherMgr_.AddFileWatcher(osAccountInfo.GetLocalId(), eventCallbackFunc_);
    }
#endif // ENABLE_FILE_WATCHER
    ACCOUNT_LOGI("End");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::DelOsAccount(const int id)
{
    ACCOUNT_LOGD("Enter");
    if (id <= Constants::START_USER_ID || id > Constants::MAX_USER_ID) {
        ACCOUNT_LOGE("Ivalid input id %{public}d to delete!", id);
        return ERR_OSACCOUNT_SERVICE_CONTROL_CANNOT_DELETE_ID_ERROR;
    }
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id);
    ErrCode result = accountFileOperator_->DeleteDirOrFile(path);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("DeleteDirOrFile failed! path %{public}s.", path.c_str());
        return result;
    }
#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    osAccountDataBaseOperator_->DelOsAccountFromDatabase(id);
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
#ifdef ENABLE_FILE_WATCHER
    path += Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    accountFileWatcherMgr_.DeleteAccountInfoDigest(path);
    std::string distributedDataPath =
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) + DISTRIBUTED_ACCOUNT_FILE_NAME;
    accountFileWatcherMgr_.DeleteAccountInfoDigest(distributedDataPath);
#endif // ENABLE_FILE_WATCHER
    RemoveAccountIndex(id);
    return UpdateAccountList(std::to_string(id), false);
}


ErrCode OsAccountControlFileManager::UpdateOsAccount(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGD("Start");
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + osAccountInfo.GetPrimeKey() +
                       Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    if (!accountFileOperator_->IsExistFile(path)) {
        ACCOUNT_LOGE("Path %{public}s does not exist!", path.c_str());
        return ERR_OSACCOUNT_SERVICE_CONTROL_UPDATE_FILE_NOT_EXISTS_ERROR;
    }

    std::string accountInfoStr = osAccountInfo.ToString();
    if (accountInfoStr.empty()) {
        ACCOUNT_LOGE("Account info str is empty!");
        return ERR_OSACCOUNT_SERVICE_ACCOUNT_INFO_EMPTY_ERROR;
    }
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(path, accountInfoStr);
    if (result != ERR_OK) {
        return result;
    }

#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    // update in database
    if (osAccountInfo.GetLocalId() >= Constants::START_USER_ID || osAccountInfo.GetLocalId() == Constants::U1_ID) {
        osAccountDataBaseOperator_->UpdateOsAccountInDatabase(osAccountInfo);
    }
#else  // DISTRIBUTED_FEATURE_ENABLED
    ACCOUNT_LOGI("No distributed feature!");
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
#ifdef ENABLE_FILE_WATCHER
    accountFileWatcherMgr_.AddAccountInfoDigest(accountInfoStr, path);
#endif // ENABLE_FILE_WATCHER
    ACCOUNT_LOGD("End");
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
    CJsonUnique accountListJson = nullptr;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetSerialNumber get accountList error");
        return result;
    }
    GetDataByType<int64_t>(accountListJson, Constants::SERIAL_NUMBER_NUM, serialNumber);
    if (serialNumber == Constants::CARRY_NUM) {
        AddBoolToJson(accountListJson, IS_SERIAL_NUMBER_FULL, true);
        serialNumber = Constants::SERIAL_NUMBER_NUM_START;
    }
    bool isSerialNumberFull = false;
    GetDataByType<bool>(accountListJson, IS_SERIAL_NUMBER_FULL, isSerialNumberFull);
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
    AddInt64ToJson(accountListJson, Constants::SERIAL_NUMBER_NUM, serialNumber + 1);
    result = SaveAccountListToFileAndDataBase(accountListJson);
    if (result != ERR_OK) {
        return result;
    }
    serialNumber = serialNumber + Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN * Constants::CARRY_NUM;
    return ERR_OK;
}

int32_t OsAccountControlFileManager::GetNextLocalId(const std::vector<std::string> &accountIdList, int32_t startId)
{
    do {
        if ((startId <= Constants::START_USER_ID) || (startId >= Constants::MAX_USER_ID)) {
            startId = Constants::START_USER_ID + 1;
        }
        if (std::find(accountIdList.begin(), accountIdList.end(), std::to_string(startId)) ==
            accountIdList.end()) {
            break;
        }
        ++startId;
    } while (true);
    return startId;
}

ErrCode OsAccountControlFileManager::GetAllowCreateId(int &id)
{
    std::lock_guard<std::mutex> lock(operatingIdMutex_);
    CJsonUnique accountListJson = nullptr;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetAllowCreateId get accountList error.");
        return result;
    }
    std::vector<std::string> accountIdList;
    int32_t nextLocalId = -1;
    if (!GetDataByType<std::vector<std::string>>(accountListJson, Constants::ACCOUNT_LIST, accountIdList)) {
        ACCOUNT_LOGE("GetAllowCreateId get accountIdList error");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    if (!GetDataByType<int32_t>(accountListJson, NEXT_LOCAL_ID, nextLocalId)) {
        ACCOUNT_LOGW("Get next localId failed");
        int32_t lastLocalId = -1;
        if (!accountIdList.empty() && StrToInt(accountIdList[accountIdList.size() - 1], lastLocalId)) {
            nextLocalId = lastLocalId + 1;
        } else {
            nextLocalId = Constants::START_USER_ID + 1;
            ACCOUNT_LOGW("Convert last item in accountIdList to string failed.");
        }
    }

    id = GetNextLocalId(accountIdList, nextLocalId);
    AddIntToJson(accountListJson, NEXT_LOCAL_ID, id + 1);
    result = SaveAccountListToFileAndDataBase(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetAllowCreateId save accountListJson error, errCode %{public}d.", result);
    }
    return result;
}

ErrCode OsAccountControlFileManager::GetAccountListFromFile(CJsonUnique &accountListJson)
{
    ACCOUNT_LOGD("Enter");
    std::string accountList;
    std::lock_guard<std::mutex> lock(accountListFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(Constants::ACCOUNT_LIST_FILE_JSON_PATH,
        accountList);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
        return errCode;
    }
    accountListJson = CreateJsonFromString(accountList);
    if (accountListJson == nullptr) {
        ACCOUNT_LOGE("AccountListFile does not comply with the json format.");
#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
        return osAccountDataBaseOperator_->GetAccountListFromStoreID(OS_ACCOUNT_STORE_ID, accountListJson);
#else
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    }
    ACCOUNT_LOGD("End");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetAccountIndexFromFile(CJsonUnique &accountIndexJson)
{
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
    accountIndexJson = CreateJsonFromString(accountIndex);
    if (accountIndexJson == nullptr) {
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
    auto accountIndexJson = osAccountInfos.empty() ? CreateJsonNull() : CreateJson();
    for (auto account = osAccountInfos.begin(); account != osAccountInfos.end(); account++) {
        // private account don't check name
        if (account->GetType() == OsAccountType::PRIVATE) {
            continue;
        }
        std::string localIdStr = std::to_string(account->GetLocalId());
        auto accountIndexElement = CreateJson();
        AddStringToJson(accountIndexElement, Constants::LOCAL_NAME, account->GetLocalName());
        AddStringToJson(accountIndexElement, Constants::SHORT_NAME, account->GetShortName());
        AddObjToJson(accountIndexJson, localIdStr, accountIndexElement);
    }
    accountIndexInfo = PackJsonToString(accountIndexJson);
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetBaseOAConstraintsFromFile(CJsonUnique &baseOAConstraintsJson)
{
    std::string baseOAConstraints;
    std::lock_guard<std::mutex> lock(baseOAConstraintsFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(
        Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH, baseOAConstraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
        return errCode;
    }
    baseOAConstraintsJson = CreateJsonFromString(baseOAConstraints);
    if (baseOAConstraintsJson == nullptr || !IsObject(baseOAConstraintsJson)) {
        ACCOUNT_LOGE("Base constraints json data parse failed code.");
        return errCode;
    }

    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetGlobalOAConstraintsFromFile(CJsonUnique &globalOAConstraintsJson)
{
    std::string globalOAConstraints;
    std::lock_guard<std::mutex> lock(globalOAConstraintsFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(
        Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH, globalOAConstraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
        return errCode;
    }
    globalOAConstraintsJson = CreateJsonFromString(globalOAConstraints);
    if (globalOAConstraintsJson == nullptr || !IsObject(globalOAConstraintsJson)) {
        ACCOUNT_LOGE("Global constraints json data parse failed code.");
        return errCode;
    }

    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetSpecificOAConstraintsFromFile(CJsonUnique &specificOAConstraintsJson)
{
    std::string specificOAConstraints;
    std::lock_guard<std::mutex> lock(specificOAConstraintsFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(
        Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH, specificOAConstraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
        return errCode;
    }
    specificOAConstraintsJson = CreateJsonFromString(specificOAConstraints);
    if (specificOAConstraintsJson == nullptr || !IsObject(specificOAConstraintsJson)) {
        ACCOUNT_LOGE("Specific constraints json data parse failed code.");
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
        CJsonUnique globalOAConstraintsJson = nullptr;
        errCode = GetGlobalOAConstraintsFromFile(globalOAConstraintsJson);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Get globalOAConstraints from file failed!");
            return errCode;
        }
        std::vector<std::string> globalOAConstraintsList;
        GetDataByType<std::vector<std::string>>(globalOAConstraintsJson, constraint, globalOAConstraintsList);

        ConstraintSourceTypeInfo constraintSourceTypeInfo;
        for (auto it = globalOAConstraintsList.begin(); it != globalOAConstraintsList.end(); it++) {
            int32_t localId = 0;
            if (!StrToInt(*it, localId)) {
                ACCOUNT_LOGE("Convert localId failed");
                continue;
            }
            if (localId == deviceOwnerId) {
                constraintSourceTypeInfo.localId = localId;
                constraintSourceTypeInfo.typeInfo = ConstraintSourceType::CONSTRAINT_TYPE_DEVICE_OWNER;
                globalSourceList.push_back(constraintSourceTypeInfo);
            } else {
                constraintSourceTypeInfo.localId = localId;
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
        CJsonUnique specificOAConstraintsJson = nullptr;
        errCode = GetSpecificOAConstraintsFromFile(specificOAConstraintsJson);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Get specificOAConstraints from file failed!");
            return errCode;
        }
        cJSON *specificOAConstraintsInfo = nullptr;
        GetDataByType<CJson *>(specificOAConstraintsJson, std::to_string(id), specificOAConstraintsInfo);
        std::vector<std::string> specificConstraintSource;
        GetDataByType<std::vector<std::string>>(specificOAConstraintsInfo, constraint, specificConstraintSource);
        ConstraintSourceTypeInfo constraintSourceTypeInfo;
        for (auto it = specificConstraintSource.begin(); it != specificConstraintSource.end(); it++) {
            int32_t localId = 0;
            if (!StrToInt(*it, localId)) {
                ACCOUNT_LOGE("Convert localId failed");
                continue;
            }
            if (localId == deviceOwnerId) {
                constraintSourceTypeInfo.localId = localId;
                constraintSourceTypeInfo.typeInfo = ConstraintSourceType::CONSTRAINT_TYPE_DEVICE_OWNER;
                specificSourceList.push_back(constraintSourceTypeInfo);
            } else {
                constraintSourceTypeInfo.localId = localId;
                constraintSourceTypeInfo.typeInfo = ConstraintSourceType::CONSTRAINT_TYPE_PROFILE_OWNER;
                specificSourceList.push_back(constraintSourceTypeInfo);
            }
        }
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveAccountListToFile(const CJsonUnique &accountListJson)
{
    std::lock_guard<std::mutex> lock(accountListFileLock_);
    std::string strValue = PackJsonToString(accountListJson);
    ErrCode result =
        accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_LIST_FILE_JSON_PATH, strValue);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Cannot save save account list file content!");
        return result;
    }
#ifdef ENABLE_FILE_WATCHER
    accountFileWatcherMgr_.AddAccountInfoDigest(strValue, Constants::ACCOUNT_LIST_FILE_JSON_PATH);
#endif // ENABLE_FILE_WATCHER
    ACCOUNT_LOGD("Save account list file succeed!");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveBaseOAConstraintsToFile(const CJsonUnique &baseOAConstraints)
{
    std::lock_guard<std::mutex> lock(baseOAConstraintsFileLock_);
    std::string strValue = PackJsonToString(baseOAConstraints);
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(
        Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH, strValue);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Cannot save base osaccount constraints file content!");
        return result;
    }
#ifdef ENABLE_FILE_WATCHER
    accountFileWatcherMgr_.AddAccountInfoDigest(
        strValue, Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH);
#endif // ENABLE_FILE_WATCHER
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveGlobalOAConstraintsToFile(const CJsonUnique &globalOAConstraints)
{
    std::lock_guard<std::mutex> lock(globalOAConstraintsFileLock_);
    std::string strValue = PackJsonToString(globalOAConstraints);
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(
        Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH, strValue);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Cannot save global osAccount constraints file content!");
        return result;
    }
#ifdef ENABLE_FILE_WATCHER
    accountFileWatcherMgr_.AddAccountInfoDigest(
        strValue, Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH);
#endif // ENABLE_FILE_WATCHER
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveSpecificOAConstraintsToFile(const CJsonUnique &specificOAConstraints)
{
    std::lock_guard<std::mutex> lock(specificOAConstraintsFileLock_);
    std::string strValue = PackJsonToString(specificOAConstraints);
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(
        Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH, strValue);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Cannot save specific osAccount constraints file content!");
        return result;
    }
#ifdef ENABLE_FILE_WATCHER
    accountFileWatcherMgr_.AddAccountInfoDigest(
        strValue, Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH);
#endif // ENABLE_FILE_WATCHER
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetDeviceOwnerId(int &deviceOwnerId)
{
    CJsonUnique globalOAConstraintsJson = nullptr;
    ErrCode result = GetGlobalOAConstraintsFromFile(globalOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get global json data from file failed!");
        return result;
    }
    GetDataByType<int>(globalOAConstraintsJson, DEVICE_OWNER_ID, deviceOwnerId);
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::UpdateDeviceOwnerId(const int deviceOwnerId)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    CJsonUnique globalOAConstraintsJson = nullptr;
    ErrCode result = GetGlobalOAConstraintsFromFile(globalOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get global json data from file failed!");
        return result;
    }
    AddIntToJson(globalOAConstraintsJson, DEVICE_OWNER_ID, deviceOwnerId);
    return SaveGlobalOAConstraintsToFile(globalOAConstraintsJson);
}

ErrCode OsAccountControlFileManager::SetDefaultActivatedOsAccount(const int32_t id)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    CJsonUnique accountListJson = nullptr;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get account list failed!");
        return result;
    }
    AddIntToJson(accountListJson, DEFAULT_ACTIVATED_ACCOUNT_ID, id);
    return SaveAccountListToFileAndDataBase(accountListJson);
}

ErrCode OsAccountControlFileManager::GetDefaultActivatedOsAccount(int32_t &id)
{
    CJsonUnique accountListJsonData = nullptr;
    ErrCode result = GetAccountListFromFile(accountListJsonData);
    if (result != ERR_OK) {
        return result;
    }
    GetDataByType<int>(accountListJsonData, DEFAULT_ACTIVATED_ACCOUNT_ID, id);
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveAccountListToFileAndDataBase(const CJsonUnique &accountListJson)
{
#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    osAccountDataBaseOperator_->UpdateOsAccountIDListInDatabase(accountListJson);
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
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
    if ((photo != USER_PHOTO_FILE_JPG_NAME) && (photo != USER_PHOTO_FILE_PNG_NAME)
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
    if (photo == USER_PHOTO_FILE_JPG_NAME) {
        photo = USER_PHOTO_BASE_JPG_HEAD + osAccountPhotoOperator_->EnCode(byteStr.c_str(), byteStr.length());
    } else {
        photo = USER_PHOTO_BASE_PNG_HEAD + osAccountPhotoOperator_->EnCode(byteStr.c_str(), byteStr.length());
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
    ErrCode errCode = accountFileOperator_->InputFileByPathAndContentWithTransaction(path, photo);
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

bool OsAccountControlFileManager::CheckConstraints(const std::vector<std::string> &constraints)
{
    return osAccountFileOperator_->CheckConstraints(constraints);
}

ErrCode OsAccountControlFileManager::IsAllowedCreateAdmin(bool &isAllowedCreateAdmin)
{
    return osAccountFileOperator_->IsAllowedCreateAdmin(isAllowedCreateAdmin);
}

ErrCode OsAccountControlFileManager::GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
    int &createdOsAccountNum)
{
#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    return osAccountDataBaseOperator_->GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
#else
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
}

ErrCode OsAccountControlFileManager::GetSerialNumberFromDatabase(const std::string& storeID,
    int64_t &serialNumber)
{
#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    return osAccountDataBaseOperator_->GetSerialNumberFromDatabase(storeID, serialNumber);
#else
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
}

ErrCode OsAccountControlFileManager::GetMaxAllowCreateIdFromDatabase(const std::string& storeID,
    int &id)
{
#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    return osAccountDataBaseOperator_->GetMaxAllowCreateIdFromDatabase(storeID, id);
#else
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
}

ErrCode OsAccountControlFileManager::GetOsAccountFromDatabase(const std::string& storeID,
    const int id, OsAccountInfo &osAccountInfo)
{
#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    return osAccountDataBaseOperator_->GetOsAccountFromDatabase(storeID, id, osAccountInfo);
#else
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
}

ErrCode OsAccountControlFileManager::GetOsAccountListFromDatabase(const std::string& storeID,
    std::vector<OsAccountInfo> &osAccountList)
{
#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    return osAccountDataBaseOperator_->GetOsAccountListFromDatabase(storeID, osAccountList);
#else
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
}

static std::string GetDomainBoundFlagPath(const int32_t localId)
{
    return Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(localId) + Constants::PATH_SEPARATOR +
        Constants::IS_DOMAIN_BOUND_COMPLETED_FILE_NAME;
}

ErrCode OsAccountControlFileManager::SetDomainBoundFlag(
    const int32_t localId, const bool isBoundCompleted, const DomainAccountInfo domainInfo)
{
    std::string flagFilePath = GetDomainBoundFlagPath(localId);
    if (isBoundCompleted) {
        return accountFileOperator_->DeleteFile(flagFilePath);
    }
    auto jsonObj = ToJson(domainInfo);
    if (!jsonObj) {
        ACCOUNT_LOGE("Domain account info to json failed.");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    std::string jsonStr = PackJsonToString(jsonObj);
    ErrCode ret = accountFileOperator_->InputFileByPathAndContent(flagFilePath, jsonStr);
    if (ret != ERR_OK) {
        accountFileOperator_->DeleteFile(flagFilePath);
        ACCOUNT_LOGE("Set domain bound completed flag failed, ret = %{public}d.", ret);
    }
    return ret;
}

ErrCode OsAccountControlFileManager::GetDomainBoundFlag(
    const int32_t localId, bool &isBoundCompleted, DomainAccountInfo &domainInfo)
{
    isBoundCompleted = false;
    domainInfo.Clear();
    std::string flagFilePath = GetDomainBoundFlagPath(localId);
    std::string jsonStr;
    ErrCode ret = accountFileOperator_->GetFileContentByPath(flagFilePath, jsonStr);
    if (ret == ERR_OSACCOUNT_SERVICE_FILE_FIND_FILE_ERROR) {
        isBoundCompleted = true;
        return ERR_OK;
    } else if (ret != ERR_OK) {
        ACCOUNT_LOGE("Get domain bound completed flag failed, ret = %{public}d.", ret);
        return ret;
    }
    auto jsonObj = CreateJsonFromString(jsonStr);
    if (!jsonObj) {
        ACCOUNT_LOGE("Get domain account info from json failed.");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    FromJson(jsonObj.get(), domainInfo);
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

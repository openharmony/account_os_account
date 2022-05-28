/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include <sstream>
#include <sys/types.h>
#ifdef WITH_SELINUX
#include <policycoreutils.h>
#endif // WITH_SELINUX
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#include "os_account_interface.h"

namespace OHOS {
namespace AccountSA {
namespace {
bool GetValidAccountID(const std::string& dirName, std::int32_t& accountID)
{
    // check length first
    if (dirName.empty() || dirName.size() > Constants::MAX_USER_ID_LENGTH) {
        return false;
    }

    for (char c : dirName) {
        if (c < '0' || c > '9') {  // check whether it is digit
            return false;
        }
    }

    // convert to osaccount id
    std::stringstream sstream;
    sstream << dirName;
    sstream >> accountID;
    return (accountID >= Constants::ADMIN_LOCAL_ID && accountID <= Constants::MAX_USER_ID);
}
}

OsAccountControlFileManager::OsAccountControlFileManager()
{
    accountFileOperator_ = std::make_shared<AccountFileOperator>();
    osAccountDataBaseOperator_ = std::make_shared<OsAccountDatabaseOperator>();
    osAccountFileOperator_ = std::make_shared<OsAccountFileOperator>();
    osAccountPhotoOperator_ = std::make_shared<OsAccountPhotoOperator>();
}
OsAccountControlFileManager::~OsAccountControlFileManager()
{}
void OsAccountControlFileManager::Init()
{
    ACCOUNT_LOGI("OsAccountControlFileManager Init start");
    osAccountDataBaseOperator_->Init();
    osAccountFileOperator_->Init();
    if (!accountFileOperator_->IsExistFile(Constants::ACCOUNT_LIST_FILE_JSON_PATH) ||
        !accountFileOperator_->IsJsonFormat(Constants::ACCOUNT_LIST_FILE_JSON_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account list, create!");
        RecoverAccountListJsonFile();
#ifdef WITH_SELINUX
        Restorecon(Constants::ACCOUNT_LIST_FILE_JSON_PATH.c_str());
#endif // WITH_SELINUX
    }
    ACCOUNT_LOGI("OsAccountControlFileManager Init end");
}

void OsAccountControlFileManager::BuildAndSaveAccountListJsonFile(const std::vector<std::string>& accounts)
{
    ACCOUNT_LOGI("enter.");
    Json accountList = Json {
        {Constants::ACCOUNT_LIST, accounts},
        {Constants::COUNT_ACCOUNT_NUM, accounts.size()},
        {Constants::MAX_ALLOW_CREATE_ACCOUNT_ID, Constants::MAX_USER_ID},
        {Constants::SERIAL_NUMBER_NUM, Constants::SERIAL_NUMBER_NUM_START},
        {Constants::IS_SERIAL_NUMBER_FULL, Constants::IS_SERIAL_NUMBER_FULL_INIT_VALUE},
    };
    SaveAccountListToFile(accountList);
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

ErrCode OsAccountControlFileManager::GetOsAccountList(std::vector<OsAccountInfo> &osAccountList)
{
    ACCOUNT_LOGI("OsAccountControlFileManager GetOsAccountList  start");
    osAccountList.clear();
    Json accountListJson;
    if (GetAccountListFromFile(accountListJson) != ERR_OK) {
        ACCOUNT_LOGE(
            "OsAccountControlFileManager GetOsAccountList ERR_OSACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR");
        return ERR_OSACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
    }
    const auto &jsonObjectEnd = accountListJson.end();
    std::vector<std::string> idList;
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        accountListJson, jsonObjectEnd, Constants::ACCOUNT_LIST, idList, OHOS::AccountSA::JsonType::ARRAY);
    if (!idList.empty()) {
        for (auto it : idList) {
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
    }
    ACCOUNT_LOGI("OsAccountControlFileManager GetOsAccountList  end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountControlFileManager GetOsAccountInfoById start");
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) +
                       Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    if (!accountFileOperator_->IsExistFile(path)) {
        ACCOUNT_LOGE("OsAccountControlFileManager GetOsAccountInfoById file does not exist err");
        return ERR_OSACCOUNT_SERVICE_CONTROL_SELECT_OS_ACCOUNT_ERROR;
    }
    std::string accountInfoStr;
    if (accountFileOperator_->GetFileContentByPath(path, accountInfoStr) != ERR_OK) {
        ACCOUNT_LOGE("OsAccountControlFileManager GetOsAccountInfoById file cannot get info err");
        return ERR_OSACCOUNT_SERVICE_CONTROL_SELECT_OS_ACCOUNT_ERROR;
    }
    osAccountInfo.FromJson(Json::parse(accountInfoStr, nullptr, false));
    ACCOUNT_LOGI("OsAccountControlFileManager GetOsAccountInfoById end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetConstraintsByType(
    const OsAccountType type, std::vector<std::string> &constraints)
{
    int typeInit = static_cast<int>(type);
    return osAccountFileOperator_->GetConstraintsByType(typeInit, constraints);
}

ErrCode OsAccountControlFileManager::UpdateAccountList(const std::string& idStr, bool isAdd)
{
    Json accountListJson;
    if (GetAccountListFromFile(accountListJson) != ERR_OK) {
        ACCOUNT_LOGE("get account list failed!");
        return ERR_OSACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
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

    if (SaveAccountListToFileAndDataBase(accountListJson) != ERR_OK) {
        ACCOUNT_LOGE("SaveAccountListToFileAndDataBase failed!");
        return ERR_OSACCOUNT_SERVICE_CONTROL_INSERT_OS_ACCOUNT_LIST_ERROR;
    }
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

    if (accountFileOperator_->InputFileByPathAndContent(path, accountInfoStr) != ERR_OK) {
        ACCOUNT_LOGE("OsAccountControlFileManager InsertOsAccount");
        return ERR_OSACCOUNT_SERVICE_CONTROL_INSERT_OS_ACCOUNT_FILE_ERROR;
    }
    osAccountDataBaseOperator_->InsertOsAccountIntoDataBase(osAccountInfo);

    if (osAccountInfo.GetLocalId() >= Constants::START_USER_ID) {
        return UpdateAccountList(osAccountInfo.GetPrimeKey(), true);
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::DelOsAccount(const int id)
{
    ACCOUNT_LOGI("enter");
    if (id <= Constants::START_USER_ID || id > Constants::MAX_USER_ID) {
        ACCOUNT_LOGE("invalid input id %{public}d to delete!", id);
        return ERR_OSACCOUNT_SERVICE_CONTROL_CANNOT_DELETE_ID_ERROR;
    }

    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id);
    if (accountFileOperator_->DeleteDirOrFile(path) != ERR_OK) {
        ACCOUNT_LOGE("OsAccountControlFileManager DelOsAccount delete dir error");
        return ERR_OSACCOUNT_SERVICE_CONTROL_DEL_OS_ACCOUNT_INFO_ERROR;
    }
    osAccountDataBaseOperator_->DelOsAccountFromDatabase(id);
    return UpdateAccountList(std::to_string(id), false);
}

ErrCode OsAccountControlFileManager::UpdateOsAccount(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountControlFileManager UpdateOsAccount start");
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

    if (accountFileOperator_->InputFileByPathAndContent(path, accountInfoStr) != ERR_OK) {
        return ERR_OSACCOUNT_SERVICE_CONTROL_UPDATE_FILE_ERROR;
    }

    // update in database
    if (osAccountInfo.GetLocalId() >= Constants::START_USER_ID) {
        osAccountDataBaseOperator_->UpdateOsAccountInDatabase(osAccountInfo);
    }

    ACCOUNT_LOGI("OsAccountControlFileManager UpdateOsAccount end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetMaxCreatedOsAccountNum(int &maxCreatedOsAccountNum)
{
    ACCOUNT_LOGI("OsAccountControlFileManager GetMaxCreatedOsAccountNum start");
    Json accountListJson;
    if (GetAccountListFromFile(accountListJson) != ERR_OK) {
        return ERR_OSACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
    }
    OHOS::AccountSA::GetDataByType<int>(accountListJson,
        accountListJson.end(),
        Constants::MAX_ALLOW_CREATE_ACCOUNT_ID,
        maxCreatedOsAccountNum,
        OHOS::AccountSA::JsonType::NUMBER);
    maxCreatedOsAccountNum -= Constants::START_USER_ID;
    ACCOUNT_LOGI("OsAccountControlFileManager GetMaxCreatedOsAccountNum end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetSerialNumber(int64_t &serialNumber)
{
    Json accountListJson;
    if (GetAccountListFromFile(accountListJson) != ERR_OK) {
        ACCOUNT_LOGE("GetSerialNumber get accountList error");
        return ERR_OSACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
    }
    OHOS::AccountSA::GetDataByType<int64_t>(accountListJson,
        accountListJson.end(),
        Constants::SERIAL_NUMBER_NUM,
        serialNumber,
        OHOS::AccountSA::JsonType::NUMBER);
    if (serialNumber == Constants::CARRY_NUM) {
        accountListJson[Constants::IS_SERIAL_NUMBER_FULL] = true;
        serialNumber = Constants::SERIAL_NUMBER_NUM_START;
    }
    bool isSerialNumberFull = false;
    OHOS::AccountSA::GetDataByType<bool>(accountListJson,
        accountListJson.end(),
        Constants::IS_SERIAL_NUMBER_FULL,
        isSerialNumberFull,
        OHOS::AccountSA::JsonType::BOOLEAN);
    if (isSerialNumberFull) {
        std::vector<OsAccountInfo> osAccountInfos;
        if (GetOsAccountList(osAccountInfos) != ERR_OK) {
            ACCOUNT_LOGE("GetSerialNumber get accountList error");
            return ERR_OSACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
        }
        while (serialNumber < Constants::CARRY_NUM) {
            bool exists = false;
            for (auto it = osAccountInfos.begin(); it != osAccountInfos.end(); it++) {
                if (it->GetSerialNumber() ==
                    Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN * Constants::CARRY_NUM + serialNumber) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                break;
            }
            serialNumber++;
            serialNumber = (serialNumber == Constants::CARRY_NUM) ? Constants::SERIAL_NUMBER_NUM_START : serialNumber;
        }
    }
    accountListJson[Constants::SERIAL_NUMBER_NUM] = serialNumber + 1;
    if (SaveAccountListToFileAndDataBase(accountListJson) != ERR_OK) {
        return ERR_OSACCOUNT_SERVICE_CONTROL_INSERT_OS_ACCOUNT_LIST_ERROR;
    }
    serialNumber = serialNumber + Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN * Constants::CARRY_NUM;
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetAllowCreateId(int &id)
{
    Json accountListJson;
    if (GetAccountListFromFile(accountListJson) != ERR_OK) {
        ACCOUNT_LOGE("GetAllowCreateId get accountList error");
        return ERR_OSACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
    }
    int countCreatedNum = 0;
    auto jsonEnd = accountListJson.end();
    OHOS::AccountSA::GetDataByType<int>(
        accountListJson, jsonEnd, Constants::COUNT_ACCOUNT_NUM, countCreatedNum, OHOS::AccountSA::JsonType::NUMBER);
    if (countCreatedNum >= Constants::MAX_USER_ID - Constants::START_USER_ID) {
        ACCOUNT_LOGE("GetAllowCreateId cannot create more account error");
        return ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR;
    }
    std::vector<std::string> accountIdList;
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        accountListJson, jsonEnd, Constants::ACCOUNT_LIST, accountIdList, OHOS::AccountSA::JsonType::ARRAY);
    id = Constants::START_USER_ID + 1;
    while (std::find(accountIdList.begin(), accountIdList.end(), std::to_string(id)) != accountIdList.end() &&
           id != Constants::MAX_USER_ID + 1) {
        id++;
    }
    if (id == Constants::MAX_USER_ID + 1) {
        id = -1;
        return ERR_OSACCOUNT_SERVICE_CONTROL_SELECT_CAN_USE_ID_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetAccountListFromFile(Json &accountListJson)
{
    ACCOUNT_LOGI("enter");
    accountListJson.clear();
    std::string accountList;
    std::lock_guard<std::mutex> lock(accountListFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(Constants::ACCOUNT_LIST_FILE_JSON_PATH,
        accountList);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_CONTROL_GET_ACCOUNT_LIST_ERROR;
    }
    accountListJson = Json::parse(accountList, nullptr, false);
    ACCOUNT_LOGI("end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveAccountListToFile(const Json &accountListJson)
{
    ACCOUNT_LOGI("enter!");
    std::lock_guard<std::mutex> lock(accountListFileLock_);
    if (accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_LIST_FILE_JSON_PATH,
        accountListJson.dump()) != ERR_OK) {
        ACCOUNT_LOGE("cannot save save account list file content!");
        return ERR_OSACCOUNT_SERVICE_CONTROL_SET_ACCOUNT_LIST_ERROR;
    }
    ACCOUNT_LOGI("save account list file succeed!");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveAccountListToFileAndDataBase(const Json &accountListJson)
{
    osAccountDataBaseOperator_->UpdateOsAccountIDListInDatabase(accountListJson);
    return SaveAccountListToFile(accountListJson);
}

ErrCode OsAccountControlFileManager::IsOsAccountExists(const int id, bool &isExists)
{
    ACCOUNT_LOGI("OsAccountControlFileManager IsOsAccountExists start");
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
    ACCOUNT_LOGI("OsAccountControlFileManager IsOsAccountExists path is %{public}d", isExists);
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetPhotoById(const int id, std::string &photo)
{
    std::string path =
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) + Constants::PATH_SEPARATOR + photo;
    std::string byteStr = "";
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(path, byteStr);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetPhotoById cannot find photo file error");
        return errCode;
    }
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
    std::string path = "";
    std::string subPhoto = "";
    if (photo.find(Constants::USER_PHOTO_BASE_JPG_HEAD) != std::string::npos) {
        path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) + Constants::PATH_SEPARATOR +
               Constants::USER_PHOTO_FILE_JPG_NAME;
        subPhoto = photo.substr(Constants::USER_PHOTO_BASE_JPG_HEAD.size());
    } else if (photo.find(Constants::USER_PHOTO_BASE_PNG_HEAD) != std::string::npos) {
        path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) + Constants::PATH_SEPARATOR +
               Constants::USER_PHOTO_FILE_PNG_NAME;
        subPhoto = photo.substr(Constants::USER_PHOTO_BASE_PNG_HEAD.size());
    } else {
        ACCOUNT_LOGE("SetPhotoById photo str error");
        return ERR_OSACCOUNT_SERVICE_CONTROL_PHOTO_STR_ERROR;
    }
    std::string bytePhoto = osAccountPhotoOperator_->DeCode(subPhoto);
    ErrCode errCode = accountFileOperator_->InputFileByPathAndContent(path, bytePhoto);
    if (errCode != ERR_OK) {
        return errCode;
    }
    return ERR_OK;
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
    return osAccountDataBaseOperator_->GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
}

ErrCode OsAccountControlFileManager::GetSerialNumberFromDatabase(const std::string& storeID,
    int64_t &serialNumber)
{
    return osAccountDataBaseOperator_->GetSerialNumberFromDatabase(storeID, serialNumber);
}

ErrCode OsAccountControlFileManager::GetMaxAllowCreateIdFromDatabase(const std::string& storeID,
    int &id)
{
    return osAccountDataBaseOperator_->GetMaxAllowCreateIdFromDatabase(storeID, id);
}

ErrCode OsAccountControlFileManager::GetOsAccountFromDatabase(const std::string& storeID,
    const int id, OsAccountInfo &osAccountInfo)
{
    return osAccountDataBaseOperator_->GetOsAccountFromDatabase(storeID, id, osAccountInfo);
}

ErrCode OsAccountControlFileManager::GetOsAccountListFromDatabase(const std::string& storeID,
    std::vector<OsAccountInfo> &osAccountList)
{
    return osAccountDataBaseOperator_->GetOsAccountListFromDatabase(storeID, osAccountList);
}
}  // namespace AccountSA
}  // namespace OHOS
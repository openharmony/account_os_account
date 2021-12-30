/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "account_log_wrapper.h"
#include "os_account_constants.h"
#include "os_account_standard_interface.h"

#include "os_account_control_file_manager.h"
namespace OHOS {
namespace AccountSA {
OsAccountControlFileManager::OsAccountControlFileManager()
{
    accountFileOperator_ = std::make_shared<AccountFileOperator>();
    osAccountFileOperator_ = std::make_shared<OsAccountFileOperator>();
    osAccountPhotoOperator_ = std::make_shared<OsAccountPhotoOperator>();
}
OsAccountControlFileManager::~OsAccountControlFileManager()
{}
void OsAccountControlFileManager::Init()
{
    ACCOUNT_LOGE("OsAccountControlFileManager Init start");
    osAccountFileOperator_->Init();
    if (!accountFileOperator_->IsExistFile(
            Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + Constants::USER_LIST_FILE_NAME)) {
        ACCOUNT_LOGE("OsAccountControlFileManager there is not have account list");
        std::vector<std::string> accountListt;
        Json accountList = Json {
            {Constants::ACCOUNT_LIST, accountListt},
            {Constants::COUNT_ACCOUNT_NUM, 0},
            {Constants::MAX_ALLOW_CREATE_ACCOUNT_NUM, Constants::MAX_USER_ID},
            {Constants::SERIAL_NUMBER_NUM, Constants::SERIAL_NUMBER_NUM_START},
            {Constants::IS_SERIAL_NUMBER_FULL, Constants::IS_SERIAL_NUMBER_FULL_INIT_VALUE},
        };
        SaveAccountList(accountList);
    }
    ACCOUNT_LOGE("OsAccountControlFileManager Init end");
}

ErrCode OsAccountControlFileManager::GetOsAccountList(std::vector<OsAccountInfo> &osAccountList)
{
    ACCOUNT_LOGE("OsAccountControlFileManager GetOsAccountList  start");
    osAccountList.clear();
    Json accountListJson;
    if (GetAccountList(accountListJson) != ERR_OK) {
        ACCOUNT_LOGE(
            "OsAccountControlFileManager GetOsAccountList  ERR_OS_ACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR");
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
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
    ACCOUNT_LOGE("OsAccountControlFileManager GetOsAccountList  end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGE("OsAccountControlFileManager GetOsAccountInfoById start");
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) +
                       Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    if (!accountFileOperator_->IsExistFile(path)) {
        ACCOUNT_LOGE("OsAccountControlFileManager GetOsAccountInfoById file donnot exists err");
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_SELECT_OS_ACCOUNT_ERROR;
    }
    std::string accountInfoStr;
    if (accountFileOperator_->GetFileContentByPath(path, accountInfoStr) != ERR_OK) {
        ACCOUNT_LOGE("OsAccountControlFileManager GetOsAccountInfoById file cannot get info err");
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_SELECT_OS_ACCOUNT_ERROR;
    }
    osAccountInfo.FromJson(Json::parse(accountInfoStr, nullptr, false));
    ACCOUNT_LOGE("OsAccountControlFileManager GetOsAccountInfoById end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetConstraintsByType(
    const OsAccountType type, std::vector<std::string> &constratins)
{
    int typeInit = static_cast<int>(type);
    return osAccountFileOperator_->GetConstraintsByType(typeInit, constratins);
}

ErrCode OsAccountControlFileManager::InsertOsAccount(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGE("OsAccountControlFileManager InsertOsAccount start");
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + osAccountInfo.GetPrimeKey() +
                       Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    if (osAccountInfo.GetLocalId() < Constants::ADMIN_LOCAL_ID || osAccountInfo.GetLocalId() > Constants::MAX_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_ID_CANNOT_CREATE_ERROR;
    }
    if (accountFileOperator_->IsExistFile(path)) {
        ACCOUNT_LOGE("OsAccountControlFileManagerInsertOsAccountControlFileManagerCreateAccountDir ERR");
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_INSERT_FILE_EXISTS_ERROR;
    }
    if (accountFileOperator_->InputFileByPathAndContent(path, osAccountInfo.ToString()) != ERR_OK) {
        ACCOUNT_LOGE("OsAccountControlFileManager InsertOsAccount");
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_INSERT_OS_ACCOUNT_FILE_ERROR;
    }
    if (osAccountInfo.GetLocalId() >= Constants::START_USER_ID) {
        Json accountListJson;
        if (GetAccountList(accountListJson) != ERR_OK) {
            ACCOUNT_LOGE("OsAccountControlFileManager get account List Err");
            return ERR_OS_ACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
        }
        std::vector<std::string> accountIdList;
        auto jsonEnd = accountListJson.end();
        OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
            accountListJson, jsonEnd, Constants::ACCOUNT_LIST, accountIdList, OHOS::AccountSA::JsonType::ARRAY);
        accountIdList.push_back(osAccountInfo.GetPrimeKey());
        accountListJson[Constants::ACCOUNT_LIST] = accountIdList;
        accountListJson[Constants::COUNT_ACCOUNT_NUM] = accountIdList.size();
        if (SaveAccountList(accountListJson) != ERR_OK) {
            ACCOUNT_LOGE("OsAccountControlFileManager save account List Err");
            return ERR_OS_ACCOUNT_SERVICE_CONTROL_INSERT_OS_ACCOUNT_LIST_ERROR;
        }
    }
    ACCOUNT_LOGE("OsAccountControlFileManager InsertOsAccount end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::DelOsAccount(const int id)
{
    ACCOUNT_LOGE("OsAccountControlFileManager DelOsAccount start");
    if (id <= Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_CANNOT_DELETE_ID_ERROR;
    }
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id);
    if (accountFileOperator_->DeleteDirOrFile(path) != ERR_OK) {
        ACCOUNT_LOGE("OsAccountControlFileManager DelOsAccount delete dir error");
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_DEL_OS_ACCOUNT_INFO_ERROR;
    }
    Json accountListJson;
    if (GetAccountList(accountListJson) != ERR_OK) {
        ACCOUNT_LOGE("OsAccountControlFileManager DelOsAccount GetAccountList error");
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
    }
    std::vector<std::string> accountIdList;
    auto jsonEnd = accountListJson.end();
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        accountListJson, jsonEnd, Constants::ACCOUNT_LIST, accountIdList, OHOS::AccountSA::JsonType::ARRAY);
    accountIdList.erase(
        std::remove(accountIdList.begin(), accountIdList.end(), std::to_string(id)), accountIdList.end());
    accountListJson[Constants::ACCOUNT_LIST] = accountIdList;
    accountListJson[Constants::COUNT_ACCOUNT_NUM] = accountIdList.size();
    if (SaveAccountList(accountListJson) != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_INSERT_OS_ACCOUNT_LIST_ERROR;
    }
    ACCOUNT_LOGE("OsAccountControlFileManager DelOsAccount end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::UpdateOsAccount(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGE("OsAccountControlFileManager UpdateOsAccount start");
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + osAccountInfo.GetPrimeKey() +
                       Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    if (!accountFileOperator_->IsExistFile(path)) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_UPDATE_FILE_NOT_EXISTS_ERROR;
    }
    if (accountFileOperator_->InputFileByPathAndContent(path, osAccountInfo.ToString()) != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_UPDATE_FILE_ERROR;
    }
    ACCOUNT_LOGE("OsAccountControlFileManager UpdateOsAccount end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetMaxCreatedOsAccountNum(int &maxCreatedOsAccountNum)
{
    ACCOUNT_LOGE("OsAccountControlFileManager GetMaxCreatedOsAccountNum start");
    Json accountListJson;
    if (GetAccountList(accountListJson) != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
    }
    OHOS::AccountSA::GetDataByType<int>(accountListJson,
        accountListJson.end(),
        Constants::MAX_ALLOW_CREATE_ACCOUNT_NUM,
        maxCreatedOsAccountNum,
        OHOS::AccountSA::JsonType::NUMBER);
    ACCOUNT_LOGE("OsAccountControlFileManager GetMaxCreatedOsAccountNum end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetSerialNumber(int64_t &serialNumber)
{
    Json accountListJson;
    if (GetAccountList(accountListJson) != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
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
            return ERR_OS_ACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
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
            serialNumber = serialNumber == Constants::CARRY_NUM ? Constants::SERIAL_NUMBER_NUM_START : serialNumber;
        }
    }
    accountListJson[Constants::SERIAL_NUMBER_NUM] = serialNumber + 1;
    if (SaveAccountList(accountListJson) != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_INSERT_OS_ACCOUNT_LIST_ERROR;
    }
    serialNumber = serialNumber + Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN * Constants::CARRY_NUM;
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetAllowCreateId(int &id)
{
    Json accountListJson;
    if (GetAccountList(accountListJson) != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
    }
    int countCreatedNum = 0;
    auto jsonEnd = accountListJson.end();
    OHOS::AccountSA::GetDataByType<int>(
        accountListJson, jsonEnd, Constants::COUNT_ACCOUNT_NUM, countCreatedNum, OHOS::AccountSA::JsonType::NUMBER);
    if (countCreatedNum >= Constants::MAX_USER_ID - Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR;
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
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_SELECT_CAN_USE_ID_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetAccountList(Json &accountListJson)
{
    ACCOUNT_LOGE("OsAccountControlFileManager GetAccountList start");
    accountListJson.clear();
    std::string accountList;
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + Constants::USER_LIST_FILE_NAME, accountList);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("OsAccountControlFileManager GetAccountList cannot get file content");
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_GET_ACCOUNT_LIST_ERROR;
    }
    accountListJson = Json::parse(accountList, nullptr, false);
    ACCOUNT_LOGE("OsAccountControlFileManager GetAccountList end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveAccountList(const Json &accountListJson)
{
    ACCOUNT_LOGE("OsAccountControlFileManager SaveAccountList start");
    std::string accountListPath =
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + Constants::USER_LIST_FILE_NAME;
    if (accountFileOperator_->InputFileByPathAndContent(accountListPath, accountListJson.dump()) != ERR_OK) {
        ACCOUNT_LOGE("OsAccountControlFileManager SaveAccountList cannot save file content");
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_SET_ACCOUNT_LIST_ERROR;
    }
    ACCOUNT_LOGE("OsAccountControlFileManager SaveAccountList end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::IsOsAccountExists(const int id, bool &isExists)
{
    ACCOUNT_LOGE("OsAccountControlFileManager IsOsAccountExists start");
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) +
                       Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    ACCOUNT_LOGE("OsAccountControlFileManager IsOsAccountExists path is %{public}s", path.c_str());
    isExists = accountFileOperator_->IsExistFile(path);
    ACCOUNT_LOGE("OsAccountControlFileManager IsOsAccountExists path is %{public}d", isExists);
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetPhotoById(const int id, std::string &photo)
{
    std::string path =
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) + Constants::PATH_SEPARATOR + photo;
    std::string byteStr = "";
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(path, byteStr);
    if (errCode != ERR_OK) {
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
    std::string type = "";
    std::string subPhoto = "";
    if (photo.find(Constants::USER_PHOTO_BASE_JPG_HEAD) != std::string::npos) {
        type = "image/jpeg";
        path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) + Constants::PATH_SEPARATOR +
               Constants::USER_PHOTO_FILE_JPG_NAME;
        subPhoto = photo.substr(Constants::USER_PHOTO_BASE_JPG_HEAD.size());
    } else if (photo.find(Constants::USER_PHOTO_BASE_PNG_HEAD) != std::string::npos) {
        type = "image/png";
        path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) + Constants::PATH_SEPARATOR +
               Constants::USER_PHOTO_FILE_PNG_NAME;
        subPhoto = photo.substr(Constants::USER_PHOTO_BASE_PNG_HEAD.size());
    } else {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_PHOTO_STR_ERROR;
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
ErrCode OsAccountControlFileManager::IsConstrarionsInTypeList(
    const std::vector<std::string> &constrains, bool &isExists)
{
    return osAccountFileOperator_->IsConstrarionsInTypeList(constrains, isExists);
}

ErrCode OsAccountControlFileManager::IsAllowedCreateAdmin(bool &isAllowedCreateAdmin)
{
    return osAccountFileOperator_->IsAllowedCreateAdmin(isAllowedCreateAdmin);
}
}  // namespace AccountSA
}  // namespace OHOS
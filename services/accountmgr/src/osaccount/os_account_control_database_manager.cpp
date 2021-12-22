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
#include "os_account_data_storage.h"

#include "os_account_control_database_manager.h"
namespace OHOS {
namespace AccountSA {
OsAccountControlDatabaseManager::OsAccountControlDatabaseManager()
{
    accountDataStorage_ = std::make_shared<OsAccountDataStorage>(
        Constants::APP_ID, Constants::STORE_ID, Constants::SYNC_OS_ACCOUNT_DATABSE);
    osAccountFileOperator_ = std::make_shared<OsAccountFileOperator>();
}
OsAccountControlDatabaseManager::~OsAccountControlDatabaseManager()
{}
void OsAccountControlDatabaseManager::Init()
{
    ACCOUNT_LOGE("OsAccountControlDatabaseManager Init start");
    osAccountFileOperator_->Init();
    bool isKeyExit = false;
    accountDataStorage_->IsKeyExists(Constants::ACCOUNT_LIST, isKeyExit);
    if (!isKeyExit) {
        std::vector<std::string> accountListt;
        Json accountList = Json {
            {Constants::ACCOUNT_LIST, accountListt},
            {Constants::COUNT_ACCOUNT_NUM, 0},
            {Constants::NOW_ALLOW_CREATE_ACCOUNT_NUM, Constants::START_USER_ID},
            {Constants::MAX_ALLOW_CREATE_ACCOUNT_NUM, Constants::MAX_USER_ID},
            {Constants::SERIAL_NUMBER_NUM, Constants::SERIAL_NUMBER_NUM_START},
        };
        SaveAccountList(accountList);
    }
    ACCOUNT_LOGE("OsAccountControlDatabaseManager Init end");
}

ErrCode OsAccountControlDatabaseManager::GetOsAccountList(std::vector<OsAccountInfo> &osAccountList)
{
    ACCOUNT_LOGE("OsAccountControlDatabaseManager GetOsAccountList  start");
    osAccountList.clear();
    std::map<std::string, std::shared_ptr<IAccountInfo>> osAccountMapInfos;
    ErrCode errCode = accountDataStorage_->LoadAllData(osAccountMapInfos);
    if (errCode != ERR_OK) {
        return errCode;
    }
    for (auto it = osAccountMapInfos.begin(); it != osAccountMapInfos.end(); it++) {
        osAccountList.push_back(*(std::static_pointer_cast<OsAccountInfo>(it->second)));
    }
    ACCOUNT_LOGE("OsAccountControlDatabaseManager GetOsAccountList  end");
    return ERR_OK;
}

ErrCode OsAccountControlDatabaseManager::GetOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGE("OsAccountControlDatabaseManager GetOsAccountInfoById start");
    return accountDataStorage_->GetAccountInfoById(std::to_string(id), osAccountInfo);
}

ErrCode OsAccountControlDatabaseManager::GetConstraintsByType(
    const OsAccountType type, std::vector<std::string> &constratins)
{
    int typeInit = static_cast<int>(type);
    return osAccountFileOperator_->GetConstraintsByType(typeInit, constratins);
}

ErrCode OsAccountControlDatabaseManager::InsertOsAccount(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGE("OsAccountControlDatabaseManager InsertOsAccount start");
    ErrCode errCode = accountDataStorage_->AddAccountInfo(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("OsAccountControlDatabaseManager insert ERR");
        return errCode;
    }
    if (osAccountInfo.GetLocalId() > Constants::START_USER_ID - 1) {
        ACCOUNT_LOGE("OsAccountControlDatabaseManager is ordinary account");
        Json accountListJson;
        if (GetAccountList(accountListJson) != ERR_OK) {
            ACCOUNT_LOGE("OsAccountControlDatabaseManager get account List Err");
            return ERR_OS_ACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
        }
        std::vector<std::string> accountIdList;
        auto jsonEnd = accountListJson.end();
        OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
            accountListJson, jsonEnd, Constants::ACCOUNT_LIST, accountIdList, OHOS::AccountSA::JsonType::ARRAY);
        ACCOUNT_LOGE("OsAccountControlDatabaseManager get account List size is %{public}zu", accountIdList.size());
        accountIdList.push_back(osAccountInfo.GetPrimeKey());
        accountListJson[Constants::ACCOUNT_LIST] = accountIdList;
        accountListJson[Constants::COUNT_ACCOUNT_NUM] = accountIdList.size();
        int maxId = Constants::MAX_USER_ID + Constants::START_USER_ID;
        int num = osAccountInfo.GetLocalId();
        num = num + 1;
        accountListJson[Constants::NOW_ALLOW_CREATE_ACCOUNT_NUM] = num > maxId ? Constants::START_USER_ID : num;
        if (SaveAccountList(accountListJson) != ERR_OK) {
            ACCOUNT_LOGE("OsAccountControlDatabaseManager save account List Err");
            return ERR_OS_ACCOUNT_SERVICE_CONTROL_INSERT_OS_ACCOUNT_LIST_ERROR;
        }
    }
    ACCOUNT_LOGE("OsAccountControlDatabaseManager InsertOsAccount end");
    return ERR_OK;
}

ErrCode OsAccountControlDatabaseManager::DelOsAccount(const int id)
{
    ACCOUNT_LOGE("OsAccountControlDatabaseManager DelOsAccount start");
    ErrCode errCode = accountDataStorage_->RemoveInfoByKey(std::to_string(id));
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("OsAccountControlDatabaseManager dele ERR");
        return errCode;
    }
    if (id > Constants::START_USER_ID - 1) {
        Json accountListJson;
        if (GetAccountList(accountListJson) != ERR_OK) {
            ACCOUNT_LOGE("OsAccountControlDatabaseManager DelOsAccount GetAccountList error");
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
    }
    ACCOUNT_LOGE("OsAccountControlDatabaseManager DelOsAccount end");
    return ERR_OK;
}

ErrCode OsAccountControlDatabaseManager::UpdateOsAccount(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGE("OsAccountControlDatabaseManager UpdateOsAccount start");
    ErrCode errCode = accountDataStorage_->SaveAccountInfo(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("OsAccountControlDatabaseManager update ERR");
        return errCode;
    }
    ACCOUNT_LOGE("OsAccountControlDatabaseManager UpdateOsAccount end");
    return ERR_OK;
}

ErrCode OsAccountControlDatabaseManager::GetMaxCreatedOsAccountNum(int &maxCreatedOsAccountNum)
{
    ACCOUNT_LOGE("OsAccountControlDatabaseManager GetMaxCreatedOsAccountNum start");
    Json accountListJson;
    if (GetAccountList(accountListJson) != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
    }
    OHOS::AccountSA::GetDataByType<int>(accountListJson,
        accountListJson.end(),
        Constants::COUNT_ACCOUNT_NUM,
        maxCreatedOsAccountNum,
        OHOS::AccountSA::JsonType::NUMBER);
    ACCOUNT_LOGE("OsAccountControlDatabaseManager GetMaxCreatedOsAccountNum end");
    return ERR_OK;
}

ErrCode OsAccountControlDatabaseManager::GetSerialNumber(int64_t &serialNumber)
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
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_DONNOT_HAVE_ALLOW_SERIAL_ERROR;
    }
    accountListJson[Constants::SERIAL_NUMBER_NUM] = serialNumber + 1;
    if (SaveAccountList(accountListJson) != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_INSERT_OS_ACCOUNT_LIST_ERROR;
    }
    serialNumber = serialNumber + Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN * Constants::CARRY_NUM;
    return ERR_OK;
}

ErrCode OsAccountControlDatabaseManager::GetAllowCreateId(int &id)
{
    Json accountListJson;
    if (GetAccountList(accountListJson) != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_GET_OS_ACCOUNT_LIST_ERROR;
    }
    int countCreatedNum = 0;
    auto jsonEnd = accountListJson.end();
    OHOS::AccountSA::GetDataByType<int>(
        accountListJson, jsonEnd, Constants::COUNT_ACCOUNT_NUM, countCreatedNum, OHOS::AccountSA::JsonType::NUMBER);
    if (countCreatedNum > Constants::MAX_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR;
    }
    std::vector<std::string> accountIdList;
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        accountListJson, jsonEnd, Constants::ACCOUNT_LIST, accountIdList, OHOS::AccountSA::JsonType::ARRAY);
    OHOS::AccountSA::GetDataByType<int>(
        accountListJson, jsonEnd, Constants::NOW_ALLOW_CREATE_ACCOUNT_NUM, id, OHOS::AccountSA::JsonType::NUMBER);
    bool findFlag = false;
    int maxId = Constants::START_USER_ID + Constants::MAX_USER_ID;
    for (; id <= maxId; id++) {
        if (accountIdList.end() == std::find(accountIdList.begin(), accountIdList.end(), std::to_string(id))) {
            findFlag = true;
            break;
        }
    }
    if (!findFlag) {
        for (id = Constants::START_USER_ID; id <= maxId; id++) {
            if (accountIdList.end() == std::find(accountIdList.begin(), accountIdList.end(), std::to_string(id))) {
                findFlag = true;
                break;
            }
        }
    }
    if (!findFlag) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_SELECT_CAN_USE_ID_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountControlDatabaseManager::GetAccountList(Json &accountListJson)
{
    ACCOUNT_LOGE("OsAccountControlDatabaseManager GetAccountList start");
    accountListJson.clear();
    std::string accountList;
    ErrCode errCode = accountDataStorage_->GetConfigById(Constants::ACCOUNT_LIST, accountList);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("OsAccountControlDatabaseManager GetAccountList cannot get file content");
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_GET_ACCOUNT_LIST_ERROR;
    }
    accountListJson = Json::parse(accountList, nullptr, false);
    ACCOUNT_LOGE("OsAccountControlDatabaseManager GetAccountList end");
    return ERR_OK;
}

ErrCode OsAccountControlDatabaseManager::SaveAccountList(const Json &accountListJson)
{
    ACCOUNT_LOGE("OsAccountControlDatabaseManager SaveAccountList start");
    ErrCode errCode;
    bool isKeyExit = false;
    accountDataStorage_->IsKeyExists(Constants::ACCOUNT_LIST, isKeyExit);
    if (isKeyExit) {
        errCode = accountDataStorage_->SavConfigInfo(Constants::ACCOUNT_LIST, accountListJson.dump());
    } else {
        errCode = accountDataStorage_->AddConfigInfo(Constants::ACCOUNT_LIST, accountListJson.dump());
    }
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("OsAccountControlDatabaseManager GetAccountList cannot get file content");
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_SET_ACCOUNT_LIST_ERROR;
    }
    ACCOUNT_LOGE("OsAccountControlDatabaseManager SaveAccountList end");
    return ERR_OK;
}

ErrCode OsAccountControlDatabaseManager::IsOsAccountExists(const int id, bool &isExists)
{
    ACCOUNT_LOGE("OsAccountControlDatabaseManager IsOsAccountExists start");
    accountDataStorage_->IsKeyExists(std::to_string(id), isExists);
    return ERR_OK;
}

ErrCode OsAccountControlDatabaseManager::GetPhotoById(const int id, std::string &photo)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
    photo = osAccountInfo.GetPhoto();
    return ERR_OK;
}

ErrCode OsAccountControlDatabaseManager::SetPhotoById(const int id, const std::string &photo)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
    osAccountInfo.SetPhoto(photo);
    errCode = UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
    return ERR_OK;
}

ErrCode OsAccountControlDatabaseManager::GetIsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    return osAccountFileOperator_->GetIsMultiOsAccountEnable(isMultiOsAccountEnable);
}

ErrCode OsAccountControlDatabaseManager::IsConstrarionsInTypeList(
    const std::vector<std::string> &constrains, bool &isExists)
{
    return osAccountFileOperator_->IsConstrarionsInTypeList(constrains, isExists);
}

ErrCode OsAccountControlDatabaseManager::IsAllowedCreateAdmin(bool &isAllowedCreateAdmin)
{
    return osAccountFileOperator_->IsAllowedCreateAdmin(isAllowedCreateAdmin);
}
}  // namespace AccountSA
}  // namespace OHOS
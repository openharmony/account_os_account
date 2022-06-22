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
#include "os_account_database_operator.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#include "os_account_data_storage.h"
#include "parameter.h"

namespace OHOS {
namespace AccountSA {
OsAccountDatabaseOperator::OsAccountDatabaseOperator()
    : accountDataStorage_(nullptr), storeID_("")
{}
OsAccountDatabaseOperator::~OsAccountDatabaseOperator()
{}
void OsAccountDatabaseOperator::Init()
{
    char udid[Constants::DEVICE_UUID_LENGTH] = {0};
    int ret = GetDevUdid(udid, Constants::DEVICE_UUID_LENGTH);
    if (ret != 0) {
        ACCOUNT_LOGE("GetDevUdid failed! ret = %{public}d.", ret);
        return;
    }
    storeID_ = std::string(udid);
}

bool OsAccountDatabaseOperator::InnerInit()
{
    if (accountDataStorage_ == nullptr) {
        ACCOUNT_LOGI("database operator inner init, enter!");
        accountDataStorage_ = std::make_shared<OsAccountDataStorage>(
            Constants::APP_ID, storeID_, Constants::SYNC_OS_ACCOUNT_DATABASE);
        if (accountDataStorage_ == nullptr) {
            ACCOUNT_LOGE("accountDataStorage_ is still nullptr.");
            return false;
        }

        if (!accountDataStorage_->IsKeyExists(Constants::ACCOUNT_LIST)) {
            ACCOUNT_LOGI("database operator inner init, create account list.");
            std::vector<std::string> accountListVec;
            Json accountList = Json {
                {Constants::ACCOUNT_LIST, accountListVec},
                {Constants::COUNT_ACCOUNT_NUM, 0},
                {Constants::MAX_ALLOW_CREATE_ACCOUNT_ID, Constants::MAX_USER_ID},
                {Constants::SERIAL_NUMBER_NUM, Constants::SERIAL_NUMBER_NUM_START},
            };
            SaveAccountListToDatabase(accountList);
        }
    }
    return true;
}

ErrCode OsAccountDatabaseOperator::GetOsAccountListFromDatabase(const std::string& storeID,
                                                                std::vector<OsAccountInfo> &osAccountList)
{
    osAccountList.clear();
    if (!InnerInit()) {
        ACCOUNT_LOGE("InnerInit failed!");
        return ERR_ACCOUNT_COMMON_NOT_INIT_ERROR;
    }

    std::map<std::string, std::shared_ptr<IAccountInfo>> osAccountMapInfos;
    ErrCode errCode = ERR_OK;
    if (storeID.empty()) {
        errCode = accountDataStorage_->LoadAllData(osAccountMapInfos);
    } else {
        std::shared_ptr<AccountDataStorage> storagePtr = std::make_shared<OsAccountDataStorage>(
            Constants::APP_ID, storeID, Constants::SYNC_OS_ACCOUNT_DATABASE);
        if (storagePtr == nullptr) {
            ACCOUNT_LOGE("storagePtr is still nullptr, storeID %{public}s.", storeID.c_str());
            return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
        }
        errCode = storagePtr->LoadAllData(osAccountMapInfos);
    }

    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("LoadAllData failed! storeID %{public}s.", storeID.c_str());
        return errCode;
    }

    for (auto it = osAccountMapInfos.begin(); it != osAccountMapInfos.end(); it++) {
        OsAccountInfo curOsInfo = *(std::static_pointer_cast<OsAccountInfo>(it->second));
        if (curOsInfo.GetLocalId() >= Constants::START_USER_ID) {
            osAccountList.push_back(curOsInfo);
        }
    }
    return ERR_OK;
}

void OsAccountDatabaseOperator::InsertOsAccountIntoDataBase(const OsAccountInfo &osAccountInfo)
{
    if (!InnerInit()) {
        ACCOUNT_LOGE("InnerInit failed! target localID %{public}d!", osAccountInfo.GetLocalId());
        return;
    }

    if (osAccountInfo.GetLocalId() < Constants::START_USER_ID) {
        ACCOUNT_LOGI("target os account id %{public}d will not be saved in database!", osAccountInfo.GetLocalId());
        return;
    }

    ErrCode errCode = accountDataStorage_->AddAccountInfo(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("AddAccountInfo failed, error code %{public}d, target id %{public}d.",
            errCode, osAccountInfo.GetLocalId());
        return;
    }
    ACCOUNT_LOGI("insert account %{public}d to database succeed.", osAccountInfo.GetLocalId());
}

void OsAccountDatabaseOperator::DelOsAccountFromDatabase(const int id)
{
    if (!InnerInit()) {
        ACCOUNT_LOGE("InnerInit failed! id %{public}d!", id);
        return;
    }

    ErrCode errCode = accountDataStorage_->RemoveValueFromKvStore(std::to_string(id));
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("delete os account %{public}d from database failed! error code %{public}d.", id, errCode);
    } else {
        ACCOUNT_LOGI("delete os account %{public}d from database succeed!", id);
    }
}

void OsAccountDatabaseOperator::UpdateOsAccountInDatabase(const OsAccountInfo &osAccountInfo)
{
    if (!InnerInit()) {
        ACCOUNT_LOGE("InnerInit failed! local id %{public}d!", osAccountInfo.GetLocalId());
        return;
    }

    ErrCode errCode = accountDataStorage_->SaveAccountInfo(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("update os account info in database for account %{public}d failed! errCode = %{public}d.",
            osAccountInfo.GetLocalId(), errCode);
    } else {
        ACCOUNT_LOGI("update os account info in database for account %{public}d succeed!", osAccountInfo.GetLocalId());
    }
}

ErrCode OsAccountDatabaseOperator::GetOsAccountFromDatabase(const std::string& storeID,
                                                            const int id,
                                                            OsAccountInfo &osAccountInfo)
{
    if (!InnerInit()) {
        ACCOUNT_LOGE("InnerInit failed! storeID %{public}s id %{public}d!", storeID.c_str(), id);
        return ERR_ACCOUNT_COMMON_NOT_INIT_ERROR;
    }

    if (storeID.empty()) {
        return accountDataStorage_->GetAccountInfoById(std::to_string(id), osAccountInfo);
    }

    std::shared_ptr<AccountDataStorage> storagePtr = std::make_shared<OsAccountDataStorage>(
        Constants::APP_ID, storeID, Constants::SYNC_OS_ACCOUNT_DATABASE);
    if (storagePtr == nullptr) {
        ACCOUNT_LOGE("storagePtr is nullptr, for other storeID %{public}s, id %{public}d.", storeID.c_str(), id);
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    return storagePtr->GetAccountInfoById(std::to_string(id), osAccountInfo);
}

ErrCode OsAccountDatabaseOperator::GetCreatedOsAccountNumFromDatabase(
    const std::string& storeID, int &createdOsAccountNum)
{
    Json accountListJson;
    ErrCode ret = GetAccountListFromStoreID(storeID, accountListJson);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("get account list from database failed, storeID %{public}s.", storeID.c_str());
        return ret;
    }
    OHOS::AccountSA::GetDataByType<int>(accountListJson, accountListJson.end(),
        Constants::COUNT_ACCOUNT_NUM, createdOsAccountNum, OHOS::AccountSA::JsonType::NUMBER);
    return ERR_OK;
}

void OsAccountDatabaseOperator::UpdateOsAccountIDListInDatabase(const Json &accountListJson)
{
    if (SaveAccountListToDatabase(accountListJson) != ERR_OK) {
        ACCOUNT_LOGE("update os account id list to database failed.");
        return;
    }
    ACCOUNT_LOGD("update os account id list to database succeed.");
}

ErrCode OsAccountDatabaseOperator::GetSerialNumberFromDatabase(
    const std::string& storeID, int64_t &serialNumber)
{
    Json accountListJson;
    ErrCode ret = GetAccountListFromStoreID(storeID, accountListJson);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("get serial number from database failed! err %{public}d, storeID %{public}s.",
            ret, storeID.c_str());
        return ret;
    }
    OHOS::AccountSA::GetDataByType<int>(accountListJson, accountListJson.end(),
        Constants::SERIAL_NUMBER_NUM, serialNumber, OHOS::AccountSA::JsonType::NUMBER);
    return ERR_OK;
}

ErrCode OsAccountDatabaseOperator::GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id)
{
    Json accountListJson;
    ErrCode ret = GetAccountListFromStoreID(storeID, accountListJson);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("get max allow created id from database failed. err %{public}d, storeID %{public}s.",
            ret, storeID.c_str());
        return ret;
    }
    OHOS::AccountSA::GetDataByType<int>(accountListJson, accountListJson.end(),
        Constants::MAX_ALLOW_CREATE_ACCOUNT_ID, id, OHOS::AccountSA::JsonType::NUMBER);
    return ERR_OK;
}

ErrCode OsAccountDatabaseOperator::GetAccountListFromStoreID(
    const std::string& storeID, Json &accountListJson)
{
    accountListJson.clear();
    if (!InnerInit()) {
        ACCOUNT_LOGE("InnerInit failed! storeID %{public}s!", storeID.c_str());
        return ERR_ACCOUNT_COMMON_NOT_INIT_ERROR;
    }

    std::string accountList;
    ErrCode errCode = ERR_OK;
    if (storeID.empty()) {
        errCode = accountDataStorage_->GetValueFromKvStore(Constants::ACCOUNT_LIST, accountList);
    } else {
        std::shared_ptr<AccountDataStorage> storagePtr = std::make_shared<OsAccountDataStorage>(
            Constants::APP_ID, storeID, Constants::SYNC_OS_ACCOUNT_DATABASE);
        if (storagePtr == nullptr) {
            ACCOUNT_LOGE("storagePtr is nullptr, for other storeID %{public}s.", storeID.c_str());
            return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
        }
        errCode = storagePtr->GetValueFromKvStore(Constants::ACCOUNT_LIST, accountList);
    }

    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get account list info from database failed! storeID %{public}s.", storeID.c_str());
        return ERR_OSACCOUNT_SERVICE_CONTROL_GET_ACCOUNT_LIST_ERROR;
    }
    accountListJson = Json::parse(accountList, nullptr, false);
    return ERR_OK;
}

ErrCode OsAccountDatabaseOperator::SaveAccountListToDatabase(const Json &accountListJson)
{
    if (!InnerInit()) {
        ACCOUNT_LOGE("InnerInit failed!");
        return ERR_ACCOUNT_COMMON_NOT_INIT_ERROR;
    }
    ErrCode errCode = accountDataStorage_->PutValueToKvStore(Constants::ACCOUNT_LIST, accountListJson.dump());
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Save or Add config info to database failed! errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_CONTROL_SET_ACCOUNT_LIST_ERROR;
    }
    ACCOUNT_LOGD("save or add account list info to database succeed!");
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
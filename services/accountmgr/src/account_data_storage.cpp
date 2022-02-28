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
#include "account_data_storage.h"
#include <memory>
#include <thread>
#include <unistd.h>
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
const int32_t MAX_TIMES = 10;
const int32_t SLEEP_INTERVAL = 100 * 1000;

AccountDataStorage::AccountDataStorage(const std::string &appId, const std::string &storeId, const bool &autoSync)
{
    appId_.appId = appId;
    storeId_.storeId = storeId;
    autoSync_ = autoSync;
}

AccountDataStorage::~AccountDataStorage()
{
    if (kvStorePtr_ != nullptr) {
        dataManager_.CloseKvStore(appId_, kvStorePtr_);
    }
}

void AccountDataStorage::TryTwice(const std::function<DistributedKv::Status()> &func) const
{
    ACCOUNT_LOGI("enter");

    OHOS::DistributedKv::Status status = func();
    if (status == OHOS::DistributedKv::Status::IPC_ERROR) {
        status = func();
        ACCOUNT_LOGE("distribute database ipc error and try again, status = %{public}d", status);
    }

    ACCOUNT_LOGI("end, status = %{public}d", status);
}

OHOS::DistributedKv::Status AccountDataStorage::GetKvStore()
{
    ACCOUNT_LOGI("enter");

    OHOS::DistributedKv::Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = autoSync_,
        .kvStoreType = OHOS::DistributedKv::KvStoreType::SINGLE_VERSION
    };

    auto status = dataManager_.GetSingleKvStore(options, appId_, storeId_, kvStorePtr_);
    if (kvStorePtr_ == nullptr) {
        ACCOUNT_LOGI("kvStorePtr_ is nullptr");
    } else {
        ACCOUNT_LOGI("kvStorePtr_ is not nullptr");
    }

    ACCOUNT_LOGI("end, status = %{public}d", status);

    return status;
}

bool AccountDataStorage::CheckKvStore()
{
    ACCOUNT_LOGI("enter");
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);

    if (kvStorePtr_ != nullptr) {
        return true;
    }
    int32_t tryTimes = MAX_TIMES;
    while (tryTimes > 0) {
        OHOS::DistributedKv::Status status = GetKvStore();
        if (status == OHOS::DistributedKv::Status::SUCCESS && kvStorePtr_ != nullptr) {
            return true;
        }

        ACCOUNT_LOGI("tryTimes = %{public}d status = %{public}d.", tryTimes, status);
        usleep(SLEEP_INTERVAL);
        tryTimes--;
    }

    ACCOUNT_LOGI("end");

    return kvStorePtr_ != nullptr;
}

bool AccountDataStorage::ResetKvStore()
{
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    kvStorePtr_ = nullptr;
    OHOS::DistributedKv::Status status = GetKvStore();
    if (status == OHOS::DistributedKv::Status::SUCCESS && kvStorePtr_ != nullptr) {
        ACCOUNT_LOGI("ResetKvStore succeed!");
        return true;
    }

    ACCOUNT_LOGE("ResetKvStore failed!");

    return false;
}

ErrCode AccountDataStorage::LoadAllData(std::map<std::string, std::shared_ptr<IAccountInfo>> &infos)
{
    ACCOUNT_LOGI("enter");

    if (!CheckKvStore()) {
        ACCOUNT_LOGE("kvStore is nullptr");
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }

    OHOS::DistributedKv::Status status;
    std::vector<OHOS::DistributedKv::Entry> allEntries;
    TryTwice([this, &status, &allEntries] {
        status = GetEntries("", allEntries);
        return status;
    });

    int ret = 0;
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("get entries error: %{public}d", status);
        // KEY_NOT_FOUND means no data in database, no need to report.
        if (status != OHOS::DistributedKv::Status::KEY_NOT_FOUND) {
            ACCOUNT_LOGE("status != OHOS::DistributedKv::Status::KEY_NOT_FOUND");
        }
        ret = OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    } else {
        ACCOUNT_LOGE("SaveEntries start");
        infos.clear();
        SaveEntries(allEntries, infos);
        ACCOUNT_LOGE("SaveEntries end");
    }

    return ret;
}

ErrCode AccountDataStorage::AddAccountInfo(IAccountInfo &iAccountInfo)
{
    ACCOUNT_LOGI("enter");

    if (!CheckKvStore()) {
        ACCOUNT_LOGE("kvStore is nullptr");
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }

    bool isKeyExists = false;
    IsKeyExists(iAccountInfo.GetPrimeKey(), isKeyExists);
    if (isKeyExists) {
        ACCOUNT_LOGE("the key already exists.");
        return ERR_OSACCOUNT_SERVICE_DATA_STORAGE_KEY_EXISTED_ERROR;
    }

    OHOS::DistributedKv::Key key(iAccountInfo.GetPrimeKey());
    ACCOUNT_LOGI("iAccountInfo.GetPrimeKey() is %{public}s", iAccountInfo.GetPrimeKey().c_str());
    OHOS::DistributedKv::Value value(iAccountInfo.ToString());

    OHOS::DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->Put(key, value);
        if (status == OHOS::DistributedKv::Status::IPC_ERROR) {
            status = kvStorePtr_->Put(key, value);
            ACCOUNT_LOGE("status = %{public}d", status);
        }
        ACCOUNT_LOGE("status = %{public}d", status);
    }
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("put error, status = %{public}d", status);
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    } else {
        ACCOUNT_LOGE("put value to kvStore successfully");
    }

    ACCOUNT_LOGE("end");

    return ERR_OK;
}

ErrCode AccountDataStorage::SaveAccountInfo(IAccountInfo &iAccountInfo)
{
    ACCOUNT_LOGI("enter");

    if (!CheckKvStore()) {
        ACCOUNT_LOGE("kvStore is nullptr");
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }

    bool isKeyExists = false;
    IsKeyExists(iAccountInfo.GetPrimeKey(), isKeyExists);
    if (!isKeyExists) {
        ACCOUNT_LOGE("the key does not exist");
        return ERR_OSACCOUNT_SERVICE_DATA_STORAGE_KEY_NOT_EXISTS_ERROR;
    }
    ACCOUNT_LOGI("iAccountInfo.GetPrimeKey() = %{public}s", iAccountInfo.GetPrimeKey().c_str());
    OHOS::DistributedKv::Key key(iAccountInfo.GetPrimeKey());
    OHOS::DistributedKv::Value value(iAccountInfo.ToString());
    OHOS::DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->Put(key, value);
        if (status == OHOS::DistributedKv::Status::IPC_ERROR) {
            status = kvStorePtr_->Put(key, value);
            ACCOUNT_LOGE("status = %{public}d", status);
        }
        ACCOUNT_LOGE("status = %{public}d", status);
    }
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("put error, status = %{public}d", status);
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    } else {
        ACCOUNT_LOGE("put value to kvStore successfully");
    }

    ACCOUNT_LOGE("end");

    return ERR_OK;
}

ErrCode AccountDataStorage::RemoveInfoByKey(const std::string &keyStr)
{
    ACCOUNT_LOGI("enter");
    ACCOUNT_LOGI("id = %{public}s", keyStr.c_str());

    if (!CheckKvStore()) {
        ACCOUNT_LOGE("kvStore is nullptr");
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }

    bool isKeyExists = false;
    IsKeyExists(keyStr, isKeyExists);
    if (!isKeyExists) {
        ACCOUNT_LOGE("the key does not exist");
        return ERR_OSACCOUNT_SERVICE_DATA_STORAGE_KEY_NOT_EXISTS_ERROR;
    }
    OHOS::DistributedKv::Key key(keyStr);
    OHOS::DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->Delete(key);
        if (status == OHOS::DistributedKv::Status::IPC_ERROR) {
            status = kvStorePtr_->Delete(key);
            ACCOUNT_LOGE("distribute database ipc error and try to call again, result = %{public}d", status);
        }
    }

    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("delete key error: %{public}d", status);
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    } else {
        ACCOUNT_LOGE("delete value to kvStore success");
    }
    return ERR_OK;
}

OHOS::DistributedKv::Status AccountDataStorage::GetEntries(
    std::string subId, std::vector<OHOS::DistributedKv::Entry> &allEntries) const
{
    ACCOUNT_LOGI("enter");

    OHOS::DistributedKv::Key allEntryKeyPrefix(subId);
    OHOS::DistributedKv::Status status = kvStorePtr_->GetEntries(allEntryKeyPrefix, allEntries);

    ACCOUNT_LOGE("end, status = %{public}d, allEntries.size() = %{public}zu", status, allEntries.size());
    return status;
}

ErrCode AccountDataStorage::DeleteKvStore()
{
    ACCOUNT_LOGI("enter");

    if (!CheckKvStore()) {
        ACCOUNT_LOGE("kvStore is nullptr");
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }

    OHOS::DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        dataManager_.CloseKvStore(this->appId_, this->storeId_);
        kvStorePtr_ = nullptr;
        status = dataManager_.DeleteKvStore(this->appId_, this->storeId_);
    }
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("error, status = %{public}d", status);
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }

    ACCOUNT_LOGE("end");

    return ERR_OK;
}

ErrCode AccountDataStorage::GetAccountInfoById(const std::string id, IAccountInfo &iAccountInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("id = %{public}s", id.c_str());
    ACCOUNT_LOGI("iAccountInfo.GetPrimeKey() = %{public}s", iAccountInfo.GetPrimeKey().c_str());

    if (!CheckKvStore()) {
        ACCOUNT_LOGE("kvStore is nullptr");
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }

    OHOS::DistributedKv::Key key(id);
    OHOS::DistributedKv::Value value;
    OHOS::DistributedKv::Status status;
    TryTwice([this, &status, &key, &value] {
        status = kvStorePtr_->Get(key, value);
        return status;
    });
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("get value error");
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }

    nlohmann::json jsonObject = nlohmann::json::parse(value.ToString(), nullptr, false);
    iAccountInfo.FromJson(jsonObject);
    return ERR_OK;
}

ErrCode AccountDataStorage::GetConfigById(const std::string keyStr, std::string &valueStr)
{
    ACCOUNT_LOGI("enter");

    if (!CheckKvStore()) {
        ACCOUNT_LOGE("kvStore is nullptr");
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }

    OHOS::DistributedKv::Key key(keyStr);
    OHOS::DistributedKv::Value value;
    OHOS::DistributedKv::Status status;
    TryTwice([this, &status, &key, &value] {
        status = kvStorePtr_->Get(key, value);
        return status;
    });
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("get Value Error");
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }

    valueStr = value.ToString();
    return ERR_OK;
}

ErrCode AccountDataStorage::LoadDataByLocalFuzzyQuery(
    std::string subId, std::map<std::string, std::shared_ptr<IAccountInfo>> &infos)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("subId = %{public}s", subId.c_str());

    if (!CheckKvStore()) {
        ACCOUNT_LOGE("kvStore is nullptr");
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }

    OHOS::DistributedKv::Status status;
    std::vector<OHOS::DistributedKv::Entry> allEntries;
    TryTwice([this, &status, &allEntries, subId] {
        status = GetEntries(subId, allEntries);
        return status;
    });

    int ret = 0;
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("get entries error: %{public}d", status);
        // KEY_NOT_FOUND means no data in database, no need to report.
        if (status != OHOS::DistributedKv::Status::KEY_NOT_FOUND) {
            ACCOUNT_LOGE("status != OHOS::DistributedKv::Status::KEY_NOT_FOUND");
        }
        ret = OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    } else {
        ACCOUNT_LOGE("SaveEntries start");
        infos.clear();
        SaveEntries(allEntries, infos);
        ACCOUNT_LOGE("SaveEntries end");
    }

    ACCOUNT_LOGI("end, status = %{public}d, ret = %{public}d", status, ret);

    return ret;
}

ErrCode AccountDataStorage::PutValueToKvStore(const std::string &keyStr, const std::string &valueStr)
{
    OHOS::DistributedKv::Key key(keyStr);
    OHOS::DistributedKv::Value value(valueStr);
    OHOS::DistributedKv::Status status;

    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        status = kvStorePtr_->Put(key, value);
        if (status == OHOS::DistributedKv::Status::IPC_ERROR) {
            status = kvStorePtr_->Put(key, value);
        }
    }

    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("put value to kvStore error, status = %{public}d", status);
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }
    ACCOUNT_LOGI("put value to kvStore succeed!");
    return ERR_OK;
}

ErrCode AccountDataStorage::AddConfigInfo(const std::string &keyStr, const std::string &valueStr)
{
    if (!CheckKvStore()) {
        ACCOUNT_LOGE("kvStore is nullptr");
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }

    bool isKeyExists = false;
    IsKeyExists(keyStr, isKeyExists);
    if (isKeyExists) {
        ACCOUNT_LOGE("the key already exists");
        return ERR_OSACCOUNT_SERVICE_DATA_STORAGE_KEY_EXISTED_ERROR;
    }
    return PutValueToKvStore(keyStr, valueStr);
}

ErrCode AccountDataStorage::SavConfigInfo(const std::string &keyStr, const std::string &valueStr)
{
    if (!CheckKvStore()) {
        ACCOUNT_LOGE("kvStore is nullptr");
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }

    bool isKeyExists = false;
    IsKeyExists(keyStr, isKeyExists);
    if (!isKeyExists) {
        ACCOUNT_LOGE("the key does not exist");
        return ERR_OSACCOUNT_SERVICE_DATA_STORAGE_KEY_NOT_EXISTS_ERROR;
    }
    return PutValueToKvStore(keyStr, valueStr);
}

ErrCode AccountDataStorage::IsKeyExists(const std::string keyStr, bool &isKeyExists)
{
    ACCOUNT_LOGI("enter");

    if (!CheckKvStore()) {
        ACCOUNT_LOGE("kvStore is nullptr");
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }

    OHOS::DistributedKv::Key key(keyStr);
    OHOS::DistributedKv::Value value;
    OHOS::DistributedKv::Status status;
    TryTwice([this, &status, &key, &value] {
        status = kvStorePtr_->Get(key, value);
        return status;
    });

    ACCOUNT_LOGE("status = %{public}d", status);
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGW("get Value Error, target key does not exist.");
        isKeyExists = false;
        return OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR;
    }
    isKeyExists = true;
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

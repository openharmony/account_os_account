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
#include <thread>
#include <memory>
#include <unistd.h>

#include "account_kvstore_death_recipient_callback.h"
#include "account_log_wrapper.h"
#include "account_data_storage.h"

namespace OHOS {
namespace AccountSA {
const int32_t MAX_TIMES = 10;
const int32_t SLEEP_INTERVAL = 100 * 1000;

AccountDataStorage::AccountDataStorage(const std::string &appId, const std::string &storeId, const bool &autoSync)
{
    ACCOUNT_LOGI("enter");

    appId_.appId = appId;
    storeId_.storeId = storeId;
    autoSync_ = autoSync;

    ACCOUNT_LOGI("end, this = %{private}p", this);
}

AccountDataStorage::~AccountDataStorage()
{
    ACCOUNT_LOGI("enter, this = %{private}p", this);

    if (kvStorePtr_ != nullptr) {
        dataManager_.CloseKvStore(appId_, std::move(kvStorePtr_));
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

    OHOS::DistributedKv::Status status;
    OHOS::DistributedKv::Options options = {.createIfMissing = true,
        .encrypt = false,
        .autoSync = autoSync_,
        .kvStoreType = OHOS::DistributedKv::KvStoreType::SINGLE_VERSION};

    dataManager_.GetSingleKvStore(options,
        appId_,
        storeId_,
        [this, &status](OHOS::DistributedKv::Status paramStatus,
            std::unique_ptr<OHOS::DistributedKv::SingleKvStore>
                singleKvStore) {
            status = paramStatus;
            if (status != OHOS::DistributedKv::Status::SUCCESS) {
                ACCOUNT_LOGE("status != OHOS::DistributedKv::Status::SUCCESS");
                return;
            }
            {
                if (singleKvStore == nullptr) {
                    ACCOUNT_LOGI("singleKvStore is nullptr");
                } else {
                    ACCOUNT_LOGI("singleKvStore is not nullptr");
                }

                kvStorePtr_ = std::move(singleKvStore);
            }
            ACCOUNT_LOGI("Get kvStore successfully");
        });

    if (kvStorePtr_ == nullptr) {
        ACCOUNT_LOGI("kvStorePtr_ is nullptr");
    } else {
        ACCOUNT_LOGI("kvStorePtr_ is not nullptr");
    }

    return status;
}

bool AccountDataStorage::CheckKvStore()
{
    ACCOUNT_LOGI("enter");

    if (kvStorePtr_ != nullptr) {
        return true;
    }
    int32_t tryTimes = MAX_TIMES;
    while (tryTimes > 0) {
        OHOS::DistributedKv::Status status = GetKvStore();
        if (status == OHOS::DistributedKv::Status::SUCCESS && kvStorePtr_ != nullptr) {
            return true;
        }
        ACCOUNT_LOGE("AccountDataStorage CheckKvStore, Times: %{public}d", tryTimes);
        usleep(SLEEP_INTERVAL);
        tryTimes--;
    }

    ACCOUNT_LOGE("end");

    return kvStorePtr_ != nullptr;
}

bool AccountDataStorage::ResetKvStore()
{
    ACCOUNT_LOGI("enter");

    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    kvStorePtr_ = nullptr;
    OHOS::DistributedKv::Status status = GetKvStore();
    if (status == OHOS::DistributedKv::Status::SUCCESS && kvStorePtr_ != nullptr) {
        return true;
    }

    ACCOUNT_LOGE("end, failed");

    return false;
}

ErrCode AccountDataStorage::LoadAllData(std::map<std::string, std::shared_ptr<IAccountInfo>> &infos)
{
    ACCOUNT_LOGI("enter");

    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            ACCOUNT_LOGE("kvStore is nullptr");
            return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
        }
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
        ret = OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
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

    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            ACCOUNT_LOGE("kvStore is nullptr");
            return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
        }
    }
    bool isKeyExists;
    IsKeyExists(iAccountInfo.GetPrimeKey(), isKeyExists);
    if (isKeyExists) {
        ACCOUNT_LOGE("the key does not exist");
        return ERR_ACCOUNT_SERVICE_DATA_STORAGE_KEY_EXISTED_ERROR;
    }
    ACCOUNT_LOGE("iAccountInfo.GetPrimeKey() is %{public}s", iAccountInfo.GetPrimeKey().c_str());
    OHOS::DistributedKv::Key key(iAccountInfo.GetPrimeKey());
    ACCOUNT_LOGE("iAccountInfo.ToString() is %{public}s", iAccountInfo.ToString().c_str());
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
        return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
    } else {
        ACCOUNT_LOGE("put value to kvStore successfully");
    }

    ACCOUNT_LOGE("end");

    return ERR_OK;
}

ErrCode AccountDataStorage::SaveAccountInfo(IAccountInfo &iAccountInfo)
{
    ACCOUNT_LOGI("enter");

    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            ACCOUNT_LOGE("kvStore is nullptr");
            return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
        }
    }
    bool isKeyExists;
    IsKeyExists(iAccountInfo.GetPrimeKey(), isKeyExists);
    if (!isKeyExists) {
        ACCOUNT_LOGE("the key does not exist");
        return ERR_ACCOUNT_SERVICE_DATA_STORAGE_KEY_NOT_EXISTS_ERROR;
    }
    ACCOUNT_LOGI("iAccountInfo.GetPrimeKey() = %{public}s", iAccountInfo.GetPrimeKey().c_str());
    OHOS::DistributedKv::Key key(iAccountInfo.GetPrimeKey());
    ACCOUNT_LOGE("iAccountInfo.ToString() is %{public}s", iAccountInfo.ToString().c_str());
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
        return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
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

    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            ACCOUNT_LOGE("kvStore is nullptr");
            return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
        }
    }
    bool isKeyExists;
    IsKeyExists(keyStr, isKeyExists);
    if (!isKeyExists) {
        ACCOUNT_LOGE("the key does not exist");
        return ERR_ACCOUNT_SERVICE_DATA_STORAGE_KEY_NOT_EXISTS_ERROR;
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
        return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
    } else {
        ACCOUNT_LOGE("delete value to kvStore success");
    }
    return ERR_OK;
}

OHOS::DistributedKv::Status AccountDataStorage::GetEntries(
    std::string subId, std::vector<OHOS::DistributedKv::Entry> &allEntries) const
{
    ACCOUNT_LOGI("enter");

    OHOS::DistributedKv::Status status = OHOS::DistributedKv::Status::ERROR;
    OHOS::DistributedKv::Key token;
    // if prefix is empty, get all entries.
    OHOS::DistributedKv::Key allEntryKeyPrefix(subId);
    if (kvStorePtr_) {
        // sync call GetEntries, the callback will be trigger at once
    }
    status = kvStorePtr_->GetEntries(allEntryKeyPrefix, allEntries);

    ACCOUNT_LOGE("end, status = %{public}d, allEntries.size() = %{public}zu", status, allEntries.size());

    return status;
}

ErrCode AccountDataStorage::DeleteKvStore()
{
    ACCOUNT_LOGI("enter");

    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            ACCOUNT_LOGE("kvStore is nullptr");
            return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
        }
    }
    OHOS::DistributedKv::Status status;  // = OHOS::DistributedKv::Status::ERROR;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        dataManager_.CloseKvStore(this->appId_, this->storeId_);  // std::move(kvStorePtr_));
        kvStorePtr_ = nullptr;
        status = dataManager_.DeleteKvStore(this->appId_, this->storeId_);
    }
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("error, status = %{public}d", status);
        return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
    }

    ACCOUNT_LOGE("end");

    return ERR_OK;
}

ErrCode AccountDataStorage::GetAccountInfoById(const std::string id, IAccountInfo &iAccountInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("id = %{public}s", id.c_str());
    ACCOUNT_LOGI("iAccountInfo.GetPrimeKey() = %{public}s", iAccountInfo.GetPrimeKey().c_str());
    ACCOUNT_LOGI("iAccountInfo.ToString() = %{public}s", iAccountInfo.ToString().c_str());

    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            ACCOUNT_LOGE("kvStore is nullptr");
            return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
        }
    }
    OHOS::DistributedKv::Key key(id);
    OHOS::DistributedKv::Value value;
    OHOS::DistributedKv::Status status;
    TryTwice([this, &status, &key, &value] {
        status = kvStorePtr_->Get(key, value);
        return status;
    });
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("get Value Error");
        return QUERY_DISTRIBUTE_DATA_FAILED;
    } else {
        ACCOUNT_LOGE("get Value is: %{public}s", value.ToString().c_str());
        nlohmann::json jsonObject = nlohmann::json::parse(value.ToString(), nullptr, false);
        iAccountInfo.FromJson(jsonObject);
        ACCOUNT_LOGE("all info is: %{public}s", iAccountInfo.ToString().c_str());
    }

    return ERR_OK;
}

ErrCode AccountDataStorage::GetConfigById(const std::string keyStr, std::string &valueStr)
{
    ACCOUNT_LOGI("enter");

    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            ACCOUNT_LOGE("kvStore is nullptr");
            return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
        }
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
        return QUERY_DISTRIBUTE_DATA_FAILED;
    } else {
        ACCOUNT_LOGE("get Value is: %{public}s", value.ToString().c_str());
        valueStr = value.ToString();
    }

    return ERR_OK;
}

ErrCode AccountDataStorage::LoadDataByLocalFuzzyQuery(
    std::string subId, std::map<std::string, std::shared_ptr<IAccountInfo>> &infos)
{
    ACCOUNT_LOGI("enter");

    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            ACCOUNT_LOGE("kvStore is nullptr");
            return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
        }
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
        ret = OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
    } else {
        ACCOUNT_LOGE("SaveEntries start");
        infos.clear();
        SaveEntries(allEntries, infos);
        ACCOUNT_LOGE("SaveEntries end");
    }
    return ret;
}

ErrCode AccountDataStorage::AddConfigInfo(const std::string &keyStr, const std::string &valueStr)
{
    ACCOUNT_LOGI("enter");

    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            ACCOUNT_LOGE("kvStore is nullptr");
            return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
        }
    }
    bool isKeyExists;
    IsKeyExists(keyStr, isKeyExists);
    if (isKeyExists) {
        ACCOUNT_LOGE("the key is not Exists");
        return ERR_ACCOUNT_SERVICE_DATA_STORAGE_KEY_EXISTED_ERROR;
    }
    ACCOUNT_LOGE("iAccountInfo.GetPrimeKey() is %{public}s", keyStr.c_str());
    OHOS::DistributedKv::Key key(keyStr);
    ACCOUNT_LOGE("AddConfigInfo.ToString() is %{public}s", valueStr.c_str());
    OHOS::DistributedKv::Value value(valueStr);
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
        ACCOUNT_LOGE("error, status = %{public}d", status);
        return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
    } else {
        ACCOUNT_LOGE("put value to kvStore success");
    }

    ACCOUNT_LOGE("end");

    return ERR_OK;
}

ErrCode AccountDataStorage::SavConfigInfo(const std::string &keyStr, const std::string &valueStr)
{
    ACCOUNT_LOGI("enter");

    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            ACCOUNT_LOGE("kvStore is nullptr");
            return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
        }
    }
    bool isKeyExists;
    IsKeyExists(keyStr, isKeyExists);
    if (!isKeyExists) {
        ACCOUNT_LOGE("the key is not Exists");
        return ERR_ACCOUNT_SERVICE_DATA_STORAGE_KEY_NOT_EXISTS_ERROR;
    }
    ACCOUNT_LOGE("iAccountInfo.GetPrimeKey() is %{public}s", keyStr.c_str());
    OHOS::DistributedKv::Key key(keyStr);
    ACCOUNT_LOGE("SavConfigInfo.ToString() is %{public}s", valueStr.c_str());
    OHOS::DistributedKv::Value value(valueStr);
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
        ACCOUNT_LOGE("error, status = %{public}d", status);
        return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
    } else {
        ACCOUNT_LOGE("put value to kvStore success");
    }

    ACCOUNT_LOGE("end");

    return ERR_OK;
}

ErrCode AccountDataStorage::IsKeyExists(const std::string keyStr, bool &isKeyExists)
{
    ACCOUNT_LOGI("enter");

    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            ACCOUNT_LOGE("kvStore is nullptr");
            return OHOS::QUERY_DISTRIBUTE_DATA_FAILED;
        }
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
        ACCOUNT_LOGE("get Value Error");
        isKeyExists = false;
        return QUERY_DISTRIBUTE_DATA_FAILED;
    } else {
        ACCOUNT_LOGE("get Value is: %{public}s", value.ToString().c_str());
        isKeyExists = true;
    }

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "kvstore_adapter_impl.h"
#include "account_log_wrapper.h"
#include <memory>

namespace OHOS {
namespace AccountSA {

DbAdapterStatus ConvertKvStatus(const OHOS::DistributedKv::Status &kvStatus)
{
    switch (kvStatus) {
        case OHOS::DistributedKv::Status::SUCCESS:
            return DbAdapterStatus::SUCCESS;
        case OHOS::DistributedKv::Status::KEY_NOT_FOUND:
            return DbAdapterStatus::KEY_NOT_EXIST;
        case OHOS::DistributedKv::Status::IPC_ERROR:
            return DbAdapterStatus::IPC_ERROR;
        default:
            ACCOUNT_LOGE("Other DistributedKv Status when convert, kvStatus: %{public}d",
                kvStatus);
            return DbAdapterStatus::INTERNAL_ERROR;
    }
}

DbAdapterStatus DbAdapterKvStore::GetEntries(const std::string subId,
    std::vector<DbAdapterEntry> &allEntries)
{
    allEntries.clear();
    OHOS::DistributedKv::Key allEntryKeyPrefix(subId);
    std::vector<OHOS::DistributedKv::Entry> entries;
    OHOS::DistributedKv::Status kvStatus = kvStorePtr_->GetEntries(allEntryKeyPrefix, entries);
    if (kvStatus != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("KvGetEntries failed, status: %{public}d", kvStatus);
        return ConvertKvStatus(kvStatus);
    }

    for (const auto &item : entries) {
        DbAdapterEntry entry;
        entry.key = item.key.ToString();
        entry.value = item.value.ToString();
        allEntries.push_back(entry);
    }
    return DbAdapterStatus::SUCCESS;
}

DbAdapterStatus DbAdapterKvStore::Get(const std::string &keyStr, std::string &valueStr)
{
    valueStr.clear();
    OHOS::DistributedKv::Key key(keyStr);
    OHOS::DistributedKv::Value value;
    OHOS::DistributedKv::Status kvStatus = kvStorePtr_->Get(key, value);
    if (kvStatus != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("Kvstore get failed, status: %{public}d", kvStatus);
        return ConvertKvStatus(kvStatus);
    }
    valueStr = value.ToString();
    return DbAdapterStatus::SUCCESS;
}

DbAdapterStatus DbAdapterKvStore::Delete(const std::string &keyStr)
{
    OHOS::DistributedKv::Key key(keyStr);
    OHOS::DistributedKv::Status kvStatus = kvStorePtr_->Delete(key);
    if (kvStatus != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("Kvstore delete failed, status: %{public}d", kvStatus);
        return ConvertKvStatus(kvStatus);
    }
    return DbAdapterStatus::SUCCESS;
}

DbAdapterStatus DbAdapterKvStore::Put(const std::string &keyStr, const std::string &valueStr)
{
    OHOS::DistributedKv::Key key(keyStr);
    OHOS::DistributedKv::Value value(valueStr);
    OHOS::DistributedKv::Status kvStatus = kvStorePtr_->Put(key, value);
    if (kvStatus != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("Kvstore put failed, status: %{public}d", kvStatus);
        return ConvertKvStatus(kvStatus);
    }
    return DbAdapterStatus::SUCCESS;
}

DbAdapterStatus DbAdapterKvStore::Commit()
{
    OHOS::DistributedKv::Status kvStatus = kvStorePtr_->Commit();
    if (kvStatus != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("Kvstore commit failed, status: %{public}d", kvStatus);
        return ConvertKvStatus(kvStatus);
    }
    return DbAdapterStatus::SUCCESS;
}

DbAdapterStatus DbAdapterKvStore::Rollback()
{
    OHOS::DistributedKv::Status kvStatus = kvStorePtr_->Rollback();
    if (kvStatus != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("Kvstore rollback failed, status: %{public}d", kvStatus);
        return ConvertKvStatus(kvStatus);
    }
    return DbAdapterStatus::SUCCESS;
}

DbAdapterStatus DbAdapterKvStore::StartTransaction()
{
    OHOS::DistributedKv::Status kvStatus = kvStorePtr_->StartTransaction();
    if (kvStatus != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("Kvstore start transaction failed, status: %{public}d", kvStatus);
        return ConvertKvStatus(kvStatus);
    }
    return DbAdapterStatus::SUCCESS;
}

DbAdapterStatus DbAdapterKvStore::PutBatch(const std::vector<DbAdapterEntry> &entries)
{
    std::vector<OHOS::DistributedKv::Entry> kvEntries;
    for (const auto &entry : entries) {
        OHOS::DistributedKv::Entry kvEntry;
        kvEntry.key = OHOS::DistributedKv::Key(entry.key);
        kvEntry.value = OHOS::DistributedKv::Value(entry.value);
        kvEntries.push_back(kvEntry);
    }
    OHOS::DistributedKv::Status kvStatus = kvStorePtr_->PutBatch(kvEntries);
    if (kvStatus != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("Kvstore put batch failed, status: %{public}d", kvStatus);
        return ConvertKvStatus(kvStatus);
    }
    return DbAdapterStatus::SUCCESS;
}

DbAdapterStatus DbAdapterKvStore::GetKvStorePtr(std::shared_ptr<OHOS::DistributedKv::SingleKvStore> &kvStorePtr)
{
    if (kvStorePtr_ == nullptr) {
        ACCOUNT_LOGE("KvStorePtr is nullptr");
        return DbAdapterStatus::INTERNAL_ERROR;
    }
    kvStorePtr = kvStorePtr_;
    return DbAdapterStatus::SUCCESS;
}

DbAdapterStatus KvStoreAdapterDataManager::GetSingleKvStore(const DbAdapterOptions &options,
    const std::string &appIdStr, const std::string &storeIdStr, std::shared_ptr<IDbAdapterSingleStore> &kvStorePtr)
{
    OHOS::DistributedKv::Options kvOptions = {
        .createIfMissing = true,
        .encrypt = options.encrypt,
        .autoSync = options.autoSync,
        .syncable = options.autoSync,
        .securityLevel = options.securityLevel,
        .area = options.area,
        .kvStoreType = OHOS::DistributedKv::KvStoreType::SINGLE_VERSION,
        .baseDir = options.baseDir,
    };
    OHOS::DistributedKv::AppId appId = { .appId = appIdStr };
    OHOS::DistributedKv::StoreId storeId = { .storeId = storeIdStr };

    std::shared_ptr<OHOS::DistributedKv::SingleKvStore> kvStore;
    OHOS::DistributedKv::Status status = dataManager_.GetSingleKvStore(kvOptions, appId, storeId, kvStore);
    if (status != OHOS::DistributedKv::Status::SUCCESS || kvStore == nullptr) {
        ACCOUNT_LOGE("KvGetSingleKvStore failed! status %{public}d, kvStorePtr is nullptr", status);
        return ConvertKvStatus(status);
    }

    kvStorePtr = std::make_shared<DbAdapterKvStore>(kvStore);

    return DbAdapterStatus::SUCCESS;
}

DbAdapterStatus KvStoreAdapterDataManager::CloseKvStore(const std::string appIdStr,
    std::shared_ptr<IDbAdapterSingleStore> &DbStorePtr)
{
    if (DbStorePtr == nullptr) {
        ACCOUNT_LOGE("DbStorePtr is nullptr.");
        return DbAdapterStatus::INTERNAL_ERROR;
    }
    std::shared_ptr<DbAdapterKvStore> kvStoreImpl = std::static_pointer_cast<DbAdapterKvStore>(DbStorePtr);
    if (kvStoreImpl == nullptr) {
        ACCOUNT_LOGE("Failed to cast DbStorePtr to DbAdapterKvStore.");
        return DbAdapterStatus::INTERNAL_ERROR;
    }
    std::shared_ptr<OHOS::DistributedKv::SingleKvStore> kvStorePtr;
    DbAdapterStatus status = kvStoreImpl->GetKvStorePtr(kvStorePtr);
    if (kvStorePtr == nullptr || status != DbAdapterStatus::SUCCESS) {
        ACCOUNT_LOGE("KvStorePtr is nullptr.");
        return DbAdapterStatus::INTERNAL_ERROR;
    }
    OHOS::DistributedKv::AppId appId = { .appId = appIdStr };
    OHOS::DistributedKv::Status kvStatus = dataManager_.CloseKvStore(appId, kvStorePtr);
    if (kvStatus != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("CloseKvStore failed! status %{public}d", kvStatus);
        return ConvertKvStatus(kvStatus);
    }
    return DbAdapterStatus::SUCCESS;
}

DbAdapterStatus KvStoreAdapterDataManager::DeleteKvStore(const std::string &appIdStr, const std::string &storeIdStr,
    const std::string &baseDir)
{
    OHOS::DistributedKv::AppId appId = { .appId = appIdStr };
    OHOS::DistributedKv::StoreId storeId = { .storeId = storeIdStr };
    OHOS::DistributedKv::Status status = dataManager_.DeleteKvStore(appId, storeId, baseDir);
    if (status != OHOS::DistributedKv::Status::SUCCESS) {
        ACCOUNT_LOGE("DeleteKvStore failed! status %{public}d", status);
        return ConvertKvStatus(status);
    }
    return DbAdapterStatus::SUCCESS;
}

bool KvStoreAdapterDataManager::IsKvStore()
{
    return true;
}

DbAdapterStatus KvStoreAdapterDataManager::GetAllKvStoreId(const std::string &appIdStr,
    std::vector<std::string> &storeIdList)
{
    OHOS::DistributedKv::AppId appId = { .appId = appIdStr };
    std::vector<OHOS::DistributedKv::StoreId> storeIds;
    OHOS::DistributedKv::Status status = dataManager_.GetAllKvStoreId(appId, storeIds);

    storeIdList.clear();
    for (const auto &storeId : storeIds) {
        storeIdList.push_back(storeId.storeId);
    }
    return ConvertKvStatus(status);
}

} // namespace AccountSA
} // namespace OHOS
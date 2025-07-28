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

#ifndef ACCOUNT_KVSTORE_ADAPTER_IMPL_H
#define ACCOUNT_KVSTORE_ADAPTER_IMPL_H

#include "database_adapter_interface.h"
#include "distributed_kv_data_manager.h"

namespace OHOS {
namespace AccountSA {

class DbAdapterKvStore : public IDbAdapterSingleStore {
public:
    DbAdapterKvStore() = default;
    explicit DbAdapterKvStore(const std::shared_ptr<OHOS::DistributedKv::SingleKvStore>& kvStorePtr)
        : kvStorePtr_(kvStorePtr) {}
    ~DbAdapterKvStore() = default;
    DbAdapterStatus GetKvStorePtr(std::shared_ptr<OHOS::DistributedKv::SingleKvStore> &kvStorePtr);
    DbAdapterStatus Get(const std::string &keyStr, std::string &valueStr) override;
    DbAdapterStatus Delete(const std::string &keyStr) override;
    DbAdapterStatus Put(const std::string &keyStr, const std::string &valueStr) override;
    DbAdapterStatus GetEntries(const std::string subId,
        std::vector<DbAdapterEntry> &allEntries) override;
    DbAdapterStatus PutBatch(const std::vector<DbAdapterEntry> &entries) override;
    DbAdapterStatus Commit() override;
    DbAdapterStatus Rollback() override;
    DbAdapterStatus StartTransaction() override;

private:
    std::shared_ptr<OHOS::DistributedKv::SingleKvStore> kvStorePtr_;
};

class KvStoreAdapterDataManager : public IDbAdapterDataManager {
public:
    KvStoreAdapterDataManager() = default;
    ~KvStoreAdapterDataManager() = default;

    DbAdapterStatus CloseKvStore(const std::string appIdStr,
        std::shared_ptr<IDbAdapterSingleStore> &kvStorePtr) override;
    DbAdapterStatus GetSingleKvStore(const DbAdapterOptions &options, const std::string &appIdStr,
        const std::string &storeIdStr, std::shared_ptr<IDbAdapterSingleStore> &kvStorePtr) override;
    DbAdapterStatus DeleteKvStore(const std::string &appIdStr, const std::string &storeIdStr,
        const std::string &baseDir) override;
    DbAdapterStatus GetAllKvStoreId(const std::string &appIdStr, std::vector<std::string> &storeIdList) override;
    bool IsKvStore() override;
private:
    OHOS::DistributedKv::DistributedKvDataManager dataManager_;
};

}
}
#endif // ACCOUNT_KVSTORE_ADAPTER_IMPL_H
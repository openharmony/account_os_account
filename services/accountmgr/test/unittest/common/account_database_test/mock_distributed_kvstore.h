/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_MOCK_DISTRIBUTED_KVSTORE_H
#define OS_ACCOUNT_SERVICES_MOCK_DISTRIBUTED_KVSTORE_H

#include "gmock/gmock.h"
#include "distributed_kv_data_manager.h"
#include "mock_distributed_kvstore.h"

namespace OHOS {
namespace AccountSA {

class MockDistributedSingleKvStore : public DistributedKv::SingleKvStore {
public:
    MOCK_CONST_METHOD2(GetEntries, OHOS::DistributedKv::Status(
        const OHOS::DistributedKv::Key &keyPrefix, std::vector<OHOS::DistributedKv::Entry> &entries));
    MOCK_METHOD2(Get, OHOS::DistributedKv::Status(
        const OHOS::DistributedKv::Key &key, OHOS::DistributedKv::Value &value));
    MOCK_METHOD2(Put, OHOS::DistributedKv::Status(const OHOS::DistributedKv::Key &key,
        const OHOS::DistributedKv::Value &value));
    MOCK_METHOD1(Delete, OHOS::DistributedKv::Status(const OHOS::DistributedKv::Key &key));
    MOCK_METHOD0(Commit, OHOS::DistributedKv::Status());
    MOCK_METHOD0(Rollback, OHOS::DistributedKv::Status());
    MOCK_METHOD0(StartTransaction, OHOS::DistributedKv::Status());
    MOCK_METHOD1(PutBatch, OHOS::DistributedKv::Status(const std::vector<OHOS::DistributedKv::Entry> &entries));

    OHOS::DistributedKv::StoreId GetStoreId() const override
    {
        OHOS::DistributedKv::StoreId mockId = { .storeId = "mock_store_id" };
        return mockId;
    }

    OHOS::DistributedKv::Status DeleteBatch(const std::vector<OHOS::DistributedKv::Key> &keys) override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status SubscribeKvStore(OHOS::DistributedKv::SubscribeType type,
        std::shared_ptr<OHOS::DistributedKv::KvStoreObserver> observer) override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status UnSubscribeKvStore(OHOS::DistributedKv::SubscribeType type,
        std::shared_ptr<OHOS::DistributedKv::KvStoreObserver> observer) override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status Backup(const std::string &file, const std::string &baseDir) override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status Restore(const std::string &file, const std::string &baseDir) override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status DeleteBackup(const std::vector<std::string> &files, const std::string &baseDir,
        std::map<std::string, DistributedKv::Status> &status) override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status GetEntries(const OHOS::DistributedKv::DataQuery &query,
        std::vector<OHOS::DistributedKv::Entry> &entries) const override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status GetResultSet(const OHOS::DistributedKv::Key &prefix,
        std::shared_ptr<OHOS::DistributedKv::KvStoreResultSet> &resultSet) const override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status GetResultSet(const OHOS::DistributedKv::DataQuery &query,
        std::shared_ptr<OHOS::DistributedKv::KvStoreResultSet> &resultSet) const override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status CloseResultSet(
        std::shared_ptr<OHOS::DistributedKv::KvStoreResultSet> &resultSet) override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status GetCount(const OHOS::DistributedKv::DataQuery &query, int &count) const override
    {
        return OHOS::DistributedKv::Status::SUCCESS;
    }

    OHOS::DistributedKv::Status RemoveDeviceData(const std::string &device) override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status GetSecurityLevel(OHOS::DistributedKv::SecurityLevel &secLevel) const override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status Sync(const std::vector<std::string> &devices,
        OHOS::DistributedKv::SyncMode mode, uint32_t delay) override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status RegisterSyncCallback(
        std::shared_ptr<OHOS::DistributedKv::KvStoreSyncCallback> callback) override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status UnRegisterSyncCallback()  override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status SetSyncParam(const OHOS::DistributedKv::KvSyncParam &syncParam) override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status GetSyncParam(OHOS::DistributedKv::KvSyncParam &syncParam) override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status SetCapabilityEnabled(bool enabled) const override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status SetCapabilityRange(const std::vector<std::string> &localLabels,
                                      const std::vector<std::string> &remoteLabels) const override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status SubscribeWithQuery(const std::vector<std::string> &devices,
        const OHOS::DistributedKv::DataQuery &query) override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }

    OHOS::DistributedKv::Status UnsubscribeWithQuery(const std::vector<std::string> &devices,
        const OHOS::DistributedKv::DataQuery &query) override
    {
        return OHOS::DistributedKv::Status::SUCCESS; // not required for mock
    }
};

}  // namespace OHOS
}  // namespace AccountSA

#endif // OS_ACCOUNT_SERVICES_MOCK_DISTRIBUTED_KVSTORE_H
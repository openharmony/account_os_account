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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "kvstore_adapter_impl.h"
#define protected public
#include "account_data_storage.h"
#undef protected
#include "mock_distributed_kvstore.h"
#include "account_log_wrapper.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const char TEST_APP_ID[] = "test_app_id";
const char TEST_STORE_ID[] = "test_store_id";
const char TEST_STORE_ID_1[] = "test_store_id_1";
}

class MockIDbAdapterDataManager : public IDbAdapterDataManager {
public:
    MOCK_METHOD2(CloseKvStore, DbAdapterStatus(const std::string appIdStr,
        std::shared_ptr<IDbAdapterSingleStore> &kvStorePtr));
    MOCK_METHOD4(GetSingleKvStore, DbAdapterStatus(const DbAdapterOptions &options, const std::string &appIdStr,
        const std::string &storeIdStr, std::shared_ptr<IDbAdapterSingleStore> &kvStorePtr));
    MOCK_METHOD3(DeleteKvStore, DbAdapterStatus(const std::string &appIdStr, const std::string &storeIdStr,
        const std::string &baseDir));
    MOCK_METHOD2(GetAllKvStoreId, DbAdapterStatus(const std::string &appIdStr,
        std::vector<std::string> &storeIdList));
    MOCK_METHOD0(IsKvStore, bool());
};

class TestAccountDataStorage : public AccountDataStorage {
public:
    TestAccountDataStorage() = delete;
    TestAccountDataStorage(const std::string &storeId, const DbAdapterOptions &options)
        : AccountDataStorage(TEST_APP_ID, storeId, options)
    {}
    ~TestAccountDataStorage() = default;
    void SaveEntries(const std::vector<DbAdapterEntry> &allEntries,
        std::map<std::string, std::shared_ptr<IAccountInfo>> &infos)
    {
        ACCOUNT_LOGI("test implement");
    }
};

class KvStoreAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

public:
    std::shared_ptr<MockDistributedSingleKvStore> kvStorePtr_;
    std::shared_ptr<OHOS::AccountSA::DbAdapterKvStore> dbStorePtr_;
    std::shared_ptr<OHOS::AccountSA::KvStoreAdapterDataManager> dataManager_;
};

void KvStoreAdapterTest::SetUpTestCase(void)
{}

void KvStoreAdapterTest::TearDownTestCase(void)
{}

void KvStoreAdapterTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    kvStorePtr_ = std::make_shared<MockDistributedSingleKvStore>();
    dbStorePtr_ = std::make_shared<OHOS::AccountSA::DbAdapterKvStore>(kvStorePtr_);
    dataManager_ = std::make_shared<OHOS::AccountSA::KvStoreAdapterDataManager>();
}

void KvStoreAdapterTest::TearDown(void)
{}

/**
 * @tc.name: AKvStoreAdapterErrTest_0100
 * @tc.desc: KvStoreAdapter abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KvStoreAdapterTest, KvStoreAdapterErrTest_0100, TestSize.Level1)
{
    ASSERT_NE(kvStorePtr_, nullptr);
    ASSERT_NE(dbStorePtr_, nullptr);
    ASSERT_NE(dataManager_, nullptr);

    std::vector<OHOS::AccountSA::DbAdapterEntry> allEntries;
    EXPECT_CALL(*kvStorePtr_, GetEntries(_, _)).WillOnce(Return(OHOS::DistributedKv::Status::IPC_ERROR));
    OHOS::AccountSA::DbAdapterStatus status = dbStorePtr_->GetEntries("test_subId", allEntries);
    EXPECT_EQ(status, OHOS::AccountSA::DbAdapterStatus::IPC_ERROR);

    EXPECT_CALL(*kvStorePtr_, Put(_, _)).WillOnce(Return(OHOS::DistributedKv::Status::IPC_ERROR));
    status = dbStorePtr_->Put("test_key", "test_value");
    EXPECT_EQ(status, OHOS::AccountSA::DbAdapterStatus::IPC_ERROR);

    EXPECT_CALL(*kvStorePtr_, Delete(_)).WillOnce(Return(OHOS::DistributedKv::Status::IPC_ERROR));
    status = dbStorePtr_->Delete("test_key");
    EXPECT_EQ(status, OHOS::AccountSA::DbAdapterStatus::IPC_ERROR);

    EXPECT_CALL(*kvStorePtr_, Commit()).WillOnce(Return(OHOS::DistributedKv::Status::IPC_ERROR));
    status = dbStorePtr_->Commit();
    EXPECT_EQ(status, OHOS::AccountSA::DbAdapterStatus::IPC_ERROR);

    EXPECT_CALL(*kvStorePtr_, Rollback()).WillOnce(Return(OHOS::DistributedKv::Status::IPC_ERROR));
    status = dbStorePtr_->Rollback();
    EXPECT_EQ(status, OHOS::AccountSA::DbAdapterStatus::IPC_ERROR);

    EXPECT_CALL(*kvStorePtr_, StartTransaction()).WillOnce(Return(OHOS::DistributedKv::Status::IPC_ERROR));
    status = dbStorePtr_->StartTransaction();
    EXPECT_EQ(status, OHOS::AccountSA::DbAdapterStatus::IPC_ERROR);

    std::vector<OHOS::AccountSA::DbAdapterEntry> entries = { {"test_key", "test_value"} };
    EXPECT_CALL(*kvStorePtr_, PutBatch(_)).WillOnce(Return(OHOS::DistributedKv::Status::IPC_ERROR));
    status = dbStorePtr_->PutBatch(entries);
    EXPECT_EQ(status, OHOS::AccountSA::DbAdapterStatus::IPC_ERROR);

    status = dataManager_->DeleteKvStore("test_appid", "test_storeid", "test_basedir");
    EXPECT_EQ(status, OHOS::AccountSA::DbAdapterStatus::INTERNAL_ERROR);

    std::shared_ptr<OHOS::DistributedKv::SingleKvStore> kvStorePtr = nullptr;
    auto dbStorePtr = std::make_shared<OHOS::AccountSA::DbAdapterKvStore>();
    status = dbStorePtr->GetKvStorePtr(kvStorePtr);
    EXPECT_EQ(status, OHOS::AccountSA::DbAdapterStatus::INTERNAL_ERROR);

    bool isKvStore = dataManager_->IsKvStore();
    EXPECT_EQ(isKvStore, true);
}

/**
 * @tc.name: CloseKvStoreTest_0100
 * @tc.desc: CloceKvStore abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KvStoreAdapterTest, CloseKvStoreTest_0100, TestSize.Level1)
{
    ASSERT_NE(kvStorePtr_, nullptr);
    ASSERT_NE(dbStorePtr_, nullptr);
    ASSERT_NE(dataManager_, nullptr);

    std::shared_ptr<OHOS::AccountSA::IDbAdapterSingleStore> dbStorePtr = nullptr;
    OHOS::AccountSA::DbAdapterStatus status = dataManager_->CloseKvStore("test_appId", dbStorePtr);
    EXPECT_EQ(status, OHOS::AccountSA::DbAdapterStatus::INTERNAL_ERROR);

    dbStorePtr = std::make_shared<OHOS::AccountSA::DbAdapterKvStore>();
    status = dataManager_->CloseKvStore("test_appId", dbStorePtr);
    EXPECT_EQ(status, OHOS::AccountSA::DbAdapterStatus::INTERNAL_ERROR);
}

/**
 * @tc.name: AccountDataStorageErrTest_0100
 * @tc.desc: AccountDataStorage abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KvStoreAdapterTest, AccountDataStorageErrTest_0100, TestSize.Level1)
{
    DbAdapterOptions options;
    auto dataStorage = std::make_shared<TestAccountDataStorage>(TEST_STORE_ID, options);
    auto mockManager =  std::make_shared<MockIDbAdapterDataManager>();
    ASSERT_NE(mockManager, nullptr);
    dataStorage->dataManager_ = mockManager;

    dataStorage->kvStorePtr_ = dbStorePtr_;
    EXPECT_CALL(*mockManager, IsKvStore()).WillOnce(Return(false));
    auto errCode = dataStorage->DeleteKvStore();
    EXPECT_EQ(errCode, ERR_OK);

    EXPECT_CALL(*mockManager, IsKvStore()).WillOnce(Return(true));
    EXPECT_CALL(*mockManager, CloseKvStore(_, _))
        .WillRepeatedly(Return(OHOS::AccountSA::DbAdapterStatus::INTERNAL_ERROR));
    errCode = dataStorage->DeleteKvStore();
    EXPECT_EQ(errCode, OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR);

    EXPECT_CALL(*mockManager, IsKvStore()).WillOnce(Return(true));
    EXPECT_CALL(*mockManager, CloseKvStore(_, _))
        .WillRepeatedly(Return(OHOS::AccountSA::DbAdapterStatus::SUCCESS));
    EXPECT_CALL(*mockManager, DeleteKvStore(_, _, _))
        .WillOnce(Return(OHOS::AccountSA::DbAdapterStatus::INTERNAL_ERROR));
    errCode = dataStorage->DeleteKvStore();
    EXPECT_EQ(errCode, OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR);

    dataStorage->kvStorePtr_ = dbStorePtr_;
    std::string keyStr = "test_key";
    std::string valueStr = "test_value";
    EXPECT_CALL(*kvStorePtr_, Get(_, _)).WillRepeatedly(Return(OHOS::DistributedKv::Status::IPC_ERROR));
    errCode = dataStorage->GetValueFromKvStore(keyStr, valueStr);
    EXPECT_EQ(errCode, OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR);

    auto oldPtr = std::make_shared<TestAccountDataStorage>(TEST_STORE_ID_1, options);
    oldPtr->kvStorePtr_ = dbStorePtr_;
    EXPECT_CALL(*mockManager, IsKvStore()).WillOnce(Return(false));
    errCode = dataStorage->MoveData(oldPtr);
    EXPECT_EQ(errCode, ERR_OK);

    EXPECT_CALL(*mockManager, IsKvStore()).WillOnce(Return(true));
    EXPECT_CALL(*kvStorePtr_, GetEntries(_, _)).WillOnce(Return(OHOS::DistributedKv::Status::ERROR));
    errCode = dataStorage->MoveData(oldPtr);
    EXPECT_EQ(errCode, OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR);

    EXPECT_CALL(*mockManager, IsKvStore()).WillOnce(Return(true));
    EXPECT_CALL(*kvStorePtr_, GetEntries(_, _)).WillOnce(Return(OHOS::DistributedKv::Status::SUCCESS));
    EXPECT_CALL(*kvStorePtr_, StartTransaction()).WillOnce(Return(OHOS::DistributedKv::Status::SUCCESS));
    EXPECT_CALL(*kvStorePtr_, PutBatch(_)).WillOnce(Return(OHOS::DistributedKv::Status::ERROR));
    EXPECT_CALL(*kvStorePtr_, Rollback()).WillOnce(Return(OHOS::DistributedKv::Status::SUCCESS));
    errCode = dataStorage->MoveData(oldPtr);
    EXPECT_EQ(errCode, OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR);
}

/**
 * @tc.name: AccountDataStorageErrTest_0200
 * @tc.desc: AccountDataStorage abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KvStoreAdapterTest, AccountDataStorageErrTest_0200, TestSize.Level1)
{
    DbAdapterOptions options;
    auto dataStorage = std::make_shared<TestAccountDataStorage>(TEST_STORE_ID, options);
    auto mockManager =  std::make_shared<MockIDbAdapterDataManager>();
    ASSERT_NE(mockManager, nullptr);
    dataStorage->dataManager_ = mockManager;
    dataStorage->kvStorePtr_ = dbStorePtr_;

    EXPECT_CALL(*kvStorePtr_, StartTransaction())
        .WillRepeatedly(Return(OHOS::DistributedKv::Status::ERROR));
    auto errCode = dataStorage->StartTransaction();
    EXPECT_EQ(errCode, OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR);

    EXPECT_CALL(*kvStorePtr_, Commit())
        .WillRepeatedly(Return(OHOS::DistributedKv::Status::ERROR));
    errCode = dataStorage->Commit();
    EXPECT_EQ(errCode, OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR);

    EXPECT_CALL(*kvStorePtr_, Rollback())
        .WillRepeatedly(Return(OHOS::DistributedKv::Status::ERROR));
    errCode = dataStorage->Rollback();
    EXPECT_EQ(errCode, OHOS::ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR);
}
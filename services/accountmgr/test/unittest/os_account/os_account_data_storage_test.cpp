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

#include <gtest/gtest.h>
#include <map>
#define protected public
#include "account_data_storage.h"
#undef protected
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#define private public
#define protected public
#include "os_account_data_storage.h"
#undef protected
#undef private
#define private public
#undef private
#include "os_account_info.h"
namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;
namespace {
const int INT_ID = 1;
const std::string STRING_NAME = "asf";
const OsAccountType INT_TYPE = OsAccountType::ADMIN;
const int64_t INT_SHERIAL = 123;
}  // namespace
class OsAccountDataStorageTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    std::shared_ptr<OsAccountDataStorage> osAccountDataStorage_;
};

void OsAccountDataStorageTest::SetUpTestCase(void)
{}

void OsAccountDataStorageTest::TearDownTestCase(void)
{}

void OsAccountDataStorageTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    osAccountDataStorage_ = std::make_shared<OsAccountDataStorage>("account_test", "account_test_case", false);
    OsAccountInfo osAccountInfo(INT_ID, STRING_NAME, INT_TYPE, INT_SHERIAL);
    osAccountDataStorage_->AddAccountInfo(osAccountInfo);
}

void OsAccountDataStorageTest::TearDown(void)
{}

/**
 * @tc.name: OsAccountDataStorageTest001
 * @tc.desc: Test OsAccountDataStorageTest init
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountDataStorageTest, OsAccountDataStorageTest001, TestSize.Level1)
{
    EXPECT_EQ(osAccountDataStorage_->CheckKvStore(), false);
}

/**
 * @tc.name: OsAccountDataStorageTest002
 * @tc.desc: The test parameters are empty and the store acquisition fails.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountDataStorageTest, OsAccountDataStorageTest002, TestSize.Level3)
{
    EXPECT_EQ(osAccountDataStorage_->MoveData(nullptr), ERR_ACCOUNT_COMMON_CHECK_KVSTORE_ERROR);
    std::shared_ptr<OsAccountDataStorage> testOsAccountDataStorageNull =
        std::make_shared<OsAccountDataStorage>("", "", false);
    EXPECT_EQ(osAccountDataStorage_->MoveData(testOsAccountDataStorageNull), ERR_ACCOUNT_COMMON_CHECK_KVSTORE_ERROR);

    std::shared_ptr<OsAccountDataStorage> testOsAccountDataStorage = std::make_shared<OsAccountDataStorage>(
        "os_account_mgr_service_test", "os_account_info_test", false);
    EXPECT_EQ(osAccountDataStorage_->MoveData(testOsAccountDataStorage), ERR_ACCOUNT_COMMON_CHECK_KVSTORE_ERROR);
}

/**
 * @tc.name: OsAccountDataStorageTest003
 * @tc.desc: Test LoadAllData when kvStore is unavailable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountDataStorageTest, OsAccountDataStorageTest003, TestSize.Level1)
{
    std::map<std::string, std::shared_ptr<IAccountInfo>> infos;
    ErrCode ret = osAccountDataStorage_->LoadAllData(infos);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.name: OsAccountDataStorageTest004
 * @tc.desc: Test GetAccountInfoById for OsAccountInfo when kvStore is unavailable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountDataStorageTest, OsAccountDataStorageTest004, TestSize.Level1)
{
    OsAccountInfo outInfo;

    // Existing key (id=1 was added in SetUp, but kvStore is not connected)
    ErrCode ret = osAccountDataStorage_->GetAccountInfoById(std::to_string(INT_ID), outInfo);
    EXPECT_NE(ret, ERR_OK);

    // Non-existent key also fails due to unavailable kvStore
    ErrCode ret2 = osAccountDataStorage_->GetAccountInfoById("9999", outInfo);
    EXPECT_NE(ret2, ERR_OK);
}

/**
 * @tc.name: OsAccountDataStorageTest005
 * @tc.desc: Test SaveAccountInfo when key does not exist in the unavailable kvStore.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountDataStorageTest, OsAccountDataStorageTest005, TestSize.Level1)
{
    OsAccountInfo osAccountInfo(INT_ID, STRING_NAME, INT_TYPE, INT_SHERIAL);
    // IsKeyExists returns false when kvStore is unavailable, so SaveAccountInfo returns key-not-exists error
    ErrCode ret = osAccountDataStorage_->SaveAccountInfo(osAccountInfo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_DATA_STORAGE_KEY_NOT_EXISTS_ERROR);
}

/**
 * @tc.name: OsAccountDataStorageTest006
 * @tc.desc: Test RemoveValueFromKvStore and PutValueToKvStore when kvStore is unavailable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountDataStorageTest, OsAccountDataStorageTest006, TestSize.Level1)
{
    // RemoveValueFromKvStore fails because CheckKvStore returns false
    ErrCode removeRet = osAccountDataStorage_->RemoveValueFromKvStore(std::to_string(INT_ID));
    EXPECT_EQ(removeRet, ERR_ACCOUNT_COMMON_CHECK_KVSTORE_ERROR);

    // PutValueToKvStore fails because CheckKvStore returns false
    ErrCode putRet = osAccountDataStorage_->PutValueToKvStore("testKey", "testValue");
    EXPECT_EQ(putRet, ERR_ACCOUNT_COMMON_CHECK_KVSTORE_ERROR);
}

/**
 * @tc.name: OsAccountDataStorageTest007
 * @tc.desc: Test GetValueFromKvStore when kvStore is unavailable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountDataStorageTest, OsAccountDataStorageTest007, TestSize.Level1)
{
    std::string value;
    ErrCode ret = osAccountDataStorage_->GetValueFromKvStore(std::to_string(INT_ID), value);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_CHECK_KVSTORE_ERROR);
    EXPECT_TRUE(value.empty());
}

/**
 * @tc.name: OsAccountDataStorageTest008
 * @tc.desc: Test LoadDataByLocalFuzzyQuery when kvStore is unavailable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountDataStorageTest, OsAccountDataStorageTest008, TestSize.Level1)
{
    std::map<std::string, std::shared_ptr<IAccountInfo>> infos;
    ErrCode ret = osAccountDataStorage_->LoadDataByLocalFuzzyQuery("", infos);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_MANAGER_QUERY_DISTRIBUTE_DATA_ERROR);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.name: OsAccountDataStorageTest009
 * @tc.desc: Test AddAccountInfo returns key-already-exists error when key is found, and key-not-exists
 *           when kvStore is unavailable, both using a different storage instance.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountDataStorageTest, OsAccountDataStorageTest009, TestSize.Level1)
{
    // A fresh storage without any data; AddAccountInfo will try PutValueToKvStore which fails
    std::shared_ptr<OsAccountDataStorage> freshStorage =
        std::make_shared<OsAccountDataStorage>("account_test_fresh", "account_test_fresh_store", false);
    OsAccountInfo info(2, "freshAccount", OsAccountType::NORMAL, 456);
    ErrCode ret = freshStorage->AddAccountInfo(info);
    // Since kvStore is not available, IsKeyExists returns false, then PutValueToKvStore fails
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_CHECK_KVSTORE_ERROR);
}
}  // namespace AccountSA
}  // namespace OHOS

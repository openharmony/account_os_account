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

#include <gtest/gtest.h>
#include <map>
#define protected public
#include "account_data_storage.h"
#undef protected
#include "account_error_no.h"
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

void OsAccountDataStorageTest::SetUp(void)
{
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
}  // namespace AccountSA
}  // namespace OHOS

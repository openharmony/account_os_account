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
#include <thread>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#define private public
#include "os_account_subscribe_manager.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

namespace {
const std::string STRING_TEST_NAME = "name";
const std::int32_t DELAY_FOR_OPERATION = 250;
const std::int32_t MAIN_ACCOUNT_ID = 100;
const std::int32_t WAIT_A_MOMENT = 3000;
const std::uint32_t MAX_WAIT_FOR_READY_CNT = 10;
}  // namespace

class OsAccountSubscribeManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
    OsAccountSubscribeManager manager_;
};

void OsAccountSubscribeManagerTest::SetUpTestCase(void)
{
}

void OsAccountSubscribeManagerTest::TearDownTestCase(void)
{}

void OsAccountSubscribeManagerTest::SetUp(void)
{}

void OsAccountSubscribeManagerTest::TearDown(void)
{}

/**
 * @tc.name: OsAccountSubscribeManager_OnAccountsChanged_0001
 * @tc.desc: Test CreateOsAccount when create max accounts.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountSubscribeManagerTest, OnAccountsChanged_0001, TestSize.Level1)
{
    ACCOUNT_LOGI(">>>>>>>>OsAccountSubscribeManager_OnAccountsChanged_0001");

    OsSubscribeRecordPtr osSubscribeRecordPtr;
    int id = 0;
    ErrCode ret = manager_.OnAccountsChanged(osSubscribeRecordPtr, id);
    EXPECT_EQ(ret, false);   
}


}  // namespace AccountSA
}  // namespace OHOS
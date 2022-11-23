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

#include <cstdint>
#include <iosfwd>
#include <string>

#include <gtest/gtest.h>
#include "gtest/gtest-message.h"
#include "gtest/gtest-test-part.h"
#include "gtest/hwext/gtest-ext.h"
#include "gtest/hwext/gtest-tag.h"
#define private public
#include "perf_stat.h"
#undef private


using namespace testing::ext;
using namespace OHOS::AccountSA;

namespace {
const int64_t INVALID_TIME = -1;
const int64_t ACCOUNT_BIND_START_TIME = 10;
const int64_t ACCOUNT_BIND_END_TIME = 120;
const int64_t ACCOUNT_ADD_START_TIME = 100;
const int64_t ACCOUNT_ADD_END_TIME = 10000;
const int64_t ACCOUNT_QUERY_START_TIME = 1220;
const int64_t ACCOUNT_QUERY_END_TIME = 10222;
const int64_t ACCOUNT_DEL_START_TIME = 10;
const int64_t ACCOUNT_DEL_END_TIME = 100;
}

class AccountPerfStatTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AccountPerfStatTest::SetUpTestCase() {}

void AccountPerfStatTest::TearDownTestCase() {}

void AccountPerfStatTest::SetUp()
{
    /**
     * @tc.setup: reset perfStat
     */
    PerfStat::GetInstance().Reset();
}

void AccountPerfStatTest::TearDown() {}

/**
 * @tc.name: AccountPerfEndGreaterBegin001
 * @tc.desc: Test bind start time and end
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AccountPerfStatTest, AccountPerfEndGreaterBegin001, TestSize.Level0)
{
    std::string result;
    /**
     * @tc.steps: step1. check valid bind start time
     */
    PerfStat::GetInstance().SetAccountBindStartTime(ACCOUNT_BIND_START_TIME);
    int64_t bindStartTime = PerfStat::GetInstance().GetAccountBindStartTime();
    EXPECT_EQ(bindStartTime, ACCOUNT_BIND_START_TIME);

    /**
     * @tc.steps: step2. check valid bind end time
     */
    PerfStat::GetInstance().SetAccountBindEndTime(ACCOUNT_BIND_END_TIME);
    PerfStat::GetInstance().Dump(result);
    int64_t bindEndTime = PerfStat::GetInstance().GetAccountBindEndTime();
    EXPECT_EQ(bindEndTime, ACCOUNT_BIND_END_TIME);

    /**
     * @tc.steps: step1. check valid add start time
     */
    PerfStat::GetInstance().SetAccountAddStartTime(ACCOUNT_ADD_START_TIME);
    int64_t addStartTime = PerfStat::GetInstance().GetAccountAddStartTime();
    EXPECT_EQ(addStartTime, ACCOUNT_ADD_START_TIME);

    /**
     * @tc.steps: step2. check valid add end time
     */
    PerfStat::GetInstance().SetAccountAddEndTime(ACCOUNT_ADD_END_TIME);
    PerfStat::GetInstance().Dump(result);
    int64_t addEndTime = PerfStat::GetInstance().GetAccountAddEndTime();
    EXPECT_EQ(addEndTime, ACCOUNT_ADD_END_TIME);

    /**
     * @tc.steps: step1. check valid add start time
     */
    PerfStat::GetInstance().SetAccountDelStartTime(ACCOUNT_DEL_START_TIME);
    int64_t delStartTime = PerfStat::GetInstance().GetAccountDelStartTime();
    EXPECT_EQ(delStartTime, ACCOUNT_DEL_START_TIME);

    /**
     * @tc.steps: step2. check valid add end time
     */
    PerfStat::GetInstance().SetAccountDelEndTime(ACCOUNT_DEL_END_TIME);
    PerfStat::GetInstance().Dump(result);
    int64_t delEndTime = PerfStat::GetInstance().GetAccountDelEndTime();
    EXPECT_EQ(delEndTime, ACCOUNT_DEL_END_TIME);

    /**
     * @tc.steps: step1. check valid add start time
     */
    PerfStat::GetInstance().SetAccountQueryStartTime(ACCOUNT_QUERY_START_TIME);
    int64_t queryStartTime = PerfStat::GetInstance().GetAccountQueryStartTime();
    EXPECT_EQ(queryStartTime, ACCOUNT_QUERY_START_TIME);

    /**
     * @tc.steps: step2. check valid add end time
     */
    PerfStat::GetInstance().SetAccountQueryEndTime(ACCOUNT_QUERY_END_TIME);
    PerfStat::GetInstance().Dump(result);
    int64_t queryEndTime = PerfStat::GetInstance().GetAccountQueryEndTime();
    EXPECT_EQ(queryEndTime, ACCOUNT_QUERY_END_TIME);
}

/**
 * @tc.name: AccountPerfInvalidEndTimeTest002
 * @tc.desc: invalid end time test
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AccountPerfStatTest, AccountPerfInvalidEndTimeTest002, TestSize.Level0)
{
    /**
    * @tc.steps: step1. set invalid end time
    */
    PerfStat::GetInstance().SetAccountBindStartTime(ACCOUNT_BIND_START_TIME);
    PerfStat::GetInstance().SetAccountBindEndTime(ACCOUNT_BIND_START_TIME - 1);
    int64_t bindEndTime = PerfStat::GetInstance().GetAccountBindEndTime();
    int64_t bindBeginTime = PerfStat::GetInstance().GetAccountBindStartTime();
    EXPECT_EQ(bindEndTime, bindBeginTime);

    PerfStat::GetInstance().SetAccountAddStartTime(ACCOUNT_ADD_START_TIME);
    PerfStat::GetInstance().SetAccountAddEndTime(INVALID_TIME);
    int64_t addStartTime = PerfStat::GetInstance().GetAccountAddStartTime();
    int64_t addEndTime = PerfStat::GetInstance().GetAccountAddEndTime();
    EXPECT_EQ(addStartTime, addEndTime);

    PerfStat::GetInstance().SetAccountQueryStartTime(ACCOUNT_QUERY_START_TIME);
    PerfStat::GetInstance().SetAccountQueryEndTime(INVALID_TIME);
    int64_t queryBeginTime = PerfStat::GetInstance().GetAccountQueryStartTime();
    int64_t queryEndTime = PerfStat::GetInstance().GetAccountQueryEndTime();
    EXPECT_EQ(queryEndTime, queryBeginTime);

    PerfStat::GetInstance().SetAccountDelEndTime(ACCOUNT_DEL_START_TIME);
    PerfStat::GetInstance().SetAccountDelEndTime(INVALID_TIME);
    int64_t delStartTime = PerfStat::GetInstance().GetAccountDelStartTime();
    int64_t delEndTime = PerfStat::GetInstance().GetAccountDelEndTime();
    EXPECT_EQ(delEndTime, delStartTime);
}

/**
 * @tc.name: AccountPerfInvalid001
 * @tc.desc: invalid end time test
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AccountPerfStatTest, AccountPerfInvalid001, TestSize.Level1)
{
    PerfStat::GetInstance().SetInstanceStartTime(0);
    EXPECT_EQ(PerfStat::GetInstance().serviceOnStart_, 0);
    PerfStat::GetInstance().SetInstanceStopTime(0);
    EXPECT_EQ(PerfStat::GetInstance().serviceOnStop_, 0);
    PerfStat::GetInstance().SetInstanceInitTime(0);
    EXPECT_EQ(PerfStat::GetInstance().serviceInit_, 0);

    PerfStat::GetInstance().SetPerfStatEnabled(false);
    EXPECT_EQ(false, PerfStat::GetInstance().GetPerfStatEnabled());

    std::string result;
    PerfStat::GetInstance().Dump(result); // cover !enableStat_
    PerfStat::GetInstance().SetPerfStatEnabled(true);
    PerfStat::GetInstance().Dump(result);

    PerfStat::GetInstance().SetInstanceCreateTime(1);
    PerfStat::GetInstance().SetInstanceInitTime(1);
    PerfStat::GetInstance().SetInstanceStopTime(1);
    PerfStat::GetInstance().SetInstanceInitTime(1);
    PerfStat::GetInstance().accountBindEnd_ = 1;
    PerfStat::GetInstance().accountBindBegin_ = 2; // 2 means it is larger than accountBindEnd_
    PerfStat::GetInstance().Dump(result);

    PerfStat::GetInstance().accountStateChangeRecords_["test"] = 1;
    PerfStat::GetInstance().Dump(result);

    EXPECT_NE(result.find("test"), std::string::npos);
}
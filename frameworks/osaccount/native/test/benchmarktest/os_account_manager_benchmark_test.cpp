/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <benchmark/benchmark.h>
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "os_account_manager.h"
#undef private
#include "os_account_constants.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::vector<std::string> CONSTANTS_VECTOR {
    "constraint.sms.use"
};
const std::string PHOTO_IMG =
    "data:image/"
    "png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AAA"
    "FBSURBVDiN7ZQ/S8NQFMVPxU/QCx06GBzrkqUZ42rBbHWUBDqYxSnUoTxXydCSycVsgltfBiFDR8HNdHGxY4nQQAPvMzwHsWn+KMWsPdN7h/"
    "vj3He5vIaUEjV0UAfe85X83KMBT7N75JEXVdSlfEAVfPRyZ5yfIrBoUkVlMU82Hkp8wu9ddt1vFew4sIiIiKwgzcXIvN7GTZOvpZRrbja3tDG/"
    "D3I1NZvmdCXz+XOv5wJANKHOVYjRTAghxIyh0FHKb+0QQH5+kXf2zkYGAG0oFr5RfnK8DAGkwY19wliRT2L448vjv0YGQFVa8VKdDXUU+"
    "faFUxpblhxYRNRzmd6FNnS0H3/X/VH6j0IIIRxMLJ5k/j/2L/"
    "zchW8pKj7iFAA0R2wajl5d46idlR3+GtPV2XOvQ3bBNvyFs8U39v9PLX0Bp0CN+yY0OAEAAAAASUVORK5CYII=";
const std::int32_t LOCAL_ID = 100;

class OsAccountManagerBenchmarkTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state)
    {}
    void TearDown(const ::benchmark::State &state)
    {}
};

/**
 * @tc.name: OsAccountManagerTestCase001
 * @tc.desc: SetOsAccountName
 * @tc.type: FUNC
 * @tc.require:
 */

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase001)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase001 start!";
    int32_t i = 0;
    for (auto _ : st) {
        i++;
        std::string STRING_NAME = "name_";
        STRING_NAME += to_string(i);
        EXPECT_EQ(OsAccountManager::SetOsAccountName(LOCAL_ID, STRING_NAME), ERR_OK);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase001)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase002
* @tc.desc: IsMultiOsAccountEnable
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase002)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase002 start!";
    bool isMultiOsAccountEnable = false;
    for (auto _ : st) {
        EXPECT_EQ(OsAccountManager::IsMultiOsAccountEnable(isMultiOsAccountEnable), ERR_OK);
        EXPECT_EQ(isMultiOsAccountEnable, true);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase002)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase003
* @tc.desc: IsOsAccountActived
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase003)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase003 start!";
    bool isOsAccountActived = false;
    for (auto _ : st) {
        EXPECT_EQ(OsAccountManager::IsOsAccountActived(LOCAL_ID, isOsAccountActived), ERR_OK);
        EXPECT_EQ(isOsAccountActived, true);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase003)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase004
* @tc.desc: isOsAccountConstraintEnable
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase004)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase004 start!";
    bool isConstraintEnable = false;
    for (auto _ : st) {
        EXPECT_EQ(OsAccountManager::IsOsAccountConstraintEnable(LOCAL_ID, "constraint.wifi.set",
            isConstraintEnable), ERR_OK);
        EXPECT_EQ(isConstraintEnable, true);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase004)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase005
* @tc.desc: IsOsAccountVerified
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase005)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase005 start!";
    bool isVerified = true;
    for (auto _ : st) {
        EXPECT_EQ(OsAccountManager::IsOsAccountVerified(LOCAL_ID, isVerified), ERR_OK);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase005)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase006
* @tc.desc: GetCreatedOsAccountsCount
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase006)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase006 start!";
    unsigned int osAccountsCount = 0;
    for (auto _ : st) {
        EXPECT_EQ(OsAccountManager::GetCreatedOsAccountsCount(osAccountsCount), ERR_OK);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase006)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase007
* @tc.desc: SetOsAccountConstraints
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase007)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase007 start!";
    for (auto _ : st) {
        EXPECT_EQ(OsAccountManager::SetOsAccountConstraints(LOCAL_ID, CONSTANTS_VECTOR, true), ERR_OK);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase007)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase008
* @tc.desc: GetOsAccountLocalIdFromUid
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase008)(
    benchmark::State &st)
{
    int testUid = 1000000;   // uid for test
    int expectedUserID = 5;  // the expected result user ID
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase008 start!";
    for (auto _ : st) {
        int id = -1;
        EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromUid(testUid, id), ERR_OK);
        EXPECT_EQ(expectedUserID, id);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase008)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase009
* @tc.desc: GetOsAccountLocalIdFromProcess
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase009)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase009 start!";
    for (auto _ : st) {
        int id = -1;
        EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromProcess(id), ERR_OK);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase009)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase0010
* @tc.desc: QueryMaxOsAccountNumber
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0010)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase0010 start!";
    for (auto _ : st) {
        int maxOsAccountNumber = 0;
        EXPECT_EQ(OsAccountManager::QueryMaxOsAccountNumber(maxOsAccountNumber), ERR_OK);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0010)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase0011
* @tc.desc: GetOsAccountAllConstraints
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0011)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase0011 start!";
    for (auto _ : st) {
        std::vector<std::string> constraints;
        const unsigned int size = 0;
        EXPECT_EQ(OsAccountManager::GetOsAccountAllConstraints(LOCAL_ID, constraints), ERR_OK);
        EXPECT_NE(size, constraints.size());
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0011)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase0012
* @tc.desc: QueryActiveOsAccountIds
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0012)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase0012 start!";
    for (auto _ : st) {
        std::vector<int32_t> ids;
        const unsigned int size = 0;
        EXPECT_EQ(OsAccountManager::QueryActiveOsAccountIds(ids), ERR_OK);
        EXPECT_NE(size, ids.size());
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0012)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase0013
* @tc.desc: QueryOsAccountById
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0013)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase0013 start!";
    for (auto _ : st) {
        OsAccountInfo osAccountInfo;
        EXPECT_EQ(OsAccountManager::QueryOsAccountById(LOCAL_ID, osAccountInfo), ERR_OK);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0013)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase0014
* @tc.desc: QueryCurrentOsAccount
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0014)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase0014 start!";
    for (auto _ : st) {
        OsAccountInfo osAccountInfo;
        EXPECT_EQ(OsAccountManager::QueryCurrentOsAccount(osAccountInfo), ERR_OK);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0014)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase0015
* @tc.desc: GetOsAccountTypeFromProcess
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0015)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase0015 start!";
    for (auto _ : st) {
        OsAccountType type = OsAccountType::ADMIN;
        EXPECT_EQ(OsAccountManager::GetOsAccountTypeFromProcess(type), ERR_OK);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0015)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase0016
* @tc.desc: GetDistributedVirtualDeviceId
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0016)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase0016 start!";
    for (auto _ : st) {
        std::string deviceId;
        EXPECT_EQ(OsAccountManager::GetDistributedVirtualDeviceId(deviceId), ERR_OK);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0016)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase0017
* @tc.desc: SetOsAccountProfilePhoto
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0017)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase0017 start!";
    for (auto _ : st) {
        EXPECT_EQ(OsAccountManager::SetOsAccountProfilePhoto(LOCAL_ID, PHOTO_IMG), ERR_OK);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0017)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase0018
* @tc.desc: GetOsAccountProfilePhoto
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0018)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase0018 start!";
    for (auto _ : st) {
        std::string photo;
        EXPECT_EQ(OsAccountManager::GetOsAccountProfilePhoto(LOCAL_ID, photo), ERR_OK);
        EXPECT_EQ(photo, PHOTO_IMG);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0018)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase0019
* @tc.desc: GetSerialNumberByOsAccountLocalId
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0019)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase0019 start!";
    for (auto _ : st) {
        int64_t serialNumber;
        EXPECT_EQ(OsAccountManager::GetSerialNumberByOsAccountLocalId(LOCAL_ID, serialNumber), ERR_OK);
        EXPECT_NE(serialNumber, 0);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0019)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase0020
* @tc.desc: GetBundleIdFromUid
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0020)(
    benchmark::State &st)
{
    int expectedBundleID = 5;  // the expected result user ID
    int testUid = 1000000 + expectedBundleID;   // uid for test

    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase0020 start!";
    for (auto _ : st) {
        int id = -1;
        EXPECT_EQ(OsAccountManager::GetBundleIdFromUid(testUid, id), ERR_OK);
        EXPECT_EQ(expectedBundleID, id);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0020)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
* @tc.name: OsAccountManagerTestCase0021
* @tc.desc: IsMainOsAccount
* @tc.type: FUNC
* @tc.require:
*/

BENCHMARK_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0021)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "OsAccountManagerBenchmarkTest OsAccountManagerTestCase0021 start!";
    for (auto _ : st) {
        bool isMainOsAccount = false;
        EXPECT_EQ(OsAccountManager::IsMainOsAccount(isMainOsAccount), ERR_OK);
    }
}

BENCHMARK_REGISTER_F(OsAccountManagerBenchmarkTest, OsAccountManagerTestCase0021)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();
}  // namespace

BENCHMARK_MAIN();
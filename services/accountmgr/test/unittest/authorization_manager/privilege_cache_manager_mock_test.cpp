/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <memory>
#include <fstream>
#include <unistd.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_file_watcher_manager.h"
#include "json_utils.h"
#define protected public
#define private public
#include "privilege_cache_manager.h"
#include "privilege_utils.h"
#undef private
#undef protected
#include "tee_auth_adapter.h"

using namespace testing::ext;
using namespace testing;
namespace OHOS {
namespace AccountSA {
namespace {
const std::string TEST_DIR = "/data/service/el1/public/account/test";
const std::string TEST_CACHE_FILE = TEST_DIR + "/privilege_cache.json";
const int32_t MILLI_SECONDS_PER_SECOND = 1000;
const int32_t MOCK_BOOT_TIME_ONE = 100;
const int32_t MOCK_BOOT_TIME_TWO = 200;
const int32_t DEFAULT_PRIVILEGE_PERIOD = 300; // seconds
const int32_t TEST_UID = 200000;
const int32_t EXPIRED_TIME_OFFSET = 2; // seconds
const int32_t TEST_ERR_CODE = -1;

// Cleanup test files
void CleanupTestFiles()
{
    if (std::filesystem::exists(TEST_CACHE_FILE)) {
        std::filesystem::remove(TEST_CACHE_FILE);
    }
    if (std::filesystem::exists(TEST_DIR)) {
        std::filesystem::remove_all(TEST_DIR);
    }
}
} // namespace

class MockTeeAdapter {
public:
    static MockTeeAdapter &GetInstance()
    {
        static MockTeeAdapter instance;
        return instance;
    }

    MOCK_METHOD(ErrCode, CheckTimestampExpired,
        (const uint32_t grantTime, const int32_t period, int32_t &remainTimeSec, bool &isValid));
};

ErrCode OsAccountTeeAdapter::CheckTimestampExpired(
    const uint32_t grantTime, const int32_t period, int32_t &remainTimeSec, bool &isValid)
{
    return MockTeeAdapter::GetInstance().CheckTimestampExpired(grantTime, period, remainTimeSec, isValid);
}

class MockUtils {
public:
    static MockUtils &GetInstance()
    {
        static MockUtils instance;
        return instance;
    }

    MOCK_METHOD(ErrCode, OpenSmartPidFd, (const int32_t pid, SmartPidFd &fdPtr));
    MOCK_METHOD(ErrCode, GetProcessStartTime, (const int32_t pid, int64_t &startTime));
    MOCK_METHOD(ErrCode, GetUptimeMs, (int64_t & bootTimeStampMs));
    MOCK_METHOD(ErrCode, GetAcl, (const int32_t pid, int32_t &aclLevel));
    MOCK_METHOD(int64_t, AddTimePeriod, (const int64_t bootTimeStampMs, const uint32_t period));
    MOCK_METHOD(int64_t, DecTimePeriod, (const int64_t bootTimeStampMs, const uint32_t period));
};

ErrCode OpenSmartPidFd(const int32_t pid, SmartPidFd &fdPtr)
{
    return MockUtils::GetInstance().OpenSmartPidFd(pid, fdPtr);
}

ErrCode GetProcessStartTime(const int32_t pid, int64_t &startTime)
{
    return MockUtils::GetInstance().GetProcessStartTime(pid, startTime);
}

ErrCode GetUptimeMs(int64_t &bootTimeStampMs)
{
    return MockUtils::GetInstance().GetUptimeMs(bootTimeStampMs);
}

ErrCode GetAcl(const int32_t pid, int32_t &aclLevel)
{
    return MockUtils::GetInstance().GetAcl(pid, aclLevel);
}

int64_t AddTimePeriod(const int64_t bootTimeStampMs, const uint32_t period)
{
    return MockUtils::GetInstance().AddTimePeriod(bootTimeStampMs, period);
}

int64_t DecTimePeriod(const int64_t bootTimeStampMs, const uint32_t period)
{
    return MockUtils::GetInstance().DecTimePeriod(bootTimeStampMs, period);
}

class PrivilegeCacheManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PrivilegeCacheManagerTest::SetUpTestCase()
{
    // init huks
    AccountFileWatcherMgr::GetInstance();
}

void PrivilegeCacheManagerTest::TearDownTestCase()
{
    CleanupTestFiles();
}
void PrivilegeCacheManagerTest::SetUp()
{
    EXPECT_CALL(MockUtils::GetInstance(), OpenSmartPidFd(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(nullptr), Return(ERR_OK)));
    EXPECT_CALL(MockUtils::GetInstance(), GetProcessStartTime(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    EXPECT_CALL(MockUtils::GetInstance(), GetAcl(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(0), Return(ERR_OK)));
    EXPECT_CALL(MockUtils::GetInstance(), AddTimePeriod(_, _))
        .WillRepeatedly(WithArgs<0, 1>(Invoke([](const int64_t bootTimeStampMs, const uint32_t period) {
            return bootTimeStampMs + period * MILLI_SECONDS_PER_SECOND;
        })));
    EXPECT_CALL(MockUtils::GetInstance(), DecTimePeriod(_, _))
        .WillRepeatedly(WithArgs<0, 1>(Invoke([](const int64_t bootTimeStampMs, const uint32_t period) {
            return bootTimeStampMs - period * MILLI_SECONDS_PER_SECOND;
        })));
    EXPECT_CALL(MockTeeAdapter::GetInstance(), CheckTimestampExpired(_, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<2>(MOCK_BOOT_TIME_ONE), SetArgReferee<3>(true), Return(ERR_OK)));
}

void PrivilegeCacheManagerTest::TearDown() {}

static void CheckProcessRecordEqual(const std::shared_ptr<ProcessPrivilegeRecord> &record1,
    const std::shared_ptr<ProcessPrivilegeRecord> &record2)
{
    ASSERT_EQ(record1->pid_, record2->pid_);
    ASSERT_EQ(record1->uid_, record2->uid_);
    ASSERT_EQ(record1->processStartTime_, record2->processStartTime_);
    ASSERT_EQ(record1->GetPrivilegeNum(), record2->GetPrivilegeNum());
    for (const auto &[key, value] : record1->privilegeRecordMap_) {
        auto it = record2->privilegeRecordMap_.find(key);
        ASSERT_TRUE(it != record2->privilegeRecordMap_.end());
        ASSERT_EQ(value->privilegeIdx_, it->second->privilegeIdx_);
        ASSERT_EQ(value->expiredTime_, it->second->expiredTime_);
        ASSERT_EQ(value->safeStartTime_, it->second->safeStartTime_);
    }
}

static void CheckCacheEqual(const std::map<int32_t, std::shared_ptr<ProcessPrivilegeRecord>> &cache1,
    const std::map<int32_t, std::shared_ptr<ProcessPrivilegeRecord>> &cache2)
{
    ASSERT_EQ(cache1.size(), cache2.size());
    for (const auto &[key, value] : cache1) {
        auto it = cache2.find(key);
        ASSERT_TRUE(it != cache2.end());
        CheckProcessRecordEqual(value, it->second);
    }
}

/**
 * @tc.name: AddCacheRecordTest001
 * @tc.desc: Normal function of AddCache
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, AddCacheRecordTest001, TestSize.Level0)
{
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));
    PrivilegeCacheManager tmpMgr;
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillOnce(DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_TWO), Return(ERR_OK)));
    EXPECT_EQ(ERR_OK, tmpMgr.FromPersistFile());
    EXPECT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    EXPECT_EQ(1, tmpMgr.processPrivilegeMap_.size());
    CheckCacheEqual(PrivilegeCacheManager::GetInstance().processPrivilegeMap_, tmpMgr.processPrivilegeMap_);
}

/**
 * @tc.name: RemoveSingleTest001
 * @tc.desc: Normal function of RemoveSingle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, RemoveSingleTest001, TestSize.Level0)
{
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));
    EXPECT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    info.privilegeIdx = 1;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().RemoveSingle(info));
    info.privilegeIdx = 0;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().RemoveSingle(info));
    EXPECT_EQ(0, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    PrivilegeCacheManager tmpMgr;
    EXPECT_EQ(ERR_OK, tmpMgr.FromPersistFile());
    EXPECT_EQ(0, tmpMgr.processPrivilegeMap_.size());
    // remove again, should be oks
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().RemoveSingle(info));
}

/**
 * @tc.name: RemoveUserTest001
 * @tc.desc: Normal function of RemoveUser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, RemoveUserTest001, TestSize.Level0)
{
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));
    EXPECT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());

    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().RemoveUser(0)); // test remove user 0
    EXPECT_EQ(0, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    PrivilegeCacheManager tmpMgr;
    EXPECT_EQ(ERR_OK, tmpMgr.FromPersistFile());
    EXPECT_EQ(0, tmpMgr.processPrivilegeMap_.size());
}

/**
 * @tc.name: RemoveProcessTest001
 * @tc.desc: Normal function of RemoveProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, RemoveProcessTest001, TestSize.Level0)
{
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));
    EXPECT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());

    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().RemoveProcess(getpid())); // test remove user 0
    EXPECT_EQ(0, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    PrivilegeCacheManager tmpMgr;
    EXPECT_EQ(ERR_OK, tmpMgr.FromPersistFile());
    EXPECT_EQ(0, tmpMgr.processPrivilegeMap_.size());
}

/**
 * @tc.name: CheckPrivilegeTest001
 * @tc.desc: Verify CheckPrivilege returns correct remainTime when cache exists,
 *           and returns PERMISSION_DENIED when cache is removed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, CheckPrivilegeTest001, TestSize.Level0)
{
    AuthenCallerInfo info = {.pid = getpid(), .uid = TEST_UID, .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));
    EXPECT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    int32_t remainTime = 0;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().CheckPrivilege(info, remainTime));
    EXPECT_TRUE(remainTime <= DEFAULT_PRIVILEGE_PERIOD);

    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().RemoveSingle(info));
    EXPECT_EQ(0, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    EXPECT_EQ(
        ERR_AUTHORIZATION_PRIVILEGE_DENIED, PrivilegeCacheManager::GetInstance().CheckPrivilege(info, remainTime));
}

/**
 * @tc.name: CheckPrivilegeTest002
 * @tc.desc: Verify CheckPrivilege returns correct remainTime when cache exists and TEE timestamp is valid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, CheckPrivilegeTest002, TestSize.Level0)
{
    AuthenCallerInfo info = {.pid = getpid(), .uid = TEST_UID, .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));
    EXPECT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    // Mock the time to make the privilege in critical state, would check TEE for timestamp validity
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(
            DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_ONE + DEFAULT_PRIVILEGE_PERIOD * MILLI_SECONDS_PER_SECOND - 1),
                Return(ERR_OK)));
    EXPECT_CALL(MockTeeAdapter::GetInstance(), CheckTimestampExpired(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(MOCK_BOOT_TIME_TWO), SetArgReferee<3>(true), Return(ERR_OK)));
    int32_t remainTime = 0;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().CheckPrivilege(info, remainTime));
    ASSERT_EQ(remainTime, MOCK_BOOT_TIME_TWO); // remainTime should be the timestamp from TEE
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().RemoveProcess(getpid()));
    EXPECT_EQ(0, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
}

/**
 * @tc.name: CheckPrivilegeTest003
 * @tc.desc: Verify CheckPrivilege returns PERMISSION_DENIED when TEE timestamp is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, CheckPrivilegeTest003, TestSize.Level0)
{
    AuthenCallerInfo info = {.pid = getpid(), .uid = TEST_UID, .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));
    EXPECT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    // Mock the time to make the privilege in critical state, would check TEE for timestamp validity
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(
            DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_ONE + DEFAULT_PRIVILEGE_PERIOD * MILLI_SECONDS_PER_SECOND - 1),
                Return(ERR_OK)));
    EXPECT_CALL(MockTeeAdapter::GetInstance(), CheckTimestampExpired(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(0), SetArgReferee<3>(false), Return(ERR_OK)));
    int32_t remainTime = 0;
    EXPECT_EQ(
        ERR_AUTHORIZATION_PRIVILEGE_DENIED, PrivilegeCacheManager::GetInstance().CheckPrivilege(info, remainTime));
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().RemoveProcess(getpid()));
    EXPECT_EQ(0, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
}

/**
 * @tc.name: CheckPrivilegeTest004
 * @tc.desc: Verify CheckPrivilege returns PERMISSION_DENIED when privilege period has expired.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, CheckPrivilegeTest004, TestSize.Level0)
{
    AuthenCallerInfo info = {.pid = getpid(), .uid = TEST_UID, .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));
    EXPECT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    // Mock the time to make the privilege in critical state, would check TEE for timestamp validity
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(
            MOCK_BOOT_TIME_ONE + (DEFAULT_PRIVILEGE_PERIOD + EXPIRED_TIME_OFFSET + 1) * MILLI_SECONDS_PER_SECOND),
            Return(ERR_OK)));
    int32_t remainTime = 0;
    EXPECT_EQ(
        ERR_AUTHORIZATION_PRIVILEGE_DENIED, PrivilegeCacheManager::GetInstance().CheckPrivilege(info, remainTime));
    // wait for clean task to remove expired record
    sleep(1);
    // old record should be removed
    EXPECT_EQ(0, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
}

/**
 * @tc.name: CheckPrivilegeTest005
 * @tc.desc: Verify CheckPrivilege returns error code when TEE CheckTimestampExpired fails in critical state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, CheckPrivilegeTest005, TestSize.Level3)
{
    AuthenCallerInfo info = {.pid = getpid(), .uid = TEST_UID, .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));
    EXPECT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    // Mock GetUptimeMs failed
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(
            DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_ONE + DEFAULT_PRIVILEGE_PERIOD * MILLI_SECONDS_PER_SECOND - 1),
                Return(ERR_OK)));
    EXPECT_CALL(MockTeeAdapter::GetInstance(), CheckTimestampExpired(_, _, _, _))
        .WillOnce(DoAll(Return(TEST_ERR_CODE)));
    int32_t remainTime = 0;
    EXPECT_EQ(TEST_ERR_CODE, PrivilegeCacheManager::GetInstance().CheckPrivilege(info, remainTime));
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().RemoveProcess(getpid()));
    EXPECT_EQ(0, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
}

/**
 * @tc.name: CheckPrivilegeAclTest001
 * @tc.desc: Verify CheckPrivilege returns PERMISSION_DENIED when ACL level is 0 (no privilege).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, CheckPrivilegeAclTest001, TestSize.Level0)
{
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    EXPECT_CALL(MockUtils::GetInstance(), GetAcl(_, _)).WillOnce(DoAll(SetArgReferee<1>(0), Return(ERR_OK)));
    int32_t remainTime = 0;
    EXPECT_EQ(
        ERR_AUTHORIZATION_PRIVILEGE_DENIED, PrivilegeCacheManager::GetInstance().CheckPrivilege(info, remainTime));
}

/**
 * @tc.name: CheckPrivilegeAclTest002
 * @tc.desc: Verify CheckPrivilege returns ERR_OK when ACL level is 1 (has privilege).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, CheckPrivilegeAclTest002, TestSize.Level0)
{
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    EXPECT_CALL(MockUtils::GetInstance(), GetAcl(_, _)).WillOnce(DoAll(SetArgReferee<1>(1), Return(ERR_OK)));
    int32_t remainTime = 0;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().CheckPrivilege(info, remainTime));
}

/**
 * @tc.name: CheckPrivilegeAclTest003
 * @tc.desc: Verify CheckPrivilege returns error code when GetAcl fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, CheckPrivilegeAclTest003, TestSize.Level3)
{
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    EXPECT_CALL(MockUtils::GetInstance(), GetAcl(_, _)).WillOnce(DoAll(SetArgReferee<1>(1), Return(TEST_ERR_CODE)));
    int32_t remainTime = 0;
    EXPECT_EQ(TEST_ERR_CODE, PrivilegeCacheManager::GetInstance().CheckPrivilege(info, remainTime));
}

/**
 * @tc.name: PrivilegeRecordCovTest001
 * @tc.desc: Verify PrivilegeRecord::FromJson returns nullptr for invalid JSON inputs.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, PrivilegeRecordCovTest001, TestSize.Level3)
{
    cJSON *testPtr = nullptr;
    EXPECT_EQ(nullptr, PrivilegeRecord::FromJson(testPtr));

    auto testArr = CreateJsonArray();
    EXPECT_EQ(nullptr, PrivilegeRecord::FromJson(testArr.get()));

    auto testObj = CreateJsonFromString("{}");
    EXPECT_EQ(nullptr, PrivilegeRecord::FromJson(testObj.get()));
    testObj = CreateJsonFromString(R"({\"privilegeName\":\"invalid\"})");
    EXPECT_EQ(nullptr, PrivilegeRecord::FromJson(testObj.get()));
    testObj = CreateJsonFromString(R"({\"privilegeName\":\"ohos.privilege.manage_local_accounts\"})");
    EXPECT_EQ(nullptr, PrivilegeRecord::FromJson(testObj.get()));
    testObj = CreateJsonFromString(
            R"({\"privilegeName\":\"ohos.privilege.manage_local_accounts\", \"expiredTimeStamp\":\"\"})");
    EXPECT_EQ(nullptr, PrivilegeRecord::FromJson(testObj.get()));
    testObj = CreateJsonFromString(
        R"({\"privilegeName\":\"ohos.privilege.manage_local_accounts\",
        \"expiredTimeStamp\":\"100\", \"safeStartTime\":\"\"})");
    EXPECT_EQ(nullptr, PrivilegeRecord::FromJson(testObj.get()));
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest001
 * @tc.desc: Verify CreateEmptyProcessPrivilegeRecord handles GetProcessStartTime and OpenSmartPidFd failures.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest001, TestSize.Level3)
{
    AuthenCallerInfo info = {.pid = 0, .uid = 0, .privilegeIdx = 0};
    std::shared_ptr<ProcessPrivilegeRecord> record = nullptr;
    EXPECT_CALL(MockUtils::GetInstance(), GetProcessStartTime(_, _))
        .WillOnce(DoAll(Return(ERR_ACCOUNT_COMMON_FILE_NOT_EXIST)));
    EXPECT_EQ(ERR_ACCOUNT_COMMON_FILE_NOT_EXIST,
        ProcessPrivilegeRecord::CreateEmptyProcessPrivilegeRecord(info, record));
    EXPECT_CALL(MockUtils::GetInstance(), GetProcessStartTime(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    EXPECT_CALL(MockUtils::GetInstance(), OpenSmartPidFd(_, _))
        .WillOnce(DoAll(Return(TEST_ERR_CODE)));
    EXPECT_EQ(TEST_ERR_CODE, ProcessPrivilegeRecord::CreateEmptyProcessPrivilegeRecord(info, record));
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest002
 * @tc.desc: Verify ParsePrivilegeRecordJsonArray returns error for invalid privilege name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest002, TestSize.Level3)
{
    auto testObj = CreateJsonFromString(
        R"({
        "pid":13251, "uid":0,
        "processStartTime":"100",
        "privilegeRecords":[{
            "privilegeName":"invalid"
        }]})");
    ASSERT_NE(nullptr, testObj);
    ProcessPrivilegeRecord record;
    auto arrayPtr = GetJsonArrayFromJson(testObj.get(), "privilegeRecords");
    ASSERT_NE(nullptr, arrayPtr);
    EXPECT_EQ(
        ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR, record.ParsePrivilegeRecordJsonArray(MOCK_BOOT_TIME_ONE, arrayPtr));
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest003
 * @tc.desc: Verify ParsePrivilegeRecordJsonArray filters out records when AddTimePeriod returns invalid timestamp.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest003, TestSize.Level3)
{
    auto testObj = CreateJsonFromString(
        R"({"pid":13251,"uid":0,
        "processStartTime":"100",
        "privilegeRecords":[{
            "privilegeName":"ohos.privilege.manage_local_accounts",
            "expiredTimeStamp": "300100",
            "safeStartTime": 100
        }]})");
    ASSERT_NE(nullptr, testObj);
    ProcessPrivilegeRecord record;
    auto arrayPtr = GetJsonArrayFromJson(testObj.get(), "privilegeRecords");
    ASSERT_NE(nullptr, arrayPtr);
    EXPECT_CALL(MockUtils::GetInstance(), AddTimePeriod(_, _))
        .WillOnce(WithArgs<0, 1>(Invoke([](const int64_t bootTimeStampMs, const uint32_t period) {
            return 0;
        })));
    EXPECT_EQ(ERR_OK, record.ParsePrivilegeRecordJsonArray(MOCK_BOOT_TIME_ONE, arrayPtr));
    EXPECT_EQ(record.privilegeRecordMap_.size(), 0);
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest004
 * @tc.desc: Verify ProcessPrivilegeRecord::FromJson handles missing required fields and process check failures.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest004, TestSize.Level3)
{
    std::shared_ptr<ProcessPrivilegeRecord> record = nullptr;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR, ProcessPrivilegeRecord::FromJson(0, nullptr, record));
    ASSERT_EQ(nullptr, record);
    // do not have pid
    auto testObj = CreateJsonFromString(R"({})");
    ASSERT_NE(nullptr, testObj);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR, ProcessPrivilegeRecord::FromJson(0, testObj.get(), record));
    ASSERT_EQ(nullptr, record);
    // do not have uid
    testObj = CreateJsonFromString(R"({"pid":13251})");
    ASSERT_NE(nullptr, testObj);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR, ProcessPrivilegeRecord::FromJson(0, testObj.get(), record));
    ASSERT_EQ(nullptr, record);
    // do not have processStartTime
    testObj = CreateJsonFromString(R"({"pid":13251,"uid":0})");
    ASSERT_NE(nullptr, testObj);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR, ProcessPrivilegeRecord::FromJson(0, testObj.get(), record));
    ASSERT_EQ(nullptr, record);
    // check pid stat failed
    testObj = CreateJsonFromString(
        R"({"pid":13251,"uid":0,
        "processStartTime":"100",
        "privilegeRecords":[]})");
    ASSERT_NE(nullptr, testObj);
    EXPECT_CALL(MockUtils::GetInstance(), GetProcessStartTime(_, _))
        .WillOnce(DoAll(Return(TEST_ERR_CODE)));
    EXPECT_EQ(ERR_AUTHORIZATION_CHECK_TIME_FAILED, ProcessPrivilegeRecord::FromJson(0, testObj.get(), record));
    EXPECT_CALL(MockUtils::GetInstance(), GetProcessStartTime(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    // OpenSmartPidFd failed
    EXPECT_CALL(MockUtils::GetInstance(), OpenSmartPidFd(_, _)).WillOnce(DoAll(Return(TEST_ERR_CODE)));
    EXPECT_EQ(TEST_ERR_CODE, ProcessPrivilegeRecord::FromJson(0, testObj.get(), record));
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest005
 * @tc.desc: Verify ProcessPrivilegeRecord::FromJson handles missing or invalid privilegeRecords field.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest005, TestSize.Level3)
{
    // do not have privilegeRecords
    auto testObj = CreateJsonFromString(
        R"({"pid":13251,"uid":0,
        "processStartTime":"100"})");
    ASSERT_NE(nullptr, testObj);
    std::shared_ptr<ProcessPrivilegeRecord> record = nullptr;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR, ProcessPrivilegeRecord::FromJson(0, testObj.get(), record));
    // privilegeRecords is not array
    testObj = CreateJsonFromString(
        R"({"pid":13251,"uid":0,
        "processStartTime":"100",
        "privilegeRecords":"123"})");
    ASSERT_NE(nullptr, testObj);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR, ProcessPrivilegeRecord::FromJson(0, testObj.get(), record));
    // privilegeRecords item invalid
    testObj = CreateJsonFromString(
        R"({"pid":13251,"uid":0,
        "processStartTime":"100",
        "privilegeRecords":[{}]})");
    ASSERT_NE(nullptr, testObj);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR, ProcessPrivilegeRecord::FromJson(0, testObj.get(), record));
    // privilegeRecords is empty, should create nothing
    testObj = CreateJsonFromString(
        R"({"pid":13251,"uid":0,
        "processStartTime":"100",
        "privilegeRecords":[]})");
    ASSERT_NE(nullptr, testObj);
    EXPECT_EQ(ERR_OK, ProcessPrivilegeRecord::FromJson(0, testObj.get(), record));
    EXPECT_EQ(nullptr, record);
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest006
 * @tc.desc: Verify ToJson returns ERR_OK with null jsonObjPtr when privilegeRecordMap_ is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest006, TestSize.Level3)
{
    ProcessPrivilegeRecord record;
    EXPECT_EQ(0, record.GetPrivilegeNum());
    CJsonUnique jsonObjPtr = nullptr;
    EXPECT_EQ(ERR_OK, record.ToJson(jsonObjPtr));
    EXPECT_EQ(nullptr, jsonObjPtr);
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest007
 * @tc.desc: Verify CheckPrivilege handles GetUptimeMs failure and missing privilege record.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest007, TestSize.Level3)
{
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillOnce(DoAll(Return(TEST_ERR_CODE)));
    ProcessPrivilegeRecord record;
    int32_t remainTime = 0;
    EXPECT_EQ(TEST_ERR_CODE, record.CheckPrivilege(0, remainTime));
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    // record not exists
    EXPECT_EQ(ERR_AUTHORIZATION_PRIVILEGE_DENIED, record.CheckPrivilege(0, remainTime));
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest008
 * @tc.desc: Verify AddCache returns error code when GetProcessStartTime fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest008, TestSize.Level3)
{
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_CALL(MockUtils::GetInstance(), GetProcessStartTime(_, _)).WillOnce(DoAll(Return(TEST_ERR_CODE)));
    EXPECT_EQ(TEST_ERR_CODE, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));

    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().RemoveProcess(info.pid));
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest009
 * @tc.desc: Verify CheckProcessAlive handles invalid PID and process start time mismatch scenarios.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest009, TestSize.Level3)
{
    ProcessPrivilegeRecord record;
    record.pid_ = 0;
    EXPECT_EQ(false, record.CheckProcessAlive());
    record.pid_ = getpid();
    EXPECT_CALL(MockUtils::GetInstance(), GetProcessStartTime(_, _)).WillOnce(DoAll(Return(TEST_ERR_CODE)));
    EXPECT_EQ(false, record.CheckProcessAlive());

    EXPECT_CALL(MockUtils::GetInstance(), GetProcessStartTime(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    record.processStartTime_ = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(true, record.CheckProcessAlive());

    record.processStartTime_ = MOCK_BOOT_TIME_TWO;
    // consider start time not equal as process not found
    EXPECT_EQ(false, record.CheckProcessAlive());
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest010
 * @tc.desc: Verify AddCache returns error code when GetUptimeMs fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest010, TestSize.Level3)
{
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));

    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_)).WillOnce(DoAll(Return(TEST_ERR_CODE)));
    EXPECT_EQ(TEST_ERR_CODE, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest011
 * @tc.desc: Verify RemoveUser removes only records matching the specified user ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest011, TestSize.Level3)
{
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));

    info = {.pid = getpid() + 1, .uid = TEST_UID, .privilegeIdx = 0};
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));

    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().RemoveUser(0)); // test remove user 0
    EXPECT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    EXPECT_EQ(TEST_UID, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.begin()->second->uid_);

    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest012
 * @tc.desc: Verify FromPersistFile returns error code when GetUptimeMs fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest012, TestSize.Level3)
{
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_)).WillOnce(DoAll(Return(TEST_ERR_CODE)));
    PrivilegeCacheManager tmpMgr;
    EXPECT_EQ(TEST_ERR_CODE, tmpMgr.FromPersistFile()); // test from persist file fail
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest013
 * @tc.desc: test CheckUpdateTimeValid when updateTime equals currTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest013, TestSize.Level3)
{
    const int64_t currTime = MOCK_BOOT_TIME_ONE;
    const int64_t updateTime = MOCK_BOOT_TIME_ONE;

    auto jsonObj = CreateJson();
    ASSERT_NE(nullptr, jsonObj);
    EXPECT_TRUE(AddInt64ToJson(jsonObj, "updateTime", updateTime));

    EXPECT_EQ(ERR_AUTHORIZATION_CHECK_TIME_FAILED,
        PrivilegeCacheManager::GetInstance().CheckUpdateTimeValid(jsonObj, currTime));
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest014
 * @tc.desc: test CheckUpdateTimeValid when updateTime is later than currTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest014, TestSize.Level3)
{
    const int64_t currTime = MOCK_BOOT_TIME_ONE;
    const int64_t updateTime = MOCK_BOOT_TIME_TWO;

    auto jsonObj = CreateJson();
    ASSERT_NE(nullptr, jsonObj);
    EXPECT_TRUE(AddInt64ToJson(jsonObj, "updateTime", updateTime));

    EXPECT_EQ(ERR_AUTHORIZATION_CHECK_TIME_FAILED,
        PrivilegeCacheManager::GetInstance().CheckUpdateTimeValid(jsonObj, currTime));
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest015
 * @tc.desc: test CheckUpdateTimeValid with missing updateTime field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest015, TestSize.Level3)
{
    const int64_t currTime = MOCK_BOOT_TIME_TWO;

    auto jsonObj = CreateJson();
    ASSERT_NE(nullptr, jsonObj);
    // Don't add updateTime field

    EXPECT_EQ(ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR,
        PrivilegeCacheManager::GetInstance().CheckUpdateTimeValid(jsonObj, currTime));
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest016
 * @tc.desc: test ReadAndCheckPersistRecordValid with invalid JSON format
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest016, TestSize.Level3)
{
    const int64_t currTime = MOCK_BOOT_TIME_TWO;
    std::string recordStr;

    // Create file with invalid JSON
    AccountFileOperator fileOperator;
    std::string invalidJson = "invalid json content{{{";
    EXPECT_EQ(ERR_OK, fileOperator.InputFileByPathAndContentWithTransaction(TEST_CACHE_FILE, invalidJson));
    bool needSkipLoading = false;
    PrivilegeCacheManager::GetInstance().ReadAndCheckPersistRecordValid(currTime, recordStr, needSkipLoading);
    ASSERT_TRUE(needSkipLoading);
    // Cleanup
    CleanupTestFiles();
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest017
 * @tc.desc: test ReadAndCheckPersistRecordValid with missing processRecords field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest017, TestSize.Level3)
{
    const int64_t currTime = MOCK_BOOT_TIME_TWO;
    std::string recordStr;

    // Create a cache file without processRecords field
    auto jsonObj = CreateJson();
    EXPECT_TRUE(AddInt64ToJson(jsonObj, "updateTime", MOCK_BOOT_TIME_ONE));
    EXPECT_TRUE(AddStringToJson(jsonObj, "digest", "test_digest"));
    // Don't add processRecords field

    std::string jsonStr = PackJsonToString(jsonObj);
    AccountFileOperator fileOperator;
    EXPECT_EQ(ERR_OK, fileOperator.InputFileByPathAndContentWithTransaction(TEST_CACHE_FILE, jsonStr));
    bool needSkipLoading = false;
    PrivilegeCacheManager::GetInstance().ReadAndCheckPersistRecordValid(currTime, recordStr, needSkipLoading);
    ASSERT_TRUE(needSkipLoading);

    // Cleanup
    CleanupTestFiles();
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest018
 * @tc.desc: test ReadAndCheckPersistRecordValid with missing updateTime field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest018, TestSize.Level3)
{
    const int64_t currTime = MOCK_BOOT_TIME_TWO;
    std::string recordStr;

    // Create a cache file without updateTime field
    auto jsonObj = CreateJson();
    EXPECT_TRUE(AddStringToJson(jsonObj, "digest", "test_digest"));
    EXPECT_TRUE(AddStringToJson(jsonObj, "processRecords", "[]"));
    // Don't add updateTime field

    std::string jsonStr = PackJsonToString(jsonObj);
    AccountFileOperator fileOperator;
    EXPECT_EQ(ERR_OK, fileOperator.InputFileByPathAndContentWithTransaction(TEST_CACHE_FILE, jsonStr));
    bool needSkipLoading = false;
    PrivilegeCacheManager::GetInstance().ReadAndCheckPersistRecordValid(currTime, recordStr, needSkipLoading);
    ASSERT_TRUE(needSkipLoading);

    // Cleanup
    CleanupTestFiles();
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest019
 * @tc.desc: test ReadAndCheckPersistRecordValid file deletion on time check failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest019, TestSize.Level3)
{
    const int64_t currTime = MOCK_BOOT_TIME_ONE;
    std::string recordStr;

    // Create a cache file with future updateTime
    auto jsonObj = CreateJson();
    EXPECT_TRUE(AddInt64ToJson(jsonObj, "updateTime", MOCK_BOOT_TIME_TWO));
    EXPECT_TRUE(AddStringToJson(jsonObj, "digest", "test_digest"));
    EXPECT_TRUE(AddStringToJson(jsonObj, "processRecords", "[]"));

    std::string jsonStr = PackJsonToString(jsonObj);
    AccountFileOperator fileOperator;
    EXPECT_EQ(ERR_OK, fileOperator.InputFileByPathAndContentWithTransaction(TEST_CACHE_FILE, jsonStr));

    // Verify file exists
    EXPECT_TRUE(fileOperator.IsExistFile(TEST_CACHE_FILE));
    bool needSkipLoading = false;
    PrivilegeCacheManager::GetInstance().ReadAndCheckPersistRecordValid(currTime, recordStr, needSkipLoading);
    ASSERT_TRUE(needSkipLoading);
    // Verify file was deleted
    EXPECT_FALSE(fileOperator.IsExistFile(TEST_CACHE_FILE));

    // Cleanup
    CleanupTestFiles();
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest020
 * @tc.desc: test ReadAndCheckPersistRecordValid when stored digest doesn't match calculated digest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest020, TestSize.Level3)
{
    const int64_t currTime = MOCK_BOOT_TIME_TWO;
    std::string recordStr;

    // Create a cache file with valid structure but mismatched digest
    auto jsonObj = CreateJson();
    EXPECT_TRUE(AddInt64ToJson(jsonObj, "updateTime", MOCK_BOOT_TIME_ONE));

    // Create a valid processRecords string
    std::string processRecords = R"([{"pid":12345,"uid":200000,"processStartTime":100,"privilegeRecords":[]}])";

    // Add an incorrect digest (not matching the actual content)
    std::vector<uint8_t> fakeDigest = {0x01, 0x02, 0x03, 0x04, 0x05};
    EXPECT_TRUE(AddVectorUint8ToJson(jsonObj, "digest", fakeDigest));

    EXPECT_TRUE(AddStringToJson(jsonObj, "processRecords", processRecords));

    std::string jsonStr = PackJsonToString(jsonObj);

    // Write the file
    AccountFileOperator fileOperator;
    EXPECT_EQ(ERR_OK, fileOperator.InputFileByPathAndContentWithTransaction(TEST_CACHE_FILE, jsonStr));

    // Verify file exists before test
    EXPECT_TRUE(fileOperator.IsExistFile(TEST_CACHE_FILE));

    // Call ReadAndCheckPersistRecordValid
    // This should needSkipLoading=true because the digest doesn't match
    bool needSkipLoading = false;
    PrivilegeCacheManager::GetInstance().ReadAndCheckPersistRecordValid(currTime, recordStr, needSkipLoading);
    ASSERT_TRUE(needSkipLoading);

    // Verify file was deleted after digest mismatch
    EXPECT_FALSE(fileOperator.IsExistFile(TEST_CACHE_FILE));

    // Cleanup
    CleanupTestFiles();
}

/**
 * @tc.name: ProcessPrivilegeRecordCovTest021
 * @tc.desc: test CleanExpiredPrivilegesAndSaveToFile when GetUptimeMs fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, ProcessPrivilegeRecordCovTest021, TestSize.Level3)
{
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_)).WillOnce(DoAll(Return(TEST_ERR_CODE)));
    PrivilegeCacheManager tmpMgr;
    EXPECT_EQ(TEST_ERR_CODE,
        tmpMgr.CleanExpiredPrivilegesAndSaveToFile()); // test CleanExpiredPrivilegesAndSaveToFile file fail
}
} // namespace AccountSA
} // namespace OHOS
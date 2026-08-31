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
#include <thread>
#include <chrono>
#include <fcntl.h>
#include <cstring>
#include <cstdarg>
#include <sys/ioctl.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_file_watcher_manager.h"
#include "json_utils.h"
#include "kernel_authorization_adapter.h"
#define protected public
#define private public
#include "privilege_cache_manager.h"
#include "privilege_utils.h"
#undef private
#undef protected
#include "tee_auth_adapter.h"
#include "account_test_common.h"

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
const int32_t MOCK_KERNEL_PID = 9999;
const int32_t MOCK_KERNEL_FD = 99999;
const int32_t CLEAN_TASK_RETRY_TIMES = 30;
const int32_t CLEAN_TASK_RETRY_INTERVAL_MS = 100;
const int32_t INVALID_AUTH_STATUS = 999;
const int32_t NON_EXISTENT_PRIVILEGE_IDX = 99;
const int64_t TEST_EXPIRED_TIME_MS = 100;
const int64_t TEST_CURRENT_TIME_BEFORE_EXPIRY = 50;
const int64_t TEST_CURRENT_TIME_AFTER_EXPIRY = 3000;

enum class MockKernelState {
    DEVICE_ABSENT,
    OPEN_FAILED,
    IOCTL_FAIL,
    IOCTL_SUCCESS_QUERY_AUTH,
    IOCTL_SUCCESS_QUERY_UNAUTH,
};
MockKernelState g_mockKernelState = MockKernelState::DEVICE_ABSENT;

static ErrCode PrepareKernelAuthCacheHelper(const AuthenCallerInfo &info)
{
    int64_t currTime = 0;
    return PrivilegeCacheManager::GetInstance().PrepareKernelAuthCache(info, currTime);
}

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

class OsAccountTeeAdapter::Impl {
public:
    Impl() = default;
    ~Impl() = default;
};
OsAccountTeeAdapter::OsAccountTeeAdapter() : impl_(std::make_unique<Impl>()) {};
OsAccountTeeAdapter::~OsAccountTeeAdapter() = default;

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
    ASSERT_TRUE(MockTokenId("accountmgr"));
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

void PrivilegeCacheManagerTest::TearDown()
{
    // Wait for any background StartCleanTask thread to release mapMutex_
    for (int i = 0; i < CLEAN_TASK_RETRY_TIMES; i++) {
        std::unique_lock<std::recursive_mutex> testLock(
            PrivilegeCacheManager::GetInstance().mapMutex_, std::try_to_lock);
        if (testLock.owns_lock()) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(CLEAN_TASK_RETRY_INTERVAL_MS));
    }
}

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
    // currentTime(500000) > expiryWithOffset(302100) → NeedClean returns true → record filtered
    int64_t expiredTime = 500000;
    EXPECT_EQ(ERR_OK, record.ParsePrivilegeRecordJsonArray(expiredTime, arrayPtr));
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
    int64_t updateTimeFromJson = 0;
    EXPECT_EQ(ERR_AUTHORIZATION_CHECK_TIME_FAILED,
        PrivilegeCacheManager::GetInstance().CheckUpdateTimeValid(jsonObj, currTime, updateTimeFromJson));
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
    int64_t updateTimeFromJson = 0;
    EXPECT_EQ(ERR_AUTHORIZATION_CHECK_TIME_FAILED,
        PrivilegeCacheManager::GetInstance().CheckUpdateTimeValid(jsonObj, currTime, updateTimeFromJson));
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
    int64_t updateTimeFromJson = 0;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR,
        PrivilegeCacheManager::GetInstance().CheckUpdateTimeValid(jsonObj, currTime, updateTimeFromJson));
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

/**
 * @tc.name: RemoveSingleRollbackTest001
 * @tc.desc: Verify RemoveSingle correctly rolls back when CleanExpiredPrivilegesAndSaveToFile fails
 *           (mocked by GetUptimeMs failure), and the process still has other privileges (not empty).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, RemoveSingleRollbackTest001, TestSize.Level1)
{
    // Setup: Add process with two privileges
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));

    info.privilegeIdx = 1;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));

    ASSERT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    ASSERT_EQ(2, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.begin()->second->GetPrivilegeNum());

    size_t initialPrivCount = PrivilegeCacheManager::GetInstance()
        .processPrivilegeMap_.begin()->second->GetPrivilegeNum();

    // Mock GetUptimeMs to fail, which will cause CleanExpiredPrivilegesAndSaveToFile to fail
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillOnce(DoAll(Return(TEST_ERR_CODE)));

    // Remove one privilege (should rollback on failure)
    info.privilegeIdx = 0;
    ErrCode ret = PrivilegeCacheManager::GetInstance().RemoveSingle(info);

    // Verify rollback occurred: privilege count should be restored
    EXPECT_NE(ERR_OK, ret) << "RemoveSingle should fail when file write fails";
    EXPECT_EQ(initialPrivCount, PrivilegeCacheManager::GetInstance()
        .processPrivilegeMap_.begin()->second->GetPrivilegeNum())
        << "Both privileges should be restored after rollback";

    // Restore normal mock behavior for other tests
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: RemoveSingleRollbackTest002
 * @tc.desc: Verify RemoveSingle correctly rolls back when CleanExpiredPrivilegesAndSaveToFile fails
 *           (mocked by GetUptimeMs failure) and removing the last privilege causes the process record to be deleted.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, RemoveSingleRollbackTest002, TestSize.Level1)
{
    // Setup: Add process with one privilege
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));

    ASSERT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    ASSERT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.begin()->second->GetPrivilegeNum());

    // Mock GetUptimeMs to fail, which will cause CleanExpiredPrivilegesAndSaveToFile to fail
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillOnce(DoAll(Return(TEST_ERR_CODE)));

    // Remove the only privilege (process will be deleted, then rolled back)
    ErrCode ret = PrivilegeCacheManager::GetInstance().RemoveSingle(info);

    // Verify rollback occurred
    EXPECT_NE(ERR_OK, ret) << "RemoveSingle should fail when file write fails";
    EXPECT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size())
        << "Process record should be restored";
    EXPECT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.begin()->second->GetPrivilegeNum())
        << "Privilege should be restored";

    // Restore normal mock behavior for other tests
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: AddCacheRollbackTest001
 * @tc.desc: Verify AddCache fails when CleanExpiredPrivilegesAndSaveToFile fails
 *           (mocked by GetUptimeMs failure) when adding a new privilege to an existing process.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, AddCacheRollbackTest001, TestSize.Level1)
{
    // Setup: Add process with one privilege
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));

    ASSERT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    size_t initialPrivCount = PrivilegeCacheManager::GetInstance()
        .processPrivilegeMap_.begin()->second->GetPrivilegeNum();

    // Mock GetUptimeMs to fail, which will cause CleanExpiredPrivilegesAndSaveToFile to fail
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillOnce(DoAll(Return(TEST_ERR_CODE)));

    // Add another privilege (should fail on file write)
    info.privilegeIdx = 1;
    ErrCode ret = PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime);

    // Verify failure occurred
    EXPECT_NE(ERR_OK, ret) << "AddCache should fail when file write fails";
    EXPECT_EQ(initialPrivCount, PrivilegeCacheManager::GetInstance()
        .processPrivilegeMap_.begin()->second->GetPrivilegeNum())
        << "Only original privilege should exist after failure";

    // Restore normal mock behavior for other tests
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: AddCacheRollbackTest002
 * @tc.desc: Verify AddCache fails when CleanExpiredPrivilegesAndSaveToFile fails
 *           (mocked by GetUptimeMs failure) when updating an existing privilege.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, AddCacheRollbackTest002, TestSize.Level1)
{
    // Setup: Add process with a privilege
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));

    ASSERT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());

    // Get the old privilege record for comparison
    auto &processRecord = PrivilegeCacheManager::GetInstance().processPrivilegeMap_[getpid()];
    auto oldPrivCount = processRecord->GetPrivilegeNum();

    // Mock GetUptimeMs to fail, which will cause CleanExpiredPrivilegesAndSaveToFile to fail
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillOnce(DoAll(Return(TEST_ERR_CODE)));

    // Update the same privilege with new safeStartTime (should fail on file write)
    int32_t newSafeStartTime = MOCK_BOOT_TIME_TWO;
    ErrCode ret = PrivilegeCacheManager::GetInstance().AddCache(info, newSafeStartTime);

    // Verify failure occurred
    EXPECT_NE(ERR_OK, ret) << "AddCache should fail when file write fails";
    EXPECT_EQ(oldPrivCount, processRecord->GetPrivilegeNum())
        << "Privilege count should remain the same after failure";

    // Restore normal mock behavior for other tests
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: AddCacheRollbackTest003
 * @tc.desc: Verify AddCache fails when CleanExpiredPrivilegesAndSaveToFile fails
 *           (mocked by GetUptimeMs failure) when creating a new process.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, AddCacheRollbackTest003, TestSize.Level1)
{
    // Setup: Start with empty cache
    ASSERT_EQ(0, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());

    // Mock GetUptimeMs to fail, which will cause CleanExpiredPrivilegesAndSaveToFile to fail
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillOnce(DoAll(Return(TEST_ERR_CODE)));

    // Add new process (should fail on file write)
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    ErrCode ret = PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime);

    // Verify failure occurred
    EXPECT_NE(ERR_OK, ret) << "AddCache should fail when file write fails";
    EXPECT_EQ(0, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size())
        << "New process should be removed from map after failure";

    // Restore normal mock behavior for other tests
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: RollbackDelSingleRecordTest001
 * @tc.desc: Verify RollbackDelSingleRecord correctly restores a deleted privilege when process exists.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, RollbackDelSingleRecordTest001, TestSize.Level1)
{
    // Setup: Create a process record with privileges
    std::shared_ptr<ProcessPrivilegeRecord> processRecord = std::make_shared<ProcessPrivilegeRecord>();
    processRecord->pid_ = 1000;
    processRecord->uid_ = 0;
    processRecord->processStartTime_ = MOCK_BOOT_TIME_ONE;

    // Create a privilege record to be "removed"
    auto removedPrivilege = std::make_shared<PrivilegeRecord>(0, MOCK_BOOT_TIME_ONE + 300000, MOCK_BOOT_TIME_ONE);

    // Add the process to cache with one privilege
    processRecord->privilegeRecordMap_[1] = std::make_shared<PrivilegeRecord>(
        1, MOCK_BOOT_TIME_ONE + 300000, MOCK_BOOT_TIME_ONE);

    PrivilegeCacheManager::GetInstance().processPrivilegeMap_[1000] = processRecord;

    ASSERT_EQ(1, processRecord->GetPrivilegeNum()) << "Process should start with 1 privilege";

    // Call RollbackDelSingleRecord to restore the removed privilege
    PrivilegeCacheManager::GetInstance().RollbackDelSingleRecord(processRecord, removedPrivilege);

    // Verify the removed privilege was restored
    EXPECT_EQ(2, processRecord->GetPrivilegeNum()) << "Process should have 2 privileges after rollback";
    EXPECT_TRUE(processRecord->privilegeRecordMap_.find(0) != processRecord->privilegeRecordMap_.end())
        << "Removed privilege (idx=0) should be restored";

    // Cleanup
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: RollbackDelRecordTest002
 * @tc.desc: Verify RollbackDelRecord correctly restores entire process when process doesn't exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, RollbackDelRecordTest002, TestSize.Level1)
{
    // Setup: Create a process record (simulating it was deleted)
    std::shared_ptr<ProcessPrivilegeRecord> processRecord = std::make_shared<ProcessPrivilegeRecord>();
    processRecord->pid_ = 1000;
    processRecord->uid_ = 0;
    processRecord->processStartTime_ = MOCK_BOOT_TIME_ONE;

    // Add two privileges
    auto priv0 = std::make_shared<PrivilegeRecord>(0, MOCK_BOOT_TIME_ONE + 300000, MOCK_BOOT_TIME_ONE);
    auto priv1 = std::make_shared<PrivilegeRecord>(1, MOCK_BOOT_TIME_ONE + 300000, MOCK_BOOT_TIME_ONE);
    processRecord->privilegeRecordMap_[0] = priv0;
    processRecord->privilegeRecordMap_[1] = priv1;

    // Ensure process is NOT in cache (simulating deletion)
    ASSERT_EQ(0, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.count(1000));

    // Call RollbackDelRecord with removedRecord = nullptr (entire process was deleted)
    PrivilegeCacheManager::GetInstance().RollbackDelSingleRecord(processRecord, nullptr);

    // Verify the entire process was restored
    EXPECT_EQ(0, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    auto it = PrivilegeCacheManager::GetInstance().processPrivilegeMap_.find(1000);
    ASSERT_TRUE(it == PrivilegeCacheManager::GetInstance().processPrivilegeMap_.end());

    // Cleanup
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: RollbackDelRecordTest003
 * @tc.desc: Verify RollbackDelRecord handles nullptr removedRecord when process exists.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, RollbackDelRecordTest003, TestSize.Level1)
{
    // Setup: Create a process in cache
    std::shared_ptr<ProcessPrivilegeRecord> processRecord = std::make_shared<ProcessPrivilegeRecord>();
    processRecord->pid_ = 1000;
    processRecord->uid_ = 0;
    processRecord->processStartTime_ = MOCK_BOOT_TIME_ONE;

    auto priv0 = std::make_shared<PrivilegeRecord>(0, MOCK_BOOT_TIME_ONE + 300000, MOCK_BOOT_TIME_ONE);
    processRecord->privilegeRecordMap_[0] = priv0;

    PrivilegeCacheManager::GetInstance().processPrivilegeMap_[1000] = processRecord;

    auto initialPrivCount = processRecord->GetPrivilegeNum();

    // Call RollbackDelRecord with removedRecord = nullptr (no specific privilege to restore)
    PrivilegeCacheManager::GetInstance().RollbackDelSingleRecord(processRecord, nullptr);

    // Verify state is unchanged
    EXPECT_EQ(initialPrivCount, processRecord->GetPrivilegeNum())
        << "Privilege count should remain the same";

    // Cleanup
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}


/**
 * @tc.name: RollbackEdgeCaseTest001
 * @tc.desc: Verify RemoveSingle correctly rolls back when CleanExpiredPrivilegesAndSaveToFile fails
 *           (mocked by GetUptimeMs failure) and the process record becomes empty after removal.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, RollbackEdgeCaseTest001, TestSize.Level1)
{
    // Setup: Create a process with one privilege
    AuthenCallerInfo info = {.pid = getpid(), .uid = getuid(), .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, safeStartTime));

    ASSERT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());

    // Get the process record before removal
    auto &processRecord = PrivilegeCacheManager::GetInstance().processPrivilegeMap_[getpid()];
    ASSERT_EQ(1, processRecord->GetPrivilegeNum());

    // Mock GetUptimeMs to fail, which will cause CleanExpiredPrivilegesAndSaveToFile to fail
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillOnce(DoAll(Return(TEST_ERR_CODE)));

    // Remove the only privilege (process becomes empty and is deleted)
    ErrCode ret = PrivilegeCacheManager::GetInstance().RemoveSingle(info);

    // Verify rollback: process and privilege should be restored
    EXPECT_NE(ERR_OK, ret);
    EXPECT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size())
        << "Process should be restored";
    EXPECT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.begin()->second->GetPrivilegeNum())
        << "Privilege should be restored";

    // Restore normal mock behavior for other tests
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: RollbackConsistencyTest001
 * @tc.desc: Verify multiple consecutive operations with failures (mocked by GetUptimeMs failure)
 *           maintain data consistency without proper rollback implementation.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, RollbackConsistencyTest001, TestSize.Level1)
{
    // Setup: Add two processes with multiple privileges
    AuthenCallerInfo info1 = {.pid = 1000, .uid = 0, .privilegeIdx = 0};
    int32_t safeStartTime = MOCK_BOOT_TIME_ONE;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info1, safeStartTime));

    info1.privilegeIdx = 1;
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info1, safeStartTime));

    AuthenCallerInfo info2 = {.pid = 1001, .uid = 0, .privilegeIdx = 0};
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info2, safeStartTime));

    ASSERT_EQ(2, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    ASSERT_EQ(3, PrivilegeCacheManager::GetInstance().processPrivilegeMap_[1000]->GetPrivilegeNum() +
                 PrivilegeCacheManager::GetInstance().processPrivilegeMap_[1001]->GetPrivilegeNum());

    size_t totalPrivileges = PrivilegeCacheManager::GetInstance().processPrivilegeMap_[1000]->GetPrivilegeNum() +
                               PrivilegeCacheManager::GetInstance().processPrivilegeMap_[1001]->GetPrivilegeNum();

    // Mock GetUptimeMs to fail twice, which will cause CleanExpiredPrivilegesAndSaveToFile to fail
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(Return(TEST_ERR_CODE)));

    // First rollback attempt
    info1.privilegeIdx = 0;
    ErrCode ret1 = PrivilegeCacheManager::GetInstance().RemoveSingle(info1);
    EXPECT_NE(ERR_OK, ret1);

    // Second rollback attempt (different operation)
    info2.privilegeIdx = 1;
    ErrCode ret2 = PrivilegeCacheManager::GetInstance().AddCache(info2, safeStartTime);
    EXPECT_NE(ERR_OK, ret2);

    // Verify cache is still in a consistent state
    EXPECT_EQ(2, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    size_t currentTotalPrivileges = PrivilegeCacheManager::GetInstance().processPrivilegeMap_[1000]->GetPrivilegeNum() +
                                     PrivilegeCacheManager::GetInstance().processPrivilegeMap_[1001]->GetPrivilegeNum();
    EXPECT_EQ(totalPrivileges, currentTotalPrivileges);

    // Restore normal mock behavior for other tests
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: PrivilegeAuthStatusToStringTest001
 * @tc.desc: Test PrivilegeAuthStatusToString for all enum values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, PrivilegeAuthStatusToStringTest001, TestSize.Level1)
{
    EXPECT_EQ("NOT_REQUIRED", PrivilegeAuthStatusToString(PrivilegeAuthStatus::NOT_REQUIRED));
    EXPECT_EQ("UNCONFIRMED", PrivilegeAuthStatusToString(PrivilegeAuthStatus::UNCONFIRMED));
    EXPECT_EQ("AUTHORIZED", PrivilegeAuthStatusToString(PrivilegeAuthStatus::AUTHORIZED));
    // default branch maps to NOT_REQUIRED
    EXPECT_EQ("NOT_REQUIRED", PrivilegeAuthStatusToString(static_cast<PrivilegeAuthStatus>(INVALID_AUTH_STATUS)));
}

/**
 * @tc.name: StringToPrivilegeAuthStatusTest001
 * @tc.desc: Test StringToPrivilegeAuthStatus for all string values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, StringToPrivilegeAuthStatusTest001, TestSize.Level1)
{
    EXPECT_EQ(PrivilegeAuthStatus::AUTHORIZED, StringToPrivilegeAuthStatus("AUTHORIZED"));
    EXPECT_EQ(PrivilegeAuthStatus::UNCONFIRMED, StringToPrivilegeAuthStatus("UNCONFIRMED"));
    EXPECT_EQ(PrivilegeAuthStatus::NOT_REQUIRED, StringToPrivilegeAuthStatus("NOT_REQUIRED"));
    EXPECT_EQ(PrivilegeAuthStatus::NOT_REQUIRED, StringToPrivilegeAuthStatus("UNKNOWN"));
    EXPECT_EQ(PrivilegeAuthStatus::NOT_REQUIRED, StringToPrivilegeAuthStatus(""));
}

/**
 * @tc.name: NeedCleanOverflowTest001
 * @tc.desc: Test NeedClean returns false for kernel-based records (AUTHORIZED/UNCONFIRMED).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, NeedCleanOverflowTest001, TestSize.Level1)
{
    auto record = std::make_shared<PrivilegeRecord>(0, INT64_MAX, 0);
    record->SetAuthStatus(PrivilegeAuthStatus::AUTHORIZED);
    EXPECT_FALSE(record->NeedClean(0));
    record->SetAuthStatus(PrivilegeAuthStatus::UNCONFIRMED);
    EXPECT_FALSE(record->NeedClean(0));
}

/**
 * @tc.name: NeedCleanNormalTest001
 * @tc.desc: Test NeedClean returns correct result for normal (non-overflow) cases.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, NeedCleanNormalTest001, TestSize.Level1)
{
    auto record = std::make_shared<PrivilegeRecord>(0, TEST_EXPIRED_TIME_MS, 0);
    EXPECT_FALSE(record->NeedClean(TEST_CURRENT_TIME_BEFORE_EXPIRY));
    EXPECT_TRUE(record->NeedClean(TEST_CURRENT_TIME_AFTER_EXPIRY));
}

/**
 * @tc.name: CheckPrivilegePublicApiTest001
 * @tc.desc: Test CheckPrivilege with isPublicApi=true and PUBLIC_API_UNCONFIRMED → DENIED.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, CheckPrivilegePublicApiTest001, TestSize.Level1)
{
    AuthenCallerInfo info = {.pid = 2000, .uid = TEST_UID, .privilegeIdx = 0};
    // Add a public cache (authType = PUBLIC_API_UNCONFIRMED)
    EXPECT_EQ(ERR_OK, PrepareKernelAuthCacheHelper(info));
    int32_t remainTime = -1;
    ErrCode ret = PrivilegeCacheManager::GetInstance().CheckPrivilege(info, remainTime);
    EXPECT_EQ(ERR_AUTHORIZATION_PRIVILEGE_DENIED, ret);
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: CheckPrivilegePublicApiTest002
 * @tc.desc: Test CheckPrivilege with isPublicApi=true and PUBLIC_API → remainTime=INT32_MAX.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, CheckPrivilegePublicApiTest002, TestSize.Level1)
{
    AuthenCallerInfo info = {.pid = 2001, .uid = TEST_UID, .privilegeIdx = 0};
    EXPECT_EQ(ERR_OK, PrepareKernelAuthCacheHelper(info));
    EXPECT_EQ(ERR_OK,
        PrivilegeCacheManager::GetInstance().SetAuthStatusForRecord(info, PrivilegeAuthStatus::AUTHORIZED));
    int32_t remainTime = -1;
    ErrCode ret = PrivilegeCacheManager::GetInstance().CheckPrivilege(info, remainTime);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(INT32_MAX, remainTime);
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: CheckPrivilegePublicApiTest003
 * @tc.desc: Test CheckPrivilege with isPublicApi=true and cache miss → DENIED.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, CheckPrivilegePublicApiTest003, TestSize.Level1)
{
    AuthenCallerInfo info = {.pid = 2999, .uid = TEST_UID, .privilegeIdx = 0};
    int32_t remainTime = -1;
    ErrCode ret = PrivilegeCacheManager::GetInstance().CheckPrivilege(info, remainTime);
    EXPECT_EQ(ERR_AUTHORIZATION_PRIVILEGE_DENIED, ret);
}

/**
 * @tc.name: AddCacheForPublicTest001
 * @tc.desc: Test AddCacheForKernelAuth with a new process.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, AddCacheForPublicTest001, TestSize.Level1)
{
    AuthenCallerInfo info = {.pid = 3000, .uid = TEST_UID, .privilegeIdx = 0};
    EXPECT_EQ(ERR_OK, PrepareKernelAuthCacheHelper(info));
    ASSERT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    auto record = PrivilegeCacheManager::GetInstance().processPrivilegeMap_[3000]->GetPrivilegeRecord(0);
    ASSERT_NE(record, nullptr);
    EXPECT_EQ(PrivilegeAuthStatus::UNCONFIRMED, record->GetAuthStatus());
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: AddCacheForPublicTest002
 * @tc.desc: Test AddCacheForKernelAuth with an existing process (add second privilege).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, AddCacheForPublicTest002, TestSize.Level1)
{
    AuthenCallerInfo info0 = {.pid = 3001, .uid = TEST_UID, .privilegeIdx = 0};
    EXPECT_EQ(ERR_OK, PrepareKernelAuthCacheHelper(info0));
    AuthenCallerInfo info1 = {.pid = 3001, .uid = TEST_UID, .privilegeIdx = 1};
    EXPECT_EQ(ERR_OK, PrepareKernelAuthCacheHelper(info1));
    ASSERT_EQ(1, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.size());
    EXPECT_EQ(2, PrivilegeCacheManager::GetInstance().processPrivilegeMap_[3001]->GetPrivilegeNum());
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: SetAuthStatusForRecordTest001
 * @tc.desc: Test SetAuthStatusForRecord when process not found.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, SetAuthStatusForRecordTest001, TestSize.Level1)
{
    AuthenCallerInfo info = {.pid = 4000, .uid = TEST_UID, .privilegeIdx = 0};
    ErrCode ret = PrivilegeCacheManager::GetInstance().SetAuthStatusForRecord(info, PrivilegeAuthStatus::AUTHORIZED);
    EXPECT_EQ(ERR_AUTHORIZATION_NO_CACHE, ret);
}

/**
 * @tc.name: SetAuthStatusForRecordTest002
 * @tc.desc: Test SetAuthStatusForRecord when privilege record not found.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, SetAuthStatusForRecordTest002, TestSize.Level1)
{
    AuthenCallerInfo info = {.pid = 4001, .uid = TEST_UID, .privilegeIdx = 0};
    EXPECT_EQ(ERR_OK, PrepareKernelAuthCacheHelper(info));
    // Use a different privilegeIdx that doesn't exist
    AuthenCallerInfo wrongInfo = {.pid = 4001, .uid = TEST_UID, .privilegeIdx = NON_EXISTENT_PRIVILEGE_IDX};
    ErrCode ret = PrivilegeCacheManager::GetInstance().SetAuthStatusForRecord(
        wrongInfo, PrivilegeAuthStatus::AUTHORIZED);
    EXPECT_EQ(ERR_AUTHORIZATION_NO_CACHE, ret);
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: SetAuthStatusForRecordTest003
 * @tc.desc: Test SetAuthStatusForRecord success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, SetAuthStatusForRecordTest003, TestSize.Level1)
{
    AuthenCallerInfo info = {.pid = 4002, .uid = TEST_UID, .privilegeIdx = 0};
    EXPECT_EQ(ERR_OK, PrepareKernelAuthCacheHelper(info));
    ErrCode ret = PrivilegeCacheManager::GetInstance().SetAuthStatusForRecord(info, PrivilegeAuthStatus::AUTHORIZED);
    EXPECT_EQ(ERR_OK, ret);
    auto record = PrivilegeCacheManager::GetInstance().processPrivilegeMap_[4002]->GetPrivilegeRecord(0);
    ASSERT_NE(record, nullptr);
    EXPECT_EQ(PrivilegeAuthStatus::AUTHORIZED, record->GetAuthStatus());
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: AddCacheAndNotifyKernelTest001
 * @tc.desc: Test AddCacheAndNotifyKernel success (kernel device absent → fail-open).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, AddCacheAndNotifyKernelTest001, TestSize.Level1)
{
    g_mockKernelState = MockKernelState::IOCTL_SUCCESS_QUERY_AUTH;
    AuthenCallerInfo info = {.pid = 5000, .uid = TEST_UID, .privilegeIdx = 0};
    ErrCode ret = PrivilegeCacheManager::GetInstance().AddCacheAndNotifyKernel(info, "test_kernel_perm");
    EXPECT_EQ(ERR_OK, ret);
    auto it = PrivilegeCacheManager::GetInstance().processPrivilegeMap_.find(5000);
    ASSERT_NE(it, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.end());
    ASSERT_NE(it->second, nullptr);
    auto record = it->second->GetPrivilegeRecord(0);
    ASSERT_NE(record, nullptr);
    EXPECT_EQ(PrivilegeAuthStatus::AUTHORIZED, record->GetAuthStatus());
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: AddCacheAndNotifyKernelTest002
 * @tc.desc: Test AddCacheAndNotifyKernel with GetUptimeMs failure.
 *          ToPersistFile(0) still succeeds, full flow returns ERR_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, AddCacheAndNotifyKernelTest002, TestSize.Level1)
{
    g_mockKernelState = MockKernelState::IOCTL_SUCCESS_QUERY_AUTH;
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(Return(TEST_ERR_CODE)));
    AuthenCallerInfo info = {.pid = 5001, .uid = TEST_UID, .privilegeIdx = 0};
    ErrCode ret = PrivilegeCacheManager::GetInstance().AddCacheAndNotifyKernel(info, "test_kernel_perm");
    EXPECT_EQ(ERR_OK, ret);
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: HasAuthorizationForPublicTest001
 * @tc.desc: Test HasKernelAuthorization when process not found → isAuthorized=false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, HasAuthorizationForPublicTest001, TestSize.Level1)
{
    bool isAuthorized = true;
    ErrCode ret = PrivilegeCacheManager::GetInstance().HasKernelAuthorization(
        6000, 0, "test_kernel_perm", isAuthorized);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_FALSE(isAuthorized);
}

/**
 * @tc.name: HasAuthorizationForPublicTest002
 * @tc.desc: Test HasKernelAuthorization when privilege record not found → isAuthorized=false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, HasAuthorizationForPublicTest002, TestSize.Level1)
{
    AuthenCallerInfo info = {.pid = 6001, .uid = TEST_UID, .privilegeIdx = 0};
    EXPECT_EQ(ERR_OK, PrepareKernelAuthCacheHelper(info));
    bool isAuthorized = true;
    // Use a different privilegeIdx that doesn't exist
    ErrCode ret = PrivilegeCacheManager::GetInstance().HasKernelAuthorization(
        6001, 99, "test_kernel_perm", isAuthorized);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_FALSE(isAuthorized);
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: HasAuthorizationForPublicTest003
 * @tc.desc: Test HasKernelAuthorization when authType is PUBLIC_API → isAuthorized=true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, HasAuthorizationForPublicTest003, TestSize.Level1)
{
    g_mockKernelState = MockKernelState::IOCTL_SUCCESS_QUERY_AUTH;
    AuthenCallerInfo info = {.pid = 6002, .uid = TEST_UID, .privilegeIdx = 0};
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCacheAndNotifyKernel(info, "test_kernel_perm"));
    bool isAuthorized = false;
    ErrCode ret = PrivilegeCacheManager::GetInstance().HasKernelAuthorization(
        6002, 0, "test_kernel_perm", isAuthorized);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(isAuthorized);
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: HasAuthorizationForPublicTest004
 * @tc.desc: Test HasKernelAuthorization when authType is SYSTEM_API → isAuthorized=false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, HasAuthorizationForPublicTest004, TestSize.Level1)
{
    // AddCache adds a record with default authType = SYSTEM_API
    AuthenCallerInfo info = {.pid = 6003, .uid = TEST_UID, .privilegeIdx = 0};
    EXPECT_EQ(ERR_OK, PrivilegeCacheManager::GetInstance().AddCache(info, MOCK_BOOT_TIME_ONE));
    bool isAuthorized = true;
    ErrCode ret = PrivilegeCacheManager::GetInstance().HasKernelAuthorization(
        6003, 0, "test_kernel_perm", isAuthorized);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_FALSE(isAuthorized);
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: HasAuthorizationForPublicTest005
 * @tc.desc: Test HasKernelAuthorization with PUBLIC_API_UNCONFIRMED, kernel query succeeds (device absent →
 *          fail-open authorized). Record should be promoted to PUBLIC_API.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, HasAuthorizationForPublicTest005, TestSize.Level1)
{
    AuthenCallerInfo info = {.pid = 6004, .uid = TEST_UID, .privilegeIdx = 0};
    // AddCacheForKernelAuth sets authType = PUBLIC_API_UNCONFIRMED (kernel not notified)
    EXPECT_EQ(ERR_OK, PrepareKernelAuthCacheHelper(info));
    g_mockKernelState = MockKernelState::IOCTL_SUCCESS_QUERY_AUTH;
    bool isAuthorized = false;
    ErrCode ret = PrivilegeCacheManager::GetInstance().HasKernelAuthorization(
        6004, 0, "test_kernel_perm", isAuthorized);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(isAuthorized);
    auto record = PrivilegeCacheManager::GetInstance().processPrivilegeMap_[6004]->GetPrivilegeRecord(0);
    ASSERT_NE(record, nullptr);
    EXPECT_EQ(PrivilegeAuthStatus::AUTHORIZED, record->GetAuthStatus());
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: HasAuthorizationForPublicTest006
 * @tc.desc: Test HasKernelAuthorization with UNCONFIRMED and GetUptimeMs failure.
 *          Kernel authorized but persist skipped, authType stays UNCONFIRMED, return ERR_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, HasAuthorizationForPublicTest006, TestSize.Level1)
{
    AuthenCallerInfo info = {.pid = 6005, .uid = TEST_UID, .privilegeIdx = 0};
    EXPECT_EQ(ERR_OK, PrepareKernelAuthCacheHelper(info));
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(Return(TEST_ERR_CODE)));
    g_mockKernelState = MockKernelState::IOCTL_SUCCESS_QUERY_AUTH;
    bool isAuthorized = true;
    ErrCode ret = PrivilegeCacheManager::GetInstance().HasKernelAuthorization(
        6005, 0, "test_kernel_perm", isAuthorized);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(isAuthorized);
    auto record = PrivilegeCacheManager::GetInstance().processPrivilegeMap_[6005]->GetPrivilegeRecord(0);
    ASSERT_NE(record, nullptr);
    EXPECT_EQ(PrivilegeAuthStatus::UNCONFIRMED, record->GetAuthStatus());
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: GetPrivilegeRecordTest001
 * @tc.desc: Test GetPrivilegeRecord returns nullptr when not found, and returns record when found.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, GetPrivilegeRecordTest001, TestSize.Level1)
{
    auto processRecord = std::make_shared<ProcessPrivilegeRecord>();
    EXPECT_EQ(nullptr, processRecord->GetPrivilegeRecord(0));
    // Add a privilege record via AddCacheForKernelAuth path
    AuthenCallerInfo info = {.pid = 7000, .uid = TEST_UID, .privilegeIdx = 5};
    EXPECT_EQ(ERR_OK, PrepareKernelAuthCacheHelper(info));
    auto record = PrivilegeCacheManager::GetInstance().processPrivilegeMap_[7000]->GetPrivilegeRecord(5);
    ASSERT_NE(record, nullptr);
    EXPECT_EQ(5u, record->privilegeIdx_);
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: KernelAuthorizationAdapterTest001
 * @tc.desc: Test KernelAuthorizationAdapter SetKernelAuthorization and QueryKernelAuthorization
 *          when kernel device absent (fail-open path).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, KernelAuthorizationAdapterTest001, TestSize.Level1)
{
    g_mockKernelState = MockKernelState::IOCTL_SUCCESS_QUERY_AUTH;
    ErrCode setRet = KernelAuthorizationAdapter::GetInstance().SetKernelAuthorization(MOCK_KERNEL_PID, "test_perm");
    EXPECT_EQ(ERR_OK, setRet);
    bool isAuthorized = false;
    ErrCode queryRet = KernelAuthorizationAdapter::GetInstance().QueryKernelAuthorization(MOCK_KERNEL_PID, "test_perm",
        isAuthorized);
    EXPECT_EQ(ERR_OK, queryRet);
    EXPECT_TRUE(isAuthorized);
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
}

// ---- Mock libc functions via --wrap for kernel_authorization_adapter.cpp ----
extern "C" {
int __real_access(const char *path, int mode);
int __wrap_access(const char *path, int mode)
{
    if (path != nullptr && std::strcmp(path, KernelAuthorizationAdapter::KERNEL_DEVICE_PATH) == 0) {
        return (g_mockKernelState == MockKernelState::DEVICE_ABSENT) ? -1 : 0;
    }
    return __real_access(path, mode);
}

int __real_open(const char *path, int flags, ...);
int __wrap_open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    if (path != nullptr && std::strcmp(path, KernelAuthorizationAdapter::KERNEL_DEVICE_PATH) == 0) {
        if (g_mockKernelState == MockKernelState::DEVICE_ABSENT) {
            errno = ENOENT;
            return -1;
        }
        if (g_mockKernelState == MockKernelState::OPEN_FAILED) {
            errno = EACCES;
            return -1;
        }
        return MOCK_KERNEL_FD; // fake fd, avoid colliding with real fds
    }
    if (flags & O_CREAT) {
        return __real_open(path, flags, mode);
    }
    return __real_open(path, flags);
}

int __real_ioctl(int fd, unsigned long request, ...);
int __wrap_ioctl(int fd, unsigned long request, ...)
{
    if (fd == MOCK_KERNEL_FD) {
        if (g_mockKernelState == MockKernelState::IOCTL_FAIL) {
            errno = EIO;
            return -1;
        }
        if (g_mockKernelState == MockKernelState::IOCTL_SUCCESS_QUERY_UNAUTH) {
            errno = ENOENT;
            return -1;
        }
        return 0; // success
    }
    return __real_ioctl(fd, request);
}

int __real_close(int fd);
int __wrap_close(int fd)
{
    if (fd == MOCK_KERNEL_FD) {
        return 0; // don't close real fds
    }
    return __real_close(fd);
}
}

/**
 * @tc.name: KernelAuthorizationAdapterTest002
 * @tc.desc: Test open device failed → ERR_AUTHORIZATION_KERNEL_OPEN_FAILED.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, KernelAuthorizationAdapterTest002, TestSize.Level1)
{
    g_mockKernelState = MockKernelState::OPEN_FAILED;
    ErrCode ret = KernelAuthorizationAdapter::GetInstance().SetKernelAuthorization(MOCK_KERNEL_PID, "test_perm");
    EXPECT_EQ(EACCES, ret);
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
}
 
/**
 * @tc.name: KernelAuthorizationAdapterTest003
 * @tc.desc: Test ioctl set failed → ERR_AUTHORIZATION_KERNEL_SET_FAILED.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, KernelAuthorizationAdapterTest003, TestSize.Level1)
{
    g_mockKernelState = MockKernelState::IOCTL_FAIL;
    ErrCode ret = KernelAuthorizationAdapter::GetInstance().SetKernelAuthorization(MOCK_KERNEL_PID, "test_perm");
    EXPECT_EQ(EIO, ret);
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
}

/**
 * @tc.name: KernelAuthorizationAdapterTest004
 * @tc.desc: Test SetKernelAuthorization success via mock.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, KernelAuthorizationAdapterTest004, TestSize.Level1)
{
    g_mockKernelState = MockKernelState::IOCTL_SUCCESS_QUERY_AUTH;
    ErrCode ret = KernelAuthorizationAdapter::GetInstance().SetKernelAuthorization(MOCK_KERNEL_PID, "test_perm");
    EXPECT_EQ(ERR_OK, ret);
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
}

/**
 * @tc.name: KernelAuthorizationAdapterTest005
 * @tc.desc: Test QueryKernelAuthorization success (authorized=true) via mock.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, KernelAuthorizationAdapterTest005, TestSize.Level1)
{
    g_mockKernelState = MockKernelState::IOCTL_SUCCESS_QUERY_AUTH;
    bool isAuthorized = false;
    ErrCode ret = KernelAuthorizationAdapter::GetInstance().QueryKernelAuthorization(MOCK_KERNEL_PID, "test_perm",
        isAuthorized);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(isAuthorized);
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
}

/**
 * @tc.name: KernelAuthorizationAdapterTest006
 * @tc.desc: Test QueryKernelAuthorization ioctl fail → ERR_AUTHORIZATION_KERNEL_QUERY_FAILED.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, KernelAuthorizationAdapterTest006, TestSize.Level1)
{
    g_mockKernelState = MockKernelState::IOCTL_FAIL;
    bool isAuthorized = false;
    ErrCode ret = KernelAuthorizationAdapter::GetInstance().QueryKernelAuthorization(MOCK_KERNEL_PID, "test_perm",
        isAuthorized);
    EXPECT_EQ(EIO, ret);
    EXPECT_FALSE(isAuthorized);
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
}

/**
 * @tc.name: KernelAuthorizationAdapterTest007
 * @tc.desc: Test SetKernelAuthorization with too long key → strncpy_s fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, KernelAuthorizationAdapterTest007, TestSize.Level1)
{
    g_mockKernelState = MockKernelState::IOCTL_SUCCESS_QUERY_AUTH;
    std::string longKey(ENCAPS_MAX_KEY_LEN + 10, 'A');
    ErrCode ret = KernelAuthorizationAdapter::GetInstance().SetKernelAuthorization(MOCK_KERNEL_PID, longKey);
    EXPECT_EQ(ERR_AUTHORIZATION_KERNEL_SET_FAILED, ret);
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
}

/**
 * @tc.name: KernelAuthorizationAdapterTest008
 * @tc.desc: Test QueryKernelAuthorization with too long key → strncpy_s fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, KernelAuthorizationAdapterTest008, TestSize.Level1)
{
    g_mockKernelState = MockKernelState::IOCTL_SUCCESS_QUERY_AUTH;
    std::string longKey(ENCAPS_MAX_KEY_LEN + 10, 'A');
    bool isAuthorized = false;
    ErrCode ret = KernelAuthorizationAdapter::GetInstance().QueryKernelAuthorization(
        MOCK_KERNEL_PID, longKey, isAuthorized);
    EXPECT_EQ(ERR_AUTHORIZATION_KERNEL_QUERY_FAILED, ret);
    EXPECT_FALSE(isAuthorized);
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
}

/**
 * @tc.name: CheckPrivilegeGetUptimeFailTest001
 * @tc.desc: Test CheckPrivilege with GetUptimeMs failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, CheckPrivilegeGetUptimeFailTest001, TestSize.Level1)
{
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(Return(TEST_ERR_CODE)));
    AuthenCallerInfo info = {.pid = 8001, .uid = TEST_UID, .privilegeIdx = 0};
    int32_t remainTime = -1;
    ErrCode ret = PrivilegeCacheManager::GetInstance().CheckPrivilege(info, remainTime);
    EXPECT_NE(ERR_OK, ret);
    EXPECT_CALL(MockUtils::GetInstance(), GetUptimeMs(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: AddCacheAndNotifyKernelFailTest001
 * @tc.desc: Test AddCacheAndNotifyKernel with AddCacheForKernelAuth failure
 *          (GetProcessStartTime fails).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, AddCacheAndNotifyKernelFailTest001, TestSize.Level1)
{
    EXPECT_CALL(MockUtils::GetInstance(), GetProcessStartTime(_, _))
        .WillRepeatedly(Return(TEST_ERR_CODE));
    AuthenCallerInfo info = {.pid = 8002, .uid = TEST_UID, .privilegeIdx = 0};
    ErrCode ret = PrivilegeCacheManager::GetInstance().AddCacheAndNotifyKernel(info, "test_kernel_perm");
    EXPECT_NE(ERR_OK, ret);
    EXPECT_CALL(MockUtils::GetInstance(), GetProcessStartTime(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(MOCK_BOOT_TIME_ONE), Return(ERR_OK)));
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: HasAuthorizationForPublicUnauthTest001
 * @tc.desc: Test HasKernelAuthorization with kernel not authorized (ioctl returns 0 but not authorized).
 *          Uses mock to simulate device present but kernel not authorized.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, HasAuthorizationForPublicUnauthTest001, TestSize.Level1)
{
    // AddCacheForKernelAuth sets UNCONFIRMED, then HasKernelAuthorization queries kernel
    // With IOCTL_FAIL, query fails → SYSTEM_SERVICE_EXCEPTION
    AuthenCallerInfo info = {.pid = 8003, .uid = TEST_UID, .privilegeIdx = 0};
    EXPECT_EQ(ERR_OK, PrepareKernelAuthCacheHelper(info));
    g_mockKernelState = MockKernelState::IOCTL_FAIL;
    bool isAuthorized = true;
    ErrCode ret = PrivilegeCacheManager::GetInstance().HasKernelAuthorization(
        8003, 0, "test_kernel_perm", isAuthorized);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_SYSTEM_SERVICE_EXCEPTION, ret);
    EXPECT_FALSE(isAuthorized);
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: HasAuthorizationForPublicKernelAuthTest001
 * @tc.desc: Test HasKernelAuthorization with kernel authorized via mock device.
 *          UNCONFIRMED → query kernel → authorized → promote to PUBLIC_API.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, HasAuthorizationForPublicKernelAuthTest001, TestSize.Level1)
{
    AuthenCallerInfo info = {.pid = 8004, .uid = TEST_UID, .privilegeIdx = 0};
    EXPECT_EQ(ERR_OK, PrepareKernelAuthCacheHelper(info));
    g_mockKernelState = MockKernelState::IOCTL_SUCCESS_QUERY_AUTH;
    bool isAuthorized = false;
    ErrCode ret = PrivilegeCacheManager::GetInstance().HasKernelAuthorization(
        8004, 0, "test_kernel_perm", isAuthorized);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(isAuthorized);
    auto it = PrivilegeCacheManager::GetInstance().processPrivilegeMap_.find(8004);
    ASSERT_NE(it, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.end());
    ASSERT_NE(it->second, nullptr);
    auto record = it->second->GetPrivilegeRecord(0);
    ASSERT_NE(record, nullptr);
    EXPECT_EQ(PrivilegeAuthStatus::AUTHORIZED, record->GetAuthStatus());
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: AddCacheAndNotifyKernelKernelFailTest001
 * @tc.desc: Test AddCacheAndNotifyKernel with SetKernelAuthorization failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, AddCacheAndNotifyKernelKernelFailTest001, TestSize.Level1)
{
    g_mockKernelState = MockKernelState::IOCTL_FAIL;
    AuthenCallerInfo info = {.pid = 8005, .uid = TEST_UID, .privilegeIdx = 0};
    ErrCode ret = PrivilegeCacheManager::GetInstance().AddCacheAndNotifyKernel(info, "test_kernel_perm");
    EXPECT_EQ(ERR_AUTHORIZATION_KERNEL_NOTIFY_FAILED, ret);
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: HasKernelAuthorizationUnauthRemoveTest001
 * @tc.desc: Test HasKernelAuthorization with kernel not authorized (ENOENT).
 *          UNCONFIRMED record should be removed via RemoveSingle.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, HasKernelAuthorizationUnauthRemoveTest001, TestSize.Level1)
{
    AuthenCallerInfo info = {.pid = 8006, .uid = TEST_UID, .privilegeIdx = 0};
    EXPECT_EQ(ERR_OK, PrepareKernelAuthCacheHelper(info));
    auto it = PrivilegeCacheManager::GetInstance().processPrivilegeMap_.find(8006);
    ASSERT_NE(it, PrivilegeCacheManager::GetInstance().processPrivilegeMap_.end());
    ASSERT_NE(it->second->GetPrivilegeRecord(0), nullptr);
    EXPECT_EQ(PrivilegeAuthStatus::UNCONFIRMED, it->second->GetPrivilegeRecord(0)->GetAuthStatus());

    g_mockKernelState = MockKernelState::IOCTL_SUCCESS_QUERY_UNAUTH;
    bool isAuthorized = true;
    ErrCode ret = PrivilegeCacheManager::GetInstance().HasKernelAuthorization(
        8006, 0, "test_kernel_perm", isAuthorized);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_FALSE(isAuthorized);

    auto itAfter = PrivilegeCacheManager::GetInstance().processPrivilegeMap_.find(8006);
    if (itAfter != PrivilegeCacheManager::GetInstance().processPrivilegeMap_.end()) {
        EXPECT_EQ(itAfter->second->GetPrivilegeRecord(0), nullptr)
            << "UNCONFIRMED record should have been removed by RemoveSingle";
    }

    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: AddCacheAndNotifyKernelDeviceAbsentTest001
 * @tc.desc: Test AddCacheAndNotifyKernel with kernel device absent.
 *          Should return ERR_AUTHORIZATION_KERNEL_DEVICE_NOT_FOUND and rollback cache.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, AddCacheAndNotifyKernelDeviceAbsentTest001, TestSize.Level1)
{
    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
    AuthenCallerInfo info = {.pid = 8007, .uid = TEST_UID, .privilegeIdx = 0};
    ErrCode ret = PrivilegeCacheManager::GetInstance().AddCacheAndNotifyKernel(info, "test_kernel_perm");
    EXPECT_EQ(ERR_AUTHORIZATION_KERNEL_DEVICE_NOT_FOUND, ret);
    EXPECT_EQ(PrivilegeCacheManager::GetInstance().processPrivilegeMap_.find(8007),
        PrivilegeCacheManager::GetInstance().processPrivilegeMap_.end());
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

/**
 * @tc.name: HasKernelAuthorizationDeviceAbsentTest001
 * @tc.desc: Test HasKernelAuthorization with kernel device absent and UNCONFIRMED record.
 *          Should return ERR_AUTHORIZATION_KERNEL_DEVICE_NOT_FOUND.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeCacheManagerTest, HasKernelAuthorizationDeviceAbsentTest001, TestSize.Level1)
{
    AuthenCallerInfo info = {.pid = 8008, .uid = TEST_UID, .privilegeIdx = 0};
    EXPECT_EQ(ERR_OK, PrepareKernelAuthCacheHelper(info));

    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
    bool isAuthorized = true;
    ErrCode ret = PrivilegeCacheManager::GetInstance().HasKernelAuthorization(
        8008, 0, "test_kernel_perm", isAuthorized);
    EXPECT_EQ(ERR_AUTHORIZATION_KERNEL_DEVICE_NOT_FOUND, ret);
    EXPECT_FALSE(isAuthorized);

    g_mockKernelState = MockKernelState::DEVICE_ABSENT;
    PrivilegeCacheManager::GetInstance().processPrivilegeMap_.clear();
}

} // namespace AccountSA
} // namespace OHOS
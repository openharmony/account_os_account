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
#include <fcntl.h>
#include <fstream>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "privilege_utils.h"

#define SET_PSL_BASE 0x16
#define ENCAPS_SET_PSL_CMD _IOW('E', SET_PSL_BASE, pid_t)

using namespace testing::ext;
using namespace testing;
namespace OHOS {
namespace AccountSA {
namespace {

};

static int32_t SetAcl(int32_t pid)
{
    int32_t fd = open("/dev/encaps", O_RDWR);
    if (fd < 0) {
        GTEST_LOG_(INFO) << "Open /dev/encaps failed, errno=" << errno;
        return -1;
    }
    int32_t ret = ioctl(fd, ENCAPS_SET_PSL_CMD, &pid);
    if (ret != 0) {
        GTEST_LOG_(INFO) << "ioctl failed, errno=" << errno;
    }
    close(fd);
    return ret;
}

class PrivilegeUtilsTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: OpenSmartPidFdTest001
 * @tc.desc: Normal function of OpenSmartPidFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeUtilsTest, OpenSmartPidFdTest001, TestSize.Level1)
{
    SmartPidFd fdPtr = nullptr;
    ASSERT_EQ(ERR_OK, OpenSmartPidFd(getpid(), fdPtr));
    ASSERT_NE(nullptr, fdPtr);
    fdPtr = nullptr; // close fd
}

/**
 * @tc.name: GetProcessStartTimeTest001
 * @tc.desc: Normal function of GetProcessStartTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeUtilsTest, GetProcessStartTimeTest001, TestSize.Level1)
{
    int32_t pid = static_cast<int32_t>(getpid());
    int64_t startTime = 0;
    ASSERT_EQ(ERR_OK, GetProcessStartTime(pid, startTime));
    ASSERT_NE(0, startTime);
    // Verify the start time by reading /proc/[pid]/stat file
    std::string statFileContent = "";
    std::ifstream file("/proc/" + std::to_string(pid) + "/stat");
    ASSERT_TRUE(file.is_open());
    std::copy(
        std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>(), std::back_inserter(statFileContent));
    auto index = statFileContent.find(std::to_string(startTime));
    ASSERT_NE(std::string::npos, index);
}

/**
 * @tc.name: GetProcessStartTimeTest002
 * @tc.desc: GetProcessStartTime when pid not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeUtilsTest, GetProcessStartTimeTest002, TestSize.Level1)
{
    int64_t startTime = 0;
    // pid 0 is invalid, should return file not exist error
    ASSERT_EQ(ERR_ACCOUNT_COMMON_FILE_NOT_EXIST, GetProcessStartTime(0, startTime));
}

/**
 * @tc.name: GetBootTimeTest001
 * @tc.desc: Normal function of GetUptimeMs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeUtilsTest, GetBootTimeTest001, TestSize.Level1)
{
    int64_t bootTime = 0;
    ASSERT_EQ(ERR_OK, GetUptimeMs(bootTime));
    ASSERT_NE(0, bootTime);
}

/**
 * @tc.name: AddTimePeriodTest001
 * @tc.desc: Normal function of AddTimePeriod
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeUtilsTest, AddTimePeriodTest001, TestSize.Level1)
{
    int64_t bootTime = 1000;
    uint32_t period = 1;
    int64_t result = AddTimePeriod(bootTime, period);
    int64_t expected = 2000;
    ASSERT_EQ(expected, result);
}

/**
 * @tc.name: DecTimePeriodTest001
 * @tc.desc: Normal function of AddTimePeriod
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeUtilsTest, DecTimePeriodTest001, TestSize.Level1)
{
    int64_t bootTime = 1000;
    uint32_t period = 1;
    int64_t result = DecTimePeriod(bootTime, period);
    int64_t expected = 0;
    ASSERT_EQ(expected, result);
}

/**
 * @tc.name: GetAclTest001
 * @tc.desc: Normal function of GetAcl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegeUtilsTest, GetAclTest001, TestSize.Level1)
{
    int32_t pid = static_cast<int32_t>(getpid());
    int32_t curLevcl = -1;
    ASSERT_EQ(ERR_OK, GetAcl(pid, curLevcl));
    ASSERT_EQ(0, curLevcl); // Default acl level is 0
    // Set acl level to 1
    ASSERT_EQ(ERR_OK, SetAcl(pid));
    int32_t aclLevel = -1;
    ASSERT_EQ(ERR_OK, GetAcl(pid, aclLevel));
    ASSERT_EQ(1, aclLevel);
}
} // namespace AccountSA
} // namespace OHOS
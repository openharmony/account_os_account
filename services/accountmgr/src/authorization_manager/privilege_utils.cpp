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
#include "privilege_utils.h"
#include <charconv>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include "account_error_no.h"
#include "account_file_operator.h"
#include "account_log_wrapper.h"
#include "time_service_client.h"

#define ENCAPS_GET_PSL_BASE 0x15
#define ENCAPS_GET_PSL_CMD _IOW('E', ENCAPS_GET_PSL_BASE, pid_t)

namespace OHOS {
namespace AccountSA {
namespace {
const int32_t MILLI_SECONDS_PER_SECOND = 1000;
const int32_t START_TIME_INDEX = 19;
};

ErrCode OpenSmartPidFd(const int32_t pid, SmartPidFd &fdPtr)
{
    int32_t tmpFd = syscall(SYS_pidfd_open, pid, 0);
    if (tmpFd < 0) {
        int32_t err = errno;
        ACCOUNT_LOGE("OpenPidFd failed, err=%{public}d", err);
        return err;
    }
    fdsan_exchange_owner_tag(tmpFd, 0, LOG_DOMAIN);
    std::function<void(int32_t *)> callbackFunc = [](int32_t *fd) {
        if (fd == nullptr) {
            return;
        }
        if (*fd >= 0) {
            fdsan_close_with_tag(*fd, LOG_DOMAIN);
        }
        delete fd;
    };
    fdPtr = SmartPidFd(new int32_t(tmpFd), callbackFunc);
    return ERR_OK;
}

std::vector<std::string> SplitString(const std::string &str, const char &delimiter)
{
    std::istringstream ss(str);
    std::vector<std::string> elems;
    for (std::string item; std::getline(ss, item, delimiter);) {
        if (item.empty()) {
            continue;
        }
        elems.push_back(item);
    }
    return elems;
}

ErrCode GetStatInfo(const std::string &path, std::vector<std::string> &output)
{
    std::string statInfo;
    std::ifstream file(path);
    if (!file.is_open()) {
        ACCOUNT_LOGE("open file failed");
        return ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED;
    }
    std::copy(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>(), std::back_inserter(statInfo));
    size_t pos = statInfo.find(')');
    if (pos != std::string::npos) {
        statInfo = statInfo.substr(++pos);
    }
    output = SplitString(statInfo, ' ');
    return ERR_OK;
}

ErrCode GetProcessStartTime(const int32_t pid, int64_t &startTime)
{
    std::string path = "/proc/" + std::to_string(pid) + "/stat";
    AccountFileOperator fileOperator;
    ErrCode err = fileOperator.CheckFileExistence(path);
    if (err == ERR_ACCOUNT_COMMON_FILE_NOT_EXIST) {
        ACCOUNT_LOGW("Get pocess start time not found, pid=%{public}d", pid);
        return err;
    }
    if (err != ERR_OK) {
        ACCOUNT_LOGE("Check file existence failed, pid=%{public}d, ret=%{public}d", pid, err);
        return err;
    }
    std::vector<std::string> statInfo;
    err = GetStatInfo(path, statInfo);
    if (err != ERR_OK) {
        ACCOUNT_LOGE("Get stat for pid %{public}d failed, ret=%{public}d", pid, err);
        return err;
    }
    if (statInfo.size() <= START_TIME_INDEX) {
        ACCOUNT_LOGE("Get stat info is smaller than expect");
        return ERR_ACCOUNT_COMMON_FILE_READ_FAILED;
    }
    std::string startTimeStr = statInfo[START_TIME_INDEX];
    uint64_t timeStamp = 0;
    auto res = std::from_chars(startTimeStr.data(), startTimeStr.data() + startTimeStr.size(), timeStamp);
    if (res.ec != std::errc()) {
        ACCOUNT_LOGE("Convert %{public}s to number failed, err=%{public}d",
            startTimeStr.c_str(), static_cast<int32_t>(res.ec));
        return static_cast<int32_t>(res.ec);
    }
    startTime = timeStamp;
    return ERR_OK;
}

ErrCode GetUptimeMs(int64_t &bootTimeStampMs)
{
    int64_t time = -1;
    ErrCode ret = MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs(time);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Get boot time failed, ret=%{public}d", ret);
        return ret;
    }
    bootTimeStampMs = time;
    return ERR_OK;
}

int64_t AddTimePeriod(const int64_t bootTimeStampMs, const uint32_t period)
{
    return bootTimeStampMs + period * MILLI_SECONDS_PER_SECOND;
}

int64_t DecTimePeriod(const int64_t bootTimeStampMs, const uint32_t period)
{
    return bootTimeStampMs - period * MILLI_SECONDS_PER_SECOND;
}

ErrCode GetAcl(const int32_t pid, int32_t &aclLevel)
{
    aclLevel = -1;
    int32_t fd = open("/dev/encaps", O_RDWR);
    if (fd < 0) {
        int32_t err = errno;
        ACCOUNT_LOGE("Open encaps failed, err=%{public}d", err);
        return err;
    }
    pid_t tmpPid = static_cast<pid_t>(pid);
    fdsan_exchange_owner_tag(fd, 0, LOG_DOMAIN);
    aclLevel = ioctl(fd, ENCAPS_GET_PSL_CMD, &tmpPid);
    fdsan_close_with_tag(fd, LOG_DOMAIN);
    return ERR_OK;
}
} // namespace AccountSA
} // namespace OHOS
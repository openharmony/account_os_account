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
#include "data_size_report_adapter.h"
#include "account_log_wrapper.h"
#ifdef HAS_HISYSEVENT_PART
#include "hisysevent.h"
#endif // HAS_HISYSEVENT_PART

#include <sstream>
#include <thread>
#include <vector>
#include <sys/statfs.h>
#include <sys/stat.h>
#include "directory_ex.h"

namespace OHOS {
namespace AccountSA {
namespace {
#ifdef HAS_HISYSEVENT_PART
using namespace OHOS::HiviewDFX;
#endif // HAS_HISYSEVENT_PART

static const std::string OS_ACCOUNT_NAME = "os_account";
static const std::string SYS_EL1_OS_ACCOUNT_DIR = "/data/service/el1/public/account";
static const std::string SYS_EL1_OS_ACCOUNT_DATABASE_DIR = "/data/service/el1/public/database/os_account_mgr_service";
static const std::string SYS_EL2_BASE_DIR = "/data/service/el2";
static const std::string OS_ACCOUNT_DIR_NAME = "account";
static const std::string USER_DATA_DIR = "/data";
static constexpr uint64_t INVALID_SIZE = 0;
static const double UNITS = 1024.0;
}

double GetPartitionRemainSize(const std::string& path)
{
    struct statfs stat;
    if (statfs(path.c_str(), &stat) != 0) {
        ACCOUNT_LOGE("Failed to get %{public}s's remaining size.", path.c_str());
        return INVALID_SIZE;
    }

    /* change B to MB */
    return (static_cast<double>(stat.f_bfree) * static_cast<double>(stat.f_bsize)) / (UNITS * UNITS);
}

template<typename T>
std::string VectorToStringArray(const std::vector<T>& arr)
{
    std::ostringstream oss;
    oss << "[";
    if (!arr.empty()) {
        std::copy(arr.begin(), arr.end() - 1, std::ostream_iterator<T>(oss, ","));
        oss << arr.back();
    }
    oss << "]";
    return oss.str();
}

#ifdef HAS_HISYSEVENT_PART
void ReportTask(const std::vector<int32_t> &accountIds)
{
    std::vector<std::string> dirs{SYS_EL1_OS_ACCOUNT_DIR, SYS_EL1_OS_ACCOUNT_DATABASE_DIR};
    for (auto &accountId : accountIds) {
        std::string sysEl2AccountDir = SYS_EL2_BASE_DIR + "/" + std::to_string(accountId)
            + "/" + OS_ACCOUNT_DIR_NAME;
        struct statfs stat;
        if (statfs(sysEl2AccountDir.c_str(), &stat) == 0) {
            dirs.push_back(sysEl2AccountDir);
        }
    }
    std::vector<uint64_t> dirsSize(dirs.size());
    for (size_t i = 0; i < dirs.size(); ++i) {
        dirsSize[i] = GetFolderSize(dirs[i]);
    }

    int ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::FILEMANAGEMENT, "USER_DATA_SIZE",
        HiviewDFX::HiSysEvent::EventType::STATISTIC, "COMPONENT_NAME", OS_ACCOUNT_NAME, "PARTITION_NAME",
        USER_DATA_DIR, "REMAIN_PARTITION_SIZE", GetPartitionRemainSize(USER_DATA_DIR),
        "FILE_OR_FOLDER_PATH", VectorToStringArray(dirs), "FILE_OR_FOLDER_SIZE", VectorToStringArray(dirsSize));
    if (ret != 0) {
        ACCOUNT_LOGE("Hisysevent report data size failed!");
    }
}
#endif

void ReportUserDataSize(const std::vector<int32_t> &accountIds)
{
#ifdef HAS_HISYSEVENT_PART
    std::thread task(ReportTask, accountIds);
    pthread_setname_np(task.native_handle(), "DataSizeReporter");
    task.detach();
#endif
}
} // AccountSA
} // OHOS
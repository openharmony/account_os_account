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

#include "kernel_authorization_adapter.h"
#include "account_log_wrapper.h"
#include "securec.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>
#include <cstring>

namespace OHOS {
namespace AccountSA {

#define HM_ENCAPS_MAGIC 'E'
#define HM_ENCAPS_ASSIGN_ACTIVE_BASE 0x21
#define HM_ENCAPS_QUERY_ACTIVE_BASE 0x22

#define ASSIGN_ENCAPS_ACTIVE_CMD _IOW(HM_ENCAPS_MAGIC, HM_ENCAPS_ASSIGN_ACTIVE_BASE, struct encaps_flag_info)
#define QUERY_ENCAPS_ACTIVE_CMD _IOW(HM_ENCAPS_MAGIC, HM_ENCAPS_QUERY_ACTIVE_BASE, struct encaps_flag_info)

KernelAuthorizationAdapter &KernelAuthorizationAdapter::GetInstance()
{
    static KernelAuthorizationAdapter instance;
    return instance;
}

static ErrCode OpenKernelDevice(int &fd)
{
    fd = open(KernelAuthorizationAdapter::KERNEL_DEVICE_PATH, O_RDWR);
    int32_t err = errno;
    if ((fd < 0) && (err == ENOENT)) {
        ACCOUNT_LOGW("Kernel encaps device not found, kernel authorization not supported");
        return ERR_AUTHORIZATION_KERNEL_DEVICE_NOT_FOUND;
    }
    if (fd < 0) {
        ACCOUNT_LOGE("Open kernel device failed, path=%{public}s, errno=%{public}d",
            KernelAuthorizationAdapter::KERNEL_DEVICE_PATH, err);
        return err;
    }
    fdsan_exchange_owner_tag(fd, 0, LOG_DOMAIN);
    return ERR_OK;
}

ErrCode KernelAuthorizationAdapter::SetKernelAuthorization(
    int32_t pid, const std::string &kernelPermission)
{
    int fd = -1;
    ErrCode ret = OpenKernelDevice(fd);
    if (ret != ERR_OK) {
        return ret;
    }

    struct encaps_flag_info info = {};
    info.pid = pid;
    if (strncpy_s(info.key, ENCAPS_MAX_KEY_LEN + 1, kernelPermission.c_str(), kernelPermission.length()) != 0) {
        ACCOUNT_LOGE("strncpy_s failed, pid=%{public}d, kernelPermission=%{public}s",
            pid, kernelPermission.c_str());
        fdsan_close_with_tag(fd, LOG_DOMAIN);
        return ERR_AUTHORIZATION_KERNEL_SET_FAILED;
    }

    int ioctlRet = ioctl(fd, ASSIGN_ENCAPS_ACTIVE_CMD, &info);
    int savedErrno = errno;
    fdsan_close_with_tag(fd, LOG_DOMAIN);

    if (ioctlRet != 0) {
        ACCOUNT_LOGE("ioctl set failed, pid=%{public}d, kernelPermission=%{public}s, errno=%{public}d",
            pid, kernelPermission.c_str(), savedErrno);
        return savedErrno;
    }

    ACCOUNT_LOGI("Set kernel authorization success, pid=%{public}d, kernelPermission=%{public}s",
        pid, kernelPermission.c_str());
    return ERR_OK;
}

ErrCode KernelAuthorizationAdapter::QueryKernelAuthorization(
    int32_t pid, const std::string &kernelPermission, bool &isAuthorized)
{
    int fd = -1;
    ErrCode ret = OpenKernelDevice(fd);
    if (ret != ERR_OK) {
        return ret;
    }
    isAuthorized = false;
    struct encaps_flag_info info = {};
    info.pid = pid;
    if (strncpy_s(info.key, ENCAPS_MAX_KEY_LEN + 1, kernelPermission.c_str(), kernelPermission.length()) != 0) {
        ACCOUNT_LOGE("strncpy_s failed, pid=%{public}d, kernelPermission=%{public}s",
            pid, kernelPermission.c_str());
        fdsan_close_with_tag(fd, LOG_DOMAIN);
        return ERR_AUTHORIZATION_KERNEL_QUERY_FAILED;
    }

    int ioctlRet = ioctl(fd, QUERY_ENCAPS_ACTIVE_CMD, &info);
    int savedErrno = errno;
    fdsan_close_with_tag(fd, LOG_DOMAIN);

    if (ioctlRet != 0 && savedErrno != ENOENT) {
        ACCOUNT_LOGE("ioctl query failed, pid=%{public}d, kernelPermission=%{public}s, errno=%{public}d",
            pid, kernelPermission.c_str(), savedErrno);
        return savedErrno;
    }
    if (ioctlRet == 0) {
        isAuthorized = true;
    }

    ACCOUNT_LOGI("Query kernel authorization, pid=%{public}d, kernelPermission=%{public}s, isAuthorized=%{public}d",
        pid, kernelPermission.c_str(), isAuthorized);
    return ERR_OK;
}

} // namespace AccountSA
} // namespace OHOS

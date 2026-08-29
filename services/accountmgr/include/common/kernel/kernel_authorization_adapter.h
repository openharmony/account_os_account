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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_KERNEL_AUTHORIZATION_ADAPTER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_KERNEL_AUTHORIZATION_ADAPTER_H

#include <cstdint>
#include <string>
#include <sys/types.h>
#include "account_error_no.h"
#include "nocopyable.h"

namespace OHOS {
namespace AccountSA {
constexpr int32_t ENCAPS_MAX_KEY_LEN = 64;

struct encaps_flag_info {
    pid_t pid;
    char key[ENCAPS_MAX_KEY_LEN + 1];
    uint64_t reserved[2];
};

class KernelAuthorizationAdapter {
public:
    static KernelAuthorizationAdapter &GetInstance();

    ErrCode SetKernelAuthorization(int32_t pid, const std::string &kernelPermission);

    ErrCode QueryKernelAuthorization(int32_t pid, const std::string &kernelPermission, bool &isAuthorized);

private:
    KernelAuthorizationAdapter() = default;
    ~KernelAuthorizationAdapter() = default;
    DISALLOW_COPY_AND_MOVE(KernelAuthorizationAdapter);

public:
    static constexpr const char *KERNEL_DEVICE_PATH = "/dev/encaps";
};

} // namespace AccountSA
} // namespace OHOS

#endif // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_KERNEL_AUTHORIZATION_ADAPTER_H

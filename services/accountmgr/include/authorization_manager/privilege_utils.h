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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_PRIVILEGE_UTILS_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_PRIVILEGE_UTILS_H
#include <cstdint>
#include <functional>
#include <sys/types.h>
#include "errors.h"

namespace OHOS {
namespace AccountSA {
typedef std::unique_ptr<int32_t, std::function<void(int32_t *)>> SmartPidFd;
ErrCode OpenSmartPidFd(const int32_t pid, SmartPidFd &fdPtr);
ErrCode GetProcessStartTime(const int32_t pid, int64_t &startTime);
ErrCode GetUptimeMs(int64_t &bootTimeStampMs);
int64_t AddTimePeriod(const int64_t bootTimeStampMs, const uint32_t period);
int64_t DecTimePeriod(const int64_t bootTimeStampMs, const uint32_t period);
ErrCode GetAcl(const int32_t pid, int32_t &aclLevel);
} // namespace AccountSA
} // namespace OHOS
#endif // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_PRIVILEGE_UTILS_H
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

#ifndef OS_ACCOUNT_TEST_COMMON_INCLUDE_ACCOUNT_TEST_COMMON_H
#define OS_ACCOUNT_TEST_COMMON_INCLUDE_ACCOUNT_TEST_COMMON_H

#include <string>

const std::vector<std::string> ALL_ACCOUNT_PERMISSION_LIST {
    "ohos.permission.MANAGE_LOCAL_ACCOUNTS",
    "ohos.permission.GET_LOCAL_ACCOUNTS",
    "ohos.permission.MANAGE_DISTRIBUTED_ACCOUNTS",
    "ohos.permission.GET_DISTRIBUTED_ACCOUNTS",
    "ohos.permission.DISTRIBUTED_DATASYNC",
    "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS",
    "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION"
};

namespace OHOS {
namespace AccountSA {
    uint64_t GetTokenIdFromProcess(const std::string &process);
    uint64_t GetTokenIdFromBundleName(const std::string &bundleName);
    bool MockTokenId(const std::string &process);
    bool AllocPermission(std::vector<std::string> permissions, uint64_t &tokenID, bool isSystemApp = true);
    bool RecoveryPermission(uint64_t tokenID, uint64_t oldTokenID);
    uint64_t GetAllAccountPermission();
} // namespace AccountSA
} // namespace OHOS

#endif // OS_ACCOUNT_TEST_COMMON_INCLUDE_ACCOUNT_TEST_COMMON_H

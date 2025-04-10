/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_FRAMEWORK_COMMON_UTILS_INCLUDE_ACCOUNT_PERMISSION_MANAGER_H
#define OS_ACCOUNT_FRAMEWORK_COMMON_UTILS_INCLUDE_ACCOUNT_PERMISSION_MANAGER_H

#include <string>
#include "account_error_no.h"

namespace OHOS {
namespace AccountSA {
class AccountPermissionManager {
public:
    static ErrCode VerifyPermission(const std::string &permissionName);
    static ErrCode CheckSystemApp(bool isCallStub = true);
    static bool CheckSaCall();
    static bool CheckShellCall();
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_FRAMEWORK_COMMON_UTILS_INCLUDE_ACCOUNT_PERMISSION_MANAGER_H

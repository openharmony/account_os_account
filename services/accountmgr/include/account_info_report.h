/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_INFO_REPORT_H
#define OS_ACCOUNT_SERVICES_INFO_REPORT_H
#include <cstdint>
#include <string>

namespace OHOS {
namespace AccountSA {
typedef enum {
    EVENT_LOGIN = 0,
    EVENT_LOGOUT = 1,
} ReportEvent;

typedef enum {
    ACCOUNT_OPERATION_TYPE_CREATE = 0,
    ACCOUNT_OPERATION_TYPE_REMOVE = 1,
    ACCOUNT_OPERATION_TYPE_UPDATE_NAME = 2,
    ACCOUNT_OPERATION_TYPE_UPDATE_TYPE = 3,
    ACCOUNT_OPERATION_TYPE_UPDATE_PHOTO = 4,
} AccountOperationType;

struct AccountOperationInfo {
    int32_t pid;
    int32_t uid;
    std::string sourceUserName;
    int32_t sourceUserId;
    std::string targetUserName;
    int32_t targetUserId;
};

class AccountInfoReport {
public:
    static void ReportSecurityInfo(const std::string &user, int32_t id, ReportEvent event, int32_t result);
    static void ReportAccountOperation(
        const AccountOperationInfo &accountOperationInfo, AccountOperationType operationType);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_INFO_REPORT_H

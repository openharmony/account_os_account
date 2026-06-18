/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OS_ACCOUNT_IAM_HISYSEVENT_UTILS_H
#define OS_ACCOUNT_IAM_HISYSEVENT_UTILS_H

#include "account_hisysevent_adapter.h"
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {
// Main operations
const char OPERATION_AUTH_CRED[] = "auth";
const char OPERATION_UPDATE_CRED[] = "updateCredential";
const char OPERATION_ADD_CRED[] = "addCredential";
const char OPERATION_READD_CRED[] = "readdCredential";
const char OPERATION_DELETE_CRED[] = "deleteCredential";
const char OPERATION_REENROLL[] = "reenroll";
const char OPERATION_OPEN_SESSION[] = "openSession";

const char OPERATION_UNLOCK_ENHANCE[] = "unlockEnhancedKeys";
const char OPERATION_COMMIT[] = "commit";

std::string ConstructSubOperationStr(const char* mainOperation, const char* subOperation);
std::string ConstructSubOperationStr(const char* mainOperation, const int32_t authType);
std::string ConstructSubOperationStr(const char* mainOperation, const char* subOperation, const int32_t authType);
} // namespace AccountSA
} // namespace OHOS
#endif // OS_ACCOUNT_IAM_HISYSEVENT_UTILS_H

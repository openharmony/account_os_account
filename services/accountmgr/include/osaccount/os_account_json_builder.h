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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_JSON_BUILDER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_JSON_BUILDER_H

#include <string>
#include <vector>
#include "json_utils.h"
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {

inline const char DEFAULT_ACTIVATED_ACCOUNT_ID[] = "DefaultActivatedAccountID";
inline const char NEXT_LOCAL_ID[] = "NextLocalId";
inline const char IS_SERIAL_NUMBER_FULL[] = "isSerialNumberFull";

CJsonUnique BuildAccountListJson(const std::vector<std::string> &accounts);
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_JSON_BUILDER_H

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

#ifndef OS_ACCOUNT_TOOLS_TEST_MODULETEST_ACM_ACCOUNT_COMMAND_UTIL_H
#define OS_ACCOUNT_TOOLS_TEST_MODULETEST_ACM_ACCOUNT_COMMAND_UTIL_H

#include <string>

namespace OHOS {
namespace AccountSA {
class AccountCommandUtil {
public:
    static std::string CreateOsAccount();
    static std::string DeleteLastOsAccount();
    static std::string DumpLastOsAccount();
    static std::string SwitchToFirstOsAccount();
    static std::string SwitchToLastOsAccount();
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_TOOLS_TEST_MODULETEST_ACM_ACCOUNT_COMMAND_UTIL_H

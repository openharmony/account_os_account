/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef BASE_ACCOUNT_SERVICES_INCLUDE_DUMP_HELPER_H
#define BASE_ACCOUNT_SERVICES_INCLUDE_DUMP_HELPER_H

#include <string>
#include <vector>
#include "ohos_account_manager.h"

namespace OHOS {
namespace AccountSA {
class AccountMgrService;

class AccountDumpHelper {
public:
    explicit AccountDumpHelper(const std::shared_ptr<OhosAccountManager>& accountMgr);
    ~AccountDumpHelper() = default;
    bool Dump(const std::vector<std::string>& args, std::string& result) const;

private:
    void ShowIllegalInformation(std::string& result) const;
    void ShowHelp(std::string& result) const;
    bool ProcessOneParameter(const std::string& arg, std::string& result) const;
    bool ProcessTwoParameter(const std::string& arg1, const std::string& arg2, std::string& result) const;
    std::weak_ptr<OhosAccountManager> accountMgr_;
    void ShowAccountInfo(std::string &result) const;
    bool SimulateInputEvent(const std::string &eventStr, std::string &result) const;
    bool SetLogLevel(const std::string& levelStr, std::string& result) const;
};
} // namespace AccountSA
} // namespace OHOS
#endif // BASE_ACCOUNT_SERVICES_INCLUDE_DUMP_HELPER_H

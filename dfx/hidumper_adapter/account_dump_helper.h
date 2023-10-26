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

#ifndef OS_ACCOUNT_DFX_HIDUMPER_ADAPTER_H
#define OS_ACCOUNT_DFX_HIDUMPER_ADAPTER_H

#include <string>
#include <vector>
#include "iinner_os_account_manager.h"
#include "ohos_account_manager.h"
#include "os_account_manager_service.h"

namespace OHOS {
namespace AccountSA {
class AccountDumpHelper {
public:
    explicit AccountDumpHelper(OsAccountManagerService* osAccountMgrService);
    ~AccountDumpHelper() = default;
    void Dump(const std::vector<std::string>& args, std::string& result) const;

private:
    void ShowIllegalInformation(std::string& result) const;
    void ShowHelp(std::string& result) const;
    void ProcessOneParameter(const std::string& arg, std::string& result) const;
    void ProcessTwoParameter(const std::string& arg1, const std::string& arg2, std::string& result) const;
    OsAccountManagerService *osAccountMgrService_;
    void ShowOhosAccountInfo(std::string &result) const;
    void ShowOsAccountInfo(std::string &result) const;
    void SetLogLevel(const std::string& levelStr, std::string& result) const;
    std::string AnonymizeNameStr(const std::string& nameStr) const;
    std::string AnonymizeUidStr(const std::string& uidStr) const;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_DFX_HIDUMPER_ADAPTER_H

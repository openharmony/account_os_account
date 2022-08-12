/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_DFX_HISYSEVENT_ADAPTER_H
#define OS_ACCOUNT_DFX_HISYSEVENT_ADAPTER_H

#include <string>

namespace OHOS {
namespace AccountSA {
void ReportServiceStartFail(int32_t errCode, const std::string& errMsg);
void ReportPermissionFail(int32_t callerUid, int32_t callerPid, const std::string& permName);
void ReportOsAccountOperationFail(
    int32_t id, const std::string& operationStr, int32_t errCode, const std::string& errMsg);
void ReportOhosAccountOperationFail(
    int32_t userId, const std::string& operationStr, int32_t errCode, const std::string& errMsg);
void ReportAppAccountOperationFail(const std::string &name, const std::string &owner, const std::string& operationStr,
    int32_t errCode, const std::string& errMsg);
void ReportOsAccountLifeCycle(int32_t id, const std::string& operationStr);
void ReportOsAccountSwitch(int32_t currentId, int32_t oldId);
void ReportOhosAccountStateChange(int32_t userId, int32_t operateType, int32_t oldStat, int32_t newStat);
} // AccountSA
} // OHOS
#endif // OS_ACCOUNT_DFX_HISYSEVENT_ADAPTER_H

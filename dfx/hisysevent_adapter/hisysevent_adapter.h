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
void ReportOhosAccountCESFail(int32_t oldStat, int32_t newStat, int32_t id);
void ReportOhosAccountStateChange(int32_t id, int32_t operateType, int32_t oldStat, int32_t newStat);
void ReportKvStoreAccessFail(int32_t status, const std::string& errMsg);
void ReportAccountOperationFail(int32_t id, int32_t errCode, const std::string& operationStr,
    const std::string& errMsg);
void ReportFileOperationFail(int32_t errCode, const std::string& operationStr, const std::string& path);
void ReportOsAccountLifeCycleEvent(int32_t id, const std::string& operationStr);
void ReportOsAccountSwitchEvent(int32_t currentId, int32_t oldId);
} // AccountSA
} // OHOS
#endif // OS_ACCOUNT_DFX_HISYSEVENT_ADAPTER_H

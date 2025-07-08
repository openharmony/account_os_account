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

#ifndef OS_ACCOUNT_DFX_HISYSEVENT_ADAPTER_H
#define OS_ACCOUNT_DFX_HISYSEVENT_ADAPTER_H

#include <string>
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
extern std::string g_resultCodeStr;
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
void ReportOsAccountDataTampered(int32_t id, const std::string& dataPath, const std::string& dataLabel);

#define ASSEMBLE_ERRMSG(str) \
    ("[" + std::string(__FUNCTION__) + "@" + std::string(LOG_FILE_NAME) + ":" + std::to_string(__LINE__) + "] " + (str))
#define REPORT_OS_ACCOUNT_FAIL(id, operationStr, errCode, errMsg) \
    ReportOsAccountOperationFail(id, operationStr, errCode, ASSEMBLE_ERRMSG(errMsg))
#define REPORT_OHOS_ACCOUNT_FAIL(userId, operationStr, errCode, errMsg) \
    ReportOhosAccountOperationFail(userId, operationStr, errCode, ASSEMBLE_ERRMSG(errMsg))
#define REPORT_APP_ACCOUNT_FAIL(name, owner, operationStr, errCode, errMsg) \
    ReportAppAccountOperationFail(name, owner, operationStr, errCode, ASSEMBLE_ERRMSG(errMsg))
#define REPORT_PERMISSION_FAIL() \
    ReportPermissionFail(IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingRealPid(), __FUNCTION__)
} // AccountSA
} // OHOS
#endif // OS_ACCOUNT_DFX_HISYSEVENT_ADAPTER_H

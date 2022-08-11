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
#include "hisysevent_adapter.h"
#include "account_log_wrapper.h"
#ifdef HAS_HISYSEVENT_PART
#include "hisysevent.h"
#endif // HAS_HISYSEVENT_PART

namespace OHOS {
namespace AccountSA {
namespace {
#ifdef HAS_HISYSEVENT_PART
using HiSysEventNameSpace = OHOS::HiviewDFX::HiSysEvent;
const std::string DOMAIN_STR = std::string(HiSysEventNameSpace::Domain::ACCOUNT);
#endif // HAS_HISYSEVENT_PART
}

void ReportServiceStartFail(int32_t errCode, const std::string& errMsg)
{
#ifdef HAS_HISYSEVENT_PART
    int ret = HiSysEventNameSpace::Write(DOMAIN_STR, "SERVICE_START_FAILED",
        HiSysEventNameSpace::EventType::FAULT,
        "ERROR_TYPE", errCode,
        "ERROR_MSG", errMsg);
    if (ret != 0) {
        ACCOUNT_LOGE("hisysevent write failed! ret %{public}d. errCode %{public}d", ret, errCode);
    }
#else // HAS_HISYSEVENT_PART
    (void)errCode;
#endif // HAS_HISYSEVENT_PART
}

void ReportPermissionFail(int32_t callerUid, int32_t callerPid, const std::string& permName)
{
#ifdef HAS_HISYSEVENT_PART
    int ret = HiSysEventNameSpace::Write(DOMAIN_STR, "PERMISSION_EXCEPTION",
        HiSysEventNameSpace::EventType::SECURITY,
        "CALLER_UID", callerUid,
        "CALLER_PID", callerPid,
        "PERMISSION_NAME", permName);
    if (ret != 0) {
        ACCOUNT_LOGE("hisysevent write failed! ret %{public}d. uid %{public}d, pid %{public}d permName %{public}s.",
            ret, callerUid, callerPid, permName.c_str());
    }
#else // HAS_HISYSEVENT_PART
    (void)callerUid;
    (void)callerPid;
    (void)permName;
#endif // HAS_HISYSEVENT_PART
}

void ReportOsAccountOperationFail(
    int32_t id, const std::string& operationStr, int32_t errCode, const std::string& errMsg)
{
#ifdef HAS_HISYSEVENT_PART
    int ret = HiSysEventNameSpace::Write(DOMAIN_STR, "OS_ACCOUNT_FAILED",
        HiSysEventNameSpace::EventType::FAULT,
        "ID", id,
        "OPERATE_TYPE", operationStr,
        "ERROR_TYPE", errCode,
        "ERROR_MSG", errMsg);
    if (ret != 0) {
        ACCOUNT_LOGE("ret %{public}d, id %{public}d, opStr %{public}s, errCode %{public}d errMsg %{public}s.",
            ret, id, operationStr.c_str(), errCode, errMsg.c_str());
    }
#else // HAS_HISYSEVENT_PART
    (void)id;
    (void)errCode;
    (void)operationStr;
    (void)errMsg;
#endif // HAS_HISYSEVENT_PART
}

void ReportOhosAccountOperationFail(
    int32_t userId, const std::string& operationStr, int32_t errCode, const std::string& errMsg)
{
#ifdef HAS_HISYSEVENT_PART
    int ret = HiSysEventNameSpace::Write(DOMAIN_STR, "DISTRIBUTED_ACCOUNT_FAILED",
        HiSysEventNameSpace::EventType::FAULT,
        "USER_ID", userId,
        "OPERATE_TYPE", operationStr,
        "ERROR_TYPE", errCode,
        "ERROR_MSG", errMsg);
    if (ret != 0) {
        ACCOUNT_LOGE("ret %{public}d, userId %{public}d, opStr %{public}s, errCode %{public}d errMsg %{public}s.",
            ret, userId, operationStr.c_str(), errCode, errMsg.c_str());
    }
#else // HAS_HISYSEVENT_PART
    (void)userId;
    (void)operationStr;
    (void)errCode;
    (void)errMsg;
#endif // HAS_HISYSEVENT_PART
}

void ReportAppAccountOperationFail(const std::string &name, const std::string &owner, const std::string& operationStr,
    int32_t errCode, const std::string& errMsg)
{
#ifdef HAS_HISYSEVENT_PART
    int ret = HiSysEventNameSpace::Write(DOMAIN_STR, "APP_ACCOUNT_FAILED",
        HiSysEventNameSpace::EventType::FAULT,
        "NAME", name,
        "OWNER", owner,
        "OPERATE_TYPE", operationStr,
        "ERROR_TYPE", errCode,
        "ERROR_MSG", errMsg);
    if (ret != 0) {
        ACCOUNT_LOGE(
            "ret %{public}d, name %{public}s, owner %{public}s, opStr %{public}s, "
            "errCode %{public}d, errMsg %{public}s.",
            ret, name.c_str(), owner.c_str(), operationStr.c_str(), errCode, errMsg.c_str());
    }
#else // HAS_HISYSEVENT_PART
    (void)name;
    (void)owner;
    (void)errCode;
    (void)operationStr;
    (void)errMsg;
#endif // HAS_HISYSEVENT_PART
}

void ReportOsAccountLifeCycle(int32_t id, const std::string& operationStr)
{
#ifdef HAS_HISYSEVENT_PART
    int ret = HiSysEventNameSpace::Write(DOMAIN_STR, "OS_ACCOUNT_LIFE_CYCLE",
        HiSysEventNameSpace::EventType::BEHAVIOR,
        "ACCOUNT_ID", id,
        "OPERATE_TYPE", operationStr);
    if (ret != 0) {
        ACCOUNT_LOGE("ret %{public}d, operationStr %{public}s, id %{public}d.",
            ret, operationStr.c_str(), id);
    }
#else // HAS_HISYSEVENT_PART
    (void)id;
    (void)operationStr;
#endif // HAS_HISYSEVENT_PART
}

void ReportOsAccountSwitch(int32_t currentId, int32_t oldId)
{
#ifdef HAS_HISYSEVENT_PART
    int ret = HiSysEventNameSpace::Write(DOMAIN_STR, "OS_ACCOUNT_SWITCH",
        HiSysEventNameSpace::EventType::BEHAVIOR,
        "CURRENT_ID", currentId,
        "OLD_ID", oldId);
    if (ret != 0) {
        ACCOUNT_LOGE("ret %{public}d, currentId %{public}d, oldId %{public}d.",
            ret, currentId, oldId);
    }
#else // HAS_HISYSEVENT_PART
    (void)currentId;
    (void)oldId;
#endif // HAS_HISYSEVENT_PART
}

void ReportOhosAccountStateChange(int32_t userId, int32_t operateType, int32_t oldStat, int32_t newStat)
{
#ifdef HAS_HISYSEVENT_PART
    int ret = HiSysEventNameSpace::Write(DOMAIN_STR, "DISTRIBUTED_ACCOUNT_CHANGE",
        HiSysEventNameSpace::EventType::BEHAVIOR,
        "USER_ID", userId,
        "OPERATION_TYPE", operateType,
        "OLD_STATE", oldStat,
        "NEW_STATE", newStat);
    if (ret != 0) {
        ACCOUNT_LOGE("ret %{public}d, [%{public}d, %{public}d, %{public}d, %{public}d]",
            ret, userId, operateType, oldStat, newStat);
    }
#else // HAS_HISYSEVENT_PART
    (void)userId;
    (void)operateType;
    (void)oldStat;
    (void)newStat;
#endif // HAS_HISYSEVENT_PART
}
} // AccountSA
} // OHOS

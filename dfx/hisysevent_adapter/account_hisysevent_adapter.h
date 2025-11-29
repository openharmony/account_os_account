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
#include "account_log_wrapper.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
namespace Constants {
//DOMAIN_DFX
const char DOMAIN_OPT_REGISTER[] = "registerPlugin";
const char DOMAIN_OPT_UNREGISTER[] = "unregisterPlugin";
const char DOMAIN_OPT_AUTH[] = "auth";
const char DOMAIN_OPT_CANCEL_AUTH[] = "cancelAuth";
const char DOMAIN_OPT_AUTH_POP[] = "authWithPop";
const char DOMAIN_OPT_AUTH_TOKEN[] = "authWithToken";
const char DOMAIN_OPT_UPDATE_INFO[] = "updateInfo";
const char DOMAIN_OPT_GET_INFO[] = "getInfo";
const char DOMAIN_OPT_ADD_CONFIG[] = "addServerConfig";
const char DOMAIN_OPT_REMOVE_CONFIG[] = "removeServerConfig";
const char DOMAIN_OPT_GET_CONFIG[] = "getServerConfig";
const char DOMAIN_OPT_UPDATE_CONFIG[] = "updateServerConfig";
const char DOMAIN_OPT_SUBSCRIBE[] = "subscribe";
const char DOMAIN_OPT_UNSUBSCRIBE[] = "unsubscribe";
const char DOMAIN_OPT_PUBLISH_EVENT[] = "publishEvent";
const char DOMAIN_OPT_GET_POLICY[] = "getPolicy";
const char DOMAIN_OPT_SET_POLICY[] = "setPolicy";
const char DOMAIN_OPT_CREATE[] = "create";
const char DOMAIN_OPT_BIND[] = "bind";
const char DOMAIN_OPT_UNBIND[] = "unbind";
const char DOMAIN_OPT_CLEAN[] = "clean";
const char DOMAIN_OPT_RECOVERY[] = "recoveryBind";
const char DOMAIN_OPT_REBOOT_RECOVERY[] = "rebootRecoveryBind";
const size_t INTERCEPT_HEAD_PART_LEN_FOR_NAME = 1;
const char DEFAULT_ANON_STR[] = "**********";

//APP_DFX
const char APP_DFX_ADD_ACCOUNT[] = "addAccount";
const char APP_DFX_REMOVE_ACCOUNT[] = "removeAccount";
const char APP_DFX_SET_ACCESS[] = "setAccess";
const char APP_DFX_SET_CREDENTIAL[] = "setCredential";
const char APP_DFX_SET_EXTRAINFO[] = "setExtraInfo";
const char APP_DFX_SET_DATA_SYNC[] = "setDataSync";
const char APP_DFX_SET_CUSTOM_DATA[] = "setCustomData";
const char APP_DFX_SET_AUTH_TOKEN[] = "setAuthToken";
const char APP_DFX_GET_AUTHENTICATOR_INFO[] = "getAuthenticatorInfo";
const char APP_DFX_SET_TOKEN_VISIBILITY[] = "setTokenVisibility";
const char APP_DFX_SUBSCRIBE[] = "subscribe";
const char APP_DFX_UNSUBSCRIBE[] = "unsubscribe";
const char APP_DFX_PUBLISH_EVENT[] = "publishEvent";
const char APP_DFX_ADD_ACCOUNT_IMPLICITLY[] = "addAccountImplicitly";
const char APP_DFX_GET_AUTHENTICATOR_CALLBACK[] = "getAuthenticatorCallback";
const char APP_DFX_AUTH[] = "auth";
const char APP_DFX_CHECK_LABELS[] = "checkLabels";
const char APP_DFX_SET_AUTHENTICATOR_PROPERTIES[] = "setAuthenticatorProperties";
const char APP_DFX_VERIFY_CREDENTIAL[] = "verifyCredential";
const char APP_DFX_DB_ERR_LOG[] = "dataStorage";
const char APP_DFX_BMS_ERR_LOG[] = "bmsErrorLog";
const char APP_DFX_ASSET_ERR_LOG[] = "assetErrorLog";
const char APP_DFX_AUTHENTICATOR_SESSION[] = "authenticatorSessionError";
const char APP_DFX_GET_ALL_ACCOUNTS[] = "getAllAccounts";
const char APP_DFX_CONNECT_ABILITY[] = "connectAbility";
}

struct DomainHisysEventInfo {
    int32_t domainBindLocalId = -1;
    std::string operationStr = "";
    int32_t callingUid = -1;
    std::string domainAccountName = "";
    DomainHisysEventInfo() = default;
    DomainHisysEventInfo(int32_t id, std::string optStr)
        : domainBindLocalId(id), operationStr(optStr) {}
    DomainHisysEventInfo(int32_t id, std::string optStr, int32_t uid)
        : domainBindLocalId(id), operationStr(optStr), callingUid(uid) {}

    DomainHisysEventInfo(int32_t id, std::string optStr, std::string accountName)
        : domainBindLocalId(id), operationStr(optStr), domainAccountName(accountName) {}

    DomainHisysEventInfo(int32_t id, std::string optStr, int32_t uid, std::string accountName)
        : domainBindLocalId(id), operationStr(optStr), callingUid(uid), domainAccountName(accountName) {}

    std::string GetCallingInfo()
    {
        if (callingUid == -1) {
            callingUid = IPCSkeleton::GetCallingUid();
        }
        return "uid=" + std::to_string(callingUid);
    }
};

std::string AnonymizeName(const std::string& nameStr);

void ReportServiceStartFail(int32_t errCode, const std::string& errMsg);
void ReportPermissionFail(int32_t callerUid, int32_t callerPid, const std::string& permName);
void ReportOsAccountOperationFail(
    int32_t id, const std::string& operationStr, int32_t errCode, const std::string& errMsg);
void ReportDomainAccountOperationFail(const DomainHisysEventInfo &info, const int32_t errCode,
    const std::string& errMsg);
void ReportDomainAccountOperationStatistic(const DomainHisysEventInfo &info);
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

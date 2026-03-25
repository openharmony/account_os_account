/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "account_info_report.h"
#include "account_log_wrapper.h"
#include "iinner_os_account_manager.h"
#include "json_utils.h"
#ifdef SECURITY_GUARDE_ENABLE
#include "sg_collect_client.h"
#include "time_service_client.h"
#endif

namespace OHOS {
namespace AccountSA {
namespace {
#ifdef SECURITY_GUARDE_ENABLE
static constexpr int NANO_TO_MILLI = 1000000LL;
#endif
}
std::string TransformIntoJson(const std::string &user, int32_t id, ReportEvent event, int32_t result)
{
    auto jsonResult = CreateJson();
#ifdef SECURITY_GUARDE_ENABLE
    AddIntToJson(jsonResult, "type", 0);
    AddIntToJson(jsonResult, "subType", static_cast<int32_t>(event));
    auto userJson = CreateJson();
    AddStringToJson(userJson, "userName", user);
    AddIntToJson(userJson, "userId", id);

    AddObjToJson(jsonResult, "caller", userJson);
    AddStringToJson(jsonResult, "bootTime",
        std::to_string(MiscServices::TimeServiceClient::GetInstance()->GetBootTimeNs()));
    AddStringToJson(jsonResult, "wallTime",
        std::to_string(MiscServices::TimeServiceClient::GetInstance()->GetWallTimeNs()));
    AddStringToJson(jsonResult, "outcome", (result == 0) ? "Success" : "Fail");
    AddStringToJson(jsonResult, "sourceInfo", "");
    AddStringToJson(jsonResult, "targetInfo", "");
    AddStringToJson(jsonResult, "extra", "");
#endif
    return PackJsonToString(jsonResult);
}

void AccountInfoReport::ReportSecurityInfo(const std::string &user, int32_t id, ReportEvent event, int32_t result)
{
#ifdef SECURITY_GUARDE_ENABLE
    using namespace Security::SecurityGuard;
    std::string userName = user;
    if (user.empty()) {
        OsAccountInfo osAccountInfo;
        (void)IInnerOsAccountManager::GetInstance().GetRealOsAccountInfoById(id, osAccountInfo);
        userName = osAccountInfo.GetLocalName();
    }
    int64_t eventId = 1011015001; // 1011015001: report event id
    std::string content = TransformIntoJson(userName, id, event, result);
    std::shared_ptr<EventInfo> eventInfo = std::make_shared<EventInfo>(eventId, "1.0", content);
    NativeDataCollectKit::ReportSecurityInfoAsync(eventInfo);
#endif
}

std::string TransformIntoAccountOperationJson(
    const AccountOperationInfo &accountOperationInfo, AccountOperationType operationType)
{
#ifdef SECURITY_GUARDE_ENABLE
    auto jsonResult = CreateJson();
    AddIntToJson(jsonResult, "operationType", static_cast<int32_t>(operationType));
    auto sourceJson = CreateJson();
    AddIntToJson(sourceJson, "sourcePid", accountOperationInfo.pid);
    AddIntToJson(sourceJson, "sourceUid", accountOperationInfo.uid);
    AddStringToJson(sourceJson, "sourceUserName", accountOperationInfo.sourceUserName);
    AddIntToJson(sourceJson, "sourceUserId", accountOperationInfo.sourceUserId);

    auto targetJson = CreateJson();
    AddStringToJson(targetJson, "targetUserName", accountOperationInfo.targetUserName);
    AddIntToJson(targetJson, "targetUserId", accountOperationInfo.targetUserId);

    AddObjToJson(jsonResult, "source", sourceJson);
    AddObjToJson(jsonResult, "target", targetJson);
    int64_t bootTime = MiscServices::TimeServiceClient::GetInstance()->GetBootTimeNs();
    int64_t wallTimeNS = MiscServices::TimeServiceClient::GetInstance()->GetWallTimeNs();
    int64_t happenTime = wallTimeNS / NANO_TO_MILLI;
    int64_t happenTimeNS = wallTimeNS % NANO_TO_MILLI;
    AddStringToJson(jsonResult, "bootTime", std::to_string(bootTime));
    AddStringToJson(jsonResult, "happenTime", std::to_string(happenTime));
    AddStringToJson(jsonResult, "happenTimeNS", std::to_string(happenTimeNS));
    return PackJsonToString(jsonResult);
#else
    return "";
#endif
}

void AccountInfoReport::ReportAccountOperation(
    const AccountOperationInfo &accountOperationInfo, AccountOperationType operationType)
{
#ifdef SECURITY_GUARDE_ENABLE
    using namespace Security::SecurityGuard;
    int64_t eventId = 0x010000103;
    std::string content = TransformIntoAccountOperationJson(accountOperationInfo, operationType);
    std::shared_ptr<EventInfo> eventInfo = std::make_shared<EventInfo>(eventId, "1.0", content);
    NativeDataCollectKit::ReportSecurityInfoAsync(eventInfo);
#endif
}
} // namespace AccountSA
} // namespace OHOS

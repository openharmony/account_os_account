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
#include "nlohmann/json.hpp"
#ifdef SECURITY_GUARDE_ENABLE
#include "sg_collect_client.h"
#include "time_service_client.h"
#endif

namespace OHOS {
namespace AccountSA {
std::string TransformIntoJson(const std::string &user, int32_t id, ReportEvent event, int32_t result)
{
    nlohmann::json jsonResult;
#ifdef SECURITY_GUARDE_ENABLE
    jsonResult["type"] = 0; // default
    jsonResult["subType"] = static_cast<int32_t>(event);
    nlohmann::json userJson = nlohmann::json {
        {"userName", user},
        {"userId", id},
    };
    jsonResult["caller"] = userJson;
    jsonResult["bootTime"] = std::to_string(MiscServices::TimeServiceClient::GetInstance()->GetBootTimeNs());
    jsonResult["wallTime"] = std::to_string(MiscServices::TimeServiceClient::GetInstance()->GetWallTimeNs());
    jsonResult["outcome"] = (result == 0) ? "Success" : "Fail";
    jsonResult["sourceInfo"] = "";
    jsonResult["targetInfo"] = "";
    jsonResult["extra"] = "";
#endif
    return jsonResult.dump();
}

void AccountInfoReport::ReportSecurityInfo(const std::string &user, int32_t id, ReportEvent event, int32_t result)
{
#ifdef SECURITY_GUARDE_ENABLE
    using namespace Security::SecurityGuard;
    std::string userName = user;
    if (user.empty()) {
        OsAccountInfo osAccountInfo;
        (void)IInnerOsAccountManager::GetInstance().QueryOsAccountById(id, osAccountInfo);
        userName = osAccountInfo.GetLocalName();
    }
    int64_t eventId = 1011015001; // 1011015001: report event id
    std::string content = TransformIntoJson(userName, id, event, result);
    std::shared_ptr<EventInfo> eventInfo = std::make_shared<EventInfo>(eventId, "1.0", content);
    NativeDataCollectKit::ReportSecurityInfo(eventInfo);
#endif
}
} // namespace AccountSA
} // namespace OHOS

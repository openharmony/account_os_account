/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DOMAIN_HISYSEVENT_UTILS_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DOMAIN_HISYSEVENT_UTILS_H

#include <atomic>
#include <variant>
#include "account_hisysevent_adapter.h"
#include "domain_plugin.h"
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
class DomainHisyseventUtils {
public:
    static void ReportFail(const int32_t errCode, const std::string &msg, PluginMethodEnum methodEnum, int32_t userId,
        const DomainAccountInfo &domainInfo = DomainAccountInfo());
    static void ReportFail(const int32_t errCode, const std::string &msg, const std::string &optName, int32_t userId,
        const GetDomainAccountInfoOptions &options);
    static void ReportFail(const int32_t errCode, const std::string &msg, const std::string &optName, int32_t userId,
        const DomainAccountInfo &domainInfo = DomainAccountInfo());
    static void ReportStatistic(PluginMethodEnum methodEnum, int32_t userId,
        const DomainAccountInfo &domainInfo = DomainAccountInfo());
    static void ReportStatistic(const std::string &optName, int32_t userId,
        const DomainAccountInfo &domainInfo = DomainAccountInfo());
    /**
     * @brief Set JS plugin registered status.
     * @param isRegistered True if JS plugin is registered, false otherwise.
     */
    static void SetJsPluginRegistered(bool isRegistered);
    /**
     * @brief Set native plugin registered status.
     * @param isRegistered True if native plugin is registered, false otherwise.
     */
    static void SetNativePluginRegistered(bool isRegistered);
    /**
     * @brief Check if any plugin (JS or native) is registered.
     * @return True if any plugin is registered, false otherwise.
     */
    static bool IsPluginRegistered();
#define REPORT_DOMAIN_ACCOUNT_FAIL(errCode, msg, optName, id, ...) \
    DomainHisyseventUtils::ReportFail(errCode, ASSEMBLE_ERRMSG(msg), optName, id, ##__VA_ARGS__)
private:
    // Atomic flag for JS plugin registration status, used to control HiSysEvent reporting
    static std::atomic<bool> jsPluginRegistered_;
    // Atomic flag for native plugin registration status, used to control HiSysEvent reporting
    static std::atomic<bool> nativePluginRegistered_;
};
} // AccountSA
} // OHOS
#endif // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DOMAIN_HISYSEVENT_UTILS_H
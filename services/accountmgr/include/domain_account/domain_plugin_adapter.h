/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_PLUGIN_ADAPTER_H
#define OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_PLUGIN_ADAPTER_H

#include <map>
#include <mutex>
#include <string>
#include <vector>
#include "account_error_no.h"
#include "domain_account_common.h"
#include "domain_plugin.h"

namespace OHOS {
namespace AccountSA {

constexpr char DLOPEN_ERR[] = "dlopen failed";
constexpr int32_t ADMIN_USERID = 0;

std::string GetMethodNameByEnum(PluginMethodEnum methondEnum);

class DomainPluginAdapter {
public:
    static DomainPluginAdapter& GetInstance();
    static ErrCode ConvertToBindDomainAccountErrCode(int32_t errCode);
    static ErrCode ConvertToCreateOsAccountForDomainErrCode(int32_t errCode);
    bool LoadPlugin(void** libHandle, std::map<PluginMethodEnum, void*>* methodMap,
        const std::string& path, const std::string& libName);
    void ClosePlugin(void** libHandle, std::map<PluginMethodEnum, void*>* methodMap);

    static void SetPluginString(const std::string& str, PluginString& pStr);
    static void CleanPluginString(char** data, size_t length);
    static bool SetPluginUint8Vector(const std::vector<uint8_t>& vector, PluginUint8Vector& pVector);
    static void GetAndCleanPluginUint8Vector(PluginUint8Vector& pVector, std::vector<uint8_t>& vector);
    static int GetAndCleanPluginBusinessError(PluginBusinessError** error, PluginMethodEnum methodEnum, int32_t id,
        const DomainAccountInfo& info = DomainAccountInfo());
    static int GetAndCleanPluginString(PluginString& pStr, std::string& str);
    static void GetAndCleanPluginServerConfigInfo(PluginServerConfigInfo** pConfigInfo,
        std::string& id, std::string& domain, std::string& parameters);
    static void SetPluginDomainAccountInfo(const DomainAccountInfo& info, PluginDomainAccountInfo& pluginInfo);
    static void CleanPluginDomainAccountInfo(PluginDomainAccountInfo& domainAccountInfo);
    static void GetAndCleanPluginDomainAccountInfo(DomainAccountInfo& info,
        PluginDomainAccountInfo** pDomainAccountInfo);
    static void GetAndCleanPluginAuthResultInfo(PluginAuthResultInfo** authResultInfo, DomainAuthResult& result);
    static void GetAndCleanPluginAuthStatusInfo(PluginAuthStatusInfo** statusInfo, AuthStatusInfo& result);
    static void GetAndCleanPluginDomainAccountPolicy(PluginDomainAccountPolicy** accountPolicy, std::string& policy);
    static void SetPluginGetDomainAccessTokenOptions(const GetAccessTokenOptions& option,
        const std::vector<uint8_t>& token,
        const DomainAccountInfo& info,
        PluginGetDomainAccessTokenOptions& pluginOptions);
    static void ParsePluginConfigInfoList(PluginServerConfigInfoList* configInfoList,
        std::vector<DomainServerConfig>& configs);

private:
    DomainPluginAdapter() = default;
    ~DomainPluginAdapter() = default;
    DISALLOW_COPY_AND_MOVE(DomainPluginAdapter);
};

} // namespace AccountSA
} // namespace OHOS

#endif // OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_PLUGIN_ADAPTER_H
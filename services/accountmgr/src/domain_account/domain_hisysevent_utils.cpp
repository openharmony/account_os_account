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

#include "domain_hisysevent_utils.h"

#include "account_log_wrapper.h"
#include "iinner_os_account_manager.h"

namespace OHOS {
namespace AccountSA {
static std::string GetOperationName(PluginMethodEnum methodEnum)
{
    switch (methodEnum) {
        case PluginMethodEnum::ADD_SERVER_CONFIG:
            return Constants::DOMAIN_OPT_ADD_CONFIG;
        case PluginMethodEnum::REMOVE_SERVER_CONFIG:
            return Constants::DOMAIN_OPT_REMOVE_CONFIG;
        case PluginMethodEnum::UPDATE_SERVER_CONFIG:
            return Constants::DOMAIN_OPT_UPDATE_CONFIG;
        case PluginMethodEnum::GET_SERVER_CONFIG:
        case PluginMethodEnum::GET_ALL_SERVER_CONFIGS:
        case PluginMethodEnum::GET_ACCOUNT_SERVER_CONFIG:
            return Constants::DOMAIN_OPT_GET_CONFIG;
        case PluginMethodEnum::AUTH:
            return Constants::DOMAIN_OPT_AUTH;
        case PluginMethodEnum::AUTH_WITH_POPUP:
            return Constants::DOMAIN_OPT_AUTH_POP;
        case PluginMethodEnum::AUTH_WITH_TOKEN:
            return Constants::DOMAIN_OPT_AUTH_TOKEN;
        case PluginMethodEnum::GET_ACCOUNT_INFO:
        case PluginMethodEnum::GET_AUTH_STATUS_INFO:
        case PluginMethodEnum::IS_AUTHENTICATION_EXPIRED:
        case PluginMethodEnum::IS_ACCOUNT_TOKEN_VALID:
        case PluginMethodEnum::GET_ACCESS_TOKEN:
            return Constants::DOMAIN_OPT_GET_INFO;
        case PluginMethodEnum::UPDATE_ACCOUNT_INFO:
            return Constants::DOMAIN_OPT_UPDATE_INFO;
        case PluginMethodEnum::BIND_ACCOUNT:
            return Constants::DOMAIN_OPT_BIND;
        case PluginMethodEnum::UNBIND_ACCOUNT:
            return Constants::DOMAIN_OPT_UNBIND;
        case PluginMethodEnum::SET_ACCOUNT_POLICY:
            return Constants::DOMAIN_OPT_SET_POLICY;
        case PluginMethodEnum::GET_ACCOUNT_POLICY:
            return Constants::DOMAIN_OPT_GET_POLICY;
        default:
            ACCOUNT_LOGE("GetOperationName can not find name");
            return "";
    }
}

void DomainHisyseventUtils::ReportStatistic(PluginMethodEnum methodEnum, const int32_t id,
    const DomainAccountInfo &domainInfo)
{
    std::string optName = GetOperationName(methodEnum);
    if (optName == Constants::DOMAIN_OPT_GET_CONFIG || optName == Constants::DOMAIN_OPT_GET_INFO ||
        optName == Constants::DOMAIN_OPT_GET_POLICY) {
        return;
    }
    int32_t userId = id;
    if (userId == -1) {
        if (domainInfo.accountName_.empty()) {
            DomainHisysEventInfo eventInfo(-1, optName);
            return ReportDomainAccountOperationStatistic(eventInfo);
        }
        ErrCode result = IInnerOsAccountManager::GetInstance().GetOsAccountLocalIdFromDomain(domainInfo, userId);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("Get os account localId from domain failed, result: %{public}d", result);
        }
    }
    DomainHisysEventInfo eventInfo(userId, optName, domainInfo.accountName_);
    return ReportDomainAccountOperationStatistic(eventInfo);
}

void DomainHisyseventUtils::ReportFail(const int32_t errCode, const std::string &msg, const std::string &optName,
    const int32_t id, const DomainAccountInfo &domainInfo)
{
    int32_t userId = id;
    if (userId == -1) {
        if (domainInfo.accountName_.empty()) {
            DomainHisysEventInfo eventInfo(-1, optName);
            return ReportDomainAccountOperationFail(eventInfo, errCode, msg);
        }
        ErrCode result = IInnerOsAccountManager::GetInstance().GetOsAccountLocalIdFromDomain(domainInfo, userId);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("Get os account localId from domain failed, result: %{public}d", result);
        }
    }
    DomainHisysEventInfo eventInfo(userId, optName, domainInfo.accountName_);
    return ReportDomainAccountOperationFail(eventInfo, errCode, msg);
}

void DomainHisyseventUtils::ReportFail(const int32_t errCode, const std::string &msg, PluginMethodEnum methodEnum,
    const int32_t id, const DomainAccountInfo &domainInfo)
{
    ReportFail(errCode, msg, GetOperationName(methodEnum), id, domainInfo);
}
} // AccountSA
} // OHOS
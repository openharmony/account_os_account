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

static void GetLocalIdFromDomain(int32_t& userId, const DomainAccountInfo& domainInfo)
{
    if (userId != -1 || domainInfo.accountName_.empty()) {
        return;
    }
    ErrCode result = IInnerOsAccountManager::GetInstance().GetOsAccountLocalIdFromDomain(domainInfo, userId);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get os account localId from domain failed, result: %{public}d", result);
    }
}

void DomainHisyseventUtils::ReportStatistic(const std::string &optName, int32_t userId,
    const DomainAccountInfo &domainInfo)
{
    if (optName == Constants::DOMAIN_OPT_GET_CONFIG || optName == Constants::DOMAIN_OPT_GET_INFO ||
        optName == Constants::DOMAIN_OPT_GET_POLICY) {
        return;
    }
    if (userId == -1 && domainInfo.accountName_.empty()) {
        DomainHisysEventInfo eventInfo(-1, optName);
            return ReportDomainAccountOperationStatistic(eventInfo);
        }
    GetLocalIdFromDomain(userId, domainInfo);
    DomainHisysEventInfo eventInfo(userId, optName, domainInfo.accountName_);
    ReportDomainAccountOperationStatistic(eventInfo);
}

void DomainHisyseventUtils::ReportStatistic(PluginMethodEnum methodEnum, int32_t userId,
    const DomainAccountInfo &domainInfo)
{
    ReportStatistic(GetOperationName(methodEnum), userId, domainInfo);
}

void DomainHisyseventUtils::ReportFail(const int32_t errCode, const std::string &msg, const std::string &optName,
    int32_t userId, const DomainAccountInfo &domainInfo)
{
    if (userId == -1 && domainInfo.accountName_.empty()) {
        DomainHisysEventInfo eventInfo(-1, optName);
        return ReportDomainAccountOperationFail(eventInfo, errCode, msg);
    }
    GetLocalIdFromDomain(userId, domainInfo);
    DomainHisysEventInfo eventInfo(userId, optName, domainInfo.accountName_);
    ReportDomainAccountOperationFail(eventInfo, errCode, msg);
}

void DomainHisyseventUtils::ReportFail(const int32_t errCode, const std::string &msg, const std::string &optName,
    int32_t userId, const GetDomainAccountInfoOptions &options)
{
    DomainAccountInfo domainInfo = options.accountInfo;
    if (userId == -1 && domainInfo.accountName_.empty()) {
        DomainHisysEventInfo eventInfo(-1, optName, options.callingUid);
        return ReportDomainAccountOperationFail(eventInfo, errCode, msg);
    }
    GetLocalIdFromDomain(userId, domainInfo);
    DomainHisysEventInfo eventInfo(userId, optName, options.callingUid, domainInfo.accountName_);
    ReportDomainAccountOperationFail(eventInfo, errCode, msg);
}

void DomainHisyseventUtils::ReportFail(const int32_t errCode, const std::string &msg, PluginMethodEnum methodEnum,
    int32_t userId, const DomainAccountInfo &domainInfo)
{
    ReportFail(errCode, msg, GetOperationName(methodEnum), userId, domainInfo);
}
} // AccountSA
} // OHOS
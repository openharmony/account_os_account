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

#include "domain_plugin_adapter.h"

#include "account_log_wrapper.h"
#include "domain_account_common.h"
#include "domain_hisysevent_utils.h"
#include "iinner_os_account_manager.h"
#include "os_account_info.h"
#include <dlfcn.h>
#include <securec.h>

namespace OHOS {
namespace AccountSA {

static const std::map<PluginMethodEnum, std::string> METHOD_NAME_MAP = {
    {PluginMethodEnum::ADD_SERVER_CONFIG, "AddServerConfig"},
    {PluginMethodEnum::REMOVE_SERVER_CONFIG, "RemoveServerConfig"},
    {PluginMethodEnum::UPDATE_SERVER_CONFIG, "UpdateServerConfig"},
    {PluginMethodEnum::GET_SERVER_CONFIG, "GetServerConfig"},
    {PluginMethodEnum::GET_ALL_SERVER_CONFIGS, "GetServerConfigList"},
    {PluginMethodEnum::GET_ACCOUNT_SERVER_CONFIG, "GetAccountServerConfig"},
    {PluginMethodEnum::AUTH, "Auth"},
    {PluginMethodEnum::AUTH_WITH_SERVER_CONFIG, "AuthWithServerConfig"},
    {PluginMethodEnum::AUTH_WITH_POPUP, "AuthWithPopup"},
    {PluginMethodEnum::AUTH_WITH_TOKEN, "AuthWithToken"},
    {PluginMethodEnum::GET_ACCOUNT_INFO, "GetAccountInfo"},
    {PluginMethodEnum::GET_AUTH_STATUS_INFO, "GetAuthStatusInfo"},
    {PluginMethodEnum::BIND_ACCOUNT, "BindAccount"},
    {PluginMethodEnum::UNBIND_ACCOUNT, "UnbindAccount"},
    {PluginMethodEnum::IS_ACCOUNT_TOKEN_VALID, "IsAccountTokenValid"},
    {PluginMethodEnum::GET_ACCESS_TOKEN, "GetAccessToken"},
    {PluginMethodEnum::UPDATE_ACCOUNT_INFO, "UpdateAccountInfo"},
    {PluginMethodEnum::IS_AUTHENTICATION_EXPIRED, "IsAuthenticationExpired"},
    {PluginMethodEnum::SET_ACCOUNT_POLICY, "SetAccountPolicy"},
    {PluginMethodEnum::GET_ACCOUNT_POLICY, "GetAccountPolicy"},
    {PluginMethodEnum::CANCEL_AUTH, "CancelAuth"},
};

std::string GetMethodNameByEnum(PluginMethodEnum methodEnum)
{
    const auto& it = METHOD_NAME_MAP.find(methodEnum);
    if (it != METHOD_NAME_MAP.end()) {
        return it->second;
    }
    ACCOUNT_LOGE("enum=%{public}d can not find string", methodEnum);
    return "";
}

DomainPluginAdapter& DomainPluginAdapter::GetInstance()
{
    static DomainPluginAdapter instance;
    return instance;
}

bool DomainPluginAdapter::LoadPlugin(void** libHandle, std::map<PluginMethodEnum, void*>* methodMap,
    const std::string& path, const std::string& libName)
{
    if (libHandle == nullptr || methodMap == nullptr) {
        ACCOUNT_LOGE("libHandle or methodMap is nullptr");
        return false;
    }
    std::string soPath = path + libName;
    *libHandle = dlopen(soPath.c_str(), RTLD_LAZY);
    if (*libHandle == nullptr) {
        const char* dlsym_error = dlerror();
        if (dlsym_error == nullptr) {
            dlsym_error = DLOPEN_ERR;
        }
        ACCOUNT_LOGE("Call dlopen failed error=%{public}s", dlsym_error);
        REPORT_DOMAIN_ACCOUNT_FAIL(
            ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, dlsym_error, Constants::DOMAIN_OPT_REGISTER, ADMIN_USERID);
        return false;
    }
    for (auto i = 0; i < static_cast<int>(PluginMethodEnum::COUNT); ++i) {
        std::string methodName = GetMethodNameByEnum(static_cast<PluginMethodEnum>(i));
        if (methodName.empty()) {
            ACCOUNT_LOGE("Call check methodName empty");
            REPORT_DOMAIN_ACCOUNT_FAIL(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, "Check methodName empty",
                Constants::DOMAIN_OPT_REGISTER, ADMIN_USERID);
            dlclose(*libHandle);
            *libHandle = nullptr;
            methodMap->clear();
            return false;
        }
        dlerror();
        void* func = dlsym(*libHandle, methodName.c_str());
        const char* dlsym_error = dlerror();
        if (dlsym_error != nullptr) {
            ACCOUNT_LOGE("Call check method=%{public}s error=%{public}s", methodName.c_str(), dlsym_error);
            std::string errMsg = "Call check method=" + methodName + " failed, error=" + std::string(dlsym_error);
            REPORT_DOMAIN_ACCOUNT_FAIL(
                ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, errMsg, Constants::DOMAIN_OPT_REGISTER, ADMIN_USERID);
            dlclose(*libHandle);
            *libHandle = nullptr;
            methodMap->clear();
            return false;
        }
        methodMap->emplace(static_cast<PluginMethodEnum>(i), func);
    }
    DomainHisyseventUtils::SetNativePluginRegistered(true);
    return true;
}

void DomainPluginAdapter::ClosePlugin(void** libHandle, std::map<PluginMethodEnum, void*>* methodMap)
{
    if (libHandle == nullptr || *libHandle == nullptr) {
        ACCOUNT_LOGE("LibHandle is nullptr.");
        REPORT_DOMAIN_ACCOUNT_FAIL(-1, "LibHandle is nullptr", Constants::DOMAIN_OPT_UNREGISTER, ADMIN_USERID);
        return;
    }
    if (methodMap == nullptr) {
        ACCOUNT_LOGE("MethodMap is nullptr.");
        return;
    }
    dlclose(*libHandle);
    *libHandle = nullptr;
    methodMap->clear();
    DomainHisyseventUtils::SetNativePluginRegistered(false);
    DomainHisyseventUtils::ReportStatistic(Constants::DOMAIN_OPT_UNREGISTER, ADMIN_USERID);
}

void DomainPluginAdapter::SetPluginString(const std::string& str, PluginString& pStr)
{
    if (str.empty()) {
        ACCOUNT_LOGD("Str is empty.");
        pStr.data = nullptr;
        pStr.length = 0;
        return;
    }
    pStr.data = strdup(str.c_str());
    if (pStr.data == nullptr) {
        ACCOUNT_LOGD("Failed to duplicate string.");
        pStr.length = 0;
        return;
    }
    pStr.length = str.length();
}

void DomainPluginAdapter::CleanPluginString(char** data, size_t length)
{
    if (data == nullptr || *data == nullptr) {
        ACCOUNT_LOGD("Data is nullptr.");
        return;
    }
    (void)memset_s(*data, length, 0, length);
    free(*data);
    *data = nullptr;
}

bool DomainPluginAdapter::SetPluginUint8Vector(const std::vector<uint8_t>& vector, PluginUint8Vector& pVector)
{
    if (vector.empty()) {
        ACCOUNT_LOGD("Vector is empty.");
        pVector.data = nullptr;
        pVector.capacity = 0;
        pVector.size = 0;
        return true;
    }
    pVector.data = const_cast<uint8_t*>(vector.data());
    pVector.capacity = vector.size();
    pVector.size = vector.size();
    return true;
}

void DomainPluginAdapter::GetAndCleanPluginUint8Vector(PluginUint8Vector& pVector, std::vector<uint8_t>& vector)
{
    if (pVector.data == nullptr) {
        ACCOUNT_LOGD("PluginUint8Vector data is null.");
        return;
    }
    vector.assign(pVector.data, pVector.data + pVector.size);
    (void)memset_s(pVector.data, pVector.capacity, 0, pVector.capacity);
    free(pVector.data);
    pVector.data = nullptr;
    pVector.capacity = 0;
    pVector.size = 0;
}

ErrCode DomainPluginAdapter::GetAndCleanPluginBusinessError(PluginBusinessError** error,
    PluginMethodEnum methodEnum,
    int32_t id,
    const DomainAccountInfo& info)
{
    if (error == nullptr || (*error) == nullptr) {
        ACCOUNT_LOGE("Error is nullptr.");
        REPORT_DOMAIN_ACCOUNT_FAIL(ERR_JS_SYSTEM_SERVICE_EXCEPTION, "Error is nullptr", methodEnum, id, info);
        return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
    }
    ErrCode err = (*error)->code;
    std::string methodName = GetMethodNameByEnum(methodEnum);
    std::string msg;
    if ((*error)->msg.data == nullptr) {
        ACCOUNT_LOGW("PluginString's data is null.");
    } else {
        msg = std::string((*error)->msg.data);
        (void)memset_s((*error)->msg.data, (*error)->msg.length, 0, (*error)->msg.length);
        free((*error)->msg.data);
        (*error)->msg.data = nullptr;
    }
    free((*error));
    (*error) = nullptr;
    if (err == ERR_OK) {
        ACCOUNT_LOGI("Call method=%{public}s is ok msg=%{public}s.", methodName.c_str(), msg.c_str());
        DomainHisyseventUtils::ReportStatistic(methodEnum, id, info);
        return err;
    }
    ACCOUNT_LOGE(
        "Call method=%{public}s is error, errorCode=%{public}d msg=%{public}s.", methodName.c_str(), err, msg.c_str());
    std::string errMsg = "Call method=" + methodName + " is error, msg=" + msg;
    REPORT_DOMAIN_ACCOUNT_FAIL(err, errMsg, methodEnum, id, info);
    return err;
}

ErrCode DomainPluginAdapter::GetAndCleanPluginString(PluginString& pStr, std::string& str)
{
    if (pStr.data == nullptr) {
        ACCOUNT_LOGD("PluginString's data is null.");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    str = std::string(pStr.data);
    (void)memset_s(pStr.data, pStr.length, 0, pStr.length);
    free(pStr.data);
    pStr.data = nullptr;
    pStr.length = 0;
    return ERR_OK;
}

void DomainPluginAdapter::GetAndCleanPluginServerConfigInfo(PluginServerConfigInfo** pConfigInfo,
    std::string& id,
    std::string& domain,
    std::string& parameters)
{
    if (pConfigInfo == nullptr || *pConfigInfo == nullptr) {
        ACCOUNT_LOGD("PluginServerConfigInfo is null");
        return;
    }
    GetAndCleanPluginString((*pConfigInfo)->id, id);
    GetAndCleanPluginString((*pConfigInfo)->domain, domain);
    GetAndCleanPluginString((*pConfigInfo)->parameters, parameters);
    free((*pConfigInfo));
    (*pConfigInfo) = nullptr;
}

void DomainPluginAdapter::SetPluginDomainAccountInfo(const DomainAccountInfo& info, PluginDomainAccountInfo& pluginInfo)
{
    SetPluginString(info.domain_, pluginInfo.domain);
    SetPluginString(info.accountName_, pluginInfo.accountName);
    SetPluginString(info.accountId_, pluginInfo.accountId);
    if (!info.serverConfigId_.empty()) {
        SetPluginString(info.serverConfigId_, pluginInfo.serverConfigId);
        return;
    }
    int32_t userId = 0;
    ErrCode errCode = IInnerOsAccountManager::GetInstance().GetOsAccountLocalIdFromDomain(info, userId);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGI("The target domain account not found, errCode = %{public}d", errCode);
        pluginInfo.serverConfigId.data = nullptr;
        return;
    }
    OsAccountInfo osAccountInfo;
    errCode = IInnerOsAccountManager::GetInstance().GetRealOsAccountInfoById(userId, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGI("Failed to get account info, userId = %{public}d, errCode = %{public}d", userId, errCode);
        pluginInfo.serverConfigId.data = nullptr;
        return;
    }
    DomainAccountInfo savedInfo;
    osAccountInfo.GetDomainInfo(savedInfo);
    SetPluginString(savedInfo.serverConfigId_, pluginInfo.serverConfigId);
}

void DomainPluginAdapter::CleanPluginDomainAccountInfo(PluginDomainAccountInfo& domainAccountInfo)
{
    CleanPluginString(&(domainAccountInfo.domain.data), domainAccountInfo.domain.length);
    CleanPluginString(&(domainAccountInfo.serverConfigId.data), domainAccountInfo.serverConfigId.length);
    CleanPluginString(&(domainAccountInfo.accountName.data), domainAccountInfo.accountName.length);
    CleanPluginString(&(domainAccountInfo.accountId.data), domainAccountInfo.accountId.length);
}

void DomainPluginAdapter::GetAndCleanPluginDomainAccountInfo(DomainAccountInfo& info,
    PluginDomainAccountInfo** pDomainAccountInfo)
{
    if (pDomainAccountInfo == nullptr || *pDomainAccountInfo == nullptr) {
        ACCOUNT_LOGD("PluginDomainAccountInfo is null.");
        return;
    }
    GetAndCleanPluginString((*pDomainAccountInfo)->serverConfigId, info.serverConfigId_);
    GetAndCleanPluginString((*pDomainAccountInfo)->domain, info.domain_);
    GetAndCleanPluginString((*pDomainAccountInfo)->accountName, info.accountName_);
    GetAndCleanPluginString((*pDomainAccountInfo)->accountId, info.accountId_);
    GetAndCleanPluginString((*pDomainAccountInfo)->extraAttributes, info.additionInfo_);
    info.isAuthenticated = (*pDomainAccountInfo)->isAuthenticated == 1;
    free((*pDomainAccountInfo));
    (*pDomainAccountInfo) = nullptr;
}

void DomainPluginAdapter::GetAndCleanPluginAuthResultInfo(PluginAuthResultInfo** authResultInfo,
    DomainAuthResult& result)
{
    if (authResultInfo == nullptr || *authResultInfo == nullptr) {
        ACCOUNT_LOGD("PluginAuthResultInfo is null");
        return;
    }
    result.authStatusInfo.freezingTime = (*authResultInfo)->freezingTime;
    result.authStatusInfo.remainingTimes = (*authResultInfo)->remainTimes;
    result.authStatusInfo.nextPhaseFreezingTime = (*authResultInfo)->nextPhaseFreezingTime;
    result.accountId = (*authResultInfo)->localId;
    GetAndCleanPluginUint8Vector((*authResultInfo)->accountToken, result.token);
    free((*authResultInfo));
    (*authResultInfo) = nullptr;
}

void DomainPluginAdapter::GetAndCleanPluginAuthStatusInfo(PluginAuthStatusInfo** statusInfo, AuthStatusInfo& result)
{
    if (statusInfo == nullptr || *statusInfo == nullptr) {
        ACCOUNT_LOGD("PluginAuthStatusInfo is null.");
        return;
    }
    result.freezingTime = (*statusInfo)->freezingTime;
    result.remainingTimes = (*statusInfo)->remainTimes;
    result.nextPhaseFreezingTime = (*statusInfo)->nextPhaseFreezingTime;
    free((*statusInfo));
    (*statusInfo) = nullptr;
}

void DomainPluginAdapter::GetAndCleanPluginDomainAccountPolicy(PluginDomainAccountPolicy** accountPolicy,
    std::string& policy)
{
    if (accountPolicy == nullptr || *accountPolicy == nullptr) {
        ACCOUNT_LOGD("PluginDomainAccountPolicy is null.");
        return;
    }
    GetAndCleanPluginString((*accountPolicy)->parameters, policy);
    free(*accountPolicy);
    *accountPolicy = nullptr;
}

void DomainPluginAdapter::SetPluginGetDomainAccessTokenOptions(const GetAccessTokenOptions& option,
    const std::vector<uint8_t>& token,
    const DomainAccountInfo& info,
    PluginGetDomainAccessTokenOptions& pluginOptions)
{
    PluginDomainAccountInfo domainAccountInfo;
    SetPluginDomainAccountInfo(info, domainAccountInfo);
    PluginUint8Vector domainAccountToken;
    SetPluginUint8Vector(token, domainAccountToken);
    PluginString businessParams;
    SetPluginString(option.getTokenParams_, businessParams);
    pluginOptions.domainAccountInfo = domainAccountInfo;
    pluginOptions.domainAccountToken = domainAccountToken;
    pluginOptions.businessParams = businessParams;
    pluginOptions.callerUid = option.callingUid_;
}

void DomainPluginAdapter::ParsePluginConfigInfoList(PluginServerConfigInfoList* configInfoList,
    std::vector<DomainServerConfig>& configs)
{
    if (configInfoList == nullptr) {
        ACCOUNT_LOGE("PluginServerConfigInfoList is nullptr");
        return;
    }
    if (configInfoList->size == 0) {
        ACCOUNT_LOGE("PluginServerConfigInfoList size is 0");
        delete configInfoList;
        return;
    }
    for (size_t i = 0; i < configInfoList->size; ++i) {
        DomainServerConfig config;
        bool idSuccess = GetAndCleanPluginString(configInfoList->items[i].id, config.id_) == ERR_OK;
        if (!idSuccess) {
            ACCOUNT_LOGE("Failed to get server config id at index %{public}zu", i);
            GetAndCleanPluginString(configInfoList->items[i].domain, config.domain_);
            GetAndCleanPluginString(configInfoList->items[i].parameters, config.parameters_);
            continue;
        }
        bool domainSuccess = GetAndCleanPluginString(configInfoList->items[i].domain, config.domain_) == ERR_OK;
        if (!domainSuccess) {
            ACCOUNT_LOGE("Failed to get server config domain at index %{public}zu", i);
            GetAndCleanPluginString(configInfoList->items[i].parameters, config.parameters_);
            continue;
        }
        bool paramsSuccess = GetAndCleanPluginString(configInfoList->items[i].parameters, config.parameters_) == ERR_OK;
        if (!paramsSuccess) {
            ACCOUNT_LOGE("Failed to get server config parameters at index %{public}zu", i);
            continue;
        }
        configs.push_back(config);
    }
    delete[] configInfoList->items;
    delete configInfoList;
}

} // namespace AccountSA
} // namespace OHOS
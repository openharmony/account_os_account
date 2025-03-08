/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "inner_domain_account_manager.h"
#include <dlfcn.h>
#include <pthread.h>
#include <thread>
#include <securec.h>
#include <cstring>
#include <vector>
#include "account_hisysevent_adapter.h"
#include "account_info_report.h"
#include "account_log_wrapper.h"
#include "bool_wrapper.h"
#ifdef HAS_CES_PART
#include "account_event_provider.h"
#include "common_event_support.h"
#endif // HAS_CES_PART
#include "domain_account_common.h"
#include "domain_account_plugin_death_recipient.h"
#include "domain_account_callback_service.h"
#include "domain_has_domain_info_callback.h"
#include "idomain_account_callback.h"
#include "iinner_os_account_manager.h"
#include "inner_account_iam_manager.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "parameters.h"
#include "status_listener_manager.h"
#include "string_wrapper.h"

namespace OHOS {
namespace AccountSA {
namespace {
constexpr char THREAD_AUTH[] = "auth";
constexpr char THREAD_INNER_AUTH[] = "innerAuth";
constexpr char THREAD_HAS_ACCOUNT[] = "hasAccount";
constexpr char THREAD_GET_ACCOUNT[] = "getAccount";
constexpr char THREAD_BIND_ACCOUNT[] = "bindAccount";
constexpr char THREAD_UNBIND_ACCOUNT[] = "unbindAccount";
constexpr char THREAD_GET_ACCESS_TOKEN[] = "getAccessToken";
constexpr char THREAD_IS_ACCOUNT_VALID[] = "isAccountTokenValid";
constexpr char DLOPEN_ERR[] = "dlopen failed";
constexpr int32_t INVALID_USERID = -1;
constexpr int32_t ADMIN_USERID = 0;
static const char OPERATOR_LOAD_LIB[] = "LoaderLib";
#ifdef _ARM64_
static const char LIB_PATH[] = "/system/lib64/platformsdk/";
#else
static const char LIB_PATH[] = "/system/lib/platformsdk/";
#endif
static const char LIB_NAME[] = "libdomain_account_plugin.z.so";
static const char EDM_FREEZE_BACKGROUND_PARAM[] = "persist.edm.inactive_user_freeze";
}
static const std::map<PluginMethodEnum, std::string> METHOD_NAME_MAP = {
    {PluginMethodEnum::ADD_SERVER_CONFIG, "AddServerConfig"},
    {PluginMethodEnum::REMOVE_SERVER_CONFIG, "RemoveServerConfig"},
    {PluginMethodEnum::UPDATE_SERVER_CONFIG, "UpdateServerConfig"},
    {PluginMethodEnum::GET_SERVER_CONFIG, "GetServerConfig"},
    {PluginMethodEnum::GET_ALL_SERVER_CONFIGS, "GetServerConfigList"},
    {PluginMethodEnum::GET_ACCOUNT_SERVER_CONFIG, "GetAccountServerConfig"},
    {PluginMethodEnum::AUTH, "Auth"},
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
};

static bool IsSupportNetRequest()
{
    bool isBackgroundFreezeEnabled = OHOS::system::GetBoolParameter(EDM_FREEZE_BACKGROUND_PARAM, false);
    if (!isBackgroundFreezeEnabled) {
        return true;
    }
    int32_t accountId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (accountId == 0) { // account 0 not limited by network policy
        return true;
    }
    bool isForeground = false;
    IInnerOsAccountManager::GetInstance().IsOsAccountForeground(accountId, 0, isForeground);
    return isForeground;
}

static int32_t GetCallingUserID()
{
    std::int32_t userId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (userId <= 0) {
        std::vector<int32_t> userIds;
        (void)IInnerOsAccountManager::GetInstance().QueryActiveOsAccountIds(userIds);
        if (userIds.empty()) {
            return INVALID_USERID;  // invalid user id
        }
        userId = userIds[0];
    }
    return userId;
}

InnerDomainAccountManager::InnerDomainAccountManager()
{
    LoaderLib(LIB_PATH, LIB_NAME);
}

InnerDomainAccountManager::~InnerDomainAccountManager()
{
    CloseLib();
}

InnerDomainAccountManager &InnerDomainAccountManager::GetInstance()
{
    static InnerDomainAccountManager *instance = new (std::nothrow) InnerDomainAccountManager();
    return *instance;
}

InnerDomainAuthCallback::InnerDomainAuthCallback(int32_t userId, const sptr<IDomainAccountCallback> &callback)
    : userId_(userId), callback_(callback)
{}

InnerDomainAuthCallback::~InnerDomainAuthCallback()
{}

static void CallbackOnResult(sptr<IDomainAccountCallback> &callback, const int32_t errCode, Parcel &resultParcel)
{
    if (callback == nullptr) {
        ACCOUNT_LOGI("callback_ is nullptr");
        return;
    }
    return callback->OnResult(errCode, resultParcel);
}

void InnerDomainAuthCallback::OnResult(const int32_t errCode, Parcel &parcel)
{
    Parcel resultParcel;
    std::shared_ptr<DomainAuthResult> authResult(DomainAuthResult::Unmarshalling(parcel));
    if (authResult == nullptr) {
        ACCOUNT_LOGE("authResult is nullptr");
        return CallbackOnResult(callback_, ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR, resultParcel);
    }
    if ((errCode == ERR_OK) && (userId_ != 0)) {
        InnerDomainAccountManager::GetInstance().InsertTokenToMap(userId_, (*authResult).token);
        DomainAccountInfo domainInfo;
        InnerDomainAccountManager::GetInstance().GetDomainAccountInfoByUserId(userId_, domainInfo);
        InnerDomainAccountManager::GetInstance().NotifyDomainAccountEvent(
            userId_, DomainAccountEvent::LOG_IN, DomainAccountStatus::LOG_END, domainInfo);
        bool isActivated = false;
        (void)IInnerOsAccountManager::GetInstance().IsOsAccountActived(userId_, isActivated);
        DomainAccountStatus status = isActivated ? DomainAccountStatus::LOGIN : DomainAccountStatus::LOGIN_BACKGROUND;
        IInnerOsAccountManager::GetInstance().UpdateAccountStatusForDomain(userId_, status);
    }
    (void)memset_s(authResult->token.data(), authResult->token.size(), 0, authResult->token.size());
    authResult->token.clear();

    if (!(*authResult).Marshalling(resultParcel)) {
        ACCOUNT_LOGE("authResult Marshalling failed");
        return CallbackOnResult(callback_, ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR, resultParcel);
    }
    AccountInfoReport::ReportSecurityInfo("", userId_, ReportEvent::EVENT_LOGIN, errCode);
    return CallbackOnResult(callback_, errCode, resultParcel);
}

ErrCode InnerDomainAccountManager::RegisterPlugin(const sptr<IDomainAccountPlugin> &plugin)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (plugin == nullptr) {
        ACCOUNT_LOGE("the registered plugin is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (plugin_ != nullptr) {
        ACCOUNT_LOGE("plugin already exists");
        return ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_ALREADY_EXIST;
    }
    auto deathRecipient = GetDeathRecipient();
    if ((plugin->AsObject()->IsProxyObject()) &&
        ((deathRecipient == nullptr) || (!plugin->AsObject()->AddDeathRecipient(deathRecipient)))) {
        ACCOUNT_LOGE("failed to add death recipient for plugin");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }
    plugin_ = plugin;
    callingUid_ = IPCSkeleton::GetCallingUid();
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::UnregisterPlugin()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callingUid_ == -1) {
        ACCOUNT_LOGI("No plugin register.");
        return ERR_OK;
    }
    if (callingUid_ != IPCSkeleton::GetCallingUid()) {
        ACCOUNT_LOGE("Failed to check callingUid, register callingUid=%{public}d, unregister callingUid=%{public}d.",
            callingUid_, IPCSkeleton::GetCallingUid());
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    if ((plugin_ != nullptr) && (plugin_->AsObject() != nullptr)) {
        plugin_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
    plugin_ = nullptr;
    callingUid_ = -1;
    deathRecipient_ = nullptr;
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::StartAuth(const sptr<IDomainAccountPlugin> &plugin, const DomainAccountInfo &info,
    const std::vector<uint8_t> &authData, const sptr<IDomainAccountCallback> &callback, AuthMode authMode)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("invalid callback, cannot return result to client");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    Parcel emptyParcel;
    AccountSA::DomainAuthResult emptyResult;
    if (!emptyResult.Marshalling(emptyParcel)) {
        ACCOUNT_LOGE("authResult Marshalling failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    if (plugin == nullptr) {
        ACCOUNT_LOGE("plugin not exists");
        callback->OnResult(ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST), emptyParcel);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    ErrCode errCode = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    switch (authMode) {
        case AUTH_WITH_CREDENTIAL_MODE:
            errCode = plugin->Auth(info, authData, callback);
            break;
        case AUTH_WITH_POPUP_MODE:
            errCode = plugin->AuthWithPopup(info, callback);
            break;
        case AUTH_WITH_TOKEN_MODE:
            errCode = plugin->AuthWithToken(info, authData, callback);
            break;
        default:
            break;
    }
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to auth domain account, errCode: %{public}d", errCode);
        callback->OnResult(ConvertToJSErrCode(errCode), emptyParcel);
        return errCode;
    }
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::GetDomainAccountInfoByUserId(int32_t userId, DomainAccountInfo &domainInfo)
{
    OsAccountInfo accountInfo;
    ErrCode errCode = IInnerOsAccountManager::GetInstance().GetRealOsAccountInfoById(userId, accountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get os account info failed, errCode: %{public}d", errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    accountInfo.GetDomainInfo(domainInfo);
    if (domainInfo.accountName_.empty()) {
        ACCOUNT_LOGE("the target user is not a domain account");
        return ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT;
    }
    return ERR_OK;
}

std::string GetMethodNameByEnum(PluginMethodEnum methondEnum)
{
    const auto& it = METHOD_NAME_MAP.find(methondEnum);
    if (it != METHOD_NAME_MAP.end()) {
        return it->second;
    }
    ACCOUNT_LOGE("enum=%{public}d can not find string", methondEnum);
    return "";
}

void InnerDomainAccountManager::LoaderLib(const std::string &path, const std::string &libName)
{
    std::lock_guard<std::mutex> lock(libMutex_);
    std::string soPath = path + libName;
    libHandle_ = dlopen(soPath.c_str(), RTLD_LAZY);
    if (libHandle_ == nullptr) {
        const char *dlsym_error = dlerror();
        ACCOUNT_LOGE("Call dlopen failed error=%{public}s", dlsym_error);
        if (dlsym_error == NULL) {
            dlsym_error = DLOPEN_ERR;
        }
        ReportOsAccountOperationFail(
            ADMIN_USERID, OPERATOR_LOAD_LIB, ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, dlsym_error);
        return;
    }
    for (auto i = 0; i < static_cast<int>(PluginMethodEnum::COUNT); ++i) {
        std::string methodName = GetMethodNameByEnum(static_cast<PluginMethodEnum>(i));
        if (methodName.empty()) {
            ACCOUNT_LOGE("Call check methodName emtpty");
            libHandle_ = nullptr;
            methodMap_.clear();
            return;
        }
        dlerror();
        void *func = dlsym(libHandle_,  methodName.c_str());
        const char *dlsym_error = dlerror();
        if (dlsym_error != nullptr) {
            ACCOUNT_LOGE("Call check method=%{public}s error=%{public}s", methodName.c_str(), dlsym_error);
            ReportOsAccountOperationFail(
                ADMIN_USERID, OPERATOR_LOAD_LIB, ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, dlsym_error);
            libHandle_ = nullptr;
            methodMap_.clear();
            return;
        }
        methodMap_.emplace(static_cast<PluginMethodEnum>(i), func);
    }
}

void InnerDomainAccountManager::CloseLib()
{
    std::lock_guard<std::mutex> lock(libMutex_);
    if (libHandle_ == nullptr) {
        ACCOUNT_LOGE("LibHandle_ is nullptr.");
        return;
    }
    dlclose(libHandle_);
    libHandle_ = nullptr;
    methodMap_.clear();
}

static void SetPluginString(const std::string &str, PluginString &pStr)
{
    if (str.empty()) {
        ACCOUNT_LOGE("Str is empty.");
        pStr.data = nullptr;
        pStr.length = 0;
        return;
    }
    pStr.data = strdup(str.c_str());
    if (pStr.data == nullptr) {
        ACCOUNT_LOGE("Failed to duplicate string.");
        pStr.length = 0;
        return;
    }
    pStr.length = str.length();
}

static void CleanPluginString(char** data, size_t length)
{
    if (data == nullptr || *data == nullptr) {
        ACCOUNT_LOGE("Data is nullptr.");
        return;
    }
    (void)memset_s(*data, length, 0, length);
    free(*data);
    *(data) = nullptr;
    return;
}

static bool SetPluginUint8Vector(const std::vector<uint8_t> &vector, PluginUint8Vector &pVector)
{
    if (vector.empty()) {
        ACCOUNT_LOGE("Vector is empty.");
        pVector.data = nullptr;
        pVector.capcity = 0;
        pVector.size = 0;
        return true;
    }
    pVector.data = (uint8_t *)vector.data();
    pVector.capcity = vector.size();
    pVector.size = vector.size();
    return true;
}

static ErrCode GetAndCleanPluginUint8Vector(PluginUint8Vector &pVector, std::vector<uint8_t> &vector)
{
    if (pVector.data == nullptr) {
        ACCOUNT_LOGE("PluginUint8Vector data is null.");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    vector.assign(pVector.data, pVector.data + pVector.size);
    (void)memset_s(pVector.data, pVector.capcity, 0, pVector.capcity);
    free(pVector.data);
    pVector.data = nullptr;
    pVector.capcity = 0;
    pVector.size = 0;
    return ERR_OK;
}

static ErrCode GetAndCleanPluginBussnessError(PluginBussnessError **error, PluginMethodEnum methodEnum)
{
    if (error == nullptr || (*error) == nullptr) {
        ACCOUNT_LOGE("Error is nullptr.");
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
        ACCOUNT_LOGD("Call method=%{public}s is ok msg=%{public}s.", methodName.c_str(), msg.c_str());
        return err;
    }
    ACCOUNT_LOGE("Call method=%{public}s is error, errorCode=%{public}d msg=%{public}s.",
        methodName.c_str(), err, msg.c_str());
    ReportOsAccountOperationFail(GetCallingUserID(), methodName, err, msg);
    return err;
}

static ErrCode GetAndCleanPluginString(PluginString &pStr, std::string &str)
{
    if (pStr.data == nullptr) {
        ACCOUNT_LOGE("PluginString's data is null.");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    str = std::string(pStr.data);
    (void)memset_s(pStr.data, pStr.length, 0, pStr.length);
    free(pStr.data);
    pStr.data = nullptr;
    pStr.length = 0;
    return ERR_OK;
}

static void GetAndCleanPluginServerConfigInfo(PluginServerConfigInfo **pConfigInfo,
    std::string &id, std::string &domain, std::string &parameters)
{
    if (pConfigInfo == nullptr || *pConfigInfo == nullptr) {
        ACCOUNT_LOGE("PluginServerConfigInfo is null");
        return;
    }
    GetAndCleanPluginString((*pConfigInfo)->id, id);
    GetAndCleanPluginString((*pConfigInfo)->domain, domain);
    GetAndCleanPluginString((*pConfigInfo)->parameters, parameters);
    free((*pConfigInfo));
    (*pConfigInfo) = nullptr;
}

static void SetPluginDomainAccountInfo(const DomainAccountInfo &info, PluginDomainAccountInfo &pluginInfo)
{
    SetPluginString(info.domain_, pluginInfo.domain);
    SetPluginString(info.accountName_, pluginInfo.accountName);
    SetPluginString(info.accountId_, pluginInfo.accountId);
    if (!info.serverConfigId_.empty()) {
        SetPluginString(info.serverConfigId_, pluginInfo.serverConfigId);
        return;
    }
    int32_t userId = GetCallingUserID();
    OsAccountInfo accountInfo;
    ErrCode errCode = IInnerOsAccountManager::GetInstance().GetRealOsAccountInfoById(userId, accountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("QueryOsAccountById fail code=%{public}d.", errCode);
        pluginInfo.serverConfigId.data = nullptr;
        return;
    }
    DomainAccountInfo savedInfo;
    accountInfo.GetDomainInfo(savedInfo);
    SetPluginString(savedInfo.serverConfigId_, pluginInfo.serverConfigId);
    return;
}

static void GetAndCleanPluginDomainAccountInfo(DomainAccountInfo &info, PluginDomainAccountInfo **pDomainAccountInfo)
{
    if (pDomainAccountInfo == nullptr || *pDomainAccountInfo == nullptr) {
        ACCOUNT_LOGE("PluginDomainAccountInfo is null.");
        return;
    }
    GetAndCleanPluginString((*pDomainAccountInfo)->serverConfigId, info.serverConfigId_);
    GetAndCleanPluginString((*pDomainAccountInfo)->domain, info.domain_);
    GetAndCleanPluginString((*pDomainAccountInfo)->accountName, info.accountName_);
    GetAndCleanPluginString((*pDomainAccountInfo)->accountId, info.accountId_);
    info.isAuthenticated = (*pDomainAccountInfo)->isAuthenticated == 1;
    free((*pDomainAccountInfo));
    (*pDomainAccountInfo) = nullptr;
}

static void GetAndCleanPluginAuthResultInfo(PluginAuthResultInfo **authResultInfo,
    std::vector<uint8_t> &token, int32_t &remainTimes, int32_t &freezingTime)
{
    if (authResultInfo == nullptr || *authResultInfo == nullptr) {
        ACCOUNT_LOGE("PluginAuthResultInfo is null");
        return;
    }
    freezingTime = (*authResultInfo)->freezingTime;
    remainTimes = (*authResultInfo)->remainTimes;
    GetAndCleanPluginUint8Vector((*authResultInfo)->accountToken, token);
    free((*authResultInfo));
    (*authResultInfo) = nullptr;
}

static void GetAndCleanPluginAuthStatusInfo(PluginAuthStatusInfo **statusInfo,
    int32_t &remainTimes, int32_t &freezingTime)
{
    if (statusInfo == nullptr || *statusInfo == nullptr) {
        ACCOUNT_LOGE("PluginAuthStatusInfo is null.");
        return;
    }
    remainTimes = (*statusInfo)->remainTimes;
    freezingTime = (*statusInfo)->freezingTime;
    free((*statusInfo));
    (*statusInfo) = nullptr;
}

static void GetAndCleanPluginDomainAccountPolicy(PluginDomainAccountPolicy **accountPolicy, std::string &policy)
{
    if (accountPolicy == nullptr || *accountPolicy == nullptr) {
        ACCOUNT_LOGE("PluginDomainAccountPolicy is null.");
        return;
    }
    GetAndCleanPluginString((*accountPolicy)->parameters, policy);
    free(*accountPolicy);
    *accountPolicy = nullptr;
}

static void SetPluginGetDomainAccessTokenOptions(const GetAccessTokenOptions &option,
    const std::vector<uint8_t> &token, const DomainAccountInfo &info, PluginGetDomainAccessTokenOptions &pluginOptions)
{
    PluginDomainAccountInfo domainAccountInfo;
    SetPluginDomainAccountInfo(info, domainAccountInfo);
    PluginUint8Vector domainAccountToken;
    SetPluginUint8Vector(token, domainAccountToken);
    PluginString bussinessParams;
    AAFwk::Want want;
    want.SetParams(option.getTokenParams_);
    std::string params = want.ToString();
    SetPluginString(params, bussinessParams);
    pluginOptions.domainAccountInfo = domainAccountInfo;
    pluginOptions.domainAccountToken = domainAccountToken;
    pluginOptions.bussinessParams = bussinessParams;
    pluginOptions.callerUid = option.callingUid_;
}

ErrCode InnerDomainAccountManager::AddServerConfig(
    const std::string &paremters, DomainServerConfig &config) __attribute__((no_sanitize("cfi")))
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    auto iter = methodMap_.find(PluginMethodEnum::ADD_SERVER_CONFIG);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::ADD_SERVER_CONFIG);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    int32_t localId = GetCallingUserID();
    if (localId == INVALID_USERID) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    PluginString param;
    SetPluginString(paremters, param);
    PluginServerConfigInfo *configInfo = nullptr;
    PluginBussnessError* error = (*reinterpret_cast<AddServerConfigFunc>(iter->second))(&param, localId, &configInfo);
    GetAndCleanPluginServerConfigInfo(&configInfo, config.id_, config.domain_, config.parameters_);
    CleanPluginString(&(param.data), param.length);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::RemoveServerConfig(const std::string &configId) __attribute__((no_sanitize("cfi")))
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    auto iter = methodMap_.find(PluginMethodEnum::REMOVE_SERVER_CONFIG);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::REMOVE_SERVER_CONFIG);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    int32_t localId = GetCallingUserID();
    if (localId == -1) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    PluginString serverConfigId;
    SetPluginString(configId, serverConfigId);
    PluginBussnessError* error = (*reinterpret_cast<RemoveServerConfigFunc>(iter->second))(&serverConfigId, localId);
    CleanPluginString(&(serverConfigId.data), serverConfigId.length);
    ErrCode errCode = GetAndCleanPluginBussnessError(&error, iter->first);
    if (errCode == ERR_JS_INVALID_PARAMETER) {
        return ERR_JS_SERVER_CONFIG_NOT_FOUND;
    }
    return errCode;
}

ErrCode InnerDomainAccountManager::UpdateServerConfig(const std::string &configId,
    const std::string &paremters, DomainServerConfig &config) __attribute__((no_sanitize("cfi")))
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    auto iter = methodMap_.find(PluginMethodEnum::UPDATE_SERVER_CONFIG);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::UPDATE_SERVER_CONFIG);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    int32_t localId = GetCallingUserID();
    if (localId == INVALID_USERID) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    PluginString serverConfigId;
    PluginString param;
    SetPluginString(configId, serverConfigId);
    SetPluginString(paremters, param);
    PluginServerConfigInfo *configInfo = nullptr;
    PluginBussnessError* error = (*reinterpret_cast<UpdateServerConfigFunc>(iter->second))(&serverConfigId, &param,
        localId, &configInfo);
    GetAndCleanPluginServerConfigInfo(&configInfo, config.id_, config.domain_, config.parameters_);
    CleanPluginString(&(param.data), param.length);
    CleanPluginString(&(serverConfigId.data), serverConfigId.length);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::GetServerConfig(const std::string &configId,
    DomainServerConfig &config) __attribute__((no_sanitize("cfi")))
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    auto iter = methodMap_.find(PluginMethodEnum::GET_SERVER_CONFIG);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::GET_SERVER_CONFIG);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    int32_t localId = GetCallingUserID();
    if (localId == INVALID_USERID) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    PluginString serverConfigId;
    SetPluginString(configId, serverConfigId);
    PluginServerConfigInfo *configInfo = nullptr;
    PluginBussnessError* error = (*reinterpret_cast<GetServerConfigFunc>(iter->second))(
            &serverConfigId, localId, &configInfo);
    GetAndCleanPluginServerConfigInfo(&configInfo, config.id_, config.domain_, config.parameters_);
    CleanPluginString(&(serverConfigId.data), serverConfigId.length);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::GetAllServerConfigs(
    std::vector<DomainServerConfig> &configs) __attribute__((no_sanitize("cfi")))
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    auto iter = methodMap_.find(PluginMethodEnum::GET_ALL_SERVER_CONFIGS);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::GET_ALL_SERVER_CONFIGS);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    int32_t localId = GetCallingUserID();
    if (localId == INVALID_USERID) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    PluginServerConfigInfoList *configInfoList = nullptr;
    PluginBussnessError* error = (*reinterpret_cast<GetServerConfigListFunc>(iter->second))(&configInfoList);
    if (configInfoList == nullptr) {
        ACCOUNT_LOGE("configInfoList is nullptr");
        return GetAndCleanPluginBussnessError(&error, iter->first);
    }
    if (configInfoList->size == 0) {
        delete configInfoList;
        return GetAndCleanPluginBussnessError(&error, iter->first);
    }
    for (size_t i = 0; i < configInfoList->size; ++i) {
        DomainServerConfig config;
        if (GetAndCleanPluginString(configInfoList->items[i].id, config.id_) != ERR_OK) {
            ACCOUNT_LOGE("Failed to get server config id at index %{public}zu", i);
            continue;
        }
        if (GetAndCleanPluginString(configInfoList->items[i].domain, config.domain_) != ERR_OK) {
            ACCOUNT_LOGE("Failed to get server config domain at index %{public}zu", i);
            continue;
        }
        configs.push_back(config);
    }
    delete[] configInfoList->items;
    delete configInfoList;
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::GetAccountServerConfig(
    const DomainAccountInfo &info, DomainServerConfig &config) __attribute__((no_sanitize("cfi")))
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    auto iter = methodMap_.find(PluginMethodEnum::GET_ACCOUNT_SERVER_CONFIG);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::GET_ACCOUNT_SERVER_CONFIG);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    int32_t localId = 0;
    ErrCode result = IInnerOsAccountManager::GetInstance().GetOsAccountLocalIdFromDomain(info, localId);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get os account localId from domain failed, result: %{public}d", result);
        return result;
    }
    PluginDomainAccountInfo domainAccountInfo;
    SetPluginDomainAccountInfo(info, domainAccountInfo);
    PluginServerConfigInfo *serverConfigInfo = nullptr;
    PluginBussnessError* error = (*reinterpret_cast<GetAccountServerConfigFunc>(iter->second))(&domainAccountInfo,
        &serverConfigInfo);
    GetAndCleanPluginServerConfigInfo(&serverConfigInfo, config.id_, config.domain_, config.parameters_);
    CleanPluginString(&(domainAccountInfo.domain.data), domainAccountInfo.domain.length);
    CleanPluginString(&(domainAccountInfo.serverConfigId.data), domainAccountInfo.serverConfigId.length);
    CleanPluginString(&(domainAccountInfo.accountName.data), domainAccountInfo.accountName.length);
    CleanPluginString(&(domainAccountInfo.accountId.data), domainAccountInfo.accountId.length);
    ErrCode errCode = GetAndCleanPluginBussnessError(&error, iter->first);
    if (errCode == ERR_JS_INVALID_PARAMETER) {
        return ERR_JS_ACCOUNT_NOT_FOUND;
    }
    return errCode;
}

ErrCode InnerDomainAccountManager::PluginAuth(const DomainAccountInfo &info,
    const std::vector<uint8_t> &password, DomainAuthResult &resultParcel) __attribute__((no_sanitize("cfi")))
{
    auto iter = methodMap_.find(PluginMethodEnum::AUTH);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::AUTH);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    int32_t localId = GetCallingUserID();
    if (localId == -1) {
        ACCOUNT_LOGE("fail to get activated os account ids");
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    PluginDomainAccountInfo domainAccountInfo;
    SetPluginDomainAccountInfo(info, domainAccountInfo);
    PluginUint8Vector credential;
    SetPluginUint8Vector(password, credential);
    PluginAuthResultInfo *authResultInfo = nullptr;
    ACCOUNT_LOGD("Param localId=%{public}d.", localId);
    PluginBussnessError* error = (*reinterpret_cast<AuthFunc>(iter->second))(&domainAccountInfo, &credential, localId,
        &authResultInfo);
    GetAndCleanPluginAuthResultInfo(&authResultInfo, resultParcel.token,
        resultParcel.authStatusInfo.remainingTimes, resultParcel.authStatusInfo.freezingTime);
    CleanPluginString(&(domainAccountInfo.domain.data), domainAccountInfo.domain.length);
    CleanPluginString(&(domainAccountInfo.serverConfigId.data), domainAccountInfo.serverConfigId.length);
    CleanPluginString(&(domainAccountInfo.accountName.data), domainAccountInfo.accountName.length);
    CleanPluginString(&(domainAccountInfo.accountId.data), domainAccountInfo.accountId.length);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const sptr<IDomainAccountCallback> &callback)
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    int32_t userId = -1;
    sptr<IDomainAccountCallback> innerCallback = callback;
    IInnerOsAccountManager::GetInstance().GetOsAccountLocalIdFromDomain(info, userId);
    if (userId >= 0) {
        innerCallback = new (std::nothrow) InnerDomainAuthCallback(userId, callback);
        if (innerCallback == nullptr) {
            ACCOUNT_LOGE("failed to create innerCallback");
            innerCallback = callback;
        }
    }
    if (plugin_ == nullptr) {
        Parcel emptyParcel;
        AccountSA::DomainAuthResult result;
        ErrCode err = PluginAuth(info, password, result);
        if (!result.Marshalling(emptyParcel)) {
            ACCOUNT_LOGE("DomainAuthResult marshalling failed.");
            err = ConvertToJSErrCode(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
        }
        if (innerCallback != nullptr) {
            innerCallback->OnResult(err, emptyParcel);
        }
        return ERR_OK;
    }
    auto task = [this, info, password, innerCallback] {
        this->StartAuth(this->plugin_, info, password, innerCallback, AUTH_WITH_CREDENTIAL_MODE);
    };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_AUTH);
    taskThread.detach();
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::PluginBindAccount(const DomainAccountInfo &info, const int32_t localId,
    DomainAuthResult &resultParcel) __attribute__((no_sanitize("cfi")))
{
    auto iter = methodMap_.find(PluginMethodEnum::BIND_ACCOUNT);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::BIND_ACCOUNT);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    ACCOUNT_LOGD("Param localId=%{public}d.", localId);
    int32_t callerLocalId = GetCallingUserID();
    if (localId == -1) {
        ACCOUNT_LOGE("fail to get activated os account ids");
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    PluginDomainAccountInfo domainAccountInfo;
    SetPluginDomainAccountInfo(info, domainAccountInfo);
    PluginBussnessError* error =
        (*reinterpret_cast<BindAccountFunc>(iter->second))(&domainAccountInfo, localId, callerLocalId);
    CleanPluginString(&(domainAccountInfo.domain.data), domainAccountInfo.domain.length);
    CleanPluginString(&(domainAccountInfo.serverConfigId.data), domainAccountInfo.serverConfigId.length);
    CleanPluginString(&(domainAccountInfo.accountName.data), domainAccountInfo.accountName.length);
    CleanPluginString(&(domainAccountInfo.accountId.data), domainAccountInfo.accountId.length);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::PluginUnBindAccount(
    const DomainAccountInfo &info, DomainAuthResult &resultParcel,
    const int32_t localId) __attribute__((no_sanitize("cfi")))
{
    auto iter = methodMap_.find(PluginMethodEnum::UNBIND_ACCOUNT);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::UNBIND_ACCOUNT);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    PluginDomainAccountInfo domainAccountInfo;
    SetPluginDomainAccountInfo(info, domainAccountInfo);
    PluginBussnessError* error = (*reinterpret_cast<UnbindAccountFunc>(iter->second))(&domainAccountInfo, localId);
    CleanPluginString(&(domainAccountInfo.domain.data), domainAccountInfo.domain.length);
    CleanPluginString(&(domainAccountInfo.serverConfigId.data), domainAccountInfo.serverConfigId.length);
    CleanPluginString(&(domainAccountInfo.accountName.data), domainAccountInfo.accountName.length);
    CleanPluginString(&(domainAccountInfo.accountId.data), domainAccountInfo.accountId.length);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::PluginIsAccountTokenValid(const DomainAccountInfo &info,
    const std::vector<uint8_t> &token, int32_t &isValid) __attribute__((no_sanitize("cfi")))
{
    auto iter = methodMap_.find(PluginMethodEnum::IS_ACCOUNT_TOKEN_VALID);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::IS_ACCOUNT_TOKEN_VALID);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    PluginDomainAccountInfo domainAccountInfo;
    SetPluginDomainAccountInfo(info, domainAccountInfo);
    PluginUint8Vector pToken;
    SetPluginUint8Vector(token, pToken);
    PluginBussnessError* error =
        (*reinterpret_cast<IsAccountTokenValidFunc>(iter->second))(&domainAccountInfo, &pToken, &isValid);
    CleanPluginString(&(domainAccountInfo.domain.data), domainAccountInfo.domain.length);
    CleanPluginString(&(domainAccountInfo.serverConfigId.data), domainAccountInfo.serverConfigId.length);
    CleanPluginString(&(domainAccountInfo.accountName.data), domainAccountInfo.accountName.length);
    CleanPluginString(&(domainAccountInfo.accountId.data), domainAccountInfo.accountId.length);
    ACCOUNT_LOGD("return isValid=%{public}d.", isValid);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::PluginGetAccessToken(const GetAccessTokenOptions &option,
    const std::vector<uint8_t> &token, const DomainAccountInfo &info,
    DomainAuthResult &resultParcel) __attribute__((no_sanitize("cfi")))
{
    auto iter = methodMap_.find(PluginMethodEnum::GET_ACCESS_TOKEN);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::GET_ACCESS_TOKEN);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    PluginGetDomainAccessTokenOptions pOption;
    SetPluginGetDomainAccessTokenOptions(option, token, info, pOption);
    PluginUint8Vector *accessToken = nullptr;
    ACCOUNT_LOGD("Param params=%{public}s callerUid=%{public}d.", pOption.bussinessParams.data, pOption.callerUid);
    PluginBussnessError* error = (*reinterpret_cast<GetAccessTokenFunc>(iter->second))(&pOption, &accessToken);
    if (accessToken != nullptr) {
        GetAndCleanPluginUint8Vector(*accessToken, resultParcel.token);
        free(accessToken);
    }
    accessToken = nullptr;
    CleanPluginString(&(pOption.domainAccountInfo.domain.data), pOption.domainAccountInfo.domain.length);
    CleanPluginString(&(pOption.domainAccountInfo.serverConfigId.data),
        pOption.domainAccountInfo.serverConfigId.length);
    CleanPluginString(&(pOption.domainAccountInfo.accountName.data),
        pOption.domainAccountInfo.accountName.length);
    CleanPluginString(&(pOption.domainAccountInfo.accountId.data),
        pOption.domainAccountInfo.accountId.length);
    CleanPluginString(&(pOption.bussinessParams.data), pOption.bussinessParams.length);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::PluginAuthWithPopup(
    const DomainAccountInfo &info, DomainAuthResult &resultParcel) __attribute__((no_sanitize("cfi")))
{
    auto iter = methodMap_.find(PluginMethodEnum::AUTH_WITH_POPUP);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::AUTH_WITH_POPUP);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    PluginDomainAccountInfo domainAccountInfo;
    SetPluginDomainAccountInfo(info, domainAccountInfo);
    PluginAuthResultInfo *authResultInfo = nullptr;
    PluginBussnessError* error = (*reinterpret_cast<AuthWithPopupFunc>(iter->second))(&domainAccountInfo,
        &authResultInfo);
    GetAndCleanPluginAuthResultInfo(&authResultInfo, resultParcel.token,
        resultParcel.authStatusInfo.remainingTimes, resultParcel.authStatusInfo.freezingTime);
    CleanPluginString(&(domainAccountInfo.domain.data), domainAccountInfo.domain.length);
    CleanPluginString(&(domainAccountInfo.serverConfigId.data), domainAccountInfo.serverConfigId.length);
    CleanPluginString(&(domainAccountInfo.accountName.data), domainAccountInfo.accountName.length);
    CleanPluginString(&(domainAccountInfo.accountId.data), domainAccountInfo.accountId.length);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::PluginAuthToken(const DomainAccountInfo &info,
    const std::vector<uint8_t> &authData, DomainAuthResult &resultParcel) __attribute__((no_sanitize("cfi")))
{
    auto iter = methodMap_.find(PluginMethodEnum::AUTH_WITH_TOKEN);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::AUTH_WITH_TOKEN);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    PluginDomainAccountInfo domainAccountInfo;
    SetPluginDomainAccountInfo(info, domainAccountInfo);
    PluginUint8Vector token;
    SetPluginUint8Vector(authData, token);
    PluginAuthResultInfo *authResultInfo = nullptr;
    PluginBussnessError* error = (*reinterpret_cast<AuthWithTokenFunc>(iter->second))(&domainAccountInfo, &token,
        &authResultInfo);
    GetAndCleanPluginAuthResultInfo(&authResultInfo, resultParcel.token,
        resultParcel.authStatusInfo.remainingTimes, resultParcel.authStatusInfo.freezingTime);
    CleanPluginString(&(domainAccountInfo.domain.data), domainAccountInfo.domain.length);
    CleanPluginString(&(domainAccountInfo.serverConfigId.data), domainAccountInfo.serverConfigId.length);
    CleanPluginString(&(domainAccountInfo.accountName.data), domainAccountInfo.accountName.length);
    CleanPluginString(&(domainAccountInfo.accountId.data), domainAccountInfo.accountId.length);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::PluginGetAuthStatusInfo(const DomainAccountInfo &info,
    AuthStatusInfo &authInfo) __attribute__((no_sanitize("cfi")))
{
    auto iter = methodMap_.find(PluginMethodEnum::GET_AUTH_STATUS_INFO);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::GET_AUTH_STATUS_INFO);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    PluginDomainAccountInfo domainAccountInfo;
    SetPluginDomainAccountInfo(info, domainAccountInfo);
    PluginAuthStatusInfo *authStatusInfo = nullptr;
    PluginBussnessError* error =
        (*reinterpret_cast<GetAuthStatusInfoFunc>(iter->second))(&domainAccountInfo, &authStatusInfo);
    GetAndCleanPluginAuthStatusInfo(&authStatusInfo, authInfo.remainingTimes, authInfo.freezingTime);
    CleanPluginString(&(domainAccountInfo.domain.data), domainAccountInfo.domain.length);
    CleanPluginString(&(domainAccountInfo.serverConfigId.data), domainAccountInfo.serverConfigId.length);
    CleanPluginString(&(domainAccountInfo.accountName.data), domainAccountInfo.accountName.length);
    CleanPluginString(&(domainAccountInfo.accountId.data), domainAccountInfo.accountId.length);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::PluginUpdateAccountInfo(const DomainAccountInfo &oldAccountInfo,
    const DomainAccountInfo &newAccountInfo) __attribute__((no_sanitize("cfi")))
{
    auto iter = methodMap_.find(PluginMethodEnum::UPDATE_ACCOUNT_INFO);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method = %{public}d not exsit.", PluginMethodEnum::UPDATE_ACCOUNT_INFO);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    int32_t callerLocalId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    PluginDomainAccountInfo oldDomainAccountInfo;
    SetPluginDomainAccountInfo(oldAccountInfo, oldDomainAccountInfo);
    PluginDomainAccountInfo newDomainAccountInfo;
    SetPluginDomainAccountInfo(newAccountInfo, newDomainAccountInfo);
    PluginBussnessError* error = (*reinterpret_cast<UpdateAccountInfoFunc>(iter->second))(&oldDomainAccountInfo,
        &newDomainAccountInfo, callerLocalId);
    CleanPluginString(&(oldDomainAccountInfo.domain.data), oldDomainAccountInfo.domain.length);
    CleanPluginString(&(oldDomainAccountInfo.serverConfigId.data), oldDomainAccountInfo.serverConfigId.length);
    CleanPluginString(&(oldDomainAccountInfo.accountName.data), oldDomainAccountInfo.accountName.length);
    CleanPluginString(&(oldDomainAccountInfo.accountId.data), oldDomainAccountInfo.accountId.length);
    CleanPluginString(&(newDomainAccountInfo.domain.data), newDomainAccountInfo.domain.length);
    CleanPluginString(&(newDomainAccountInfo.serverConfigId.data), newDomainAccountInfo.serverConfigId.length);
    CleanPluginString(&(newDomainAccountInfo.accountName.data), newDomainAccountInfo.accountName.length);
    CleanPluginString(&(newDomainAccountInfo.accountId.data), newDomainAccountInfo.accountId.length);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::InnerAuth(int32_t userId, const std::vector<uint8_t> &authData,
    const sptr<IDomainAccountCallback> &callback, AuthMode authMode)
{
    DomainAccountInfo domainInfo;
    ErrCode errCode = GetDomainAccountInfoByUserId(userId, domainInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
    sptr<InnerDomainAuthCallback> innerCallback = new (std::nothrow) InnerDomainAuthCallback(userId, callback);
    if (innerCallback == nullptr) {
        ACCOUNT_LOGE("failed to create innerCallback");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    if (plugin_ == nullptr) {
        Parcel emptyParcel;
        AccountSA::DomainAuthResult result;
        switch (authMode) {
            case AUTH_WITH_CREDENTIAL_MODE:
                errCode = PluginAuth(domainInfo, authData, result);
                break;
            case AUTH_WITH_POPUP_MODE:
                errCode = PluginAuthWithPopup(domainInfo, result);
                break;
            case AUTH_WITH_TOKEN_MODE:
                errCode = PluginAuthToken(domainInfo, authData, result);
                break;
            default:
                ACCOUNT_LOGE("AuthMode not match.");
                break;
        }
        if (!result.Marshalling(emptyParcel)) {
            ACCOUNT_LOGE("DomainAuthResult marshalling failed.");
            errCode = ConvertToJSErrCode(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
        }
        innerCallback->OnResult(errCode, emptyParcel);
        return ERR_OK;
    }
    auto task = [this, domainInfo, authData, innerCallback, authMode] {
        this->StartAuth(this->plugin_, domainInfo, authData, innerCallback, authMode);
    };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_INNER_AUTH);
    taskThread.detach();
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::AuthUser(int32_t userId, const std::vector<uint8_t> &password,
    const sptr<IDomainAccountCallback> &callback)
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    bool isVerified = false;
    (void) IInnerOsAccountManager::GetInstance().IsOsAccountVerified(userId, isVerified);
    if (isVerified) {
        return InnerAuth(userId, password, callback, AUTH_WITH_CREDENTIAL_MODE);
    }

    uint64_t credentialId = 0;
    (void) IInnerOsAccountManager::GetInstance().GetOsAccountCredentialId(userId, credentialId);
    if (credentialId > 0) {
        ACCOUNT_LOGE("unsupported auth type");
        return ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE;
    }
    return InnerAuth(userId, password, callback, AUTH_WITH_CREDENTIAL_MODE);
}

ErrCode InnerDomainAccountManager::AuthWithPopup(int32_t userId, const sptr<IDomainAccountCallback> &callback)
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    if (userId == 0) {
        std::vector<int32_t> userIds;
        (void)IInnerOsAccountManager::GetInstance().QueryActiveOsAccountIds(userIds);
        if (userIds.empty()) {
            ACCOUNT_LOGE("fail to get activated os account ids");
            return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
        }
        userId = userIds[0];
    }
    return InnerAuth(userId, {}, callback, AUTH_WITH_POPUP_MODE);
}

ErrCode InnerDomainAccountManager::AuthWithToken(int32_t userId, const std::vector<uint8_t> &token)
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    return InnerAuth(userId, token, nullptr, AUTH_WITH_TOKEN_MODE);
}

void InnerDomainAccountManager::InsertTokenToMap(int32_t userId, const std::vector<uint8_t> &token)
{
    std::lock_guard<std::mutex> lock(mutex_);
    userTokenMap_[userId] = token;
}

bool InnerDomainAccountManager::GetTokenFromMap(int32_t userId, std::vector<uint8_t> &token)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = userTokenMap_.find(userId);
    if (it == userTokenMap_.end()) {
        token.clear();
        return false;
    }
    token = it->second;
    return true;
}

void InnerDomainAccountManager::RemoveTokenFromMap(int32_t userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    userTokenMap_.erase(userId);
    return;
}

void InnerDomainAccountManager::NotifyDomainAccountEvent(
    int32_t userId, DomainAccountEvent event, DomainAccountStatus status, const DomainAccountInfo &info)
{
    if (status == DomainAccountStatus::LOG_END) {
        bool isActivated = false;
        (void)IInnerOsAccountManager::GetInstance().IsOsAccountActived(userId, isActivated);
        status = isActivated ? DomainAccountStatus::LOGIN : DomainAccountStatus::LOGIN_BACKGROUND;
    }

    // There is not need to check userid.
    DomainAccountEventData report;
    report.domainAccountInfo = info;
    report.event = event;
    report.status = status;
    report.userId = userId;
    StatusListenerManager::GetInstance().NotifyEventAsync(report);
}

ErrCode InnerDomainAccountManager::UpdateAccountToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token)
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if ((callingUid_ != -1) && (callingUid != callingUid_)) {
        ACCOUNT_LOGE("callingUid and register callinguid is not same!");
        return ERR_DOMAIN_ACCOUNT_SERVICE_INVALID_CALLING_UID;
    }
    int32_t userId = 0;
    ErrCode result = IInnerOsAccountManager::GetInstance().GetOsAccountLocalIdFromDomain(info, userId);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get os account localId from domain failed, result: %{public}d", result);
        return result;
    }

    if (token.empty()) {
        RemoveTokenFromMap(userId);
        result =
            IInnerOsAccountManager::GetInstance().UpdateAccountStatusForDomain(userId, DomainAccountStatus::LOGOUT);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("Update domain account status failed, result: %{public}d", result);
            return result;
        }
        NotifyDomainAccountEvent(userId, DomainAccountEvent::TOKEN_INVALID, DomainAccountStatus::LOGOUT, info);
        return ERR_OK;
    }
    InsertTokenToMap(userId, token);
    NotifyDomainAccountEvent(userId, DomainAccountEvent::TOKEN_UPDATED, DomainAccountStatus::LOG_END, info);
    return ERR_OK;
}

static void OnResultForGetAccessToken(const ErrCode errCode, const sptr<IDomainAccountCallback> &callback)
{
    std::vector<uint8_t> token;
    Parcel emptyParcel;
    emptyParcel.WriteUInt8Vector(token);
    callback->OnResult(errCode, emptyParcel);
}

ErrCode InnerDomainAccountManager::StartGetAccessToken(const sptr<IDomainAccountPlugin> &plugin,
    const std::vector<uint8_t> &accountToken, const DomainAccountInfo &info, const GetAccessTokenOptions &option,
    const sptr<IDomainAccountCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("invalid callback");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (plugin == nullptr) {
        ACCOUNT_LOGE("plugin is nullptr");
        OnResultForGetAccessToken(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, callback);
        return ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST;
    }
    DomainAccountCallbackFunc callbackFunc = [callback](const int32_t errCode, Parcel &parcel) {
        if (callback != nullptr) {
            callback->OnResult(errCode, parcel);
        }
    };
    sptr<DomainAccountCallbackService> callbackService =
        new (std::nothrow) DomainAccountCallbackService(callbackFunc);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("make shared DomainAccountCallbackService failed");
        OnResultForGetAccessToken(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, callback);
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    ErrCode result = plugin->GetAccessToken(info, accountToken, option, callbackService);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get access token, errCode: %{public}d", result);
        OnResultForGetAccessToken(result, callback);
        return result;
    }
    return ERR_OK;
}

static ErrCode QueryAccountInfo(const DomainAccountInfo &info, const int32_t &callingUid,
    DomainAccountInfo &targetInfo, int32_t &userId)
{
    ErrCode result = ERR_OK;
    if (!info.accountName_.empty()) {
        result = IInnerOsAccountManager::GetInstance().GetOsAccountLocalIdFromDomain(info, userId);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("domain account not found");
            return result;
        }
    } else {
        userId = callingUid / UID_TRANSFORM_DIVISOR;
        OsAccountInfo osAccountInfo;
        (void) IInnerOsAccountManager::GetInstance().GetRealOsAccountInfoById(userId, osAccountInfo);
        osAccountInfo.GetDomainInfo(targetInfo);
        if (targetInfo.accountName_.empty()) {
            ACCOUNT_LOGE("domain account not found");
            return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
        }
    }
    return result;
}

ErrCode InnerDomainAccountManager::GetAccessToken(
    const DomainAccountInfo &info, const AAFwk::WantParams &parameters, const sptr<IDomainAccountCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("invalid callback");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = 0;
    DomainAccountInfo targetInfo = info;
    ErrCode result = QueryAccountInfo(info, callingUid, targetInfo, userId);
    if (result != ERR_OK) {
        return result;
    }
    std::vector<uint8_t> accountToken;
    if (!GetTokenFromMap(userId, accountToken)) {
        ACCOUNT_LOGI("The target domain account has not authenticated");
    }
    GetAccessTokenOptions option(callingUid, parameters);
    if (plugin_ == nullptr) {
        Parcel emptyParcel;
        AccountSA::DomainAuthResult authResult;
        ErrCode err = PluginGetAccessToken(option, accountToken, targetInfo, authResult);
        if (!authResult.Marshalling(emptyParcel)) {
            ACCOUNT_LOGE("DomainAuthResult marshalling failed.");
            err = ConvertToJSErrCode(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
        }
        callback->OnResult(err, emptyParcel);
        return ERR_OK;
    }
    auto task = [this, accountToken, targetInfo, option, callback] {
        this->StartGetAccessToken(this->plugin_, accountToken, targetInfo, option, callback);
    };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_GET_ACCESS_TOKEN);
    taskThread.detach();
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::IsAuthenticationExpired(
    const DomainAccountInfo &info, bool &isExpired) __attribute__((no_sanitize("cfi")))
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    auto iter = methodMap_.find(PluginMethodEnum::IS_AUTHENTICATION_EXPIRED);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::IS_AUTHENTICATION_EXPIRED);
        return ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST;
    }
    int32_t userId = 0;
    ErrCode result = IInnerOsAccountManager::GetInstance().GetOsAccountLocalIdFromDomain(info, userId);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("The target domain account not found, isExpired=true.");
        isExpired = true;
        return ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT;
    }
    OsAccountInfo osAccountInfo;
    result = IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(userId, osAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("Failed to get account info");
        return result;
    }

    DomainAccountInfo domainInfo;
    osAccountInfo.GetDomainInfo(domainInfo);
    if (domainInfo.serverConfigId_.empty()) {
        ACCOUNT_LOGI("No server config id, isExpired=false");
        isExpired = false;
        return ERR_OK;
    }

    std::vector<uint8_t> accountToken;
    if (!GetTokenFromMap(userId, accountToken)) {
        ACCOUNT_LOGI("The target domain account has not authenticated");
    }

    PluginDomainAccountInfo domainAccountInfo;
    SetPluginDomainAccountInfo(info, domainAccountInfo);
    PluginUint8Vector pToken;
    SetPluginUint8Vector(accountToken, pToken);
    int32_t isValid = 0;
    PluginBussnessError* error =
        (*reinterpret_cast<IsAuthenticationExpiredFunc>(iter->second))(&domainAccountInfo, &pToken, &isValid);
    ACCOUNT_LOGI("Return isValid=%{public}d.", isValid);
    if (error == nullptr) {
        ACCOUNT_LOGE("Error is nullptr.");
        return ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST;
    }
    isExpired = (isValid == 0);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::SetAccountPolicy(const DomainAccountInfo &info,
    const std::string &policy) __attribute__((no_sanitize("cfi")))
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    auto iter = methodMap_.find(PluginMethodEnum::SET_ACCOUNT_POLICY);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::SET_ACCOUNT_POLICY);
        return ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST;
    }
    int32_t callerLocalId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (!info.IsEmpty()) {
        int32_t userId = 0;
        ErrCode result = IInnerOsAccountManager::GetInstance().GetOsAccountLocalIdFromDomain(info, userId);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("The target domain account not found.");
            return ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT;
        }
    }
    PluginString parameters;
    SetPluginString(policy, parameters);
    PluginDomainAccountInfo domainAccountInfo;
    SetPluginDomainAccountInfo(info, domainAccountInfo);
    PluginBussnessError* error =
        (*reinterpret_cast<SetAccountPolicyFunc>(iter->second))(&parameters, &domainAccountInfo, callerLocalId);
    CleanPluginString(&(domainAccountInfo.domain.data), domainAccountInfo.domain.length);
    CleanPluginString(&(domainAccountInfo.serverConfigId.data), domainAccountInfo.serverConfigId.length);
    CleanPluginString(&(domainAccountInfo.accountName.data), domainAccountInfo.accountName.length);
    CleanPluginString(&(domainAccountInfo.accountId.data), domainAccountInfo.accountId.length);
    CleanPluginString(&(parameters.data), parameters.length);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::GetAccountPolicy(const DomainAccountInfo &info,
    std::string &policy) __attribute__((no_sanitize("cfi")))
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    auto iter = methodMap_.find(PluginMethodEnum::GET_ACCOUNT_POLICY);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::GET_ACCOUNT_POLICY);
        return ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST;
    }
    int32_t callerLocalId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (!info.IsEmpty()) {
        int32_t userId = 0;
        ErrCode result = IInnerOsAccountManager::GetInstance().GetOsAccountLocalIdFromDomain(info, userId);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("The target domain account not found.");
            return ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT;
        }
    }
    PluginDomainAccountInfo domainAccountInfo;
    SetPluginDomainAccountInfo(info, domainAccountInfo);
    PluginDomainAccountPolicy *domainAccountPolicy = nullptr;
    PluginBussnessError* error = (*reinterpret_cast<GetAccountPolicyFunc>(iter->second))(&domainAccountInfo,
        callerLocalId, &domainAccountPolicy);
    if (domainAccountPolicy != nullptr) {
        GetAndCleanPluginDomainAccountPolicy(&domainAccountPolicy, policy);
    }
    CleanPluginString(&(domainAccountInfo.domain.data), domainAccountInfo.domain.length);
    CleanPluginString(&(domainAccountInfo.serverConfigId.data), domainAccountInfo.serverConfigId.length);
    CleanPluginString(&(domainAccountInfo.accountName.data), domainAccountInfo.accountName.length);
    CleanPluginString(&(domainAccountInfo.accountId.data), domainAccountInfo.accountId.length);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

static void ErrorOnResult(const ErrCode errCode, const sptr<IDomainAccountCallback> &callback)
{
    Parcel emptyParcel;
    emptyParcel.WriteBool(false);
    callback->OnResult(errCode, emptyParcel);
}

void CheckUserTokenCallback::OnResult(int32_t result, Parcel &parcel)
{
    ACCOUNT_LOGI("enter");
    if (result == ERR_OK) {
        isValid_ = parcel.ReadBool();
    }
    NotifyCallbackEnd();
}

bool CheckUserTokenCallback::GetValidity(void)
{
    return isValid_;
}

void CheckUserTokenCallback::WaitForCallbackResult()
{
    std::unique_lock<std::mutex> lock(lock_);
    condition_.wait(lock, [this] {
        return threadInSleep_ == false;
    });
    ACCOUNT_LOGI("WaitForCallbackResult.");
}

void CheckUserTokenCallback::NotifyCallbackEnd()
{
    std::unique_lock<std::mutex> lock(lock_);
    if (threadInSleep_) {
        ACCOUNT_LOGI("threadInSleep_ set false.");
        threadInSleep_ = false;
        condition_.notify_one();
    }
}

ErrCode InnerDomainAccountManager::CheckUserToken(
    const std::vector<uint8_t> &token, bool &isValid, const DomainAccountInfo &info)
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    std::shared_ptr<CheckUserTokenCallback> callback = std::make_shared<CheckUserTokenCallback>();
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("make shared DomainAccountCallbackService failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }

    ErrCode errCode = ERR_OK;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (plugin_ == nullptr) {
            Parcel emptyParcel;
            int32_t isTokenValid = -1;
            ErrCode err = PluginIsAccountTokenValid(info, token, isTokenValid);
            if (err == ERR_OK) {
                isValid = (isTokenValid == 1);
            }
            return err;
        }
        errCode = plugin_->IsAccountTokenValid(info, token, callbackService);
    }
    callback->WaitForCallbackResult();
    isValid = callback->GetValidity();
    return errCode;
}

ErrCode InnerDomainAccountManager::GetAccountStatus(const DomainAccountInfo &info, DomainAccountStatus &status)
{
    status = DomainAccountStatus::LOGOUT;

    int32_t userId = 0;
    ErrCode res = IInnerOsAccountManager::GetInstance().GetOsAccountLocalIdFromDomain(info, userId);
    if (res != ERR_OK) {
        return res;
    }
    std::vector<uint8_t> token;
    if (!GetTokenFromMap(userId, token)) {
        ACCOUNT_LOGI("the target domain account has not authenticated");
        return ERR_OK;
    }

    bool isValid = false;
    res = CheckUserToken(token, isValid, info);
    if (!isValid) {
        ACCOUNT_LOGI("Token is invalid.");
        return res;
    }

    bool isActivated = false;
    res = IInnerOsAccountManager::GetInstance().IsOsAccountActived(userId, isActivated);
    if (isActivated) {
        status = DomainAccountStatus::LOGIN;
    } else {
        status = DomainAccountStatus::LOGIN_BACKGROUND;
    }
    return res;
}

ErrCode InnerDomainAccountManager::RegisterAccountStatusListener(const sptr<IDomainAccountCallback> &listener)
{
    return StatusListenerManager::GetInstance().InsertListenerToRecords(listener->AsObject());
}

ErrCode InnerDomainAccountManager::UnregisterAccountStatusListener(const sptr<IDomainAccountCallback> &listener)
{
    // userid may be removed already.
    return StatusListenerManager::GetInstance().RemoveListenerByListener(listener->AsObject());
}

ErrCode InnerDomainAccountManager::GetAuthStatusInfo(
    const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback)
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    sptr<IDomainAccountCallback> callbackService =
        new (std::nothrow) DomainAccountCallbackService(callback);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("failed to create DomainAccountCallbackService");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    if (plugin_ == nullptr) {
        Parcel emptyParcel;
        AuthStatusInfo authInfo;
        ErrCode err = PluginGetAuthStatusInfo(info, authInfo);
        if (!authInfo.Marshalling(emptyParcel)) {
            ACCOUNT_LOGE("AuthStatusInfo marshalling failed.");
            err = ConvertToJSErrCode(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
        }
        callbackService->OnResult(err, emptyParcel);
        return ERR_OK;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return plugin_->GetAuthStatusInfo(info, callbackService);
}

sptr<IRemoteObject::DeathRecipient> InnerDomainAccountManager::GetDeathRecipient()
{
    if (deathRecipient_ != nullptr) {
        return deathRecipient_;
    }
    deathRecipient_ = new (std::nothrow) DomainAccountPluginDeathRecipient();
    return deathRecipient_;
}

bool InnerDomainAccountManager::IsPluginAvailable()
{
    std::lock(mutex_, libMutex_);
    std::lock_guard<std::mutex> lock1(mutex_, std::adopt_lock);
    std::lock_guard<std::mutex> lock2(libMutex_, std::adopt_lock);
    return plugin_ != nullptr || libHandle_ != nullptr;
}

ErrCode InnerDomainAccountManager::StartHasDomainAccount(const sptr<IDomainAccountPlugin> &plugin,
    const GetDomainAccountInfoOptions &options, const sptr<IDomainAccountCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("invalid callback");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (plugin == nullptr) {
        ACCOUNT_LOGE("plugin is nullptr");
        ErrorOnResult(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, callback);
        return ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST;
    }
    auto callbackWrapper = std::make_shared<DomainHasDomainInfoCallback>(
        callback, options.accountInfo.domain_, options.accountInfo.accountName_);
    if (callbackWrapper == nullptr) {
        ACCOUNT_LOGE("make shared DomainHasDomainInfoCallback failed");
        ErrorOnResult(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, callback);
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    sptr<DomainAccountCallbackService> callbackService =
        new (std::nothrow) DomainAccountCallbackService(callbackWrapper);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("make shared DomainAccountCallbackService failed");
        ErrorOnResult(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, callback);
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    ErrCode result = plugin->GetDomainAccountInfo(options, callbackService);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get domain account, errCode: %{public}d", result);
        ErrorOnResult(result, callback);
        return result;
    }
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::HasDomainAccount(
    const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    GetDomainAccountInfoOptions options;
    options.accountInfo = info;
    options.callingUid = callingUid;
    auto task = [this, options, callback] { this->StartHasDomainAccount(this->plugin_, options, callback); };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_HAS_ACCOUNT);
    taskThread.detach();
    return ERR_OK;
}

void InnerDomainAccountManager::StartOnAccountBound(const sptr<IDomainAccountPlugin> &plugin,
    const DomainAccountInfo &info, const int32_t localId, const sptr<IDomainAccountCallback> &callback)
{
    if (plugin == nullptr) {
        ACCOUNT_LOGE("plugin not exists");
        return ErrorOnResult(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, callback);
    }
    plugin->OnAccountBound(info, localId, callback);
}

ErrCode InnerDomainAccountManager::OnAccountBound(const DomainAccountInfo &info, const int32_t localId,
    const std::shared_ptr<DomainAccountCallback> &callback)
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("make shared DomainAccountCallbackService failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    if (plugin_ == nullptr) {
        Parcel emptyParcel;
        AccountSA::DomainAuthResult result;
        ErrCode err = PluginBindAccount(info, localId, result);
        if (!result.Marshalling(emptyParcel)) {
            ACCOUNT_LOGE("DomainAuthResult marshalling failed.");
            err = ConvertToJSErrCode(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
        }
        callbackService->OnResult(err, emptyParcel);
        return ERR_OK;
    }
    auto task = [this, info, localId, callbackService] {
        this->StartOnAccountBound(this->plugin_, info, localId, callbackService);
    };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_BIND_ACCOUNT);
    taskThread.detach();
    return ERR_OK;
}

void InnerDomainAccountManager::StartOnAccountUnBound(const sptr<IDomainAccountPlugin> &plugin,
    const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    if (plugin == nullptr) {
        ACCOUNT_LOGE("plugin not exists");
        return ErrorOnResult(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, callback);
    }
    plugin->OnAccountUnBound(info, callback);
}

ErrCode InnerDomainAccountManager::OnAccountUnBound(const DomainAccountInfo &info,
    const std::shared_ptr<DomainAccountCallback> &callback, const int32_t localId)
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("make shared DomainAccountCallbackService failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    if (plugin_ == nullptr) {
        Parcel emptyParcel;
        AccountSA::DomainAuthResult result;
        ErrCode err = PluginUnBindAccount(info, result, localId);
        if (!result.Marshalling(emptyParcel)) {
            ACCOUNT_LOGE("DomainAuthResult marshalling failed.");
            err = ConvertToJSErrCode(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
        }
        callbackService->OnResult(err, emptyParcel);
        return ERR_OK;
    }
    auto task = [this, info, callbackService] {
        this->StartOnAccountUnBound(this->plugin_, info, callbackService);
    };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_UNBIND_ACCOUNT);
    taskThread.detach();
    return ERR_OK;
}

void InnerDomainAccountManager::StartGetDomainAccountInfo(const sptr<IDomainAccountPlugin> &plugin,
    const GetDomainAccountInfoOptions &options, const sptr<IDomainAccountCallback> &callback)
{
    if (plugin == nullptr) {
        ACCOUNT_LOGE("plugin not exists");
        return ErrorOnResult(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, callback);
    }
    ErrCode errCode = plugin->GetDomainAccountInfo(options, callback);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to get domain account, errCode: %{public}d", errCode);
        ErrorOnResult(errCode, callback);
    }
}

ErrCode InnerDomainAccountManager::PluginGetDomainAccountInfo(const GetDomainAccountInfoOptions &options,
    DomainAccountInfo &info) __attribute__((no_sanitize("cfi")))
{
    auto iter = methodMap_.find(PluginMethodEnum::GET_ACCOUNT_INFO);
    if (iter == methodMap_.end() || iter->second == nullptr) {
        ACCOUNT_LOGE("Caller method=%{public}d not exsit.", PluginMethodEnum::GET_ACCOUNT_INFO);
        return ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
    }
    int32_t localId = GetCallingUserID();
    if (localId == -1) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    PluginGetDomainAccountInfoOptions pluginOptions;
    SetPluginDomainAccountInfo(options.accountInfo, pluginOptions.domainAccountInfo);
    pluginOptions.callerUid = options.callingUid;
    PluginDomainAccountInfo *accountInfoResult = nullptr;
    PluginBussnessError* error =
        (*reinterpret_cast<GetAccountInfoFunc>(iter->second))(&pluginOptions, localId, &accountInfoResult);
    GetAndCleanPluginDomainAccountInfo(info, &accountInfoResult);
    CleanPluginString(&(pluginOptions.domainAccountInfo.domain.data), pluginOptions.domainAccountInfo.domain.length);
    CleanPluginString(&(pluginOptions.domainAccountInfo.serverConfigId.data),
        pluginOptions.domainAccountInfo.serverConfigId.length);
    CleanPluginString(&(pluginOptions.domainAccountInfo.accountName.data),
        pluginOptions.domainAccountInfo.accountName.length);
    CleanPluginString(&(pluginOptions.domainAccountInfo.accountId.data),
        pluginOptions.domainAccountInfo.accountId.length);
    return GetAndCleanPluginBussnessError(&error, iter->first);
}

ErrCode InnerDomainAccountManager::GetDomainAccountInfo(const DomainAccountInfo &info, DomainAccountInfo &result)
{
    if (info.accountName_.empty()) {
        ACCOUNT_LOGI("Domian Account not bind");
        return ERR_OK;
    }
    if (plugin_ == nullptr) {
        GetDomainAccountInfoOptions options;
        options.accountInfo = info;
        options.callingUid = IPCSkeleton::GetCallingUid();
        return PluginGetDomainAccountInfo(options, result);
    }
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::GetDomainAccountInfo(
    const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    DomainAccountCallbackFunc callbackFunc = [callback](const int32_t errCode, Parcel &parcel) {
        if (callback != nullptr) {
            callback->OnResult(errCode, parcel);
        }
    };
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callbackFunc);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("make shared DomainAccountCallbackService failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    GetDomainAccountInfoOptions options;
    options.accountInfo = info;
    options.callingUid = callingUid;
    if (plugin_ == nullptr) {
        Parcel emptyParcel;
        DomainAccountInfo result;
        ErrCode err = PluginGetDomainAccountInfo(options, result);
        AAFwk::WantParams wParam;
        wParam.SetParam("domain", OHOS::AAFwk::String::Box(result.domain_));
        wParam.SetParam("accountName", OHOS::AAFwk::String::Box(result.accountName_));
        wParam.SetParam("accountId", OHOS::AAFwk::String::Box(result.accountId_));
        wParam.SetParam("serverConfigId", OHOS::AAFwk::String::Box(result.serverConfigId_));
        wParam.SetParam("isAuthenticated", OHOS::AAFwk::Boolean::Box(result.isAuthenticated));
        wParam.SetParam("status", OHOS::AAFwk::Integer::Box(result.status_));
        if (!wParam.Marshalling(emptyParcel)) {
            ACCOUNT_LOGE("DomainAccountInfo marshalling failed.");
            err = ConvertToJSErrCode(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
        }
        callbackService->OnResult(err, emptyParcel);
        return ERR_OK;
    }
    auto task = [this, options, callbackService] {
        this->StartGetDomainAccountInfo(this->plugin_, options, callbackService);
    };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_GET_ACCOUNT);
    taskThread.detach();
    return ERR_OK;
}

void InnerDomainAccountManager::StartIsAccountTokenValid(const sptr<IDomainAccountPlugin> &plugin,
    const DomainAccountInfo &info, const std::vector<uint8_t> &token, const sptr<IDomainAccountCallback> &callback)
{
    if (plugin == nullptr) {
        ACCOUNT_LOGE("plugin not exists");
        return ErrorOnResult(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, callback);
    }
    ErrCode errCode = plugin->IsAccountTokenValid(info, token, callback);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to get domain account, errCode: %{public}d", errCode);
        ErrorOnResult(errCode, callback);
    }
}

ErrCode InnerDomainAccountManager::IsAccountTokenValid(const DomainAccountInfo &info,
    const std::vector<uint8_t> &token, const std::shared_ptr<DomainAccountCallback> &callback)
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("make shared DomainAccountCallbackService failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    if (plugin_ == nullptr) {
        Parcel emptyParcel;
        int32_t isValid = -1;
        ErrCode err = PluginIsAccountTokenValid(info, token, isValid);
        if (!emptyParcel.WriteBool(isValid == 1)) {
            ACCOUNT_LOGE("IsValid marshalling failed.");
            err = ConvertToJSErrCode(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
        }
        callbackService->OnResult(err, emptyParcel);
        return ERR_OK;
    }
    auto task = [this, info, token, callbackService] {
        this->StartIsAccountTokenValid(this->plugin_, info, token, callbackService);
    };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_IS_ACCOUNT_VALID);
    taskThread.detach();
    return ERR_OK;
}

void UpdateAccountInfoCallback::OnResult(int32_t result, Parcel &parcel)
{
    std::unique_lock<std::mutex> lock(lock_);
    if (result_ >= 0) {
        return;
    }
    if (result == ERR_JS_ACCOUNT_NOT_FOUND) {
        result_ = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    } else if (result == ERR_JS_CAPABILITY_NOT_SUPPORTED) {
        result_ = ERR_OK;
    } else {
        result_ = result;
    }
    if (result_ == ERR_OK) {
        std::shared_ptr<AAFwk::WantParams> parameters(AAFwk::WantParams::Unmarshalling(parcel));
        if (parameters == nullptr) {
            ACCOUNT_LOGE("Parameters unmarshalling error");
            result_ = ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
        } else {
            accountInfo_.accountName_ = parameters->GetStringParam("accountName");
            accountInfo_.domain_ = parameters->GetStringParam("domain");
            accountInfo_.accountId_ = parameters->GetStringParam("accountId");
            accountInfo_.serverConfigId_ = parameters->GetStringParam("serverConfigId");
        }
    }
    ACCOUNT_LOGI("ThreadInSleep_ set false.");
    threadInSleep_ = false;
    condition_.notify_one();
}

int32_t UpdateAccountInfoCallback::GetResult()
{
    return result_;
}

void UpdateAccountInfoCallback::WaitForCallbackResult()
{
    std::unique_lock<std::mutex> lock(lock_);
    condition_.wait(lock, [this] {
        return threadInSleep_ == false;
    });
    ACCOUNT_LOGI("WaitForCallbackResult.");
}

DomainAccountInfo UpdateAccountInfoCallback::GetAccountInfo()
{
    return accountInfo_;
}

static ErrCode CheckNewDomainAccountInfo(const DomainAccountInfo &oldAccountInfo, DomainAccountInfo &newAccountInfo)
{
    if (!oldAccountInfo.serverConfigId_.empty()) {
        if (newAccountInfo.serverConfigId_.empty()) {
            newAccountInfo.serverConfigId_ = oldAccountInfo.serverConfigId_;
        }
    }
    ErrCode result = ERR_OK;
    if (!IInnerOsAccountManager::GetInstance().IsSameAccount(oldAccountInfo, newAccountInfo)) {
        int32_t userId = 0;
        result = IInnerOsAccountManager::GetInstance().GetOsAccountLocalIdFromDomain(newAccountInfo, userId);
        if (result == ERR_OK && userId > 0) {
            ACCOUNT_LOGE("NewAccountInfo already exists");
            return ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR;
        }
    }
    std::shared_ptr<UpdateAccountInfoCallback> callback = std::make_shared<UpdateAccountInfoCallback>();
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("Make shared DomainAccountCallbackService failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    result = InnerDomainAccountManager::GetInstance().GetDomainAccountInfo(newAccountInfo, callbackService);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetDomainAccountInfo failed, result = %{public}d", result);
        return result;
    }
    callback->WaitForCallbackResult();
    result = callback->GetResult();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("NewAccountInfo is invaild");
        return result;
    }
    newAccountInfo = callback->GetAccountInfo();
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::UpdateAccountInfo(
    const DomainAccountInfo &oldAccountInfo, const DomainAccountInfo &newAccountInfo)
{
    if (!IsSupportNetRequest()) {
        ACCOUNT_LOGE("Not support background account request");
        return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
    }
    if (!IsPluginAvailable()) {
        ACCOUNT_LOGE("Plugin is nullptr.");
        return ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST;
    }
    // check old account info
    int32_t userId = 0;
    ErrCode result = IInnerOsAccountManager::GetInstance().GetOsAccountLocalIdFromDomain(oldAccountInfo, userId);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetOsAccountLocalIdFromDomain failed, result = %{public}d", result);
        return result;
    }
    // check new account info
    DomainAccountInfo newDomainAccountInfo(newAccountInfo);
    result = CheckNewDomainAccountInfo(oldAccountInfo, newDomainAccountInfo);
    if (result != ERR_OK) {
        return result;
    }

    if (oldAccountInfo.serverConfigId_.empty() && !newAccountInfo.serverConfigId_.empty()) {
        Parcel emptyParcel;
        AccountSA::DomainAuthResult authResult;
        result = PluginBindAccount(newAccountInfo, userId, authResult);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("PluginBindAccount failed, errCode = %{public}d", result);
            return result;
        }
        if (!authResult.Marshalling(emptyParcel)) {
            ACCOUNT_LOGE("DomainAuthResult marshalling failed.");
            return ConvertToJSErrCode(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
        }
    } else {
        // update account info
        if (plugin_ == nullptr) {
            result = PluginUpdateAccountInfo(oldAccountInfo, newDomainAccountInfo);
            if (result != ERR_OK) {
                ACCOUNT_LOGE("PluginUpdateAccountInfo failed, errCode = %{public}d", result);
                return result;
            }
        }
    }

    // update local info
    return IInnerOsAccountManager::GetInstance().UpdateAccountInfoByDomainAccountInfo(
        userId, newDomainAccountInfo);
}
}  // namespace AccountSA
}  // namespace OHOS

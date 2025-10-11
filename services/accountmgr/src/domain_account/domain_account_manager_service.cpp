/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "domain_account_manager_service.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "inner_domain_account_manager.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
namespace {
constexpr int32_t START_USER_ID = 100;
const std::set<uint32_t> UID_WHITELIST_FOR_SET { 3057 };
const char MANAGE_LOCAL_ACCOUNTS[] = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
const char MANAGE_DOMAIN_ACCOUNTS[] = "ohos.permission.MANAGE_DOMAIN_ACCOUNTS";
const char GET_LOCAL_ACCOUNTS[] = "ohos.permission.GET_LOCAL_ACCOUNTS";
const char ACCESS_USER_AUTH_INTERNAL[] = "ohos.permission.ACCESS_USER_AUTH_INTERNAL";
const char GET_DOMAIN_ACCOUNTS[] = "ohos.permission.GET_DOMAIN_ACCOUNTS";
const char INTERACT_ACROSS_LOCAL_ACCOUNTS[] = "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS";
const char MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS[] = "ohos.permission.MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS";
static const std::set<IDomainAccountIpcCode> NON_SYSTEM_API_SET = {
    IDomainAccountIpcCode::COMMAND_UPDATE_ACCOUNT_INFO,
    IDomainAccountIpcCode::COMMAND_UPDATE_SERVER_CONFIG,
    IDomainAccountIpcCode::COMMAND_GET_SERVER_CONFIG,
    IDomainAccountIpcCode::COMMAND_GET_ALL_SERVER_CONFIGS,
    IDomainAccountIpcCode::COMMAND_ADD_SERVER_CONFIG,
    IDomainAccountIpcCode::COMMAND_REMOVE_SERVER_CONFIG,
    IDomainAccountIpcCode::COMMAND_GET_ACCOUNT_SERVER_CONFIG,
};
static const std::map<IDomainAccountIpcCode, std::vector<std::string>> PERMISSIONMAP = {
    {IDomainAccountIpcCode::COMMAND_REGISTER_PLUGIN, {MANAGE_LOCAL_ACCOUNTS}},
    {IDomainAccountIpcCode::COMMAND_UNREGISTER_PLUGIN, {MANAGE_LOCAL_ACCOUNTS}},
    {IDomainAccountIpcCode::COMMAND_SET_ACCOUNT_POLICY, {MANAGE_LOCAL_ACCOUNTS}},
    {IDomainAccountIpcCode::COMMAND_GET_ACCOUNT_POLICY, {MANAGE_LOCAL_ACCOUNTS}},
    {IDomainAccountIpcCode::COMMAND_HAS_DOMAIN_ACCOUNT, {MANAGE_LOCAL_ACCOUNTS}},
    {IDomainAccountIpcCode::COMMAND_UPDATE_ACCOUNT_TOKEN, {MANAGE_LOCAL_ACCOUNTS}},
    {IDomainAccountIpcCode::COMMAND_UPDATE_ACCOUNT_INFO, {MANAGE_LOCAL_ACCOUNTS, MANAGE_DOMAIN_ACCOUNTS}},
    {IDomainAccountIpcCode::COMMAND_GET_ACCOUNT_STATUS, {GET_LOCAL_ACCOUNTS}},
    {IDomainAccountIpcCode::COMMAND_REGISTER_ACCOUNT_STATUS_LISTENER, {GET_LOCAL_ACCOUNTS}},
    {IDomainAccountIpcCode::COMMAND_UNREGISTER_ACCOUNT_STATUS_LISTENER, {GET_LOCAL_ACCOUNTS}},
    {IDomainAccountIpcCode::COMMAND_AUTH, {ACCESS_USER_AUTH_INTERNAL}},
    {IDomainAccountIpcCode::COMMAND_AUTH_USER, {ACCESS_USER_AUTH_INTERNAL}},
    {IDomainAccountIpcCode::COMMAND_GET_DOMAIN_ACCOUNT_INFO, {GET_DOMAIN_ACCOUNTS}},
    {IDomainAccountIpcCode::COMMAND_IS_AUTHENTICATION_EXPIRED,
        {MANAGE_LOCAL_ACCOUNTS, INTERACT_ACROSS_LOCAL_ACCOUNTS}},
    {IDomainAccountIpcCode::COMMAND_ADD_SERVER_CONFIG,
        {MANAGE_LOCAL_ACCOUNTS, MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS}},
    {IDomainAccountIpcCode::COMMAND_REMOVE_SERVER_CONFIG,
        {MANAGE_LOCAL_ACCOUNTS, MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS}},
    {IDomainAccountIpcCode::COMMAND_GET_ACCOUNT_SERVER_CONFIG,
        {MANAGE_LOCAL_ACCOUNTS, MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS}},
    {IDomainAccountIpcCode::COMMAND_UPDATE_SERVER_CONFIG, {MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS}},
    {IDomainAccountIpcCode::COMMAND_GET_SERVER_CONFIG, {MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS}},
    {IDomainAccountIpcCode::COMMAND_GET_ALL_SERVER_CONFIGS, {MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS}},
    {IDomainAccountIpcCode::COMMAND_CANCEL_AUTH, {ACCESS_USER_AUTH_INTERNAL}},
};
}

DomainAccountManagerService::DomainAccountManagerService()
{}

DomainAccountManagerService::~DomainAccountManagerService()
{}

ErrCode DomainAccountManagerService::RegisterPlugin(const sptr<IDomainAccountPlugin> &plugin)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_REGISTER_PLUGIN);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().RegisterPlugin(plugin);
}

ErrCode DomainAccountManagerService::UnregisterPlugin()
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_UNREGISTER_PLUGIN);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().UnregisterPlugin();
}

ErrCode DomainAccountManagerService::HasDomainAccount(
    const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_HAS_DOMAIN_ACCOUNT);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().HasDomainAccount(info, callback);
}

ErrCode DomainAccountManagerService::GetAccessToken(
    const DomainAccountInfo &info, const AAFwk::WantParams &parameters, const sptr<IDomainAccountCallback> &callback)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_GET_ACCESS_TOKEN);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().GetAccessToken(info, parameters, callback);
}

ErrCode DomainAccountManagerService::UpdateAccountToken(
    const DomainAccountInfo &info, const std::vector<uint8_t> &token)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_UPDATE_ACCOUNT_TOKEN);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().UpdateAccountToken(info, token);
}

static bool CheckManageExpiryThresholdWhiteList()
{
    return UID_WHITELIST_FOR_SET.find(IPCSkeleton::GetCallingUid()) != UID_WHITELIST_FOR_SET.end();
}

ErrCode DomainAccountManagerService::IsAuthenticationExpired(const DomainAccountInfo &info, bool &isExpired)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_IS_AUTHENTICATION_EXPIRED);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().IsAuthenticationExpired(info, isExpired);
}

ErrCode DomainAccountManagerService::SetAccountPolicy(const DomainAccountInfo &info, const std::string &policy)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_SET_ACCOUNT_POLICY);
    if (result != ERR_OK) {
        return result;
    }
    // check EDM uid
    if (!CheckManageExpiryThresholdWhiteList()) {
        ACCOUNT_LOGE("Permission denied, callingUid=%{public}d.", IPCSkeleton::GetCallingUid());
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return InnerDomainAccountManager::GetInstance().SetAccountPolicy(info, policy);
}

ErrCode DomainAccountManagerService::GetAccountPolicy(const DomainAccountInfo &info, std::string &policy)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_GET_ACCOUNT_POLICY);
    if (result != ERR_OK) {
        return result;
    }
    // check EDM uid
    if (!CheckManageExpiryThresholdWhiteList()) {
        ACCOUNT_LOGE("Permission denied, callingUid=%{public}d.", IPCSkeleton::GetCallingUid());
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return InnerDomainAccountManager::GetInstance().GetAccountPolicy(info, policy);
}

ErrCode DomainAccountManagerService::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const sptr<IDomainAccountCallback> &callback)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_AUTH);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().Auth(info, password, callback);
}

ErrCode DomainAccountManagerService::AuthUser(int32_t userId, const std::vector<uint8_t> &password,
    const sptr<IDomainAccountCallback> &callback)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_AUTH_USER);
    if (result != ERR_OK) {
        return result;
    }
    if (userId < START_USER_ID) {
        ACCOUNT_LOGE("invalid userId");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return InnerDomainAccountManager::GetInstance().AuthUser(userId, password, callback);
}

ErrCode DomainAccountManagerService::CancelAuth(const sptr<IDomainAccountCallback> &callback)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_CANCEL_AUTH);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().CancelAuth(callback);
}

ErrCode DomainAccountManagerService::AuthWithPopup(int32_t userId, const sptr<IDomainAccountCallback> &callback)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_AUTH_WITH_POPUP);
    if (result != ERR_OK) {
        return result;
    }
    if (userId < 0) {
        ACCOUNT_LOGE("invalid userId");
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    return InnerDomainAccountManager::GetInstance().AuthWithPopup(userId, callback);
}

ErrCode DomainAccountManagerService::GetAccountStatus(const DomainAccountInfo &info, int32_t &status)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_GET_ACCOUNT_STATUS);
    if (result != ERR_OK) {
        return result;
    }
    DomainAccountStatus domainAccountStatus;
    auto errcode = InnerDomainAccountManager::GetInstance().GetAccountStatus(info, domainAccountStatus);
    status = static_cast<int32_t>(domainAccountStatus);
    return errcode;
}

ErrCode DomainAccountManagerService::GetDomainAccountInfo(
    const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_GET_DOMAIN_ACCOUNT_INFO);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().GetDomainAccountInfo(info, callback);
}

ErrCode DomainAccountManagerService::UpdateAccountInfo(
    const DomainAccountInfo &oldAccountInfo, const DomainAccountInfo &newAccountInfo)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_UPDATE_ACCOUNT_INFO);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().UpdateAccountInfo(oldAccountInfo, newAccountInfo);
}

ErrCode DomainAccountManagerService::RegisterAccountStatusListener(const sptr<IDomainAccountCallback> &listener)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_REGISTER_ACCOUNT_STATUS_LISTENER);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().RegisterAccountStatusListener(listener);
}

ErrCode DomainAccountManagerService::UnregisterAccountStatusListener(const sptr<IDomainAccountCallback> &listener)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_UNREGISTER_ACCOUNT_STATUS_LISTENER);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().UnregisterAccountStatusListener(listener);
}

ErrCode DomainAccountManagerService::AddServerConfig(const std::string &parameters, DomainServerConfig &config)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_ADD_SERVER_CONFIG);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().AddServerConfig(parameters, config);
}

ErrCode DomainAccountManagerService::RemoveServerConfig(const std::string &configId)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_REMOVE_SERVER_CONFIG);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().RemoveServerConfig(configId);
}

ErrCode DomainAccountManagerService::UpdateServerConfig(const std::string &configId, const std::string &parameters,
    DomainServerConfig &config)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_UPDATE_SERVER_CONFIG);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().UpdateServerConfig(configId, parameters, config);
}

ErrCode DomainAccountManagerService::GetAccountServerConfig(const DomainAccountInfo &info, DomainServerConfig &config)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_GET_ACCOUNT_SERVER_CONFIG);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().GetAccountServerConfig(info, config);
}

ErrCode DomainAccountManagerService::GetServerConfig(const std::string &configId, DomainServerConfig &config)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_GET_SERVER_CONFIG);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().GetServerConfig(configId, config);
}

ErrCode DomainAccountManagerService::GetAllServerConfigs(std::vector<DomainServerConfig> &configs)
{
    auto result = CheckPermission(IDomainAccountIpcCode::COMMAND_GET_ALL_SERVER_CONFIGS);
    if (result != ERR_OK) {
        return result;
    }
    return InnerDomainAccountManager::GetInstance().GetAllServerConfigs(configs);
}

ErrCode DomainAccountManagerService::CheckPermission(IDomainAccountIpcCode code)
{
    if (NON_SYSTEM_API_SET.find(code) == NON_SYSTEM_API_SET.end()) {
        ErrCode errCode = AccountPermissionManager::CheckSystemApp();
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("The caller is not system application, errCode = %{public}d, code = %{public}d.",
                errCode, static_cast<int>(code));
            return errCode;
        }
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid == 0) {
        return ERR_OK;
    }
    const auto& it = PERMISSIONMAP.find(code);
    if (it == PERMISSIONMAP.end()) {
        ACCOUNT_LOGE("No specific permission defined for code %{public}d, returning OK", static_cast<int>(code));
        return ERR_OK;
    }
    const auto& requiredPermissions = it->second;
    if (requiredPermissions.empty()) {
        return ERR_OK;
    }
    bool hasAnyPermission = std::any_of(requiredPermissions.begin(), requiredPermissions.end(),
        [](const std::string& permission) {
            return AccountPermissionManager::VerifyPermission(permission) == ERR_OK;
        });
    if (!hasAnyPermission) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

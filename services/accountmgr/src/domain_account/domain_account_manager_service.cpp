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

#include "account_log_wrapper.h"
#include "inner_domain_account_manager.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
namespace {
constexpr int32_t START_USER_ID = 100;
const std::set<uint32_t> UID_WHITELIST_FOR_SET { 3057 };
}

DomainAccountManagerService::DomainAccountManagerService()
{}

DomainAccountManagerService::~DomainAccountManagerService()
{}

ErrCode DomainAccountManagerService::RegisterPlugin(const sptr<IDomainAccountPlugin> &plugin)
{
    return InnerDomainAccountManager::GetInstance().RegisterPlugin(plugin);
}

ErrCode DomainAccountManagerService::UnregisterPlugin()
{
    InnerDomainAccountManager::GetInstance().UnregisterPlugin();
    return ERR_OK;
}

ErrCode DomainAccountManagerService::HasDomainAccount(
    const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    return InnerDomainAccountManager::GetInstance().HasDomainAccount(info, callback);
}

ErrCode DomainAccountManagerService::GetAccessToken(
    const DomainAccountInfo &info, const AAFwk::WantParams &parameters, const sptr<IDomainAccountCallback> &callback)
{
    return InnerDomainAccountManager::GetInstance().GetAccessToken(info, parameters, callback);
}

ErrCode DomainAccountManagerService::UpdateAccountToken(
    const DomainAccountInfo &info, const std::vector<uint8_t> &token)
{
    return InnerDomainAccountManager::GetInstance().UpdateAccountToken(info, token);
}

static bool CheckManageExpiryThresholdWhiteList()
{
    return UID_WHITELIST_FOR_SET.find(IPCSkeleton::GetCallingUid()) != UID_WHITELIST_FOR_SET.end();
}

ErrCode DomainAccountManagerService::IsAuthenticationExpired(const DomainAccountInfo &info, bool &isExpired)
{
    return InnerDomainAccountManager::GetInstance().IsAuthenticationExpired(info, isExpired);
}

ErrCode DomainAccountManagerService::SetAccountPolicy(const DomainAccountPolicy &policy)
{
    // check EDM uid
    if (!CheckManageExpiryThresholdWhiteList()) {
        ACCOUNT_LOGE("Permission denied, callingUid=%{public}d.", IPCSkeleton::GetCallingUid());
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return InnerDomainAccountManager::GetInstance().SetAccountPolicy(policy);
}

ErrCode DomainAccountManagerService::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const sptr<IDomainAccountCallback> &callback)
{
    return InnerDomainAccountManager::GetInstance().Auth(info, password, callback);
}

ErrCode DomainAccountManagerService::AuthUser(int32_t userId, const std::vector<uint8_t> &password,
    const sptr<IDomainAccountCallback> &callback)
{
    if (userId < START_USER_ID) {
        ACCOUNT_LOGE("invalid userId");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return InnerDomainAccountManager::GetInstance().AuthUser(userId, password, callback);
}

ErrCode DomainAccountManagerService::AuthWithPopup(int32_t userId, const sptr<IDomainAccountCallback> &callback)
{
    if (userId < 0) {
        ACCOUNT_LOGE("invalid userId");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return InnerDomainAccountManager::GetInstance().AuthWithPopup(userId, callback);
}

ErrCode DomainAccountManagerService::GetAccountStatus(const DomainAccountInfo &info, DomainAccountStatus &status)
{
    return InnerDomainAccountManager::GetInstance().GetAccountStatus(info, status);
}

ErrCode DomainAccountManagerService::GetDomainAccountInfo(
    const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    return InnerDomainAccountManager::GetInstance().GetDomainAccountInfo(info, callback);
}

ErrCode DomainAccountManagerService::UpdateAccountInfo(
    const DomainAccountInfo &oldAccountInfo, const DomainAccountInfo &newAccountInfo)
{
    return InnerDomainAccountManager::GetInstance().UpdateAccountInfo(oldAccountInfo, newAccountInfo);
}

ErrCode DomainAccountManagerService::RegisterAccountStatusListener(const sptr<IDomainAccountCallback> &listener)
{
    return InnerDomainAccountManager::GetInstance().RegisterAccountStatusListener(listener);
}

ErrCode DomainAccountManagerService::UnregisterAccountStatusListener(const sptr<IDomainAccountCallback> &listener)
{
    return InnerDomainAccountManager::GetInstance().UnregisterAccountStatusListener(listener);
}

ErrCode DomainAccountManagerService::AddServerConfig(const std::string &parameters, DomainServerConfig &config)
{
    return InnerDomainAccountManager::GetInstance().AddServerConfig(parameters, config);
}

ErrCode DomainAccountManagerService::RemoveServerConfig(const std::string &configId)
{
    return InnerDomainAccountManager::GetInstance().RemoveServerConfig(configId);
}

ErrCode DomainAccountManagerService::GetAccountServerConfig(const DomainAccountInfo &info, DomainServerConfig &config)
{
    return InnerDomainAccountManager::GetInstance().GetAccountServerConfig(info, config);
}
}  // namespace AccountSA
}  // namespace OHOS

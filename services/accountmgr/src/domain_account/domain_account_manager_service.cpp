/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

namespace OHOS {
namespace AccountSA {
namespace {
constexpr int32_t START_USER_ID = 100;
}

DomainAccountManagerService::DomainAccountManagerService()
{}

DomainAccountManagerService::~DomainAccountManagerService()
{}

ErrCode DomainAccountManagerService::RegisterPlugin(const sptr<IDomainAccountPlugin> &plugin)
{
    return InnerDomainAccountManager::GetInstance()->RegisterPlugin(plugin);
}

ErrCode DomainAccountManagerService::UnregisterPlugin()
{
    InnerDomainAccountManager::GetInstance()->UnregisterPlugin();
    return ERR_OK;
}

ErrCode DomainAccountManagerService::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const sptr<IDomainAuthCallback> &callback)
{
    return InnerDomainAccountManager::GetInstance()->Auth(info, password, callback);
}

ErrCode DomainAccountManagerService::AuthUser(int32_t userId, const std::vector<uint8_t> &password,
    const sptr<IDomainAuthCallback> &callback)
{
    if (userId < START_USER_ID) {
        ACCOUNT_LOGE("invalid userId");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    }
    return InnerDomainAccountManager::GetInstance()->AuthUser(userId, password, callback);
}
}  // namespace AccountSA
}  // namespace OHOS

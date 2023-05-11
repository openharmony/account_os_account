/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "mock_account_mgr_service.h"
#include "account_log_wrapper.h"
#include "account_error_no.h"
#include "device_account_info.h"
#include "iaccount.h"

namespace OHOS {
namespace AccountSA {
MockAccountMgrService::MockAccountMgrService()
{
    devAccountId_ = 0;
    IAccountContext::SetInstance(this);
}

MockAccountMgrService::~MockAccountMgrService()
{
    IAccountContext::SetInstance(nullptr);
}

void MockAccountMgrService::HandleNotificationEvents(const std::string &eventStr)
{
    ACCOUNT_LOGI("Get event: %{public}s", eventStr.c_str());
}

std::int32_t MockAccountMgrService::QueryDeviceAccountId(std::int32_t &accountId)
{
    accountId = devAccountId_;
    return ERR_OK;
}

bool MockAccountMgrService::UpdateOhosAccountInfo(
    const std::string &accountName, const std::string &uid, const std::string &eventStr)
{
    ACCOUNT_LOGI("MockUpdateOhosAccountInfo: success done");
    return true;
}

std::pair<bool, OhosAccountInfo> MockAccountMgrService::QueryOhosAccountInfo(void)
{
    std::string name = DEFAULT_OHOS_ACCOUNT_NAME;
    std::string id = DEFAULT_OHOS_ACCOUNT_UID;
    std::int32_t status = ACCOUNT_STATE_UNBOUND;
    return std::make_pair(true, OhosAccountInfo(name, id, status));
}

std::pair<bool, OhosAccountInfo> MockAccountMgrService::QueryOhosAccountInfoByUserId(std::int32_t userId)
{
    std::string name = DEFAULT_OHOS_ACCOUNT_NAME;
    std::string id = DEFAULT_OHOS_ACCOUNT_UID;
    std::int32_t status = ACCOUNT_STATE_UNBOUND;
    return std::make_pair(true, OhosAccountInfo(name, id, status));
}

sptr<IRemoteObject> MockAccountMgrService::GetAppAccountService()
{
    ACCOUNT_LOGI("enter");

    return nullptr;
}

sptr<IRemoteObject> MockAccountMgrService::GetOsAccountService()
{
    ACCOUNT_LOGI("enter");

    return nullptr;
}

sptr<IRemoteObject> MockAccountMgrService::GetDomainAccountService()
{
    ACCOUNT_LOGI("enter");

    return nullptr;
}
}  // namespace AccountSA
}  // namespace OHOS

/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

ErrCode MockAccountMgrService::QueryDeviceAccountId(std::int32_t &accountId)
{
    accountId = devAccountId_;
    return ERR_OK;
}

ErrCode MockAccountMgrService::UpdateOhosAccountInfo(
    const std::string &accountName, const std::string &uid, const std::string &eventStr)
{
    ACCOUNT_LOGI("MockUpdateOhosAccountInfo: success done");
    return ERR_OK;
}

ErrCode MockAccountMgrService::QueryOhosAccountInfo(std::string& accountName, std::string& uid, int32_t& status)
{
    accountName = DEFAULT_OHOS_ACCOUNT_NAME;
    uid = DEFAULT_OHOS_ACCOUNT_UID;
    status = ACCOUNT_STATE_UNBOUND;
    return ERR_OK;
}

ErrCode MockAccountMgrService::QueryOsAccountDistributedInfo(
    std::int32_t localId, std::string& accountName, std::string& uid, int32_t& status)
{
    accountName = DEFAULT_OHOS_ACCOUNT_NAME;
    uid = DEFAULT_OHOS_ACCOUNT_UID;
    status = ACCOUNT_STATE_UNBOUND;
    return ERR_OK;
}

ErrCode MockAccountMgrService::SubscribeDistributedAccountEvent(
    const int32_t typeInt, const sptr<IRemoteObject>& eventListener)
{
    return ERR_OK;
}

ErrCode MockAccountMgrService::UnsubscribeDistributedAccountEvent(
    const int32_t typeInt, const sptr<IRemoteObject>& eventListener)
{
    return ERR_OK;
}

ErrCode MockAccountMgrService::GetAppAccountService(sptr<IRemoteObject>& funcResult)
{
    ACCOUNT_LOGI("enter");
    funcResult = nullptr;
    return 0;
}

ErrCode MockAccountMgrService::GetOsAccountService(sptr<IRemoteObject>& funcResult)
{
    ACCOUNT_LOGI("enter");
    funcResult = nullptr;
    return 0;
}

ErrCode MockAccountMgrService::GetDomainAccountService(sptr<IRemoteObject>& funcResult)
{
    ACCOUNT_LOGI("enter");
    funcResult = nullptr;
    return 0;
}
}  // namespace AccountSA
}  // namespace OHOS

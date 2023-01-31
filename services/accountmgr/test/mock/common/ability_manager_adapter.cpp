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
#include "ability_manager_adapter.h"

#include "account_log_wrapper.h"
#include "mock_app_account_authenticator_stub.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string STRING_BUNDLE = "com.example.name";
} // namespace
using namespace AAFwk;
std::shared_ptr<AbilityManagerAdapter> AbilityManagerAdapter::instance_ = nullptr;
std::mutex AbilityManagerAdapter::mockInstanceMutex_;

std::shared_ptr<AbilityManagerAdapter> AbilityManagerAdapter::GetInstance()
{
    std::lock_guard<std::mutex> lock(mockInstanceMutex_);
    if (instance_ == nullptr) {
        instance_ = std::make_shared<AbilityManagerAdapter>();
    }
    return instance_;
}

AbilityManagerAdapter::AbilityManagerAdapter()
{}

AbilityManagerAdapter::~AbilityManagerAdapter()
{}

ErrCode AbilityManagerAdapter::ConnectAbility(const AAFwk::Want &want, const sptr<AAFwk::IAbilityConnection> &connect,
    const sptr<IRemoteObject> &callerToken, int32_t userId)
{
    if (want.GetBundle() == STRING_BUNDLE) {
        sptr<AccountSA::MockAppAccountAuthenticator> mockServicePtr_ =
            new (std::nothrow) AccountSA::MockAppAccountAuthenticator();
        int resultCode = ERR_OK;
        AppExecFwk::ElementName element = want.GetElement();
        connect->OnAbilityConnectDone(element, mockServicePtr_, resultCode);
    } else {
        int resultCode = ERR_OK;
        AppExecFwk::ElementName element = want.GetElement();
        connect->OnAbilityConnectDone(element, nullptr, resultCode);
    }
    return ERR_OK;
}

ErrCode AbilityManagerAdapter::DisconnectAbility(const sptr<AAFwk::IAbilityConnection> &connect)
{
    return ERR_OK;
}

ErrCode AbilityManagerAdapter::StartUser(int accountId)
{
    return ERR_OK;
}

ErrCode AbilityManagerAdapter::StopUser(int accountId, const sptr<AAFwk::IStopUserCallback> &callback)
{
    return ERR_OK;
}
} // namespace AccountSA
} // namespace OHOS
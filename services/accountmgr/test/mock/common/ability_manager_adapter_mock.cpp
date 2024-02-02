/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include "ability_manager_adapter_mock.h"

#include "account_log_wrapper.h"
#include "string_wrapper.h"

namespace OHOS {
namespace AccountSA {
using namespace AAFwk;

AbilityManagerAdapter *AbilityManagerAdapter::GetInstance()
{
    static AbilityManagerAdapter *instance = new (std::nothrow) AbilityManagerAdapter();
    return instance;
}

AbilityManagerAdapter::AbilityManagerAdapter()
{}

AbilityManagerAdapter::~AbilityManagerAdapter()
{}

ErrCode AbilityManagerAdapter::ConnectAbility(const AAFwk::Want &want, const sptr<AAFwk::IAbilityConnection> &connect,
    const sptr<IRemoteObject> &callerToken, int32_t userId)
{
    return ERR_OK;
}

ErrCode AbilityManagerAdapter::DisconnectAbility(const sptr<AAFwk::IAbilityConnection> &connect)
{
    return ERR_OK;
}

ErrCode AbilityManagerAdapter::StartUser(int accountId, const sptr<AAFwk::IUserCallback> &callback)
{
    auto task = std::bind(&IUserCallback::OnStartUserDone, callback, accountId, 0);
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), "StartUser");
    taskThread.detach();
    return ERR_OK;
}

ErrCode AbilityManagerAdapter::StopUser(int accountId, const sptr<AAFwk::IUserCallback> &callback)
{
    auto task = std::bind(&AAFwk::IUserCallback::OnStopUserDone, callback, accountId, 0);
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), "StopUser");
    taskThread.detach();
    return ERR_OK;
}

ErrCode AbilityManagerAdapter::LogoutUser(int accountId)
{
    return ERR_OK;
}
} // namespace AccountSA
} // namespace OHOS
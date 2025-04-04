/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "os_account_user_callback.h"
#include <chrono>
#include <thread>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_manager.h"
#include "os_account_interface.h"

namespace OHOS {
namespace AccountSA {
OsAccountUserCallback::OsAccountUserCallback()
{}

OsAccountUserCallback::OsAccountUserCallback(const OsAccountStartCallbackFunc &callbackFunc)
    :startUserCallbackFunc_(callbackFunc)
{}

int OsAccountUserCallback::OnStopUserDoneInner(MessageParcel &data, MessageParcel &reply)
{
    auto accountId = data.ReadInt32();
    auto errCode = data.ReadInt32();
    OnStopUserDone(accountId, errCode);
    return ERR_OK;
}

int OsAccountUserCallback::OnStartUserDoneInner(MessageParcel &data, MessageParcel &reply)
{
    auto accountId = data.ReadInt32();
    auto errCode = data.ReadInt32();
    OnStartUserDone(accountId, errCode);
    return ERR_OK;
}

int OsAccountUserCallback::OnLogoutUserDoneInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t accountId;
    if (!data.ReadInt32(accountId)) {
        ACCOUNT_LOGE("Read accountId from reply failed.");
        OnLogoutUserDone(-1, ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    int32_t errCode;
    if (!data.ReadInt32(errCode)) {
        ACCOUNT_LOGE("Read errCode from reply failed.");
        OnLogoutUserDone(accountId, ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    OnLogoutUserDone(accountId, errCode);
    return ERR_OK;
}

int OsAccountUserCallback::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::u16string descriptor = OsAccountUserCallback::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        ACCOUNT_LOGI("Local descriptor is not equal to remote");
        return ERR_INVALID_STATE;
    }

    switch (code) {
        case UserCallbackCmd::ON_STOP_USER_DONE:
            return OnStopUserDoneInner(data, reply);
        case UserCallbackCmd::ON_START_USER_DONE:
            return OnStartUserDoneInner(data, reply);
        case UserCallbackCmd::ON_LOGOUT_USER_DONE:
            return OnLogoutUserDoneInner(data, reply);
        default:
            break;
    }

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

void OsAccountUserCallback::OnStopUserDone(int userId, int errcode)
{
    std::unique_lock<std::mutex> lock(mutex_);
    ACCOUNT_LOGI("In call back account, OnStopUserDone id is %{public}d, errcode is %{public}d.",
        userId, errcode);
    isCalled_ = true;
    resultCode_ = errcode;
    onStopCondition_.notify_one();
}

void OsAccountUserCallback::OnStartUserDone(int userId, int errcode)
{
    std::unique_lock<std::mutex> lock(mutex_);
    ACCOUNT_LOGI("In call back account, OnStartUserDone id is %{public}d, errcode is %{public}d.",
        userId, errcode);
    if (errcode == ERR_OK && startUserCallbackFunc_ != nullptr) {
        startUserCallbackFunc_(userId);
    }
    isCalled_ = true;
    resultCode_ = errcode;
    onStartCondition_.notify_one();
}

void OsAccountUserCallback::OnLogoutUserDone(int userId, int errcode)
{
    std::unique_lock<std::mutex> lock(mutex_);
    ACCOUNT_LOGI("In call back account, OnLogoutUserDone id is %{public}d, errcode is %{public}d.",
        userId, errcode);
    isCalled_ = true;
    resultCode_ = errcode;
    onLogoutCondition_.notify_one();
}
}  // namespace AccountSA
}  // namespace OHOS

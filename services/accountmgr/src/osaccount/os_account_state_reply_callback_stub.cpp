/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "os_account_state_reply_callback_stub.h"
#include "accountmgr_service_ipc_interface_code.h"
#include "account_hisysevent_adapter.h"
#include "account_log_wrapper.h"
#include "ipc_skeleton.h"
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {
namespace {
constexpr int64_t TIMEOUT_THRESHOLD = 5000000; // 5s
}

OsAccountStateReplyCallbackStub::OsAccountStateReplyCallbackStub(int32_t accountId, OsAccountState state,
    const std::shared_ptr<std::condition_variable> &cvPtr, const std::shared_ptr<SafeQueue<uint8_t>> &safeQueue,
    uid_t subscriberUid)
    : accountId_(accountId), state_(state), cvPtr_(cvPtr), safeQueue_(safeQueue), subscriberUid_(subscriberUid)
{}

static const char *ConvertStateToSceneFlag(OsAccountState state)
{
    switch (state) {
        case OsAccountState::STOPPING:
        case OsAccountState::STOPPED:
            return Constants::OPERATION_STOP;
        case OsAccountState::ACTIVATED:
        case OsAccountState::ACTIVATING:
            return Constants::OPERATION_ACTIVATE;
        case OsAccountState::CREATED:
            return Constants::OPERATION_CREATE;
        case OsAccountState::REMOVED:
            return Constants::OPERATION_REMOVE;
        case OsAccountState::SWITCHING:
        case OsAccountState::SWITCHED:
            return Constants::OPERATION_SWITCH;
        case OsAccountState::UNLOCKED:
            return Constants::OPERATION_UNLOCK;
        default:
            return "";
    }
}

void OsAccountStateReplyCallbackStub::OnComplete()
{
    std::lock_guard lock(mutex_);
    int64_t duration = 0;
    if (startTime_.time_since_epoch().count() != 0) {
        duration = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now() - startTime_).count();
    }
    if (isCompleted_) {
        ACCOUNT_LOGE("Already completed, callingUid: %{public}d", subscriberUid_);
        return;
    }
    int32_t callerUid = IPCSkeleton::GetCallingUid();
    if (callerUid != subscriberUid_) {
        ACCOUNT_LOGE("Permission denied");
        ReportOsAccountOperationFail(accountId_, ConvertStateToSceneFlag(state_), ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
            "Failed to check permission, callerUid=" + std::to_string(callerUid) + ", subscriberUid="
            + std::to_string(subscriberUid_) + ", state=" + std::to_string(state_));
        return;
    }
    isCompleted_ = true;
    if (duration > TIMEOUT_THRESHOLD) {
        ACCOUNT_LOGE("Timeout, callingUid: %{public}d, duration: %{public}lld us",
            subscriberUid_, static_cast<long long>(duration));
        ReportOsAccountOperationFail(accountId_, ConvertStateToSceneFlag(state_), ERR_ACCOUNT_COMMON_OPERATION_TIMEOUT,
            "OnComplete timed out, duration=" + std::to_string(duration) + "us, uid=" + std::to_string(subscriberUid_)
            + ", state=" + std::to_string(state_));
    }
    ACCOUNT_LOGI("Done, subscriberUid: %{public}d, state: %{public}d", subscriberUid_, state_);
    if (cvPtr_ == nullptr || safeQueue_ == nullptr) {
        ACCOUNT_LOGE("CvPtr or SafeQueue is nullptr");
        return;
    }
    uint8_t tmp;
    safeQueue_->Pop(tmp);
    cvPtr_->notify_one();
}

void OsAccountStateReplyCallbackStub::SetStartTime(const std::chrono::system_clock::time_point &startTime)
{
    std::lock_guard lock(mutex_);
    startTime_ = startTime;
}

int32_t OsAccountStateReplyCallbackStub::GetSubscriberUid() const
{
    return subscriberUid_;
}

int OsAccountStateReplyCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("Failed to check descriptor, code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    switch (code) {
        case static_cast<uint32_t>(StateReplyCallbackInterfaceCode::ON_COMPLETE): {
            OnComplete();
            break;
        }
        default:
            ACCOUNT_LOGI("Default, code = %{public}u, flags = %{public}u", code, option.GetFlags());
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

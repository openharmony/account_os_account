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

#ifndef OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_STATE_REPLY_CALLBACK_STUB_H
#define OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_STATE_REPLY_CALLBACK_STUB_H

#include "ios_account_state_reply_callback.h"
#include "iremote_stub.h"
#include "os_account_subscribe_info.h"
#include "safe_queue.h"

namespace OHOS {
namespace AccountSA {
class OsAccountStateReplyCallbackStub : public IRemoteStub<IOsAccountStateReplyCallback> {
public:
    OsAccountStateReplyCallbackStub(int32_t accountId, OsAccountState state,
        const std::shared_ptr<std::condition_variable> &cvPtr, const std::shared_ptr<SafeQueue<uint8_t>> &safeQueue,
        uid_t subscriberUid);
    ~OsAccountStateReplyCallbackStub() override = default;

    void OnComplete() override;
    void SetStartTime(const std::chrono::system_clock::time_point &startTime);
    uid_t GetSubscriberUid() const;
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int32_t accountId_;
    OsAccountState state_;
    std::shared_ptr<std::condition_variable> cvPtr_;
    std::shared_ptr<SafeQueue<uint8_t>> safeQueue_;
    uid_t subscriberUid_;
    std::mutex mutex_;
    bool isCompleted_ = false;
    std::chrono::system_clock::time_point startTime_;
    DISALLOW_COPY_AND_MOVE(OsAccountStateReplyCallbackStub);
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_STATE_REPLY_CALLBACK_STUB_H

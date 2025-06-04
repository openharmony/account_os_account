/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_STATE_REPLY_CALLBACK_SERVICE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_STATE_REPLY_CALLBACK_SERVICE_H

#include "os_account_state_reply_callback_stub.h"

#include "ios_account_state_reply_callback.h"
#include "os_account_subscribe_info.h"
#include "safe_queue.h"

namespace OHOS {
namespace AccountSA {
class OsAccountStateReplyCallbackService : public OsAccountStateReplyCallbackStub {
public:
    OsAccountStateReplyCallbackService(int32_t accountId, OsAccountState state,
        const std::shared_ptr<std::condition_variable> &cvPtr, const std::shared_ptr<SafeQueue<uint8_t>> &safeQueue,
        int32_t subscriberUid);
    ~OsAccountStateReplyCallbackService() override;
    ErrCode OnComplete() override;
    void SetStartTime(const std::chrono::system_clock::time_point &startTime);
    int32_t GetSubscriberUid() const;

private:
    int32_t accountId_;
    OsAccountState state_;
    std::shared_ptr<std::condition_variable> cvPtr_;
    std::shared_ptr<SafeQueue<uint8_t>> safeQueue_;
    int32_t subscriberUid_;
    std::mutex mutex_;
    bool isCompleted_ = false;
    std::chrono::system_clock::time_point startTime_;
    DISALLOW_COPY_AND_MOVE(OsAccountStateReplyCallbackService);
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_STATE_REPLY_CALLBACK_SERVICE_H
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_EVENT_SUBSCRIBE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_EVENT_SUBSCRIBE_H

#include "account_error_no.h"
#include "account_info.h"
#ifdef HAS_CES_PART
#include "common_event_data.h"
#include "common_event_subscriber.h"
#include "common_event_subscribe_info.h"
#endif // HAS_CES_PART

namespace OHOS {
namespace AccountSA {
#ifdef HAS_CES_PART
struct AccountCommonEventCallback {
    std::function<void(const std::int32_t callingUid)> OnPackageRemoved;
};

class AccountEventSubscriberCallback final : public EventFwk::CommonEventSubscriber {
public:
    explicit AccountEventSubscriberCallback(
        const EventFwk::CommonEventSubscribeInfo &subscribeInfo, const AccountCommonEventCallback &callback);
    ~AccountEventSubscriberCallback() = default;

    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;

private:
    AccountCommonEventCallback callback_;
};
class AccountEventSubscriber {
public:
    explicit AccountEventSubscriber(const AccountCommonEventCallback &callback);
    bool CreateEventSubscribe();
    bool DestroyEventSubscribe();

private:
    AccountCommonEventCallback callback_;
    std::shared_ptr<AccountEventSubscriberCallback> subscriber_ = nullptr;
};
#endif // HAS_CES_PART
} // namespace AccountSA
} // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_EVENT_SUBSCRIBE_H
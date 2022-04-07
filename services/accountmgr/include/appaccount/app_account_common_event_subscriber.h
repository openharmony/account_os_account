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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_COMMON_EVENT_SUBSCRIBER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_COMMON_EVENT_SUBSCRIBER_H

#ifdef HAS_CES_PART
#include "common_event_subscriber.h"
#endif // HAS_CES_PART

namespace OHOS {
namespace AccountSA {
#ifdef HAS_CES_PART
using CommonEventSubscriber = OHOS::EventFwk::CommonEventSubscriber;
using CommonEventData = OHOS::EventFwk::CommonEventData;
using CommonEventSubscribeInfo = OHOS::EventFwk::CommonEventSubscribeInfo;

class AppAccountCommonEventSubscriber : public CommonEventSubscriber {
public:
    explicit AppAccountCommonEventSubscriber(
        const CommonEventSubscribeInfo &subscribeInfo, const std::function<void(const CommonEventData &)> &callback);
    ~AppAccountCommonEventSubscriber() = default;

    void OnReceiveEvent(const CommonEventData &data) override;

private:
    std::function<void(const EventFwk::CommonEventData &)> callback_;
};
#endif // HAS_CES_PART
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_COMMON_EVENT_SUBSCRIBER_H

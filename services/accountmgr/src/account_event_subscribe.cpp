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

#include "account_event_subscribe.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "bundle_constants.h"
#ifdef HAS_CES_PART
#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "common_event_subscribe_info.h"
#include "matching_skills.h"
#endif // HAS_CES_PART

namespace OHOS {
namespace AccountSA {
#ifdef HAS_CES_PART
AccountEventSubscriberCallback::AccountEventSubscriberCallback(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo, const AccountCommonEventCallback &callback)
    : CommonEventSubscriber(subscribeInfo), callback_(callback)
{}

void AccountEventSubscriberCallback::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    auto want = data.GetWant();
    std::string action = want.GetAction();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        auto uid = want.GetIntParam(AppExecFwk::Constants::UID, -1);
        callback_.OnPackageRemoved(uid);
    }
}

AccountEventSubscriber::AccountEventSubscriber(const AccountCommonEventCallback &callback) : callback_(callback)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscriber_ = std::make_shared<AccountEventSubscriberCallback>(subscribeInfo, callback_);
}

bool AccountEventSubscriber::CreateEventSubscribe()
{
    return EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
}

bool AccountEventSubscriber::DestroyEventSubscribe()
{
    return EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_);
}
#endif // HAS_CES_PART
} // namespace AccountSA
} // namespace OHOS
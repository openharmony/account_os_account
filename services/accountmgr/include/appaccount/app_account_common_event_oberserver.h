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

#ifndef OS_ACCOUNT_FRAMEWORKS_APPACCOUNT_CORE_INCLUDE_APP_ACCOUNT_COMMON_EVENT_OBERSERVER_H
#define OS_ACCOUNT_FRAMEWORKS_APPACCOUNT_CORE_INCLUDE_APP_ACCOUNT_COMMON_EVENT_OBERSERVER_H

#include "account_error_no.h"
#include "app_account_common_event_subscriber.h"
#include "event_handler.h"

namespace OHOS {
namespace AccountSA {
struct CommonEventCallback {
    std::function<void(const CommonEventData &data)> OnPackageRemoved;
};

class AppAccountCommonEventOberserver {
public:
    using EventHandler = OHOS::AppExecFwk::EventHandler;
    using EventRunner = OHOS::AppExecFwk::EventRunner;
    using Callback = OHOS::AppExecFwk::InnerEvent::Callback;

    explicit AppAccountCommonEventOberserver(const CommonEventCallback &callback);
    ~AppAccountCommonEventOberserver();

private:
    ErrCode GetEventHandler(void);
    void SubscribeCommonEvent(void);
    void OnReceiveEvent(const CommonEventData &data);

private:
    std::shared_ptr<EventHandler> handler_;
    std::shared_ptr<AppAccountCommonEventSubscriber> subscriber_;
    CommonEventCallback callback_;
    unsigned int counter_;

    const unsigned int DELAY_FOR_COMMON_EVENT_SERVICE = 5 * 1000;  // 5s
    const unsigned int DELAY_FOR_TIME_INTERVAL = 1 * 1000;         // 1s
    const unsigned int MAX_TRY_TIMES = 10;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_APPACCOUNT_CORE_INCLUDE_APP_ACCOUNT_COMMON_EVENT_OBERSERVER_H

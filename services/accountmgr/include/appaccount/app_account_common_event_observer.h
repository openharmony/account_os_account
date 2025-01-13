/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_COMMON_EVENT_OBERSERVER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_COMMON_EVENT_OBERSERVER_H

#include "account_error_no.h"
#include "app_account_common_event_subscriber.h"

namespace OHOS {
namespace AccountSA {
#ifdef HAS_CES_PART
class AppAccountCommonEventObserver {
public:
    static AppAccountCommonEventObserver &GetInstance();

    void SubscribeOsAccountEvent(void);
    void SubscribeCommonEvent(void);
private:
    AppAccountCommonEventObserver();
    ~AppAccountCommonEventObserver();
    DISALLOW_COPY_AND_MOVE(AppAccountCommonEventObserver);
    void OnReceiveEvent(const CommonEventData &data);
    void DealWithRemoveEvent(const AAFwk::Want &want, const std::string action);

private:
    std::shared_ptr<AppAccountCommonEventSubscriber> subscriber_ = nullptr;
    std::int32_t counter_;
    sptr<IRemoteObject> subscriberOsAccountPtr_;
};
#endif // HAS_CES_PART
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_COMMON_EVENT_OBERSERVER_H

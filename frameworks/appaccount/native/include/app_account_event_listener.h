/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_EVENT_LISTENER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_EVENT_LISTENER_H

#include "app_account_event_stub.h"
#include "app_account_subscriber.h"

namespace OHOS {
namespace AccountSA {
class AppAccountEventListener : public AppAccountEventStub {
public:
    ErrCode OnAccountsChanged(const std::vector<AppAccountInfo> &accounts, const std::string &owner) override;

    static AppAccountEventListener *GetInstance();
    ErrCode SubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber, bool &needNotifyService);
    ErrCode UnsubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber, bool &needNotifyService,
        std::vector<std::string> &deleteOwners);
    bool GetRestoreData(AppAccountSubscribeInfo &subscribeInfo);

private:
    AppAccountEventListener();
    ~AppAccountEventListener() override;

private:
    std::mutex appAccountsMutex_;
    std::vector<std::shared_ptr<AppAccountSubscriber>> appAccountSubscriberList_;
    std::map<std::string, std::vector<std::shared_ptr<AppAccountSubscriber>>> owner2Subscribers_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_EVENT_LISTENER_H

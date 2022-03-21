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

#ifndef OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_EVENT_LISTENER_H
#define OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_EVENT_LISTENER_H

#include "os_account_event_stub.h"
#include "os_account_subscriber.h"

namespace OHOS {
namespace AccountSA {
class OsAccountEventListener : public OsAccountEventStub {
public:
    explicit OsAccountEventListener(const std::shared_ptr<OsAccountSubscriber> &subscriber);
    ~OsAccountEventListener() override;

    void OnAccountsChanged(const int &id) override;

    void Stop();

private:
    std::shared_ptr<OsAccountSubscriber> osAccountSubscriber_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_EVENT_LISTENER_H

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

#include "account_log_wrapper.h"
#include "os_account_event_listener.h"

namespace OHOS {
namespace AccountSA {
OsAccountEventListener::OsAccountEventListener(const std::shared_ptr<OsAccountSubscriber> &subscriber)
    : osAccountSubscriber_(subscriber)
{}

OsAccountEventListener::~OsAccountEventListener()
{}

void OsAccountEventListener::OnAccountsChanged(const int &id)
{
    if (osAccountSubscriber_ == nullptr) {
        ACCOUNT_LOGI("osAccountSubscriber_ is nullptr");
        return;
    }

    osAccountSubscriber_->OnAccountsChanged(id);
}

void OsAccountEventListener::Stop()
{}
}  // namespace AccountSA
}  // namespace OHOS

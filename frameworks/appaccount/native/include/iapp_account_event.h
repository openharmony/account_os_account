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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_IAPP_ACCOUNT_EVENT_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_IAPP_ACCOUNT_EVENT_H

#include "app_account_info.h"
#include "iremote_broker.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
class IAppAccountEvent : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IAppAccountEvent");

    virtual void OnAccountsChanged(const std::vector<AppAccountInfo> &accounts) = 0;

    enum class Message {
        ACCOUNT_CHANGED = 0,
    };
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_IAPP_ACCOUNT_EVENT_H

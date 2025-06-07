/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_OSACCOUNT_NATIVE_INCLUDE_OS_ACCOUNT_SUBSCRIBER_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_OSACCOUNT_NATIVE_INCLUDE_OS_ACCOUNT_SUBSCRIBER_H

#include "os_account_info.h"
#include "os_account_state_reply_callback.h"
#include "os_account_subscribe_info.h"

namespace OHOS {
namespace AccountSA {
struct OsAccountStateData {
    OsAccountState state = OsAccountState::INVALID_TYPE;
    int32_t fromId = -1;
    int32_t toId = -1;
    std::shared_ptr<OsAccountStateReplyCallback> callback = nullptr;
};

class OsAccountSubscriber {
public:
    OsAccountSubscriber();
    OsAccountSubscriber(const OsAccountSubscribeInfo &subscribeInfo);
    virtual ~OsAccountSubscriber();

    /**
     * Notify the account state changed.
     *
     * @since 16
     */
    virtual void OnStateChanged(const OsAccountStateData &data) {};

    /**
     * Notify the account changed.
     *
     * @deprecated since 16
     * @useinstead OnStateChanged
     * @since 7
     */
    virtual void OnAccountsChanged(const int &id) {};

    /**
     * Notify the account swtiching or switched.
     *
     * @deprecated since 16
     * @useinstead OnStateChanged
     * @since 12
     */
    virtual void OnAccountsSwitch(const int &newId, const int &oldId) {};

    void GetSubscribeInfo(OsAccountSubscribeInfo &subscribeInfo) const;

private:
    OsAccountSubscribeInfo subscribeInfo_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OSACCOUNT_NATIVE_INCLUDE_OS_ACCOUNT_SUBSCRIBER_H

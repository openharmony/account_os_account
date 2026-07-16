/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_OHOSACCOUNT_NATIVE_INCLUDE_DISTRIBUTED_ACCOUNT_SUBSCRIBE_CALLBACK_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_OHOSACCOUNT_NATIVE_INCLUDE_DISTRIBUTED_ACCOUNT_SUBSCRIBE_CALLBACK_H

#include "account_error_no.h"
#include "parcel.h"

namespace OHOS {
namespace AccountSA {

enum class DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE : int32_t {
    LOGIN = 0,
    LOGOUT,
    LOGOFF,
    TOKEN_INVALID,
    BOUND,
    UNBOUND,
    INVALID_TYPE,
};

class DistributedAccountEventData : public Parcelable {
public:
    int32_t id_;
    DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type_;
    int32_t subspaceId_ = -1;

    bool Marshalling(Parcel &parcel) const override;
    static DistributedAccountEventData *Unmarshalling(Parcel &parcel);
    bool operator==(const DistributedAccountEventData &eventData) const;

private:
    bool ReadFromParcel(Parcel &parcel);
};

/**
 * @brief Base class for distributed account subscription callback.
 *
 * Usage:
 * - If subscribed to original distributed account events (LOGIN/LOGOUT/LOGOFF/TOKEN_INVALID),
 *   must implement OnAccountsChanged
 *
 * Warning: Failing to implement the corresponding callback method will result in
 * not receiving event notifications after successful subscription. Please ensure
 * to implement the appropriate methods based on subscription type.
 */
class DistributedAccountSubscribeCallback {
public:
    /**
     * @brief Callback for original distributed account events.
     * @param eventData Event data containing event type (LOGIN/LOGOUT/LOGOFF/TOKEN_INVALID) and OS account ID.
     * @warning Must implement this method if subscribed via SubscribeDistributedAccountEvent.
     */
    virtual void OnAccountsChanged(const DistributedAccountEventData &eventData) {};
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OHOSACCOUNT_NATIVE_INCLUDE_DISTRIBUTED_ACCOUNT_SUBSCRIBE_CALLBACK_H

/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
};

class DistributedAccountEventData : public Parcelable {
public:
    int32_t id_;
    DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type_;

    bool Marshalling(Parcel &parcel) const override;
    static DistributedAccountEventData *Unmarshalling(Parcel &parcel);
    bool operator==(const DistributedAccountEventData &eventData) const;

private:
    bool ReadFromParcel(Parcel &parcel);
};

class DistributedAccountSubscribeCallback {
public:
    virtual void OnAccountsChanged(const DistributedAccountEventData &eventData) = 0;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OHOSACCOUNT_NATIVE_INCLUDE_DISTRIBUTED_ACCOUNT_SUBSCRIBE_CALLBACK_H

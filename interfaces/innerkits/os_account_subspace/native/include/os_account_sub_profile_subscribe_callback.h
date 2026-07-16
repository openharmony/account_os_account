/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_SUBSPACE_INCLUDE_OS_ACCOUNT_SUB_PROFILE_SUBSCRIBE_CALLBACK_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_SUBSPACE_INCLUDE_OS_ACCOUNT_SUB_PROFILE_SUBSCRIBE_CALLBACK_H

#include "account_error_no.h"
#include "parcel.h"

namespace OHOS {
namespace AccountSA {

enum class OsAccountSubProfileEventType : int32_t {
    CREATED = 0,
    DELETED = 1,
    SWITCHING = 2,
    SWITCHED = 3,
    INVALID_TYPE = 4,
};

bool IsValidOsAccountSubProfileEventType(int32_t value);

class SubProfileEventData : public Parcelable {
public:
    ~SubProfileEventData() override;
    OsAccountSubProfileEventType type_ = OsAccountSubProfileEventType::INVALID_TYPE;
    int32_t osAccountId_ = -1;
    int32_t subProfileId_ = -1;
    int32_t previousSubProfileId_ = -1;

    bool Marshalling(Parcel &parcel) const override;

    static SubProfileEventData *Unmarshalling(Parcel &parcel);

    bool operator==(const SubProfileEventData &eventData) const;

private:
    bool ReadFromParcel(Parcel &parcel);
};

class OsAccountSubProfileSubscribeCallback {
public:
    virtual ~OsAccountSubProfileSubscribeCallback() = default;

    virtual void OnSubProfileChanged(const SubProfileEventData &eventData) = 0;
};

}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_SUBSPACE_INCLUDE_OS_ACCOUNT_SUB_PROFILE_SUBSCRIBE_CALLBACK_H

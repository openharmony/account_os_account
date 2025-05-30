/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_PARCEL_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_PARCEL_H

#include "parcel.h"

namespace OHOS {
namespace AccountSA {
class DomainAccountParcel : public Parcelable {
public:
    DomainAccountParcel() = default;

    void GetParcelData(Parcel &parcel) const
    {
        parcel.ParseFrom(parcelData_.GetData(), parcelData_.GetDataSize());
    }

    void SetParcelData(const Parcel &parcel)
    {
        parcelData_.ParseFrom(parcel.GetData(), parcel.GetDataSize());
    }

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static DomainAccountParcel *Unmarshalling(Parcel &parcel);

private:
    Parcel parcelData_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_PARCEL_H
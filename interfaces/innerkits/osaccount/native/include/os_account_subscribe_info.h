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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_OSACCOUNT_NATIVE_INCLUDE_OS_ACCOUNT_SUBSCRIBE_INFO_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_OSACCOUNT_NATIVE_INCLUDE_OS_ACCOUNT_SUBSCRIBE_INFO_H

#include "account_error_no.h"
#include "parcel.h"

namespace OHOS {
namespace AccountSA {
typedef enum {
    ACTIVED = 0,
    ACTIVATING,
} OS_ACCOUNT_SUBSCRIBE_TYPE;
class OsAccountSubscribeInfo : public Parcelable {
public:
    OsAccountSubscribeInfo();
    explicit OsAccountSubscribeInfo(const OS_ACCOUNT_SUBSCRIBE_TYPE &osAccountSubscribeType, const std::string &name);
    virtual ~OsAccountSubscribeInfo();

    void GetOsAccountSubscribeType(OS_ACCOUNT_SUBSCRIBE_TYPE &osAccountSubscribeType) const;
    void SetOsAccountSubscribeType(const OS_ACCOUNT_SUBSCRIBE_TYPE &osAccountSubscribeType);
    void GetName(std::string &name) const;
    void SetName(const std::string &name);

    bool Marshalling(Parcel &parcel) const override;
    static OsAccountSubscribeInfo *Unmarshalling(Parcel &parcel);

private:
    bool ReadFromParcel(Parcel &parcel);

private:
    OS_ACCOUNT_SUBSCRIBE_TYPE osAccountSubscribeType_;
    std::string name_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OSACCOUNT_NATIVE_INCLUDE_OS_ACCOUNT_SUBSCRIBE_INFO_H

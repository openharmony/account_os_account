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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_SUBSCRIBE_INFO_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_SUBSCRIBE_INFO_H

#include "account_error_no.h"
#include "parcel.h"

namespace OHOS {
namespace AccountSA {
class AppAccountSubscribeInfo : public Parcelable {
public:
    AppAccountSubscribeInfo();
    explicit AppAccountSubscribeInfo(std::vector<std::string> &owners);
    virtual ~AppAccountSubscribeInfo() = default;

    ErrCode GetOwners(std::vector<std::string> &owners) const;
    ErrCode SetOwners(const std::vector<std::string> &owners);

    bool Marshalling(Parcel &parcel) const override;
    static AppAccountSubscribeInfo *Unmarshalling(Parcel &parcel);

private:
    bool ReadFromParcel(Parcel &parcel);

private:
    std::vector<std::string> owners_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_SUBSCRIBE_INFO_H

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

#ifndef OS_ACCOUNT_FRAMEWORKS_OS_ACCOUNT_INCLUDE_OS_ACCOUNT_STATE_PARCEL_H
#define OS_ACCOUNT_FRAMEWORKS_OS_ACCOUNT_INCLUDE_OS_ACCOUNT_STATE_PARCEL_H

#include <optional>
#include "iremote_object.h"
#include "os_account_subscribe_info.h"
#include "parcel.h"

namespace OHOS {
namespace AccountSA {
struct OsAccountStateParcel : public Parcelable {
    OsAccountState state = OsAccountState::INVALID_TYPE;
    int32_t fromId = -1;
    int32_t toId = -1;
    std::optional<uint64_t> displayId = std::nullopt;
    sptr<IRemoteObject> callback = nullptr;
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static OsAccountStateParcel *Unmarshalling(Parcel &parcel);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_OS_ACCOUNT_INCLUDE_OS_ACCOUNT_STATE_PARCEL_H

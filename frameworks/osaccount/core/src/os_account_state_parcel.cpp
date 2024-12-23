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

#include "os_account_state_parcel.h"

#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
bool OsAccountStateParcel::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(state)) {
        ACCOUNT_LOGE("Failed to write state");
        return false;
    }
    if (!parcel.WriteInt32(fromId)) {
        ACCOUNT_LOGE("Failed to write fromId");
        return false;
    }
    if (!parcel.WriteInt32(toId)) {
        ACCOUNT_LOGE("Failed to write toId");
        return false;
    }
    bool withHandshake = (callback != nullptr);
    if (!parcel.WriteBool(withHandshake)) {
        ACCOUNT_LOGE("Failed to write handshake");
        return false;
    }
    if (withHandshake && !parcel.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("Failed to write callback");
        return false;
    }
    return true;
}

OsAccountStateParcel *OsAccountStateParcel::Unmarshalling(Parcel &parcel)
{
    OsAccountStateParcel *stateParcel = new (std::nothrow) OsAccountStateParcel();
    if ((stateParcel != nullptr) && (!stateParcel->ReadFromParcel(parcel))) {
        ACCOUNT_LOGE("Failed to read state parcel");
        delete stateParcel;
        stateParcel = nullptr;
    }
    return stateParcel;
}

bool OsAccountStateParcel::ReadFromParcel(Parcel &parcel)
{
    int32_t stateInt;
    if (!parcel.ReadInt32(stateInt)) {
        ACCOUNT_LOGE("Failed to read state");
        return false;
    }
    state = static_cast<OsAccountState>(stateInt);
    if (!parcel.ReadInt32(fromId)) {
        ACCOUNT_LOGE("Failed to read fromId");
        return false;
    }
    if (!parcel.ReadInt32(toId)) {
        ACCOUNT_LOGE("Failed to read toId");
        return false;
    }
    bool withHandshake = false;
    if (!parcel.ReadBool(withHandshake)) {
        ACCOUNT_LOGE("Failed to read handshake");
        return false;
    }
    if (!withHandshake) {
        return true;
    }
    callback = static_cast<MessageParcel *>(&parcel)->ReadRemoteObject();
    if (callback == nullptr) {
        ACCOUNT_LOGE("Failed to read callback");
        return false;
    }
    return true;
}
} // AccountSA
} // OHOS

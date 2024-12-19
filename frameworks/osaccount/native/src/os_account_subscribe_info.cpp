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
#include "os_account_subscribe_info.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {
OsAccountSubscribeInfo::OsAccountSubscribeInfo()
    : osAccountSubscribeType_(ACTIVATING), name_("")
{}

OsAccountSubscribeInfo::OsAccountSubscribeInfo(const std::set<OsAccountState> &states, bool withHandshake)
    : states_(states), withHandshake_(withHandshake)
{}

OsAccountSubscribeInfo::OsAccountSubscribeInfo(const OS_ACCOUNT_SUBSCRIBE_TYPE &osAccountSubscribeType,
    const std::string &name) : osAccountSubscribeType_(osAccountSubscribeType), name_(name)
{}

OsAccountSubscribeInfo::~OsAccountSubscribeInfo()
{}

void OsAccountSubscribeInfo::GetOsAccountSubscribeType(OS_ACCOUNT_SUBSCRIBE_TYPE &osAccountSubscribeType) const
{
    osAccountSubscribeType = osAccountSubscribeType_;
}

void OsAccountSubscribeInfo::SetOsAccountSubscribeType(const OS_ACCOUNT_SUBSCRIBE_TYPE &osAccountSubscribeType)
{
    osAccountSubscribeType_ = osAccountSubscribeType;
}

void OsAccountSubscribeInfo::GetName(std::string &name) const
{
    name = name_;
}

void OsAccountSubscribeInfo::SetName(const std::string &name)
{
    name_ = name;
}

void OsAccountSubscribeInfo::GetStates(std::set<OsAccountState> &states) const
{
    states = states_;
}

bool OsAccountSubscribeInfo::IsWithHandshake() const
{
    return withHandshake_;
}

bool OsAccountSubscribeInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(osAccountSubscribeType_)) {
        ACCOUNT_LOGE("Failed to write osAccountSubscribeType_");
        return false;
    }
    if (!parcel.WriteString(name_)) {
        ACCOUNT_LOGE("Failed to write name");
        return false;
    }
    if (!parcel.WriteUint32(states_.size())) {
        ACCOUNT_LOGE("Failed to write the size of states");
        return false;
    }
    for (auto state : states_) {
        if (!parcel.WriteInt32(state)) {
            ACCOUNT_LOGE("Failed to write state");
            return false;
        }
    }
    if (!parcel.WriteBool(withHandshake_)) {
        ACCOUNT_LOGE("Failed to write withHandshake");
        return false;
    }

    return true;
}

OsAccountSubscribeInfo *OsAccountSubscribeInfo::Unmarshalling(Parcel &parcel)
{
    OsAccountSubscribeInfo *subscribeInfo = new (std::nothrow) OsAccountSubscribeInfo();

    if (subscribeInfo && !subscribeInfo->ReadFromParcel(parcel)) {
        ACCOUNT_LOGE("failed to read from parcel");
        delete subscribeInfo;
        subscribeInfo = nullptr;
    }

    return subscribeInfo;
}

bool OsAccountSubscribeInfo::ReadFromParcel(Parcel &parcel)
{
    int type = -1;
    if (!parcel.ReadInt32(type)) {
        ACCOUNT_LOGE("Failed to read type");
        return false;
    }
    osAccountSubscribeType_ = static_cast<OS_ACCOUNT_SUBSCRIBE_TYPE>(type);
    if (!parcel.ReadString(name_)) {
        ACCOUNT_LOGE("Failed to read name");
        return false;
    }
    uint32_t stateSize = 0;
    if (!parcel.ReadUint32(stateSize)) {
        ACCOUNT_LOGE("Failed to read the size of states");
        return false;
    }
    if (stateSize > Constants::MAX_SUBSCRIBED_STATES_SIZE) {
        ACCOUNT_LOGE("The states is oversize");
        return false;
    }
    int32_t state;
    for (uint32_t i = 0; i < stateSize; ++i) {
        if (!parcel.ReadInt32(state)) {
            ACCOUNT_LOGE("Failed to read state");
            return false;
        }
        states_.emplace(static_cast<OsAccountState>(state));
    }
    if (!parcel.ReadBool(withHandshake_)) {
        ACCOUNT_LOGE("Failed to read withHandshake");
        return false;
    }
    return true;
}
}  // namespace AccountSA
}  // namespace OHOS

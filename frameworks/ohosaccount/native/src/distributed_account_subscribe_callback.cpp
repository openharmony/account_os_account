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

#include "account_log_wrapper.h"
#include "distributed_account_subscribe_callback.h"

namespace OHOS {
namespace AccountSA {

bool DistributedAccountEventData::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(id_)) {
        ACCOUNT_LOGE("Write id failed.");
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(type_))) {
        ACCOUNT_LOGE("Write type failed.");
        return false;
    }
    if (!parcel.WriteInt32(subspaceId_)) {
        ACCOUNT_LOGE("Write subProfileId failed.");
        return false;
    }
    return true;
}

DistributedAccountEventData *DistributedAccountEventData::Unmarshalling(Parcel &parcel)
{
    DistributedAccountEventData *eventData = new (std::nothrow) DistributedAccountEventData();

    if (eventData != nullptr && !eventData->ReadFromParcel(parcel)) {
        ACCOUNT_LOGE("Read from parcel failed.");
        delete eventData;
        eventData = nullptr;
    }

    return eventData;
}

bool DistributedAccountEventData::operator==(const DistributedAccountEventData &eventData) const
{
    return (this->id_ == eventData.id_) && (this->type_ == eventData.type_) &&
        (this->subspaceId_ == eventData.subspaceId_);
}

bool DistributedAccountEventData::ReadFromParcel(Parcel &parcel)
{
    int32_t id = 0;
    if (!parcel.ReadInt32(id)) {
        ACCOUNT_LOGE("Read id failed.");
        return false;
    }
    id_ = id;
    int32_t type = 0;
    if (!parcel.ReadInt32(type)) {
        ACCOUNT_LOGE("Read type failed.");
        return false;
    }
    type_ = static_cast<DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE>(type);
    int32_t subProfileId = 0;
    if (!parcel.ReadInt32(subProfileId)) {
        ACCOUNT_LOGE("Read subProfileId failed.");
        return false;
    }
    subspaceId_ = subProfileId;
    return true;
}

bool DistributedAccountSubProfileEventData::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(type_))) {
        ACCOUNT_LOGE("Write type failed.");
        return false;
    }
    if (!parcel.WriteInt32(osAccountId_)) {
        ACCOUNT_LOGE("Write osAccountId failed.");
        return false;
    }
    if (!parcel.WriteInt32(subspaceId_)) {
        ACCOUNT_LOGE("Write subProfileId failed.");
        return false;
    }
    if (!parcel.WriteInt32(previousSubspaceId_)) {
        ACCOUNT_LOGE("Write previousSubProfileId failed.");
        return false;
    }
    return true;
}

DistributedAccountSubProfileEventData *DistributedAccountSubProfileEventData::Unmarshalling(Parcel &parcel)
{
    DistributedAccountSubProfileEventData *eventData = new (std::nothrow) DistributedAccountSubProfileEventData();

    if (eventData != nullptr && !eventData->ReadFromParcel(parcel)) {
        ACCOUNT_LOGE("Read from parcel failed.");
        delete eventData;
        eventData = nullptr;
    }

    return eventData;
}

bool DistributedAccountSubProfileEventData::operator==(const DistributedAccountSubProfileEventData &eventData) const
{
    if (this->type_ != eventData.type_) {
        return false;
    }
    if (this->osAccountId_ != eventData.osAccountId_ ||
        this->subspaceId_ != eventData.subspaceId_ ||
        this->previousSubspaceId_ != eventData.previousSubspaceId_) {
        return false;
    }
    return true;
}

bool DistributedAccountSubProfileEventData::ReadFromParcel(Parcel &parcel)
{
    int32_t type = 0;
    if (!parcel.ReadInt32(type)) {
        ACCOUNT_LOGE("Read type failed.");
        return false;
    }
    type_ = static_cast<DistributedAccountSubProfileEventType>(type);

    int32_t osAccountId = -1;
    if (!parcel.ReadInt32(osAccountId)) {
        ACCOUNT_LOGE("Read osAccountId failed.");
        return false;
    }
    osAccountId_ = osAccountId;

    int32_t spaceId = -1;
    if (!parcel.ReadInt32(spaceId)) {
        ACCOUNT_LOGE("Read subProfileId failed.");
        return false;
    }
    subspaceId_ = spaceId;

    int32_t previousSpaceId = -1;
    if (!parcel.ReadInt32(previousSpaceId)) {
        ACCOUNT_LOGE("Read previousSubProfileId failed.");
        return false;
    }
    previousSubspaceId_ = previousSpaceId;

    return true;
}
}  // namespace AccountSA
}  // namespace OHOS

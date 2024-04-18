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
    return (this->id_ == eventData.id_) && (this->type_ == eventData.type_);
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

    return true;
}
}  // namespace AccountSA
}  // namespace OHOS

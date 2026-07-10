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

#include "os_account_sub_profile_subscribe_callback.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {

SubProfileEventData::~SubProfileEventData()
{}

bool SubProfileEventData::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(type_))) {
        ACCOUNT_LOGE("Write type_ to parcel failed.");
        return false;
    }
    if (!parcel.WriteInt32(osAccountId_)) {
        ACCOUNT_LOGE("Write osAccountId_ to parcel failed.");
        return false;
    }
    if (!parcel.WriteInt32(subProfileId_)) {
        ACCOUNT_LOGE("Write subProfileId_ to parcel failed.");
        return false;
    }
    if (!parcel.WriteInt32(previousSubProfileId_)) {
        ACCOUNT_LOGE("Write previousSubProfileId_ to parcel failed.");
        return false;
    }
    return true;
}

SubProfileEventData *SubProfileEventData::Unmarshalling(Parcel &parcel)
{
    SubProfileEventData *data = new (std::nothrow) SubProfileEventData();
    if (data == nullptr) {
        ACCOUNT_LOGE("Allocate SubProfileEventData failed.");
        return nullptr;
    }
    if (!data->ReadFromParcel(parcel)) {
        ACCOUNT_LOGE("Read SubProfileEventData from parcel failed.");
        delete data;
        return nullptr;
    }
    return data;
}

bool SubProfileEventData::ReadFromParcel(Parcel &parcel)
{
    int32_t typeValue;
    if (!parcel.ReadInt32(typeValue)) {
        ACCOUNT_LOGE("Read event type from parcel failed.");
        return false;
    }
    if (!IsValidOsAccountSubProfileEventType(typeValue)) {
        ACCOUNT_LOGE("Validate event type failed, typeValue=%{public}d.", typeValue);
        return false;
    }
    type_ = static_cast<OsAccountSubProfileEventType>(typeValue);
    if (!parcel.ReadInt32(osAccountId_)) {
        ACCOUNT_LOGE("Read osAccountId from parcel failed.");
        return false;
    }
    if (!parcel.ReadInt32(subProfileId_)) {
        ACCOUNT_LOGE("Read subProfileId from parcel failed.");
        return false;
    }
    if (!parcel.ReadInt32(previousSubProfileId_)) {
        ACCOUNT_LOGE("Read previousSubProfileId from parcel failed.");
        return false;
    }
    return true;
}

bool SubProfileEventData::operator==(const SubProfileEventData &eventData) const
{
    return type_ == eventData.type_ &&
           osAccountId_ == eventData.osAccountId_ &&
           subProfileId_ == eventData.subProfileId_ &&
           previousSubProfileId_ == eventData.previousSubProfileId_;
}

bool IsValidOsAccountSubProfileEventType(int32_t value)
{
    return value >= static_cast<int32_t>(OsAccountSubProfileEventType::CREATED) &&
           value < static_cast<int32_t>(OsAccountSubProfileEventType::INVALID_TYPE);
}

}  // namespace AccountSA
}  // namespace OHOS

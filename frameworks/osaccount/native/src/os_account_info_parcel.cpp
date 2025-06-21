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
#include "os_account_info.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
bool ConstraintSourceTypeInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(localId)) {
        ACCOUNT_LOGE("Write localId failed, please check localId value or parcel status");
        return false;
    }
    if (!parcel.WriteInt32(typeInfo)) {
        ACCOUNT_LOGE("Write typeInfo failed, please check typeInfo value or parcel status");
        return false;
    }
    return true;
}

ConstraintSourceTypeInfo *ConstraintSourceTypeInfo::Unmarshalling(Parcel &parcel)
{
    ConstraintSourceTypeInfo *info = new (std::nothrow) ConstraintSourceTypeInfo();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("ReadFromParcel failed, please check parcel data");
        delete info;
        info = nullptr;
    }
    return info;
}

bool ConstraintSourceTypeInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt32(localId)) {
        ACCOUNT_LOGE("Read localId failed, please check localId in parcel");
        return false;
    }
    int32_t typeInfoValue;
    if (!parcel.ReadInt32(typeInfoValue)) {
        ACCOUNT_LOGE("Read typeInfo failed, please check typeInfo in parcel");
        return false;
    }
    typeInfo = static_cast<ConstraintSourceType>(typeInfoValue);
    return true;
}

bool ForegroundOsAccount::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(localId)) {
        ACCOUNT_LOGE("Write localId failed, please check localId value or parcel status");
        return false;
    }
    if (!parcel.WriteUint64(displayId)) {
        ACCOUNT_LOGE("Write displayId failed, please check displayId value or parcel status");
        return false;
    }
    return true;
}

ForegroundOsAccount *ForegroundOsAccount::Unmarshalling(Parcel &parcel)
{
    ForegroundOsAccount *info = new (std::nothrow) ForegroundOsAccount();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("ReadFromParcel failed, please check parcel data");
        delete info;
        info = nullptr;
    }
    return info;
}

bool ForegroundOsAccount::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt32(localId)) {
        ACCOUNT_LOGE("Read localId failed, please check localId in parcel");
        return false;
    }
    if (!parcel.ReadUint64(displayId)) {
        ACCOUNT_LOGE("Read displayId failed, please check displayId in parcel");
        return false;
    }
    return true;
}
} // namespace AccountSA
} // namespace OHOS
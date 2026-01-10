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
#include "authorization_common.h"
#include <string>
#include <vector>
#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
bool ConnectAbilityInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(bundleName)) {
        ACCOUNT_LOGE("Read bundleName failed.");
        return false;
    }
    if (!parcel.ReadString(abilityName)) {
        ACCOUNT_LOGE("Read abilityName failed.");
        return false;
    }
    return true;
}

bool ConnectAbilityInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(bundleName)) {
        ACCOUNT_LOGE("Failed to write bundleName.");
        return false;
    }
    if (!parcel.WriteString(abilityName)) {
        ACCOUNT_LOGE("Failed to write abilityName.");
        return false;
    }
    return true;
}

ConnectAbilityInfo *ConnectAbilityInfo::Unmarshalling(Parcel &parcel)
{
    ConnectAbilityInfo *info = new (std::nothrow) ConnectAbilityInfo();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("Read from parcel failed, please check info value.");
        delete info;
        info = nullptr;
    }
    return info;
}

bool AuthorizationResult::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(privilege)) {
        ACCOUNT_LOGE("Read privilege failed.");
        return false;
    }
    if (!parcel.ReadBool(isReused)) {
        ACCOUNT_LOGE("Read isReused failed.");
        return false;
    }
    if (!parcel.ReadInt32(validityPeriod)) {
        ACCOUNT_LOGE("Read validityPeriod failed.");
        return false;
    }
    if (!parcel.ReadUInt8Vector(&token)) {
        ACCOUNT_LOGE("Read token failed.");
        return false;
    }
    return true;
}

bool AuthorizationResult::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(privilege)) {
        ACCOUNT_LOGE("Failed to write privilege.");
        return false;
    }
    if (!parcel.WriteBool(isReused)) {
        ACCOUNT_LOGE("Failed to write isReused.");
        return false;
    }
    if (!parcel.WriteInt32(validityPeriod)) {
        ACCOUNT_LOGE("Failed to write validityPeriod.");
        return false;
    }
    if (!parcel.WriteUInt8Vector(token)) {
        ACCOUNT_LOGE("Failed to write token.");
        return false;
    }
    return true;
}

AuthorizationResult *AuthorizationResult::Unmarshalling(Parcel &parcel)
{
    AuthorizationResult *info = new (std::nothrow) AuthorizationResult();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("Read from parcel failed, please check info value.");
        delete info;
        info = nullptr;
    }
    return info;
}

bool AcquireAuthorizationOptions::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadUInt8Vector(&challenge)) {
        ACCOUNT_LOGE("Read challenge failed.");
        return false;
    }
    if (!parcel.ReadBool(isReuseNeeded)) {
        ACCOUNT_LOGE("Read isReuseNeeded failed.");
        return false;
    }
    if (!parcel.ReadBool(isInteractionAllowed)) {
        ACCOUNT_LOGE("Read isInteractionAllowed failed.");
        return false;
    }
    return true;
}

bool AcquireAuthorizationOptions::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteUInt8Vector(challenge)) {
        ACCOUNT_LOGE("Failed to write challenge.");
        return false;
    }
    if (!parcel.WriteBool(isReuseNeeded)) {
        ACCOUNT_LOGE("Failed to write isReuseNeeded.");
        return false;
    }
    if (!parcel.WriteBool(isInteractionAllowed)) {
        ACCOUNT_LOGE("Failed to write isInteractionAllowed.");
        return false;
    }

    return true;
}

AcquireAuthorizationOptions *AcquireAuthorizationOptions::Unmarshalling(Parcel &parcel)
{
    AcquireAuthorizationOptions *info = new (std::nothrow) AcquireAuthorizationOptions();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("Read from parcel failed, please check info value.");
        delete info;
        info = nullptr;
    }
    return info;
}
}
}

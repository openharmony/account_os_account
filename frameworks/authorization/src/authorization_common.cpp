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
#include <string_ex.h>
#include <vector>
#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
constexpr std::uint8_t TWO_BYTE_MASK = 0xF0;
bool CheckAuthorizationResult::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadBool(isAuthorized)) {
        ACCOUNT_LOGE("Failed to read isAuthrization");
        return false;
    }
    if (!parcel.ReadUInt8Vector(&challenge)) {
        ACCOUNT_LOGE("Failed to read challenge");
        return false;
    }
    return true;
}

bool CheckAuthorizationResult::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(isAuthorized)) {
        ACCOUNT_LOGE("Failed to write isAuthrization.");
        return false;
    }
    if (!parcel.WriteUInt8Vector(challenge)) {
        ACCOUNT_LOGE("Failed to write challenge.");
        return false;
    }
    return true;
}

CheckAuthorizationResult *CheckAuthorizationResult::Unmarshalling(Parcel &parcel)
{
    CheckAuthorizationResult *info = new (std::nothrow) CheckAuthorizationResult();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("Read from parcel failed, please check info value.");
        delete info;
        info = nullptr;
    }
    return info;
}

bool ConnectAbilityInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(privilege)) {
        ACCOUNT_LOGE("Read privilege failed.");
        return false;
    }
    if (!parcel.ReadString(description)) {
        ACCOUNT_LOGE("Read description failed.");
        return false;
    }
    if (!parcel.ReadString(bundleName)) {
        ACCOUNT_LOGE("Read bundleName failed.");
        return false;
    }
    if (!parcel.ReadString(abilityName)) {
        ACCOUNT_LOGE("Read abilityName failed.");
        return false;
    }
    if (!parcel.ReadInt32(callingUid)) {
        ACCOUNT_LOGE("Read callingUid failed.");
        return false;
    }
    if (!parcel.ReadInt32(callingPid)) {
        ACCOUNT_LOGE("Read callingPid failed.");
        return false;
    }
    if (!parcel.ReadUInt8Vector(&challenge)) {
        ACCOUNT_LOGE("Read challenge failed.");
        return false;
    }
    return true;
}

bool ConnectAbilityInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(privilege)) {
        ACCOUNT_LOGE("Failed to write privilege.");
        return false;
    }
    if (!parcel.WriteString(description)) {
        ACCOUNT_LOGE("Failed to write description.");
        return false;
    }
    if (!parcel.WriteString(bundleName)) {
        ACCOUNT_LOGE("Failed to write bundleName.");
        return false;
    }
    if (!parcel.WriteString(abilityName)) {
        ACCOUNT_LOGE("Failed to write abilityName.");
        return false;
    }
    if (!parcel.WriteInt32(callingUid)) {
        ACCOUNT_LOGE("Failed to write callingUid.");
        return false;
    }
    if (!parcel.WriteInt32(callingPid)) {
        ACCOUNT_LOGE("Failed to write callingPid.");
        return false;
    }
    if (!parcel.WriteUInt8Vector(challenge)) {
        ACCOUNT_LOGE("Failed to write bundleName.");
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
    int32_t resultCodeValue;
    if (!parcel.ReadInt32(resultCodeValue)) {
        ACCOUNT_LOGE("Read resultCodeValue failed.");
        return false;
    }
    resultCode = static_cast<AuthorizationResultCode>(resultCodeValue);
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
    if (!parcel.WriteInt32(static_cast<int32_t>(resultCode))) {
        ACCOUNT_LOGE("Failed to write resultCode.");
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
    if (!parcel.ReadBool(hasContext)) {
        ACCOUNT_LOGE("Read challenge failed.");
        return false;
    }
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
    if (!parcel.WriteBool(hasContext)) {
        ACCOUNT_LOGE("Failed to write hasContext");
        return false;
    }
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

void TransVectorU8ToString(const std::vector<uint8_t> &vec, std::string &str)
{
    str.clear();
    for (uint8_t item : vec) {
        if ((item & TWO_BYTE_MASK) == 0) {
            str.append("0");
        }
        str.append(DexToHexString(item, true));
    }
}

void TransStringToVectorU8(std::vector<uint8_t> &vec, const std::string &str)
{
    vec.clear();
    for (char ch : str) {
        vec.push_back(static_cast<uint8_t>(ch));
    }
}
}
}

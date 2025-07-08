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

#include "account_info.h"
#include "account_log_wrapper.h"
#include "message_parcel.h"

namespace OHOS {
namespace AccountSA {
namespace {
const int32_t AVATAR_MAX_SIZE = 10 * 1024 * 1024;
}

bool OhosAccountInfo::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteString16(Str8ToStr16(name_))) {
        ACCOUNT_LOGE("write name failed!");
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(uid_))) {
        ACCOUNT_LOGE("write uid failed!");
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(rawUid_))) {
        ACCOUNT_LOGE("write rawUid failed!");
        return false;
    }
    if (!parcel.WriteInt32(status_)) {
        ACCOUNT_LOGE("write status failed!");
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(nickname_))) {
        ACCOUNT_LOGE("write nickname failed!");
        return false;
    }
    if (!parcel.WriteInt32(avatar_.size() + 1)) {
        ACCOUNT_LOGE("write avatarSize failed!");
        return false;
    }
    if (!static_cast<MessageParcel&>(parcel).WriteRawData(static_cast<const void*>(avatar_.c_str()),
        avatar_.size() + 1)) {
        ACCOUNT_LOGE("write avatar failed!");
        return false;
    }
    if (!parcel.WriteParcelable(&(scalableData_))) {
        ACCOUNT_LOGE("write scalableData failed!");
        return false;
    }
    return true;
}

OhosAccountInfo* OhosAccountInfo::Unmarshalling(Parcel& parcel)
{
    OhosAccountInfo* info = new (std::nothrow) OhosAccountInfo();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool OhosAccountInfo::ReadFromParcel(Parcel& parcel)
{
    std::u16string name;
    if (!parcel.ReadString16(name)) {
        ACCOUNT_LOGE("read name failed");
        return false;
    }
    std::u16string uid;
    if (!parcel.ReadString16(uid)) {
        ACCOUNT_LOGE("read uid failed");
        return false;
    }
    std::u16string rawUid;
    if (!parcel.ReadString16(rawUid)) {
        ACCOUNT_LOGE("read rawUid failed");
        return false;
    }
    int32_t status;
    if (!parcel.ReadInt32(status)) {
        ACCOUNT_LOGE("read status failed");
        return false;
    }
    std::u16string nickname;
    if (!parcel.ReadString16(nickname)) {
        ACCOUNT_LOGE("read nickname failed");
        return false;
    }

    if (!ReadAvatarData(parcel)) {
        ACCOUNT_LOGE("read avatar failed");
        return false;
    }
    sptr<AAFwk::Want> want = parcel.ReadParcelable<AAFwk::Want>();
    if (want == nullptr) {
        ACCOUNT_LOGE("read want failed");
        return false;
    }
    name_ = Str16ToStr8(name);
    uid_ = Str16ToStr8(uid);
    status_ = status;
    nickname_ = Str16ToStr8(nickname);
    scalableData_ = *want;
    rawUid_ = Str16ToStr8(rawUid);
    return true;
}

bool OhosAccountInfo::ReadAvatarData(Parcel& parcel)
{
    int32_t avatarSize;
    if (!parcel.ReadInt32(avatarSize)) {
        ACCOUNT_LOGE("read avatarSize failed");
        return false;
    }
    if ((avatarSize - 1 > AVATAR_MAX_SIZE) || (avatarSize - 1 < 0)) {
        ACCOUNT_LOGE("avatarSize is invalid");
        return false;
    }
    auto readRawData = static_cast<MessageParcel&>(parcel).ReadRawData(avatarSize);
    if (readRawData == nullptr) {
        ACCOUNT_LOGE("read avatar failed");
        return false;
    }
    const char* avatar = reinterpret_cast<const char*>(readRawData);
    avatar_ = std::string(avatar, avatarSize - 1);
    return true;
}
} // namespace AccountSA
} // namespace OHOS

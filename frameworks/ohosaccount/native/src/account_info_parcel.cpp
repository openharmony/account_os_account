/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "account_info_parcel.h"
#include <ipc_types.h>
#include <string_ex.h>
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
namespace {
const int32_t AVATAR_MAX_SIZE = 10 * 1024 * 1024;
}
bool WriteOhosAccountInfo(MessageParcel &data, const OhosAccountInfo &ohosAccountInfo)
{
    if (!data.WriteString16(Str8ToStr16(ohosAccountInfo.name_))) {
        ACCOUNT_LOGE("write name failed!");
        return false;
    }
    if (!data.WriteString16(Str8ToStr16(ohosAccountInfo.uid_))) {
        ACCOUNT_LOGE("write uid failed!");
        return false;
    }
    if (!data.WriteString16(Str8ToStr16(ohosAccountInfo.GetRawUid()))) {
        ACCOUNT_LOGE("write rawUid failed!");
        return false;
    }
    if (!data.WriteInt32(ohosAccountInfo.status_)) {
        ACCOUNT_LOGE("write status failed!");
        return false;
    }
    if (!data.WriteString16(Str8ToStr16(ohosAccountInfo.nickname_))) {
        ACCOUNT_LOGE("write nickname failed!");
        return false;
    }
    if (!data.WriteInt32(ohosAccountInfo.avatar_.size() + 1)) {
        ACCOUNT_LOGE("write avatarSize failed!");
        return false;
    }
    if (!data.WriteRawData(ohosAccountInfo.avatar_.c_str(), ohosAccountInfo.avatar_.size() + 1)) {
        ACCOUNT_LOGE("write avatar failed!");
        return false;
    }
    if (!data.WriteParcelable(&(ohosAccountInfo.scalableData_))) {
        ACCOUNT_LOGE("write scalableData failed!");
        return false;
    }
    return true;
}

static ErrCode ReadAvatarData(MessageParcel &data, std::string &avatarStr)
{
    int32_t avatarSize;
    if (!data.ReadInt32(avatarSize)) {
        ACCOUNT_LOGE("read avatarSize failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if ((avatarSize - 1 > AVATAR_MAX_SIZE) || (avatarSize - 1 < 0)) {
        ACCOUNT_LOGE("avatarSize is invalid");
        return ERR_OHOSACCOUNT_KIT_INVALID_PARAMETER;
    }
    const char *avatar = reinterpret_cast<const char *>(data.ReadRawData(avatarSize));
    if (avatar == nullptr) {
        ACCOUNT_LOGE("read avatar failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    avatarStr = std::string(avatar, avatarSize - 1);
    return ERR_OK;
}

ErrCode ReadOhosAccountInfo(MessageParcel &data, OhosAccountInfo &ohosAccountInfo)
{
    std::u16string name;
    if (!data.ReadString16(name)) {
        ACCOUNT_LOGE("read name failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::u16string uid;
    if (!data.ReadString16(uid)) {
        ACCOUNT_LOGE("read uid failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::u16string rawUid;
    if (!data.ReadString16(rawUid)) {
        ACCOUNT_LOGE("read rawUid failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    int32_t status;
    if (!data.ReadInt32(status)) {
        ACCOUNT_LOGE("read status failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::u16string nickname;
    if (!data.ReadString16(nickname)) {
        ACCOUNT_LOGE("read nickname failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    ErrCode ret = ReadAvatarData(data, ohosAccountInfo.avatar_);
    if (ret != ERR_OK) {
        return ret;
    }
    sptr<AAFwk::Want> want = data.ReadParcelable<AAFwk::Want>();
    if (want == nullptr) {
        ACCOUNT_LOGE("read want failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ohosAccountInfo.name_ = Str16ToStr8(name);
    ohosAccountInfo.uid_ = Str16ToStr8(uid);
    ohosAccountInfo.status_ = status;
    ohosAccountInfo.nickname_ = Str16ToStr8(nickname);
    ohosAccountInfo.scalableData_ = *want;
    ohosAccountInfo.SetRawUid(Str16ToStr8(rawUid));
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

bool ReadOhosAccountInfo(MessageParcel &data, OhosAccountInfo &ohosAccountInfo)
{
    std::u16string name;
    if (!data.ReadString16(name)) {
        ACCOUNT_LOGE("read name failed");
        return false;
    }
    std::u16string uid;
    if (!data.ReadString16(uid)) {
        ACCOUNT_LOGE("read uid failed");
        return false;
    }
    int32_t status;
    if (!data.ReadInt32(status)) {
        ACCOUNT_LOGE("read status failed");
        return false;
    }
    std::u16string nickname;
    if (!data.ReadString16(nickname)) {
        ACCOUNT_LOGE("read nickname failed");
        return false;
    }
    int32_t avatarSize;
    if (!data.ReadInt32(avatarSize)) {
        ACCOUNT_LOGE("read avatarSize failed");
        return false;
    }
    const char *avatar = reinterpret_cast<const char *>(data.ReadRawData(avatarSize));
    if (avatar == nullptr) {
        ACCOUNT_LOGE("read avatar failed");
        return false;
    }
    sptr<AAFwk::Want> want = data.ReadParcelable<AAFwk::Want>();
    if (want == nullptr) {
        ACCOUNT_LOGE("read want failed");
        return false;
    }
    ohosAccountInfo.name_ = Str16ToStr8(name);
    ohosAccountInfo.uid_ = Str16ToStr8(uid);
    ohosAccountInfo.status_ = status;
    ohosAccountInfo.nickname_ = Str16ToStr8(nickname);
    ohosAccountInfo.avatar_ = avatar;
    ohosAccountInfo.scalableData_ = *want;
    return true;
}
}  // namespace AccountSA
}  // namespace OHOS

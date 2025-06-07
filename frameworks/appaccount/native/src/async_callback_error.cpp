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

#include "async_callback_error.h"

#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
bool AsyncCallbackError::Marshalling(Parcel &parcel) const
{
    return parcel.WriteInt32(code) && parcel.WriteString(message) && parcel.WriteParcelable(&data);
}

AsyncCallbackError *AsyncCallbackError::Unmarshalling(Parcel &parcel)
{
    AsyncCallbackError *info = new (std::nothrow) AsyncCallbackError();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("Read from parcel failed, please check parcel data");
        delete info;
        info = nullptr;
    }
    return info;
}

bool AsyncCallbackError::ReadFromParcel(Parcel &parcel)
{
    if ((!parcel.ReadInt32(code)) || (!parcel.ReadString(message))) {
        return false;
    }
    sptr<AAFwk::WantParams> wantParams = parcel.ReadParcelable<AAFwk::WantParams>();
    if (wantParams == nullptr) {
        return false;
    }
    data = *wantParams;
    return true;
}
}  // namespace AccountSA
}  // namespace OHOS
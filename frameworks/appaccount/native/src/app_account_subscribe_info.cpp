/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "app_account_subscribe_info.h"

#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
AppAccountSubscribeInfo::AppAccountSubscribeInfo()
{}

AppAccountSubscribeInfo::AppAccountSubscribeInfo(std::vector<std::string> &owners) : owners_(owners)
{}

ErrCode AppAccountSubscribeInfo::GetOwners(std::vector<std::string> &owners) const
{
    owners = owners_;

    return ERR_OK;
}

ErrCode AppAccountSubscribeInfo::SetOwners(const std::vector<std::string> &owners)
{
    owners_ = owners;

    return ERR_OK;
}

bool AppAccountSubscribeInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteStringVector(owners_)) {
        ACCOUNT_LOGE("failed to write string vector owners_");
        return false;
    }

    return true;
}

AppAccountSubscribeInfo *AppAccountSubscribeInfo::Unmarshalling(Parcel &parcel)
{
    AppAccountSubscribeInfo *subscribeInfo = new (std::nothrow) AppAccountSubscribeInfo();

    if (subscribeInfo && !subscribeInfo->ReadFromParcel(parcel)) {
        ACCOUNT_LOGE("failed to read from parcel");
        delete subscribeInfo;
        subscribeInfo = nullptr;
    }

    return subscribeInfo;
}

bool AppAccountSubscribeInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadStringVector(&owners_)) {
        ACCOUNT_LOGE("failed to read string vector owners_");
        return false;
    }

    return true;
}
}  // namespace AccountSA
}  // namespace OHOS

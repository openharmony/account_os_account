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

#include "account_log_wrapper.h"
#include "os_account_subscribe_info.h"

namespace OHOS {
namespace AccountSA {
OsAccountSubscribeInfo::OsAccountSubscribeInfo()
{}

OsAccountSubscribeInfo::OsAccountSubscribeInfo(OS_ACCOUNT_SUBSCRIBE_TYPE &osAccountSubscribeType, std::string &name)
    : osAccountSubscribeType_(osAccountSubscribeType), name_(name)
{}

OsAccountSubscribeInfo::~OsAccountSubscribeInfo()
{}

ErrCode OsAccountSubscribeInfo::GetOsAccountSubscribeType(OS_ACCOUNT_SUBSCRIBE_TYPE &osAccountSubscribeType) const
{
    osAccountSubscribeType = osAccountSubscribeType_;

    return ERR_OK;
}

ErrCode OsAccountSubscribeInfo::SetOsAccountSubscribeType(const OS_ACCOUNT_SUBSCRIBE_TYPE &osAccountSubscribeType)
{
    osAccountSubscribeType_ = osAccountSubscribeType;

    return ERR_OK;
}

ErrCode OsAccountSubscribeInfo::GetName(std::string &name) const
{
    name = name_;

    return ERR_OK;
}

ErrCode OsAccountSubscribeInfo::SetName(const std::string &name)
{
    name_ = name;

    return ERR_OK;
}

bool OsAccountSubscribeInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(osAccountSubscribeType_)) {
        ACCOUNT_LOGE("failed to write osAccountSubscribeType_");
        return false;
    }
    if (!parcel.WriteString(name_)) {
        ACCOUNT_LOGE("failed to write name_");
        return false;
    }

    return true;
}

OsAccountSubscribeInfo *OsAccountSubscribeInfo::Unmarshalling(Parcel &parcel)
{
    OsAccountSubscribeInfo *subscribeInfo = new (std::nothrow) OsAccountSubscribeInfo();

    if (subscribeInfo && !subscribeInfo->ReadFromParcel(parcel)) {
        ACCOUNT_LOGE("failed to read from pacel");
        delete subscribeInfo;
        subscribeInfo = nullptr;
    }

    return subscribeInfo;
}

bool OsAccountSubscribeInfo::ReadFromParcel(Parcel &parcel)
{
    int type = -1;
    if (!parcel.ReadInt32(type)) {
        ACCOUNT_LOGE("failed to read OS_ACCOUNT_SUBSCRIBE_TYPE osAccountSubscribeType_");
        return false;
    }
    osAccountSubscribeType_ = static_cast<OS_ACCOUNT_SUBSCRIBE_TYPE>(type);
    if (!parcel.ReadString(name_)) {
        ACCOUNT_LOGE("failed to read string  name_");
        return false;
    }

    return true;
}
}  // namespace AccountSA
}  // namespace OHOS

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

#include "domain_account_parcel.h"

#include <securec.h>
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
namespace {
const unsigned int DOMAIN_DATA_MAX_SIZE = 6144; // os account and domain account property limits addition
}
bool DomainAccountParcel::ReadFromParcel(Parcel &parcel)
{
    uint32_t size;
    if (!parcel.ReadUint32(size)) {
        ACCOUNT_LOGE("Read size failed, please check size value in parcel");
        return false;
    }
    if (size > DOMAIN_DATA_MAX_SIZE) {
        return false;
    }
    const uint8_t *buffer = parcel.ReadBuffer(size);
    if (buffer == nullptr) {
        ACCOUNT_LOGE("Read buffer failed, please check buffer value in parcel");
        return false;
    }
    void *bufferNew = nullptr;
    bufferNew = malloc(size);
    if (bufferNew == nullptr) {
        return false;
    }
    if (memcpy_s(bufferNew, size, buffer, size) != EOK) {
        free(bufferNew);
        bufferNew = nullptr;
        return false;
    }
    if (!parcelData_.ParseFrom(reinterpret_cast<uintptr_t>(bufferNew), size)) {
        ACCOUNT_LOGE("Parse from failed, please check data");
        free(bufferNew);
        bufferNew = nullptr;
        return false;
    }
    return true;
}

bool DomainAccountParcel::Marshalling(Parcel &parcel) const
{
    uint32_t size = parcelData_.GetDataSize();
    if (!parcel.WriteUint32(size)) {
        ACCOUNT_LOGE("Write size failed, please check size value in parcelData_");
        return false;
    }
    if (!parcel.WriteBuffer(reinterpret_cast<const uint8_t *>(parcelData_.GetData()), size)) {
        ACCOUNT_LOGE("Write buffer failed, please check buffer value in parcelData_");
        return false;
    }
    return true;
}

DomainAccountParcel *DomainAccountParcel::Unmarshalling(Parcel &parcel)
{
    DomainAccountParcel *info = new (std::nothrow) DomainAccountParcel();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("Read from parcel failed, please check info value");
        delete info;
        info = nullptr;
    }
    return info;
}
}  // namespace AccountSA
}  // namespace OHOS

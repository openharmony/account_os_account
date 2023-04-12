/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "domain_account_callback_stub.h"

#include <securec.h>
#include "account_log_wrapper.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
namespace {
const unsigned int DOMAIN_DATA_MAX_SIZE = 6144; // os account and domain account property limits addition
}

DomainAccountCallbackStub::DomainAccountCallbackStub()
{}

DomainAccountCallbackStub::~DomainAccountCallbackStub()
{}


int32_t DomainAccountCallbackStub::OnRemoteRequest(
    std::uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGI("Received stub message: %{public}d, callingUid: %{public}d", code, IPCSkeleton::GetCallingUid());
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE(
            "check descriptor failed! code %{public}u, callingUid: %{public}d", code, IPCSkeleton::GetCallingUid());
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    return ProcOnResult(data, reply);
}

int32_t DomainAccountCallbackStub::ProcOnResult(MessageParcel &data, MessageParcel &reply)
{
    int32_t result;
    if (!data.ReadInt32(result)) {
        ACCOUNT_LOGE("failed to read result");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    uint32_t size;
    if (!data.ReadUint32(size)) {
        ACCOUNT_LOGE("failed to read size");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (size > DOMAIN_DATA_MAX_SIZE) {
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    const uint8_t *buffer = data.ReadBuffer(size);
    if (buffer == nullptr) {
        ACCOUNT_LOGE("failed to read buffer");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    void *buffer_new = nullptr;
    buffer_new = malloc(size);
    if (buffer_new == nullptr) {
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    if (memcpy_s(buffer_new, size, buffer, size) != EOK) {
        free(buffer_new);
        buffer_new = nullptr;
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    Parcel parcel;
    if (!parcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer_new), size)) {
        ACCOUNT_LOGE("failed to parse from");
        free(buffer_new);
        buffer_new = nullptr;
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    OnResult(result, parcel);
    return ERR_NONE;
}
}  // namespace AccountSA
}  // namespace OHOS

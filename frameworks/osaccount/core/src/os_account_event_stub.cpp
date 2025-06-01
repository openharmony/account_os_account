/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "os_account_event_stub.h"

#include "account_log_wrapper.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
namespace {
const uid_t ACCOUNT_UID = 3058;
}
OsAccountConstraintEventStub::OsAccountConstraintEventStub()
{}

OsAccountConstraintEventStub::~OsAccountConstraintEventStub()
{}

ErrCode OsAccountConstraintEventStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != ACCOUNT_UID) {
        ACCOUNT_LOGE("Permission denied, callingUid: %{public}d", callingUid);
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    switch (code) {
        case static_cast<uint32_t>(ConstraintEventInterfaceCode::CONSTRAINT_CHANGED): {
            int id;
            if (!data.ReadInt32(id)) {
                ACCOUNT_LOGE("Failed to read localId.");
                return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
            }
            uint32_t size;
            if (!data.ReadUint32(size)) {
                ACCOUNT_LOGE("Failed to read size.");
                return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
            }
            std::set<std::string> constraints;
            for (uint32_t i = 0; i < size; i++) {
                std::string constraint;
                if ((!data.ReadString(constraint))) {
                    ACCOUNT_LOGE("Failed to read constraint.");
                    return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
                }
                constraints.emplace(constraint);
            }
            bool enable;
            if (!data.ReadBool(enable)) {
                ACCOUNT_LOGE("Failed to read enable.");
                return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
            }
            ErrCode errCode = OnConstraintChanged(id, constraints, enable);
            if (!reply.WriteInt32(errCode)) {
                ACCOUNT_LOGE("Failed to write reply");
                return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
            }
            return ERR_OK;
        }
        default:
            ACCOUNT_LOGI("Code not match, code = %{public}u, flags = %{public}u", code, option.GetFlags());
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return ERR_OK;
}

OsAccountEventStub::OsAccountEventStub()
{}

OsAccountEventStub::~OsAccountEventStub()
{}

int OsAccountEventStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != ACCOUNT_UID) {
        ACCOUNT_LOGE("Permission denied, callingUid: %{public}d", callingUid);
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }

    switch (code) {
        case static_cast<uint32_t>(OsAccountEventInterfaceCode::ON_STATE_CHANGED): {
            std::shared_ptr<OsAccountStateParcel> stateParcelPtr(data.ReadParcelable<OsAccountStateParcel>());
            if (stateParcelPtr == nullptr) {
                ACCOUNT_LOGE("Failed to read state parcel");
                return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
            }
            return OnStateChanged(*stateParcelPtr);
        }
        case static_cast<uint32_t>(OsAccountEventInterfaceCode::ACCOUNT_CHANGED): {
            int id;
            if (!data.ReadInt32(id)) {
                ACCOUNT_LOGE("failed to read localId");
                return ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR;
            }
            OnAccountsChanged(id);
            break;
        }
        case static_cast<uint32_t>(OsAccountEventInterfaceCode::ACCOUNT_SWITCHED): {
            int newId;
            if (!data.ReadInt32(newId)) {
                ACCOUNT_LOGE("Read newId failed.");
                return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
            }
            int oldId;
            if (!data.ReadInt32(oldId)) {
                ACCOUNT_LOGE("Read oldId failed.");
                return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
            }
            OnAccountsSwitch(newId, oldId);
            break;
        }
        default:
            ACCOUNT_LOGI("default, code = %{public}u, flags = %{public}u", code, option.GetFlags());
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
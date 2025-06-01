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

#include "os_account_constraint_event_proxy.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
OsAccountConstraintEventProxy::OsAccountConstraintEventProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IConstraintEvent>(object)
{}

OsAccountConstraintEventProxy::~OsAccountConstraintEventProxy()
{}

ErrCode OsAccountConstraintEventProxy::OnConstraintChanged(int localId, const std::set<std::string> &constraints,
    bool enable)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(localId)) {
        ACCOUNT_LOGE("Failed to write WriteInt32 localId %{public}d.", localId);
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteUint32(constraints.size())) {
        ACCOUNT_LOGE("Write constraints size failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    for (auto const &item : constraints) {
        if ((!data.WriteString(item))) {
            ACCOUNT_LOGE("Write constraints item failed.");
            return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
        }
    }

    if (!data.WriteBool(enable)) {
        ACCOUNT_LOGE("Write enable failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    return SendRequest(ConstraintEventInterfaceCode::CONSTRAINT_CHANGED, data, reply);
}

ErrCode OsAccountConstraintEventProxy::SendRequest(ConstraintEventInterfaceCode code, MessageParcel &data,
    MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("Remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    MessageOption option(MessageOption::TF_SYNC);
    return remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
}
}  // namespace AccountSA
}  // namespace OHOS

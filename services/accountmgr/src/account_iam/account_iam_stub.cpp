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

#include "account_iam_stub.h"

#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
AccountIAMStub::AccountIAMStub()
{}

AccountIAMStub::~AccountIAMStub()
{}

const std::map<uint32_t, AccountIAMStub::MessageProcFunction> AccountIAMStub::messageProcMap_ = {
    {
        static_cast<uint32_t>(IAccountIAM::Message::ACTIVATE_USER_KEY),
        &AccountIAMStub::ProcActivateUserKey
    },
    {
        static_cast<uint32_t>(IAccountIAM::Message::UPDATE_USER_KEY),
        &AccountIAMStub::ProcUpdateUserKey
    },
    {
        static_cast<uint32_t>(IAccountIAM::Message::REMOVE_USER_KEY),
        &AccountIAMStub::ProcRemoveUserKey
    },
    {
        static_cast<uint32_t>(IAccountIAM::Message::RESTORE_USER_KEY),
        &AccountIAMStub::ProcResotreUserKey
    }
};

std::int32_t AccountIAMStub::OnRemoteRequest(
    std::uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d", code);
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGD("check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }

    const auto &itFunc = messageProcMap_.find(code);
    if (itFunc != messageProcMap_.end()) {
        return (this->*(itFunc->second))(data, reply);
    }

    ACCOUNT_LOGW("remote request unhandled: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrCode AccountIAMStub::ProcActivateUserKey(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = 0;
    data.ReadInt32(userId);
    std::vector<uint8_t> token;
    data.ReadUInt8Vector(&token);
    std::vector<uint8_t> secret;
    data.ReadUInt8Vector(&secret);
    ErrCode result = ActivateUserKey(userId, token, secret);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGD("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AccountIAMStub::ProcUpdateUserKey(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = 0;
    data.ReadInt32(userId);
    uint64_t credentialId = 0;
    data.ReadUint64(credentialId);
    std::vector<uint8_t> token;
    data.ReadUInt8Vector(&token);
    std::vector<uint8_t> newSecret;
    data.ReadUInt8Vector(&newSecret);
    ErrCode result = UpdateUserKey(userId, credentialId, token, newSecret);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGD("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AccountIAMStub::ProcRemoveUserKey(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = 0;
    data.ReadInt32(userId);
    std::vector<uint8_t> token;
    data.ReadUInt8Vector(&token);
    ErrCode result = RemoveUserKey(userId, token);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGD("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AccountIAMStub::ProcResotreUserKey(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = 0;
    data.ReadInt32(userId);
    uint64_t credentialId = 0;
    data.ReadUint64(credentialId);
    std::vector<uint8_t> token;
    data.ReadUInt8Vector(&token);
    ErrCode result = RestoreUserKey(userId, credentialId, token);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGD("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}
}  // AccountSA
}  // OHOS

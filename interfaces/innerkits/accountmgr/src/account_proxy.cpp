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

#include "account_proxy.h"
#include <ipc_types.h>
#include <string_ex.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
bool AccountProxy::UpdateOhosAccountInfo(const std::string& accountName, const std::string& uid,
    const std::string& eventStr)
{
    ACCOUNT_LOGI("UpdateOhosAccountInfo enter");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AccountProxy::GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return false;
    }
    if (!data.WriteString16(Str8ToStr16(accountName.c_str()))) {
        return false;
    }
    if (!data.WriteString16(Str8ToStr16(uid.c_str()))) {
        return false;
    }
    if (!data.WriteString16(Str8ToStr16(eventStr.c_str()))) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto ret = Remote()->SendRequest(UPDATE_OHOS_ACCOUNT_INFO, data, reply, option);
    if (ret != ERR_NONE) {
        ACCOUNT_LOGE("SendRequest failed %d", ret);
        return false;
    }

    std::int32_t result = ERR_OK;
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("reply ReadInt32 failed");
        return false;
    }

    if (result != ERR_OK) {
        ACCOUNT_LOGE("UpdateOhosAccountInfo failed: %{public}d", result);
        return false;
    }

    ACCOUNT_LOGI("UpdateOhosAccountInfo exit");
    return true;
}

std::pair<bool, OhosAccountInfo> AccountProxy::QueryOhosAccountInfo(void)
{
    ACCOUNT_LOGI("QueryOhosAccountInfo enter");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AccountProxy::GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return std::make_pair(false, OhosAccountInfo());
    }
    MessageParcel reply;
    MessageOption option;
    auto ret = Remote()->SendRequest(QUERY_OHOS_ACCOUNT_INFO, data, reply, option);
    if (ret != ERR_NONE) {
        ACCOUNT_LOGE("SendRequest failed %d", ret);
        return std::make_pair(false, OhosAccountInfo());
    }

    std::u16string name = reply.ReadString16();
    std::u16string uid = reply.ReadString16();
    std::int32_t status = reply.ReadInt32();
    ACCOUNT_LOGI("QueryOhosAccountInfo exit");
    return std::make_pair(true, OhosAccountInfo(Str16ToStr8(name), Str16ToStr8(uid), status));
}

std::int32_t AccountProxy::QueryDeviceAccountIdFromUid(std::int32_t uid)
{
    ACCOUNT_LOGI("QueryDeviceAccountIdFromUid enter");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AccountProxy::GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return ERR_ACCOUNT_ZIDL_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(uid)) {
        return ERR_ACCOUNT_ZIDL_WRITE_PARCEL_DATA_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    auto ret = Remote()->SendRequest(QUERY_DEVICE_ACCOUNT_ID_FROM_UID, data, reply, option);
    if (ret != ERR_NONE) {
        ACCOUNT_LOGE("SendRequest failed %d", ret);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SEND_REQUEST_ERROR;
    }

    return reply.ReadInt32();
}

std::int32_t AccountProxy::QueryDeviceAccountId(std::int32_t& accountId)
{
    ACCOUNT_LOGI("QueryDeviceAccountId enter");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AccountProxy::GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return ERR_ACCOUNT_ZIDL_WRITE_DESCRIPTOR_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    auto ret = Remote()->SendRequest(QUERY_DEVICE_ACCOUNT_ID, data, reply, option);
    if (ret != ERR_NONE) {
        ACCOUNT_LOGE("SendRequest failed %d", ret);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SEND_REQUEST_ERROR;
    }

    accountId = reply.ReadInt32();
    return ERR_OK;
}
} // namespace AccountSA
} // namespace OHOS

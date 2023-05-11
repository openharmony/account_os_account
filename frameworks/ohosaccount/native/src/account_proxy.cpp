/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "account_info_parcel.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
bool AccountProxy::UpdateOhosAccountInfo(
    const std::string &accountName, const std::string &uid, const std::string &eventStr)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed!");
        return false;
    }
    if (!data.WriteString16(Str8ToStr16(accountName))) {
        ACCOUNT_LOGE("Write accountName failed!");
        return false;
    }
    if (!data.WriteString16(Str8ToStr16(uid))) {
        ACCOUNT_LOGE("Write uid failed!");
        return false;
    }
    if (!data.WriteString16(Str8ToStr16(eventStr))) {
        ACCOUNT_LOGE("Write eventStr failed!");
        return false;
    }

    auto ret = Remote()->SendRequest(UPDATE_OHOS_ACCOUNT_INFO, data, reply, option);
    if (ret != ERR_NONE) {
        ACCOUNT_LOGE("SendRequest failed %{public}d", ret);
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

    ACCOUNT_LOGD("UpdateOhosAccountInfo exit");
    return true;
}

std::int32_t AccountProxy::SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed!");
        return ERR_ACCOUNT_ZIDL_WRITE_PARCEL_DATA_ERROR;
    }
    if (!WriteOhosAccountInfo(data, ohosAccountInfo)) {
        ACCOUNT_LOGE("Write ohosAccountInfo failed!");
        return ERR_ACCOUNT_ZIDL_WRITE_PARCEL_DATA_ERROR;
    }
    if (!data.WriteString16(Str8ToStr16(eventStr))) {
        ACCOUNT_LOGE("Write eventStr failed!");
        return ERR_ACCOUNT_ZIDL_WRITE_PARCEL_DATA_ERROR;
    }
    auto ret = Remote()->SendRequest(SET_OHOS_ACCOUNT_INFO, data, reply, option);
    if (ret != ERR_NONE) {
        ACCOUNT_LOGE("SendRequest failed %{public}d", ret);
        return ret;
    }

    std::int32_t result = ERR_OK;
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("reply ReadInt32 failed");
        return ERR_ACCOUNT_ZIDL_READ_RESULT_ERROR;
    }

    if (result != ERR_OK) {
        ACCOUNT_LOGE("SetOhosAccountInfo failed: %{public}d", result);
    }
    ACCOUNT_LOGD("SetOhosAccountInfo exit");
    return result;
}

std::pair<bool, OhosAccountInfo> AccountProxy::QueryOhosAccountInfo(void)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return std::make_pair(false, OhosAccountInfo());
    }

    auto ret = Remote()->SendRequest(QUERY_OHOS_ACCOUNT_INFO, data, reply, option);
    if (ret != ERR_NONE) {
        ACCOUNT_LOGE("SendRequest failed %{public}d", ret);
        return std::make_pair(false, OhosAccountInfo());
    }

    std::u16string name = reply.ReadString16();
    std::u16string uid = reply.ReadString16();
    std::int32_t status = reply.ReadInt32();
    ACCOUNT_LOGD("QueryOhosAccountInfo exit");
    return std::make_pair(true, OhosAccountInfo(Str16ToStr8(name), Str16ToStr8(uid), status));
}

ErrCode AccountProxy::GetOhosAccountInfo(OhosAccountInfo &ohosAccountInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return ERR_ACCOUNT_ZIDL_WRITE_DESCRIPTOR_ERROR;
    }

    auto ret = Remote()->SendRequest(GET_OHOS_ACCOUNT_INFO, data, reply, option);
    if (ret != ERR_NONE) {
        ACCOUNT_LOGE("SendRequest failed %{public}d", ret);
        return ret;
    }
    ret = ReadOhosAccountInfo(reply, ohosAccountInfo);
    if (ret != ERR_OK) {
        return ret;
    }

    ACCOUNT_LOGD("QueryOhosAccountInfo exit");
    return ERR_OK;
}

ErrCode AccountProxy::GetOhosAccountInfoByUserId(int32_t userId, OhosAccountInfo &ohosAccountInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return ERR_ACCOUNT_ZIDL_WRITE_PARCEL_DATA_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGE("failed to write int for userId %{public}d.", userId);
        return ERR_ACCOUNT_ZIDL_WRITE_PARCEL_DATA_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    auto ret = Remote()->SendRequest(GET_OHOS_ACCOUNT_INFO_BY_USER_ID, data, reply, option);
    if (ret != ERR_NONE) {
        ACCOUNT_LOGE("SendRequest failed %{public}d", ret);
        return ret;
    }
    ret = ReadOhosAccountInfo(reply, ohosAccountInfo);
    if (ret != ERR_OK) {
        return ret;
    }
    return ERR_OK;
}

std::pair<bool, OhosAccountInfo> AccountProxy::QueryOhosAccountInfoByUserId(std::int32_t userId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return std::make_pair(false, OhosAccountInfo());
    }

    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGE("failed to write int for userId %{public}d.", userId);
        return std::make_pair(false, OhosAccountInfo());
    }

    auto ret = Remote()->SendRequest(QUERY_OHOS_ACCOUNT_INFO_BY_USER_ID, data, reply, option);
    if (ret != ERR_NONE) {
        ACCOUNT_LOGE("SendRequest failed %{public}d", ret);
        return std::make_pair(false, OhosAccountInfo());
    }

    std::u16string name;
    std::u16string uid;
    std::int32_t status;
    if ((!reply.ReadString16(name)) || (!reply.ReadString16(uid)) || (!reply.ReadInt32(status))) {
        ACCOUNT_LOGE("failed to read from parcel");
        return std::make_pair(false, OhosAccountInfo());
    }
    return std::make_pair(true, OhosAccountInfo(Str16ToStr8(name), Str16ToStr8(uid), status));
}

std::int32_t AccountProxy::QueryDeviceAccountId(std::int32_t &accountId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return ERR_ACCOUNT_ZIDL_WRITE_DESCRIPTOR_ERROR;
    }

    auto ret = Remote()->SendRequest(QUERY_DEVICE_ACCOUNT_ID, data, reply, option);
    if (ret != ERR_NONE) {
        ACCOUNT_LOGE("SendRequest failed %{public}d", ret);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SEND_REQUEST_ERROR;
    }

    accountId = reply.ReadInt32();

    return ERR_OK;
}

sptr<IRemoteObject> AccountProxy::GetAppAccountService()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return nullptr;
    }

    auto ret = Remote()->SendRequest(GET_APP_ACCOUNT_SERVICE, data, reply, option);
    if (ret != ERR_NONE) {
        ACCOUNT_LOGE("SendRequest failed %{public}d", ret);
        return nullptr;
    }

    return reply.ReadRemoteObject();
}

sptr<IRemoteObject> AccountProxy::GetOsAccountService()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return nullptr;
    }

    auto ret = Remote()->SendRequest(GET_OS_ACCOUNT_SERVICE, data, reply, option);
    if (ret != ERR_NONE) {
        ACCOUNT_LOGE("SendRequest failed %{public}d", ret);
        return nullptr;
    }

    return reply.ReadRemoteObject();
}

sptr<IRemoteObject> AccountProxy::GetAccountIAMService()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return nullptr;
    }

    auto ret = Remote()->SendRequest(GET_ACCOUNT_IAM_SERVICE, data, reply, option);
    if (ret != ERR_NONE) {
        ACCOUNT_LOGE("SendRequest failed %d", ret);
        return nullptr;
    }

    return reply.ReadRemoteObject();
}

sptr<IRemoteObject> AccountProxy::GetDomainAccountService()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return nullptr;
    }
    MessageParcel reply;
    MessageOption option;
    auto ret = Remote()->SendRequest(GET_DOMAIN_ACCOUNT_SERVICE, data, reply, option);
    if (ret != ERR_NONE) {
        ACCOUNT_LOGE("SendRequest failed %d", ret);
        return nullptr;
    }
    return reply.ReadRemoteObject();
}
}  // namespace AccountSA
}  // namespace OHOS

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
const size_t INTERCEPT_HEAD_PART_LEN_FOR_NAME = 1;
const char DEFAULT_ANON_STR[] = "**********";

AccountProxy::~AccountProxy()
{
    destroyedMagic_ = 0x6b6b6b6b;
}

static std::string AnonymizeNameStr(const std::string& nameStr)
{
    if (nameStr.empty()) {
        return nameStr;
    }
    return nameStr.substr(0, INTERCEPT_HEAD_PART_LEN_FOR_NAME) + DEFAULT_ANON_STR;
}

ErrCode AccountProxy::SendRequest(AccountMgrInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send account request, code = %{public}d, result = %{public}d", code, result);
    }
    return result;
}

ErrCode AccountProxy::UpdateOhosAccountInfo(
    const std::string &accountName, const std::string &uid, const std::string &eventStr)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString16(Str8ToStr16(accountName))) {
        ACCOUNT_LOGE("Write accountName failed!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString16(Str8ToStr16(uid))) {
        ACCOUNT_LOGE("Write uid failed!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString16(Str8ToStr16(eventStr))) {
        ACCOUNT_LOGE("Write eventStr failed!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    auto ret = SendRequest(AccountMgrInterfaceCode::UPDATE_OHOS_ACCOUNT_INFO, data, reply);
    if (ret != ERR_NONE) {
        return ret;
    }

    std::int32_t result = ERR_OK;
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("reply ReadInt32 failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    if (result != ERR_OK) {
        ACCOUNT_LOGE("UpdateOhosAccountInfo failed: %{public}d", result);
    }

    return ERR_OK;
}

ErrCode AccountProxy::SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!WriteOhosAccountInfo(data, ohosAccountInfo)) {
        ACCOUNT_LOGE("Write ohosAccountInfo failed!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString16(Str8ToStr16(eventStr))) {
        ACCOUNT_LOGE("Write eventStr failed!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    MessageParcel reply;
    auto ret = SendRequest(AccountMgrInterfaceCode::SET_OHOS_ACCOUNT_INFO, data, reply);
    if (ret != ERR_NONE) {
        return ret;
    }

    std::int32_t result = ERR_OK;
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("reply ReadInt32 failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    if (result != ERR_OK) {
        ACCOUNT_LOGE("SetOhosAccountInfo failed: %{public}d", result);
    }

    return result;
}

ErrCode AccountProxy::SetOsAccountDistributedInfo(
    const int32_t localId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(localId)) {
        ACCOUNT_LOGE("Failed to write localId.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!WriteOhosAccountInfo(data, ohosAccountInfo)) {
        ACCOUNT_LOGE("Write ohosAccountInfo failed!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString16(Str8ToStr16(eventStr))) {
        ACCOUNT_LOGE("Write eventStr failed!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    auto ret = SendRequest(AccountMgrInterfaceCode::SET_OHOS_ACCOUNT_INFO_BY_USER_ID, data, reply);
    if (ret != ERR_NONE) {
        return ret;
    }

    std::int32_t result = ERR_OK;
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("reply ReadInt32 failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return result;
}

ErrCode AccountProxy::QueryDistributedVirtualDeviceId(std::string &dvid)
{
    dvid = "";
    MessageParcel data;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    MessageParcel reply;
    ErrCode code = SendRequest(AccountMgrInterfaceCode::QUERY_DISTRIBUTE_VIRTUAL_DEVICE_ID, data, reply);
    if (code != ERR_OK) {
        ACCOUNT_LOGE("Failed to send request, code %{public}d.", code);
        return code;
    }
    int32_t result = ERR_OK;
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("Failed to read result");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to query dvid, result %{public}d.", result);
        return result;
    }
    if (!reply.ReadString(dvid)) {
        ACCOUNT_LOGE("Failed to read dvid");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AccountProxy::QueryDistributedVirtualDeviceId(const std::string &bundleName, int32_t localId, std::string &dvid)
{
    dvid = "";
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        ACCOUNT_LOGE("Failed to write bundleName=%{public}s", bundleName.c_str());
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(localId)) {
        ACCOUNT_LOGE("Failed to write localId %{public}d.", localId);
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode code = SendRequest(AccountMgrInterfaceCode::QUERY_DISTRIBUTE_VIRTUAL_DEVICE_ID_BY_BUNDLE_NAME, data, reply);
    if (code != ERR_OK) {
        ACCOUNT_LOGE("Failed to send request, code %{public}d.", code);
        return code;
    }
    int32_t result = ERR_OK;
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("Failed to read result");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to query dvid, result %{public}d.", result);
        return result;
    }
    if (!reply.ReadString(dvid)) {
        ACCOUNT_LOGE("Failed to read dvid");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AccountProxy::QueryOhosAccountInfo(OhosAccountInfo &accountInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    MessageParcel reply;
    auto ret = SendRequest(AccountMgrInterfaceCode::QUERY_OHOS_ACCOUNT_INFO, data, reply);
    if (ret != ERR_NONE) {
        return ret;
    }

    std::u16string name;
    std::u16string uid;
    std::int32_t status;
    if ((!reply.ReadString16(name)) || (!reply.ReadString16(uid)) || (!reply.ReadInt32(status))) {
        ACCOUNT_LOGE("failed to read from parcel");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    accountInfo.name_ = Str16ToStr8(name);
    accountInfo.uid_ = Str16ToStr8(uid);
    accountInfo.status_ = status;
    return ERR_OK;
}

ErrCode AccountProxy::GetOhosAccountInfo(OhosAccountInfo &ohosAccountInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    MessageParcel reply;
    auto ret = SendRequest(AccountMgrInterfaceCode::GET_OHOS_ACCOUNT_INFO, data, reply);
    if (ret != ERR_NONE) {
        return ret;
    }
    ret = ReadOhosAccountInfo(reply, ohosAccountInfo);
    if (ret != ERR_OK) {
        return ret;
    }
    ACCOUNT_LOGI("Get ohos account %{public}s.", AnonymizeNameStr(ohosAccountInfo.nickname_).c_str());
    return ERR_OK;
}

ErrCode AccountProxy::GetOsAccountDistributedInfo(int32_t localId, OhosAccountInfo &ohosAccountInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(localId)) {
        ACCOUNT_LOGE("Failed to write localId %{public}d.", localId);
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    auto ret = SendRequest(AccountMgrInterfaceCode::GET_OHOS_ACCOUNT_INFO_BY_USER_ID, data, reply);
    if (ret != ERR_NONE) {
        return ret;
    }
    ret = ReadOhosAccountInfo(reply, ohosAccountInfo);
    if (ret != ERR_OK) {
        return ret;
    }
    ACCOUNT_LOGI("Get ohos account %{public}s.", AnonymizeNameStr(ohosAccountInfo.nickname_).c_str());
    return ERR_OK;
}

ErrCode AccountProxy::QueryOsAccountDistributedInfo(std::int32_t localId, OhosAccountInfo &accountInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(localId)) {
        ACCOUNT_LOGE("Failed to write localId %{public}d.", localId);
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    auto ret = SendRequest(AccountMgrInterfaceCode::QUERY_OHOS_ACCOUNT_INFO_BY_USER_ID, data, reply);
    if (ret != ERR_NONE) {
        return ret;
    }

    std::u16string name;
    std::u16string uid;
    std::int32_t status;
    if ((!reply.ReadString16(name)) || (!reply.ReadString16(uid)) || (!reply.ReadInt32(status))) {
        ACCOUNT_LOGE("failed to read from parcel");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    accountInfo.name_ = Str16ToStr8(name);
    accountInfo.uid_ = Str16ToStr8(uid);
    accountInfo.status_ = status;
    return ERR_OK;
}

std::int32_t AccountProxy::QueryDeviceAccountId(std::int32_t &accountId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    MessageParcel reply;
    auto ret = SendRequest(AccountMgrInterfaceCode::QUERY_DEVICE_ACCOUNT_ID, data, reply);
    if (ret != ERR_NONE) {
        return ret;
    }
    accountId = reply.ReadInt32();
    return ERR_OK;
}

ErrCode AccountProxy::SubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
    const sptr<IRemoteObject> &eventListener)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed.");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(static_cast<int32_t>(type))) {
        ACCOUNT_LOGE("Write type failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(eventListener)) {
        ACCOUNT_LOGE("Write remote object for eventListener failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(AccountMgrInterfaceCode::SUBSCRIBE_DISTRIBUTED_ACCOUNT_EVENT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed, result=%{public}d.", result);
        return result;
    }

    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("Read reply failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Subscribe distributed account event failed, result=%{public}d.", result);
        return result;
    }
    return ERR_OK;
}

ErrCode AccountProxy::UnsubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
    const sptr<IRemoteObject> &eventListener)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed.");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(static_cast<int32_t>(type))) {
        ACCOUNT_LOGE("Write type failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(eventListener)) {
        ACCOUNT_LOGE("Write remote object for eventListener failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(AccountMgrInterfaceCode::UNSUBSCRIBE_DISTRIBUTED_ACCOUNT_EVENT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed, result=%{public}d.", result);
        return result;
    }

    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("Read reply failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Unsubscribe distributed account failed, result=%{public}d.", result);
    }

    return result;
}

sptr<IRemoteObject> AccountProxy::GetAppAccountService()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return nullptr;
    }
    MessageParcel reply;
    auto ret = SendRequest(AccountMgrInterfaceCode::GET_APP_ACCOUNT_SERVICE, data, reply);
    if (ret != ERR_NONE) {
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

sptr<IRemoteObject> AccountProxy::GetOsAccountService()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return nullptr;
    }
    MessageParcel reply;
    auto ret = SendRequest(AccountMgrInterfaceCode::GET_OS_ACCOUNT_SERVICE, data, reply);
    if (ret != ERR_NONE) {
        return nullptr;
    }

    return reply.ReadRemoteObject();
}

sptr<IRemoteObject> AccountProxy::GetAccountIAMService()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return nullptr;
    }
    MessageParcel reply;
    auto ret = SendRequest(AccountMgrInterfaceCode::GET_ACCOUNT_IAM_SERVICE, data, reply);
    if (ret != ERR_NONE) {
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
    auto ret = SendRequest(AccountMgrInterfaceCode::GET_DOMAIN_ACCOUNT_SERVICE, data, reply);
    if (ret != ERR_NONE) {
        return nullptr;
    }
    return reply.ReadRemoteObject();
}
}  // namespace AccountSA
}  // namespace OHOS

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

#include "os_account_proxy.h"

namespace OHOS {
namespace AccountSA {
OsAccountProxy::OsAccountProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IOsAccount>(object)
{
    ACCOUNT_LOGI("enter");
}

OsAccountProxy::~OsAccountProxy()
{
    ACCOUNT_LOGI("enter");
}

ErrCode OsAccountProxy::CreateOsAccount(
    const std::string &name, const int &type, OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_OS_ACCOUNT_KIT_WRITE_LOCALNAME_ERROR;
    }

    if (!data.WriteInt32(type)) {
        ACCOUNT_LOGE("failed to write type ");
        return ERR_OS_ACCOUNT_KIT_WRITE_OSACCOUNT_TYPE_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::CREATE_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        return ERR_OS_ACCOUNT_KIT_CREATE_OS_ACCOUNT_ERROR;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OS_ACCOUNT_KIT_CREATE_OS_ACCOUNT_ERROR;
    }
    osAccountInfo = *(reply.ReadParcelable<OsAccountInfo>());
    return ERR_OK;
}

ErrCode OsAccountProxy::RemoveOsAccount(const int id)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::REMOVE_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_REMOVE_OSACCOUNT_ERROR;
    }

    return ERR_OK;
}

ErrCode OsAccountProxy::IsOsAccountExists(const int id, bool &isOsAccountExists)
{
    ACCOUNT_LOGI("OsAccountProxy::IsOsAccountExists start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::IS_OS_ACCOUNT_EXISTS, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_EXISTS_ERROR;
    }
    isOsAccountExists = reply.ReadBool();
    return ERR_OK;
}

ErrCode OsAccountProxy::IsOsAccountActived(const int id, bool &isOsAccountActived)
{
    ACCOUNT_LOGI("OsAccountProxy IsOsAccountActived start");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::IS_OS_ACCOUNT_ACTIVED, data, reply);
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_ACTIVED_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_ACTIVED_ERROR;
    }
    isOsAccountActived = reply.ReadBool();
    ACCOUNT_LOGI("OsAccountProxy IsOsAccountActived end");
    return ERR_OK;
}

ErrCode OsAccountProxy::IsOsAccountConstraintEnable(
    const int id, const std::string &constraint, bool &isConstraintEnable)
{
    ACCOUNT_LOGI("OsAccountProxy IsOsAccountActived start");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    if (!data.WriteString(constraint)) {
        ACCOUNT_LOGE("failed to write string for constraint");
        return ERR_OSACCOUNT_KIT_WRITE_STRING_CONSTRAINT_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::IS_OS_ACCOUNT_CONSTRAINT_ENABLE, data, reply);
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_CONSTRAINT_ENABLE_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_CONSTRAINT_ENABLE_ERROR;
    }
    isConstraintEnable = reply.ReadBool();
    ACCOUNT_LOGI("OsAccountProxy IsOsAccountActived end");
    return ERR_OK;
}

ErrCode OsAccountProxy::IsOsAccountVerified(const int id, bool &isOsAccountVerified)
{
    ACCOUNT_LOGI("OsAccountProxy IsOsAccountVerified start");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::IS_OS_ACCOUNT_VERIFIED, data, reply);
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_VERIFIED_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_VERIFIED_ERROR;
    }
    isOsAccountVerified = reply.ReadBool();
    ACCOUNT_LOGI("OsAccountProxy IsOsAccountVerified end");
    return ERR_OK;
}

ErrCode OsAccountProxy::GetCreatedOsAccountsCount(int &osAccountsCount)
{
    ACCOUNT_LOGI("OsAccountProxy GetCreatedOsAccountsCount start");
    MessageParcel data;
    MessageParcel reply;
    ErrCode result = SendRequest(IOsAccount::Message::GET_CREATED_OS_ACCOUNT_COUNT, data, reply);
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_CREATED_OS_ACCOUNT_COUNT_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_CREATED_OS_ACCOUNT_COUNT_ERROR;
    }
    osAccountsCount = reply.ReadInt32();
    ACCOUNT_LOGI("OsAccountProxy GetCreatedOsAccountsCount end");
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountLocalIdFromProcess(int &id)
{
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountLocalIdFromProcess start");
    MessageParcel data;
    MessageParcel reply;
    ErrCode result = SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_LOCAL_ID_FROM_PROCESS, data, reply);
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FROM_PROCESS_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FROM_PROCESS_ERROR;
    }
    id = reply.ReadInt32();
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountLocalIdFromProcess end");
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountLocalIdFromUid(const int uid, int &id)
{
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountLocalIdFromUid start");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(uid)) {
        ACCOUNT_LOGE("failed to write int for uid");
        return ERR_OSACCOUNT_KIT_WRITE_INT_UID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_LOCAL_ID_FROM_UID, data, reply);
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FROM_UID_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FROM_UID_ERROR;
    }
    id = reply.ReadInt32();
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountLocalIdFromUid end");
    return ERR_OK;
}

ErrCode OsAccountProxy::QueryMaxOsAccountNumber(int &maxOsAccountNumber)
{
    ACCOUNT_LOGI("OsAccountProxy QueryMaxOsAccountNumber start");
    MessageParcel data;
    MessageParcel reply;
    ErrCode result = SendRequest(IOsAccount::Message::QUERY_MAX_OS_ACCOUNT_NUMBER, data, reply);
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_QUERY_MAX_OS_ACCOUNT_NUMBER_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_QUERY_MAX_OS_ACCOUNT_NUMBER_ERROR;
    }
    maxOsAccountNumber = reply.ReadInt32();
    ACCOUNT_LOGI("OsAccountProxy QueryMaxOsAccountNumber end");
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints)
{
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountAllConstraints start");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_ALL_CONSTRAINTS, data, reply);
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_ALL_CONSTRAINTS_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_ALL_CONSTRAINTS_ERROR;
    }
    bool readFlag = reply.ReadStringVector(&constraints);
    if (!readFlag) {
        return ERR_OSACCOUNT_KIT_READ_CONSTRAINTS_ERROR;
    }
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountAllConstraints end");
    return ERR_OK;
}

ErrCode OsAccountProxy::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    ACCOUNT_LOGI("OsAccountProxy QueryAllCreatedOsAccounts start");
    MessageParcel data;
    MessageParcel reply;
    ErrCode result = SendRequest(IOsAccount::Message::QUERY_ALL_CREATED_OS_ACCOUNTS, data, reply);
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_QUERY_ALL_CREATED_OS_ACCOUNTS_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_QUERY_ALL_CREATED_OS_ACCOUNTS_ERROR;
    }
    ReadParcelableVector(osAccountInfos, reply);

    ACCOUNT_LOGI("OsAccountProxy osAccountInfos.size() is %{public}zu", osAccountInfos.size());
    ACCOUNT_LOGI("OsAccountProxy QueryAllCreatedOsAccounts end");
    return ERR_OK;
}

ErrCode OsAccountProxy::QueryCurrentOsAccount(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountProxy QueryCurrentOsAccount start");
    MessageParcel data;
    MessageParcel reply;
    ErrCode result = SendRequest(IOsAccount::Message::QUERY_CURRENT_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_QUERY_CURRENT_OS_ACCOUNT_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_QUERY_CURRENT_OS_ACCOUNT_ERROR;
    }
    osAccountInfo = *(reply.ReadParcelable<OsAccountInfo>());
    ACCOUNT_LOGI("OsAccountProxy QueryCurrentOsAccount end");
    return ERR_OK;
}

ErrCode OsAccountProxy::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountProxy QueryOsAccountById start");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::QUERY_OS_ACCOUNT_BY_ID, data, reply);
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_QUERY_OS_ACCOUNT_BY_ID_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_QUERY_OS_ACCOUNT_BY_ID_ERROR;
    }
    osAccountInfo = *(reply.ReadParcelable<OsAccountInfo>());
    ACCOUNT_LOGI("OsAccountProxy QueryOsAccountById end");
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountTypeFromProcess(int &type)
{
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountTypeFromProcess start");
    MessageParcel data;
    MessageParcel reply;
    ErrCode result = SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_TYPE_FROM_PROCESS, data, reply);
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_TYPE_FROM_PROCESS_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_TYPE_FROM_PROCESS_ERROR;
    }
    type = reply.ReadInt32();
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountTypeFromProcess end");
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountProfilePhoto(const int id, std::string &photo)
{
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountProfilePhoto start");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_PROFILE_PHOTO, data, reply);
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_PROFILE_PHOTO_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_PROFILE_PHOTO_ERROR;
    }
    photo = reply.ReadString();
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountProfilePhoto end");
    return ERR_OK;
}

ErrCode OsAccountProxy::IsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    ACCOUNT_LOGI("OsAccountProxy IsMultiOsAccountEnable start");
    MessageParcel data;
    MessageParcel reply;
    ErrCode result = SendRequest(IOsAccount::Message::IS_MULTI_OS_ACCOUNT_ENABLE, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("OsAccountProxy IsMultiOsAccountEnable err");
        return ERR_OSACCOUNT_KIT_IS_MULTI_OS_ACCOUNT_ENABLE_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_IS_MULTI_OS_ACCOUNT_ENABLE_ERROR;
    }
    isMultiOsAccountEnable = reply.ReadBool();
    ACCOUNT_LOGI("OsAccountProxy IsMultiOsAccountEnable end");
    return ERR_OK;
}

ErrCode OsAccountProxy::SetOsAccountName(const int id, const std::string &name)
{
    ACCOUNT_LOGI("OsAccountProxy SetOsAccountName start");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_OSACCOUNT_KIT_WRITE_STRING_LOACLNAME_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::SET_OS_ACCOUNT_NAME, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("OsAccountProxy SetOsAccountName err");
        return ERR_OSACCOUNT_KIT_SET_OS_ACCOUNT_NAME_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_SET_OS_ACCOUNT_NAME_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::SetOsAccountConstraints(
    const int id, const std::vector<std::string> &constraints, const bool enable)
{
    ACCOUNT_LOGI("OsAccountProxy SetOsAccountConstraints start");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    if (!data.WriteStringVector(constraints)) {
        ACCOUNT_LOGE("failed to write stringVector for constraints");
        return ERR_OSACCOUNT_KIT_WRITE_STRINGVECTOR_CONSTRAINTS_ERROR;
    }
    if (!data.WriteBool(enable)) {
        ACCOUNT_LOGE("failed to write bool for enable");
        return ERR_OSACCOUNT_KIT_WRITE_BOOL_ENABLE_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::SET_OS_ACCOUNT_CONSTRAINTS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("OsAccountProxy SetOsAccountConstraints err");
        return ERR_OSACCOUNT_KIT_SET_OS_ACCOUNT_CONSTRAINTS_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_SET_OS_ACCOUNT_CONSTRAINTS_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::SetOsAccountProfilePhoto(const int id, const std::string &photo)
{
    ACCOUNT_LOGI("OsAccountProxy SetOsAccountProfilePhoto start");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    if (!data.WriteString(photo)) {
        ACCOUNT_LOGE("failed to write string for photo");
        return ERR_OSACCOUNT_KIT_WRITE_STRING_PHOTO_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::SET_OS_ACCOUNT_PROFILE_PHOTO, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("OsAccountProxy SetOsAccountProfilePhoto err");
        return ERR_OSACCOUNT_KIT_SET_OS_ACCOUNT_PROFILE_PHOTO_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_SET_OS_ACCOUNT_PROFILE_PHOTO_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::GetDistributedVirtualDeviceId(std::int32_t &deviceId)
{
    ACCOUNT_LOGI("OsAccountProxy GetDistributedVirtualDeviceId start");
    MessageParcel data;
    MessageParcel reply;
    ErrCode result = SendRequest(IOsAccount::Message::GET_DISTRIBUTED_VIRTUAL_DEVICE_ID, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("OsAccountProxy GetDistributedVirtualDeviceId err");
        return ERR_OSACCOUNT_KIT_GET_DISTRIBUTED_VIRTUAL_DEVICE_ID_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_DISTRIBUTED_VIRTUAL_DEVICE_ID_ERROR;
    }
    deviceId = reply.ReadInt32();
    ACCOUNT_LOGI("OsAccountProxy GetDistributedVirtualDeviceId end");
    return ERR_OK;
}

ErrCode OsAccountProxy::ActivateOsAccount(const int id)
{
    ACCOUNT_LOGI("OsAccountProxy ActivateOsAccount start");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::ACTIVATE_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("OsAccountProxy ActivateOsAccount err");
        return ERR_OSACCOUNT_KIT_ACTIVATE_OS_ACCOUNT_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_ACTIVATE_OS_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::StartOsAccount(const int id)
{
    ACCOUNT_LOGI("OsAccountProxy StartOsAccount start");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::START_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("OsAccountProxy StartOsAccount err");
        return ERR_OSACCOUNT_KIT_START_OS_ACCOUNT_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_START_OS_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::StopOsAccount(const int id)
{
    ACCOUNT_LOGI("OsAccountProxy StopOsAccount start");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::STOP_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("OsAccountProxy StopOsAccount err");
        return ERR_OSACCOUNT_KIT_STOP_OS_ACCOUNT_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_STOP_OS_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountLocalIdBySerialNumber start");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt64(serialNumber)) {
        ACCOUNT_LOGE("failed to write int for serialNumber");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_LOCAL_ID_FOR_SERIAL_NUMBER, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("OsAccountProxy StopOsAccount err");
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FOR_SERIAL_NUMBER_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FOR_SERIAL_NUMBER_ERROR;
    }
    id = reply.ReadInt32();
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountLocalIdBySerialNumber end");
    return ERR_OK;
}

ErrCode OsAccountProxy::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    ACCOUNT_LOGI("OsAccountProxy GetSerialNumberByOsAccountLocalId start");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::GET_SERIAL_NUMBER_FOR_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("OsAccountProxy StopOsAccount err");
        return ERR_OSACCOUNT_KIT_GET_SERIAL_NUMBER_FOR_OS_ACCOUNT__ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_SERIAL_NUMBER_FOR_OS_ACCOUNT__ERROR;
    }
    serialNumber = reply.ReadInt64();
    ACCOUNT_LOGI("OsAccountProxy GetSerialNumberByOsAccountLocalId end");
    return ERR_OK;
}

ErrCode OsAccountProxy::SubscribeOsAccount(
    const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteParcelable(&subscribeInfo)) {
        ACCOUNT_LOGE("failed to write parcelable for subscribeInfo");
        return ERR_OSACCOUNT_KIT_WRITE_PARCELABLE_SUBSCRIBE_INFO_ERROR;
    }

    if (!data.WriteParcelable(eventListener)) {
        ACCOUNT_LOGE("failed to write parcelable for eventListener");
        return ERR_OSACCOUNT_KIT_WRITE_PARCELABLE_EVENT_LISTENER_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::SUBSCRIBE_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_SUBSCRIBE_ERROR;
    }

    return ERR_OK;
}

ErrCode OsAccountProxy::UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteParcelable(eventListener)) {
        ACCOUNT_LOGE("failed to write parcelable for eventListener");
        return ERR_OSACCOUNT_KIT_WRITE_PARCELABLE_EVENT_LISTENER_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::UNSUBSCRIBE_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_UNSUBSCRIBE_ERROR;
    }

    return ERR_OK;
}
OS_ACCOUNT_SWITCH_MOD OsAccountProxy::GetOsAccountSwitchMod()
{
    MessageParcel data;
    MessageParcel reply;
    SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_SWITCH_MOD, data, reply);
    OS_ACCOUNT_SWITCH_MOD osAccountSwitchMod = static_cast<OS_ACCOUNT_SWITCH_MOD>(reply.ReadInt32());
    return osAccountSwitchMod;
}

ErrCode OsAccountProxy::SendRequest(IOsAccount::Message code, MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_OSACCOUNT_KIT_REMOTE_IS_NULLPTR;
    }

    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to SendRequest, code = %{public}d, result = %{public}d", code, result);
        return ERR_OSACCOUNT_KIT_SEND_REQUEST_ERROR;
    }

    return ERR_OK;
}

ErrCode OsAccountProxy::IsCurrentOsAccountVerified(bool &isOsAccountVerified)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode result = SendRequest(IOsAccount::Message::IS_CURRENT_OS_ACCOUNT_VERIFIED, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_UNSUBSCRIBE_ERROR;
    }
    isOsAccountVerified = reply.ReadBool();
    return ERR_OK;
}

ErrCode OsAccountProxy::IsOsAccountCompleted(const int id, bool &isOsAccountCompleted)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::IS_OS_ACCOUNT_COMPLETED, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_UNSUBSCRIBE_ERROR;
    }
    isOsAccountCompleted = reply.ReadBool();
    return ERR_OK;
}

ErrCode OsAccountProxy::SetCurrentOsAccountIsVerified(const bool isOsAccountVerified)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteBool(isOsAccountVerified)) {
        ACCOUNT_LOGE("failed to write bool for isOsAccountVerified");
        return ERR_OSACCOUNT_KIT_WRITE_BOOL_ISOSACCOUNT_VERIFIED_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::SET_CURRENT_OS_ACCOUNT_IS_VERIFIED, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_UNSUBSCRIBE_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::SetOsAccountIsVerified(const int id, const bool isOsAccountVerified)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    if (!data.WriteBool(isOsAccountVerified)) {
        ACCOUNT_LOGE("failed to write bool for isOsAccountVerified");
        return ERR_OSACCOUNT_KIT_WRITE_BOOL_ISOSACCOUNT_VERIFIED_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::SET_OS_ACCOUNT_IS_VERIFIED, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_UNSUBSCRIBE_ERROR;
    }
    return ERR_OK;
}
template <typename T>
bool OsAccountProxy::WriteParcelableVector(const std::vector<T> &parcelableVector, MessageParcel &data)
{
    if (!data.WriteInt32(parcelableVector.size())) {
        ACCOUNT_LOGI("Account write ParcelableVector failed");
        return false;
    }

    for (auto &parcelable : parcelableVector) {
        if (!data.WriteParcelable(&parcelable)) {
            ACCOUNT_LOGI("Account write ParcelableVector failed");
            return false;
        }
    }
    return true;
}
template <typename T>
bool OsAccountProxy::ReadParcelableVector(std::vector<T> &parcelableInfos, MessageParcel &data)
{
    int32_t infoSize = 0;
    if (!data.ReadInt32(infoSize)) {
        ACCOUNT_LOGI("Account read Parcelable size failed.");
        return false;
    }
    ACCOUNT_LOGE("Account read Parcelable size is %{public}d", infoSize);
    parcelableInfos.clear();
    for (int32_t index = 0; index < infoSize; index++) {
        T *info = data.ReadParcelable<T>();
        if (info == nullptr) {
            ACCOUNT_LOGI("Account read Parcelable infos failed.");
            return false;
        }
        parcelableInfos.emplace_back(*info);
    }

    return true;
}
}  // namespace AccountSA
}  // namespace OHOS

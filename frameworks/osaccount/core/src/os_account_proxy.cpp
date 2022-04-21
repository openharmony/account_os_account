/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "os_account_proxy.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
OsAccountProxy::OsAccountProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IOsAccount>(object)
{}

OsAccountProxy::~OsAccountProxy()
{}

ErrCode OsAccountProxy::CreateOsAccount(
    const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_OSACCOUNT_KIT_WRITE_LOCALNAME_ERROR;
    }

    if (!data.WriteInt32(type)) {
        ACCOUNT_LOGE("failed to write type ");
        return ERR_OSACCOUNT_KIT_WRITE_OSACCOUNT_TYPE_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::CREATE_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_CREATE_OS_ACCOUNT_ERROR;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for create os account.");
        return ERR_OSACCOUNT_KIT_CREATE_OS_ACCOUNT_ERROR;
    }
    osAccountInfo = *(reply.ReadParcelable<OsAccountInfo>());
    return ERR_OK;
}

ErrCode OsAccountProxy::CreateOsAccountForDomain(
    const OsAccountType &type, const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(type)) {
        ACCOUNT_LOGE("failed to write type ");
        return ERR_OSACCOUNT_KIT_WRITE_OSACCOUNT_TYPE_ERROR;
    }

    if (!data.WriteString(domainInfo.domain_)) {
        ACCOUNT_LOGE("failed to write string for domain");
        return ERR_OSACCOUNT_KIT_WRITE_DOMAIN_ERROR;
    }

    if (!data.WriteString(domainInfo.accountName_)) {
        ACCOUNT_LOGE("failed to write string for domain account name");
        return ERR_OSACCOUNT_KIT_WRITE_DOMAIN_ACCOUNT_NAME_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::CREATE_OS_ACCOUNT_FOR_DOMAIN, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request for create os account for domain.");
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for create os account for domain.");
        return result;
    }
    osAccountInfo = *(reply.ReadParcelable<OsAccountInfo>());
    return ERR_OK;
}

ErrCode OsAccountProxy::RemoveOsAccount(const int id)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::REMOVE_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for remove os account info.");
        return ERR_OSACCOUNT_KIT_REMOVE_OSACCOUNT_ERROR;
    }

    return ERR_OK;
}

ErrCode OsAccountProxy::IsOsAccountExists(const int id, bool &isOsAccountExists)
{
    ACCOUNT_LOGI("OsAccountProxy::IsOsAccountExists start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::IS_OS_ACCOUNT_EXISTS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for is os account exists.");
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

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::IS_OS_ACCOUNT_ACTIVED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_ACTIVED_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for is os account activated.");
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

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

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
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_CONSTRAINT_ENABLE_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for is os account constraint enable.");
        return ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_CONSTRAINT_ENABLE_ERROR;
    }
    isConstraintEnable = reply.ReadBool();
    ACCOUNT_LOGI("OsAccountProxy IsOsAccountActived end");
    return ERR_OK;
}

ErrCode OsAccountProxy::IsOsAccountVerified(const int id, bool &isVerified)
{
    ACCOUNT_LOGI("OsAccountProxy IsOsAccountVerified start");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::IS_OS_ACCOUNT_VERIFIED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_VERIFIED_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for is os account verified.");
        return ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_VERIFIED_ERROR;
    }
    isVerified = reply.ReadBool();
    ACCOUNT_LOGI("OsAccountProxy IsOsAccountVerified end");
    return ERR_OK;
}

ErrCode OsAccountProxy::GetCreatedOsAccountsCount(unsigned int &osAccountsCount)
{
    osAccountsCount = 0;
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::GET_CREATED_OS_ACCOUNT_COUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_GET_CREATED_OS_ACCOUNT_COUNT_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for get os account count.");
        return ERR_OSACCOUNT_KIT_GET_CREATED_OS_ACCOUNT_COUNT_ERROR;
    }
    osAccountsCount = reply.ReadUint32();
    ACCOUNT_LOGI("succeed! osAccountsCount %{public}u.", osAccountsCount);
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountLocalIdFromProcess(int &id)
{
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountLocalIdFromProcess start");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_LOCAL_ID_FROM_PROCESS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FROM_PROCESS_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for get os account id from process.");
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FROM_PROCESS_ERROR;
    }
    id = reply.ReadInt32();
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountLocalIdFromProcess end");
    return ERR_OK;
}

ErrCode OsAccountProxy::IsMainOsAccount(bool &isMainOsAccount)
{
    ACCOUNT_LOGI("OsAccountProxy IsMainOsAccount start");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::IS_MAIN_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for is main os account.");
        return result;
    }
    isMainOsAccount = reply.ReadBool();
    ACCOUNT_LOGI("OsAccountProxy IsMainOsAccount end");
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id)
{
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountLocalIdFromDomain start");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(domainInfo.domain_)) {
        ACCOUNT_LOGE("failed to write int for domain.");
        return ERR_OSACCOUNT_KIT_WRITE_DOMAIN_ERROR;
    }
    if (!data.WriteString(domainInfo.accountName_)) {
        ACCOUNT_LOGE("failed to write int for domain account name.");
        return ERR_OSACCOUNT_KIT_WRITE_DOMAIN_ACCOUNT_NAME_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_LOCAL_ID_FROM_DOMAIN, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FOR_DOMAIN_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("read from reply err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FOR_DOMAIN_ERROR;
    }
    id = reply.ReadInt32();
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountLocalIdFromDomain end");
    return ERR_OK;
}

ErrCode OsAccountProxy::QueryMaxOsAccountNumber(int &maxOsAccountNumber)
{
    ACCOUNT_LOGI("OsAccountProxy QueryMaxOsAccountNumber start");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::QUERY_MAX_OS_ACCOUNT_NUMBER, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_QUERY_MAX_OS_ACCOUNT_NUMBER_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for query os account number.");
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

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_ALL_CONSTRAINTS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_ALL_CONSTRAINTS_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for get os account all constraints.");
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

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::QUERY_ALL_CREATED_OS_ACCOUNTS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_QUERY_ALL_CREATED_OS_ACCOUNTS_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for query all os accounts.");
        return ERR_OSACCOUNT_KIT_QUERY_ALL_CREATED_OS_ACCOUNTS_ERROR;
    }
    ReadParcelableVector(osAccountInfos, reply);

    ACCOUNT_LOGI("OsAccountProxy osAccountInfos.size() is %{public}zu", osAccountInfos.size());
    return ERR_OK;
}

ErrCode OsAccountProxy::QueryCurrentOsAccount(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountProxy QueryCurrentOsAccount start");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::QUERY_CURRENT_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_QUERY_CURRENT_OS_ACCOUNT_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for query current os account.");
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

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::QUERY_OS_ACCOUNT_BY_ID, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_QUERY_OS_ACCOUNT_BY_ID_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for query os account by id.");
        return ERR_OSACCOUNT_KIT_QUERY_OS_ACCOUNT_BY_ID_ERROR;
    }
    osAccountInfo = *(reply.ReadParcelable<OsAccountInfo>());
    ACCOUNT_LOGI("OsAccountProxy QueryOsAccountById end");
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountTypeFromProcess(OsAccountType &type)
{
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountTypeFromProcess start");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_TYPE_FROM_PROCESS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_TYPE_FROM_PROCESS_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for get os account type by process.");
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_TYPE_FROM_PROCESS_ERROR;
    }
    type = static_cast<OsAccountType>(reply.ReadInt32());
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountTypeFromProcess end");
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountProfilePhoto(const int id, std::string &photo)
{
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountProfilePhoto start");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_PROFILE_PHOTO, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_PROFILE_PHOTO_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for get os account profile photo.");
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

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::IS_MULTI_OS_ACCOUNT_ENABLE, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_IS_MULTI_OS_ACCOUNT_ENABLE_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for is multi os account enable.");
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

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

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
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_SET_OS_ACCOUNT_NAME_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for set os account name.");
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

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

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
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_SET_OS_ACCOUNT_CONSTRAINTS_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for set os account constraints.");
        return ERR_OSACCOUNT_KIT_SET_OS_ACCOUNT_CONSTRAINTS_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::SetOsAccountProfilePhoto(const int id, const std::string &photo)
{
    ACCOUNT_LOGI("OsAccountProxy SetOsAccountProfilePhoto start");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

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
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_SET_OS_ACCOUNT_PROFILE_PHOTO_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for set os account profile photo.");
        return ERR_OSACCOUNT_KIT_SET_OS_ACCOUNT_PROFILE_PHOTO_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::ActivateOsAccount(const int id)
{
    ACCOUNT_LOGI("OsAccountProxy ActivateOsAccount start");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::ACTIVATE_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_ACTIVATE_OS_ACCOUNT_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for activate os account.");
        return ERR_OSACCOUNT_KIT_ACTIVATE_OS_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::StartOsAccount(const int id)
{
    ACCOUNT_LOGI("OsAccountProxy StartOsAccount start");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::START_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_START_OS_ACCOUNT_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for start os account.");
        return ERR_OSACCOUNT_KIT_START_OS_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::StopOsAccount(const int id)
{
    ACCOUNT_LOGI("OsAccountProxy StopOsAccount start");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::STOP_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_STOP_OS_ACCOUNT_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for stop os account.");
        return ERR_OSACCOUNT_KIT_STOP_OS_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    ACCOUNT_LOGI("OsAccountProxy GetOsAccountLocalIdBySerialNumber start");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt64(serialNumber)) {
        ACCOUNT_LOGE("failed to write int for serialNumber");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_LOCAL_ID_FOR_SERIAL_NUMBER, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FOR_SERIAL_NUMBER_ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for get os account id by serial number.");
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

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::GET_SERIAL_NUMBER_FOR_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return ERR_OSACCOUNT_KIT_GET_SERIAL_NUMBER_FOR_OS_ACCOUNT__ERROR;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for get serial number by os account id.");
        return ERR_OSACCOUNT_KIT_GET_SERIAL_NUMBER_FOR_OS_ACCOUNT__ERROR;
    }
    serialNumber = reply.ReadInt64();
    ACCOUNT_LOGI("OsAccountProxy GetSerialNumberByOsAccountLocalId end");
    return ERR_OK;
}

ErrCode OsAccountProxy::SubscribeOsAccount(
    const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteParcelable(&subscribeInfo)) {
        ACCOUNT_LOGE("failed to write parcelable for subscribeInfo");
        return ERR_OSACCOUNT_KIT_WRITE_PARCELABLE_SUBSCRIBE_INFO_ERROR;
    }

    if (!data.WriteRemoteObject(eventListener)) {
        ACCOUNT_LOGE("failed to write remote object for eventListener");
        return ERR_OSACCOUNT_KIT_WRITE_PARCELABLE_EVENT_LISTENER_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::SUBSCRIBE_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for subscriber os account.");
        return ERR_OSACCOUNT_KIT_SUBSCRIBE_ERROR;
    }

    return ERR_OK;
}

ErrCode OsAccountProxy::UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteRemoteObject(eventListener)) {
        ACCOUNT_LOGE("failed to write remote object for eventListener");
        return ERR_OSACCOUNT_KIT_WRITE_PARCELABLE_EVENT_LISTENER_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::UNSUBSCRIBE_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for unsubscriber os account.");
        return ERR_OSACCOUNT_KIT_UNSUBSCRIBE_ERROR;
    }

    return ERR_OK;
}
OS_ACCOUNT_SWITCH_MOD OsAccountProxy::GetOsAccountSwitchMod()
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return OS_ACCOUNT_SWITCH_MOD::ERROR_MOD;
    }

    ErrCode result = SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_SWITCH_MOD, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return OS_ACCOUNT_SWITCH_MOD::ERROR_MOD;
    }

    OS_ACCOUNT_SWITCH_MOD osAccountSwitchMod = static_cast<OS_ACCOUNT_SWITCH_MOD>(reply.ReadInt32());
    return osAccountSwitchMod;
}

ErrCode OsAccountProxy::SendRequest(IOsAccount::Message code, MessageParcel &data, MessageParcel &reply)
{
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

ErrCode OsAccountProxy::IsCurrentOsAccountVerified(bool &isVerified)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::IS_CURRENT_OS_ACCOUNT_VERIFIED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for is current os account verified.");
        return ERR_OSACCOUNT_KIT_UNSUBSCRIBE_ERROR;
    }
    isVerified = reply.ReadBool();
    return ERR_OK;
}

ErrCode OsAccountProxy::IsOsAccountCompleted(const int id, bool &isOsAccountCompleted)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::IS_OS_ACCOUNT_COMPLETED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for is os account completed.");
        return ERR_OSACCOUNT_KIT_UNSUBSCRIBE_ERROR;
    }
    isOsAccountCompleted = reply.ReadBool();
    return ERR_OK;
}

ErrCode OsAccountProxy::SetCurrentOsAccountIsVerified(const bool isVerified)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteBool(isVerified)) {
        ACCOUNT_LOGE("failed to write bool for isVerified");
        return ERR_OSACCOUNT_KIT_WRITE_BOOL_ISOSACCOUNT_VERIFIED_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::SET_CURRENT_OS_ACCOUNT_IS_VERIFIED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for set current os account verified.");
        return ERR_OSACCOUNT_KIT_UNSUBSCRIBE_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::SetOsAccountIsVerified(const int id, const bool isVerified)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }
    if (!data.WriteBool(isVerified)) {
        ACCOUNT_LOGE("failed to write bool for isVerified");
        return ERR_OSACCOUNT_KIT_WRITE_BOOL_ISOSACCOUNT_VERIFIED_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::SET_OS_ACCOUNT_IS_VERIFIED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for set os account verified.");
        return ERR_OSACCOUNT_KIT_UNSUBSCRIBE_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::DumpState(const int &id, std::vector<std::string> &state)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::DUMP_STATE, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_DUMP_STATE_ERROR;
    }

    uint32_t size = reply.ReadUint32();
    for (uint32_t i = 0; i < size; i++) {
        std::string info = reply.ReadString();
        state.emplace_back(info);
    }

    return ERR_OK;
}

void OsAccountProxy::CreateBasicAccounts()
{
    ACCOUNT_LOGI("OsAccountProxy::CreateBasicAccounts called. Do nothing.");
}

ErrCode OsAccountProxy::GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
    int &createdOsAccountNum)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(storeID)) {
        ACCOUNT_LOGE("failed to write string for storeID");
        return ERR_OSACCOUNT_KIT_WRITE_STRING_STOREID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::GET_CREATED_OS_ACCOUNT_NUM_FROM_DATABASE, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_CREATED_OS_ACCOUNT_NUM_FROM_DATABASE_ERROR;
    }
    createdOsAccountNum = reply.ReadInt32();
    return ERR_OK;
}

ErrCode OsAccountProxy::GetSerialNumberFromDatabase(const std::string& storeID, int64_t &serialNumber)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(storeID)) {
        ACCOUNT_LOGE("failed to write string for storeID");
        return ERR_OSACCOUNT_KIT_WRITE_STRING_STOREID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::GET_SERIAL_NUM_FROM_DATABASE, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_SERIAL_NUM_FROM_DATABASE_ERROR;
    }
    serialNumber = reply.ReadInt64();
    return ERR_OK;
}

ErrCode OsAccountProxy::GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(storeID)) {
        ACCOUNT_LOGE("failed to write string for isVerified");
        return ERR_OSACCOUNT_KIT_WRITE_STRING_STOREID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::GET_MAX_ALLOW_CREATE_ID_FROM_DATABASE, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_MAX_ALLOWED_CREATE_ID_FROM_DATABASE_ERROR;
    }
    id = reply.ReadInt32();
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountFromDatabase(const std::string& storeID,
    const int id, OsAccountInfo &osAccountInfo)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(storeID)) {
        ACCOUNT_LOGE("failed to write string for storeID");
        return ERR_OSACCOUNT_KIT_WRITE_STRING_STOREID_ERROR;
    }
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_OSACCOUNT_KIT_WRITE_INT_LOCALID_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_FROM_DATABASE, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_FROM_DATABASE_ERROR;
    }
    osAccountInfo = *(reply.ReadParcelable<OsAccountInfo>());
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountListFromDatabase(const std::string& storeID,
    std::vector<OsAccountInfo> &osAccountList)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(storeID)) {
        ACCOUNT_LOGE("failed to write string for storeID");
        return ERR_OSACCOUNT_KIT_WRITE_STRING_STOREID_ERROR;
    }
    ErrCode result = SendRequest(IOsAccount::Message::GET_OS_ACCOUNT_LIST_FROM_DATABASE, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LIST_FROM_DATABASE_ERROR;
    }
    ReadParcelableVector(osAccountList, reply);
    return ERR_OK;
}

ErrCode OsAccountProxy::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(IOsAccount::Message::QUERY_ACTIVE_OS_ACCOUNT_IDS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for query active os account ids.");
        return ERR_OSACCOUNT_KIT_QUERY_ACTIVE_OS_ACCOUNT_IDS_ERROR;
    }

    bool readFlag = reply.ReadInt32Vector(&ids);
    if (!readFlag) {
        ACCOUNT_LOGE("failed to read vector for active ids.");
        return ERR_OSACCOUNT_KIT_QUERY_ACTIVE_OS_ACCOUNT_IDS_ERROR;
    }
    return ERR_OK;
}

template<typename T>
bool OsAccountProxy::WriteParcelableVector(const std::vector<T> &parcelableVector, MessageParcel &data)
{
    if (!data.WriteUint32(parcelableVector.size())) {
        ACCOUNT_LOGE("Account write ParcelableVector failed");
        return false;
    }

    for (auto &parcelable : parcelableVector) {
        if (!data.WriteParcelable(&parcelable)) {
            ACCOUNT_LOGE("Account write ParcelableVector failed");
            return false;
        }
    }
    return true;
}
template<typename T>
bool OsAccountProxy::ReadParcelableVector(std::vector<T> &parcelableInfos, MessageParcel &data)
{
    uint32_t infoSize = 0;
    if (!data.ReadUint32(infoSize)) {
        ACCOUNT_LOGE("Account read Parcelable size failed.");
        return false;
    }
    ACCOUNT_LOGI("Account read Parcelable size is %{public}d", infoSize);
    parcelableInfos.clear();
    for (uint32_t index = 0; index < infoSize; index++) {
        std::shared_ptr<T> info(data.ReadParcelable<T>());
        if (info == nullptr) {
            ACCOUNT_LOGE("Account read Parcelable infos failed.");
            return false;
        }
        parcelableInfos.emplace_back(*info);
    }

    return true;
}
}  // namespace AccountSA
}  // namespace OHOS
